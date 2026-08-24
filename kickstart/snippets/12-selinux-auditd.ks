# ============================================================================
# Module 12 — SELinux + auditd
# Status: LOCKED 2026-08-23 (v62) — close the exact Yescrypt HugeTLB SELinux gap.
#
# Covers:
#   - /etc/selinux/config explicit enforcing + targeted (F44 reinforces
#     this: runtime SELinux-disable was removed upstream — LSM hooks are
#     read-only after init)
#   - selinuxuser_execstack=off + selinuxuser_execmod=off (user-domain
#     executable-stack and modified-executable mapping restrictions)
#   - noid-selinux-fixes SELinux policy module (heredoc, currently 1.9):
#     switcheroo nnp_transition into Fedora's builtin-permissive labeled
#     domain, the audit-notify systemd sandbox mount point, usbguard
#     GDM/machined/xdm grants, logind
#     usbguard_tmpfs dir-walk bundle, AIDE /boot/efi dosfs getattr and
#     Yescrypt's optional HugeTLB mapping for the three password-related domains —
#     per-rule rationale lives inline in the .te heredoc
#   - Fedora's signed liveinst wrapper remains RPM-pristine; the vendor Live
#     installer controls its documented permissive installation environment,
#     while the installed target remains explicitly enforcing
#   - Fedora audit.rules gotcha fix: stock `-a task,never` DISABLES all
#     syscall auditing — replaced with bare `-D`
#   - /etc/audit/auditd.conf hardened replacement: measured 640-MiB rolling
#     ceiling, absolute installed-system watermarks and boot-scoped low-space
#     alert marker; an auditd ExecStartPre selects bounded percentages only
#     for the smaller ephemeral Live overlay
#   - /etc/audit/rules.d/99-hardening.rules — complete b64/b32 pairs for every
#     syscall/path rule, 132 rules in 33 keys + -e 2 immutable
#   - noid-audit-notify-plugin (auditd string plugin + auparse feed), its
#     bounded root-private runtime spool and normally-domained event drain,
#     plus audit-notify.service opt-in controller + noid-toggle-audit-notify
#
# Deliberate deviations (do NOT re-litigate):
#   - deny_execmem NOT set — Firefox/Electron JIT needs execmem; the two
#     selinuxuser_* booleans retain narrower executable-stack/modified-file
#     restrictions without breaking those JITs.
#   - no MediaWriter `execmod` exception: a rule over `unconfined_t` and
#     `user_tmp_t` would grant every unconfined process that permission, not
#     bind it to one executable. `dd` remains the no-grant image-writer path.
#   - Fedora's live installer wrapper temporarily selects permissive mode by
#     vendor design. NoID Privacy does not byte-patch or suppress RPM drift for it;
#     installed-system SELinux must be Enforcing in every candidate pass.
#   - secure_mode_insmod + deny_ptrace rejected; kernel.loginuid_immutable
#     skipped (breaks podman); IMA/EVM/IPE passive; no explicit lsm=
#     cmdline (Fedora kernel default).
#   - audit-notify ships DISABLED (user feedback: notifications too loud
#     by default) — opt-in via the Welcome dialog / toggle wrapper.
#     auditd + all 132 rules are always active regardless.
#   - desktop popups are delivered only to the event AUID's unlocked active
#     local graphical session. Audit evidence itself remains complete while
#     popups are disabled, rate-limited, coalesced or session-suppressed.
#
# Constraint notes (keep when editing):
#   - Rule ORDERING is load-bearing: -b/-f first and -e 2 LAST. There is no
#     trusted-daemon never-filter: authenticated chronyd adjustments remain
#     evidence, including `clock_adjtime`.
#   - Cron dirs are pre-created before the watch rules: a missing watch
#     target makes auditctl stop at that rule. Earlier rules remain loaded,
#     while every later rule including trailing -e 2 is skipped: a partial,
#     non-immutable ruleset that can look healthier than it is.
#   - The "132 rules" count is code-bearing, but count alone is insufficient:
#     tests also require normalized b64/b32 multiset equality.
#   - SELinux AVC-cascade lesson: grant the full dir-walk perm-bundle
#     ({ getattr read open search }) in one iteration — one-perm-at-a-time
#     just surfaces the next denial after every reboot.
#   - Auditd's dispatcher queue is unrelated to the kernel backlog. With zero
#     active plugins its vendor-default depth is retained; M01 owns the 8192
#     kernel backlog and runtime gates inspect both lost/backlog state.
#
# Cross-reference:
#   - Module 01: kernel cmdline audit=1 audit_backlog_limit=8192
#     (early-boot auditability before auditd starts).
#   - Module 02: kernel.yama.ptrace_scope=2. Module 09/10/11/14: watched
#     config paths (ssh, pam, chrony, usbguard). Module 13: AIDE
#     complements audit (periodic hashing vs real-time events). Module 25:
#     the process/lock-bound update-window validator drives narrow suppression
#     in the notification worker; mere marker existence is never authority.
# ============================================================================

# No %packages block here. M26 explicitly installs python3-audit and libnotify;
# audit, audit-libs, policycoreutils and SELinux policy are Fedora base.

%post --erroronfail --log=/var/log/ks-12-selinux-auditd.log

set -euo pipefail
echo "=============================================================="
echo "[Module 12] SELinux + auditd + LSM verification"
echo "=============================================================="

# Verify one exact RPM payload file. `rpm -Vf PATH` selects the package that
# owns PATH and verifies every file in that package; it is therefore too broad
# once M32 deliberately brands other anaconda-live assets. Bind only the
# maintained wrapper to its signed RPM digest while checking its metadata
# separately below.
rpm_payload_file_pristine() {
    local package=$1 path=$2 expected actual
    [ "$(rpm -q --qf '%{FILEDIGESTALGO}' "$package" 2>/dev/null || true)" = 8 ] \
        || return 1
    expected=$(rpm -q --qf '[%{FILENAMES}\t%{FILEDIGESTS}\n]' "$package" \
        2>/dev/null | awk -F '\t' -v target="$path" '
            $1 == target { count++; digest=$2 }
            END { if (count != 1 || digest == "") exit 1; print digest }
        ') || return 1
    actual=$(sha256sum -- "$path" 2>/dev/null) || return 1
    actual=${actual%% *}
    [ "$actual" = "$expected" ]
}

# ----------------------------------------------------------------------------
# Step 1: Package presence check (fail-fast if base dep missing)
# ----------------------------------------------------------------------------
echo ""
echo "[Step 1] Verifying required packages present"

missing_pkgs=""
for pkg in audit audit-libs checkpolicy libnotify libselinux policycoreutils \
           python3-audit selinux-policy selinux-policy-targeted util-linux; do
    if ! rpm -q "$pkg" >/dev/null 2>&1; then
        missing_pkgs="$missing_pkgs $pkg"
    fi
done

if [ -n "$missing_pkgs" ]; then
    echo "  [FAIL] missing required packages:$missing_pkgs"
    exit 1
fi
if ! /usr/bin/python3 -c 'import auparse' 2>/dev/null; then
    echo "  [FAIL] python3-audit is installed but the auparse binding is unusable"
    exit 1
fi
for tool in /usr/bin/loginctl /usr/bin/matchpathcon /usr/bin/notify-send \
            /usr/bin/restorecon /usr/bin/setpriv /usr/bin/timeout; do
    [ -x "$tool" ] || {
        echo "  [FAIL] audit notification dependency missing: $tool"
        exit 1
    }
done
echo "  [OK] all 10 required packages and notification interfaces present"

# ----------------------------------------------------------------------------
# Step 2: SELinux config (explicit enforcing + targeted)
# ----------------------------------------------------------------------------
# Fedora default is already SELINUX=enforcing + SELINUXTYPE=targeted.
# We set explicitly for audit trail + defense against future Fedora default
# changes. %config(noreplace) protects against rpm update regressions.
# Current kernels removed the legacy pre-policy-load runtime-disable interface,
# so an enabled SELinux LSM cannot have its hooks removed after initialization.
# That is distinct from enforcement state: privileged `setenforce 0` can still
# make an enabled policy permissive, while `selinux=0` is a boot-time choice.
# The image therefore pins both persistent config and runtime candidate gates.
echo ""
echo "[Step 2] SELinux config"

sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config

if grep -q "^SELINUX=enforcing$" /etc/selinux/config && \
   grep -q "^SELINUXTYPE=targeted$" /etc/selinux/config; then
    echo "  [OK] /etc/selinux/config set (enforcing + targeted)"
else
    echo "  [FAIL] /etc/selinux/config verification failed"
    exit 1
fi

# ----------------------------------------------------------------------------
# Step 2b: Preserve Fedora's signed Live-installer boundary
# ----------------------------------------------------------------------------
# Fedora's maintained Anaconda documentation distinguishes the permissive
# installation environment from the installed-system SELinux setting. The
# anaconda-live wrapper owns that transition. Modifying its RPM payload in
# `%post` would create an unsupported installer variant and then require an
# integrity suppression generated from the same mutated bytes. Keep the signed
# package payload pristine. The installed target is independently configured
# Enforcing above and verified after each candidate install and reboot.
echo ""
echo "[Step 2b] Verifying Fedora Live-installer RPM payload"

LIVEINST=/usr/bin/liveinst
if [ ! -f "$LIVEINST" ] || [ -L "$LIVEINST" ] \
   || [ "$(rpm -qf --qf '%{NAME}\n' "$LIVEINST" 2>/dev/null || true)" != \
        anaconda-live ] \
   || [ "$(stat -c '%U:%G:%a' "$LIVEINST" 2>/dev/null || true)" != root:root:755 ] \
   || ! rpm_payload_file_pristine anaconda-live "$LIVEINST"; then
    echo "  [FAIL] liveinst is missing, redirected, not anaconda-live-owned or RPM-drifted"
    exit 1
fi
bash -n "$LIVEINST"
echo "  [OK] Fedora liveinst wrapper is package-owned and RPM-pristine"

# ----------------------------------------------------------------------------
# Step 3: SELinux custom booleans (2 execution restrictions OFF)
# ----------------------------------------------------------------------------
# execstack=off restricts executable stacks; execmod=off restricts executing or
# mapping modified files. Neither is a blanket W^X control. deny_execmem remains
# deliberately unset (header deviations: Firefox/Electron JIT compatibility).
# Persistence uses only maintained policy-management interfaces.
echo ""
echo "[Step 3] SELinux custom booleans"

boolean_set() {
    local name="$1"
    # Prefer the native policy-store transaction.
    if semanage boolean -m --off "$name" 2>/dev/null; then
        echo "  [OK] $name set via semanage"
        return 0
    fi
    # setsebool -P is the maintained runtime + persistent fallback.
    if setsebool -P "$name" off 2>/dev/null; then
        echo "  [OK] $name set via setsebool -P"
        return 0
    fi
    echo "  [FAIL] no maintained interface could persist $name=off" >&2
    return 1
}

boolean_set selinuxuser_execstack
boolean_set selinuxuser_execmod

# ----------------------------------------------------------------------------
# Step 3b: NoID Privacy SELinux policy module (narrow F44 policy-gap fixes)
# ----------------------------------------------------------------------------
# Minimal .te module compiled in %post (checkmodule + semodule_package +
# semodule -i; checkpolicy ships in base). Every allow rule is
# AVC-evidence-driven and documents its own rationale + security analysis
# inline in the heredoc below. The switcheroo nnp_transition grant exists
# BECAUSE M08's NNP=true drop-in is kept (dropping the hardening was
# rejected — the grant restores the intended domain transition and AVC
# visibility instead of leaving the daemon in init_t).

echo ""
echo "[Step 3b] NoID Privacy SELinux policy module (narrow Fedora policy gaps)"

NOID_SE_DIR=/var/lib/noid-privacy/selinux
mkdir -p "$NOID_SE_DIR"

install -d -m 0755 -o root -g root "$NOID_SE_DIR"

cat > "$NOID_SE_DIR/noid-selinux-fixes.te" <<'NOID_TE_EOF'
module noid-selinux-fixes 1.9;

require {
    type init_t;
    type auditd_etc_t;
    type switcheroo_control_t;
    type usbguard_t;
    type xdm_var_run_t;
    type xdm_t;
    type systemd_machined_t;
    type systemd_logind_t;
    type usbguard_tmpfs_t;
    type aide_t;
    type dosfs_t;
    type passwd_t;
    type chkpwd_t;
    type updpwd_t;
    type hugetlbfs_t;
    class process2 nnp_transition;
    class sock_file write;
    class unix_stream_socket connectto;
    class dir { getattr read open search mounton };
    class filesystem getattr;
    class file { read write map };
}

# switcheroo nnp_transition root cause.
# Module 08 99-noid-hardening.conf sets NoNewPrivileges=true. Without this
# allow rule, init_t cannot transition to switcheroo_control_t domain and the
# daemon remains in init_t. This grant reaches the dedicated labeled domain
# and makes denials visible there. Fedora currently ships
# switcheroo_control_t as a builtin-permissive type, so its denials are logged
# rather than enforced; the transition is enforcement-ready if Fedora later
# makes the type enforcing.
allow init_t switcheroo_control_t:process2 nnp_transition;

# audit-notify.service systemd sandbox mount point.
# ProtectSystem=strict makes the host filesystem read-only in the controller's
# private mount namespace; ReadWritePaths=/etc/audit/plugins.d then requires
# PID 1 (init_t) to bind-mount the narrowly writable auditd_etc_t directory
# into that namespace. Fedora's targeted policy does not currently grant that
# mounton edge, so systemd fails at step NAMESPACE before the reviewed
# controller can atomically toggle the plugin. This permission authorizes only
# use of an already labeled directory as a mount point. It grants init_t no new
# read, write, create, relabel or mount-source permission and preserves the
# service's filesystem sandbox instead of removing ProtectSystem=strict.
allow init_t auditd_etc_t:dir mounton;

# usbguard → GDM socket file + machined userdb fix.
# usbguard-daemon writes notifications via GDM session bus and may query
# systemd userdb while resolving IPC peer identities. M14 now uses named ACLs,
# not broad group authorization; these targeted SELinux grants remain required
# for the maintained daemon/session path.
allow usbguard_t xdm_var_run_t:sock_file write;
allow usbguard_t systemd_machined_t:unix_stream_socket connectto;

# Layer 2 — usbguard → xdm_t process follow-up.
# After the first fix granted xdm_var_run_t:sock_file write, the next layer of
# SELinux check surfaced: connectto check uses PEER PROCESS DOMAIN, not file
# label. When systemd-machined is masked or absent (live-ISO + no-machined
# install), the GDM userdb socket peer-process is xdm_t directly.
# Path observed: /run/systemd/userdb/org.gnome.DisplayManager
# Security: usbguard already runs as root + CAP_SYS_ADMIN. userdb sockets
# expose user metadata only (UID, GID, home dir, shell) — NO password hashes. Net
# new attack surface: zero meaningful (usbguard could already read /etc/passwd).
allow usbguard_t xdm_t:unix_stream_socket connectto;

# First-boot audit follow-up:
# systemd-logind enumerates /dev/shm during session-tracking + cleanup.
# usbguard-daemon creates /dev/shm/qb-NNNN-NNNN-NN-XXXXX/ subdirs for libqb
# IPC (3 dirs per IPC channel, labeled usbguard_tmpfs_t). systemd-logind's
# session-state-walker calls stat() (= getattr) AND opendir() (= read) on
# these dirs → SELinux default-policy denies both perms.
#
# `read` is required on top of `getattr`: logind's opendir-style
# enumeration of these dirs is denied without it.
#
# The full `{ getattr read open search }` bundle is granted in one shot:
# the kernel logs only the NEXT required perm once previous perms are
# allowed, so granting one-at-a-time just surfaces another denial after
# each reboot. Bundling the complete dir-walk set (stat + readdir + opendir
# + path-traversal) prevents further cascade iterations.
#
# Security: the directory bundle exposes metadata, entry names and traversal,
# but grants no file/socket payload access (no file or socket class permission).
# Logind already enumerates other tmpfs subdirs via default policy; this rule
# extends that bounded directory-walk capability to usbguard_tmpfs_t.
allow systemd_logind_t usbguard_tmpfs_t:dir { getattr read open search };

# AIDE getattr on /boot/efi dosfs_t:
# M13 explicitly content-tracks /boot/efi with a VFAT-safe ESP rule (content,
# size and portable metadata; no inode/ACL/xattr assumptions). Secure Boot is
# complementary and is not a substitute for local change evidence. AIDE's
# directory walker performs statfs() on the /boot/efi mount point at scan
# start to identify filesystem semantics. The
# statfs() call lands at aide_t→dosfs_t:filesystem getattr check, which
# default Fedora SELinux policy denies. That denial is not classified as
# harmless because it can impair evidence collection on an actively tracked
# security-relevant filesystem.
#
# Granting `getattr` on dosfs_t:filesystem enables that bounded query without
# expanding AIDE's read scope: getattr returns filesystem statistics
# (block count, free space, fs type), not file contents. File reads remain
# governed separately by the distro policy and the explicit M13 ESP rule.
allow aide_t dosfs_t:filesystem getattr;

# Yescrypt private HugeTLB work-area mapping:
# Fedora 44 uses libxcrypt Yescrypt for local password creation, password
# history maintenance and verification. libxcrypt 4.5.2 requests a private
# read/write anonymous HugeTLB mapping for sufficiently large work areas and
# falls back to ordinary anonymous memory when that request fails. SELinux
# represents the successful HugeTLB path as hugetlbfs_t:file read, write and
# map checks. Granting only map leaves a real denial cascade: passwd_t and
# chkpwd_t next require read/write, while the password-history helper updpwd_t
# requires map/read/write. The exact three-domain permission set below was
# verified with a real password change and a fresh sudo authentication: it
# produced no new AVC event.
#
# This grants only the three access operations needed for the private work-area
# mapping. It grants no create, unlink, rename, relabel, execute or directory
# permission and does not broaden a shared user/authentication attribute. Keep
# all three password domains explicit so unrelated domains receive no access.
allow passwd_t hugetlbfs_t:file { read write map };
allow chkpwd_t hugetlbfs_t:file { read write map };
allow updpwd_t hugetlbfs_t:file { read write map };
NOID_TE_EOF

# Compile, package, install and bind the selected module store entry to these
# exact generated bytes. Every tool and transaction is load-bearing.
for tool in checkmodule semodule_package semodule sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "  [FAIL] required SELinux module tool missing: $tool"
        exit 1
    }
done
[ -x /usr/libexec/selinux/hll/pp ] || {
    echo "  [FAIL] SELinux pp-to-CIL checksum translator missing"
    exit 1
}

if ! checkmodule -E -M -m -o "$NOID_SE_DIR/noid-selinux-fixes.mod" \
        "$NOID_SE_DIR/noid-selinux-fixes.te"; then
    echo "  [FAIL] checkmodule rejected noid-selinux-fixes.te"
    exit 1
fi
if ! semodule_package -o "$NOID_SE_DIR/noid-selinux-fixes.pp" \
        -m "$NOID_SE_DIR/noid-selinux-fixes.mod"; then
    echo "  [FAIL] semodule_package rejected noid-selinux-fixes.mod"
    exit 1
fi
chmod 0644 "$NOID_SE_DIR/noid-selinux-fixes.te" \
    "$NOID_SE_DIR/noid-selinux-fixes.pp"
chown root:root "$NOID_SE_DIR/noid-selinux-fixes.te" \
    "$NOID_SE_DIR/noid-selinux-fixes.pp"
cat > "$NOID_SE_DIR/noid-selinux-policy-reconcile" <<'NOID_SELINUX_RECONCILE_EOF'
#!/bin/bash
# Recommit NoID Privacy's retained local module against the newly installed Fedora
# targeted policy. Fedora's policy RPM rebuild suppresses semodule stderr and
# does not bind that rebuild's status to the RPM transaction. This helper is
# the fail-closed package-update boundary for removed/renamed policy symbols.
set -euo pipefail

POLICY_DIR=/var/lib/noid-privacy/selinux
MODULE_TE=$POLICY_DIR/noid-selinux-fixes.te
MODULE_PP=$POLICY_DIR/noid-selinux-fixes.pp
MODULE_NAME=noid-selinux-fixes
MODULE_PRIORITY=400

fail() {
    printf 'ERROR: noid-selinux-policy-reconcile: %s\n' "$*" >&2
    exit 1
}

[ "$EUID" -eq 0 ] || fail "root privileges are required"
[ ! -L "$POLICY_DIR" ] \
    && [ "$(/usr/bin/stat -c '%U:%G:%a' "$POLICY_DIR" 2>/dev/null || true)" = root:root:755 ] \
    || fail "retained policy directory metadata is invalid"
for retained in "$MODULE_TE" "$MODULE_PP"; do
    [ -f "$retained" ] && [ ! -L "$retained" ] \
        && [ "$(/usr/bin/stat -c '%U:%G:%a' "$retained" 2>/dev/null || true)" = root:root:644 ] \
        || fail "retained policy payload metadata is invalid: $retained"
done
/usr/bin/grep -qxF 'module noid-selinux-fixes 1.9;' "$MODULE_TE" \
    || fail "retained policy source version is invalid"
/usr/bin/grep -qE 'unconfined_t|user_tmp_t|execmod' "$MODULE_TE" \
    && fail "retained policy source contains a forbidden broad grant"

for tool in /usr/bin/awk /usr/bin/checkmodule /usr/bin/grep /usr/bin/mktemp \
            /usr/bin/rm /usr/bin/semodule /usr/bin/semodule_package \
            /usr/bin/sha256sum /usr/bin/stat; do
    [ -x "$tool" ] || fail "required tool is unavailable: $tool"
done
[ -x /usr/libexec/selinux/hll/pp ] \
    || fail "SELinux pp-to-CIL checksum translator is unavailable"

expected_checksum=$(
    /usr/libexec/selinux/hll/pp "$MODULE_PP" | \
        /usr/bin/sha256sum | /usr/bin/awk '{print "sha256:" $1}'
) || fail "cannot derive the retained module checksum"
[ -n "$expected_checksum" ] || fail "retained module checksum is empty"

umask 077
work_dir=$(/usr/bin/mktemp -d /run/noid-selinux-reconcile.XXXXXX) \
    || fail "cannot create the private compile workspace"
cleanup() {
    case "$work_dir" in
        /run/noid-selinux-reconcile.*) /usr/bin/rm -rf -- "$work_dir" ;;
    esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/checkmodule -E -M -m -o "$work_dir/noid-selinux-fixes.mod" \
    "$MODULE_TE" || fail "retained policy source no longer compiles"
/usr/bin/semodule_package -o "$work_dir/noid-selinux-fixes.pp" \
    -m "$work_dir/noid-selinux-fixes.mod" \
    || fail "cannot package the retained policy source"
source_checksum=$(
    /usr/libexec/selinux/hll/pp "$work_dir/noid-selinux-fixes.pp" | \
        /usr/bin/sha256sum | /usr/bin/awk '{print "sha256:" $1}'
) || fail "cannot derive the compiled source checksum"
[ "$source_checksum" = "$expected_checksum" ] \
    || fail "retained policy source and package are not byte-equivalent CIL"

# Installing the exact package forces libsemanage to resolve and commit it
# against the current base policy. A removed type/class therefore fails this
# command instead of leaving update success to be inferred from stale state.
/usr/bin/semodule -X "$MODULE_PRIORITY" -i "$MODULE_PP" \
    || fail "module commit against the current targeted policy failed"

module_records=$(
    /usr/bin/semodule -lfull -m | \
        /usr/bin/awk -v name="$MODULE_NAME" '$2 == name {print}'
) || fail "cannot inspect the selected module store"
[ "$(printf '%s\n' "$module_records" | /usr/bin/grep -c . || true)" -eq 1 ] \
    || fail "module-store entry is missing or shadowed"
read -r module_priority module_name module_lang module_checksum module_extra \
    <<< "$module_records"
[ "$module_priority" = "$MODULE_PRIORITY" ] \
    && [ "$module_name" = "$MODULE_NAME" ] \
    && [ "$module_lang" = pp ] \
    && [ "$module_checksum" = "$expected_checksum" ] \
    && [ -z "${module_extra:-}" ] \
    || fail "selected module priority/type/checksum is not exact"

printf 'OK: %s reconciled at priority %s with exact retained checksum\n' \
    "$MODULE_NAME" "$MODULE_PRIORITY"
NOID_SELINUX_RECONCILE_EOF
install -o root -g root -m 0755 \
    "$NOID_SE_DIR/noid-selinux-policy-reconcile" \
    /usr/local/sbin/noid-selinux-policy-reconcile
rm -f "$NOID_SE_DIR/noid-selinux-policy-reconcile"
/usr/bin/restorecon -F /usr/local/sbin/noid-selinux-policy-reconcile
/usr/bin/matchpathcon -V /usr/local/sbin/noid-selinux-policy-reconcile \
    >/dev/null

install -d -o root -g root -m 0755 /etc/dnf/libdnf5-plugins/actions.d
cat > "$NOID_SE_DIR/noid-selinux-policy.actions" <<'NOID_SELINUX_ACTION_EOF'
post_transaction:selinux-policy-targeted:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-selinux-policy-reconcile\ >/dev/null
NOID_SELINUX_ACTION_EOF
install -o root -g root -m 0644 \
    "$NOID_SE_DIR/noid-selinux-policy.actions" \
    /etc/dnf/libdnf5-plugins/actions.d/noid-selinux-policy.actions
rm -f "$NOID_SE_DIR/noid-selinux-policy.actions"
/usr/bin/restorecon -F \
    /etc/dnf/libdnf5-plugins/actions.d/noid-selinux-policy.actions
/usr/bin/matchpathcon -V \
    /etc/dnf/libdnf5-plugins/actions.d/noid-selinux-policy.actions >/dev/null

# The installed helper is the runtime package-update boundary. Do not execute
# that bin_t helper from Anaconda's kernel_t kickstart runner: the intermediate
# kernel_generic_helper_t domain cannot transition to semanage_t and a full
# store commit then emits tens of thousands of permissive installer AVCs. The
# initial compose path already owns the freshly compiled package, so install it
# directly from the kickstart runner (the same quiet native path used before
# the runtime reconciler was added) and verify the selected store entry here.
expected_module_checksum=$(
    /usr/libexec/selinux/hll/pp "$NOID_SE_DIR/noid-selinux-fixes.pp" | \
        /usr/bin/sha256sum | /usr/bin/awk '{print "sha256:" $1}'
) || {
    echo "  [FAIL] cannot derive the expected installed-module checksum"
    exit 1
}
[ -n "$expected_module_checksum" ] || {
    echo "  [FAIL] expected installed-module checksum is empty"
    exit 1
}
if ! /usr/bin/semodule -X 400 -i "$NOID_SE_DIR/noid-selinux-fixes.pp"; then
    echo "  [FAIL] semodule could not commit noid-selinux-fixes at priority 400"
    exit 1
fi
module_records=$(
    /usr/bin/semodule -lfull -m | \
        /usr/bin/awk '$2 == "noid-selinux-fixes" {print}'
) || {
    echo "  [FAIL] cannot inspect the selected SELinux module store"
    exit 1
}
[ "$(printf '%s\n' "$module_records" | /usr/bin/grep -c . || true)" -eq 1 ] || {
    echo "  [FAIL] noid-selinux-fixes has a missing or shadowed module-store entry"
    exit 1
}
read -r module_priority module_name module_lang module_checksum module_extra \
    <<< "$module_records"
if [ "$module_priority" != 400 ] \
   || [ "$module_name" != noid-selinux-fixes ] \
   || [ "$module_lang" != pp ] \
   || [ "$module_checksum" != "$expected_module_checksum" ] \
   || [ -n "${module_extra:-}" ]; then
    echo "  [FAIL] selected noid-selinux-fixes checksum/priority/type is not exact"
    exit 1
fi
rm -f "$NOID_SE_DIR/noid-selinux-fixes.mod"
echo "  [OK] noid-selinux-fixes v1.9 installed byte-exactly with fail-closed policy-update reconciliation"

# ----------------------------------------------------------------------------
# Step 4: Fedora audit.rules gotcha fix
# ----------------------------------------------------------------------------
# Fedora ships /etc/audit/rules.d/audit.rules with:
#   ## First rule - delete all
#   -D
#   ## Feature bitmask
#   -a task,never              <-- CRITICAL: DISABLES ALL SYSCALL AUDITING
#   ## Increase the buffers
#   -b 8192
# The '-a task,never' line prevents ANY task-event auditing. All our
# 99-hardening.rules would LOAD but NEVER FIRE. Known Fedora gotcha,
# documented in author's hardening reference (12-selinux-auditd.md section 2.3).
#
# Fix: replace the entire file with just '-D' (clear rules on startup).
# Our buffer size (-b 8192) and failure mode (-f 1) are set in 99-hardening.rules.
echo ""
echo "[Step 4] Fedora audit.rules gotcha fix (-a task,never removed)"

cat > /etc/audit/rules.d/audit.rules <<'EOF'
## NoID Privacy — audit.rules startup clear (Module 12)
## Fedora default contains "-a task,never" which DISABLES all syscall auditing.
## This file only clears rules on startup. Real rules live in 99-hardening.rules.
-D
EOF
chmod 640 /etc/audit/rules.d/audit.rules
chown root:root /etc/audit/rules.d/audit.rules
echo "  [OK] /etc/audit/rules.d/audit.rules set to just '-D'"

# ----------------------------------------------------------------------------
# Step 5: /etc/audit/auditd.conf (full hardened replacement)
# ----------------------------------------------------------------------------
# Base: Fedora 44 default + explicit evidence-preservation policy:
#   - dispatcher q_depth stays at its vendor default 2000; it is not the
#     kernel audit backlog. The image has no active plugin by default; the
#     reviewed notification plugin joins this queue only after explicit opt-in
#   - max_log_file 64 × num_logs 10 is a measured 640-MiB rolling ceiling,
#     not a claim of 30 complete days
# All other 30+ parameters kept at Fedora defaults (sensible for desktop).
echo ""
echo "[Step 5] /etc/audit/auditd.conf full hardened replacement"

cat > /usr/local/sbin/noid-audit-space-alert <<'AUDIT_SPACE_ALERT_EOF'
#!/bin/bash
# Invoked synchronously by auditd at its installed-system 8-GiB low-space
# watermark or the Live-only 15-percent watermark.
# auditd pauses disk logging while an EXEC action runs, so keep this local,
# bounded and allocation-light, publish boot-scoped state, then always request
# resume. The later 4-GiB critical-suspend and disk-full rotate actions
# remain owned by auditd.conf and cannot be cleared by this helper.
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$#" -ne 0 ]; then
    echo "ERROR: noid-audit-space-alert accepts no arguments" >&2
    exit 2
fi
umask 077

MARKER=/run/noid-privacy/audit-storage-degraded
LOG_TAG=noid-audit-storage
rc=0

# M05's /etc/tmpfiles.d/noid-runtime.conf boot-creates this directory. The
# helper runs in auditd_t (bin_t + execute_no_trans from auditd), and the
# Fedora 44 targeted policy grants auditd_t no setattr/add_name/create on
# var_lib_t, so `install -d` on /var/lib/noid-privacy failed with EACCES and
# short-circuited every marker step below -- the notification, noid-status and
# the M25 login re-nag then all reported a healthy audit store while auditd had
# actually suspended logging. auditd_t does hold
# `allow auditd_t var_run_t:dir { add_name remove_name write }` plus a
# `type_transition auditd_t var_run_t:file auditd_var_run_t`, so publishing here
# needs no policy grant at all. Verify the directory rather than creating it:
# creating or chmod-ing it is exactly what auditd_t may not do.
[ -d /run/noid-privacy ] && [ ! -L /run/noid-privacy ] || rc=1
if [ "$rc" -eq 0 ]; then
    marker_tmp=$(mktemp /run/noid-privacy/.audit-storage-degraded.XXXXXX) \
        || rc=1
fi
if [ "$rc" -eq 0 ]; then
    {
        printf 'status=degraded\n'
        printf 'reason=auditd-space-left\n'
        printf 'detected_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'remediation=free-space-then-review-and-remove-this-marker\n'
    } > "$marker_tmp" || rc=1
fi
if [ "$rc" -eq 0 ]; then
    chmod 0600 "$marker_tmp" \
        && chown root:root "$marker_tmp" \
        && mv -fT "$marker_tmp" "$MARKER" \
        && sync -- "$MARKER" /run/noid-privacy || rc=1
fi
if [ "${marker_tmp:-}" != "" ] && [ -e "$marker_tmp" ]; then
    rm -f -- "$marker_tmp" || true
fi

logger -p auth.alert -t "$LOG_TAG" \
    "AUDIT STORAGE DEGRADED: low free space; marker=$MARKER" || rc=1
if command -v wall >/dev/null 2>&1; then
    printf '%s\n' \
        'NoID Privacy SECURITY ALERT: audit storage is low.' \
        "Inspect $MARKER and free space immediately." | \
        timeout 5 wall --nobanner >/dev/null 2>&1 || true
fi

# auditd documents that an EXEC action suspends logging until an explicit
# resume signal. A failed resume is fatal and remains visible to the daemon.
#
# The signal is sent directly rather than through auditctl. auditd EXECs this
# helper without a domain transition, so it runs in auditd_t; /usr/bin/auditctl
# carries auditctl_exec_t, and the Fedora 44 targeted policy grants auditd_t
# neither `execute` on that type nor a transition to auditctl_t. `auditctl
# --signal resume` therefore failed with EACCES on an enforcing installation
# and auditd stayed suspended until someone ran auditctl by hand from an
# unconfined shell -- the advertised immutable evidence stream was silently
# dead in the meantime.
#
# Nothing is lost by signalling directly: auditctl(8) lists resume as the
# friendly name for USR2, and auditd(8) documents SIGUSR2 as "attempt to resume
# logging and passing events to plugins". auditd_t already holds
# `allow auditd_t auditd_t:process { ... signal ... }`, so this needs no policy
# grant. auditd is this helper's own parent; confirm that before signalling so
# a re-parented process can never receive USR2 by mistake.
resume_target=$PPID
if [ "$(cat "/proc/$resume_target/comm" 2>/dev/null || true)" != auditd ] \
   || ! kill -USR2 "$resume_target" 2>/dev/null; then
    logger -p auth.alert -t "$LOG_TAG" \
        'CRITICAL: auditd resume signal failed after low-space alert' || true
    exit 1
fi
[ "$rc" -eq 0 ]
AUDIT_SPACE_ALERT_EOF
chmod 0755 /usr/local/sbin/noid-audit-space-alert
chown root:root /usr/local/sbin/noid-audit-space-alert
/usr/bin/restorecon -F /usr/local/sbin/noid-audit-space-alert
/usr/bin/matchpathcon -V /usr/local/sbin/noid-audit-space-alert >/dev/null

cat > /usr/local/sbin/noid-audit-space-critical <<'AUDIT_SPACE_CRITICAL_EOF'
#!/bin/bash
# Invoked synchronously by auditd at the emergency watermark (4 GiB installed,
# 10 percent Live) or on an audit-log device error. Owner decision 2026-07-16:
# the desktop never drops to single-user or halts over audit storage — on this
# image root is locked and rescue has no shell, so SINGLE was a dead end, not
# a recovery path. auditd suspends disk logging while an EXEC action runs and
# this helper deliberately sends NO resume signal: logging stays in auditd's
# documented suspended state while the session survives. The marker,
# wall, auth.alert and the M12 path-unit notifier make that state loud; after
# freeing space the user resumes capture with `sudo auditctl --signal resume`.
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$#" -ne 0 ]; then
    echo "ERROR: noid-audit-space-critical accepts no arguments" >&2
    exit 2
fi
umask 077

MARKER=/run/noid-privacy/audit-storage-degraded
LOG_TAG=noid-audit-storage
rc=0

# M05's /etc/tmpfiles.d/noid-runtime.conf boot-creates this directory. The
# helper runs in auditd_t (bin_t + execute_no_trans from auditd), and the
# Fedora 44 targeted policy grants auditd_t no setattr/add_name/create on
# var_lib_t, so `install -d` on /var/lib/noid-privacy failed with EACCES and
# short-circuited every marker step below -- the notification, noid-status and
# the M25 login re-nag then all reported a healthy audit store while auditd had
# actually suspended logging. auditd_t does hold
# `allow auditd_t var_run_t:dir { add_name remove_name write }` plus a
# `type_transition auditd_t var_run_t:file auditd_var_run_t`, so publishing here
# needs no policy grant at all. Verify the directory rather than creating it:
# creating or chmod-ing it is exactly what auditd_t may not do.
[ -d /run/noid-privacy ] && [ ! -L /run/noid-privacy ] || rc=1
if [ "$rc" -eq 0 ]; then
    marker_tmp=$(mktemp /run/noid-privacy/.audit-storage-degraded.XXXXXX) \
        || rc=1
fi
if [ "$rc" -eq 0 ]; then
    {
        printf 'status=critical\n'
        printf 'reason=auditd-admin-space-or-disk-error\n'
        printf 'audit_logging=suspended\n'
        printf 'detected_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'remediation=free-space-then-sudo-auditctl-signal-resume-then-review-and-remove-this-marker\n'
    } > "$marker_tmp" || rc=1
fi
if [ "$rc" -eq 0 ]; then
    chmod 0600 "$marker_tmp" \
        && chown root:root "$marker_tmp" \
        && mv -fT "$marker_tmp" "$MARKER" \
        && sync -- "$MARKER" /run/noid-privacy || rc=1
fi
if [ "${marker_tmp:-}" != "" ] && [ -e "$marker_tmp" ]; then
    rm -f -- "$marker_tmp" || true
fi

logger -p auth.alert -t "$LOG_TAG" \
    "AUDIT STORAGE CRITICAL: audit logging SUSPENDED (no resume by design); marker=$MARKER" || rc=1
if command -v wall >/dev/null 2>&1; then
    printf '%s\n' \
        'NoID Privacy SECURITY ALERT: audit storage critical — audit logging is SUSPENDED.' \
        "Free disk space, then resume evidence capture: sudo auditctl --signal resume. Inspect $MARKER." | \
        timeout 5 wall --nobanner >/dev/null 2>&1 || true
fi
[ "$rc" -eq 0 ]
AUDIT_SPACE_CRITICAL_EOF
chmod 0755 /usr/local/sbin/noid-audit-space-critical
chown root:root /usr/local/sbin/noid-audit-space-critical
/usr/bin/restorecon -F /usr/local/sbin/noid-audit-space-critical
/usr/bin/matchpathcon -V /usr/local/sbin/noid-audit-space-critical >/dev/null

cat > /etc/audit/auditd.conf <<'EOF'
# NoID Privacy — auditd daemon configuration (Module 12)
# Design rationale captured inline per-section below.
# Base: Fedora 44 default + hardening + research upgrades.

## === Event source ===
local_events = yes
write_logs = yes

## === Log file ===
log_file = /var/log/audit/audit.log
log_group = root
## ENRICHED: human-readable records (names instead of UIDs in log)
log_format = ENRICHED

## === Event flushing ===
freq = 50
## INCREMENTAL_ASYNC: async flushing with periodic fsync (performance + safety)
flush = INCREMENTAL_ASYNC

## === Log rotation ===
## 64 MiB per file × 10 files = a bounded 640-MiB rolling audit window.
## The audited 2026-07-12/13 workstation workload filled roughly 550 MiB in
## about 31 hours; rule completeness and workload can shorten the window.
## M42 forces a daily rotation and removes copies older than 30 days, so 30
## days is a maximum age, never a promise that every event survives 30 days.
max_log_file = 64
num_logs = 10
max_log_file_action = ROTATE

## === Disk space thresholds ===
## The low watermark runs a bounded local alert helper which atomically writes
## /run/noid-privacy/audit-storage-degraded, emits auth.alert + wall, then
## explicitly resumes auditd. Watermarks are absolute megabytes: the rolling
## ring above is fixed at 640 MiB, so a percentage of the shared Btrfs pool
## would scale the demanded reserve with disk size (10% of 1 TiB is ~100 GiB)
## and trigger the configured low/critical alert actions far too early.
space_left = 8192
space_left_action = EXEC /usr/local/sbin/noid-audit-space-alert
verify_email = yes
action_mail_acct = root

## Emergency watermark and failure actions (owner decision 2026-07-16): the
## desktop stays alive. On this image root is locked and rescue is shell-free,
## so SINGLE/HALT were dead ends, not recovery paths. The critical helper
## records boot-scoped state, alerts every channel and deliberately sends no
## resume — auditd's documented EXEC-without-resume suspended state. A full
## log device rotates the bounded 640-MiB ring (oldest file is overwritten)
## instead of halting. Named trade-off: filling the disk can pause new
## evidence or age out the oldest events; that state is loud (GUI, wall,
## auth.alert, noid-status) and never silent.
admin_space_left = 4096
admin_space_left_action = EXEC /usr/local/sbin/noid-audit-space-critical
disk_full_action = ROTATE
disk_error_action = EXEC /usr/local/sbin/noid-audit-space-critical

## === Process priority ===
priority_boost = 4
name_format = NONE

## === Event dispatcher queue ===
## This is only the audit userspace plugin queue, not the kernel backlog.
## NoID Privacy enables no dispatcher plugin by default, so retain the vendor value.
## The optional auparse notification plugin must keep this queue drained when
## enabled. M01 owns audit_backlog_limit=8192; runtime gates inspect both.
q_depth = 2000
overflow_action = SYSLOG
end_of_event_timeout = 2
max_restarts = 10

## === Network aggregation (desktop: standalone, disabled) ===
## distribute_network = no: this machine doesn't receive audit from other hosts
distribute_network = no
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
transport = TCP
use_libwrap = yes
krb5_principal = auditd

## === Plugin directory ===
plugin_dir = /etc/audit/plugins.d

## === Reporting ===
report_interval = 0
EOF

chmod 640 /etc/audit/auditd.conf
chown root:root /etc/audit/auditd.conf
echo "  [OK] /etc/audit/auditd.conf written (640-MiB rolling window + hard failure policy)"

# The installed-system 8/4-GiB reserves are intentionally absolute: they do
# not scale into a 100-GiB emergency reserve on a large shared Btrfs pool.
# A Live image is a different storage topology. Its writable root is a small,
# ephemeral overlay, so either absolute threshold already exceeds the whole
# filesystem and would immediately trigger the configured alert/suspend actions.
# Use auditd's maintained percentage syntax only when the kernel explicitly
# identifies a Live image. The drop-in runs before auditd reads its config;
# installed boots are a strict no-op and retain the source-owned 8192/4096
# values. A same-directory atomic replacement avoids a partially written
# daemon configuration.
mkdir -p /usr/local/libexec /etc/systemd/system/auditd.service.d
cat > /usr/local/libexec/noid-auditd-live-thresholds <<'AUDITD_LIVE_THRESHOLDS_EOF'
#!/bin/bash
# Select Live-only auditd watermarks before the daemon reads auditd.conf.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$#" -ne 0 ]; then
    echo "ERROR: noid-auditd-live-thresholds accepts no arguments" >&2
    exit 2
fi

if [ "${NOID_AUDITD_THRESHOLD_TEST_MODE:-0}" = 1 ]; then
    test_root=${NOID_AUDITD_THRESHOLD_TEST_ROOT:?test root is required}
    [[ "$test_root" == /* && "$test_root" != / && -d "$test_root" && ! -L "$test_root" ]]
    config="$test_root/etc/audit/auditd.conf"
    cmdline="$test_root/proc/cmdline"
    expected_owner="$(id -u):$(id -g)"
else
    [ "$(id -u)" -eq 0 ]
    config=/etc/audit/auditd.conf
    cmdline=/proc/cmdline
    expected_owner=0:0
fi

[ -f "$cmdline" ] && [ ! -L "$cmdline" ] || {
    echo "noid-auditd-live-thresholds: unsafe or missing kernel cmdline" >&2
    exit 1
}
live_image=0
read -r -a cmdline_tokens < "$cmdline"
for token in "${cmdline_tokens[@]}"; do
    case "$token" in
        rd.live.image|rd.live.image=*) live_image=1 ;;
    esac
done
[ "$live_image" -eq 1 ] || exit 0

[ -f "$config" ] && [ ! -L "$config" ] \
    && [ "$(stat -c '%u:%g:%a' "$config" 2>/dev/null || true)" = \
         "$expected_owner:640" ] || {
    echo "noid-auditd-live-thresholds: auditd.conf type or metadata is unsafe" >&2
    exit 1
}
[ "$(grep -Ec '^space_left[[:space:]]*=' "$config" || true)" -eq 1 ] \
    && [ "$(grep -Ec '^admin_space_left[[:space:]]*=' "$config" || true)" -eq 1 ] || {
    echo "noid-auditd-live-thresholds: watermark fields are not unique" >&2
    exit 1
}
space_value=$(awk -F= '/^space_left[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2}' "$config")
admin_value=$(awk -F= '/^admin_space_left[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2}' "$config")
if [ "$space_value:$admin_value" = 15%:10% ]; then
    exit 0
fi
[ "$space_value:$admin_value" = 8192:4096 ] || {
    echo "noid-auditd-live-thresholds: embedded watermark pair is not exact" >&2
    exit 1
}

config_dir=${config%/*}
temporary=$(mktemp "$config_dir/.auditd.conf.noid-live.XXXXXX")
cleanup() {
    local rc=$?
    trap - EXIT
    rm -f -- "${temporary:-}" || true
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
awk '
    /^space_left[[:space:]]*=/ { print "space_left = 15%"; next }
    /^admin_space_left[[:space:]]*=/ { print "admin_space_left = 10%"; next }
    { print }
' "$config" > "$temporary"
chown "$expected_owner" "$temporary"
chmod 0640 "$temporary"
sync -- "$temporary"
mv -fT -- "$temporary" "$config"
temporary=""
if [ "${NOID_AUDITD_THRESHOLD_TEST_MODE:-0}" != 1 ]; then
    /usr/bin/restorecon -F "$config"
    /usr/bin/matchpathcon -V "$config" >/dev/null
fi
sync -- "$config" "$config_dir"

[ "$(stat -c '%u:%g:%a' "$config")" = "$expected_owner:640" ] \
    && grep -qxF 'space_left = 15%' "$config" \
    && grep -qxF 'admin_space_left = 10%' "$config"
AUDITD_LIVE_THRESHOLDS_EOF
chmod 0755 /usr/local/libexec/noid-auditd-live-thresholds
chown root:root /usr/local/libexec/noid-auditd-live-thresholds

cat > /etc/systemd/system/auditd.service.d/10-noid-live-thresholds.conf <<'AUDITD_LIVE_DROPIN_EOF'
[Service]
# "-" prefix: a non-zero exit (unrecognized watermark pair on a drifted Live
# medium) degrades to stock thresholds instead of aborting auditd startup.
ExecStartPre=-/usr/local/libexec/noid-auditd-live-thresholds
AUDITD_LIVE_DROPIN_EOF
chmod 0644 /etc/systemd/system/auditd.service.d/10-noid-live-thresholds.conf
chown root:root /etc/systemd/system/auditd.service.d/10-noid-live-thresholds.conf
echo "  [OK] auditd Live-only 15/10-percent pre-start selector installed"

# Storage-degradation visibility: the marker is written from auditd's
# EXEC context, which must stay bounded and cannot reach user sessions. A path
# unit watches the marker via inotify (event-driven, no polling daemon) and a
# oneshot service — ordinary init context, SELinux-clean — delivers one
# persistent critical notification only to unlocked active local graphical
# sessions (M19's reviewed session-notify pattern). PathModified fires on each
# atomic marker replacement; the pre-existing-marker-at-boot case is covered by
# M25 login-time re-nag instead of a PathExists steady-state retrigger loop.
cat > /usr/local/libexec/noid-audit-storage-notify <<'AUDIT_STORAGE_NOTIFY_EOF'
#!/bin/bash
# Notify each unlocked active local graphical user once about marker state.
set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH LANG=C.UTF-8 LC_ALL=C.UTF-8
if [ "$#" -ne 0 ]; then
    echo "ERROR: noid-audit-storage-notify accepts no arguments" >&2
    exit 2
fi
umask 077

MARKER=/run/noid-privacy/audit-storage-degraded
if [ ! -e "$MARKER" ] && [ ! -L "$MARKER" ]; then
    exit 0
fi
[ -f "$MARKER" ] && [ ! -L "$MARKER" ] \
    && [ "$(stat -c '%U:%G:%a:%h' "$MARKER" 2>/dev/null || true)" = \
         root:root:600:1 ] || {
    logger -p auth.alert -t noid-audit-storage \
        "refusing unsafe audit-storage marker metadata: $MARKER"
    exit 1
}
mapfile -t marker_states < <(sed -n 's/^status=//p' "$MARKER")
[ "${#marker_states[@]}" -eq 1 ] \
    && [[ "${marker_states[0]}" =~ ^(degraded|critical)$ ]] || {
    logger -p auth.alert -t noid-audit-storage \
        "refusing malformed audit-storage marker state: $MARKER"
    exit 1
}
status=${marker_states[0]}
if [ "$status" = critical ]; then
    title="Audit storage CRITICAL — audit logging suspended"
    body="Free disk space now, then resume evidence capture: sudo auditctl --signal resume. Details: noid-status"
else
    title="Audit storage low — free disk space"
    body="The audit reserve is nearly used up. Free disk space now to keep evidence capture running. Details: noid-status"
fi

sessions_json=$(
    /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
        /usr/bin/loginctl list-sessions --json=short
)
session_rows=$(
    /usr/bin/python3 -c '
import json
import sys

rows = json.load(sys.stdin)
if not isinstance(rows, list):
    raise SystemExit("loginctl JSON is not a list")
for row in rows:
    if not isinstance(row, dict):
        continue
    session = row.get("session")
    uid = row.get("uid")
    if isinstance(session, (str, int)) and isinstance(uid, int):
        print(f"{session}\t{uid}")
' <<< "$sessions_json"
)

property_value() {
    local property=$1 data=$2 values
    values=$(printf '%s\n' "$data" | sed -n "s/^${property}=//p")
    [ "$(printf '%s\n' "$values" | grep -c . || true)" -eq 1 ] || return 1
    printf '%s\n' "$values"
}

declare -A notified_uids=()
delivery_failed=0
while IFS=$'\t' read -r session uid extra; do
    [ -z "${extra:-}" ] || continue
    [[ "$session" =~ ^[[:alnum:]_.-]{1,128}$ ]] || continue
    [[ "$uid" =~ ^[0-9]+$ ]] \
        && [ "$uid" -ge 1000 ] \
        && [ "$uid" -le 4294967294 ] || continue
    [ -z "${notified_uids[$uid]:-}" ] || continue

    properties=$(
        /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
            /usr/bin/loginctl show-session "$session" \
            --property=User --property=Seat --property=Remote \
            --property=Class --property=Type --property=State \
            --property=Active --property=LockedHint
    ) || continue
    session_uid=$(property_value User "$properties") || continue
    seat=$(property_value Seat "$properties") || continue
    remote=$(property_value Remote "$properties") || continue
    session_class=$(property_value Class "$properties") || continue
    session_type=$(property_value Type "$properties") || continue
    session_state=$(property_value State "$properties") || continue
    active=$(property_value Active "$properties") || continue
    locked=$(property_value LockedHint "$properties") || continue
    [ "$session_uid" = "$uid" ] \
        && [[ "$seat" =~ ^[[:alnum:]_.-]{1,128}$ ]] \
        && [ "$remote" = no ] \
        && [ "$session_class" = user ] \
        && [[ "$session_type" =~ ^(wayland|x11)$ ]] \
        && [ "$session_state" = active ] \
        && [ "$active" = yes ] \
        && [ "$locked" = no ] || continue
    active_session=$(
        /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
            /usr/bin/loginctl show-seat "$seat" \
            --property=ActiveSession --value
    ) || continue
    [ "$active_session" = "$session" ] || continue

    passwd_record=$(
        /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
            /usr/bin/getent passwd "$uid"
    ) || continue
    [ "$(printf '%s\n' "$passwd_record" | grep -c . || true)" -eq 1 ] \
        || continue
    IFS=: read -r user _ account_uid gid _ home shell extra \
        <<< "$passwd_record"
    [ -z "${extra:-}" ] \
        && [ "$user" != root ] \
        && [ "$account_uid" = "$uid" ] \
        && [[ "$gid" =~ ^[0-9]+$ ]] \
        && [ -n "$home" ] \
        && [ -n "$shell" ] || continue
    runtime=/run/user/$uid
    bus=$runtime/bus
    bus_status=$(
        /usr/bin/setpriv --reuid="$uid" --regid="$gid" --init-groups \
            --reset-env /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
            /usr/bin/stat -c '%F:%u' "$bus" 2>/dev/null
    ) || continue
    [ "$bus_status" = "socket:$uid" ] || continue

    if /usr/bin/setpriv --reuid="$uid" --regid="$gid" --init-groups \
        --reset-env /usr/bin/timeout --signal=TERM --kill-after=1s 5s \
        /usr/bin/env \
        "HOME=$home" "XDG_RUNTIME_DIR=$runtime" \
        "DBUS_SESSION_BUS_ADDRESS=unix:path=$bus" \
        /usr/bin/notify-send --urgency=critical --icon=drive-harddisk \
        --app-name="NoID Privacy" --expire-time=0 -- "$title" "$body"; then
        notified_uids["$uid"]=1
    else
        logger -p auth.alert -t noid-audit-storage \
            "notification delivery failed for local uid=$uid session=$session"
        delivery_failed=1
    fi
done <<< "$session_rows"
exit "$delivery_failed"
AUDIT_STORAGE_NOTIFY_EOF
chmod 0755 /usr/local/libexec/noid-audit-storage-notify
chown root:root /usr/local/libexec/noid-audit-storage-notify

cat > /etc/systemd/system/noid-audit-storage-notify.service <<'AUDIT_NOTIFY_SERVICE_EOF'
[Unit]
Description=NoID Privacy — audit storage degradation notifier
Documentation=https://noid-privacy.com

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/noid-audit-storage-notify
TimeoutStartSec=30s
UMask=0077
CapabilityBoundingSet=CAP_SETGID CAP_SETUID
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
InaccessiblePaths=/home /root
ProtectClock=true
ProtectControlGroups=true
ProtectHome=read-only
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProtectSystem=strict
ProcSubset=pid
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
SystemCallArchitectures=native
AUDIT_NOTIFY_SERVICE_EOF

cat > /etc/systemd/system/noid-audit-storage-notify.path <<'AUDIT_NOTIFY_PATH_EOF'
[Unit]
Description=NoID Privacy — watch the audit-storage marker
Documentation=https://noid-privacy.com

[Path]
PathModified=/run/noid-privacy/audit-storage-degraded

[Install]
WantedBy=multi-user.target
AUDIT_NOTIFY_PATH_EOF
chmod 0644 /etc/systemd/system/noid-audit-storage-notify.service \
    /etc/systemd/system/noid-audit-storage-notify.path
chown root:root /etc/systemd/system/noid-audit-storage-notify.service \
    /etc/systemd/system/noid-audit-storage-notify.path
/usr/bin/restorecon -F /usr/local/libexec/noid-audit-storage-notify \
    /etc/systemd/system/noid-audit-storage-notify.service \
    /etc/systemd/system/noid-audit-storage-notify.path
/usr/bin/matchpathcon -V /usr/local/libexec/noid-audit-storage-notify \
    /etc/systemd/system/noid-audit-storage-notify.service \
    /etc/systemd/system/noid-audit-storage-notify.path >/dev/null
systemctl enable noid-audit-storage-notify.path 2>&1 | sed 's/^/  /'
echo "  [OK] audit-storage visibility notifier installed (inotify path unit)"

# Event notification delivery uses the identical split, and for the identical
# reason. auditd execve()s /usr/local/bin/audit-notify.sh from bin_t with
# execute_no_trans, so the plugin runs in auditd_t. Verified against the
# installed targeted policy: auditd_t holds `capability { audit_control
# audit_write chown fsetid net_bind_service setpcap sys_nice sys_resource }`
# with no setuid/setgid, and /run/user/<uid>/bus is session_dbusd_tmp_t, for
# which auditd_t has neither sock_file access nor connectto on the session bus
# daemon. setpriv changes credentials, not the SELinux domain, so granting the
# two capabilities would only move the failure one step later — the delivery
# path cannot live in auditd_t at all. The plugin therefore queues bounded
# requests under /run/noid-privacy/audit-notify.d and this drain owns the
# session gauntlet and the setpriv route in ordinary init context.
# DirectoryNotEmpty= is level-triggered, so a request that arrives while the
# drain already runs re-triggers the unit instead of being lost, which an
# edge-triggered PathModified= on a single request file could not guarantee.
cat > /usr/local/libexec/noid-audit-event-notify <<'AUDIT_EVENT_NOTIFY_EOF'
#!/usr/bin/python3
"""NoID Privacy audit-event notification delivery.

The auditd-hosted plugin (/usr/local/bin/audit-notify.sh) owns event assembly,
filtering, coalescing and rate limiting, but it cannot deliver anything: auditd
execve()s it without a domain transition, so it runs in auditd_t, which holds
no setuid/setgid capability and no access to a user session bus.  It therefore
queues one bounded request per surviving event under /run/noid-privacy and
noid-audit-event-notify.path starts this drain in ordinary init context, where
the session gauntlet and setpriv route below actually work.

This mirrors the split M12 already uses for the audit-storage marker.  The
session gauntlet is the reviewed one moved out of the plugin unchanged: only
the event AUID's own unlocked, active, local, graphical seat is ever notified.
"""

import json
import os
import pathlib
import pwd
import stat
import subprocess
import sys
import syslog


RUNTIME_DIR = pathlib.Path("/run/noid-privacy")
SPOOL_DIR = RUNTIME_DIR / "audit-notify.d"
# One drain handles at most this many requests.  DirectoryNotEmpty= is level
# triggered, so a longer backlog simply restarts this unit instead of letting a
# single invocation run unbounded.
DRAIN_LIMIT = 64
REQUEST_FIELDS = ("serial", "auid", "key", "command", "path")
FIELD_LIMITS = {"key": 64, "command": 64, "path": 512}
# The spool is produced by root (auditd) and consumed by root (this drain).
# Naming the expected owner lets the behavior fixtures exercise the metadata
# predicates without being root; tests/12 pins these two values structurally so
# the seam cannot silently become a weaker check.
TRUSTED_UID = 0
TRUSTED_GID = 0


def sanitize_text(value, limit=512):
    """Bound untrusted audit text and remove UI control characters."""
    if not value or value in {"(null)", "?"}:
        return ""
    cleaned = "".join(
        ch if ch.isprintable() and ch not in "\r\n" else " " for ch in value
    )
    return " ".join(cleaned.split())[:limit]


def _run(command, timeout=3):
    return subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C.UTF-8"},
    ).stdout


def _properties(session):
    output = _run(
        [
            "/usr/bin/loginctl",
            "show-session",
            session,
            "--property=User",
            "--property=Seat",
            "--property=Remote",
            "--property=Class",
            "--property=Type",
            "--property=State",
            "--property=Active",
            "--property=LockedHint",
        ]
    )
    result = {}
    for line in output.splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            result[name] = value
    return result


def resolve_local_target(uid):
    """Resolve only the event AUID's unlocked active local graphical seat."""
    sessions = json.loads(
        _run(["/usr/bin/loginctl", "list-sessions", "--json=short"])
    )
    saw_locked = False
    for row in sessions:
        session = str(row.get("session", ""))
        if row.get("uid") != uid or not row.get("seat"):
            continue
        if not session or len(session) > 128 or not all(
            character.isalnum() or character in "_.-" for character in session
        ):
            continue
        properties = _properties(session)
        if properties.get("User") != str(uid):
            continue
        if (
            properties.get("Remote") != "no"
            or properties.get("Class") != "user"
        ):
            continue
        if properties.get("Type") not in {"wayland", "x11"}:
            continue
        if (
            properties.get("Active") != "yes"
            or properties.get("State") != "active"
        ):
            continue
        seat = properties.get("Seat", "")
        if not seat or len(seat) > 128 or not all(
            character.isalnum() or character in "_.-" for character in seat
        ):
            continue
        active_session = _run(
            [
                "/usr/bin/loginctl",
                "show-seat",
                seat,
                "--property=ActiveSession",
                "--value",
            ]
        ).strip()
        if active_session != session:
            continue
        if properties.get("LockedHint") != "no":
            saw_locked = True
            continue

        runtime = pathlib.Path(f"/run/user/{uid}")
        bus = runtime / "bus"
        account = pwd.getpwuid(uid)
        # Inspect the bus AS the target user, not as root. The unit keeps only
        # CAP_SETGID/CAP_SETUID, so this process has no CAP_DAC_OVERRIDE and
        # cannot even traverse the 0700 /run/user/<uid> that user owns -- a
        # root lstat() here fails with EACCES on every real desktop. This is
        # the same route the sibling audit-storage notifier uses. `stat` does
        # not dereference without -L, so a symlink still fails closed, and the
        # explicit LC_ALL keeps the translated %F string out of the compare.
        #
        # The watchdog runs INSIDE setpriv, as the target uid. A Python-side
        # `timeout=` cannot police this child: on expiry CPython calls
        # os.kill(SIGKILL), and this process is uid 0 with a bounding set of
        # only CAP_SETGID/CAP_SETUID -- no CAP_KILL -- so signalling a child
        # that already dropped to another uid raises PermissionError out of
        # Popen.__exit__, which then blocks in an unbounded wait(). Verified on
        # a live host: "SIGKILL -> Operation not permitted", child still alive.
        try:
            bus_status = _run(
                [
                    "/usr/bin/setpriv",
                    f"--reuid={uid}",
                    f"--regid={account.pw_gid}",
                    "--init-groups",
                    "--reset-env",
                    "/usr/bin/timeout",
                    "--signal=TERM",
                    "--kill-after=1s",
                    "3s",
                    "/usr/bin/env",
                    "LC_ALL=C.UTF-8",
                    "/usr/bin/stat",
                    "-c",
                    "%F:%u",
                    str(bus),
                ],
                # Outer backstop only, and deliberately longer than the inner
                # 3s + 1s kill-after: if it fired first it would re-enter the
                # unkillable-child path this construction exists to avoid.
                timeout=10,
            ).strip()
        except subprocess.CalledProcessError as error:
            raise RuntimeError("active-session-bus-invalid") from error
        if bus_status != f"socket:{uid}":
            raise RuntimeError("active-session-bus-invalid")
        return {
            "uid": uid,
            "gid": account.pw_gid,
            "home": account.pw_dir,
            "runtime": str(runtime),
            "bus": str(bus),
        }, "ready"
    return None, "locked" if saw_locked else "no-active-local-session"


def deliver_notification(target, event):
    body = f"Check: sudo ausearch -k {event['key']} -ts recent"
    if event["path"]:
        body = f"{event['path']}\n\n{body}"
    # Same reason as the bus probe above: the watchdog has to be inside setpriv
    # so it runs as the target uid and can signal its own child. GNOME Shell's
    # notification service being wedged is an ordinary desktop condition, and
    # without this the drain hangs there until systemd kills the cgroup at
    # TimeoutStartSec -- which skips the finally: that retires the request, so
    # the level-triggered path unit re-triggers on the same file forever.
    command = [
        "/usr/bin/setpriv",
        f"--reuid={target['uid']}",
        f"--regid={target['gid']}",
        "--init-groups",
        "--reset-env",
        "/usr/bin/timeout",
        "--signal=TERM",
        "--kill-after=1s",
        "5s",
        "/usr/bin/env",
        f"HOME={target['home']}",
        f"XDG_RUNTIME_DIR={target['runtime']}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={target['bus']}",
        "/usr/bin/notify-send",
        "--urgency=critical",
        "--icon=dialog-warning",
        "--",
        f"auditd: {event['key']}",
        body,
    ]
    subprocess.run(
        command,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        # Outer backstop only; the inner 5s + 1s kill-after must expire first.
        timeout=12,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C.UTF-8"},
    )


def spool_is_trusted():
    """Refuse to drain anything but a root-owned private directory."""
    try:
        status = SPOOL_DIR.lstat()
    except FileNotFoundError:
        return None
    return (
        stat.S_ISDIR(status.st_mode)
        and status.st_uid == TRUSTED_UID
        and status.st_gid == TRUSTED_GID
        and stat.S_IMODE(status.st_mode) == 0o700
    )


def read_request(path):
    """Parse one spool entry, or raise ValueError if it is not exact."""
    status = path.lstat()
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != TRUSTED_UID
        or status.st_gid != TRUSTED_GID
        or stat.S_IMODE(status.st_mode) != 0o600
        or status.st_nlink != 1
    ):
        raise ValueError("request metadata is not root-owned private regular")
    fields = {}
    with path.open("r", encoding="utf-8") as stream:
        for line in stream.read(8192).splitlines():
            name, separator, value = line.partition("=")
            if not separator or name not in REQUEST_FIELDS or name in fields:
                raise ValueError("request carries an unexpected field")
            fields[name] = value
    if set(fields) != set(REQUEST_FIELDS):
        raise ValueError("request is missing a mandatory field")
    for name in ("serial", "auid"):
        if not fields[name].isdigit():
            raise ValueError(f"{name} is not a plain decimal number")
        fields[name] = int(fields[name], 10)
    if fields["auid"] < 1000 or fields["auid"] > 4294967294:
        raise ValueError("auid is outside the notifiable range")
    for name, limit in FIELD_LIMITS.items():
        fields[name] = sanitize_text(fields[name], limit)
    if not fields["key"]:
        raise ValueError("request carries no audit key")
    return fields


def retire_request(path):
    """Retire one handled entry without aborting the rest of the drain."""
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        # A directory or otherwise unremovable entry is not traversed or
        # recursively deleted.  Keep processing valid requests and leave a
        # precise alert for the operator instead of raising out of an except or
        # finally suite and abandoning the whole spool.
        syslog.syslog(
            syslog.LOG_ALERT,
            "audit notification request retirement failed "
            f"({type(error).__name__})",
        )
        return False
    return True


def main():
    if len(sys.argv) != 1:
        print(
            "ERROR: noid-audit-event-notify accepts no arguments",
            file=sys.stderr,
        )
        return 2
    syslog.openlog("noid-audit-event-notify", syslog.LOG_PID, syslog.LOG_AUTH)
    trusted = spool_is_trusted()
    if trusted is None:
        return 0
    if not trusted:
        # Deliberately leave an untrusted directory untouched: consuming or
        # deleting attacker-controlled entries would turn this closed metadata
        # gate into traversal.  The producer no longer recreates missing parent
        # directories, so this state requires external metadata drift and is
        # surfaced by both this nonzero unit and its LOG_ALERT.
        syslog.syslog(
            syslog.LOG_ALERT,
            f"refusing unsafe audit notification spool metadata: {SPOOL_DIR}",
        )
        return 1
    failed = 0
    for name in sorted(os.listdir(SPOOL_DIR))[:DRAIN_LIMIT]:
        entry = SPOOL_DIR / name
        try:
            event = read_request(entry)
        except (OSError, ValueError, UnicodeDecodeError) as error:
            syslog.syslog(
                syslog.LOG_ALERT,
                f"discarding malformed audit notification request: {error}",
            )
            failed = 1
            if not retire_request(entry):
                failed = 1
            continue
        try:
            target, reason = resolve_local_target(event["auid"])
            if target is None:
                syslog.syslog(
                    syslog.LOG_INFO,
                    f"audit notification not delivered ({reason}): "
                    f"key={event['key']} auid={event['auid']}",
                )
            else:
                deliver_notification(target, event)
        except (
            OSError,
            KeyError,
            ValueError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as error:
            syslog.syslog(
                syslog.LOG_ALERT,
                "audit notification delivery failed "
                f"({type(error).__name__}): key={event['key']} "
                f"auid={event['auid']}",
            )
            failed = 1
        finally:
            # Always retire the request. DirectoryNotEmpty= re-triggers this
            # unit while anything remains, so a retained entry would spin the
            # notifier instead of surfacing the failure the syslog line above
            # already records.
            if not retire_request(entry):
                failed = 1
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
AUDIT_EVENT_NOTIFY_EOF
chmod 0755 /usr/local/libexec/noid-audit-event-notify
chown root:root /usr/local/libexec/noid-audit-event-notify
python3 -c 'path="/usr/local/libexec/noid-audit-event-notify"; compile(open(path, encoding="utf-8").read(), path, "exec")'

cat > /etc/systemd/system/noid-audit-event-notify.service <<'AUDIT_EVENT_SERVICE_EOF'
[Unit]
Description=NoID Privacy — audit event notification delivery
Documentation=https://noid-privacy.com

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/noid-audit-event-notify
TimeoutStartSec=30s
UMask=0077
CapabilityBoundingSet=CAP_SETGID CAP_SETUID
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
InaccessiblePaths=/home /root
ProtectClock=true
ProtectControlGroups=true
ProtectHome=read-only
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProtectSystem=strict
# The drain retires every request it has handled, so unlike the read-only
# storage notifier it needs the shared runtime directory writable. M05's
# noid-runtime.conf boot-creates it; the spool subdirectory below it is created
# by the plugin, where the auditd_t type_transition gives it a label it may
# actually write.
ReadWritePaths=/run/noid-privacy
ProcSubset=pid
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
SystemCallArchitectures=native
AUDIT_EVENT_SERVICE_EOF

cat > /etc/systemd/system/noid-audit-event-notify.path <<'AUDIT_EVENT_PATH_EOF'
[Unit]
Description=NoID Privacy — watch the audit notification spool
Documentation=https://noid-privacy.com

[Path]
DirectoryNotEmpty=/run/noid-privacy/audit-notify.d

[Install]
WantedBy=multi-user.target
AUDIT_EVENT_PATH_EOF
chmod 0644 /etc/systemd/system/noid-audit-event-notify.service \
    /etc/systemd/system/noid-audit-event-notify.path
chown root:root /etc/systemd/system/noid-audit-event-notify.service \
    /etc/systemd/system/noid-audit-event-notify.path
/usr/bin/restorecon -F /usr/local/libexec/noid-audit-event-notify \
    /etc/systemd/system/noid-audit-event-notify.service \
    /etc/systemd/system/noid-audit-event-notify.path
/usr/bin/matchpathcon -V /usr/local/libexec/noid-audit-event-notify \
    /etc/systemd/system/noid-audit-event-notify.service \
    /etc/systemd/system/noid-audit-event-notify.path >/dev/null
# The watcher itself is inert while the opt-in is off: the plugin is the only
# writer of the spool, and it only runs when auditd has the plugin active. An
# armed inotify watch on a directory that never fills costs no execution, which
# is why the storage watcher above is enabled the same unconditional way.
systemctl enable noid-audit-event-notify.path 2>&1 | sed 's/^/  /'
echo "  [OK] audit event notification drain installed (inotify path unit)"

# ----------------------------------------------------------------------------
# Step 6: /etc/audit/rules.d/99-hardening.rules (132 rules + immutable)
# ----------------------------------------------------------------------------
# 132 rules in 33 unique keys (the verify step 10.8 lists all 33; categories
# span identity/auth, kernel state, network + time integrity, user
# activity, storage, cron, banners and the AIDE evidence boundary).
# RULE ORDERING IS CRITICAL: -b/-f first and -e 2 LAST.
echo ""
echo "[Step 6] /etc/audit/rules.d/99-hardening.rules (132 rules)"

# On F44, both /etc/chrony.d and the cron directories below can be absent:
# chrony does not require its optional drop-in directory, while
# cronie/crontabs are excluded from the package set. An audit `-F dir=` rule
# aimed at an absent directory is rejected (kernel: "No such file or
# directory"). auditctl stops there: earlier rules stay active, but every later
# rule including augenrules' trailing `-e 2` is skipped, leaving a partial,
# non-immutable ruleset. Pre-creation therefore remains load-bearing.
# Pre-create every optional target with its final owner-owned mode. M10 owns
# the root-only 0700 policy for the five /etc/cron* directories; applying that
# mode here avoids a temporary 0755 window and removes an ordering dependency
# on M99's later tmpfiles reconciliation. The remaining targets stay 0755.
AUDIT_TARGET_DIRS=(
    '/etc/chrony.d|755'
    '/etc/cron.d|700'
    '/etc/cron.daily|700'
    '/etc/cron.hourly|700'
    '/etc/cron.weekly|700'
    '/etc/cron.monthly|700'
    '/var/spool/cron|755'
    '/var/lib/aide|700'
)
for audit_target_spec in "${AUDIT_TARGET_DIRS[@]}"; do
    IFS='|' read -r audit_target_dir audit_target_mode <<< "$audit_target_spec"
    install -d -o root -g root -m "$audit_target_mode" "$audit_target_dir"
done
unset audit_target_spec audit_target_dir audit_target_mode

cat > /etc/audit/rules.d/99-hardening.rules <<'EOF'
## NoID Privacy — auditd hardening rules (Module 12)
## Design rationale captured inline per-section below.
## 132 rules: every path/dir/syscall rule has an exact b64+b32 pair;
## deprecated -w watch syntax is deliberately absent
## (DISA STIG RHEL 9 + CIS Benchmark + ComplianceAsCode OSPP v4.2 + neo23x0)
##
## Exact path watches also require their expected SELinux object type. Linux
## audit path matching uses the filesystem device + inode, while distinct
## Btrfs subvolumes have independent inode namespaces. Without the type
## conjunct, an unrelated object on a separate subvolume can share that pair
## and generate false evidence. Directory-tree rules use their own scoped
## tree identity and do not need this guard.

## ============================================================================
## Buffer and failure behavior (FIRST)
## ============================================================================
-b 8192
-f 1

## ============================================================================
## === GNOME Session Files ===
## ============================================================================
-a always,exit -F arch=b64 -F dir=/usr/share/gnome-session/sessions -F perm=wa -k gnome_session_files
-a always,exit -F arch=b32 -F dir=/usr/share/gnome-session/sessions -F perm=wa -k gnome_session_files

## ============================================================================
## === Identity & Authentication ===
## ============================================================================
-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -F obj_type=passwd_file_t -k identity
-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -F obj_type=passwd_file_t -k identity
-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -F obj_type=shadow_t -k identity
-a always,exit -F arch=b32 -F path=/etc/shadow -F perm=wa -F obj_type=shadow_t -k identity
-a always,exit -F arch=b64 -F path=/etc/group -F perm=wa -F obj_type=passwd_file_t -k identity
-a always,exit -F arch=b32 -F path=/etc/group -F perm=wa -F obj_type=passwd_file_t -k identity
-a always,exit -F arch=b64 -F path=/etc/gshadow -F perm=wa -F obj_type=shadow_t -k identity
-a always,exit -F arch=b32 -F path=/etc/gshadow -F perm=wa -F obj_type=shadow_t -k identity

## ============================================================================
## === Sudo/Su Configuration ===
## ============================================================================
-a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F obj_type=etc_t -k sudoers
-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F obj_type=etc_t -k sudoers
-a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -k sudoers
-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=wa -k sudoers

## ============================================================================
## === SSH Configuration (server + client, Module 09 cross-ref) ===
## ============================================================================
## Server-side (even though openssh-server removed in Module 09, user may opt-in)
-a always,exit -F arch=b64 -F path=/etc/ssh/sshd_config -F perm=wa -F obj_type=etc_t -k sshd_config
-a always,exit -F arch=b32 -F path=/etc/ssh/sshd_config -F perm=wa -F obj_type=etc_t -k sshd_config
-a always,exit -F arch=b64 -F dir=/etc/ssh/sshd_config.d -F perm=wa -k sshd_config
-a always,exit -F arch=b32 -F dir=/etc/ssh/sshd_config.d -F perm=wa -k sshd_config
## Client-side (NEW 2026 — Module 09 hardened ssh_config.d/99-noid-hardening.conf)
-a always,exit -F arch=b64 -F path=/etc/ssh/ssh_config -F perm=wa -F obj_type=etc_t -k sshd_config
-a always,exit -F arch=b32 -F path=/etc/ssh/ssh_config -F perm=wa -F obj_type=etc_t -k sshd_config
-a always,exit -F arch=b64 -F dir=/etc/ssh/ssh_config.d -F perm=wa -k sshd_config
-a always,exit -F arch=b32 -F dir=/etc/ssh/ssh_config.d -F perm=wa -k sshd_config

## ============================================================================
## === Audit Configuration (protect audit itself) ===
## ============================================================================
-a always,exit -F arch=b64 -F dir=/etc/audit -F perm=wa -k audit_config
-a always,exit -F arch=b32 -F dir=/etc/audit -F perm=wa -k audit_config
## The recursive /etc/audit pair already covers rules.d. Keep this explicit
## same-key pair only as a declarative reviewer marker; first-match evaluation
## means it adds no event or coverage beyond the parent pair.
-a always,exit -F arch=b64 -F dir=/etc/audit/rules.d -F perm=wa -k audit_config
-a always,exit -F arch=b32 -F dir=/etc/audit/rules.d -F perm=wa -k audit_config

## ============================================================================
## === AIDE evidence boundary (Module 13 cross-ref) ===
## ============================================================================
## The reviewed AIDE configuration and trust database are themselves evidence.
## Watch the exact config with its expected SELinux type and the entire
## database directory so candidate, review and committed database replacement
## cannot occur without a durable audit record. This never creates, updates or
## accepts an AIDE baseline.
-a always,exit -F arch=b64 -F path=/etc/aide.conf -F perm=wa -F obj_type=etc_t -k aide_integrity
-a always,exit -F arch=b32 -F path=/etc/aide.conf -F perm=wa -F obj_type=etc_t -k aide_integrity
-a always,exit -F arch=b64 -F dir=/var/lib/aide -F perm=wa -k aide_integrity
-a always,exit -F arch=b32 -F dir=/var/lib/aide -F perm=wa -k aide_integrity

## ============================================================================
## === Kernel Parameters ===
## ============================================================================
-a always,exit -F arch=b64 -F path=/etc/sysctl.conf -F perm=wa -F obj_type=system_conf_t -k sysctl
-a always,exit -F arch=b32 -F path=/etc/sysctl.conf -F perm=wa -F obj_type=system_conf_t -k sysctl
-a always,exit -F arch=b64 -F dir=/etc/sysctl.d -F perm=wa -k sysctl
-a always,exit -F arch=b32 -F dir=/etc/sysctl.d -F perm=wa -k sysctl

## ============================================================================
## === Kernel Modules ===
## ============================================================================
-a always,exit -F arch=b64 -F dir=/etc/modprobe.d -F perm=wa -k modprobe
-a always,exit -F arch=b32 -F dir=/etc/modprobe.d -F perm=wa -k modprobe
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k kernel_modules

## ============================================================================
## === Bootloader & initramfs ===
## ============================================================================
-a always,exit -F arch=b64 -F path=/etc/default/grub -F perm=wa -F obj_type=bootloader_etc_t -k bootloader
-a always,exit -F arch=b32 -F path=/etc/default/grub -F perm=wa -F obj_type=bootloader_etc_t -k bootloader
-a always,exit -F arch=b64 -F dir=/etc/dracut.conf.d -F perm=wa -k bootloader
-a always,exit -F arch=b32 -F dir=/etc/dracut.conf.d -F perm=wa -k bootloader

## ============================================================================
## === Systemd Units ===
## ============================================================================
-a always,exit -F arch=b64 -F dir=/etc/systemd/system -F perm=wa -k systemd
-a always,exit -F arch=b32 -F dir=/etc/systemd/system -F perm=wa -k systemd

## ============================================================================
## === Firewall ===
## ============================================================================
-a always,exit -F arch=b64 -F dir=/etc/firewalld -F perm=wa -k firewall
-a always,exit -F arch=b32 -F dir=/etc/firewalld -F perm=wa -k firewall

## ============================================================================
## === USBGuard (Module 14 cross-ref) ===
## ============================================================================
## Watches /etc/usbguard/ for tampering with daemon config, rule file, or
## IPC access control files. Complements Module 14 runtime event flow via
## AuditBackend=LinuxAudit (which delivers usbguard block/allow events, NOT
## config-file tampering — this rule catches the config-file path).
-a always,exit -F arch=b64 -F dir=/etc/usbguard -F perm=wa -k usbguard_config
-a always,exit -F arch=b32 -F dir=/etc/usbguard -F perm=wa -k usbguard_config

## ============================================================================
## === Network ===
## ============================================================================
-a always,exit -F arch=b64 -F dir=/etc/NetworkManager/system-connections -F perm=wa -k network_config
-a always,exit -F arch=b32 -F dir=/etc/NetworkManager/system-connections -F perm=wa -k network_config

## ============================================================================
## === User Management Binaries ===
## ============================================================================
-a always,exit -F arch=b64 -F path=/usr/sbin/useradd -F perm=x -F obj_type=useradd_exec_t -k user_mgmt
-a always,exit -F arch=b32 -F path=/usr/sbin/useradd -F perm=x -F obj_type=useradd_exec_t -k user_mgmt
-a always,exit -F arch=b64 -F path=/usr/sbin/userdel -F perm=x -F obj_type=useradd_exec_t -k user_mgmt
-a always,exit -F arch=b32 -F path=/usr/sbin/userdel -F perm=x -F obj_type=useradd_exec_t -k user_mgmt
-a always,exit -F arch=b64 -F path=/usr/sbin/usermod -F perm=x -F obj_type=useradd_exec_t -k user_mgmt
-a always,exit -F arch=b32 -F path=/usr/sbin/usermod -F perm=x -F obj_type=useradd_exec_t -k user_mgmt
-a always,exit -F arch=b64 -F path=/usr/sbin/groupadd -F perm=x -F obj_type=groupadd_exec_t -k user_mgmt
-a always,exit -F arch=b32 -F path=/usr/sbin/groupadd -F perm=x -F obj_type=groupadd_exec_t -k user_mgmt
-a always,exit -F arch=b64 -F path=/usr/sbin/groupdel -F perm=x -F obj_type=groupadd_exec_t -k user_mgmt
-a always,exit -F arch=b32 -F path=/usr/sbin/groupdel -F perm=x -F obj_type=groupadd_exec_t -k user_mgmt
-a always,exit -F arch=b64 -F path=/usr/sbin/groupmod -F perm=x -F obj_type=groupadd_exec_t -k user_mgmt
-a always,exit -F arch=b32 -F path=/usr/sbin/groupmod -F perm=x -F obj_type=groupadd_exec_t -k user_mgmt
-a always,exit -F arch=b64 -F path=/usr/sbin/passwd -F perm=x -F obj_type=passwd_exec_t -k user_mgmt
-a always,exit -F arch=b32 -F path=/usr/sbin/passwd -F perm=x -F obj_type=passwd_exec_t -k user_mgmt

## ============================================================================
## === Privilege Escalation ===
## ============================================================================
-a always,exit -F arch=b64 -F path=/usr/bin/sudo -F perm=x -F obj_type=sudo_exec_t -k sudo_usage
-a always,exit -F arch=b32 -F path=/usr/bin/sudo -F perm=x -F obj_type=sudo_exec_t -k sudo_usage
-a always,exit -F arch=b64 -F path=/usr/bin/su -F perm=x -F obj_type=su_exec_t -k su_usage
-a always,exit -F arch=b32 -F path=/usr/bin/su -F perm=x -F obj_type=su_exec_t -k su_usage

## ============================================================================
## === Set-ID privilege transitions initiated by non-system users ===
## ============================================================================
## Record the actual unprivileged-to-root exec transition. The explicit
## sudo/su path rules above, sudo's USER_CMD events and PAM's authentication
## events retain invocation and authentication evidence; logging every later
## root child would only duplicate that evidence and can overwhelm the journal
## during package/initramfs work.
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -k priv_exec
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -k priv_exec

## ============================================================================
## === LUKS/Crypto ===
## ============================================================================
-a always,exit -F arch=b64 -F path=/etc/crypttab -F perm=wa -F obj_type=etc_t -k luks
-a always,exit -F arch=b32 -F path=/etc/crypttab -F perm=wa -F obj_type=etc_t -k luks

## ============================================================================
## === Login & Security Configuration ===
## ============================================================================
-a always,exit -F arch=b64 -F path=/etc/login.defs -F perm=wa -F obj_type=etc_t -k login_config
-a always,exit -F arch=b32 -F path=/etc/login.defs -F perm=wa -F obj_type=etc_t -k login_config
-a always,exit -F arch=b64 -F dir=/etc/security -F perm=wa -k security_config
-a always,exit -F arch=b32 -F dir=/etc/security -F perm=wa -k security_config

## ============================================================================
## === Login/session accounting and failed-authentication evidence ===
## ============================================================================
## systemd-tmpfiles creates utmp/wtmp/btmp/lastlog before auditd starts.
## M10 deliberately persists faillock under /var/lib/faillock. util-linux
## lastlog2 owns /var/lib/lastlog; watching the directory also captures atomic
## database replacement and sidecar files instead of binding only one inode.
-a always,exit -F arch=b64 -F path=/run/utmp -F perm=wa -F obj_type=initrc_var_run_t -k session
-a always,exit -F arch=b32 -F path=/run/utmp -F perm=wa -F obj_type=initrc_var_run_t -k session
-a always,exit -F arch=b64 -F path=/var/log/wtmp -F perm=wa -F obj_type=wtmp_t -k session
-a always,exit -F arch=b32 -F path=/var/log/wtmp -F perm=wa -F obj_type=wtmp_t -k session
-a always,exit -F arch=b64 -F path=/var/log/btmp -F perm=wa -F obj_type=faillog_t -k logins
-a always,exit -F arch=b32 -F path=/var/log/btmp -F perm=wa -F obj_type=faillog_t -k logins
-a always,exit -F arch=b64 -F path=/var/log/lastlog -F perm=wa -F obj_type=lastlog_t -k logins
-a always,exit -F arch=b32 -F path=/var/log/lastlog -F perm=wa -F obj_type=lastlog_t -k logins
-a always,exit -F arch=b64 -F dir=/var/lib/faillock -F perm=wa -k logins
-a always,exit -F arch=b32 -F dir=/var/lib/faillock -F perm=wa -k logins
-a always,exit -F arch=b64 -F dir=/var/lib/lastlog -F perm=wa -k logins
-a always,exit -F arch=b32 -F dir=/var/lib/lastlog -F perm=wa -k logins

## ============================================================================
## === Cron (FULL coverage — 2026 research added hourly/weekly/monthly/spool) ===
## ============================================================================
-a always,exit -F arch=b64 -F path=/etc/crontab -F perm=wa -F obj_type=system_cron_spool_t -k cron
-a always,exit -F arch=b32 -F path=/etc/crontab -F perm=wa -F obj_type=system_cron_spool_t -k cron
-a always,exit -F arch=b64 -F dir=/etc/cron.d -F perm=wa -k cron
-a always,exit -F arch=b32 -F dir=/etc/cron.d -F perm=wa -k cron
-a always,exit -F arch=b64 -F dir=/etc/cron.daily -F perm=wa -k cron
-a always,exit -F arch=b32 -F dir=/etc/cron.daily -F perm=wa -k cron
## NEW 2026 additions — attackers often hide persistence in non-daily cron dirs
-a always,exit -F arch=b64 -F dir=/etc/cron.hourly -F perm=wa -k cron
-a always,exit -F arch=b32 -F dir=/etc/cron.hourly -F perm=wa -k cron
-a always,exit -F arch=b64 -F dir=/etc/cron.weekly -F perm=wa -k cron
-a always,exit -F arch=b32 -F dir=/etc/cron.weekly -F perm=wa -k cron
-a always,exit -F arch=b64 -F dir=/etc/cron.monthly -F perm=wa -k cron
-a always,exit -F arch=b32 -F dir=/etc/cron.monthly -F perm=wa -k cron
-a always,exit -F arch=b64 -F dir=/var/spool/cron -F perm=wa -k cron
-a always,exit -F arch=b32 -F dir=/var/spool/cron -F perm=wa -k cron

## ============================================================================
## === PAM ===
## ============================================================================
-a always,exit -F arch=b64 -F dir=/etc/pam.d -F perm=wa -k pam_changes
-a always,exit -F arch=b32 -F dir=/etc/pam.d -F perm=wa -k pam_changes

## ============================================================================
## === NEW 2026 RESEARCH ADDITIONS (following rules are new in image) ===
## Based on DISA STIG RHEL 9, CIS RHEL 9 v2.0, ComplianceAsCode OSPP v4.2.
## Every architecture-qualified rule above and below is paired exactly.
## ============================================================================

## === Time changes (DISA STIG Cat II) ===
## Includes daemon-originated corrections and clock_adjtime. There is no
## trusted-chronyd suppression: a compromised daemon or authenticated malicious
## source must not erase the only persistent clock-adjustment evidence.
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -S clock_adjtime -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -S clock_adjtime -k time_change

## === NTP Configuration (Module 11 cross-ref) ===
## Module 11 ships chrony NTS-only config. Watch for tampering that would
## weaken to plain NTP or add rogue servers.
-a always,exit -F arch=b64 -F path=/etc/chrony.conf -F perm=wa -F obj_type=etc_t -k chrony_config
-a always,exit -F arch=b32 -F path=/etc/chrony.conf -F perm=wa -F obj_type=etc_t -k chrony_config
-a always,exit -F arch=b64 -F dir=/etc/chrony.d -F perm=wa -k chrony_config
-a always,exit -F arch=b32 -F dir=/etc/chrony.d -F perm=wa -k chrony_config

## === DNS / Resolver config ===
## DNS resolver hijack = man-in-the-middle for all network traffic.
-a always,exit -F arch=b64 -F path=/etc/resolv.conf -F perm=wa -F obj_type=net_conf_t -k dns_config
-a always,exit -F arch=b32 -F path=/etc/resolv.conf -F perm=wa -F obj_type=net_conf_t -k dns_config
-a always,exit -F arch=b64 -F path=/etc/nsswitch.conf -F perm=wa -F obj_type=etc_t -k dns_config
-a always,exit -F arch=b32 -F path=/etc/nsswitch.conf -F perm=wa -F obj_type=etc_t -k dns_config

## === /etc/hosts tampering ===
## Classic attack: redirect github.com or update servers to attacker IP.
-a always,exit -F arch=b64 -F path=/etc/hosts -F perm=wa -F obj_type=net_conf_t -k network_modifications
-a always,exit -F arch=b32 -F path=/etc/hosts -F perm=wa -F obj_type=net_conf_t -k network_modifications

## === Login banner tampering (DISA STIG) ===
-a always,exit -F arch=b64 -F path=/etc/issue -F perm=wa -F obj_type=etc_t -k login_banners
-a always,exit -F arch=b32 -F path=/etc/issue -F perm=wa -F obj_type=etc_t -k login_banners
-a always,exit -F arch=b64 -F path=/etc/issue.net -F perm=wa -F obj_type=etc_t -k login_banners
-a always,exit -F arch=b32 -F path=/etc/issue.net -F perm=wa -F obj_type=etc_t -k login_banners
-a always,exit -F arch=b64 -F path=/etc/motd -F perm=wa -F obj_type=etc_t -k login_banners
-a always,exit -F arch=b32 -F path=/etc/motd -F perm=wa -F obj_type=etc_t -k login_banners
-a always,exit -F arch=b64 -F dir=/etc/motd.d -F perm=wa -k login_banners
-a always,exit -F arch=b32 -F dir=/etc/motd.d -F perm=wa -k login_banners

## === Mount / Umount syscalls (forensic USB tracking) ===
## Only for user-initiated mounts (auid>=1000), not system automounts.
## Bubblewrap deliberately constructs each Flatpak sandbox through many mounts
## in a new, host-invisible user/mount namespace. Record one typed bwrap exec
## per sandbox instead of every internal layout syscall; all non-bwrap
## mount/umount activity retains the original user-session scope.
-a always,exit -F arch=b64 -F path=/usr/bin/bwrap -F perm=x -F obj_type=bin_t -k mount_ops
-a always,exit -F arch=b32 -F path=/usr/bin/bwrap -F perm=x -F obj_type=bin_t -k mount_ops
-a always,exit -F arch=b64 -S mount -S umount2 -F auid>=1000 -F auid!=-1 -F exe!=/usr/bin/bwrap -k mount_ops
-a always,exit -F arch=b32 -S mount -S umount2 -F auid>=1000 -F auid!=-1 -F exe!=/usr/bin/bwrap -k mount_ops

## === Hostname / Domain name tampering ===
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system_locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system_locale

## === Timezone tampering ===
## TZ change = indirect clock attack vector (shifts log timestamps, cron).
-a always,exit -F arch=b64 -F path=/etc/localtime -F perm=wa -F obj_type=locale_t -k localtime
-a always,exit -F arch=b32 -F path=/etc/localtime -F perm=wa -F obj_type=locale_t -k localtime

## ============================================================================
## === Immutable (MUST BE LAST RULE — locks entire ruleset until reboot) ===
## ============================================================================
-e 2
EOF

chmod 640 /etc/audit/rules.d/99-hardening.rules
chown root:root /etc/audit/rules.d/99-hardening.rules
echo "  [OK] /etc/audit/rules.d/99-hardening.rules written (132 ABI-complete rules + -e 2)"

# ----------------------------------------------------------------------------
# Step 7: Enable auditd service
# ----------------------------------------------------------------------------
# auditd is enabled by default on Fedora, but we explicit-enable for safety.
# Surface enable errors instead of silently
# swallowing them. auditd is critical infra — any enable failure (e.g. unit
# syntax error after future Fedora update) needs to be visible in the build log.
# The "already enabled" case is not an error and is handled by `is-enabled`
# pre-check.
echo ""
echo "[Step 7] Enabling auditd.service"
if systemctl is-enabled auditd.service >/dev/null 2>&1; then
    echo "  [OK] auditd.service already enabled (Fedora default)"
elif systemctl enable auditd.service 2>&1 | tee -a /var/log/ks-12-selinux-auditd.log; then
    echo "  [OK] auditd.service enabled"
else
    echo "  [WARN] auditd.service enable returned non-zero — verify post-boot via:"
    echo "         systemctl status auditd.service && systemctl cat auditd.service"
fi

# ============================================================================
# audit-notify — complete-event desktop notification for audit events
# ============================================================================
# auditd string plugin → maintained auparse feed assembler → CRITICAL_KEYS
# filter → per-AUID/key coalescing/rate limit → exact active local logind seat.
# Ships inactive and service-disabled until explicit opt-in.
# ============================================================================

# ----------------------------------------------------------------------------
# Step 8: Install the auparse feed plugin
# ----------------------------------------------------------------------------
echo ""
echo "[Step 8] Installing /usr/local/bin/audit-notify.sh (auparse plugin v1)"

mkdir -p /usr/local/bin

cat > /usr/local/bin/audit-notify.sh <<'AUDIT_NOTIFY_SCRIPT_EOF'
#!/usr/bin/python3
"""NoID Privacy opt-in auditd notification plugin.

auditd sends string records on stdin.  The maintained auparse feed API owns
event assembly, including interlaced/out-of-order records and EOE timeouts.
Only a complete critical event is queued for the notification worker.

Desktop delivery deliberately does NOT happen here.  auditd execve()s this
plugin without a domain transition, so it runs in auditd_t, and the Fedora
targeted policy grants that domain neither CAP_SETUID/CAP_SETGID nor any
access to a user session bus.  This plugin therefore owns parsing, filtering,
coalescing and rate limiting, and hands each surviving event to
noid-audit-event-notify.service through a bounded /run spool.
"""

import datetime as dt
import os
import pathlib
import queue
import select
import signal
import subprocess
import sys
import syslog
import tempfile
import threading
import time

import auparse


CRITICAL_KEYS = frozenset(
    {
        "identity",
        "sudoers",
        "audit_config",
        "aide_integrity",
        "bootloader",
        "sysctl",
        "systemd",
        "firewall",
        "pam_changes",
        "network_config",
        "user_mgmt",
        "su_usage",
        "luks",
        "login_config",
        "security_config",
        "cron",
    }
)
ROUTINE_PROCESSES = frozenset(
    {
        ("systemd-udevd", "/usr/lib/systemd/systemd-udevd"),
        ("udevd", "/usr/lib/systemd/systemd-udevd"),
        ("kmod", "/usr/bin/kmod"),
        ("auditd", "/usr/sbin/auditd"),
        ("auditctl", "/usr/sbin/auditctl"),
        ("systemd-sysctl", "/usr/lib/systemd/systemd-sysctl"),
    }
)
UPDATE_SUPPRESSED_KEYS = frozenset(
    {"sysctl", "systemd", "bootloader", "network_config"}
)
UPDATE_WINDOW_HELPER = pathlib.Path("/usr/libexec/noid-update-window-active")
RUNTIME_DIR = pathlib.Path("/run/noid-privacy")
HEALTH_FILE = RUNTIME_DIR / "audit-notify.health"
SPOOL_DIR = RUNTIME_DIR / "audit-notify.d"
DEGRADED_MARKER = RUNTIME_DIR / "audit-notify-degraded"
RATE_LIMIT_SECONDS = 300
QUEUE_LIMIT = 512
SPOOL_LIMIT = 64
EOE_TIMEOUT_SECONDS = 2


def utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sanitize_text(value, limit=512):
    """Bound untrusted audit text and remove UI control characters."""
    if not value or value in {"(null)", "?"}:
        return ""
    cleaned = "".join(
        ch if ch.isprintable() and ch not in "\r\n" else " " for ch in value
    )
    return " ".join(cleaned.split())[:limit]


def atomic_write(path, content, mode, temporary_parent=None):
    """Replace one file without recreating or weakening its owned parent."""
    if temporary_parent is None:
        temporary_parent = path.parent
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=temporary_parent
    )
    try:
        os.fchmod(fd, mode)
        stream = os.fdopen(fd, "w", encoding="utf-8")
        # fdopen() owns the descriptor from this point, including every error
        # path through write/flush/fsync.  Clear our ownership before any of
        # those operations so another thread can never have a reused descriptor
        # closed by the cleanup handler below.
        fd = -1
        with stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        # A cross-directory rename needs both directory entries persisted.
        # dict.fromkeys keeps the ordinary same-directory path to one fsync.
        for directory in dict.fromkeys((path.parent, temporary_parent)):
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _record_fields(parser):
    fields = {}
    if not parser.first_field():
        return fields
    while True:
        name = parser.get_field_name()
        raw = parser.get_field_str()
        try:
            interpreted = parser.interpret_field()
        except RuntimeError:
            interpreted = raw
        fields[name] = (raw, interpreted)
        if not parser.next_field():
            return fields


def parse_complete_event(parser):
    """Return one bounded critical-event dictionary, or None."""
    key = ""
    auid_raw = ""
    command = ""
    executable = ""
    primary_path = ""
    fallback_path = ""

    for record_number in range(parser.get_num_records()):
        if not parser.goto_record_num(record_number):
            continue
        record_type = parser.get_type_name()
        fields = _record_fields(parser)
        if record_type == "SYSCALL":
            key = fields.get("key", ("", ""))[1]
            auid_raw = fields.get("auid", ("", ""))[0]
            command = fields.get("comm", ("", ""))[1]
            executable = fields.get("exe", ("", ""))[1]
        elif record_type == "PATH":
            path_value = fields.get("name", ("", ""))[1]
            item = fields.get("item", ("", ""))[0]
            if item == "0":
                primary_path = path_value
            elif not fallback_path:
                fallback_path = path_value

    key = sanitize_text(key, 64)
    command = sanitize_text(command, 64)
    executable = sanitize_text(executable, 512)
    if key not in CRITICAL_KEYS or (command, executable) in ROUTINE_PROCESSES:
        return None
    if auid_raw in {"", "unset", "4294967295", "-1"}:
        return None
    try:
        auid = int(auid_raw, 10)
    except ValueError:
        return None
    if auid < 1000 or auid > 4294967294:
        return None

    timestamp = parser.get_timestamp()
    return {
        "serial": int(timestamp.serial),
        "key": key,
        "auid": auid,
        "command": command,
        "path": sanitize_text(primary_path or fallback_path or executable),
    }


class FeedAssembler:
    """Small testable wrapper around the supported auparse feed interface."""

    def __init__(self, event_handler):
        self.event_handler = event_handler
        self.parser = auparse.AuParser(auparse.AUSOURCE_FEED, None)
        self.parser.set_eoe_timeout(EOE_TIMEOUT_SECONDS)
        # python3-audit requires a Python function object here; it rejects a
        # bound method even though both are callable. Retain the closure for
        # the parser lifetime and delegate into the supplied event handler.
        def event_ready(parser, callback_type, _user_data):
            if callback_type == auparse.AUPARSE_CB_EVENT_READY:
                self.event_handler(parse_complete_event(parser))

        self._callback = event_ready
        self.parser.add_callback(self._callback, None)

    def feed(self, data):
        self.parser.feed(data)

    def age(self):
        self.parser.feed_age_events()

    def flush(self):
        self.parser.flush_feed()


def update_window_active():
    """Trust only M25's process/lock-bound update-window validator."""
    try:
        result = subprocess.run(
            [str(UPDATE_WINDOW_HELPER)],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1,
            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def queue_notification(event):
    """Hand one surviving event to the normally-domained delivery notifier.

    Delivery cannot happen in this process.  auditd execve()s the plugin from
    bin_t with execute_no_trans, so it stays in auditd_t, and `setpriv` changes
    credentials without changing the SELinux domain.  Verified against the
    installed targeted policy: auditd_t holds `capability { audit_control
    audit_write chown fsetid net_bind_service setpcap sys_nice sys_resource }`
    (no setuid/setgid), and /run/user/<uid>/bus is session_dbusd_tmp_t, for
    which auditd_t has no sock_file access and no connectto on the session
    bus daemon.  Granting the two capabilities alone would therefore only move
    the failure one step later, so the whole delivery path lives in
    noid-audit-event-notify.service instead — the same split M12 already uses
    for the audit-storage marker.

    The spool is bounded: a stalled or disabled notifier can never let auditd
    fill the runtime tmpfs.  Returns False when the bound is reached so the
    caller records a suppression instead of an unnoticed drop.
    """
    if len(os.listdir(SPOOL_DIR)) >= SPOOL_LIMIT:
        return False
    request = (
        f"serial={event['serial']}\n"
        f"auid={event['auid']}\n"
        f"key={event['key']}\n"
        f"command={event['command']}\n"
        f"path={event['path']}\n"
    )
    # Both components are integers validated in parse_complete_event, so the
    # name cannot carry a separator or escape the spool directory.
    name = f"{event['serial']:020d}-{event['auid']}"
    # Stage in the sibling runtime directory, not inside the directory watched
    # by DirectoryNotEmpty=.  The watcher can therefore see only a completely
    # written request after the same-filesystem atomic rename, never mkstemp's
    # in-flight file.  SPOOL_DIR.parent also keeps behavior fixtures isolated.
    atomic_write(
        SPOOL_DIR / name,
        request,
        0o600,
        temporary_parent=SPOOL_DIR.parent,
    )
    return True


class AuditNotificationPlugin:
    def __init__(self):
        self.running = True
        self.health_refresh_requested = False
        self.events = queue.Queue(maxsize=QUEUE_LIMIT)
        self.pending = set()
        self.rates = {}
        self.lock = threading.Lock()
        self.stats = {
            "complete_events": 0,
            "critical_events": 0,
            "notifications_queued": 0,
            "notifications_suppressed": 0,
            "coalesced_events": 0,
            "queue_drops": 0,
            "handoff_failures": 0,
            "last_event_serial": 0,
            "last_suppression_reason": "none",
            "last_input_at": "never",
            "last_queued_at": "never",
        }
        self.assembler = FeedAssembler(self.enqueue)
        self.worker = threading.Thread(target=self._worker, name="notify-worker", daemon=True)

    def enqueue(self, event):
        with self.lock:
            self.stats["complete_events"] += 1
            if event is None:
                return
            self.stats["critical_events"] += 1
            self.stats["last_event_serial"] = event["serial"]
            token = (event["auid"], event["key"])
            if token in self.pending:
                self.stats["coalesced_events"] += 1
                return
            self.pending.add(token)
        try:
            self.events.put_nowait(event)
        except queue.Full:
            with self.lock:
                self.pending.discard(token)
                self.stats["queue_drops"] += 1
            self.mark_degraded("notification-queue-overflow")

    def write_health(self, state="running"):
        with self.lock:
            snapshot = dict(self.stats)
        lines = [
            f"state={state}",
            f"pid={os.getpid()}",
            f"updated_at={utc_now()}",
            f"persistent_degraded={'yes' if DEGRADED_MARKER.exists() else 'no'}",
        ]
        lines.extend(f"{name}={value}" for name, value in snapshot.items())
        atomic_write(HEALTH_FILE, "\n".join(lines) + "\n", 0o640)

    def mark_degraded(self, reason):
        """Publish degraded state without ever killing the dispatcher worker."""
        reason = sanitize_text(reason, 80) or "unspecified-plugin-failure"
        marker_persisted = True
        try:
            atomic_write(
                DEGRADED_MARKER,
                "status=degraded\n"
                f"reason={reason}\n"
                f"detected_at={utc_now()}\n"
                "remediation=review-audit-notify-health-before-removing-this-marker\n",
                0o600,
            )
        except OSError as error:
            marker_persisted = False
            syslog.syslog(
                syslog.LOG_CRIT,
                "audit notification degradation marker write failed: "
                f"{type(error).__name__}",
            )
        syslog.syslog(syslog.LOG_ALERT, f"audit notification degraded: {reason}")
        try:
            self.write_health("degraded")
        except OSError:
            pass
        return marker_persisted

    def _suppress(self, reason):
        with self.lock:
            self.stats["notifications_suppressed"] += 1
            self.stats["last_suppression_reason"] = reason

    def _handle(self, event):
        token = (event["auid"], event["key"])
        try:
            if event["key"] in UPDATE_SUPPRESSED_KEYS and update_window_active():
                self._suppress("reviewed-update-window")
                return
            now = time.monotonic()
            if now - self.rates.get(token, -RATE_LIMIT_SECONDS) < RATE_LIMIT_SECONDS:
                self._suppress("rate-limit")
                return
            if not queue_notification(event):
                self._suppress("notification-spool-full")
                self.mark_degraded("notification-spool-full")
                return
            self.rates[token] = now
            with self.lock:
                self.stats["notifications_queued"] += 1
                self.stats["last_queued_at"] = utc_now()
                self.stats["last_suppression_reason"] = "none"
        except (OSError, KeyError, ValueError, RuntimeError) as error:
            with self.lock:
                self.stats["handoff_failures"] += 1
            self.mark_degraded(type(error).__name__)
        finally:
            with self.lock:
                self.pending.discard(token)

    def _worker(self):
        while self.running or not self.events.empty():
            try:
                event = self.events.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._handle(event)
            except Exception as error:
                with self.lock:
                    self.stats["handoff_failures"] += 1
                self.mark_degraded(f"notification-worker-{type(error).__name__}")
            finally:
                self.events.task_done()
                try:
                    self.write_health()
                except OSError:
                    self.mark_degraded("health-write-failed")

    def stop(self, _signum, _frame):
        self.running = False

    def reload(self, _signum, _frame):
        # Python runs signal handlers on the main thread.  Do not acquire
        # self.lock or perform filesystem I/O here: a signal may interrupt that
        # same thread while it already owns the non-reentrant lock.
        self.health_refresh_requested = True

    def run(self):
        syslog.openlog("noid-audit-notify", syslog.LOG_PID, syslog.LOG_AUTH)
        try:
            # M05's /etc/tmpfiles.d/noid-runtime.conf boot-creates this
            # directory with the exact 0755 root:root shape, so neither the
            # mkdir nor the chmod was ever load-bearing -- but both were fatal.
            # auditd execve()s this plugin without a domain transition, so it
            # runs in auditd_t, and the Fedora targeted policy grants that
            # domain { add_name remove_name write } on var_run_t:dir but NOT
            # setattr. chmod(2) performs the SELinux setattr check even when
            # the mode is already correct, so os.chmod raised OSError on every
            # enforcing installation and the plugin returned 1 before handling
            # a single event. The controller's health poll then never observed
            # state=running, reverted active=no and reported that auditd had
            # not started a healthy plugin. Verify the directory instead of
            # reshaping it; reshaping is exactly what auditd_t may not do.
            if not RUNTIME_DIR.is_dir():
                self.mark_degraded("runtime-directory-missing")
                return 1
            # Mode 0700 carries no group/other bits, so no umask can widen it
            # and no follow-up chmod is needed. The new name transitions to
            # auditd_var_run_t, where auditd_t does hold create/write/unlink --
            # unlike the var_run_t parent it may only add names to.
            SPOOL_DIR.mkdir(mode=0o700, exist_ok=True)
            self.write_health()
        except OSError:
            self.mark_degraded("initial-health-write-failed")
            return 1
        self.worker.start()
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGHUP, self.reload)
        os.set_blocking(0, False)
        last_health = time.monotonic()
        exit_status = 0
        try:
            while self.running:
                readable, _, _ = select.select([0], [], [], 1.0)
                if readable:
                    chunk = os.read(0, 65536)
                    if not chunk:
                        # auditd owns this pipe and closes it whenever a
                        # configuration reload retires or replaces the plugin,
                        # including an unchanged active=yes reload. Clean EOF
                        # is therefore the normal dispatcher lifecycle. The
                        # controller independently requires active=yes to map
                        # to an exact live plugin PID; parser, I/O, worker,
                        # queue and health failures remain degraded here.
                        break
                    with self.lock:
                        self.stats["last_input_at"] = utc_now()
                    self.assembler.feed(chunk.decode("utf-8", "replace"))
                else:
                    self.assembler.age()
                if self.health_refresh_requested:
                    self.health_refresh_requested = False
                    self.write_health()
                    last_health = time.monotonic()
                elif time.monotonic() - last_health >= 5:
                    self.write_health()
                    last_health = time.monotonic()
        except (OSError, RuntimeError) as error:
            self.mark_degraded(type(error).__name__)
            exit_status = 1
        finally:
            try:
                self.assembler.flush()
            except (OSError, RuntimeError):
                self.mark_degraded("auparse-flush-failed")
                exit_status = 1
            self.running = False
            self.worker.join(timeout=5)
            if self.worker.is_alive() or not self.events.empty():
                self.mark_degraded("notification-worker-stop-timeout")
                exit_status = 1
            try:
                self.write_health("stopped")
            except OSError:
                self.mark_degraded("final-health-write-failed")
                exit_status = 1
        return exit_status


def main():
    if len(sys.argv) != 1:
        print("ERROR: audit-notify.sh accepts no arguments", file=sys.stderr)
        return 2
    return AuditNotificationPlugin().run()


if __name__ == "__main__":
    raise SystemExit(main())
AUDIT_NOTIFY_SCRIPT_EOF

chmod 0755 /usr/local/bin/audit-notify.sh
chown root:root /usr/local/bin/audit-notify.sh
python3 -c 'path="/usr/local/bin/audit-notify.sh"; compile(open(path, encoding="utf-8").read(), path, "exec")'
echo "  [OK] /usr/local/bin/audit-notify.sh installed (755, Python parses)"

# auditd owns plugin lifecycle and feeds one string record per stdin line.
# `active = no` is the immutable image default; the opt-in controller below
# changes only that one field and requests a documented auditd reload.
install -d -m 0750 -o root -g root /etc/audit/plugins.d
cat > /etc/audit/plugins.d/noid-notify.conf <<'AUDIT_NOTIFY_PLUGIN_EOF'
active = no
path = /usr/local/bin/audit-notify.sh
type = always
format = string
AUDIT_NOTIFY_PLUGIN_EOF
chmod 0640 /etc/audit/plugins.d/noid-notify.conf
chown root:root /etc/audit/plugins.d/noid-notify.conf

cat > /usr/local/sbin/noid-audit-notify-controller <<'AUDIT_NOTIFY_CONTROLLER_EOF'
#!/bin/bash
# Atomically toggle the reviewed auditd plugin and prove its child lifecycle.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$#" -gt 1 ]; then
    echo "ERROR: noid-audit-notify-controller accepts at most one argument" >&2
    exit 2
fi

CONF=/etc/audit/plugins.d/noid-notify.conf
HEALTH=/run/noid-privacy/audit-notify.health
DEGRADED=/run/noid-privacy/audit-notify-degraded
PLUGIN=/usr/local/bin/audit-notify.sh
ACTION=${1:-status}

[ "$(id -u)" -eq 0 ] || {
    echo "audit notification mutation requires root" >&2
    exit 1
}
if [ ! -f "$CONF" ] || [ -L "$CONF" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$CONF")" != root:root:640:1 ] \
   || [ "$(grep -c '^active = ' "$CONF" || true)" -ne 1 ] \
   || ! grep -qxF "path = $PLUGIN" "$CONF" \
   || ! grep -qxF 'type = always' "$CONF" \
   || ! grep -qxF 'format = string' "$CONF"; then
    echo "audit notification plugin configuration is not exact" >&2
    exit 1
fi

# The lock lives under /run/noid-privacy, not directly in /run. This script is
# the ExecStart of audit-notify.service, which runs ProtectSystem=strict with
# ReadWritePaths=/etc/audit/plugins.d /run/noid-privacy -- and strict remounts
# the whole hierarchy read-only except /dev, /proc and /sys, so /run itself is
# not writable inside that namespace. A redirection to /run would fail with
# EROFS before the on|off|status case is even reached, aborting the unit while
# `systemctl enable --now` has already written the wants symlink, so M13's
# is_unit_enabled() would keep reporting the GUI toggle as ON. M05's
# noid-runtime.conf boot-creates this path with the other runtime locks.
exec 9>/run/noid-privacy/audit-notify-toggle.lock
flock -x 9

set_active() {
    local value=$1 temporary
    temporary=$(mktemp /etc/audit/plugins.d/.noid-notify.conf.XXXXXX)
    trap 'rm -f -- "${temporary:-}"' RETURN
    awk -v value="$value" '
        /^active = / { print "active = " value; next }
        { print }
    ' "$CONF" > "$temporary"
    chown root:root "$temporary"
    chmod 0640 "$temporary"
    mv -fT "$temporary" "$CONF"
    trap - RETURN
    /usr/bin/restorecon -F "$CONF"
    /usr/bin/matchpathcon -V "$CONF" >/dev/null
    [ "$(stat -c '%U:%G:%a:%h' "$CONF")" = root:root:640:1 ] \
        && grep -qxF "active = $value" "$CONF"
}

plugin_pid() {
    sed -n 's/^pid=//p' "$HEALTH" 2>/dev/null | head -1
}

plugin_running() {
    local pid
    pid=$(plugin_pid)
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    [ -f "$HEALTH" ] && [ ! -L "$HEALTH" ] \
        && grep -qxF 'state=running' "$HEALTH" \
        && kill -0 "$pid" 2>/dev/null \
        && tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | \
            grep -qxF "$PLUGIN"
}

reload_auditd() {
    if ! auditctl --signal reload; then
        echo "auditd rejected the plugin reload signal" >&2
        return 1
    fi
}

case "$ACTION" in
    on)
        rm -f -- "$HEALTH"
        [ ! -e "$DEGRADED" ] || {
            echo "existing audit notification degradation must be reviewed" >&2
            exit 1
        }
        set_active yes
        if ! reload_auditd; then
            set_active no
            auditctl --signal reload >/dev/null 2>&1 || true
            exit 1
        fi
        stable_samples=0
        for _ in $(seq 1 15); do
            if plugin_running && [ ! -e "$DEGRADED" ]; then
                stable_samples=$((stable_samples + 1))
                [ "$stable_samples" -ge 2 ] && exit 0
            else
                stable_samples=0
            fi
            sleep 1
        done
        echo "auditd did not start a healthy notification plugin" >&2
        set_active no
        auditctl --signal reload >/dev/null 2>&1 || true
        exit 1
        ;;
    off)
        old_pid=$(plugin_pid)
        set_active no
        reload_auditd
        if [[ "$old_pid" =~ ^[0-9]+$ ]]; then
            for _ in $(seq 1 15); do
                kill -0 "$old_pid" 2>/dev/null || exit 0
                sleep 1
            done
            echo "auditd did not stop the notification plugin" >&2
            exit 1
        fi
        ;;
    status)
        active_value=$(sed -n 's/^active = //p' "$CONF")
        echo "active = $active_value"
        status_failed=0
        if [ -f "$HEALTH" ] && [ ! -L "$HEALTH" ]; then
            cat "$HEALTH"
        else
            echo "state=never-started"
        fi
        if [ "$active_value" = yes ]; then
            status_running=0
            for _ in 1 2 3; do
                if plugin_running; then
                    status_running=1
                    break
                fi
                sleep 1
            done
            if [ "$status_running" -ne 1 ]; then
                echo "runtime_degraded=active-plugin-not-running"
                status_failed=1
            fi
        fi
        if [ -e "$DEGRADED" ]; then
            echo "persistent_degraded=yes"
            status_failed=1
        fi
        exit "$status_failed"
        ;;
    *)
        echo "Usage: noid-audit-notify-controller {on|off|status}" >&2
        exit 2
        ;;
esac
AUDIT_NOTIFY_CONTROLLER_EOF
chmod 0755 /usr/local/sbin/noid-audit-notify-controller
chown root:root /usr/local/sbin/noid-audit-notify-controller
bash -n /usr/local/sbin/noid-audit-notify-controller

# ----------------------------------------------------------------------------
# Step 9: Install the opt-in auditd-plugin controller unit
# ----------------------------------------------------------------------------
echo ""
echo "[Step 9] Installing audit-notify.service (auparse plugin controller)"

cat > /etc/systemd/system/audit-notify.service <<'AUDIT_NOTIFY_UNIT_EOF'
[Unit]
Description=NoID Privacy - opt-in auditd notification plugin controller
Documentation=file:///usr/local/bin/audit-notify.sh
After=auditd.service systemd-tmpfiles-setup.service
Requires=auditd.service systemd-tmpfiles-setup.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-audit-notify-controller on
ExecStop=/usr/local/sbin/noid-audit-notify-controller off
RemainAfterExit=yes
TimeoutStartSec=25s
TimeoutStopSec=25s
ProtectSystem=strict
# Shared runtime state is created by /etc/tmpfiles.d/noid-runtime.conf. Do not
# make its lifetime depend on this optional controller being active.
ReadWritePaths=/etc/audit/plugins.d /run/noid-privacy
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictRealtime=true
RestrictNamespaces=true
ProtectKernelLogs=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
AUDIT_NOTIFY_UNIT_EOF

chmod 0644 /etc/systemd/system/audit-notify.service
chown root:root /etc/systemd/system/audit-notify.service
echo "  [OK] /etc/systemd/system/audit-notify.service installed (644)"

# audit-notify.service ships DISABLED (opt-in via Welcome dialog — header
# deviations). The plugin config is also `active = no`; auditd + all rules
# stay active while only desktop popup delivery is absent.
echo "  [OK] audit-notify.service installed but NOT enabled (opt-in via welcome dialog)"

# ============================================================================
# Step 9b: Install /usr/local/sbin/noid-toggle-audit-notify wrapper
# ============================================================================
# Setup's "Audit Event Notifications" switch invokes this wrapper through an
# exact already-authorized noninteractive sudo route when one exists. Otherwise
# M08 pins uncached AUTH_ADMIN to this exact wrapper path as the pkexec fallback
# for local active wheel sessions. Polkit authenticates every such action; it
# must not retain generic pkexec authorization across different programs.
#
# Without this wrapper: on_audit_toggle in noid-welcome.sh would call
# `pkexec systemctl enable --now audit-notify.service` which hits the
# broad systemctl mechanism instead of this argument-validating helper.
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/noid-toggle-audit-notify <<'TOGGLE_AUDIT_NOTIFY_EOF'
#!/bin/bash
# noid-toggle-audit-notify — enable or disable the audit-notify.service.
#
# audit-notify.service atomically activates the auditd/auparse plugin which
# sends complete, context-filtered events only to the matching AUID's unlocked
# active local graphical session. auditd itself stays enabled either way.
#
# Usage:
#   sudo noid-toggle-audit-notify on     # enable + start now
#   sudo noid-toggle-audit-notify off    # disable + stop now (default image state)
#   sudo noid-toggle-audit-notify        # show current state

set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$#" -gt 1 ]; then
    echo "ERROR: noid-toggle-audit-notify accepts at most one argument" >&2
    exit 2
fi

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Audit Alerts" \
    NOID_FMT_AUTO_SUBTITLE="Critical event notification state" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

UNIT=audit-notify.service
ACTION="${1:-status}"

if [ "$ACTION" != "status" ] && [ "$(id -u)" -ne 0 ]; then
    echo "Mutating action requires root (use sudo or pkexec)." >&2
    exit 1
fi

disable_and_clear_unit() {
    local failed=0
    systemctl disable --now "$UNIT" || failed=1
    if systemctl is-failed --quiet "$UNIT"; then
        systemctl reset-failed "$UNIT" || failed=1
    fi
    if systemctl is-enabled --quiet "$UNIT"; then
        failed=1
    fi
    if systemctl is-active --quiet "$UNIT"; then
        failed=1
    fi
    if systemctl is-failed --quiet "$UNIT"; then
        failed=1
    fi
    [ "$failed" -eq 0 ]
}

case "$ACTION" in
    on|enable)
        if ! systemctl enable --now "$UNIT" \
           || ! systemctl is-enabled --quiet "$UNIT" \
           || ! systemctl is-active --quiet "$UNIT"; then
            echo "Failed to enable and start $UNIT; restoring disabled state." >&2
            if ! disable_and_clear_unit; then
                echo "Failed to restore the disabled $UNIT state." >&2
            fi
            exit 1
        fi
        echo "Audit Event Notifications: ENABLED."
        echo "Disable again: sudo noid-toggle-audit-notify off"
        ;;
    off|disable)
        if ! disable_and_clear_unit; then
            echo "Failed to disable, stop and clear $UNIT." >&2
            exit 1
        fi
        echo "Audit Event Notifications: disabled."
        echo "Enable again: sudo noid-toggle-audit-notify on"
        ;;
    status|"")
        # systemctl is-enabled returns rc=1 for "disabled" while still
        # printing "disabled" to stdout — `|| echo` would append "unknown"
        # to the real state. Use plain capture + post-check instead.
        state=$(systemctl is-enabled "$UNIT" 2>/dev/null || true)
        [ -z "$state" ] && state="unknown"
        active=$(systemctl is-active "$UNIT" 2>/dev/null || true)
        [ -z "$active" ] && active="unknown"
        echo "Audit Event Notifications:"
        echo "  unit:     $UNIT"
        echo "  enabled:  $state"
        echo "  active:   $active"
        if [ "$(id -u)" -eq 0 ]; then
            /usr/local/sbin/noid-audit-notify-controller status
        else
            echo "  health:   run status with sudo for root-owned delivery metrics"
        fi
        ;;
    *)
        echo "Usage: noid-toggle-audit-notify [on|off|status]" >&2
        exit 1
        ;;
esac
TOGGLE_AUDIT_NOTIFY_EOF
chmod 0755 /usr/local/sbin/noid-toggle-audit-notify
chown root:root /usr/local/sbin/noid-toggle-audit-notify
/usr/bin/restorecon -F /usr/local/sbin/noid-toggle-audit-notify
/usr/bin/matchpathcon -V /usr/local/sbin/noid-toggle-audit-notify >/dev/null
echo "  [OK] /usr/local/sbin/noid-toggle-audit-notify installed (755)"

# Normalize every generated file through the active targeted-policy mapping.
# The Step-10 inventory then binds type, owner, mode, hardlink count and label.
M12_FILE_ARTIFACTS=(
    '/var/lib/noid-privacy/selinux/noid-selinux-fixes.te|644'
    '/var/lib/noid-privacy/selinux/noid-selinux-fixes.pp|644'
    '/usr/local/sbin/noid-selinux-policy-reconcile|755'
    '/etc/dnf/libdnf5-plugins/actions.d/noid-selinux-policy.actions|644'
    '/etc/audit/rules.d/audit.rules|640'
    '/usr/local/sbin/noid-audit-space-alert|755'
    '/usr/local/sbin/noid-audit-space-critical|755'
    '/etc/audit/auditd.conf|640'
    '/usr/local/libexec/noid-auditd-live-thresholds|755'
    '/etc/systemd/system/auditd.service.d/10-noid-live-thresholds.conf|644'
    '/usr/local/libexec/noid-audit-storage-notify|755'
    '/etc/systemd/system/noid-audit-storage-notify.service|644'
    '/etc/systemd/system/noid-audit-storage-notify.path|644'
    '/usr/local/libexec/noid-audit-event-notify|755'
    '/etc/systemd/system/noid-audit-event-notify.service|644'
    '/etc/systemd/system/noid-audit-event-notify.path|644'
    '/etc/audit/rules.d/99-hardening.rules|640'
    '/usr/local/bin/audit-notify.sh|755'
    '/etc/audit/plugins.d/noid-notify.conf|640'
    '/usr/local/sbin/noid-audit-notify-controller|755'
    '/etc/systemd/system/audit-notify.service|644'
    '/usr/local/sbin/noid-toggle-audit-notify|755'
)
for m12_artifact_spec in "${M12_FILE_ARTIFACTS[@]}"; do
    IFS='|' read -r m12_artifact _ <<< "$m12_artifact_spec"
    /usr/bin/restorecon -F "$m12_artifact"
done
unset m12_artifact_spec m12_artifact

# ----------------------------------------------------------------------------
# Step 10: Verification (renamed from Step 8 in v2 reopen)
# ----------------------------------------------------------------------------
echo ""
echo "[Step 10] Verification"

fail=0

# 10.1 — SELinux config
if grep -q "^SELINUX=enforcing$" /etc/selinux/config; then
    echo "  [OK] SELinux=enforcing in config"
else
    echo "  [FAIL] SELinux config enforcing missing"
    fail=$((fail + 1))
fi

if grep -q "^SELINUXTYPE=targeted$" /etc/selinux/config; then
    echo "  [OK] SELINUXTYPE=targeted in config"
else
    echo "  [FAIL] SELinux targeted type missing"
    fail=$((fail + 1))
fi

selinux_action=/etc/dnf/libdnf5-plugins/actions.d/noid-selinux-policy.actions
selinux_action_contract='post_transaction:selinux-policy-targeted:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-selinux-policy-reconcile\ >/dev/null'
if [ "$(stat -c '%U:%G:%a' /usr/local/sbin/noid-selinux-policy-reconcile 2>/dev/null || true)" = root:root:755 ] \
   && bash -n /usr/local/sbin/noid-selinux-policy-reconcile \
   && [ "$(stat -c '%U:%G:%a' "$selinux_action" 2>/dev/null || true)" = root:root:644 ] \
   && [ "$(grep -c '^post_transaction:' "$selinux_action" 2>/dev/null || true)" -eq 1 ] \
   && grep -qxF "$selinux_action_contract" "$selinux_action"; then
    echo "  [OK] SELinux policy-update reconciliation is fail-closed"
else
    echo "  [FAIL] SELinux policy-update reconciliation contract invalid"
    fail=$((fail + 1))
fi
unset selinux_action selinux_action_contract

# 10.2 — SELinux boolean policy-store overrides are exact
if boolean_overrides=$(semanage boolean -E 2>/dev/null); then
    boolean_fail=0
    for boolean_name in selinuxuser_execstack selinuxuser_execmod; do
        if [ "$(printf '%s\n' "$boolean_overrides" | \
                grep -xcF "boolean -m -0 $boolean_name" || true)" -eq 1 ]; then
            echo "  [OK] $boolean_name has one exact persistent off override"
        else
            echo "  [FAIL] $boolean_name persistent off override is missing or ambiguous"
            fail=$((fail + 1))
            boolean_fail=$((boolean_fail + 1))
        fi
    done
    [ "$boolean_fail" -eq 0 ] \
        && echo "  [OK] both SELinux execution restrictions are policy-store-persistent"
else
    echo "  [FAIL] SELinux boolean policy-store overrides are unreadable"
    fail=$((fail + 1))
fi
unset boolean_overrides boolean_name boolean_fail

# 10.2b — every generated M12 file is singular, exact and correctly labeled
m12_artifact_fail=0
for m12_artifact_spec in "${M12_FILE_ARTIFACTS[@]}"; do
    IFS='|' read -r m12_artifact m12_mode <<< "$m12_artifact_spec"
    if [ -f "$m12_artifact" ] && [ ! -L "$m12_artifact" ] \
       && [ "$(stat -c '%U:%G:%a:%h' "$m12_artifact" \
            2>/dev/null || true)" = "root:root:${m12_mode}:1" ] \
       && /usr/bin/matchpathcon -V "$m12_artifact" >/dev/null 2>&1; then
        :
    else
        echo "  [FAIL] generated artifact metadata/label invalid: $m12_artifact"
        fail=$((fail + 1))
        m12_artifact_fail=$((m12_artifact_fail + 1))
    fi
done
if [ "$m12_artifact_fail" -eq 0 ]; then
    echo "  [OK] all generated M12 files have exact metadata and SELinux labels"
fi
unset m12_artifact_spec m12_artifact m12_mode m12_artifact_fail

# 10.3 — Fedora audit.rules gotcha fix
if grep -qE "^-a task,never" /etc/audit/rules.d/audit.rules; then
    echo "  [FAIL] -a task,never still present — gotcha fix FAILED"
    fail=$((fail + 1))
else
    echo "  [OK] Fedora -a task,never gotcha removed"
fi

# 10.4 — auditd.conf rolling-window and failure policy present
if grep -q "^q_depth = 2000$" /etc/audit/auditd.conf; then
    echo "  [OK] q_depth = 2000 (vendor dispatcher queue; opt-in plugin bounded)"
else
    echo "  [FAIL] dispatcher q_depth policy invalid"
    fail=$((fail + 1))
fi

if grep -q "^max_log_file = 64$" /etc/audit/auditd.conf; then
    echo "  [OK] max_log_file = 64 (2026 research upgrade)"
else
    echo "  [FAIL] max_log_file rolling ceiling missing"
    fail=$((fail + 1))
fi
if [ "$(stat -c '%U:%G:%a' /usr/local/sbin/noid-audit-space-alert 2>/dev/null || true)" = \
     root:root:755 ] \
   && [ "$(stat -c '%U:%G:%a' /usr/local/libexec/noid-auditd-live-thresholds 2>/dev/null || true)" = \
        root:root:755 ] \
   && [ "$(stat -c '%U:%G:%a' /etc/systemd/system/auditd.service.d/10-noid-live-thresholds.conf 2>/dev/null || true)" = \
        root:root:644 ] \
   && bash -n /usr/local/libexec/noid-auditd-live-thresholds \
   && grep -qxF 'ExecStartPre=-/usr/local/libexec/noid-auditd-live-thresholds' \
        /etc/systemd/system/auditd.service.d/10-noid-live-thresholds.conf \
   && grep -qxF 'space_left = 8192' /etc/audit/auditd.conf \
   && grep -qxF 'space_left_action = EXEC /usr/local/sbin/noid-audit-space-alert' \
        /etc/audit/auditd.conf \
   && grep -qxF 'admin_space_left = 4096' /etc/audit/auditd.conf \
   && grep -qxF 'admin_space_left_action = EXEC /usr/local/sbin/noid-audit-space-critical' \
        /etc/audit/auditd.conf \
   && grep -qxF 'disk_full_action = ROTATE' /etc/audit/auditd.conf \
   && grep -qxF 'disk_error_action = EXEC /usr/local/sbin/noid-audit-space-critical' \
        /etc/audit/auditd.conf \
   && bash -n /usr/local/sbin/noid-audit-space-alert \
   && [ "$(stat -c '%U:%G:%a' /usr/local/sbin/noid-audit-space-critical 2>/dev/null || true)" = \
        root:root:755 ] \
   && bash -n /usr/local/sbin/noid-audit-space-critical \
   && ! grep -qE '^[[:space:]]*(if ! )?auditctl --signal resume' \
        /usr/local/sbin/noid-audit-space-critical \
   && [ "$(stat -c '%U:%G:%a' /usr/local/libexec/noid-audit-storage-notify 2>/dev/null || true)" = \
        root:root:755 ] \
   && bash -n /usr/local/libexec/noid-audit-storage-notify \
   && grep -qxF 'PathModified=/run/noid-privacy/audit-storage-degraded' \
        /etc/systemd/system/noid-audit-storage-notify.path \
   && grep -qxF 'ExecStart=/usr/local/libexec/noid-audit-storage-notify' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   && grep -qxF 'CapabilityBoundingSet=CAP_SETGID CAP_SETUID' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   && grep -qxF 'ProtectSystem=strict' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   && grep -qxF 'InaccessiblePaths=/home /root' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   && grep -qxF 'ProtectHome=read-only' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   && grep -qxF 'RestrictAddressFamilies=AF_UNIX' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   && grep -qF -- '--property=LockedHint' \
        /usr/local/libexec/noid-audit-storage-notify \
   && grep -qF '/usr/bin/setpriv' /usr/local/libexec/noid-audit-storage-notify \
   && ! grep -qF 'loginctl list-users' \
        /usr/local/libexec/noid-audit-storage-notify \
   && [ "$(systemctl is-enabled noid-audit-storage-notify.path 2>/dev/null)" = enabled ]; then
    echo "  [OK] installed/Live audit-storage selector and survivable failure actions present"
else
    echo "  [FAIL] audit-storage degradation/failure policy invalid"
    fail=$((fail + 1))
fi

# 10.4b — event notification delivery runs outside auditd_t
# The auditd-hosted plugin may only queue; the drain unit below owns every
# privileged and session-facing step. Assert both halves of that split, so a
# later edit cannot quietly move setpriv or notify-send back into auditd_t.
if [ "$(stat -c '%U:%G:%a' /usr/local/libexec/noid-audit-event-notify 2>/dev/null || true)" = \
     root:root:755 ] \
   && python3 -c 'path="/usr/local/libexec/noid-audit-event-notify"; compile(open(path, encoding="utf-8").read(), path, "exec")' \
   && grep -qxF 'DirectoryNotEmpty=/run/noid-privacy/audit-notify.d' \
        /etc/systemd/system/noid-audit-event-notify.path \
   && grep -qxF 'ExecStart=/usr/local/libexec/noid-audit-event-notify' \
        /etc/systemd/system/noid-audit-event-notify.service \
   && grep -qxF 'CapabilityBoundingSet=CAP_SETGID CAP_SETUID' \
        /etc/systemd/system/noid-audit-event-notify.service \
   && grep -qxF 'ProtectSystem=strict' \
        /etc/systemd/system/noid-audit-event-notify.service \
   && grep -qxF 'ReadWritePaths=/run/noid-privacy' \
        /etc/systemd/system/noid-audit-event-notify.service \
   && grep -qxF 'InaccessiblePaths=/home /root' \
        /etc/systemd/system/noid-audit-event-notify.service \
   && grep -qxF 'RestrictAddressFamilies=AF_UNIX' \
        /etc/systemd/system/noid-audit-event-notify.service \
   && grep -qF -- '--property=LockedHint' \
        /usr/local/libexec/noid-audit-event-notify \
   && grep -qF '/usr/bin/setpriv' /usr/local/libexec/noid-audit-event-notify \
   && grep -qF '/usr/bin/notify-send' /usr/local/libexec/noid-audit-event-notify \
   && ! grep -qF '/usr/bin/setpriv' /usr/local/bin/audit-notify.sh \
   && ! grep -qF '/usr/bin/notify-send' /usr/local/bin/audit-notify.sh \
   && ! grep -qF '/usr/bin/loginctl' /usr/local/bin/audit-notify.sh \
   && grep -qF 'SPOOL_LIMIT = 64' /usr/local/bin/audit-notify.sh \
   && [ "$(systemctl is-enabled noid-audit-event-notify.path 2>/dev/null)" = enabled ]; then
    echo "  [OK] audit event delivery is confined to the normally-domained drain unit"
else
    echo "  [FAIL] audit event notification delivery split invalid"
    fail=$((fail + 1))
fi

# 10.5 — 99-hardening.rules rule count
# Count -a rules + -w rules (-b, -f are config; -e is terminator).
# Use `|| true` pattern to tolerate grep exit 1 on zero matches without
# producing multi-line output from `|| echo 0` (bash $(...) capture bug).
syscall_count=$(grep -cE "^-a " /etc/audit/rules.d/99-hardening.rules 2>/dev/null || true)
legacy_watch_count=$(grep -cE "^-w " /etc/audit/rules.d/99-hardening.rules 2>/dev/null || true)
syscall_count=${syscall_count:-0}
legacy_watch_count=${legacy_watch_count:-0}

if [ "$syscall_count" -eq 132 ] && [ "$legacy_watch_count" -eq 0 ]; then
    echo "  [OK] 99-hardening.rules has exactly 132 ABI-qualified rules and no legacy -w watches"
else
    echo "  [FAIL] 99-hardening.rules expected 132 -a rules and zero -w watches"
    echo "         -a rules: $syscall_count, legacy -w watches: $legacy_watch_count"
    fail=$((fail + 1))
fi

# Every `-F dir=` target that the base package set may omit must already be a
# real, Root-owned directory before audit-rules.service loads the immutable
# rules. A present rule in the file is not evidence that the kernel accepted it.
# Do not impose a hardlink count on directories: Btrfs commonly reports one
# while ext4 accounts for "." and child ".." entries. Linux link(2) rejects
# user-created directory hardlinks; the explicit type and symlink checks are
# the portable substitution boundary.
audit_target_dir_fail=0
for audit_target_spec in "${AUDIT_TARGET_DIRS[@]}"; do
    IFS='|' read -r audit_target_dir audit_target_mode <<< "$audit_target_spec"
    if [ -d "$audit_target_dir" ] && [ ! -L "$audit_target_dir" ] \
       && [ "$(stat -c '%U:%G:%a' "$audit_target_dir" \
            2>/dev/null || true)" = "root:root:${audit_target_mode}" ]; then
        :
    else
        echo "  [FAIL] optional audit directory target invalid: $audit_target_dir (expected mode $audit_target_mode)"
        fail=$((fail + 1))
        audit_target_dir_fail=$((audit_target_dir_fail + 1))
    fi
done
unset audit_target_spec audit_target_dir audit_target_mode
if [ "$audit_target_dir_fail" -eq 0 ]; then
    echo "  [OK] all optional audit directory targets have exact owner-owned modes"
fi
if cmp -s \
    <(grep '^-a .*arch=b64' /etc/audit/rules.d/99-hardening.rules | \
        sed 's/arch=b64/arch=ABI/' | sort) \
    <(grep '^-a .*arch=b32' /etc/audit/rules.d/99-hardening.rules | \
        sed 's/arch=b32/arch=ABI/' | sort); then
    echo "  [OK] every architecture-qualified audit rule has exact b64/b32 parity"
else
    echo "  [FAIL] audit rule b64/b32 parity mismatch"
    fail=$((fail + 1))
fi

# 10.6 — -e 2 is the last rule
# The `|^##` term is redundant (already covered by
# `^#` since both `#` and `##` lines start with `#`).
last_line=$(grep -vE "^$|^#" /etc/audit/rules.d/99-hardening.rules | tail -1)
if [ "$last_line" = "-e 2" ]; then
    echo "  [OK] -e 2 is last rule (immutable mode will activate)"
else
    echo "  [FAIL] -e 2 not last rule — found '$last_line'"
    fail=$((fail + 1))
fi

# 10.7 — no trusted-daemon suppression; all four time syscalls retained
if ! grep -qE '^-a never,exit' /etc/audit/rules.d/99-hardening.rules \
   && [ "$(grep -cE '^-a always,exit -F arch=b(32|64) -S adjtimex -S settimeofday -S clock_settime -S clock_adjtime -k time_change$' \
        /etc/audit/rules.d/99-hardening.rules 2>/dev/null || true)" -eq 2 ]; then
    echo "  [OK] daemon-inclusive adjtimex/settimeofday/clock_settime/clock_adjtime evidence"
else
    echo "  [FAIL] time-change coverage is suppressed or incomplete"
    fail=$((fail + 1))
fi

# 10.8 — Key coverage spot check (all 33 distinct -k tags documented
#        in the header Categories block above)
key_fail=0
for key in identity sudoers sshd_config audit_config aide_integrity login_config security_config pam_changes \
           sysctl modprobe kernel_modules bootloader systemd firewall usbguard_config \
           network_config dns_config network_modifications chrony_config system_locale \
           time_change localtime \
           gnome_session_files user_mgmt sudo_usage su_usage priv_exec \
           luks mount_ops cron login_banners session logins; do
    if grep -qE -- "(^|[[:space:]])-k[[:space:]]+${key}([[:space:]]|$)" \
            /etc/audit/rules.d/99-hardening.rules; then
        :  # present — silent
    else
        echo "  [FAIL] key '$key' missing from rules file"
        fail=$((fail + 1))
        key_fail=$((key_fail + 1))
    fi
done
if [ "$key_fail" -eq 0 ]; then
    echo "  [OK] all 33 expected audit keys present"
fi

# 10.9 — auditd enabled
if systemctl is-enabled auditd.service >/dev/null 2>&1; then
    echo "  [OK] auditd.service enabled"
else
    echo "  [FAIL] auditd.service not enabled"
    fail=$((fail + 1))
fi

# audit-notify integration verification
# 10.10 — auparse plugin, controller and inactive config are exact
#
# Assert only what the plugin itself still owns. The session gauntlet moved to
# the separately-domained drain, so this block asserts the handoff contract
# (queue_notification + the spool path it writes into) and 10.4b above asserts
# the delivery side on the file that now carries it. Greping this file for a
# delivery-side literal is what made every compose abort once the split landed.
if [ "$(stat -c '%U:%G:%a' /usr/local/bin/audit-notify.sh 2>/dev/null || true)" = \
     root:root:755 ] \
   && /usr/bin/python3 -c 'path="/usr/local/bin/audit-notify.sh"; compile(open(path, encoding="utf-8").read(), path, "exec")' \
   && grep -qF 'auparse.AuParser(auparse.AUSOURCE_FEED, None)' \
        /usr/local/bin/audit-notify.sh \
   && grep -qF 'def queue_notification' /usr/local/bin/audit-notify.sh \
   && grep -qF 'SPOOL_DIR = RUNTIME_DIR / "audit-notify.d"' \
        /usr/local/bin/audit-notify.sh \
   && [ "$(stat -c '%U:%G:%a' /usr/local/sbin/noid-audit-notify-controller 2>/dev/null || true)" = \
        root:root:755 ] \
   && bash -n /usr/local/sbin/noid-audit-notify-controller \
   && [ "$(stat -c '%U:%G:%a' /etc/audit/plugins.d/noid-notify.conf 2>/dev/null || true)" = \
        root:root:640 ] \
   && grep -qxF 'active = no' /etc/audit/plugins.d/noid-notify.conf \
   && grep -qxF 'path = /usr/local/bin/audit-notify.sh' \
        /etc/audit/plugins.d/noid-notify.conf \
   && grep -qxF 'type = always' /etc/audit/plugins.d/noid-notify.conf \
   && grep -qxF 'format = string' /etc/audit/plugins.d/noid-notify.conf \
   && [ ! -e /run/noid-privacy/audit-notify-degraded ]; then
    echo "  [OK] inactive auparse plugin and persistent health boundary are exact"
else
    echo "  [FAIL] audit notification plugin/config/controller contract invalid"
    fail=$((fail + 1))
fi

# 10.11 — audit-notify.service unit file present with correct perms
if [ -f /etc/systemd/system/audit-notify.service ]; then
    mode=$(stat -c "%a" /etc/systemd/system/audit-notify.service)
    if [ "$mode" = "644" ]; then
        echo "  [OK] audit-notify.service installed (mode $mode, controller v1)"
    else
        echo "  [FAIL] audit-notify.service mode = $mode (expected 644)"
        fail=$((fail + 1))
    fi
else
    echo "  [FAIL] audit-notify.service unit file missing"
    fail=$((fail + 1))
fi

# 10.12 — audit-notify.service INSTALLED (opt-in,
# so it must NOT be enabled at install-time. Setup handles the user-requested
# change through its exact sudo/pkexec privilege router.)
if [ -L /etc/systemd/system/multi-user.target.wants/audit-notify.service ]; then
    echo "  [FAIL] audit-notify.service is enabled (should be opt-in)"
    fail=$((fail + 1))
elif [ -f /etc/systemd/system/audit-notify.service ]; then
    echo "  [OK] audit-notify.service installed but NOT enabled (opt-in via welcome dialog)"
else
    echo "  [FAIL] audit-notify.service not installed"
    fail=$((fail + 1))
fi

# 10.13 — exact 16-key set remains source-visible and event-complete
if grep -qF 'CRITICAL_KEYS = frozenset(' /usr/local/bin/audit-notify.sh \
   && grep -qF 'AUPARSE_CB_EVENT_READY' /usr/local/bin/audit-notify.sh \
   && grep -qF 'QUEUE_LIMIT = 512' /usr/local/bin/audit-notify.sh; then
    echo "  [OK] audit-notify complete-event/key/queue contracts present"
else
    echo "  [FAIL] audit-notify complete-event/key/queue contract missing"
    fail=$((fail + 1))
fi

if [ $fail -gt 0 ]; then
    echo ""
    echo "[Module 12] FAILED ($fail checks)"
    exit 1
fi

echo ""
echo "=============================================================="
echo "[Module 12] Done — all checks passed"
echo "=============================================================="
echo "First-boot notes:"
echo "  - auditctl -l will show 132 ABI-complete rules after first auditd load"
echo "  - -e 2 becomes effective, auditctl -D will fail"
echo "  - IMA will start collecting measurements (passive, default policy)"
echo "  - SELinux booleans effective after first policy load"
echo "  - audit-notify.service is installed DISABLED; plugin active=no"
echo "  - opt-in uses auditd + auparse complete-event assembly (no log tail)"
echo "  - opt in with: sudo noid-toggle-audit-notify on"
echo "  - popups match event AUID to an unlocked active local logind seat"
echo "  - health: sudo noid-toggle-audit-notify status"

%end

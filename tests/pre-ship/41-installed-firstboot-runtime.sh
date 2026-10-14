#!/usr/bin/env bash
# Installed-candidate gate for complete Kickstart evidence and the first-login
# contracts owned jointly by M08, M17 and M41. It is intentionally read-only.
set -euo pipefail
export LC_ALL=C

TEST_NAME=41-installed-firstboot-runtime
if [[ $# -ne 1 ]]; then
    echo "Usage: sudo bash $0 {fresh-install|reboot}" >&2
    exit 2
fi
PASS_ID=$1
case "$PASS_ID" in
    fresh-install) BOOTS=(0) ;;
    reboot) BOOTS=(-1 0) ;;
    *)
        echo "Usage: sudo bash $0 {fresh-install|reboot}" >&2
        exit 2
        ;;
esac

fail() {
    echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2
    exit 1
}
pass() {
    echo "PASS  $TEST_NAME [$PASS_ID]: $*"
}

verify_prelogin_package_order() {
    python3 - "$1" <<'PY_ORDER'
import json, sys
with open(sys.argv[1]) as stream:
    events = [json.loads(line) for line in stream]
def stamps(unit, result):
    return [int(e["__MONOTONIC_TIMESTAMP"]) for e in events
            if e.get("_PID") == "1" and e.get("UNIT") == unit
            and e.get("JOB_TYPE") == "start" and e.get("JOB_RESULT") == result]
completed = stamps("noid-anaconda-maintenance.service", "done")
admitted = stamps("systemd-user-sessions.service", None)
# Later GDM restarts may re-run the validated no-op. Compare the first
# successful maintenance with the first admission, not the latest ExecMain.
if not completed or not admitted or not (0 < min(completed) <= min(admitted)):
    raise SystemExit("package maintenance did not complete before first login")
PY_ORDER
}

classify_m41_rpm_verify() {
    local verify_file=$1 drift_file=$2 missing_file=$3
    : >"$drift_file"
    : >"$missing_file"
    awk -v drift_file="$drift_file" -v missing_file="$missing_file" '
        function in_m41_scope(path) {
            return path == "/etc/sysconfig" ||
                index(path, "/etc/sysconfig/") == 1 ||
                path == "/usr/lib/grub" ||
                index(path, "/usr/lib/grub/") == 1
        }
        {
            path = $NF
            if (!in_m41_scope(path))
                next
            status = $1
            if (status == "missing") {
                print path >> missing_file
                next
            }
            # rpm -V status positions are:
            # S M 5 D L U G T P. M41 owns only mode/type, link target,
            # owner and group; content, size, mtime and capabilities are
            # deliberately outside its metadata-only repair contract.
            if (length(status) != 9 ||
                substr(status, 2, 1) != "." ||
                substr(status, 5, 1) != "." ||
                substr(status, 6, 1) != "." ||
                substr(status, 7, 1) != ".")
                print >> drift_file
        }
    ' "$verify_file"
}

classify_missing_rpm_path() {
    local records_file=$1 expected_path=$2
    awk -F '\t' -v expected="$expected_path" '
        $1 == expected {
            if ($2 !~ /^[0-7]{5,7}$/ || $3 !~ /^[0-9]+$/) {
                malformed = 1
                next
            }
            flags = $3 + 0
            if (int(flags / 64) % 2 == 1) {
                ignored++
                next
            }
            count++
            if ($2 ~ /^12/)
                links++
            else
                nonlinks++
        }
        END {
            if (malformed)
                print "malformed"
            else if (count == 0 && ignored > 0)
                print "ghost"
            else if (count == 0)
                print "unknown"
            else if (links == count)
                print "symlink"
            else if (nonlinks == count)
                print "non-symlink"
            else
                print "conflict"
        }
    ' "$records_file"
}

# Unique non-ghost regular package files with a SHA-256 payload digest in the
# three trees Anaconda's live-image -rx copy re-stamps. Co-owners that disagree
# leave the path without one authoritative timestamp, exactly as M41 does.
classify_m41_payload_timestamps() {
    local records_file=$1 candidates_file=$2
    : >"$candidates_file"
    awk -F '\t' -v candidates="$candidates_file" '
        function in_m41_scope(path) {
            return index(path, "/etc/sysconfig/") == 1 ||
                index(path, "/usr/lib/grub/") == 1 ||
                index(path, "/boot/grub2/") == 1
        }
        in_m41_scope($1) {
            if (NF != 6 || $2 !~ /^[0-7]{5,7}$/ || $3 !~ /^[0-9]+$/ ||
                $4 !~ /^[0-9]+$/ || $5 !~ /^[0-9]+$/ ||
                $6 !~ /^[0-9a-f]*$/) {
                malformed = 1
                exit
            }
            if ($2 !~ /^10[0-7]{4}$/ || int($3 / 64) % 2 == 1 ||
                length($6) != 64)
                next
            record = $4 "\t" $5 "\t" $6
            if (($1 in seen) && seen[$1] != record)
                conflict[$1] = 1
            seen[$1] = record
        }
        END {
            if (malformed)
                exit 1
            for (path in seen)
                if (!(path in conflict))
                    print path "\t" seen[path] >> candidates
        }
    ' "$records_file"
}

[[ $EUID -eq 0 ]] || fail "run as root in the installed candidate"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for command_name in ausearch awk dnf5 find getent grep journalctl matchpathcon mktemp \
        readlink rpm sed sha256sum sleep sort stat systemctl wc; do
    command -v "$command_name" >/dev/null 2>&1 || \
        fail "required command missing: $command_name"
done

tmp_dir=$(mktemp -d /var/tmp/noid-installed-firstboot.XXXXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT
[[ -d $tmp_dir && ! -L $tmp_dir ]] || fail "temporary evidence directory is unsafe"
# Owner and mode are the security properties here; a directory link count is
# filesystem-dependent (Btrfs 1, tmpfs/fresh overlayfs upper 2) and carries no
# guarantee that mktemp -d has not already given us.
[[ $(stat -c '%u:%a' "$tmp_dir") == 0:700 ]] || \
    fail "temporary evidence directory metadata differs"

# Wait for both maintenance's terminal state and its durable marker. The
# installed boot orders package transactions before admitting user sessions.
marker=/var/lib/noid-privacy/anaconda-cleanup.done
maintenance_unit=noid-anaconda-maintenance.service
maintenance_deadline=$((SECONDS + 620))
while :; do
    maintenance_state=$(systemctl show "$maintenance_unit" \
        -p ActiveState --value 2>/dev/null) || \
        fail "cannot read $maintenance_unit state"
    case "$maintenance_state" in
        failed)
            journalctl -u "$maintenance_unit" --no-pager -n 80 >&2 || true
            fail "$maintenance_unit failed before publishing its marker"
            ;;
        inactive)
            [[ -f $marker && ! -L $marker ]] && break
            ;;
        activating|active|deactivating) ;;
        *) fail "$maintenance_unit entered unexpected state: ${maintenance_state:-empty}" ;;
    esac
    [[ $SECONDS -lt $maintenance_deadline ]] || \
        fail "$maintenance_unit did not publish its marker within 620 seconds"
    sleep 1
done

# Ordering must hold in the installed units, including console-only boots.
# Package failures may leave the safe login available, but a successful boot
# must not race native RPM user-service scriptlets with an existing session.
for login_unit in gdm.service systemd-user-sessions.service; do
    login_after=$(systemctl show "$login_unit" -p After --value) || \
        fail "cannot inspect $login_unit ordering"
    login_wants=$(systemctl show "$login_unit" -p Wants --value) || \
        fail "cannot inspect $login_unit package-maintenance dependency"
    [[ " $login_after " == *" $maintenance_unit "* \
        && " $login_wants " == *" $maintenance_unit "* ]] || \
        fail "$login_unit does not wait for package maintenance"
done

# Compose and installer logs remain private candidate evidence; they are not
# part of the installed workstation. M41 also retires exact logs created by a
# real Anaconda installation before publishing its pre-login success marker.
for installer_evidence in /root/anaconda-ks.cfg /root/original-ks.cfg; do
    [[ ! -e $installer_evidence && ! -L $installer_evidence ]] || \
        fail "installed root retains installer evidence: $installer_evidence"
done
kickstart_log=$tmp_dir/first-kickstart-log
find -P /var/log -mindepth 1 -maxdepth 1 -name 'ks-*.log' \
    -print -quit >"$kickstart_log"
[[ ! -s $kickstart_log ]] || {
    sed -n '1p' "$kickstart_log" >&2
    fail "installed root retains a Kickstart log"
}
anaconda_payload=$tmp_dir/first-anaconda-payload
if [[ -d /var/log/anaconda && ! -L /var/log/anaconda ]]; then
    find -P /var/log/anaconda -xdev -mindepth 1 -print -quit \
        >"$anaconda_payload"
    [[ ! -s $anaconda_payload ]] || {
        sed -n '1p' "$anaconda_payload" >&2
        fail "installed root retains Anaconda log payload"
    }
elif [[ -e /var/log/anaconda || -L /var/log/anaconda ]]; then
    fail "installed Anaconda log path has an unsafe type"
fi

[[ -f $marker && ! -L $marker ]] || \
    fail "M41 first-boot completion marker is missing or unsafe"
[[ $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:644:1 ]] || \
    fail "M41 first-boot completion marker metadata differs"
matchpathcon -V "$marker" >/dev/null 2>&1 || \
    fail "M41 first-boot completion marker SELinux label differs"
[[ $(wc -l <"$marker") -eq 1 ]] || \
    fail "M41 first-boot completion marker is not one record"
grep -qEx \
    '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z cleanup_count=[0-9]+' \
    "$marker" || fail "M41 first-boot completion marker schema differs"

# Anaconda deliberately leaves this systemwide interaction file for
# unprivileged post-install consumers such as GNOME Initial Setup. Its
# generated file is not RPM-owned, so the broad metadata verifier below cannot
# prove it. Require the narrow pre-login publication contract explicitly.
interaction_config=/etc/sysconfig/anaconda
[[ -f $interaction_config && ! -L $interaction_config ]] || \
    fail "Anaconda post-install interaction config is missing or unsafe"
[[ $(readlink -e -- "$interaction_config") == "$interaction_config" ]] || \
    fail "Anaconda post-install interaction config is non-canonical"
[[ $(stat -c '%u:%g:%a:%h' "$interaction_config") == 0:0:644:1 ]] || \
    fail "Anaconda post-install interaction config is not safely readable"
matchpathcon -V "$interaction_config" >/dev/null 2>&1 || \
    fail "Anaconda post-install interaction config SELinux label differs"
awk '
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
        section = $0
        gsub(/[[:space:]]/, "", section)
        next
    }
    section == "[General]" &&
            /^[[:space:]]*post_install_tools_disabled[[:space:]]*=/ {
        value = $0
        sub(/^[^=]*=/, "", value)
        gsub(/[[:space:]]/, "", value)
        if (value !~ /^[01]$/)
            bad = 1
        count++
    }
    END { exit !(count == 1 && !bad) }
' "$interaction_config" || \
    fail "Anaconda post-install interaction config schema differs"

security_marker=/var/lib/noid-privacy/anaconda-cleanup-security.done
[[ -f $security_marker && ! -L $security_marker ]] || \
    fail "M41 pre-login security marker is missing or unsafe"
[[ $(stat -c '%u:%g:%a:%h' "$security_marker") == 0:0:644:1 ]] || \
    fail "M41 pre-login security marker metadata differs"
matchpathcon -V "$security_marker" >/dev/null 2>&1 || \
    fail "M41 pre-login security marker SELinux label differs"
grep -qEx \
    '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z cleanup_count=[0-9]+' \
    "$security_marker" || fail "M41 pre-login security marker schema differs"

# Fedora GDM owns this RPM-ghost path at runtime as root:gdm 0711, while the
# SELinux package owns its xserver_log_t policy. M41 must establish both before
# its security marker can release the first installed GDM process.
gdm_group=$(getent -s files group gdm) || \
    fail "local GDM group is unavailable"
[[ $(printf '%s\n' "$gdm_group" | \
        awk -F: 'NF == 4 && $1 == "gdm" && $3 ~ /^[0-9]+$/ { count++ } END { print count + 0 }') == 1 ]] || \
    fail "local GDM group record is malformed or ambiguous"
gdm_gid=$(printf '%s\n' "$gdm_group" | \
    awk -F: 'NF == 4 && $1 == "gdm" && $3 ~ /^[0-9]+$/ { print $3 }')
[[ $gdm_gid =~ ^[0-9]+$ ]] || fail "local GDM group ID is invalid"
gdm_log_dir=/var/log/gdm
[[ -d $gdm_log_dir && ! -L $gdm_log_dir ]] || \
    fail "GDM log directory is missing or unsafe"
[[ $(readlink -e -- "$gdm_log_dir") == "$gdm_log_dir" ]] || \
    fail "GDM log directory is non-canonical"
[[ $(stat -c '%u:%g:%a' "$gdm_log_dir") == "0:$gdm_gid:711" ]] || \
    fail "GDM log directory metadata differs from GDM's native contract"
matchpathcon -V "$gdm_log_dir" >/dev/null 2>&1 || \
    fail "GDM log directory SELinux label differs"

identity_marker=/var/lib/noid-privacy/host-identity-installed.done
[[ -f $identity_marker && ! -L $identity_marker \
   && $(stat -c '%u:%g:%a:%h' "$identity_marker") == 0:0:644:1 ]] || \
    fail "installed host-identity marker is missing or unsafe"
matchpathcon -V "$identity_marker" >/dev/null 2>&1 || \
    fail "installed host-identity marker SELinux label differs"
grep -qEx \
    'NOID_HOST_IDENTITY_INSTALLED_V1 mode=(rotated|nvme-preserved-active-fabric)' \
    "$identity_marker" || fail "installed host-identity marker schema differs"
/usr/local/bin/noid-host-identity --check >/dev/null \
    || fail "installed host-identity files do not validate"

for property in \
        'LoadState=loaded' \
        'ActiveState=active' \
        'Result=success' \
        'ExecMainStatus=0'; do
    key=${property%%=*}
    expected=${property#*=}
    actual=$(systemctl show noid-host-identity.service \
        -p "$key" --value 2>/dev/null) || \
        fail "cannot read noid-host-identity.service property $key"
    [[ $actual == "$expected" ]] || \
        fail "noid-host-identity.service $key differs: expected $expected, got ${actual:-empty}"
done

for m41_unit in \
        noid-anaconda-cleanup.service \
        noid-anaconda-maintenance.service; do
    for property in \
        'LoadState=loaded' \
        'ActiveState=inactive' \
        'Result=success' \
        'ExecMainStatus=0'; do
        key=${property%%=*}
        expected=${property#*=}
        actual=$(systemctl show "$m41_unit" \
            -p "$key" --value 2>/dev/null) || \
            fail "cannot read $m41_unit property $key"
        [[ $actual == "$expected" ]] || \
            fail "$m41_unit $key differs: expected $expected, got ${actual:-empty}"
    done
done

# M41_INSTALLER_PACKAGE_GATE_BEGIN
# A valid first-boot marker must describe a currently complete installed-image
# transition, not merely a maintenance attempt that once returned zero. Keep
# both the direct installer stack and the dependency-reason result observable.
INSTALLER_ONLY_PKGS=(
    anaconda
    anaconda-core
    anaconda-gui
    anaconda-tui
    anaconda-widgets
    anaconda-widgets-devel
    anaconda-webui
    anaconda-live
    anaconda-dracut
    anaconda-realmd
    anaconda-install-env-deps
    anaconda-install-img-deps
    lorax
    lorax-lmc-novirt
    lorax-lmc-virt
    lorax-templates-generic
    lorax-templates-rhel
    lorax-docs
    livesys-scripts
)
installed_package_names=$(rpm -qa --qf '%{NAME}\n') || \
    fail "cannot enumerate installed packages"
[[ -n $installed_package_names ]] || fail "installed package inventory is empty"
installer_remnants=()
for installer_pkg in "${INSTALLER_ONLY_PKGS[@]}"; do
    if grep -qxF "$installer_pkg" <<<"$installed_package_names"; then
        installer_remnants+=("$installer_pkg")
    fi
done
[[ ${#installer_remnants[@]} -eq 0 ]] || \
    fail "installer-only packages remain: ${installer_remnants[*]}"
[[ ! -e /usr/local/bin/liveinst && ! -L /usr/local/bin/liveinst ]] || \
    fail "M17 Live-installer public-umask wrapper survived installation"

unneeded_packages=$tmp_dir/unneeded-packages
if ! dnf5 --cacheonly repoquery --installed --unneeded \
        --qf '%{name}\n' | sort -u >"$unneeded_packages"; then
    fail "cannot query DNF5 dependency-reason convergence"
fi
if [[ -s $unneeded_packages ]]; then
    sed -n '1,80p' "$unneeded_packages" >&2
    fail "DNF5 still classifies installed packages as unneeded"
fi

# M19's unpackaged GSK helper depends on dbus-tools. M41 must retain the
# explicit user reason it published before autoremove, not merely leave the
# package incidentally required by a transient dependency.
userinstalled_packages=$tmp_dir/userinstalled-packages
if ! dnf5 --cacheonly repoquery --userinstalled \
        --qf '%{name}\n' | sort -u >"$userinstalled_packages"; then
    fail "cannot query DNF5 user-installed package reasons"
fi
grep -qxF dbus-tools "$userinstalled_packages" || \
    fail "dbus-tools does not retain the required user-installed reason"
# M41_INSTALLER_PACKAGE_GATE_END

[[ $(systemctl show accounts-daemon.service -p PrivateTmp --value 2>/dev/null) == no ]] || \
    fail "accounts-daemon no longer preserves Fedora's shared-/tmp contract"
[[ $(systemctl show accounts-daemon.service -p ProtectHome --value 2>/dev/null) == no ]] || \
    fail "accounts-daemon can no longer create a normal user's home"
[[ $(systemctl show accounts-daemon.service -p RestrictSUIDSGID --value 2>/dev/null) == yes ]] || \
    fail "accounts-daemon lost NoID Privacy's compatible hardening"

accounts_dropin=/etc/systemd/system/accounts-daemon.service.d/99-noid-hardening.conf
[[ -f $accounts_dropin && ! -L $accounts_dropin \
   && $(stat -c '%u:%g:%a:%h' "$accounts_dropin") == 0:0:644:1 ]] || \
    fail "accounts-daemon drop-in metadata differs"
matchpathcon -V "$accounts_dropin" >/dev/null 2>&1 || \
    fail "accounts-daemon drop-in SELinux label differs"

rpm_verify=$tmp_dir/rpm-verify
rpm_rc=0
rpm -Va --nodeps --nodigest --nosize --nomtime \
    >"$rpm_verify" 2>"$tmp_dir/rpm-verify.err" || rpm_rc=$?
case "$rpm_rc" in
    0|1) ;;
    *) fail "RPM verification could not inspect installed metadata (rc=$rpm_rc)" ;;
esac
[[ ! -s "$tmp_dir/rpm-verify.err" ]] || \
    fail "RPM metadata verification emitted diagnostics"
[[ $rpm_rc -eq 0 || -s $rpm_verify ]] || \
    fail "RPM metadata verification failed without discrepancy evidence"
classify_m41_rpm_verify \
    "$rpm_verify" "$tmp_dir/scoped-rpm-drift" "$tmp_dir/scoped-rpm-missing" || \
    fail "cannot classify RPM verification evidence in M41 repair scopes"

# Query the installed database independently of filesystem presence. `rpm -qf`
# first resolves its operand as a live path and therefore cannot classify the
# very records that `rpm -Va` has already reported as missing.
rpm_file_records=$tmp_dir/rpm-file-records
if ! rpm -qa --qf '[%{FILENAMES}\t%{FILEMODES:octal}\t%{FILEFLAGS}\n]' \
        >"$rpm_file_records"; then
    fail "cannot enumerate installed RPM file metadata"
fi

# Missing regular files and directories are an explicit preserved state:
# metadata-only convergence cannot recreate their content. An absent
# non-ghost package symlink is different because M41 owns restoring exactly
# that skipped rsync object; resolve only those missing records against the
# installed RPM database.
while IFS= read -r missing_path; do
    [[ $missing_path == /etc/sysconfig ||
       $missing_path == /etc/sysconfig/* ||
       $missing_path == /usr/lib/grub ||
       $missing_path == /usr/lib/grub/* ]] || \
        fail "RPM missing-path classifier emitted an out-of-scope path"
    missing_kind=$(classify_missing_rpm_path \
        "$rpm_file_records" "$missing_path") || \
        fail "cannot classify missing RPM path metadata: $missing_path"
    case "$missing_kind" in
        non-symlink|ghost) ;;
        symlink)
            printf 'missing package symlink %s\n' "$missing_path" \
                >>"$tmp_dir/scoped-rpm-drift"
            ;;
        *)
            fail "ambiguous missing RPM path metadata ($missing_kind): $missing_path"
            ;;
    esac
done <"$tmp_dir/scoped-rpm-missing"

if [[ -s $tmp_dir/scoped-rpm-drift ]]; then
    sed -n '1,80p' "$tmp_dir/scoped-rpm-drift" >&2
    fail "RPM-owned mode/link/owner/group still differs in an M41 repair scope"
fi

# The same transfer recreates /boot/grub2 as 0755, skips selinux-policy's
# scriptlet-published %ghost alias and stamps every file with the copy time.
# M41 owns those three side effects too.
[[ $(stat -c '%u:%g:%a' /boot/grub2 2>/dev/null) == 0:0:700 ]] || \
    fail "GRUB directory differs from its 0700 root:root contract"
[[ -L /etc/sysconfig/selinux \
   && $(readlink /etc/sysconfig/selinux) == ../selinux/config ]] || \
    fail "selinux-policy config alias is absent or differs"
rpm_payload_records=$tmp_dir/rpm-payload-records
if ! rpm -qa --qf '[%{FILENAMES}\t%{FILEMODES:octal}\t%{FILEFLAGS}\t%{FILEMTIMES}\t%{FILESIZES}\t%{FILEDIGESTS}\n]' \
        >"$rpm_payload_records"; then
    fail "cannot enumerate installed RPM payload timestamps"
fi
classify_m41_payload_timestamps \
    "$rpm_payload_records" "$tmp_dir/payload-candidates" || \
    fail "cannot classify RPM payload timestamps in M41 scopes"
payload_count=0
: >"$tmp_dir/payload-drift"
while IFS=$'\t' read -r payload_path payload_mtime payload_size payload_digest; do
    [[ -f $payload_path && ! -L $payload_path \
       && $(stat -c '%h' -- "$payload_path") == 1 ]] || continue
    payload_count=$((payload_count + 1))
    [[ $(stat -c '%Y' -- "$payload_path") != "$payload_mtime" ]] || continue
    [[ $(stat -c '%s' -- "$payload_path") == "$payload_size" ]] || continue
    payload_hash=$(sha256sum -- "$payload_path") || \
        fail "cannot hash package payload: $payload_path"
    [[ ${payload_hash%% *} == "$payload_digest" ]] || continue
    printf 'payload-identical file keeps its transfer timestamp %s\n' \
        "$payload_path" >>"$tmp_dir/payload-drift"
done <"$tmp_dir/payload-candidates"
[[ $payload_count -gt 0 ]] || fail "M41 payload timestamp inventory is empty"
if [[ -s $tmp_dir/payload-drift ]]; then
    sed -n '1,80p' "$tmp_dir/payload-drift" >&2
    fail "byte-identical RPM payload in an M41 scope lacks its package timestamp"
fi

m41_scope_paths=$tmp_dir/m41-scope-paths
if ! find -P /etc/sysconfig /usr/lib/grub -xdev -print0 \
        >"$m41_scope_paths"; then
    fail "cannot enumerate the complete M41 metadata scopes"
fi
m41_scope_count=0
while IFS= read -r -d '' scope_path; do
    matchpathcon -V "$scope_path" >/dev/null 2>&1 || \
        fail "SELinux label differs in an M41 repair scope: $scope_path"
    m41_scope_count=$((m41_scope_count + 1))
done <"$m41_scope_paths"
[[ $m41_scope_count -gt 0 ]] || fail "M41 metadata scope inventory is empty"

journal_pattern='Could not read /etc/sysconfig/anaconda|usericon.*not a regular file|accounts-daemon.*not a regular file|gnome-session-manager@gnome-initial-setup\.service.*(timed out|Failed with result|status=6/ABRT|code=dumped)|Configuration file .*world-inaccessible|dnf(-installer-remove)?: >>> Failed to (start transient service unit|start jobs|disable unit)'
# Audit records live only in auditd (M12 keeps journald's audit socket off), so
# a gnome-session abort is read from the complete audit trail for each boot
# window instead of the journal.
audit_abend_rc=0
audit_abend=$(ausearch -m ANOM_ABEND --raw 2>/dev/null) || audit_abend_rc=$?
case "$audit_abend_rc" in
    0|1) ;;
    *) fail "audit query for ANOM_ABEND records failed (rc=$audit_abend_rc)" ;;
esac
boot_list=$(journalctl --list-boots -o json --no-pager 2>/dev/null) || \
    fail "journal boot list is unreadable"
for boot in "${BOOTS[@]}"; do
    boot_label=current
    [[ $boot == 0 ]] || boot_label=previous
    journalctl -b "$boot" -u "$maintenance_unit" \
        -u systemd-user-sessions.service -o json --no-pager \
        >"$tmp_dir/$boot_label-package-order.json" || \
        fail "$boot_label package-maintenance ordering evidence is unreadable"
    verify_prelogin_package_order "$tmp_dir/$boot_label-package-order.json" || \
        fail "$boot_label user sessions opened before package maintenance completed"
    journal_rc=0
    journalctl -b "$boot" -o short-monotonic --no-pager --quiet \
        --grep="$journal_pattern" >"$tmp_dir/$boot_label-journal" 2>/dev/null \
        || journal_rc=$?
    case "$journal_rc" in
        0)
            sed -n '1,80p' "$tmp_dir/$boot_label-journal" >&2
            fail "$boot_label boot contains a known firstboot regression"
            ;;
        1)
            [[ ! -s $tmp_dir/$boot_label-journal ]] || \
                fail "$boot_label journal returned no-match with output"
            ;;
        *)
            fail "$boot_label journal query failed (rc=$journal_rc)"
            ;;
    esac
    session_abend=$(python3 -c '
import json, re, sys
boot_index = int(sys.argv[1])
boots = json.loads(sys.argv[2])
match = [b for b in boots if int(b.get("index", 1)) == boot_index]
if len(match) != 1:
    raise SystemExit(f"boot {boot_index} is not in the journal boot list")
first = int(match[0]["first_entry"]) / 1e6
last = float("inf") if boot_index == 0 else int(match[0]["last_entry"]) / 1e6
for line in sys.argv[3].splitlines():
    stamp = re.search(r"msg=audit\(([0-9]+\.[0-9]+):", line)
    if (stamp and first <= float(stamp.group(1)) <= last
            and "comm=\"gnome-session" in line):
        print(line)
' "$boot" "$boot_list" "$audit_abend") || \
        fail "$boot_label audit evidence could not be bound to its boot window"
    [[ -z $session_abend ]] || {
        printf '%s\n' "$session_abend" | sed -n '1,20p' >&2
        fail "$boot_label boot contains a gnome-session abort (ANOM_ABEND)"
    }
done

pass "installed compose/Anaconda evidence is absent, the post-install interaction config is safely readable, host identities validate, M41/accounts mode-link-owner-group metadata is exact across $m41_scope_count labeled paths, /boot/grub2 keeps 0700, the SELinux config alias exists, $payload_count payload files keep their RPM timestamps, and ${#BOOTS[@]} boot lifecycle(s) are free of known firstboot regressions"

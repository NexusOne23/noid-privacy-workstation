#!/bin/bash
# M10 candidate runtime gate — native permission policy and function boundary.
# Run as root in live, fresh-install and reboot candidate passes.
set -euo pipefail

pass_id=${1:-}
case "$pass_id" in
    live|fresh-install|reboot) ;;
    *)
        echo "usage: sudo $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac
[[ $EUID -eq 0 ]] || {
    echo "FAIL: permission-policy runtime gate requires root" >&2
    exit 1
}

policy=/etc/tmpfiles.d/90-noid-permission-policy.conf
action=/etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions
for artifact in "$policy" "$action"; do
    [[ -f "$artifact" && ! -L "$artifact" \
       && $(stat -c '%U:%G:%a' "$artifact") == root:root:644 ]] || {
        echo "FAIL: permission artifact missing, symlinked or wrong metadata: $artifact" >&2
        exit 1
    }
done
systemd-tmpfiles --dry-run --create "$policy"

for obsolete in /usr/local/sbin/noid-suid-harden.sh \
                /etc/systemd/system/noid-suid-harden.service \
                /etc/systemd/system/noid-suid-harden.timer; do
    [[ ! -e "$obsolete" && ! -L "$obsolete" ]] || {
        echo "FAIL: obsolete periodic permission mutator remains: $obsolete" >&2
        exit 1
    }
done

[[ $(grep -c '^post_transaction:' "$action") -eq 5 ]] || {
    echo "FAIL: permission dnf5 action trigger count is not five" >&2
    exit 1
}
for pkg in util-linux shadow-utils glusterfs-fuse cronie sudo; do
    grep -qxF \
        "post_transaction:${pkg}:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/bin/systemd-tmpfiles\\ --create\\ /etc/tmpfiles.d/90-noid-permission-policy.conf\\ >/dev/null" \
        "$action" || {
        echo "FAIL: missing exact permission action for $pkg" >&2
        exit 1
    }
done

# path|effective mode|owning RPM|package-declared mode
stripped_specs=(
    '/usr/bin/chfn|711|util-linux|0104711'
    '/usr/bin/chsh|711|util-linux|0104711'
    '/usr/bin/gpasswd|755|shadow-utils|0104755'
    '/usr/bin/newgrp|755|shadow-utils|0104755'
    '/usr/bin/fusermount-glusterfs|755|glusterfs-fuse|0104755'
)
native_specs=(
    '/usr/bin/chage|4755|shadow-utils|0104755'
    '/usr/bin/pam_timestamp_check|4755|pam|0104755'
    '/usr/bin/userhelper|4711|usermode|0104711'
    '/usr/libexec/libgtop_server2|4755|libgtop2|0104755'
)

check_spec() {
    local spec=$1 class=$2 path mode pkg vendor_mode declared_mode
    IFS='|' read -r path mode pkg vendor_mode <<< "$spec"
    [[ -f "$path" && ! -L "$path" ]] || {
        echo "FAIL: $class permission path missing/non-regular/symlinked: $path" >&2
        exit 1
    }
    [[ $(rpm -qf --qf '%{NAME}' "$path") == "$pkg" ]] || {
        echo "FAIL: unexpected RPM owner for $path" >&2
        exit 1
    }
    [[ $(stat -c '%U:%G:%a' "$path") == "root:root:$mode" ]] || {
        echo "FAIL: effective $class permission mismatch for $path" >&2
        exit 1
    }
    declared_mode=$(rpm -q --dump "$pkg" | awk -v p="$path" '$1 == p {print $5}')
    [[ "$declared_mode" == "$vendor_mode" ]] || {
        echo "FAIL: package-declared mode drift for $path: $declared_mode" >&2
        exit 1
    }
    matchpathcon -V "$path" || {
        echo "FAIL: SELinux context drift for $path" >&2
        exit 1
    }
}

for spec in "${stripped_specs[@]}"; do check_spec "$spec" stripped; done
for spec in "${native_specs[@]}"; do check_spec "$spec" native; done

for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
           /etc/cron.monthly /etc/cron.d /etc/sudoers.d; do
    if [[ -d "$dir" ]]; then
        [[ ! -L "$dir" && $(stat -c '%U:%G:%a' "$dir") == root:root:700 ]] || {
            echo "FAIL: root-only policy directory mismatch: $dir" >&2
            exit 1
        }
        matchpathcon -V "$dir" || {
            echo "FAIL: SELinux context drift for $dir" >&2
            exit 1
        }
    fi
done

audit_user=${SUDO_USER:-}
if [[ -z "$audit_user" || "$audit_user" == root ]] \
   || ! id "$audit_user" >/dev/null 2>&1; then
    audit_user=$(getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ {print $1; exit}')
fi
[[ -n "$audit_user" && "$audit_user" != root ]] || {
    echo "FAIL: no normal candidate user found for permission behavior checks" >&2
    exit 1
}

# chage is intentionally native: Fedora documents self `-l` as the supported
# non-root operation. Removing SUID makes this fail against /etc/shadow.
runuser -u "$audit_user" -- /usr/bin/chage -l "$audit_user" >/dev/null || {
    echo "FAIL: normal user cannot inspect their own password-aging state" >&2
    exit 1
}

# The PAM helper documents rc=2 specifically for a non-setuid binary. With no
# reusable timestamp/TTY, maintained candidate results are normally 5, 6 or 7;
# rc=0 is also valid if a timestamp exists.
pam_stderr=$(mktemp /var/tmp/noid-pam-timestamp-check.XXXXXX)
trap 'rm -f -- "$pam_stderr"' EXIT
set +e
runuser -u "$audit_user" -- /usr/bin/pam_timestamp_check \
    >/dev/null 2>"$pam_stderr"
pam_rc=$?
rm -f -- "$pam_stderr"
trap - EXIT
set -e
case "$pam_rc" in
    0|5|6|7) ;;
    2)
        echo "FAIL: pam_timestamp_check reports that its required SUID is absent" >&2
        exit 1
        ;;
    *)
        echo "FAIL: unexpected pam_timestamp_check rc=$pam_rc" >&2
        exit 1
        ;;
esac

# chsh retains its non-mutating listing interface. With CHFN_RESTRICT closed
# and SUID deliberately stripped, current util-linux rejects chfn before even
# rendering --help; require that exact fail-closed behavior instead of
# misreporting the rejection as an unusable candidate.
runuser -u "$audit_user" -- /usr/bin/chsh -l >/dev/null || {
    echo "FAIL: normal user cannot list the installed login shells" >&2
    exit 1
}
set +e
chfn_output=$(runuser -u "$audit_user" -- env LC_ALL=C \
    /usr/bin/chfn --help 2>&1)
chfn_rc=$?
set -e
[[ $chfn_rc -eq 1 \
   && $chfn_output == 'chfn: /etc/login.defs: CHFN_RESTRICT does not allow any changes' ]] || {
    echo "FAIL: stripped chfn did not enforce the exact CHFN_RESTRICT denial" >&2
    exit 1
}

read -r vfs_options fs_options < <(
    findmnt -n -o VFS-OPTIONS,FS-OPTIONS -T /usr/bin/chage
) || {
    echo "FAIL: cannot inspect mount options for retained Fedora SUID paths" >&2
    exit 1
}
mount_opts="$vfs_options,$fs_options"
[[ ",$mount_opts," != *,nosuid,* ]] || {
    echo "FAIL: retained Fedora SUID paths are disabled by a nosuid mount" >&2
    exit 1
}

permission_versions=$(
    for pkg in util-linux shadow-utils pam usermode glusterfs-fuse libgtop2 cronie sudo; do
        rpm -q --qf '%{NAME}-%{EVR}.%{ARCH}\n' "$pkg" 2>/dev/null \
            || printf '%s=absent\n' "$pkg"
    done | paste -sd, -
)
echo "PASS: M10 native permission policy [$pass_id] pam_rc=$pam_rc chfn_rc=$chfn_rc packages=$permission_versions"

#!/usr/bin/env bash
# Exact raw-compose -> SquashFS transport -> installed-system ACL release gate.
#
# Usage:
#   30-live-payload-acl-parity.sh RAW_ROOT SQUASH_ROOT INSTALLED_ROOT
#
# The three arguments are already-mounted/extracted roots. SquashFS may either
# preserve the reviewed ACLs (future toolchains) or show the exact known loss
# state, but the latter is accepted only with byte-identical restore artifacts.
# The installed root must always match the complete manifest.
set -euo pipefail

TEST_NAME=30-live-payload-acl-parity
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MANIFEST=${NOID_ACL_MANIFEST:-$REPO_ROOT/manifests/live-payload-acls.tsv}

[ "$#" -eq 3 ] || {
    echo "FAIL  $TEST_NAME: expected RAW_ROOT SQUASH_ROOT INSTALLED_ROOT" >&2
    exit 2
}
for tool in getfacl stat readlink cmp awk sed paste systemctl; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FAIL  $TEST_NAME: missing command: $tool" >&2
        exit 2
    }
done
[ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || {
    echo "FAIL  $TEST_NAME: canonical manifest is unavailable" >&2
    exit 2
}

declare -a ROOTS
for supplied_root in "$@"; do
    [ -d "$supplied_root" ] && [ ! -L "$supplied_root" ] || {
        echo "FAIL  $TEST_NAME: invalid root: $supplied_root" >&2
        exit 2
    }
    canonical_root=$(readlink -f -- "$supplied_root")
    [ -n "$canonical_root" ] || {
        echo "FAIL  $TEST_NAME: cannot canonicalize root: $supplied_root" >&2
        exit 2
    }
    ROOTS+=("$canonical_root")
done
RAW_ROOT=${ROOTS[0]}
SQUASH_ROOT=${ROOTS[1]}
INSTALLED_ROOT=${ROOTS[2]}

target_uid() {
    local root=$1 name=$2
    awk -F: -v name="$name" '$1 == name { print $3; found=1; exit } END { exit !found }' \
        "$root/etc/passwd"
}

target_gid() {
    local root=$1 name=$2
    awk -F: -v name="$name" '$1 == name { print $3; found=1; exit } END { exit !found }' \
        "$root/etc/group"
}

numeric_acl() {
    local root=$1 acl=$2 entry name uid gid output="" prefix suffix
    local -a entries
    IFS=',' read -r -a entries <<< "$acl"
    for entry in "${entries[@]}"; do
        prefix=""
        suffix=$entry
        if [[ $suffix == default:* ]]; then
            prefix=default:
            suffix=${suffix#default:}
        fi
        if [[ $suffix == group:*:* ]] && [[ $suffix != group::* ]]; then
            name=${suffix#group:}
            name=${name%%:*}
            gid=$(target_gid "$root" "$name") || {
                echo "FAIL  $TEST_NAME: target group is absent in $root: $name" >&2
                return 1
            }
            suffix="group:${gid}:${suffix##*:}"
        elif [[ $suffix == user:*:* ]] && [[ $suffix != user::* ]]; then
            name=${suffix#user:}
            name=${name%%:*}
            uid=$(target_uid "$root" "$name") || {
                echo "FAIL  $TEST_NAME: target user is absent in $root: $name" >&2
                return 1
            }
            suffix="user:${uid}:${suffix##*:}"
        fi
        output+="${output:+,}${prefix}${suffix}"
    done
    printf '%s\n' "$output"
}

actual_acl() {
    local root=$1 path=$2
    getfacl -cnp -- "${root%/}${path}" | sed '/^$/d' | paste -sd, -
}

trivial_transport_acl() {
    local access=$1 entry output=""
    local -a entries
    IFS=',' read -r -a entries <<< "$access"
    for entry in "${entries[@]}"; do
        case "$entry" in
            user::*|group::*|other::*) output+="${output:+,}${entry}" ;;
        esac
    done
    printf '%s\n' "$output"
}

check_exact_root() {
    local label=$1 root=$2 path mode owner group access_acl default_acl
    local full expected actual uid gid
    while IFS='|' read -r path mode owner group access_acl default_acl; do
        full="${root%/}${path}"
        [ -d "$full" ] && [ ! -L "$full" ] \
            || { echo "FAIL  $TEST_NAME: $label path invalid: $path" >&2; return 1; }
        uid=$(target_uid "$root" "$owner") || {
            echo "FAIL  $TEST_NAME: $label owner is absent for $path: $owner" >&2
            return 1
        }
        gid=$(target_gid "$root" "$group") || {
            echo "FAIL  $TEST_NAME: $label group is absent for $path: $group" >&2
            return 1
        }
        [ "$(stat -c '%a:%u:%g' -- "$full")" = "$mode:$uid:$gid" ] \
            || { echo "FAIL  $TEST_NAME: $label owner/mode drift: $path" >&2; return 1; }
        expected=$(numeric_acl "$root" "$access_acl,$default_acl") || return 1
        actual=$(actual_acl "$root" "$path") || {
            echo "FAIL  $TEST_NAME: cannot read $label ACL: $path" >&2
            return 1
        }
        [ "$actual" = "$expected" ] \
            || { echo "FAIL  $TEST_NAME: $label ACL drift: $path" >&2; return 1; }
    done < "$MANIFEST"
}

check_squash_transport() {
    local path mode owner group access_acl default_acl full expected trivial actual uid gid
    local state=""
    while IFS='|' read -r path mode owner group access_acl default_acl; do
        full="${SQUASH_ROOT%/}${path}"
        [ -d "$full" ] && [ ! -L "$full" ] || {
            echo "FAIL  $TEST_NAME: SquashFS path invalid: $path" >&2
            return 1
        }
        uid=$(target_uid "$SQUASH_ROOT" "$owner") || {
            echo "FAIL  $TEST_NAME: SquashFS owner is absent for $path: $owner" >&2
            return 1
        }
        gid=$(target_gid "$SQUASH_ROOT" "$group") || {
            echo "FAIL  $TEST_NAME: SquashFS group is absent for $path: $group" >&2
            return 1
        }
        [ "$(stat -c '%a:%u:%g' -- "$full")" = "$mode:$uid:$gid" ] || {
            echo "FAIL  $TEST_NAME: SquashFS owner/mode drift: $path" >&2
            return 1
        }
        expected=$(numeric_acl "$SQUASH_ROOT" "$access_acl,$default_acl") || return 1
        trivial=$(numeric_acl "$SQUASH_ROOT" "$(trivial_transport_acl "$access_acl")") \
            || return 1
        actual=$(actual_acl "$SQUASH_ROOT" "$path") || {
            echo "FAIL  $TEST_NAME: cannot read SquashFS ACL: $path" >&2
            return 1
        }
        if [ "$actual" = "$expected" ]; then
            current=preserved
        elif [ "$actual" = "$trivial" ]; then
            current=known-loss
        else
            echo "FAIL  $TEST_NAME: unknown SquashFS ACL state: $path" >&2
            return 1
        fi
        [ -z "$state" ] || [ "$state" = "$current" ] || {
            echo "FAIL  $TEST_NAME: mixed SquashFS ACL transport state" >&2
            return 1
        }
        state=$current
    done < "$MANIFEST"
    printf '%s\n' "$state"
}

rooted_link_target() {
    local root=$1 link=$2 raw
    raw=$(readlink -- "$link") || return 1
    if [[ $raw == /* ]]; then
        printf '%s%s\n' "${root%/}" "$raw"
    else
        readlink -m -- "$(dirname -- "$link")/$raw"
    fi
}

check_exact_root raw "$RAW_ROOT"
squash_state=$(check_squash_transport)

for root in "$SQUASH_ROOT" "$INSTALLED_ROOT"; do
    cmp -s "$MANIFEST" "$root/usr/share/noid-privacy/live-payload-acls.tsv" || {
        echo "FAIL  $TEST_NAME: deployed ACL manifest differs in $root" >&2
        exit 1
    }
    [ -x "$root/usr/libexec/noid-restore-live-payload-acls" ] || {
        echo "FAIL  $TEST_NAME: ACL restore helper missing or not executable in $root" >&2
        exit 1
    }
    [ -f "$root/usr/lib/systemd/system/noid-live-payload-acl-restore.service" ] || {
        echo "FAIL  $TEST_NAME: ACL restore unit missing in $root" >&2
        exit 1
    }
    enabled="$root/etc/systemd/system/sysinit.target.wants/noid-live-payload-acl-restore.service"
    [ -L "$enabled" ] \
        && [ "$(rooted_link_target "$root" "$enabled")" = \
             "${root%/}/usr/lib/systemd/system/noid-live-payload-acl-restore.service" ] \
        || { echo "FAIL  $TEST_NAME: ACL restore not enabled in $root" >&2; exit 1; }
done
cmp -s "$SQUASH_ROOT/usr/libexec/noid-restore-live-payload-acls" \
    "$INSTALLED_ROOT/usr/libexec/noid-restore-live-payload-acls" || {
    echo "FAIL  $TEST_NAME: restore helper changed across installation" >&2
    exit 1
}
check_exact_root installed "$INSTALLED_ROOT"

if [ "$INSTALLED_ROOT" = "/" ]; then
    systemctl is-enabled noid-live-payload-acl-restore.service >/dev/null || {
        echo "FAIL  $TEST_NAME: installed ACL restore unit is not enabled" >&2
        exit 1
    }
    systemctl is-active noid-live-payload-acl-restore.service >/dev/null || {
        echo "FAIL  $TEST_NAME: installed ACL restore unit is not active" >&2
        exit 1
    }
    [ "$(systemctl show -p Result --value noid-live-payload-acl-restore.service)" = success ] || {
        echo "FAIL  $TEST_NAME: installed ACL restore unit result is not success" >&2
        exit 1
    }
    [ "$(systemctl show -p PrivateTmp --value noid-live-payload-acl-restore.service)" = no ] || {
        echo "FAIL  $TEST_NAME: ACL restore unit lost its shared-/tmp contract" >&2
        exit 1
    }
    [ "$(systemctl show -p RuntimeDirectory --value noid-live-payload-acl-restore.service)" = noid-live-payload-acls ] || {
        echo "FAIL  $TEST_NAME: ACL restore RuntimeDirectory differs" >&2
        exit 1
    }
    unit_after=$(systemctl show -p After --value \
        noid-live-payload-acl-restore.service) || {
        echo "FAIL  $TEST_NAME: cannot read ACL restore unit ordering" >&2
        exit 1
    }
    unit_after=" $unit_after "
    [[ $unit_after != *" systemd-tmpfiles-setup.service "* ]] || {
        echo "FAIL  $TEST_NAME: ACL restore unit runs after tmpfiles setup" >&2
        exit 1
    }
fi

echo "PASS  $TEST_NAME: raw=exact squash=$squash_state installed=exact"

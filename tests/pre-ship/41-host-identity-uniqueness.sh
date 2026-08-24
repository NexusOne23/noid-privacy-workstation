#!/usr/bin/env bash
# Two-install release gate for machine-local identities. Raw values are never
# printed or written to evidence; comparison uses per-field SHA-256 only.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin
umask 0077

TEST_NAME=41-host-identity-uniqueness
fail() { echo "FAIL  $TEST_NAME: $*" >&2; exit 1; }
pass() { echo "PASS  $TEST_NAME: $*"; }

usage() {
    echo "Usage: sudo bash $0 record ABSOLUTE-EVIDENCE-FILE | compare EVIDENCE-A EVIDENCE-B" >&2
    exit 2
}

validate_evidence() {
    local path=$1
    [[ -f $path && ! -L $path \
       && $(stat -c '%u:%g:%a:%h' "$path") == 0:0:600:1 \
       && $(wc -l <"$path") -eq 6 ]] || return 1
    awk '
        NR == 1 {
            if ($0 != "NOID_HOST_IDENTITY_EVIDENCE_V1") exit 1
            next
        }
        /^[a-z_]+=[a-f0-9]{64}$/ {
            split($0, fields, "=")
            if (seen[fields[1]]++) exit 1
            next
        }
        { exit 1 }
        END {
            if (!(seen["machine_id"] == 1 &&
                  seen["random_seed"] == 1 &&
                  seen["brlapi_key"] == 1 &&
                  seen["nvme_hostid"] == 1 &&
                  seen["nvme_hostnqn"] == 1)) exit 1
        }
    ' "$path"
}

record_evidence() {
    local output=$1 parent candidate machine_id
    [[ $EUID -eq 0 ]] || fail "record mode must run as root"
    [[ $output == /* ]] || fail "evidence path must be absolute"
    parent=${output%/*}
    [[ -d $parent && ! -L $parent \
       && $(readlink -e -- "$parent") == "$parent" \
       && $(stat -c '%u:%g:%a' "$parent") == 0:0:700 ]] || \
        fail "evidence parent must be a canonical root-owned 0700 directory"
    [[ ! -e $output && ! -L $output ]] || fail "evidence target already exists"
    grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
        fail "not running inside the NoID Privacy candidate"
    /usr/local/bin/noid-host-identity --check >/dev/null \
        || fail "host identity files do not validate"
    [[ -f /etc/machine-id && ! -L /etc/machine-id \
       && $(stat -c '%u:%g:%a:%h:%s' /etc/machine-id) == 0:0:444:1:33 ]] || \
        fail "machine-id metadata differs"
    IFS= read -r machine_id </etc/machine-id || fail "cannot read machine-id"
    [[ $machine_id =~ ^[a-f0-9]{32}$ ]] || fail "machine-id schema differs"
    [[ -f /var/lib/systemd/random-seed \
       && ! -L /var/lib/systemd/random-seed \
       && $(stat -c '%u:%g:%a:%h:%s' /var/lib/systemd/random-seed) == \
            0:0:600:1:32 ]] || fail "random-seed metadata differs"

    candidate=$(mktemp "$parent/.host-identity-evidence.XXXXXXXX") \
        || fail "cannot stage identity evidence"
    {
        echo NOID_HOST_IDENTITY_EVIDENCE_V1
        printf 'machine_id=%s\n' "$(sha256sum /etc/machine-id | cut -d ' ' -f1)"
        printf 'random_seed=%s\n' "$(sha256sum /var/lib/systemd/random-seed | cut -d ' ' -f1)"
        printf 'brlapi_key=%s\n' "$(sha256sum /etc/brlapi.key | cut -d ' ' -f1)"
        printf 'nvme_hostid=%s\n' "$(sha256sum /etc/nvme/hostid | cut -d ' ' -f1)"
        printf 'nvme_hostnqn=%s\n' "$(sha256sum /etc/nvme/hostnqn | cut -d ' ' -f1)"
    } >"$candidate"
    chown root:root "$candidate"
    chmod 0600 "$candidate"
    validate_evidence "$candidate" || fail "staged identity evidence is invalid"
    sync -- "$candidate"
    mv -T -- "$candidate" "$output"
    sync -- "$parent"
    validate_evidence "$output" || fail "published identity evidence is invalid"
    pass "recorded private per-field digests without disclosing identity values"
}

compare_evidence() {
    local first=$1 second=$2 field first_digest second_digest
    validate_evidence "$first" || fail "first evidence record is invalid"
    validate_evidence "$second" || fail "second evidence record is invalid"
    [[ $(readlink -e -- "$first") != $(readlink -e -- "$second") ]] || \
        fail "both arguments resolve to the same evidence record"
    for field in machine_id random_seed brlapi_key nvme_hostid nvme_hostnqn; do
        first_digest=$(awk -F= -v wanted="$field" '$1 == wanted { print $2 }' "$first")
        second_digest=$(awk -F= -v wanted="$field" '$1 == wanted { print $2 }' "$second")
        [[ $first_digest != "$second_digest" ]] || \
            fail "$field was reused across two independent installations"
    done
    pass "all five machine-local values differ across two independent installations"
}

[[ $# -ge 1 ]] || usage
case "$1" in
    record) [[ $# -eq 2 ]] || usage; record_evidence "$2" ;;
    compare) [[ $# -eq 3 ]] || usage; compare_evidence "$2" "$3" ;;
    *) usage ;;
esac

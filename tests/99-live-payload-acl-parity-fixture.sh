#!/usr/bin/env bash
# Rootless regression fixture for offline-root systemd symlink resolution in
# the raw -> SquashFS -> installed ACL parity gate.
set -euo pipefail

TEST_NAME=99-live-payload-acl-parity-fixture
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/var/tmp}/noid-acl-parity-fixture.XXXXXX")
GATE="$ROOT/tests/pre-ship/99-live-payload-acl-parity.sh"

fail() {
    echo "FAIL  $TEST_NAME: $*" >&2
    exit 1
}

cleanup() {
    chmod -R u+rwX "$WORK" 2>/dev/null || true
    find "$WORK" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

user=$(id -un)
group=$(id -gn)
uid=$(id -u)
gid=$(id -g)
manifest="$WORK/manifest.tsv"
printf '/payload|750|%s|%s|user::rwx,group::r-x,other::---|default:user::rwx,default:group::r-x,default:other::---\n' \
    "$user" "$group" > "$manifest"

make_root() {
    local target=$1
    mkdir -p "$target/etc/systemd/system/sysinit.target.wants" \
        "$target/usr/lib/systemd/system" "$target/usr/libexec" \
        "$target/usr/share/noid-privacy" "$target/payload"
    printf '%s:x:%s:%s::/home/%s:/bin/bash\n' "$user" "$uid" "$gid" "$user" \
        > "$target/etc/passwd"
    printf '%s:x:%s:\n' "$group" "$gid" > "$target/etc/group"
    cp "$manifest" "$target/usr/share/noid-privacy/live-payload-acls.tsv"
    printf '#!/usr/bin/env bash\nexit 0\n' \
        > "$target/usr/libexec/noid-restore-live-payload-acls"
    chmod 0755 "$target/usr/libexec/noid-restore-live-payload-acls"
    printf '[Unit]\nDescription=fixture\n' \
        > "$target/usr/lib/systemd/system/noid-live-payload-acl-restore.service"
    ln -s /usr/lib/systemd/system/noid-live-payload-acl-restore.service \
        "$target/etc/systemd/system/sysinit.target.wants/noid-live-payload-acl-restore.service"
    chmod 0750 "$target/payload"
    setfacl -b -k "$target/payload"
    setfacl -m d:u::rwx,d:g::r-x,d:o::--- "$target/payload"
}

make_case() {
    local case_name=$1 phase
    for phase in raw squash installed; do
        make_root "$WORK/$case_name/$phase"
    done
}

make_two_row_case() {
    local case_name=$1 phase target
    mkdir -p "$WORK/$case_name"
    {
        cat "$manifest"
        printf '/payload2|750|%s|%s|user::rwx,group::r-x,other::---|default:user::rwx,default:group::r-x,default:other::---\n' \
            "$user" "$group"
    } > "$WORK/$case_name/manifest.tsv"
    for phase in raw squash installed; do
        target="$WORK/$case_name/$phase"
        make_root "$target"
        cp "$WORK/$case_name/manifest.tsv" \
            "$target/usr/share/noid-privacy/live-payload-acls.tsv"
        mkdir -p "$target/payload2"
        chmod 0750 "$target/payload2"
        setfacl -b -k "$target/payload2"
        setfacl -m d:u::rwx,d:g::r-x,d:o::--- "$target/payload2"
    done
}

run_case() {
    local case_name=$1 case_manifest=$manifest
    if [ -f "$WORK/$case_name/manifest.tsv" ]; then
        case_manifest="$WORK/$case_name/manifest.tsv"
    fi
    NOID_ACL_MANIFEST="$case_manifest" bash "$GATE" \
        "$WORK/$case_name/raw" \
        "$WORK/$case_name/squash" \
        "$WORK/$case_name/installed"
}

expect_pass() {
    local case_name=$1 squash_state=$2 output
    output=$(run_case "$case_name" 2>&1) || \
        fail "$case_name unexpectedly failed: $output"
    [[ $output == \
        "PASS  99-live-payload-acl-parity: raw=exact squash=$squash_state installed=exact" ]] || \
        fail "$case_name returned unexpected evidence: $output"
}

expect_fail() {
    local case_name=$1 expected=$2 output
    if output=$(run_case "$case_name" 2>&1); then
        fail "$case_name unexpectedly passed: $output"
    fi
    grep -qF "$expected" <<< "$output" || \
        fail "$case_name failed outside its intended assertion: $output"
}

make_case preserved
expect_pass preserved preserved

make_case known-loss
setfacl -b -k "$WORK/known-loss/squash/payload"
expect_pass known-loss known-loss

make_case relative-link
relative_enabled="$WORK/relative-link/squash/etc/systemd/system/sysinit.target.wants/noid-live-payload-acl-restore.service"
rm -f -- "$relative_enabled"
ln -s ../../../../usr/lib/systemd/system/noid-live-payload-acl-restore.service \
    "$relative_enabled"
expect_pass relative-link preserved

make_case mode-drift
chmod 0755 "$WORK/mode-drift/raw/payload"
expect_fail mode-drift 'raw owner/mode drift: /payload'

make_case owner-drift
bad_uid=$((uid + 1))
printf '%s:x:%s:%s::/home/%s:/bin/bash\n' \
    "$user" "$bad_uid" "$gid" "$user" > "$WORK/owner-drift/raw/etc/passwd"
expect_fail owner-drift 'raw owner/mode drift: /payload'

make_case acl-drift
setfacl -m d:o::r-x "$WORK/acl-drift/raw/payload"
expect_fail acl-drift 'raw ACL drift: /payload'

make_case missing-link
rm -f -- "$WORK/missing-link/squash/etc/systemd/system/sysinit.target.wants/noid-live-payload-acl-restore.service"
expect_fail missing-link 'ACL restore not enabled in'

make_case wrong-relative-link
wrong_enabled="$WORK/wrong-relative-link/squash/etc/systemd/system/sysinit.target.wants/noid-live-payload-acl-restore.service"
rm -f -- "$wrong_enabled"
ln -s ../../../usr/lib/systemd/system/noid-live-payload-acl-restore.service \
    "$wrong_enabled"
expect_fail wrong-relative-link 'ACL restore not enabled in'

make_case helper-drift
printf '# drift\n' >> \
    "$WORK/helper-drift/installed/usr/libexec/noid-restore-live-payload-acls"
expect_fail helper-drift 'restore helper changed across installation'

make_case manifest-drift
printf '# drift\n' >> \
    "$WORK/manifest-drift/squash/usr/share/noid-privacy/live-payload-acls.tsv"
expect_fail manifest-drift 'deployed ACL manifest differs in'

make_case installed-acl-drift
setfacl -m d:o::r-x "$WORK/installed-acl-drift/installed/payload"
expect_fail installed-acl-drift 'installed ACL drift: /payload'

make_case squash-mode-drift
chmod 0755 "$WORK/squash-mode-drift/squash/payload"
expect_fail squash-mode-drift 'SquashFS owner/mode drift: /payload'

make_case unknown-squash-acl
setfacl -m "u:${uid}:r-x" "$WORK/unknown-squash-acl/squash/payload"
expect_fail unknown-squash-acl 'unknown SquashFS ACL state: /payload'

make_case missing-unit
rm -f -- "$WORK/missing-unit/squash/usr/lib/systemd/system/noid-live-payload-acl-restore.service"
expect_fail missing-unit 'ACL restore unit missing in'

make_case missing-helper
rm -f -- "$WORK/missing-helper/installed/usr/libexec/noid-restore-live-payload-acls"
expect_fail missing-helper 'ACL restore helper missing or not executable in'

make_two_row_case two-row-preserved
expect_pass two-row-preserved preserved

make_two_row_case two-row-known-loss
setfacl -b -k "$WORK/two-row-known-loss/squash/payload" \
    "$WORK/two-row-known-loss/squash/payload2"
expect_pass two-row-known-loss known-loss

make_two_row_case mixed-transport
setfacl -b -k "$WORK/mixed-transport/squash/payload2"
expect_fail mixed-transport 'mixed SquashFS ACL transport state'

echo "PASS  $TEST_NAME: one- and two-path preserved/known-loss transport and exact failure classes verified"

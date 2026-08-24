#!/usr/bin/env bash
# Structural and positive-control fixtures for final rootfs hygiene.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT=$(find_project_root)
VERIFIER=$PROJECT_ROOT/scripts/verify-rootfs-hygiene.py
WRAPPER=$PROJECT_ROOT/scripts/verify-live-image-hygiene.sh
TMPDIR=$(mktemp -d)
trap 'rm -rf -- "$TMPDIR"' EXIT

test_start "00-rootfs-hygiene"
assert_file_executable "$VERIFIER" "rootfs hygiene verifier is executable"
assert_file_executable "$WRAPPER" "final Live ISO hygiene wrapper is executable"
assert_cmd_success "rootfs hygiene verifier compiles" \
    env PYTHONPYCACHEPREFIX="$TMPDIR/pycache" \
    python3 -m py_compile "$VERIFIER"
assert_cmd_success "final Live ISO hygiene wrapper parses" bash -n "$WRAPPER"

fixture=$TMPDIR/root
mkdir -p \
    "$fixture/etc/NetworkManager/system-connections" \
    "$fixture/etc/nvme" \
    "$fixture/etc/ssh" \
    "$fixture/root" \
    "$fixture/var/lib/NetworkManager" \
    "$fixture/var/lib/chrony" \
    "$fixture/var/lib/dbus" \
    "$fixture/var/lib/systemd" \
    "$fixture/var/log/journal"
: > "$fixture/etc/machine-id"
chmod 0444 "$fixture/etc/machine-id"
ln -s /etc/machine-id "$fixture/var/lib/dbus/machine-id"

run_verifier() {
    local report=$1
    python3 -B -I "$VERIFIER" --root "$fixture" --report "$report" \
        --expected-uid "$(id -u)" --expected-gid "$(id -g)"
}

assert_cmd_success "clean golden-root fixture passes" \
    run_verifier "$TMPDIR/clean.json"
assert_grep_fixed '"schema": "NOID_ROOTFS_HYGIENE_V1"' "$TMPDIR/clean.json"
assert_grep_fixed '"verdict": "pass"' "$TMPDIR/clean.json"

assert_positive_control() {
    local description=$1 path=$2 report=$3
    install -D -m 0600 /dev/null "$fixture/$path"
    assert_cmd_failure "$description is detected" run_verifier "$report"
    rm -f -- "$fixture/$path"
}

positive_index=0
for forbidden_path in \
    etc/brlapi.key \
    etc/nvme/hostid \
    etc/nvme/hostnqn \
    root/anaconda-ks.cfg \
    root/original-ks.cfg \
    var/lib/noid-privacy/host-identity-installed.done \
    var/lib/systemd/random-seed; do
    positive_index=$((positive_index + 1))
    assert_positive_control "forbidden $forbidden_path" "$forbidden_path" \
        "$TMPDIR/positive-$positive_index.json"
done

for state_path in \
    etc/NetworkManager/system-connections/compose.nmconnection \
    var/lib/NetworkManager/secret_key \
    var/lib/chrony/drift \
    var/log/journal/compose-journal; do
    positive_index=$((positive_index + 1))
    assert_positive_control "state artifact $state_path" "$state_path" \
        "$TMPDIR/positive-$positive_index.json"
done

positive_index=$((positive_index + 1))
assert_positive_control "compose log" "var/log/ks-fixture.log" \
    "$TMPDIR/positive-$positive_index.json"
positive_index=$((positive_index + 1))
assert_positive_control "SSH host private key" "etc/ssh/ssh_host_ed25519_key" \
    "$TMPDIR/positive-$positive_index.json"

chmod 0644 "$fixture/etc/machine-id"
assert_cmd_failure "noncanonical machine-id metadata is detected" \
    run_verifier "$TMPDIR/machine-id-mode.json"
chmod 0444 "$fixture/etc/machine-id"
rm -f -- "$fixture/var/lib/dbus/machine-id"
ln -s /wrong-target "$fixture/var/lib/dbus/machine-id"
assert_cmd_failure "wrong D-Bus machine-id link is detected" \
    run_verifier "$TMPDIR/dbus-link.json"
rm -f -- "$fixture/var/lib/dbus/machine-id"
rmdir "$fixture/var/lib/dbus"
mkdir "$TMPDIR/outside-dbus"
ln -s "$TMPDIR/outside-dbus" "$fixture/var/lib/dbus"
assert_cmd_failure "symlinked verifier parent is rejected" \
    run_verifier "$TMPDIR/dbus-parent.json"

assert_grep_fixed 'xorriso -osirrox on' "$WRAPPER" \
    "wrapper extracts the final ISO filesystem"
assert_grep_fixed 'unsquashfs -no-progress' "$WRAPPER" \
    "wrapper extracts the nested final rootfs image"
assert_grep_fixed 'losetup --find --show --read-only' "$WRAPPER" \
    "wrapper uses a read-only loop device"
assert_grep_fixed 'mount -t ext4 -o ro,noload' "$WRAPPER" \
    "wrapper mounts without replaying the ext4 journal"
assert_grep_fixed 'ISO path must be canonical' "$WRAPPER" \
    "wrapper rejects an ISO reached through symlinked path components"

test_finish

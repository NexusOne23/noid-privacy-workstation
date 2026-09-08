#!/bin/bash
# Candidate-only M10 umask scope gate. Run as the normal user in all VM passes.

set -euo pipefail

TEST_NAME=10-umask-runtime
PASS_ID="${1:-}"
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *)
        echo "Usage: bash $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac

fail() {
    echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2
    exit 1
}

[[ $EUID -ne 0 ]] || fail "run as the normal candidate user"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for cmd in bash dnf mkdir stat touch; do
    command -v "$cmd" >/dev/null 2>&1 || fail "required command missing: $cmd"
done

DROPIN=/etc/profile.d/99-noid-security-umask.sh
[[ -r "$DROPIN" && ! -L "$DROPIN" ]] || fail "umask drop-in missing or symlinked"
bash -n "$DROPIN" || fail "umask drop-in does not parse"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf -- "$tmpdir"; }
trap cleanup EXIT INT TERM

umask 022
bash -lc "touch '$tmpdir/noninteractive-file'; mkdir '$tmpdir/noninteractive-dir'"
bash -lic "touch '$tmpdir/interactive-file'; mkdir '$tmpdir/interactive-dir'" \
    >/dev/null 2>&1

[[ "$(stat -c %a "$tmpdir/noninteractive-file")" == 644 ]] || \
    fail "noninteractive login shell did not retain umask 022 for files"
[[ "$(stat -c %a "$tmpdir/noninteractive-dir")" == 755 ]] || \
    fail "noninteractive login shell did not retain umask 022 for directories"
[[ "$(stat -c %a "$tmpdir/interactive-file")" == 640 ]] || \
    fail "interactive login shell did not apply umask 027 for files"
[[ "$(stat -c %a "$tmpdir/interactive-dir")" == 750 ]] || \
    fail "interactive login shell did not apply umask 027 for directories"

direct_noninteractive="$(bash -c 'umask 022; . "$1"; umask' _ "$DROPIN")"
[[ "$direct_noninteractive" == 0022 ]] || \
    fail "direct noninteractive sourcing changed the inherited umask"

for state_file in environments groups modules nevras packages system; do
    state_path="/usr/lib/sysimage/libdnf5/${state_file}.toml"
    [[ -f "$state_path" && ! -L "$state_path" ]] || \
        fail "DNF5 system-state file missing or symlinked: $state_path"
    [[ "$(stat -c '%U:%G:%a' "$state_path")" == root:root:644 ]] || \
        fail "DNF5 system-state file is not public package inventory: $state_path"
done
dnf -q --cacheonly repoquery --installed bash >/dev/null || \
    fail "ordinary user cannot read DNF5 installed-package state"

echo "PASS  $TEST_NAME [$PASS_ID]: interactive shells use 027; noninteractive and DNF system state retain 022"

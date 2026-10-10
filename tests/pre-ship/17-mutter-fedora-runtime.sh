#!/usr/bin/env bash
# Installed-candidate gate: Mutter must be the unmodified Fedora package.
set -euo pipefail

TEST_NAME=17-mutter-fedora-runtime
TARGET_ROOT=${1:-/}

fail() { echo "FAIL  $TEST_NAME: $*" >&2; exit 1; }
pass() { echo "PASS  $TEST_NAME: $*"; }

for command_name in grep head readlink rpm sort; do
    command -v "$command_name" >/dev/null 2>&1 || fail "required command missing: $command_name"
done

[[ $TARGET_ROOT == /* ]] || fail "candidate root must be absolute"
[[ -d $TARGET_ROOT && ! -L $TARGET_ROOT ]] || fail "candidate root is missing, non-directory or symlinked"
TARGET_ROOT=$(readlink -e -- "$TARGET_ROOT") || fail "cannot canonicalize candidate root"
candidate_os_release=$(readlink -e -- "$TARGET_ROOT/etc/os-release") || \
    fail "candidate os-release is missing or unresolved"
if [[ $TARGET_ROOT != / && $candidate_os_release != "$TARGET_ROOT"/* ]]; then
    fail "candidate os-release resolves outside candidate root"
fi
[[ -f $candidate_os_release && -r $candidate_os_release ]] || \
    fail "candidate os-release is not a readable regular file"
grep -q '^ID=noid-privacy-workstation$' "$candidate_os_release" || \
    fail "target is not a NoID Privacy candidate"

query_format=$'%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{VENDOR}\t%{PACKAGER}\t%{ARCH}\t%{SOURCERPM}\t%{RSAHEADER:pgpsig}\n'
metadata=$(rpm --root="$TARGET_ROOT" -q --qf "$query_format" mutter mutter-common 2>/dev/null) || fail "Mutter packages are not both installed"
mapfile -t rows <<<"$metadata"
[[ ${#rows[@]} -eq 2 ]] || fail "Mutter query did not return exactly two records"

expected_evr=
for row in "${rows[@]}"; do
    IFS=$'\t' read -r name epoch version release vendor packager arch source_rpm \
        signature extra <<<"$row"
    [[ -n $name && $epoch == 0 && -n $version && -n $release \
       && -n $source_rpm && -n $signature && -z ${extra:-} ]] || \
        fail "malformed package metadata record"
    case "$name:$arch" in
        mutter:x86_64|mutter-common:noarch) ;;
        *) fail "unexpected package/architecture: $name:$arch" ;;
    esac
    [[ $vendor == "Fedora Project" && $packager == "Fedora Project" ]] || fail "$name is not Fedora Project packaged"
    [[ $release == *.fc44 ]] || fail "$name is not a Fedora 44 build"
    [[ $signature == *"Key ID dbfcf71c6d9f90a6" ]] || \
        fail "$name is not signed by the Fedora 44 package key"
    [[ $release != *noid* && $source_rpm != *noid* ]] || fail "$name still carries a NoID Privacy-local Mutter build"
    [[ $source_rpm == "mutter-$version-$release.src.rpm" ]] || fail "$name source-RPM identity is inconsistent"
    [[ $(printf '%s\n%s\n' 50.3 "$version" | sort -V | head -n 1) == 50.3 ]] || fail "$name is older than the first Fedora release containing the replacement fix"
    if [[ -z $expected_evr ]]; then
        expected_evr="$version-$release"
    else
        [[ $expected_evr == "$version-$release" ]] || fail "mutter and mutter-common EVRs differ"
    fi
done

verification=$(rpm --root="$TARGET_ROOT" -V mutter mutter-common 2>&1) || {
    printf '%s\n' "$verification" >&2
    fail "Fedora Mutter package verification failed"
}
[[ -z $verification ]] || {
    printf '%s\n' "$verification" >&2
    fail "Fedora Mutter-owned bytes differ"
}
[[ ! -e $TARGET_ROOT/var/lib/noid-privacy/mutter-mr5023-status ]] || fail "retired MR !5023 status artifact is present"

pass "Fedora Project Mutter $expected_evr is installed, byte-clean and free of the retired NoID Privacy override"

#!/usr/bin/env bash
# Verify RPM files against exactly one full-fingerprint public key in a fresh,
# isolated RPM database. Intended to be sourced; no host RPM trust is accepted.

noid_verify_rpms_with_isolated_key() {
    if [ "$#" -lt 3 ]; then
        printf 'ERROR: noid_verify_rpms_with_isolated_key requires KEY FINGERPRINT RPM...\n' >&2
        return 2
    fi

    local public_key="$1" expected_fingerprint="${2^^}"
    shift 2
    local rpm_file verify_root key_output
    local -a key_fingerprints=() imported_fingerprints=()

    [[ "$expected_fingerprint" =~ ^[0-9A-F]{40}$ ]] || {
        printf 'ERROR: RPM signing fingerprint must be exactly 40 hex characters\n' >&2
        return 2
    }
    [ -f "$public_key" ] && [ ! -L "$public_key" ] || {
        printf 'ERROR: RPM public key is missing, non-regular or symlinked: %s\n' "$public_key" >&2
        return 1
    }
    for rpm_file in "$@"; do
        [ -f "$rpm_file" ] && [ ! -L "$rpm_file" ] || {
            printf 'ERROR: RPM input is missing, non-regular or symlinked: %s\n' "$rpm_file" >&2
            return 1
        }
    done

    # Reject bundles containing additional primary identities. Subkey
    # fingerprints are deliberately not treated as separate trust roots.
    mapfile -t key_fingerprints < <(
        gpg --batch --no-options --show-keys --with-colons -- \
            "$public_key" 2>/dev/null |
            awk -F: '
                $1 == "pub" { need_primary_fpr=1; next }
                need_primary_fpr && $1 == "fpr" {
                    print toupper($10); need_primary_fpr=0
                }
            '
    )
    if [ "${#key_fingerprints[@]}" -ne 1 ] || \
       [ "${key_fingerprints[0]:-}" != "$expected_fingerprint" ]; then
        printf 'ERROR: RPM public-key bundle does not contain exactly the selected full fingerprint\n' >&2
        return 1
    fi

    verify_root=$(mktemp -d "${TMPDIR:-/tmp}/noid-rpm-verify.XXXXXXXX") || return 1
    chmod 0700 "$verify_root"

    if ! LC_ALL=C rpmkeys --noplugins --dbpath "$verify_root" \
            --define '_keyring rpmdb' --import "$public_key" >/dev/null 2>&1; then
        printf 'ERROR: selected key could not be imported into isolated RPM database\n' >&2
        rm -rf -- "$verify_root"
        return 1
    fi

    key_output=$(LC_ALL=C rpmkeys --noplugins --dbpath "$verify_root" \
        --define '_keyring rpmdb' --list 2>/dev/null) || {
        printf 'ERROR: isolated RPM key database could not be enumerated\n' >&2
        rm -rf -- "$verify_root"
        return 1
    }
    mapfile -t imported_fingerprints < <(
        awk 'NF { print toupper($1) }' <<< "$key_output"
    )
    if [ "${#imported_fingerprints[@]}" -ne 1 ] || \
       [ "${imported_fingerprints[0]:-}" != "$expected_fingerprint" ]; then
        printf 'ERROR: isolated RPM database does not contain exactly the selected fingerprint\n' >&2
        rm -rf -- "$verify_root"
        return 1
    fi

    for rpm_file in "$@"; do
        # RPM 6 defaults to digest-level verification, under which an unsigned
        # RPM can return success. Level "all" makes both cryptographic signature
        # and package digests mandatory. The isolated db contains no host keys.
        if ! LC_ALL=C rpmkeys --noplugins --dbpath "$verify_root" \
                --define '_keyring rpmdb' \
                --define '_pkgverify_level all' \
                --checksig "$rpm_file" >/dev/null 2>&1; then
            printf 'ERROR: RPM signature/digest verification failed against selected key: %s\n' \
                "$rpm_file" >&2
            rm -rf -- "$verify_root"
            return 1
        fi
    done

    rm -rf -- "$verify_root"
}

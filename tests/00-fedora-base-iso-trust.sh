#!/usr/bin/env bash
# 00-fedora-base-iso-trust — the reviewed Fedora base-ISO signer/digest pin,
# the single verifier-owned release authority and the canonical builder's
# verifier call; the local ISO, when present, must verify without a user
# keyring.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT="$(find_project_root)"
VERIFY="$ROOT/scripts/verify-fedora-base-iso.sh"
BUILD="$ROOT/scripts/build-iso.sh"

test_start "00-fedora-base-iso-trust"

bash -n "$VERIFY" && _pass "base-ISO verifier syntax" \
    || _fail "base-ISO verifier has a syntax error"
grep -qF 'export PATH=/usr/sbin:/usr/bin' "$VERIFY" \
    && _pass "base-ISO verifier resolves only Fedora system tools" \
    || _fail "base-ISO verifier inherits an open tool path"
for signal_contract in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    grep -qF "$signal_contract" "$VERIFY" \
        && _pass "base-ISO verifier preserves the signal-derived exit status" \
        || _fail "base-ISO verifier signal contract is incomplete"
done
EXPECTED_NAME="$("$VERIFY" --print-expected-name)" || EXPECTED_NAME=""
if [[ "$EXPECTED_NAME" =~ ^Fedora-Server-netinst-x86_64-([0-9]+-[0-9.]+)\.iso$ ]]; then
    BASE_RELEASE=${BASH_REMATCH[1]}
    _pass "base-ISO verifier publishes a safe canonical filename"
else
    # Every later check depends on the published release.
    _fail "base-ISO verifier did not publish a safe canonical filename"
    test_finish
    exit 1
fi
MANIFEST="$ROOT/scripts/fedora-base/Fedora-Server-${BASE_RELEASE}-x86_64-CHECKSUM"
REAL_ISO=
for candidate in \
        "/var/tmp/${EXPECTED_NAME}" \
        "${HOME:?}/Downloads/${EXPECTED_NAME}"; do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then
        REAL_ISO=$candidate
        break
    fi
done
grep -qF 'BASE_ISO_NAME="$("$BASE_ISO_VERIFIER" --print-expected-name)"' "$BUILD" \
    && _pass "canonical build derives the base-ISO filename from its verifier" \
    || _fail "canonical build duplicates or omits the verifier-owned base-ISO filename"
! grep -qF "$EXPECTED_NAME" "$BUILD" \
    && _pass "canonical builder contains no duplicate base-release literal" \
    || _fail "canonical builder still duplicates the verifier-owned base release"
[ "$(grep -Ec '^BASE_RELEASE="[0-9]+-[0-9]+(\.[0-9]+)*"$' "$VERIFY" || true)" -eq 1 ] \
    && _pass "base verifier has one release authority" \
    || _fail "base verifier release authority is missing or duplicated"
grep -qF '"$BASE_ISO_VERIFIER" "$INSTALL_ISO"' "$BUILD" \
    && _pass "canonical build invokes base-ISO verifier" \
    || _fail "canonical build does not invoke base-ISO verifier"
! grep -q 'Fedora-Workstation-Live-' "$BUILD" \
    && _pass "unreviewed Workstation fallback removed" \
    || _fail "unreviewed Workstation fallback remains"

tmp="$(mktemp "${TMPDIR:-/var/tmp}/noid-fake-base.XXXXXX.iso")"
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
if "$VERIFY" "$tmp" >/dev/null 2>&1; then
    _fail "invalid base ISO was accepted"
else
    _pass "invalid base ISO rejected"
fi

grep -qF '36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6' "$VERIFY" \
    && grep -qF 'ae20c06bea746913cadea7d80463e13f4bf55bee4df2918111c921c674b70283' "$MANIFEST" \
    && _pass "Fedora 44 signer and signed digest are pinned" \
    || _fail "Fedora signer/digest pin missing"

if [ -f "$REAL_ISO" ]; then
    env GNUPGHOME="$tmp/absent-user-keyring" "$VERIFY" "$REAL_ISO" >/dev/null \
        && _pass "local canonical Fedora base verifies without a user keyring" \
        || _fail "local canonical Fedora base failed verification"
else
    _skip "local canonical Fedora base not present in either supported location"
fi

test_finish

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERIFY="$ROOT/scripts/verify-fedora-base-iso.sh"
BUILD="$ROOT/scripts/build-iso.sh"
checks=0

ok() { checks=$((checks + 1)); printf '[OK] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1" >&2; exit 1; }

bash -n "$VERIFY" && ok "base-ISO verifier syntax"
grep -qF 'export PATH=/usr/sbin:/usr/bin' "$VERIFY" \
    && ok "base-ISO verifier resolves only Fedora system tools" \
    || fail "base-ISO verifier inherits an open tool path"
for signal_contract in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    grep -qF "$signal_contract" "$VERIFY" \
        && ok "base-ISO verifier preserves the signal-derived exit status" \
        || fail "base-ISO verifier signal contract is incomplete"
done
EXPECTED_NAME="$("$VERIFY" --print-expected-name)" \
    || fail "base-ISO verifier did not publish its canonical filename"
[[ "$EXPECTED_NAME" =~ ^Fedora-Server-netinst-x86_64-([0-9]+-[0-9.]+)\.iso$ ]] \
    || fail "base-ISO verifier published an unsafe filename"
BASE_RELEASE=${BASH_REMATCH[1]}
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
    && ok "canonical build derives the base-ISO filename from its verifier" \
    || fail "canonical build duplicates or omits the verifier-owned base-ISO filename"
! grep -qF 'Fedora-Server-netinst-x86_64-44-1.7.iso' "$BUILD" \
    && ok "canonical builder contains no duplicate base-release literal" \
    || fail "canonical builder still duplicates the verifier-owned base release"
[ "$(grep -Ec '^BASE_RELEASE="[0-9]+-[0-9]+(\.[0-9]+)*"$' "$VERIFY" || true)" -eq 1 ] \
    && ok "base verifier has one release authority" \
    || fail "base verifier release authority is missing or duplicated"
grep -qF '"$BASE_ISO_VERIFIER" "$INSTALL_ISO"' "$BUILD" \
    && ok "canonical build invokes base-ISO verifier" \
    || fail "canonical build does not invoke base-ISO verifier"
! grep -q 'Fedora-Workstation-Live-' "$BUILD" \
    && ok "unreviewed Workstation fallback removed" \
    || fail "unreviewed Workstation fallback remains"

tmp="$(mktemp "${TMPDIR:-/var/tmp}/noid-fake-base.XXXXXX.iso")"
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
if "$VERIFY" "$tmp" >/dev/null 2>&1; then
    fail "invalid base ISO was accepted"
else
    ok "invalid base ISO rejected"
fi

grep -qF '36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6' "$VERIFY" \
    && grep -qF 'ae20c06bea746913cadea7d80463e13f4bf55bee4df2918111c921c674b70283' "$MANIFEST" \
    && ok "Fedora 44 signer and signed digest are pinned" \
    || fail "Fedora signer/digest pin missing"

if [ -f "$REAL_ISO" ]; then
    "$VERIFY" "$REAL_ISO" >/dev/null \
        && ok "local canonical Fedora base verifies end-to-end" \
        || fail "local canonical Fedora base failed verification"
else
    printf '[SKIP] local canonical Fedora base not present in either supported location\n'
fi

printf 'Passed: %d checks\n' "$checks"

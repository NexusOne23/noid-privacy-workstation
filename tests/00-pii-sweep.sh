#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SWEEP="$ROOT/scripts/pii-sweep.sh"
tmp="$(mktemp -d "${TMPDIR:-/var/tmp}/noid-pii-sweep.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM
checks=0

ok() { checks=$((checks + 1)); printf '[OK] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1" >&2; exit 1; }

bash -n "$SWEEP" && ok "PII sweep syntax"
grep -qF 'export PATH=/usr/sbin:/usr/bin' "$SWEEP" \
    && ok "PII sweep resolves only Fedora system tools" \
    || fail "PII sweep inherits an open tool path"
grep -qF -- '-o -path "$ROOT/.hist-*"' "$SWEEP" \
    && ok "retained local history fixtures are outside the public-source default" \
    || fail "default sweep does not isolate retained local history fixtures"
mkdir -p "$tmp/allowed" "$tmp/rejected-mac" "$tmp/rejected-machine-id" \
    "$tmp/rejected-home" "$tmp/rejected-cache/__pycache__" \
    "$tmp/rejected-mixed" "$tmp/rejected-png" "$tmp/rejected-png-crc" \
    "$tmp/rejected-png-trailing" "$tmp/rejected-symlink"
python3 - "$tmp/allowed/clean.png" "$tmp/rejected-png/timestamped.png" \
    "$tmp/rejected-png-crc/bad-crc.png" \
    "$tmp/rejected-png-trailing/trailing.png" <<'PY'
import pathlib
import struct
import sys
import zlib


def chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


signature = b"\x89PNG\r\n\x1a\n"
ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
idat = chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
iend = chunk(b"IEND", b"")
pathlib.Path(sys.argv[1]).write_bytes(signature + ihdr + idat + iend)
timestamp = struct.pack(">HBBBBB", 2026, 7, 23, 12, 0, 0)
pathlib.Path(sys.argv[2]).write_bytes(
    signature + ihdr + chunk(b"tIME", timestamp) + idat + iend
)
bad_idat = bytearray(idat)
bad_idat[-1] ^= 1
pathlib.Path(sys.argv[3]).write_bytes(
    signature + ihdr + bytes(bad_idat) + iend
)
pathlib.Path(sys.argv[4]).write_bytes(
    signature + ihdr + idat + iend + chunk(b"tIME", timestamp)
)
PY
printf '%s\n' '02:00:00:00:00:01' '/home/<user>/document' \
    > "$tmp/allowed/fixture"
"$SWEEP" "$tmp/allowed" >/dev/null 2>&1 \
    && ok "reviewed synthetic runtime MAC is accepted" \
    || fail "reviewed synthetic runtime MAC was rejected"

printf '%s\n' 'de:ad:be:ef:'"12:34" > "$tmp/rejected-mac/fixture"
if "$SWEEP" "$tmp/rejected-mac" >/dev/null 2>&1; then
    fail "unapproved MAC was accepted"
else
    ok "unapproved MAC is rejected"
fi

printf '%s\n' '0123456789abcdef'"fedcba9876543210" > "$tmp/rejected-machine-id/fixture"
if "$SWEEP" "$tmp/rejected-machine-id" >/dev/null 2>&1; then
    fail "unapproved machine-id was accepted"
else
    ok "unapproved machine-id is rejected"
fi

# Binary bytecode is scanned with grep's text mode. This reproduces the audit
# finding where a .pyc embedded an absolute checkout path. The synthetic name
# is quote-split because this gate intentionally detects contiguous bytes in
# public artifacts; the fixture source must not flag itself.
printf '\0prefix\0/home/'"samplebuilder"'/Downloads/private-source\0suffix\0' \
    > "$tmp/rejected-home/fixture.pyc.bin"
if "$SWEEP" "$tmp/rejected-home" >/dev/null 2>&1; then
    fail "personal build-host path in a binary file was accepted"
else
    ok "personal build-host path in a binary file is rejected"
fi

ln -s "/home/"'samplebuilder'"/private-source" "$tmp/rejected-symlink/host-path"
if "$SWEEP" "$tmp/rejected-symlink" >/dev/null 2>&1; then
    fail "personal build-host path in a symlink target was accepted"
else
    ok "personal build-host path in a symlink target is rejected"
fi

printf '%s\n' bytecode > "$tmp/rejected-cache/__pycache__/clean.pyc"
if "$SWEEP" "$tmp/rejected-cache" >/dev/null 2>&1; then
    fail "ignored Python cache artifact was accepted"
else
    ok "ignored Python cache artifact is rejected independently of content"
fi

printf '%s\n' 'DE:AD:BE:EF:'"12:34" > "$tmp/rejected-mixed/fixture"
if "$SWEEP" "$tmp/rejected-mixed" >/dev/null 2>&1; then
    fail "mixed-case machine identifier was accepted"
else
    ok "mixed-case machine identifier is rejected"
fi

if png_output=$("$SWEEP" "$tmp/rejected-png" 2>&1); then
    fail "PNG timestamp metadata was accepted"
else
    ok "PNG timestamp metadata is rejected"
fi
printf '%s\n' "$png_output" | grep -qF \
    '[pii-sweep] ERROR: PNG metadata or structure gate failed' \
    && ok "PNG failure carries the sweep-level diagnostic" \
    || fail "PNG failure bypassed the sweep-level diagnostic"

if "$SWEEP" "$tmp/rejected-png-crc" >/dev/null 2>&1; then
    fail "PNG with an invalid chunk CRC was accepted"
else
    ok "PNG with an invalid chunk CRC is rejected"
fi

if "$SWEEP" "$tmp/rejected-png-trailing" >/dev/null 2>&1; then
    fail "PNG with data after IEND was accepted"
else
    ok "PNG data after IEND is rejected"
fi

if "$SWEEP" "$tmp/allowed" "$tmp/does-not-exist" >/dev/null 2>&1; then
    fail "missing explicitly requested scan root was ignored"
else
    ok "missing explicitly requested scan root is fatal"
fi

# The exception list carries unanchored home-path alternatives, and grep prints
# `<path>:<lineno>:<match>`. Filtering that composite line meant any checkout
# living under one of those paths discarded every content hit and reported OK.
# Every fixture above sits under $TMPDIR, which contains no exception
# substring, so none of them could observe it. Scan an identical leak from
# inside such a path explicitly.
for excepted_root in home/alice home/liveuser home/service home/you; do
    leak_root="$tmp/excepted/$excepted_root/checkout"
    mkdir -p "$leak_root"
    # Split like the fixtures above so the sweep's own source never carries a
    # contiguous identifier that it would then have to flag in this repository.
    printf 'mac %s id %s\n' 'de:ad:be:ef:'"12:34" \
        '0123456789abcdef'"fedcba9876543210" > "$leak_root/leak.md"
    if "$SWEEP" "$leak_root" >/dev/null 2>&1; then
        fail "leak under /$excepted_root was silently swept away"
    else
        ok "leak under /$excepted_root is still detected"
    fi
done

# The same alternatives must keep working as real exceptions in file content.
mkdir -p "$tmp/excepted-content"
printf 'documented example ab:cd:ef:12:34:56 under /home/liveuser/ is allowed\n' \
    > "$tmp/excepted-content/doc.md"
if "$SWEEP" "$tmp/excepted-content" >/dev/null 2>&1; then
    ok "reviewed example identifiers are still excepted by content"
else
    fail "reviewed example identifiers were rejected"
fi

# Exact fixture users remain excepted, but their names are not prefixes: a
# real longer username must still be reported as a build-host path.
for longer_user in younes aliceson services liveuser2 fixtures; do
    longer_root="$tmp/longer-user-$longer_user"
    mkdir -p "$longer_root"
    printf 'private checkout /home/%s/source\n' "$longer_user" \
        > "$longer_root/leak.md"
    if "$SWEEP" "$longer_root" >/dev/null 2>&1; then
        fail "home-path exception swallowed longer user $longer_user"
    else
        ok "home-path exception is bounded before $longer_user"
    fi
done

"$SWEEP" >/dev/null && ok "repository passes canonical PII sweep" \
    || fail "repository fails canonical PII sweep"

printf 'Passed: %d checks\n' "$checks"

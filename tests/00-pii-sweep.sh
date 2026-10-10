#!/usr/bin/env bash
# 00-pii-sweep — the public-tree PII sweep and its synthetic fixtures: Python
# cache, PNG metadata/structure, binary and symlink home paths, machine-id and
# MAC identifiers, filename punctuation and the reviewed exception list.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT="$(find_project_root)"
SWEEP="$ROOT/scripts/pii-sweep.sh"
tmp="$(mktemp -d "${TMPDIR:-/var/tmp}/noid-pii-sweep.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

test_start "00-pii-sweep"

bash -n "$SWEEP" && _pass "PII sweep syntax" \
    || _fail "PII sweep has a syntax error"
grep -qF 'export PATH=/usr/sbin:/usr/bin' "$SWEEP" \
    && _pass "PII sweep resolves only Fedora system tools" \
    || _fail "PII sweep inherits an open tool path"
grep -qF -- '-o -path "$ROOT/.hist-*"' "$SWEEP" \
    && _pass "retained local history fixtures are outside the public-source default" \
    || _fail "default sweep does not isolate retained local history fixtures"
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
    && _pass "reviewed synthetic runtime MAC is accepted" \
    || _fail "reviewed synthetic runtime MAC was rejected"

printf '%s\n' 'de:ad:be:ef:'"12:34" > "$tmp/rejected-mac/fixture"
if "$SWEEP" "$tmp/rejected-mac" >/dev/null 2>&1; then
    _fail "unapproved MAC was accepted"
else
    _pass "unapproved MAC is rejected"
fi

printf '%s\n' '0123456789abcdef'"fedcba9876543210" > "$tmp/rejected-machine-id/fixture"
if "$SWEEP" "$tmp/rejected-machine-id" >/dev/null 2>&1; then
    _fail "unapproved machine-id was accepted"
else
    _pass "unapproved machine-id is rejected"
fi

# Binary bytecode is scanned with grep's text mode, so a .pyc that embeds an
# absolute checkout path is rejected. The synthetic name is quote-split
# because this gate intentionally detects contiguous bytes in public
# artifacts; the fixture source must not flag itself.
printf '\0prefix\0/home/'"samplebuilder"'/Downloads/private-source\0suffix\0' \
    > "$tmp/rejected-home/fixture.pyc.bin"
if "$SWEEP" "$tmp/rejected-home" >/dev/null 2>&1; then
    _fail "personal build-host path in a binary file was accepted"
else
    _pass "personal build-host path in a binary file is rejected"
fi

ln -s "/home/"'samplebuilder'"/private-source" "$tmp/rejected-symlink/host-path"
if "$SWEEP" "$tmp/rejected-symlink" >/dev/null 2>&1; then
    _fail "personal build-host path in a symlink target was accepted"
else
    _pass "personal build-host path in a symlink target is rejected"
fi

printf '%s\n' bytecode > "$tmp/rejected-cache/__pycache__/clean.pyc"
if "$SWEEP" "$tmp/rejected-cache" >/dev/null 2>&1; then
    _fail "ignored Python cache artifact was accepted"
else
    _pass "ignored Python cache artifact is rejected independently of content"
fi

printf '%s\n' 'DE:AD:BE:EF:'"12:34" > "$tmp/rejected-mixed/fixture"
if "$SWEEP" "$tmp/rejected-mixed" >/dev/null 2>&1; then
    _fail "mixed-case machine identifier was accepted"
else
    _pass "mixed-case machine identifier is rejected"
fi

if png_output=$("$SWEEP" "$tmp/rejected-png" 2>&1); then
    _fail "PNG timestamp metadata was accepted"
else
    _pass "PNG timestamp metadata is rejected"
fi
printf '%s\n' "$png_output" | grep -qF \
    '[pii-sweep] ERROR: PNG metadata or structure gate failed' \
    && _pass "PNG failure carries the sweep-level diagnostic" \
    || _fail "PNG failure bypassed the sweep-level diagnostic"

if "$SWEEP" "$tmp/rejected-png-crc" >/dev/null 2>&1; then
    _fail "PNG with an invalid chunk CRC was accepted"
else
    _pass "PNG with an invalid chunk CRC is rejected"
fi

if "$SWEEP" "$tmp/rejected-png-trailing" >/dev/null 2>&1; then
    _fail "PNG with data after IEND was accepted"
else
    _pass "PNG data after IEND is rejected"
fi

if "$SWEEP" "$tmp/allowed" "$tmp/does-not-exist" >/dev/null 2>&1; then
    _fail "missing explicitly requested scan root was ignored"
else
    _pass "missing explicitly requested scan root is fatal"
fi

# The exception list carries home-path alternatives, and grep prints
# `<path>:<lineno>:<match>`. Exceptions must apply to the matched content
# only, never to the file path: a checkout living under an excepted path must
# still report every content hit. The fixtures above sit under $TMPDIR, which
# contains no exception substring, so scan an identical leak from inside such
# a path explicitly.
for excepted_root in home/alice home/liveuser home/service home/you; do
    leak_root="$tmp/excepted/$excepted_root/checkout"
    mkdir -p "$leak_root"
    # Split like the fixtures above so the sweep's own source never carries a
    # contiguous identifier that it would then have to flag in this repository.
    printf 'mac %s id %s\n' 'de:ad:be:ef:'"12:34" \
        '0123456789abcdef'"fedcba9876543210" > "$leak_root/leak.md"
    if "$SWEEP" "$leak_root" >/dev/null 2>&1; then
        _fail "leak under /$excepted_root was silently swept away"
    else
        _pass "leak under /$excepted_root is still detected"
    fi
done

# Colons and newlines are valid filename bytes, not grep field separators.
# A leak must stay visible under both a neutral and an excepted parent path,
# and clean content at those same paths must remain accepted.
for unusual_path in 'prefix:/home/alice/repository' \
                    'home/alice/prefix:/home/service/repository' \
                    $'prefix\n/home/alice/repository'; do
    leak_root="$tmp/unusual/$unusual_path"
    mkdir -p "$leak_root"
    printf '%s\n' 'de:ad:be:ef:'"12:34" > "$leak_root/fixture.txt"
    if leak_output=$("$SWEEP" "$leak_root" 2>&1); then
        _fail "filename punctuation hid an unapproved identifier"
    else
        _pass "filename punctuation cannot hide an unapproved identifier"
    fi
    [[ "$leak_output" != *'de:ad:be:ef:'"12:34"* ]] \
        && _pass "identifier diagnostic does not disclose the matched value" \
        || _fail "identifier diagnostic disclosed the matched value"
    [[ "$leak_output" == *':1: possible identifier or home path (redacted)'* ]] \
        && _pass "identifier diagnostic retains its source line" \
        || _fail "identifier diagnostic lost its source line"
    printf '%s\n' 'ab:cd:ef:12:34:56' > "$leak_root/fixture.txt"
    "$SWEEP" "$leak_root" >/dev/null 2>&1 \
        && _pass "reviewed content stays accepted with filename punctuation" \
        || _fail "filename punctuation rejected reviewed content"
done

if symlink_output=$("$SWEEP" "$tmp/rejected-symlink" 2>&1); then
    _fail "private symlink target was accepted"
else
    [[ "$symlink_output" != *'/home/'"samplebuilder"* ]] \
        && _pass "symlink diagnostic does not disclose the private target" \
        || _fail "symlink diagnostic disclosed the private target"
fi

# The same alternatives must keep working as real exceptions in file content.
mkdir -p "$tmp/excepted-content"
printf 'documented example ab:cd:ef:12:34:56 under /home/liveuser/ is allowed\n' \
    > "$tmp/excepted-content/doc.md"
if "$SWEEP" "$tmp/excepted-content" >/dev/null 2>&1; then
    _pass "reviewed example identifiers are still excepted by content"
else
    _fail "reviewed example identifiers were rejected"
fi

# Exact fixture users remain excepted, but their names are not prefixes: a
# real longer username must still be reported as a build-host path.
for longer_user in younes aliceson services liveuser2 fixtures; do
    longer_root="$tmp/longer-user-$longer_user"
    mkdir -p "$longer_root"
    printf 'private checkout /home/%s/source\n' "$longer_user" \
        > "$longer_root/leak.md"
    if "$SWEEP" "$longer_root" >/dev/null 2>&1; then
        _fail "home-path exception swallowed longer user $longer_user"
    else
        _pass "home-path exception is bounded before $longer_user"
    fi
done

"$SWEEP" >/dev/null && _pass "repository passes canonical PII sweep" \
    || _fail "repository fails canonical PII sweep"

test_finish

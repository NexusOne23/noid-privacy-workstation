#!/usr/bin/env bash
# Enforce the public source tree's machine-identifier and build-host-path gate.

set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PATTERNS='([0-9a-f]{2}:){5}[0-9a-f]{2}|\b[0-9a-f]{32}\b|/home/([A-Za-z0-9][A-Za-z0-9._-]*|<[^/>]+>)(/|[^A-Za-z0-9._-]|$)'
# Only explicitly reviewed documentation/test fixtures belong here. The
# 02:00:00 values are locally administered identities used by the
# multi-interface XDP and ARP transaction fixtures; the remaining values are
# conventional unmistakably synthetic examples.
EXCEPTIONS='ab:cd:ef:12:34:56|aa:bb:cc:dd:ee:ff|12:34:56:78:9a:bc|52:54:00:aa:bb:cc|02:00:00:00:00:01|02:00:00:00:00:02|02:00:00:00:00:03|02:00:00:00:00:10|02:00:00:00:00:11|02:00:00:00:00:22|02:00:00:00:00:33|02:00:00:00:01:11|abcd1234abcd1234abcd1234abcd1234|/home/(<user>|<your-user>|<new-user>|<name>|you|liveuser|fixture|alice|gdm-greeter|service)(/|[^A-Za-z0-9._-]|$)'

# The exception filter must see only the matched text, never grep's
# `<path>:<lineno>:<match>` prefix. EXCEPTIONS carries unanchored home-path
# alternatives such as `/home/alice` and `/home/service`, so filtering the
# composite line meant a checkout living under any of those paths discarded
# every content hit and the sweep reported OK with real MACs and machine-ids
# still in the tree. Reproduced: the same file under a neutral path reports two
# leaks, under .../home/alice/... it reports none.
#
# The prefix is stripped stepwise rather than with one greedy expression: a
# matched MAC contains `:<digits>:` itself (`ab:cd:ef:12:34:56`), so a greedy
# strip would cut into the match. EXCEPTIONS is entirely lowercase, so lowering
# the subject reproduces the case-insensitive behaviour of the previous
# `grep -i`. The symlink-target branch below needs none of this: it pipes the
# bare target string with no location prefix.
drop_excepted_matches() {
    awk -v ex="$EXCEPTIONS" '
        {
            match_text = $0
            sub(/^[^:]*:/, "", match_text)
            sub(/^[0-9]+:/, "", match_text)
            if (tolower(match_text) !~ ex) print $0
        }
    '
}


if [ "$#" -gt 0 ]; then
    roots=("$@")
    default_scan=0
else
    roots=("$ROOT")
    default_scan=1
fi

existing=()
missing=()
for path in "${roots[@]}"; do
    case "$path" in
        /*) candidate="$path" ;;
        *)  candidate="$ROOT/$path" ;;
    esac
    if [ -e "$candidate" ]; then
        existing+=("$candidate")
    else
        missing+=("$candidate")
    fi
done
[ "$default_scan" -eq 1 ] || [ "${#missing[@]}" -eq 0 ] || {
    printf '[pii-sweep] ERROR: requested scan root does not exist: %s\n' \
        "${missing[@]}" >&2
    exit 2
}
[ "${#existing[@]}" -gt 0 ] || {
    echo "[pii-sweep] ERROR: no scan roots exist" >&2
    exit 2
}

# The default scans every project-owned source/workflow/browser/mail file,
# including ignored bytecode, while excluding explicit local evidence,
# retained `.hist-*` test fixtures, dependency venvs and multi-gigabyte images.
# Pinned third-party `.tools`
# content has its own byte-integrity gate and is excluded only from the
# identifier-content match; generated caches beneath it are still rejected.
# User-supplied roots are scanned in full.
default_find() {
    find "$ROOT" \
        \( -path "$ROOT/.git" -o -path "$ROOT/build-output" \
           -o -path "$ROOT/build-archive" -o -path "$ROOT/build" \
           -o -path "$ROOT/output" -o -path "$ROOT/image" \
           -o -path "$ROOT/discovery" -o -path "$ROOT/.hist-*" \
           -o -path "$ROOT/.claude" \
           -o -path "$ROOT/.claude-*" -o -path "$ROOT/.venv" \
           -o -path "$ROOT/venv" \) -prune -o "$@"
}

if [ "$default_scan" -eq 1 ]; then
    cache_path=$(default_find \
        \( -type d -name __pycache__ -o -type f \
           \( -name '*.pyc' -o -name '*.pyo' \) \) -print -quit)
else
    cache_path=$(find "${existing[@]}" \
        \( -type d -name __pycache__ -o -type f \
           \( -name '*.pyc' -o -name '*.pyo' \) \) -print -quit)
fi
if [ -n "$cache_path" ]; then
    echo "[pii-sweep] ERROR: generated Python cache in source surface: $cache_path" >&2
    exit 1
fi

# Git records a symlink target as repository content, but `find -type f` does
# not pass it to grep. Inspect the link bytes without following the target:
# following could read unrelated host data outside the public source tree.
if [ "$default_scan" -eq 1 ]; then
    mapfile -d '' symlink_files < <(
        default_find -type l ! -path "$ROOT/.tools/*" -print0
    )
else
    mapfile -d '' symlink_files < <(
        find "${existing[@]}" -type l -print0
    )
fi
symlink_leaks=()
for link in "${symlink_files[@]}"; do
    target=$(readlink -- "$link") || {
        echo "[pii-sweep] ERROR: cannot read symlink target: $link" >&2
        exit 1
    }
    matches=$(printf '%s' "$target" | grep -aioE "$PATTERNS" \
        | grep -viE "$EXCEPTIONS" || true)
    if [ -n "$matches" ]; then
        symlink_leaks+=("$link -> $matches")
    fi
done
if [ "${#symlink_leaks[@]}" -gt 0 ]; then
    printf '%s\n' "${symlink_leaks[@]}"
    echo "[pii-sweep] ERROR: possible identifier or home path in symlink target" >&2
    exit 1
fi

# PNG time, EXIF and text chunks can disclose build-host or author metadata
# outside grep-visible source text. Parse the chunk table directly; color,
# transparency and physical-dimension chunks remain permitted.
if [ "$default_scan" -eq 1 ]; then
    mapfile -d '' png_files < <(default_find -type f -iname '*.png' -print0)
else
    mapfile -d '' png_files < <(
        find "${existing[@]}" -type f -iname '*.png' -print0
    )
fi
if [ "${#png_files[@]}" -gt 0 ]; then
    png_status=0
    python3 - "${png_files[@]}" <<'PY' || png_status=$?
import pathlib
import struct
import sys
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
FORBIDDEN = {b"tIME", b"eXIf", b"iTXt", b"tEXt", b"zTXt"}
failures: list[str] = []

for argument in sys.argv[1:]:
    path = pathlib.Path(argument)
    try:
        with path.open("rb") as stream:
            if stream.read(8) != PNG_SIGNATURE:
                failures.append(f"{path}: invalid PNG signature")
                continue
            stream.seek(0, 2)
            file_size = stream.tell()
            stream.seek(8)
            forbidden_present: set[bytes] = set()
            saw_iend = False
            chunk_index = 0
            while True:
                header = stream.read(8)
                if len(header) != 8:
                    failures.append(f"{path}: truncated PNG chunk header")
                    break
                length, chunk_type = struct.unpack(">I4s", header)
                if chunk_index == 0 and (
                    chunk_type != b"IHDR" or length != 13
                ):
                    failures.append(f"{path}: invalid first PNG chunk")
                    break
                if chunk_index > 0 and chunk_type == b"IHDR":
                    failures.append(f"{path}: duplicate PNG IHDR chunk")
                    break
                if chunk_type == b"IEND" and length != 0:
                    failures.append(f"{path}: non-empty PNG IEND chunk")
                    break
                remaining = file_size - stream.tell()
                if length + 4 > remaining:
                    failures.append(f"{path}: truncated {chunk_type!r} chunk")
                    break
                checksum = zlib.crc32(chunk_type)
                bytes_left = length
                chunk_truncated = False
                while bytes_left:
                    block = stream.read(min(bytes_left, 1024 * 1024))
                    if not block:
                        failures.append(
                            f"{path}: truncated {chunk_type!r} chunk data"
                        )
                        chunk_truncated = True
                        break
                    checksum = zlib.crc32(block, checksum)
                    bytes_left -= len(block)
                if chunk_truncated:
                    break
                stored_checksum_bytes = stream.read(4)
                if len(stored_checksum_bytes) != 4:
                    failures.append(
                        f"{path}: truncated {chunk_type!r} chunk CRC"
                    )
                    break
                stored_checksum = struct.unpack(">I", stored_checksum_bytes)[0]
                if checksum & 0xFFFFFFFF != stored_checksum:
                    failures.append(f"{path}: invalid {chunk_type!r} chunk CRC")
                    break
                if chunk_type in FORBIDDEN:
                    forbidden_present.add(chunk_type)
                if chunk_type == b"IEND":
                    saw_iend = True
                    if stream.tell() != file_size:
                        failures.append(f"{path}: trailing data after PNG IEND")
                    break
                chunk_index += 1
            if not saw_iend:
                continue
            if forbidden_present:
                names = ",".join(
                    item.decode("ascii") for item in sorted(forbidden_present)
                )
                failures.append(f"{path}: forbidden PNG metadata chunk(s): {names}")
    except OSError as error:
        failures.append(f"{path}: {error}")

if failures:
    print("\n".join(failures), file=sys.stderr)
    raise SystemExit(1)
PY
    if [ "$png_status" -ne 0 ]; then
        echo "[pii-sweep] ERROR: PNG metadata or structure gate failed" >&2
        exit "$png_status"
    fi
fi

if [ "$default_scan" -eq 1 ]; then
    unreadable=$(default_find -type f \
        ! -path "$ROOT/livemedia.log" \
        ! -path "$ROOT/program.log" \
        ! -path "$ROOT/virt-install.log" ! -readable -print -quit)
    [ -z "$unreadable" ] || {
        echo "[pii-sweep] ERROR: unreadable public source file: $unreadable" >&2
        exit 1
    }
    scan_output=$(default_find -type f \
        ! -path "$ROOT/livemedia.log" \
        ! -path "$ROOT/program.log" \
        ! -path "$ROOT/virt-install.log" \
        ! -path "$ROOT/.tools/*" \
        -exec grep -aiHEno "$PATTERNS" {} + 2>/dev/null \
        | drop_excepted_matches || true)
else
    unreadable=$(find "${existing[@]}" -type f ! -readable -print -quit)
    [ -z "$unreadable" ] || {
        echo "[pii-sweep] ERROR: unreadable scan file: $unreadable" >&2
        exit 1
    }
    scan_output=$(find "${existing[@]}" -type f \
        -exec grep -aiHEno "$PATTERNS" {} + 2>/dev/null \
        | drop_excepted_matches || true)
fi
if [ -n "$scan_output" ]; then
    printf '%s\n' "$scan_output"
    echo "[pii-sweep] ERROR: possible machine identifier or build-host path leak" >&2
    exit 1
fi

echo "[pii-sweep] OK: no Python cache, unsafe symlink target, forbidden PNG metadata, unapproved MAC/machine-id, or personal home path"

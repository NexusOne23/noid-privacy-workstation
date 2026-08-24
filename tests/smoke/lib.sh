#!/bin/bash
# tests/smoke/lib.sh — shared helpers for bwrap-sandboxed smoke tests
#
# Sourced by tests/smoke/MNN-smoke.sh. Provides:
#   - Prerequisite checks (bwrap + rootfs) with graceful skip (exit 77)
#   - Sandbox setup + teardown (ephemeral overlay per test)
#   - %post extraction from .ks files
#   - Assertion helpers that run inside the sandbox

# State
SMOKE_NAME=""
SMOKE_PASS=0
SMOKE_FAIL=0
SANDBOX_DIR=""
SMOKE_TEMP_FILES=()

# Configuration
ROOTFS_SRC="${NOID_SMOKE_ROOTFS:-/var/cache/noid-smoke/rootfs-f44}"
ROOTFS_RELEASEVER="${NOID_SMOKE_RELEASEVER:-44}"
SANDBOX_PARENT="${NOID_SMOKE_SANDBOX_PARENT:-/var/tmp}"
BWRAP_BIN=${BWRAP:-}
if [ -z "$BWRAP_BIN" ]; then
    BWRAP_BIN=$(command -v bwrap 2>/dev/null || true)
fi

# Terminal colors (conditional)
if [ -t 1 ]; then
    C_OK=$'\033[32m'
    C_FAIL=$'\033[31m'
    C_SKIP=$'\033[33m'
    C_RST=$'\033[0m'
else
    C_OK=""; C_FAIL=""; C_SKIP=""; C_RST=""
fi

# -----------------------------------------------------------------------------
# Entry: check prereqs, register cleanup, print header
# -----------------------------------------------------------------------------
smoke_start() {
    SMOKE_NAME="$1"
    SMOKE_PASS=0
    SMOKE_FAIL=0
    local manifest prep_script expected_definition manifest_definition
    local manifest_release manifest_version
    printf '=== smoke/%s ===\n' "$SMOKE_NAME"

    # Prereq 1: bwrap
    if [ -z "$BWRAP_BIN" ] || [ ! -x "$BWRAP_BIN" ]; then
        printf '  %sSKIP%s bwrap (bubblewrap) not installed\n' "$C_SKIP" "$C_RST"
        exit 77
    fi

    # Prereq 2: rootfs
    if [ ! -d "$ROOTFS_SRC" ] || [ ! -x "$ROOTFS_SRC/usr/bin/bash" ]; then
        printf '  %sSKIP%s rootfs not prepared at %s\n' "$C_SKIP" "$C_RST" "$ROOTFS_SRC"
        printf '         run: sudo ./tests/smoke/prep-rootfs.sh\n'
        exit 77
    fi

    # A directory plus /usr/bin/bash is insufficient evidence that the cache
    # matches the current package/fixture definition. Refuse stale caches so a
    # newly required command is not misreported as a product %post failure.
    manifest="$ROOTFS_SRC/.noid-smoke-rootfs-manifest"
    prep_script="$(project_root)/tests/smoke/prep-rootfs.sh"
    expected_definition="$(sha256sum "$prep_script" | awk '{print $1}')"
    manifest_version="$(sed -n 's/^manifest-version=//p' "$manifest" 2>/dev/null || true)"
    manifest_definition="$(sed -n 's/^definition-sha256=//p' "$manifest" 2>/dev/null || true)"
    manifest_release="$(sed -n 's/^releasever=//p' "$manifest" 2>/dev/null || true)"
    if [ "$manifest_version" != 2 ] \
       || [ "$manifest_definition" != "$expected_definition" ] \
       || [ "$manifest_release" != "$ROOTFS_RELEASEVER" ]; then
        printf '  %sSKIP%s rootfs definition is stale or unverified at %s\n' \
            "$C_SKIP" "$C_RST" "$ROOTFS_SRC"
        printf '         rebuild: sudo ./tests/smoke/prep-rootfs.sh\n'
        exit 77
    fi

    # Prereq 3: must be root (bwrap snapshot copy needs it)
    if [ "$(id -u)" -ne 0 ]; then
        printf '  %sSKIP%s smoke tests need sudo (rootfs snapshot copy)\n' "$C_SKIP" "$C_RST"
        exit 77
    fi

    # Keep one cleanup owner. A smoke module that installs a second EXIT trap
    # would replace this one and leak the complete rootfs snapshot.
    if [ ! -d "$SANDBOX_PARENT" ] || [ ! -w "$SANDBOX_PARENT" ]; then
        printf '  %sSKIP%s sandbox parent is unavailable: %s\n' \
            "$C_SKIP" "$C_RST" "$SANDBOX_PARENT"
        exit 77
    fi
    SANDBOX_DIR=$(mktemp -d -p "$SANDBOX_PARENT" noid-smoke-XXXXXX)
    trap 'smoke_cleanup' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    # Snapshot the prepared rootfs so each test starts from the same fixture
    cp -a --reflink=auto "$ROOTFS_SRC"/. "$SANDBOX_DIR/"
    printf '  sandbox: %s\n' "$SANDBOX_DIR"
}

smoke_register_temp_file() {
    if [ "$#" -ne 1 ] || [ -z "$1" ]; then
        printf 'ERR: smoke_register_temp_file requires one non-empty path\n' >&2
        return 2
    fi
    SMOKE_TEMP_FILES+=("$1")
}

smoke_cleanup() {
    local temp_file
    for temp_file in "${SMOKE_TEMP_FILES[@]}"; do
        rm -f -- "$temp_file"
    done
    SMOKE_TEMP_FILES=()
    if [ -n "$SANDBOX_DIR" ] && [ -d "$SANDBOX_DIR" ]; then
        rm -rf -- "$SANDBOX_DIR"
    fi
    SANDBOX_DIR=""
}

# -----------------------------------------------------------------------------
# Exit: report tallies
# -----------------------------------------------------------------------------
smoke_finish() {
    local total=$((SMOKE_PASS + SMOKE_FAIL))
    if [ "$SMOKE_FAIL" -eq 0 ]; then
        printf '%sPASS%s  smoke/%s  (%d checks)\n' "$C_OK" "$C_RST" "$SMOKE_NAME" "$total"
        return 0
    else
        printf '%sFAIL%s  smoke/%s  (%d/%d checks passed)\n' \
            "$C_FAIL" "$C_RST" "$SMOKE_NAME" "$SMOKE_PASS" "$total"
        return 1
    fi
}

_pass() {
    SMOKE_PASS=$((SMOKE_PASS + 1))
    printf '  %s[OK]%s %s\n' "$C_OK" "$C_RST" "$1"
}

_fail() {
    SMOKE_FAIL=$((SMOKE_FAIL + 1))
    printf '  %s[FAIL]%s %s\n' "$C_FAIL" "$C_RST" "$1"
}

# -----------------------------------------------------------------------------
# Extract the first %post block from a kickstart snippet
# Usage: extract_post /path/to/NN-name.ks /tmp/out.sh
# -----------------------------------------------------------------------------
extract_post() {
    local ks="$1" out="$2"
    awk '
        /^%post/ { inpost=1; next }
        /^%end/ && inpost { inpost=0; exit }
        inpost { print }
    ' "$ks" > "$out"
    if [ ! -s "$out" ]; then
        _fail "extract_post: no %post content extracted from $ks"
        return 1
    fi
    # Prepend a minimal environment for %post snippets (log helper, set -e)
    local full; full=$(mktemp)
    {
        echo '#!/bin/bash'
        echo 'set -euo pipefail'
        echo 'log() { echo "[smoke] $*"; }'
        cat "$out"
    } > "$full"
    mv "$full" "$out"
    chmod +x "$out"
}

# -----------------------------------------------------------------------------
# Run a script inside the sandbox rootfs
# Usage: run_in_sandbox /path/on/host/script.sh
# -----------------------------------------------------------------------------
run_in_sandbox() {
    local script="$1"
    local script_in_sandbox
    local -a bash_args=()
    local -a optional_binds=()
    # Do not place the copied script below /tmp: bwrap intentionally overlays
    # /tmp with a fresh tmpfs, which previously hid the script immediately
    # before execution and made every smoke test fail with ENOENT.
    script_in_sandbox="/root/.noid-smoke-$(basename "$script")"
    cp "$script" "$SANDBOX_DIR$script_in_sandbox"
    chmod +x "$SANDBOX_DIR$script_in_sandbox"

    # Hardware-policy smoke tests can opt into a read-only host sysfs fixture.
    # Keep this off by default so unrelated module smoke tests cannot branch on
    # or act against the source host's hardware.
    if [ "${SMOKE_BIND_SYS:-0}" = 1 ]; then
        optional_binds=(--ro-bind /sys /sys)
    elif [ "${SMOKE_BIND_CGROUP:-0}" = 1 ]; then
        # Offline `systemd-analyze --user verify` still needs the kernel's
        # controller inventory to instantiate generated application slices.
        # Expose only that read-only subtree; unrelated smoke tests must not
        # branch on or act against the source host's wider hardware sysfs.
        install -d -m 0755 -o root -g root "$SANDBOX_DIR/sys/fs/cgroup"
        optional_binds=(--ro-bind /sys/fs/cgroup /sys/fs/cgroup)
    fi
    if [ "${NOID_SMOKE_TRACE:-0}" = 1 ]; then
        bash_args=(-x)
    fi

    "$BWRAP_BIN" \
        --bind "$SANDBOX_DIR" / \
        "${optional_binds[@]}" \
        --uid 0 --gid 0 \
        --unshare-pid \
        --unshare-net \
        --unshare-uts \
        --new-session \
        --die-with-parent \
        --proc /proc \
        --dev /dev \
        --tmpfs /run \
        --tmpfs /tmp \
        --setenv HOME /tmp \
        --setenv PATH /usr/sbin:/usr/bin:/sbin:/bin \
        /bin/bash "${bash_args[@]}" "$script_in_sandbox"
}

# -----------------------------------------------------------------------------
# Run a single command in the sandbox; return its exit code
# Usage: assert_in_sandbox 'test -f /etc/foo' "description"
# -----------------------------------------------------------------------------
assert_in_sandbox() {
    local cmd="$1" desc="$2"
    local rc
    if [ "${NOID_SMOKE_TRACE:-0}" = 1 ]; then
        if "$BWRAP_BIN" \
            --bind "$SANDBOX_DIR" / \
            --uid 0 --gid 0 \
            --unshare-pid --unshare-net --unshare-uts \
            --new-session --die-with-parent \
            --proc /proc --dev /dev --tmpfs /run --tmpfs /tmp \
            --setenv PATH /usr/sbin:/usr/bin:/sbin:/bin \
            /bin/bash -c "$cmd"; then
            rc=0
        else
            rc=$?
        fi
    else
        if "$BWRAP_BIN" \
            --bind "$SANDBOX_DIR" / \
            --uid 0 --gid 0 \
            --unshare-pid --unshare-net --unshare-uts \
            --new-session --die-with-parent \
            --proc /proc --dev /dev --tmpfs /run --tmpfs /tmp \
            --setenv PATH /usr/sbin:/usr/bin:/sbin:/bin \
            /bin/bash -c "$cmd" >/dev/null 2>&1; then
            rc=0
        else
            rc=$?
        fi
    fi
    if [ "$rc" -eq 0 ]; then
        _pass "$desc"
    else
        _fail "$desc  (cmd: $cmd)"
    fi
}

# -----------------------------------------------------------------------------
# Project root detection (duplicates find_project_root from tests/lib.sh)
# -----------------------------------------------------------------------------
project_root() {
    local caller_dir
    caller_dir="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
    if [ -f "$caller_dir/../../kickstart/master.ks" ]; then
        (cd "$caller_dir/../.." && pwd)
    elif [ -f "$caller_dir/../kickstart/master.ks" ]; then
        (cd "$caller_dir/.." && pwd)
    else
        printf 'ERR: cannot find project root from %s\n' "$caller_dir" >&2
        return 1
    fi
}

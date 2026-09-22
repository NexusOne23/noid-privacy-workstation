#!/usr/bin/env bash
# Release-user-wide serialization for the canonical ISO builder.
# This file is sourced; it intentionally changes no state until
# noid_build_lock_acquire is called.

noid_build_lock_acquire() {
    local lock_file=$1 lock_parent lock_metadata expected_metadata

    [[ "$lock_file" = /* ]] || {
        echo "build host lock: path must be absolute" >&2
        return 1
    }
    lock_parent=${lock_file%/*}
    [ -n "$lock_parent" ] && [ "$lock_parent" != "$lock_file" ] \
        && [ -d "$lock_parent" ] && [ ! -L "$lock_parent" ] || {
        echo "build host lock: parent must be a real directory" >&2
        return 1
    }
    [ "$(readlink -e -- "$lock_parent" 2>/dev/null || true)" = "$lock_parent" ] \
        || {
            echo "build host lock: parent path is not canonical" >&2
            return 1
        }
    [ "$(stat -c '%u:%g:%a' -- "$lock_parent" 2>/dev/null || true)" \
        = "$(id -u):$(id -g):700" ] || {
        echo "build host lock: parent is not the invoking user's private runtime directory" >&2
        return 1
    }
    command -v flock >/dev/null 2>&1 || {
        echo "build host lock: flock is unavailable" >&2
        return 1
    }

    if [ ! -e "$lock_file" ] && [ ! -L "$lock_file" ]; then
        # noclobber makes same-user concurrent creation atomic. The parent is
        # already a private mode-0700 runtime directory, so no other identity
        # can exchange the path between validation and open.
        (
            umask 077
            set -o noclobber
            : > "$lock_file"
        ) 2>/dev/null || true
    fi
    [ -f "$lock_file" ] && [ ! -L "$lock_file" ] || {
        echo "build host lock: lock path is not a regular non-symlink file" >&2
        return 1
    }
    lock_metadata=$(stat -c '%u:%g:%a:%h' -- "$lock_file" 2>/dev/null || true)
    expected_metadata="$(id -u):$(id -g):600:1"
    [ "$lock_metadata" = "$expected_metadata" ] || {
        echo "build host lock: unsafe lock metadata: ${lock_metadata:-unavailable}" >&2
        return 1
    }

    # Keep this descriptor open for the wrapper's complete lifetime. flock is
    # tied to the open file description, so normal exit and every EXIT-trap
    # path release it without a stale PID-file protocol.
    exec 9<> "$lock_file"
    if ! flock --exclusive --nonblock 9; then
        exec 9>&-
        echo "build host lock: another canonical ISO build is active for this release user" >&2
        return 75
    fi
}

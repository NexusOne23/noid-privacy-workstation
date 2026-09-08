#!/usr/bin/env bash
# Shared fail-before-write contract for repository source generators.
# Sourcing this file has no side effects.

# shellcheck disable=SC2034 # public global consumed by each sourcing wrapper.
noid_generator_parse_cli() {
    NOID_GENERATOR_MODE=regen
    case "$#:${1:-}" in
        0:) ;;
        1:--check) NOID_GENERATOR_MODE=check ;;
        1:-h|1:--help) NOID_GENERATOR_MODE=help ;;
        *) return 2 ;;
    esac
}

noid_generator_require_tools() {
    local command
    # Every wrapper calls this before marker inspection or candidate creation.
    # Include the shared library's own commands here so per-wrapper lists cover
    # only their additional tools and cannot drift from this implementation.
    for command in chmod cut diff grep mktemp mv od readlink sed stat tail tr "$@"; do
        command -v "$command" >/dev/null 2>&1 || {
            echo "source-generator: required command missing: $command" >&2
            return 1
        }
    done
}

noid_generator_require_file() {
    local path=$1
    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || {
        echo "source-generator: not a readable regular non-symlink file: $path" >&2
        return 1
    }
}

noid_generator_require_source() {
    local path=$1 delimiter=$2 last_byte
    noid_generator_require_file "$path" || return 1
    [ -s "$path" ] || {
        echo "source-generator: source is empty: $path" >&2
        return 1
    }
    if grep -qxF "$delimiter" "$path"; then
        echo "source-generator: source contains reserved delimiter: $delimiter" >&2
        return 1
    fi
    last_byte=$(tail -c 1 -- "$path" | od -An -t x1 | tr -d '[:space:]')
    [ "$last_byte" = 0a ] || {
        echo "source-generator: source must end in a newline: $path" >&2
        return 1
    }
}

noid_generator_marker_pair() {
    local target=$1 opening=$2 closing=$3
    local -a starts=() ends=()
    noid_generator_require_file "$target" || return 1
    mapfile -t starts < <(grep -nF "$opening" "$target" | cut -d: -f1)
    mapfile -t ends < <(grep -nxF "$closing" "$target" | cut -d: -f1)
    if [ "${#starts[@]}" -ne 1 ] || [ "${#ends[@]}" -ne 1 ] \
            || [ "${starts[0]:-0}" -ge "${ends[0]:-0}" ]; then
        echo "source-generator: exactly one ordered marker pair is required: $closing" >&2
        return 1
    fi
    NOID_GENERATOR_START=${starts[0]}
    NOID_GENERATOR_END=${ends[0]}
}

noid_generator_block_matches() {
    local target=$1 source=$2 opening=$3 closing=$4 start end
    noid_generator_marker_pair "$target" "$opening" "$closing" || return 1
    start=$NOID_GENERATOR_START
    end=$NOID_GENERATOR_END
    diff -q <(sed -n "$((start + 1)),$((end - 1))p" "$target") \
        "$source" >/dev/null
}

noid_generator_temp_for() {
    local target=$1 temporary
    noid_generator_require_file "$target" || return 1
    temporary=$(mktemp "${target}.tmp.XXXXXX") || return 1
    chmod --reference="$target" "$temporary" || {
        rm -f -- "$temporary"
        return 1
    }
    printf '%s\n' "$temporary"
}

noid_generator_publish() {
    local candidate=$1 target=$2 candidate_parent target_parent
    noid_generator_require_file "$target" || return 1
    [ -f "$candidate" ] && [ ! -L "$candidate" ] || return 1
    candidate_parent=$(readlink -e -- "${candidate%/*}") || return 1
    target_parent=$(readlink -e -- "${target%/*}") || return 1
    [ "$candidate_parent" = "$target_parent" ] || {
        echo "source-generator: candidate is not on the target filesystem" >&2
        return 1
    }
    [ "$(stat -c '%u:%g:%a' -- "$candidate")" \
        = "$(stat -c '%u:%g:%a' -- "$target")" ] || {
        echo "source-generator: candidate security metadata drifted" >&2
        return 1
    }
    mv -T -- "$candidate" "$target"
}

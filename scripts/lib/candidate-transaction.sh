#!/usr/bin/env bash
# Write-once candidate directory transaction used by scripts/build-iso.sh.
# This file is sourced; it intentionally changes no state until
# noid_candidate_begin is called.

noid_candidate_begin() {
    local output_root=$1 build_id=$2 candidate_class=$3 transaction_suffix

    [[ $output_root = /* ]] || {
        echo "candidate transaction: output root must be absolute" >&2
        return 1
    }
    [[ $build_id =~ ^[0-9a-f]{12}-[0-9]+$ ]] || {
        echo "candidate transaction: invalid build ID" >&2
        return 1
    }
    case "$candidate_class" in
        unsigned-candidate|signed-release) ;;
        *) echo "candidate transaction: invalid candidate class" >&2; return 1 ;;
    esac
    [ ! -L "$output_root" ] || {
        echo "candidate transaction: output root must not be a symlink" >&2
        return 1
    }
    if [ -e "$output_root" ] && [ ! -d "$output_root" ]; then
        echo "candidate transaction: output root is not a directory" >&2
        return 1
    fi
    mkdir -p -- "$output_root" || return 1

    CANDIDATE_PARENT="$output_root/candidates"
    [ ! -L "$CANDIDATE_PARENT" ] || {
        echo "candidate transaction: candidate parent must not be a symlink" >&2
        return 1
    }
    if [ -e "$CANDIDATE_PARENT" ] && [ ! -d "$CANDIDATE_PARENT" ]; then
        echo "candidate transaction: candidate parent is not a directory" >&2
        return 1
    fi
    mkdir -p -- "$CANDIDATE_PARENT" || return 1
    TRANSACTION_ROOT=$(mktemp -d \
        "$CANDIDATE_PARENT/.transaction.${build_id}.XXXXXX") || return 1
    chmod 0700 "$TRANSACTION_ROOT" || return 1
    transaction_suffix=${TRANSACTION_ROOT##*.}
    CANDIDATE_NAME="${candidate_class}-${build_id}-${transaction_suffix}"
    CANDIDATE_DIR="$CANDIDATE_PARENT/$CANDIDATE_NAME"
    RESULT_DIR="$TRANSACTION_ROOT/result"
    if [ -e "$RESULT_DIR" ] || [ -L "$RESULT_DIR" ] \
            || [ -e "$CANDIDATE_DIR" ] || [ -L "$CANDIDATE_DIR" ]; then
        echo "candidate transaction: unique path collision" >&2
        return 1
    fi
}

noid_candidate_publish() {
    local canonical_parent canonical_transaction_parent published_transaction

    [ -n "${CANDIDATE_PARENT:-}" ] && [ -n "${CANDIDATE_DIR:-}" ] \
        && [ -n "${TRANSACTION_ROOT:-}" ] && [ -n "${RESULT_DIR:-}" ] \
        || { echo "candidate transaction: incomplete publication state" >&2; return 1; }
    [ -d "$CANDIDATE_PARENT" ] && [ ! -L "$CANDIDATE_PARENT" ] \
        || { echo "candidate transaction: unsafe candidate parent" >&2; return 1; }
    [ -d "$TRANSACTION_ROOT" ] && [ ! -L "$TRANSACTION_ROOT" ] \
        || { echo "candidate transaction: unsafe transaction root" >&2; return 1; }
    [ -d "$RESULT_DIR" ] && [ ! -L "$RESULT_DIR" ] \
        || { echo "candidate transaction: result is not a non-symlink directory" >&2; return 1; }
    [ "$RESULT_DIR" = "$TRANSACTION_ROOT/result" ] \
        || { echo "candidate transaction: result escaped transaction root" >&2; return 1; }
    [ "${CANDIDATE_DIR%/*}" = "$CANDIDATE_PARENT" ] \
        || { echo "candidate transaction: destination escaped candidate parent" >&2; return 1; }
    canonical_parent=$(readlink -e -- "$CANDIDATE_PARENT") || return 1
    canonical_transaction_parent=$(readlink -e -- "${TRANSACTION_ROOT%/*}") \
        || return 1
    [ "$canonical_transaction_parent" = "$canonical_parent" ] \
        || { echo "candidate transaction: transaction is on another parent" >&2; return 1; }
    [ "$(stat -c %d -- "$RESULT_DIR")" = "$(stat -c %d -- "$CANDIDATE_PARENT")" ] \
        || { echo "candidate transaction: publication would cross filesystems" >&2; return 1; }
    if [ -e "$CANDIDATE_DIR" ] || [ -L "$CANDIDATE_DIR" ]; then
        echo "candidate transaction: refusing to replace existing candidate" >&2
        return 1
    fi

    # The preflight gives a clear diagnostic; the no-replace rename also closes
    # the collision window between that check and publication. GNU mv reports a
    # skipped destination as failure with update=none-fail.
    mv -T --update=none-fail -- "$RESULT_DIR" "$CANDIDATE_DIR" || return 1
    # Publication is complete at this point. Converge the caller-visible state
    # before the nonessential empty-shell cleanup so a failure or signal cannot
    # leave cleanup logic pointing at the vanished pre-publication result path.
    published_transaction=$TRANSACTION_ROOT
    TRANSACTION_ROOT=""
    RESULT_DIR="$CANDIDATE_DIR"
    if ! rmdir -- "$published_transaction"; then
        echo "candidate transaction: candidate published but transaction shell is not empty" >&2
        return 1
    fi
}

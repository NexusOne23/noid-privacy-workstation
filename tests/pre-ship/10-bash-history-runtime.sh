#!/bin/bash
# M10 candidate runtime gate — Bash history serialization and compaction.
# Run as the normal VM user in live, fresh-install and reboot passes.
set -euo pipefail

pass_id=${1:-}
case "$pass_id" in
    live|fresh-install|reboot) ;;
    *)
        echo "usage: $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac

if [[ $EUID -eq 0 ]]; then
    echo "FAIL: run this gate as the normal VM user, not root" >&2
    exit 1
fi

profile=/etc/profile.d/98-noid-bash-history.sh
compactor=/usr/local/libexec/noid-bash-history-compact
toggle=/usr/local/bin/noid-toggle-bash-history
doc=/usr/share/doc/noid-privacy/10-bash-history.md

expect_meta() {
    local path=$1 expected=$2
    [[ -f "$path" && ! -L "$path" ]] || {
        echo "FAIL: missing, non-regular or symlinked candidate artifact: $path" >&2
        exit 1
    }
    [[ $(stat -c '%U:%G:%a' "$path") == "$expected" ]] || {
        echo "FAIL: metadata mismatch for $path" >&2
        exit 1
    }
}

expect_meta "$profile" root:root:644
expect_meta "$compactor" root:root:755
expect_meta "$toggle" root:root:755
expect_meta "$doc" root:root:644
[[ -x "$compactor" && -x "$toggle" ]] || {
    echo "FAIL: installed M10 history helpers are not executable" >&2
    exit 1
}
for script in "$profile" "$compactor" "$toggle"; do
    bash -n "$script" || {
        echo "FAIL: installed Bash artifact does not parse: $script" >&2
        exit 1
    }
done

tmp_root=${XDG_RUNTIME_DIR:-/tmp}
tmp=$(mktemp -d -p "$tmp_root" noid-history-runtime.XXXXXX)
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT INT TERM

logical_count() {
    local history_file=$1
    HISTFILE="$history_file" HISTSIZE=1000 HISTFILESIZE=-1 \
        bash --noprofile --norc -c '
            history -c
            history -r "$HISTFILE"
            last=$(HISTTIMEFORMAT= history 1)
            if [[ -n "$last" ]]; then
                read -r count _ <<< "$last"
                printf "%s\n" "${count%\*}"
            else
                printf "0\n"
            fi
        '
}

# Existing string and array prompt hooks must survive repeated profile loads,
# and the NoID Privacy hook must appear exactly once.
array_state=$(
    PROFILE="$profile" HISTFILE="$tmp/array-history" \
        bash --noprofile --norc -ic \
        'PROMPT_COMMAND=(alpha beta); . "$PROFILE"; . "$PROFILE"; declare -p PROMPT_COMMAND; unset HISTFILE' \
        2>"$tmp/array.stderr"
)
[[ "$array_state" == 'declare -a PROMPT_COMMAND=([0]="alpha" [1]="beta" [2]="_noid_history_sync")' ]] || {
    echo "FAIL: PROMPT_COMMAND array preservation/idempotency mismatch" >&2
    exit 1
}

string_state=$(
    PROFILE="$profile" HISTFILE="$tmp/string-history" \
        bash --noprofile --norc -ic \
        'PROMPT_COMMAND="alpha; beta"; . "$PROFILE"; . "$PROFILE"; declare -p PROMPT_COMMAND; unset HISTFILE' \
        2>"$tmp/string.stderr"
)
[[ "$string_state" == 'declare -- PROMPT_COMMAND="alpha; beta; _noid_history_sync"' ]] || {
    echo "FAIL: PROMPT_COMMAND string preservation/idempotency mismatch" >&2
    exit 1
}

# One successful sync must publish exactly the newest 100 simple entries.
sequential="$tmp/sequential.history"
PROFILE="$profile" HISTFILE="$sequential" \
    bash --noprofile --norc -ic '
        . "$PROFILE"
        history -c
        for n in $(seq 1 125); do history -s "sequential-$n"; done
        _noid_history_sync
        unset HISTFILE
    ' 2>"$tmp/sequential.stderr"
[[ $(logical_count "$sequential") -eq 100 ]] || {
    echo "FAIL: sequential prompt sync did not retain exactly 100 entries" >&2
    exit 1
}
[[ $(tail -n 1 "$sequential") == sequential-125 ]] || {
    echo "FAIL: sequential prompt sync did not retain the newest entry" >&2
    exit 1
}
[[ $(stat -c %a "$sequential") == 600 ]] || {
    echo "FAIL: sequential history is not mode 0600" >&2
    exit 1
}

# Reproduce the prompt-append shape that defeated in-memory `erasedups`: the
# shared file already contains every occurrence when compaction starts.
dedup_history="$tmp/dedup.history"
for n in $(seq 1 80); do
    printf 'dedup-unique-%s\n' "$n" >> "$dedup_history"
done
for _ in $(seq 1 20); do
    printf 'dedup-SAME\n' >> "$dedup_history"
done
chmod 0600 "$dedup_history"
"$compactor" "$dedup_history" 100
[[ $(logical_count "$dedup_history") -eq 81 ]] || {
    echo "FAIL: 80 distinct plus 20 repeated commands did not retain 81 entries" >&2
    exit 1
}
[[ $(grep -c '^dedup-SAME$' "$dedup_history") -eq 1 \
   && $(tail -n 1 "$dedup_history") == dedup-SAME ]] || {
    echo "FAIL: persistent compaction did not retain only the newest exact duplicate" >&2
    exit 1
}

# Timestamp framing is enabled only for files that actually contain an exact
# numeric Bash timestamp record. A hash-digit command in a timestamp-free file
# must remain command text; numeric timestamp metadata must not be published.
hash_digit_history="$tmp/hash-digit.history"
printf '%s\n' 'echo before' '#5 my note' 'echo after' > "$hash_digit_history"
chmod 0600 "$hash_digit_history"
"$compactor" "$hash_digit_history" 10
printf '%s\n' 'echo before' '#5 my note' 'echo after' \
    > "$tmp/hash-digit.expected"
cmp -s "$tmp/hash-digit.expected" "$hash_digit_history" || {
    echo "FAIL: timestamp-free hash-digit command was reclassified as metadata" >&2
    exit 1
}

timestamp_history="$tmp/timestamp.history"
printf '%s\n' 'echo before' '#1700000000' 'echo after' > "$timestamp_history"
chmod 0600 "$timestamp_history"
"$compactor" "$timestamp_history" 10
printf '%s\n' 'echo before' 'echo after' > "$tmp/timestamp.expected"
cmp -s "$tmp/timestamp.expected" "$timestamp_history" || {
    echo "FAIL: numeric Bash timestamp metadata survived compaction" >&2
    exit 1
}

# Option-looking history text is data, not a second command-line for the Bash
# builtins used by the compactor. Exercise both a raw existing file and two
# real prompt syncs so retrieval and reconstruction boundaries are covered.
option_history="$tmp/option.history"
printf '%s\n' safe-first -pu-ok- -a -c '-d 1' -n -p -r -s -w -- -anrw \
    '  leading-spaces' -pu-ok- safe-last \
    > "$option_history"
chmod 0600 "$option_history"
printf '%s\n' safe-first -a -c '-d 1' -n -p -r -s -w -- -anrw \
    '  leading-spaces' -pu-ok- safe-last \
    > "$tmp/option.expected"
"$compactor" "$option_history" 100
cmp -s "$tmp/option.expected" "$option_history" || {
    echo "FAIL: compactor reinterpreted or reordered option-looking history text" >&2
    exit 1
}

prompt_option_history="$tmp/prompt-option.history"
PROFILE="$profile" HISTFILE="$prompt_option_history" \
    bash --noprofile --norc -ic '
        . "$PROFILE"
        history -c
        history -s -- safe-before
        history -s -- "-pu-ok-"
        _noid_history_sync
        history -s -- safe-after
        _noid_history_sync
        unset HISTFILE
    ' 2>"$tmp/prompt-option.stderr"
printf '%s\n' safe-before -pu-ok- safe-after > "$tmp/prompt-option.expected"
cmp -s "$tmp/prompt-option.expected" "$prompt_option_history" || {
    echo "FAIL: prompt compaction did not preserve a leading-dash entry" >&2
    exit 1
}
if grep -qE 'invalid option|history compaction failed' "$tmp/prompt-option.stderr"; then
    echo "FAIL: leading-dash prompt sync emitted an option-parser failure" >&2
    exit 1
fi

# A legitimate single entry may exceed 10 KiB. It must survive because the
# maintained contract is an entry limit, deliberately not a byte limit.
long_history="$tmp/long.history"
PROFILE="$profile" HISTFILE="$long_history" \
    bash --noprofile --norc -ic '
        . "$PROFILE"
        history -c
        for n in $(seq 1 99); do history -s "long-fixture-$n"; done
        printf -v long_entry "L%020000d" 0
        history -s "$long_entry"
        _noid_history_sync
        unset HISTFILE
    ' 2>"$tmp/long.stderr"
[[ $(logical_count "$long_history") -eq 100 ]] || {
    echo "FAIL: long-entry fixture changed the 100-entry boundary" >&2
    exit 1
}
[[ $(stat -c %s "$long_history") -gt 10240 ]] || {
    echo "FAIL: long-entry fixture was truncated to a fictitious 10-KiB cap" >&2
    exit 1
}

# Multiline serialization remains readable and bounded. Bash may parse the
# physical continuation as another history entry on a later read; the contract
# deliberately names Bash-parsed entries rather than promising command ASTs.
multiline_history="$tmp/multiline.history"
PROFILE="$profile" HISTFILE="$multiline_history" \
    bash --noprofile --norc -ic '
        . "$PROFILE"
        history -c
        for n in $(seq 1 98); do history -s "multiline-fixture-$n"; done
        history -s $'"'"'multiline-first\nmultiline-second'"'"'
        history -s multiline-final
        _noid_history_sync
        unset HISTFILE
    ' 2>"$tmp/multiline.stderr"
[[ $(logical_count "$multiline_history") -eq 100 ]] || {
    echo "FAIL: multiline serialization escaped the Bash-entry boundary" >&2
    exit 1
}
grep -qxF multiline-first "$multiline_history" \
    && grep -qxF multiline-second "$multiline_history" \
    && [[ $(tail -n 1 "$multiline_history") == multiline-final ]] || {
        echo "FAIL: multiline history content was lost or reordered" >&2
        exit 1
    }

expanded=$(
    HISTFILE="$multiline_history" bash --noprofile --norc -c \
        'history -c; history -r "$HISTFILE"; history -p "!!"'
)
[[ "$expanded" == multiline-final ]] || {
    echo "FAIL: history expansion does not resolve the newest retained entry" >&2
    exit 1
}

# Kill a separate process group after `history -a` has visibly published its
# newest entry but while a deliberately large compaction is still in flight.
# The original must stay complete; the next sync must heal the excess and
# remove any mode-0600 temporary copies that SIGKILL prevented traps cleaning.
recovery_history="$tmp/recovery.history"
seq 1 200000 | sed 's/^/recovery-/' > "$recovery_history"
chmod 0600 "$recovery_history"
PROFILE="$profile" HISTFILE=/dev/null TARGET_HISTORY="$recovery_history" \
    setsid bash --noprofile --norc -ic '
        . "$PROFILE"
        HISTFILE="$TARGET_HISTORY"
        history -c
        history -s recovery-killed-newest
        _noid_history_sync
        unset HISTFILE
    ' 2>"$tmp/recovery-killed.stderr" &
kill_pid=$!
kill_pgid=$(ps -o pgid= -p "$kill_pid" | tr -d ' ')
[[ "$kill_pgid" == "$kill_pid" ]] || {
    echo "FAIL: SIGKILL fixture did not get an isolated process group" >&2
    kill "$kill_pid" 2>/dev/null || true
    wait "$kill_pid" 2>/dev/null || true
    exit 1
}
append_seen=0
for _ in $(seq 1 2000); do
    if [[ $(tail -n 1 "$recovery_history" 2>/dev/null || true) == \
          recovery-killed-newest ]]; then
        append_seen=1
        break
    fi
    kill -0 "$kill_pid" 2>/dev/null || break
    sleep 0.001
done
[[ $append_seen -eq 1 ]] || {
    echo "FAIL: could not observe the append-before-compaction window" >&2
    kill -KILL -- "-$kill_pid" 2>/dev/null || true
    wait "$kill_pid" 2>/dev/null || true
    exit 1
}
kill -KILL -- "-$kill_pid"
if wait "$kill_pid" 2>/dev/null; then
    echo "FAIL: interrupted-compaction shell did not die from SIGKILL" >&2
    exit 1
fi
[[ $(logical_count "$recovery_history") -gt 100 \
   && $(tail -n 1 "$recovery_history") == recovery-killed-newest ]] || {
    echo "FAIL: SIGKILL window did not preserve the complete appended history" >&2
    exit 1
}

PROFILE="$profile" HISTFILE=/dev/null TARGET_HISTORY="$recovery_history" \
    bash --noprofile --norc -ic '
        . "$PROFILE"
        HISTFILE="$TARGET_HISTORY"
        history -c
        _noid_history_sync
        unset HISTFILE
    ' 2>"$tmp/recovery-heal.stderr"
[[ $(logical_count "$recovery_history") -eq 100 \
   && $(tail -n 1 "$recovery_history") == recovery-killed-newest ]] || {
    echo "FAIL: next prompt sync did not heal the real SIGKILL excess" >&2
    exit 1
}
shopt -s nullglob
recovery_leftovers=(
    "$tmp/.recovery.history.noid-compact."*
    "$tmp/.recovery.history.noid-parse."*
)
[[ ${#recovery_leftovers[@]} -eq 0 ]] || {
    echo "FAIL: next sync left SIGKILL compaction copies behind" >&2
    exit 1
}
unset recovery_leftovers
shopt -u nullglob

# Four simultaneous, independent terminal shells share one file. Give every
# fixture its own session and no controlling terminal; nested interactive Bash
# processes must not share the gate's foreground process group and stop the
# whole gate through terminal job control.
parallel_history="$tmp/parallel.history"
run_parallel_shell() {
    local prefix=$1
    PROFILE="$profile" HISTFILE=/dev/null TARGET_HISTORY="$parallel_history" \
        setsid bash --noprofile --norc -ic '
            . "$PROFILE"
            HISTFILE="$TARGET_HISTORY"
            history -c
            for n in $(seq 1 35); do history -s "$1-$n"; done
            _noid_history_sync
            unset HISTFILE
        ' _ "$prefix" </dev/null 2>"$tmp/parallel-$prefix.stderr"
}

pids=()
for prefix in alpha beta gamma delta; do
    run_parallel_shell "$prefix" &
    pids+=("$!")
done
parallel_failed=0
for pid in "${pids[@]}"; do
    wait "$pid" || parallel_failed=1
done
[[ $parallel_failed -eq 0 ]] || {
    echo "FAIL: at least one concurrent history sync failed" >&2
    exit 1
}
[[ $(logical_count "$parallel_history") -eq 100 ]] || {
    echo "FAIL: concurrent prompt sync did not publish exactly 100 entries" >&2
    exit 1
}
[[ $(stat -c %a "$parallel_history") == 600 ]] || {
    echo "FAIL: concurrent history is not mode 0600" >&2
    exit 1
}
[[ -f "$parallel_history.noid.lock" && ! -L "$parallel_history.noid.lock" \
   && $(stat -c %a "$parallel_history.noid.lock") == 600 ]] || {
    echo "FAIL: per-user history lock is missing, symlinked or not mode 0600" >&2
    exit 1
}

# Refuse a symlink target and leave its referent byte-identical.
printf '%s\n' sentinel > "$tmp/symlink-target"
ln -s "$tmp/symlink-target" "$tmp/history-link"
before=$(sha256sum "$tmp/symlink-target" | awk '{print $1}')
if "$compactor" "$tmp/history-link" 100 >/dev/null 2>&1; then
    echo "FAIL: compactor accepted a symlink history path" >&2
    exit 1
fi
after=$(sha256sum "$tmp/symlink-target" | awk '{print $1}')
[[ "$before" == "$after" ]] || {
    echo "FAIL: rejected symlink compaction changed its referent" >&2
    exit 1
}

echo "PASS: M10 Bash history runtime [$pass_id]"

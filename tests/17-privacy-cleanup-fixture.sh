#!/usr/bin/env bash
# Behavioral fixtures for M17's ordered, path-safe GNOME privacy cleanup.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT=$(find_project_root)
HELPER="$ROOT/scripts/noid-gnome-privacy-cleanup.py"
TEST_TMPDIR=$(mktemp -d "$ROOT/.privacy-cleanup-fixture.XXXXXX")
trap 'rm -rf -- "$TEST_TMPDIR"' EXIT HUP INT TERM

test_start "17-privacy-cleanup-fixture"

assert_absent() {
    local path=$1 description=$2
    if [[ ! -e $path && ! -L $path ]]; then
        _pass "$description"
    else
        _fail "$description (still present: $path)"
    fi
}

assert_file_executable "$HELPER" "canonical cleanup helper is executable"
assert_cmd_success "cleanup helper compiles" python3 -c \
    'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_bytes(), str(p), "exec")' \
    "$HELPER"
assert_cmd_success "cleanup help is side-effect-free" "$HELPER" --help

home="$TEST_TMPDIR/home"
data="$TEST_TMPDIR/data home"
cache="$TEST_TMPDIR/cache home"
mkdir -p \
    "$home/.mozilla/firefox/default" \
    "$home/.config/mozilla/firefox/playground" \
    "$home/.thunderbird/default" \
    "$data/gnome-shell" \
    "$cache/thumbnails/normal/deep" \
    "$cache/thumbnails/fail"
printf 'app-state\n' > "$data/gnome-shell/application_state"
printf 'history\n' > "$data/gnome-shell/session-active-history.json"
printf 'thumb\n' > "$cache/thumbnails/normal/deep/.hidden-thumbnail"
printf 'failed\n' > "$cache/thumbnails/fail/item"
ln -s '127.0.0.1:+43210' "$home/.mozilla/firefox/default/lock"
printf 'ff-parent\n' > "$home/.mozilla/firefox/default/.parentlock"
ln -s '127.0.0.1:+43211' "$home/.config/mozilla/firefox/playground/lock"
printf 'play-parent\n' > "$home/.config/mozilla/firefox/playground/.parentlock"
ln -s '127.0.0.1:+43212' "$home/.thunderbird/default/lock"
printf 'tb-parent\n' > "$home/.thunderbird/default/.parentlock"

assert_cmd_success "custom-XDG cleanup removes exact tracking/cache state" \
    env HOME="$home" XDG_DATA_HOME="$data" XDG_CACHE_HOME="$cache" "$HELPER"
assert_absent "$data/gnome-shell/application_state" \
    "GNOME application_state removed"
assert_absent "$data/gnome-shell/session-active-history.json" \
    "GNOME session history removed"
assert_absent "$cache/thumbnails" \
    "complete thumbnail tree including hidden entries removed"
assert_eq '127.0.0.1:+43210' "$(readlink "$home/.mozilla/firefox/default/lock")" \
    "Firefox traditional lock remains application-owned"
assert_grep_fixed 'ff-parent' "$home/.mozilla/firefox/default/.parentlock" \
    "Firefox parent lock remains byte-intact"
assert_eq '127.0.0.1:+43211' "$(readlink "$home/.config/mozilla/firefox/playground/lock")" \
    "Firefox playground lock remains application-owned"
assert_grep_fixed 'play-parent' "$home/.config/mozilla/firefox/playground/.parentlock" \
    "Firefox playground parent lock remains byte-intact"
assert_eq '127.0.0.1:+43212' "$(readlink "$home/.thunderbird/default/lock")" \
    "Thunderbird lock remains application-owned"
assert_grep_fixed 'tb-parent' "$home/.thunderbird/default/.parentlock" \
    "Thunderbird parent lock remains byte-intact"

victim="$TEST_TMPDIR/symlink-victim"
mkdir -p "$victim"
printf 'keep\n' > "$victim/keep"
ln -s "$victim" "$cache/thumbnails"
assert_cmd_success "thumbnail-root symlink is unlinked without traversal" \
    env HOME="$home" XDG_DATA_HOME="$data" XDG_CACHE_HOME="$cache" "$HELPER"
assert_file_exists "$victim/keep" "thumbnail symlink target remains intact"
assert_absent "$cache/thumbnails" "thumbnail symlink itself is removed"

real_cache="$TEST_TMPDIR/real-cache"
mkdir -p "$real_cache/thumbnails"
printf 'keep-root\n' > "$real_cache/thumbnails/keep"
ln -s "$real_cache" "$TEST_TMPDIR/cache-link"
assert_cmd_failure "symlinked XDG cache root is refused" \
    env HOME="$home" XDG_DATA_HOME="$data" \
        XDG_CACHE_HOME="$TEST_TMPDIR/cache-link" "$HELPER"
assert_file_exists "$real_cache/thumbnails/keep" \
    "refused XDG root symlink cannot delete its target"

readonly_data="$TEST_TMPDIR/readonly-data"
readonly_cache="$TEST_TMPDIR/readonly-cache"
mkdir -p "$readonly_data/gnome-shell" "$readonly_cache/thumbnails"
printf 'keep-readonly\n' > "$readonly_data/gnome-shell/application_state"
printf 'keep-cache\n' > "$readonly_cache/thumbnails/keep"
chmod 0500 "$readonly_data/gnome-shell"
assert_cmd_failure "read-only tracking root exposes failure before cache mutation" \
    env HOME="$home" XDG_DATA_HOME="$readonly_data" \
        XDG_CACHE_HOME="$readonly_cache" "$HELPER"
assert_file_exists "$readonly_data/gnome-shell/application_state" \
    "read-only tracking record remains intact"
assert_file_exists "$readonly_cache/thumbnails/keep" \
    "read-only failure does not partially delete cache"
chmod 0700 "$readonly_data/gnome-shell"

if command -v unshare >/dev/null 2>&1 && command -v mount >/dev/null 2>&1 \
   && unshare --user --map-root-user --mount true >/dev/null 2>&1; then
    assert_cmd_success "bind-mounted thumbnail root is refused before any deletion" \
        env HELPER="$HELPER" unshare --user --map-root-user --mount \
        bash -Eeuo pipefail -c '
            mount --make-rprivate /
            root=$(mktemp -d)
            trap '\''umount "$root/cache/thumbnails" 2>/dev/null || true; rm -rf -- "$root"'\'' EXIT
            mkdir -p "$root/home" "$root/data/gnome-shell" \
                "$root/cache/thumbnails" "$root/victim"
            printf "tracking\n" > "$root/data/gnome-shell/application_state"
            printf "keep-mounted\n" > "$root/victim/keep"
            mount --bind "$root/victim" "$root/cache/thumbnails"
            if HOME="$root/home" XDG_DATA_HOME="$root/data" \
               XDG_CACHE_HOME="$root/cache" "$HELPER" \
               >"$root/out" 2>"$root/err"; then
                exit 1
            fi
            grep -qF "mount boundary refused" "$root/err"
            test -f "$root/victim/keep"
            test -f "$root/data/gnome-shell/application_state"
        '
else
    _pass "mount-substitution fixture deferred; unprivileged mount namespace unavailable"
fi

interrupt_cache="$TEST_TMPDIR/interrupt-cache"
mkdir -p "$interrupt_cache/thumbnails/bulk"
python3 - "$interrupt_cache/thumbnails/bulk" <<'INTERRUPT_FIXTURE_PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
for number in range(10000):
    (root / f"entry-{number:05d}").write_bytes(b"fixture\n")
INTERRUPT_FIXTURE_PY
env HOME="$home" XDG_DATA_HOME="$data" XDG_CACHE_HOME="$interrupt_cache" \
    "$HELPER" >"$TEST_TMPDIR/interrupted.out" 2>"$TEST_TMPDIR/interrupted.err" &
cleanup_pid=$!
quarantine_seen=0
for _ in {1..20000}; do
    if compgen -G "$interrupt_cache/.noid-thumbnails-delete-*" >/dev/null; then
        quarantine_seen=1
        kill -STOP "$cleanup_pid" 2>/dev/null || true
        break
    fi
    kill -0 "$cleanup_pid" 2>/dev/null || break
done
assert_eq 1 "$quarantine_seen" "interrupt fixture observes atomic quarantine"
kill -KILL "$cleanup_pid" 2>/dev/null || true
wait "$cleanup_pid" 2>/dev/null || true
assert_cmd_success "interrupted quarantine remains recoverable" \
    bash -c 'compgen -G "$1/.noid-thumbnails-delete-*" >/dev/null' _ \
    "$interrupt_cache"
assert_cmd_success "next cleanup resumes interrupted quarantine" \
    env HOME="$home" XDG_DATA_HOME="$data" \
        XDG_CACHE_HOME="$interrupt_cache" "$HELPER"
assert_cmd_failure "recovered cleanup leaves no quarantine residue" \
    bash -c 'compgen -G "$1/.noid-thumbnails-delete-*" >/dev/null' _ \
    "$interrupt_cache"
assert_absent "$interrupt_cache/thumbnails" \
    "recovered cleanup leaves no public thumbnail tree"

mkdir -p "$TEST_TMPDIR/empty-home"
assert_cmd_success "missing XDG roots are a clean no-op" \
    env HOME="$TEST_TMPDIR/empty-home" \
        XDG_DATA_HOME="$TEST_TMPDIR/missing-data" \
        XDG_CACHE_HOME="$TEST_TMPDIR/missing-cache" "$HELPER"

test_finish

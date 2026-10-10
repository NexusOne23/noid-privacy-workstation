#!/bin/bash
# 08-udisks2-mount-propagation-structural — Module 08 udisks2 drop-in
#
# Guards against the "ghost mount" regression:
# any mount-namespace-creating directive in the udisks2 hardening
# drop-in forces udisksd into a private mount-NS; mounts the daemon
# creates under /run/media/<user>/* then stay invisible to the host.
#
# This test asserts at the SOURCE level (before build) that:
#   1. The drop-in heredoc is present + extractable
#   2. The [Service] block contains EXACTLY the 10 expected NS-free
#      directives (verified: udisksd PID stays in
#      host mnt-NS mnt:[4026531832] with this set)
#   3. NONE of the reviewed mount-NS-creating directives appear in the
#      [Service] block (each would re-trigger the ghost-mount bug)
#   4. The root-cause explanation + systemd-issue/moby-PR references
#      are present in the heredoc comment block (drift-proof for future
#      audits — if anyone touches the drop-in without reading why those
#      directives are forbidden, this test points them at the rationale)
#
# Would have caught the introduction of PrivateTmp/ProtectHome/
# ProtectSystem=full/ProtectKernel*/ProtectControlGroups into the
# drop-in. This regression existed in previously shipped images.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"

test_start "08-udisks2-mount-propagation-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"

# --- Heredoc presence + extraction ------------------------------------------

assert_grep_fixed \
    "cat > /etc/systemd/system/udisks2.service.d/99-noid-hardening.conf <<'UDISKS2_HARDEN_EOF'" \
    "$KS_FILE" \
    "udisks2 drop-in heredoc start present"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

extract_heredoc "$KS_FILE" "UDISKS2_HARDEN_EOF" "$TMPDIR/udisks2-hardening.conf" \
    || _fail "UDISKS2_HARDEN_EOF heredoc extraction"

# --- Extract just the [Service] block for directive assertions --------------
#
# Comments in the heredoc body may legally mention forbidden directive
# names (the "Deliberately NOT set" listing is intentional).
# Only the live [Service]-block directives matter for mount-NS behaviour,
# so directive presence/absence is asserted against the [Service] section
# alone, not the comment headers.

awk '/^\[Service\]$/,0' "$TMPDIR/udisks2-hardening.conf" \
    | grep -v '^[[:space:]]*#' \
    > "$TMPDIR/service-block.conf"

# Sanity: [Service] header was found
assert_grep_extended '^\[Service\]$' "$TMPDIR/service-block.conf" \
    "[Service] section present in drop-in"

# --- Required 10 NS-free directives (verified) --------------

for directive in \
    '^NoNewPrivileges=yes$' \
    '^RestrictSUIDSGID=yes$' \
    '^LockPersonality=yes$' \
    '^MemoryDenyWriteExecute=yes$' \
    '^ProtectClock=yes$' \
    '^ProtectHostname=yes$' \
    '^RestrictRealtime=yes$' \
    '^RestrictAddressFamilies=AF_UNIX AF_NETLINK$' \
    '^IPAddressDeny=any$' \
    '^UMask=0077$' \
; do
    assert_grep_extended "$directive" "$TMPDIR/service-block.conf" \
        "required NS-free directive: $directive"
done

cat > "$TMPDIR/expected-service-directives" <<'EXPECTED_DIRECTIVES'
IPAddressDeny=any
LockPersonality=yes
MemoryDenyWriteExecute=yes
NoNewPrivileges=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictRealtime=yes
RestrictSUIDSGID=yes
UMask=0077
EXPECTED_DIRECTIVES
grep -E '^[A-Za-z][A-Za-z0-9]*=' "$TMPDIR/service-block.conf" | \
    LC_ALL=C sort > "$TMPDIR/actual-service-directives"
LC_ALL=C sort -o "$TMPDIR/expected-service-directives" \
    "$TMPDIR/expected-service-directives"
assert_eq 10 "$(wc -l < "$TMPDIR/actual-service-directives")" \
    "[Service] contains exactly ten active directives"
assert_cmd_success "[Service] directive set is closed and exact" \
    diff -u "$TMPDIR/expected-service-directives" \
        "$TMPDIR/actual-service-directives"

# --- Forbidden mount-NS-creating directives ---------------------------------
#
# Per systemd.exec(5), these directives in a [Service] section force a
# private mount-namespace and downgrade propagation from shared → slave,
# making mounts created by the service invisible to the host. udisks2
# publishes mounts to /run/media/<user>/* — it MUST run in the host
# mount namespace. References: systemd issue #9873, moby PR #22806
# (same root-cause + same fix for docker.service).

for forbidden in \
    '^PrivateTmp=' \
    '^PrivateDevices=' \
    '^PrivateMounts=' \
    '^PrivateUsers=' \
    '^PrivatePIDs=' \
    '^PrivateNetwork=' \
    '^PrivateBPF=' \
    '^ProtectHome=' \
    '^ProtectSystem=' \
    '^ProtectKernelTunables=' \
    '^ProtectKernelModules=' \
    '^ProtectKernelLogs=' \
    '^ProtectControlGroups=' \
    '^ProtectProc=' \
    '^ProcSubset=' \
    '^ReadOnlyPaths=' \
    '^ReadWritePaths=' \
    '^NoExecPaths=' \
    '^ExecPaths=' \
    '^InaccessiblePaths=' \
    '^BindPaths=' \
    '^BindReadOnlyPaths=' \
    '^TemporaryFileSystem=' \
    '^MountFlags=' \
    '^RootDirectory=' \
    '^RootImage=' \
    '^MountImages=' \
    '^ExtensionImages=' \
    '^ExtensionDirectories=' \
    '^LogNamespace=' \
    '^DynamicUser=' \
; do
    assert_not_grep "$forbidden" "$TMPDIR/service-block.conf" \
        "forbidden mount-NS directive absent: $forbidden"
done

# RestrictNamespaces= does not create a mount namespace. It is forbidden for
# a separate reason: filtering CLONE_NEWNS breaks udisks mount helpers.
assert_not_grep '^RestrictNamespaces=' "$TMPDIR/service-block.conf" \
    "namespace filter absent so udisks helpers can use CLONE_NEWNS"

# --- rationale anchors in heredoc comments (drift-proof) ----------------
#
# If any of these go missing, someone removed the root-cause context.
# Re-introduce the explanation BEFORE re-introducing any directive
# present in the forbidden-list above.

assert_grep_fixed "ROOT-CAUSE FIX (verified)" "$TMPDIR/udisks2-hardening.conf" \
    "root-cause-fix marker present in heredoc"
assert_not_grep '\<v[0-9][0-9]*\>' "$TMPDIR/udisks2-hardening.conf" \
    "shipped drop-in carries no internal revision labels"
assert_grep_fixed "ghost mount" "$TMPDIR/udisks2-hardening.conf" \
    "ghost-mount terminology referenced"
assert_grep_fixed "systemd #9873" "$TMPDIR/udisks2-hardening.conf" \
    "systemd upstream issue #9873 cross-ref present"
assert_grep_fixed "moby PR #22806" "$TMPDIR/udisks2-hardening.conf" \
    "moby PR #22806 (docker same-fix) cross-ref present"
assert_grep_fixed "Deliberately NOT set" "$TMPDIR/udisks2-hardening.conf" \
    "deliberately-not-set listing present"
assert_grep_fixed "CVE-2025-6019" "$TMPDIR/udisks2-hardening.conf" \
    "CVE-2025-6019 coverage note present"
assert_grep_fixed "CVE-2026-7867 as-user" "$TMPDIR/udisks2-hardening.conf" \
    "shipped drop-in names the as-user Mount fix carried by the package"
assert_not_grep 'udisks2-2\.11\.1-\|Reproduced on the hardened host\|verified live' \
    "$TMPDIR/udisks2-hardening.conf" \
    "shipped drop-in states the current package floor without lab narration"

# --- package security floor (CVE-2026-7867) ---------------------------------

assert_grep_fixed 'UDISKS2_MIN_VER="2.11.2"' "$KS_FILE" \
    "Module 08 requires the udisks2 as-user Mount authorization fix"
sed -n '/^if ! UDISKS2_VER=/,/^echo "  \[OK\] udisks2 \$UDISKS2_VER/p' "$KS_FILE" \
    > "$TMPDIR/udisks2-floor.sh"
assert_cmd_success "udisks2 floor fixture extracts" bash -n "$TMPDIR/udisks2-floor.sh"
run_udisks2_floor_fixture() {
    local mode=$1 expected_rc=$2 rc=0
    FAKE_UDISKS2_MODE="$mode" bash -c '
        set -euo pipefail
        rpm() {
            case "$FAKE_UDISKS2_MODE" in
                current) printf "%s\n" 2.11.2 ;;
                newer) printf "%s\n" 2.12.0 ;;
                old) printf "%s\n" 2.11.1 ;;
                two-arches) printf "%s\n" 2.11.2 2.11.2 ;;
                missing) printf "%s\n" "package udisks2 is not installed"; return 1 ;;
            esac
        }
        source "$1"
    ' _ "$TMPDIR/udisks2-floor.sh" >/dev/null || rc=$?
    assert_eq "$expected_rc" "$rc" "udisks2 floor ${mode} result"
}
run_udisks2_floor_fixture current 0
run_udisks2_floor_fixture newer 0
run_udisks2_floor_fixture old 1
run_udisks2_floor_fixture two-arches 1
run_udisks2_floor_fixture missing 1

# --- libmount mount-event file (companion of UMask=0077) --------------------
#
# libmount's first writer creates /run/mount/utab.event with 0644 filtered by
# its umask, so a first UDisks mount would leave it 0600 and every later
# systemd --user manager would fail its inotify watch with EACCES.

assert_grep_fixed \
    "cat > /etc/tmpfiles.d/noid-libmount-utab-event.conf <<'LIBMOUNT_UTAB_EVENT_EOF'" \
    "$KS_FILE" "libmount mount-event tmpfiles heredoc present"
extract_heredoc "$KS_FILE" "LIBMOUNT_UTAB_EVENT_EOF" "$TMPDIR/libmount-utab-event.conf" \
    || _fail "LIBMOUNT_UTAB_EVENT_EOF heredoc extraction"
grep -v '^#' "$TMPDIR/libmount-utab-event.conf" > "$TMPDIR/libmount-active.conf"
printf '%s\n' 'd /run/mount 0755 root root -' 'f /run/mount/utab.event 0644 root root -' \
    > "$TMPDIR/libmount-expected.conf"
assert_cmd_success "libmount tmpfiles entry is exactly the directory + 0644 event file" \
    diff -u "$TMPDIR/libmount-expected.conf" "$TMPDIR/libmount-active.conf"
assert_grep_fixed 'chmod 0644 /etc/tmpfiles.d/noid-libmount-utab-event.conf' "$KS_FILE" \
    "libmount tmpfiles entry published 0644"
assert_grep_fixed 'chown root:root /etc/tmpfiles.d/noid-libmount-utab-event.conf' "$KS_FILE" \
    "libmount tmpfiles entry owned by root"
assert_grep_fixed '# 10.3b2 — libmount mount-event file entry' "$KS_FILE" \
    "Module 08 verification checks the libmount tmpfiles entry"
assert_grep_fixed '/etc/tmpfiles.d/noid-libmount-utab-event.conf' "$TMPDIR/udisks2-hardening.conf" \
    "udisks2 drop-in names its UMask companion"

if command -v systemd-tmpfiles >/dev/null 2>&1; then
    # Owners need root; the unprivileged fixture keeps the reviewed modes.
    tmpfiles_root="$TMPDIR/tmpfiles-root"
    mkdir -p "$tmpfiles_root/run"
    sed 's/ root root / - - /' "$TMPDIR/libmount-active.conf" > "$TMPDIR/libmount-user.conf"
    event="$tmpfiles_root/run/mount/utab.event"
    libmount_writer() {
        (umask 077; python3 -c 'import os, sys
os.close(os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o644))' "$1")
    }
    assert_cmd_success "systemd-tmpfiles accepts the entry under a restrictive umask" \
        bash -c 'umask 077; systemd-tmpfiles --root="$1" --create "$2"' _ \
        "$tmpfiles_root" "$TMPDIR/libmount-user.conf"
    assert_eq 755 "$(stat -c %a "$tmpfiles_root/run/mount")" "tmpfiles creates /run/mount 0755"
    assert_eq 644 "$(stat -c %a "$event")" "tmpfiles creates utab.event 0644"
    libmount_writer "$event"
    assert_eq 644 "$(stat -c %a "$event")" \
        "a umask-0077 libmount writer keeps the pre-created 0644 mode"
    rm -f -- "$event"
    libmount_writer "$event"
    assert_eq 600 "$(stat -c %a "$event")" \
        "positive control: without the entry the same writer creates 0600"
else
    _fail "systemd-tmpfiles is required for the libmount mount-event fixture"
fi

# --- Echo-line + score claim sanity -----------------------------------------

assert_grep_fixed \
    "udisks2 hardening drop-in (+10 NS-free directives" \
    "$KS_FILE" \
    "echo-line directive-count present"
assert_grep_fixed "score 7.9 EXPOSED" "$KS_FILE" \
    "echo-line score claim present"

# --- header documents the udisks2 hardening decision ------------------------

assert_grep_fixed "# Status: LOCKED" "$KS_FILE" \
    "header status line present"
assert_grep_fixed "udisks2 ghost-mount" "$KS_FILE" \
    "header mentions ghost-mount"

test_finish

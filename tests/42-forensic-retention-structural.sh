#!/bin/bash
# 42-forensic-retention-structural — M42 + companion-fix regression test
#
# Covers:
#   - M42 module (5 prune+rotate scripts, 5 service+timer pairs, strict
#     active-log + wtmp/btmp logrotate policies, stamp adopter)
#   - M20 (logrotate.d/snapper sed cap) + (NUMBER_LIMIT bump +
#     noid-snapper-prune script/service/timer)
#   - M13 (aide-check wrapper + explicit user-owned baseline review)
#   - M25 (check-only update evidence)
#   - M99 EXPECTED_STAMPS += 42
#   - master.ks %include for M42
#
# Would catch:
#   - Missing script/service/timer for any of the 5 M42 prune flows
#   - Missing/wrong audit-netlink or capability boundary on auditd-rotate
#     (auditctl needs AF_NETLINK + CAP_AUDIT_CONTROL before CAP_KILL)
#   - A fake live-daemon NetworkManager history truncate that its RAM database
#     can repopulate, or section-blind profile-key deletion
#   - A scheduled retention job deleting user-owned AIDE trust databases
#   - Source/live drift between M13/M25 and the retained documentation
#   - EXPECTED_STAMPS list out of sync with the actual stamp adopters
#     (= 99-finalize would silently pass when an adopter's stamp was missing)

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"

KS_M42="$PROJECT_ROOT/kickstart/snippets/42-forensic-retention.ks"
KS_M20="$PROJECT_ROOT/kickstart/snippets/20-snapper.ks"
KS_M13="$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks"
KS_M25="$PROJECT_ROOT/kickstart/snippets/25-update-process.ks"
KS_M99="$PROJECT_ROOT/kickstart/snippets/99-finalize.ks"
KS_M08="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"
KS_M21="$PROJECT_ROOT/kickstart/snippets/21-kernel-module-blacklist.ks"
KS_MASTER="$PROJECT_ROOT/kickstart/master.ks"
DOC_RETENTION="$PROJECT_ROOT/docs/log-retention.md"
DOC_FAILURES="$PROJECT_ROOT/docs/known-failures.md"
README="$PROJECT_ROOT/README.md"
INDEX="$PROJECT_ROOT/INDEX.md"
TMPDIR="$(mktemp -d)"
EXEC_TMPDIR="$(mktemp -d /var/tmp/noid-m42-test.XXXXXX)"
trap 'rm -rf "$TMPDIR" "$EXEC_TMPDIR"' EXIT

test_start "42-forensic-retention-structural"

# ----------------------------------------------------------------------------
# M42 module — file exists + bash -n
# ----------------------------------------------------------------------------
assert_file_exists "$KS_M42"
assert_cmd_success "bash -n $KS_M42" bash -n "$KS_M42"

# ----------------------------------------------------------------------------
# M42 — 5 prune+rotate scripts deployed via heredoc
# ----------------------------------------------------------------------------
assert_grep_fixed '/usr/local/sbin/noid-install-logs-prune.sh' "$KS_M42"
assert_grep_fixed '/usr/local/sbin/noid-audit-prune.sh' "$KS_M42"
assert_grep_fixed '/usr/local/sbin/noid-misc-logs-prune.sh' "$KS_M42"
assert_grep_fixed '/usr/local/sbin/noid-nm-privacy-prune.sh' "$KS_M42"
assert_grep_fixed '/usr/local/sbin/noid-auditd-rotate.sh' "$KS_M42"
assert_grep_fixed '[ "$(readlink -- /usr/local/sbin)" = bin ]' "$KS_M42" \
    "M42 binds Fedora 44's exact unified-sbin alias"
canonical_script_stage_count=$(grep -c \
    '^stage_root_file /usr/local/bin/noid-' "$KS_M42" || true)
assert_eq "5" "${canonical_script_stage_count:-0}" \
    "all five helpers publish through the real unified-sbin directory"
assert_not_grep '^stage_root_file /usr/local/sbin/' "$KS_M42" \
    "strict publication never follows the unified-sbin parent symlink"

# Heredoc terminators for each of the 5 scripts
assert_grep_fixed "INSTALL_LOGS_PRUNE_EOF" "$KS_M42"
assert_grep_fixed "AUDIT_PRUNE_EOF" "$KS_M42"
assert_grep_fixed "MISC_LOGS_PRUNE_EOF" "$KS_M42"
assert_grep_fixed "NM_PRIVACY_PRUNE_EOF" "$KS_M42"
assert_grep_fixed "AUDITD_ROTATE_EOF" "$KS_M42"

for script_marker in INSTALL_LOGS_PRUNE_EOF AUDIT_PRUNE_EOF \
                     MISC_LOGS_PRUNE_EOF NM_PRIVACY_PRUNE_EOF \
                     AUDITD_ROTATE_EOF; do
    extract_heredoc "$KS_M42" "$script_marker" \
        "$TMPDIR/${script_marker}.sh" || _fail "$script_marker extraction"
    assert_cmd_success "$script_marker is valid bash" \
        bash -n "$TMPDIR/${script_marker}.sh"
done

# Every shipped helper is a zero-argument systemd entry point. Reject hostile
# bytes before logger, filesystem, daemon-state or audit-control work begins.
helper_arg_specs=(
    INSTALL_LOGS_PRUNE_EOF:noid-install-logs-prune.sh
    AUDIT_PRUNE_EOF:noid-audit-prune.sh
    MISC_LOGS_PRUNE_EOF:noid-misc-logs-prune.sh
    NM_PRIVACY_PRUNE_EOF:noid-nm-privacy-prune.sh
    AUDITD_ROTATE_EOF:noid-auditd-rotate.sh
)
for helper_arg_spec in "${helper_arg_specs[@]}"; do
    helper_marker=${helper_arg_spec%%:*}
    helper_name=${helper_arg_spec#*:}
    helper_stdout="$TMPDIR/${helper_marker}.hostile.stdout"
    helper_stderr="$TMPDIR/${helper_marker}.hostile.stderr"
    set +e
    bash "$TMPDIR/${helper_marker}.sh" \
        $'hostile\n\033[31m' duplicate \
        > "$helper_stdout" 2> "$helper_stderr"
    helper_rc=$?
    set -e
    assert_eq 2 "$helper_rc" \
        "$helper_name rejects hostile surplus arguments"
    assert_eq "" "$(cat "$helper_stdout")" \
        "$helper_name hostile rejection has no stdout"
    assert_eq "Usage: $helper_name" "$(cat "$helper_stderr")" \
        "$helper_name emits one constant usage line"
    assert_eq 1 "$(wc -l < "$helper_stderr")" \
        "$helper_name usage output is exactly one line"
    assert_cmd_failure \
        "$helper_name does not reflect hostile terminal-control bytes" \
        grep -q $'\033' "$helper_stderr"
done
stage_count=$(grep -c '^stage_root_file ' "$KS_M42" || true)
assert_eq "22" "${stage_count:-0}" \
    "all five scripts, ten units, two drop-ins and five policies use the durable publisher"
assert_not_grep_extended \
    '^[[:space:]]*cat[[:space:]]*>[[:space:]]*/(usr/local|etc)/' \
    "$KS_M42" "M42 never streams bytes directly into a privileged final path"
assert_grep_fixed '# M42_ROOT_PUBLICATION_BEGIN' "$KS_M42" \
    "the tested durable publisher has an explicit extraction boundary"
assert_grep_fixed '! -newermt "-${CUTOFF_DAYS} days"' \
    "$TMPDIR/INSTALL_LOGS_PRUNE_EOF.sh"
assert_grep_fixed '! -newermt "-${CUTOFF_DAYS} days"' \
    "$TMPDIR/AUDIT_PRUNE_EOF.sh"
assert_grep_fixed 'High-volume records can therefore leave the ring before 30 days' \
    "$TMPDIR/AUDIT_PRUNE_EOF.sh" \
    "audit retention is not overstated as a 30-day completeness guarantee"
assert_grep_fixed 'maximum age' "$KS_M42" \
    "M42 consistently describes an age ceiling"
assert_grep_fixed '[ "$FAILURES" -eq 0 ] || exit 1' \
    "$TMPDIR/INSTALL_LOGS_PRUNE_EOF.sh" \
    "install-log deletion failures propagate"
assert_grep_fixed '[ "$FAILURES" -eq 0 ] || exit 1' \
    "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh" \
    "NetworkManager history failures propagate"

# ----------------------------------------------------------------------------
# M42 — 30-day cutoff consistent across scripts (= forensic policy invariant)
# ----------------------------------------------------------------------------
# Three day-based prune scripts each declare CUTOFF_DAYS=30 once:
# install-logs-prune, audit-prune and misc-logs-prune. NM privacy state and
# forced audit rotation are event-based and do not need this variable.
count_30=$(grep -cE '^CUTOFF_DAYS=30$' "$KS_M42" || true)
count_30=${count_30:-0}
assert_cmd_success "M42 CUTOFF_DAYS=30 occurrences >= 3 (got $count_30)" \
    test "$count_30" -ge 3

# NetworkManager global history must cover BOTH seen-bssids and timestamps.
# The daemon owns in-memory copies, so clearing is allowed only at its stopped
# pre-start boundary; a live daily run sanitizes profiles without a restart.
assert_grep_fixed 'for f in "$NM_STATE_DIR/seen-bssids" "$NM_STATE_DIR/timestamps"; do' \
    "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh"
assert_grep_fixed 'Before=NetworkManager.service' "$KS_M42"
assert_grep_fixed 'Wants=noid-nm-privacy-prune.service' "$KS_M42"
assert_grep_fixed 'After=noid-nm-privacy-prune.service' "$KS_M42"
assert_grep_fixed 'ConditionPathExists=!/etc/noid-privacy/disable-nm-history-prune' \
    "$KS_M42" "NetworkManager history clearing has an explicit complete opt-out"
assert_grep_fixed 'NetworkManager history opt-out boundary is unsafe' "$KS_M42" \
    "complete opt-out marker has a verified root-owned parent"
assert_grep_fixed 'install -d -m 0700 -o root -g root /etc/noid-privacy' \
    "$KS_M08" "M08 defines the shared private root boundary"
assert_grep_fixed 'chmod 0700 /etc/noid-privacy' "$KS_M21" \
    "M21 preserves the shared private root boundary"
assert_grep_fixed 'NetworkManager history opt-out boundary did not converge to 0700' \
    "$KS_M42" "M42 verifies the shared private root boundary before publication"
assert_grep_fixed \
    '&& [ "$(stat -Lc '\''%u:%g:%a'\'' /etc/noid-privacy)" = "0:0:700" ]' \
    "$KS_M42" "M42 final gate binds the exact private parent mode"
assert_grep_fixed 'active daemon owns RAM history; deferring clear until its next start' \
    "$KS_M42" "a live daemon is never misreported as cleared"
assert_not_grep ': > "$f"' "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh" \
    "M42 has no ineffective live-daemon in-place truncate"
assert_grep_fixed 'internal-*.lease files are NOT pruned' "$KS_M42" \
    "M42 records the deliberate NetworkManager lease-state exception"
assert_file_exists "$DOC_RETENTION"
assert_not_grep 'cleared daily.*in-place truncate' "$DOC_RETENTION" \
    "retention guide contains no obsolete fake live-clear claim"
assert_grep_fixed 'cleared before every daemon start; a bootless session may exceed 30 days' \
    "$DOC_RETENTION" "retention guide states the honest global-history boundary"
assert_grep_fixed 'A few records can be lost in the short interval' \
    "$DOC_RETENTION" "retention guide states copytruncate's bounded loss window"
assert_grep_fixed '/etc/noid-privacy/disable-nm-history-prune' "$DOC_RETENTION" \
    "retention guide documents the complete opt-out marker"
assert_grep_fixed "NetworkManager's private \`internal-*.lease\` files" \
    "$DOC_RETENTION" \
    "retention guide discloses retained private lease state"
assert_grep_fixed 'per-interface recency signal through their mtime' \
    "$DOC_RETENTION" \
    "retention guide names the lease-state privacy exposure"
assert_grep_fixed '.local/state/noid-privacy/extension-updates.log' \
    "$DOC_RETENTION" \
    "retention guide discloses the unpruned per-user extension ledger"
assert_grep_fixed 'before every UPower start' "$DOC_RETENTION" \
    "retention guide names the stopped-daemon UPower lifecycle boundary"
assert_grep_fixed 'never infers inactivity from mtime' "$DOC_RETENTION" \
    "retention inventory does not overclaim mtime-based device inactivity"
assert_grep_fixed 'only after the user accepts a baseline and enables AIDE' \
    "$DOC_RETENTION" "retention schedule preserves AIDE's user-owned enable boundary"
assert_grep_fixed 'sudo /usr/local/sbin/noid-aide-check.sh' "$DOC_FAILURES" \
    "failure guide uses the validated, serialized AIDE wrapper"
assert_not_grep 'sudo aide --check' "$DOC_FAILURES" \
    "failure guide never bypasses the supported AIDE wrapper"
assert_grep_fixed 'disabling only the daily timer does not' \
    "$DOC_FAILURES" "failure guide distinguishes timer and pre-start boundaries"
assert_grep_fixed "daemon-owned live state use their documented safe lifecycle boundaries" \
    "$README" "landing-page retention claim preserves the lifecycle exception"
assert_grep_fixed "stopped-daemon boundary for NetworkManager's RAM-backed history" \
    "$INDEX" "repository index describes M42's real NetworkManager mechanism"

# Legacy/imported per-profile seen-bssids + timestamp state is stripped from
# exact native sections in system .nmconnection files. Same-named keys in a
# VPN/plugin section must survive. The script uses native offline validation,
# atomic exchange/rollback and an exact per-file active-daemon load.
assert_grep_fixed '/etc/NetworkManager/system-connections' "$KS_M42"
assert_grep_fixed 'section == "connection"' "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh"
assert_grep_fixed 'section == "wifi" || section == "802-11-wireless"' \
    "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh"
assert_grep_fixed 'chmod 0600 "$ACTIVE_CANDIDATE"' "$KS_M42"
assert_grep_fixed 'profile_meta" != "0:0:600:1"' "$KS_M42"
assert_grep_fixed '/usr/bin/mv --exchange -T -- "$ACTIVE_CANDIDATE" "$ACTIVE_PROFILE"' \
    "$KS_M42"
assert_grep_fixed '/usr/bin/nmcli --offline connection modify' "$KS_M42"
assert_grep_fixed '/usr/bin/nmcli connection load' "$KS_M42"
assert_grep_fixed 'rollback_active_profile()' "$KS_M42"
assert_not_grep 'nmcli connection reload' "$KS_M42" \
    "M42 uses per-file load failures instead of an always-successful global reload"
# ReadWritePaths must include /etc/NetworkManager/system-connections for
# the atomic edit to survive ProtectSystem=strict.
assert_grep_extended 'ReadWritePaths=/var/lib/NetworkManager /etc/NetworkManager/system-connections' "$KS_M42"

# The live image exposes package directories from a SquashFS lower layer,
# where st_nlink is 2; copied-up overlay and installed Btrfs directories report
# 1. Bind the portable security boundary without weakening its exact type,
# canonical path, owner/mode or SELinux-label checks.
assert_grep_fixed 'stat -Lc '\''%u:%g:%a'\'' -- "$path"' \
    "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh" \
    "NetworkManager directory validation is independent of filesystem link-count encoding"
assert_grep_fixed 'verify_directory "$NM_STATE_DIR" "0:0:700"' \
    "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh" \
    "NetworkManager state directory keeps exact root-only ownership and mode"
assert_grep_fixed 'verify_directory "$NMCONN_DIR" "0:0:755"' \
    "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh" \
    "NetworkManager profile directory keeps exact root ownership and mode"
assert_cmd_failure "NetworkManager directory validation never pins st_nlink" \
    grep -Fq "stat -Lc '%u:%g:%a:%h' -- \"\$path\"" \
        "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh"

# Exercise stopped-daemon clearing, active-daemon deferral, exact-section
# sanitation and failed-load rollback without touching host NetworkManager.
nm_fixture="$EXEC_TMPDIR/nm-fixture"
nm_state="$nm_fixture/state"
nm_profiles="$nm_fixture/system-connections"
nm_tools="$nm_fixture/tools"
mkdir -p "$nm_state" "$nm_profiles" "$nm_tools"
chmod 0700 "$nm_state"
chmod 0755 "$nm_profiles"
printf '%s\n' 'aa:bb:cc:dd:ee:ff' > "$nm_state/seen-bssids"
printf '%s\n' 'profile-uuid=1700000000' > "$nm_state/timestamps"
chmod 0644 "$nm_state/seen-bssids" "$nm_state/timestamps"
seen_inode_before=$(stat -Lc %i "$nm_state/seen-bssids")
timestamps_inode_before=$(stat -Lc %i "$nm_state/timestamps")
printf '%s\n' 'interrupted-old-state' > "$nm_state/.noid-nm-state.ABCDEF"
chmod 0644 "$nm_state/.noid-nm-state.ABCDEF"

changed_profile="$nm_profiles/Office WiFi.nmconnection"
unchanged_profile="$nm_profiles/Wired.nmconnection"
same_name_profile="$nm_profiles/VPN data.nmconnection"
cat > "$changed_profile" <<'NM_CHANGED_EOF'
[connection]
id=Office WiFi
uuid=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
type=wifi
 timestamp =1700000000
[wifi]
ssid=Office WiFi
mode=infrastructure
 seen-bssids =aa:bb:cc:dd:ee:ff;
bssid=aa:bb:cc:dd:ee:ff
cloned-mac-address=random
[ipv4]
method=auto
[ipv6]
method=auto
NM_CHANGED_EOF
cat > "$unchanged_profile" <<'NM_UNCHANGED_EOF'
[connection]
id=Wired
uuid=11111111-2222-4333-8444-555555555555
type=ethernet
[ethernet]
cloned-mac-address=stable
[ipv4]
method=auto
[ipv6]
method=auto
NM_UNCHANGED_EOF
cat > "$same_name_profile" <<'NM_SAME_NAME_EOF'
[connection]
id=VPN data
uuid=99999999-8888-4777-8666-555555555555
type=vpn
[vpn]
service-type=org.freedesktop.NetworkManager.openvpn
timestamp=must-survive
seen-bssids=must-survive
NM_SAME_NAME_EOF
chmod 0600 "$changed_profile" "$unchanged_profile" "$same_name_profile"
unchanged_sha_before=$(sha256sum "$unchanged_profile" | awk '{print $1}')
same_name_sha_before=$(sha256sum "$same_name_profile" | awk '{print $1}')
printf '%s\n' 'interrupted-profile-candidate' \
    > "$nm_profiles/.noid-nm-profile.ABCDEF"
chmod 0600 "$nm_profiles/.noid-nm-profile.ABCDEF"

cat > "$nm_tools/nmcli" <<'NMCLI_FIXTURE_EOF'
#!/bin/bash
set -euo pipefail
case "${1:-}" in
    --offline)
        printf '%s\n' offline >> "$NMCLI_FIXTURE_LOG"
        exec /usr/bin/nmcli "$@"
        ;;
    connection)
        printf 'load:%s\n' "${3:-}" >> "$NMCLI_FIXTURE_LOG"
        [ "${NMCLI_FIXTURE_FAIL_LOAD:-0}" -eq 0 ]
        ;;
    *) exit 2 ;;
esac
NMCLI_FIXTURE_EOF
cat > "$nm_tools/matchpathcon" <<'MATCHPATHCON_FIXTURE_EOF'
#!/bin/bash
exit 0
MATCHPATHCON_FIXTURE_EOF
cat > "$nm_tools/systemctl" <<'SYSTEMCTL_FIXTURE_EOF'
#!/bin/bash
set -euo pipefail
[ "${1:-}" = show ]
printf 'ActiveState=%s\nMainPID=%s\n' \
    "${NM_SYSTEMCTL_STATE:?}" "${NM_SYSTEMCTL_MAIN_PID:?}"
SYSTEMCTL_FIXTURE_EOF
cat > "$nm_tools/rm" <<'RM_FIXTURE_EOF'
#!/bin/bash
set -euo pipefail
target="${!#}"
/usr/bin/rm "$@"
if [ "${NM_FAIL_FINAL_SYNC:-0}" -eq 1 ]; then
    case "$target" in
        "$NM_FIXTURE_PROFILE_DIR"/.noid-nm-profile.*)
            : > "$NM_FAULT_MARKER"
            ;;
    esac
fi
RM_FIXTURE_EOF
cat > "$nm_tools/sync" <<'SYNC_FIXTURE_EOF'
#!/bin/bash
set -euo pipefail
if [ "${NM_FAIL_FINAL_SYNC:-0}" -eq 1 ] \
   && [ -e "$NM_FAULT_MARKER" ] \
   && [ "$#" -eq 2 ] && [ "$1" = -- ] \
   && [ "$2" = "$NM_FIXTURE_PROFILE_DIR" ]; then
    /usr/bin/rm -f -- "$NM_FAULT_MARKER"
    exit 1
fi
exec /usr/bin/sync "$@"
SYNC_FIXTURE_EOF
chmod 0755 "$nm_tools/nmcli" "$nm_tools/matchpathcon" \
    "$nm_tools/systemctl" "$nm_tools/rm" "$nm_tools/sync"

fixture_owner="$(id -u):$(id -g)"
sed -e "s#/var/lib/NetworkManager#$nm_state#g" \
    -e "s#/etc/NetworkManager/system-connections#$nm_profiles#g" \
    -e "s#/usr/bin/nmcli#$nm_tools/nmcli#g" \
    -e "s#/usr/bin/systemctl#$nm_tools/systemctl#g" \
    -e "s#/usr/sbin/matchpathcon#$nm_tools/matchpathcon#g" \
    -e 's#rm -f -- "$ACTIVE_CANDIDATE"#'"$nm_tools"'/rm -f -- "$ACTIVE_CANDIDATE"#g' \
    -e 's#sync -- "$NMCONN_DIR"#'"$nm_tools"'/sync -- "$NMCONN_DIR"#g' \
    -e "s#0:0:#$fixture_owner:#g" \
    "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh" > "$TMPDIR/nm-privacy-fixture.sh"
assert_cmd_success "fixture-rewritten NetworkManager helper remains valid bash" \
    bash -n "$TMPDIR/nm-privacy-fixture.sh"
NMCLI_FIXTURE_LOG="$nm_fixture/nmcli.log" NM_SYSTEMCTL_STATE=inactive \
    NM_SYSTEMCTL_MAIN_PID=0 \
    PATH="$nm_tools:$PATH" bash "$TMPDIR/nm-privacy-fixture.sh"
assert_eq "0" "$(stat -Lc %s "$nm_state/seen-bssids")" \
    "stopped-daemon seen-bssids state is cleared"
assert_eq "0" "$(stat -Lc %s "$nm_state/timestamps")" \
    "stopped-daemon timestamps state is cleared"
assert_cmd_failure "seen-bssids clearing uses atomic replacement" \
    test "$seen_inode_before" = "$(stat -Lc %i "$nm_state/seen-bssids")"
assert_cmd_failure "timestamps clearing uses atomic replacement" \
    test "$timestamps_inode_before" = "$(stat -Lc %i "$nm_state/timestamps")"
assert_eq "$fixture_owner:600:1" \
    "$(stat -Lc '%u:%g:%a:%h' "$nm_state/seen-bssids")" \
    "cleared state becomes root-only"
assert_cmd_failure "legacy profile timestamp is removed" \
    grep -qE '^[[:space:]]*timestamp[[:space:]]*=' "$changed_profile"
assert_cmd_failure "legacy profile seen-bssids is removed" \
    grep -qE '^[[:space:]]*seen-bssids[[:space:]]*=' "$changed_profile"
assert_grep_fixed 'bssid=aa:bb:cc:dd:ee:ff' "$changed_profile" \
    "manual BSSID pin survives profile sanitation"
assert_grep_fixed 'cloned-mac-address=random' "$changed_profile" \
    "MAC-cloning policy survives profile sanitation"
assert_eq "$fixture_owner:600:1" \
    "$(stat -Lc '%u:%g:%a:%h' "$changed_profile")" \
    "changed profile retains exact root-only metadata"
assert_eq "$unchanged_sha_before" \
    "$(sha256sum "$unchanged_profile" | awk '{print $1}')" \
    "unchanged profile bytes remain untouched"
assert_eq "$same_name_sha_before" \
    "$(sha256sum "$same_name_profile" | awk '{print $1}')" \
    "same-named VPN/plugin data survives section-aware sanitation"
assert_eq "offline" "$(cat "$nm_fixture/nmcli.log")" \
    "stopped-daemon profile is natively parsed without a D-Bus load"
assert_cmd_success "interrupted state candidate is retired safely" \
    test ! -e "$nm_state/.noid-nm-state.ABCDEF"
assert_cmd_success "interrupted profile candidate is retired safely" \
    test ! -e "$nm_profiles/.noid-nm-profile.ABCDEF"
assert_cmd_success "no staged profile is left behind" \
    test -z "$(find "$nm_profiles" -maxdepth 1 \
        -name '.noid-nm-profile.*' -print -quit)"

# A start job ordered after this prerequisite can already expose
# ActiveState=activating. PID 0 still proves that no daemon owns the RAM-backed
# databases, so the pre-start boundary must remain effective.
printf '%s\n' 'queued-start-seen-history' > "$nm_state/seen-bssids"
printf '%s\n' 'queued-start-time-history' > "$nm_state/timestamps"
: > "$nm_fixture/nmcli.log"
NMCLI_FIXTURE_LOG="$nm_fixture/nmcli.log" NM_SYSTEMCTL_STATE=activating \
    NM_SYSTEMCTL_MAIN_PID=0 \
    PATH="$nm_tools:$PATH" bash "$TMPDIR/nm-privacy-fixture.sh"
assert_eq "0" "$(stat -Lc %s "$nm_state/seen-bssids")" \
    "queued daemon start with no MainPID preserves the clearing boundary"
assert_eq "0" "$(stat -Lc %s "$nm_state/timestamps")" \
    "queued daemon start clears both RAM-backed databases before ExecStart"

# A live-daemon pass must leave global RAM-backed state untouched, while still
# validating and loading the exact changed profile.
printf '%s\n' 'live-seen-history' > "$nm_state/seen-bssids"
printf '%s\n' 'live-time-history' > "$nm_state/timestamps"
sed -i '/^type=wifi$/a timestamp=1800000000' "$changed_profile"
sed -i '/^mode=infrastructure$/a seen-bssids=02:00:00:00:00:01;' \
    "$changed_profile"
: > "$nm_fixture/nmcli.log"
NMCLI_FIXTURE_LOG="$nm_fixture/nmcli.log" NM_SYSTEMCTL_STATE=active \
    NM_SYSTEMCTL_MAIN_PID=123 \
    PATH="$nm_tools:$PATH" bash "$TMPDIR/nm-privacy-fixture.sh"
assert_grep_fixed 'live-seen-history' "$nm_state/seen-bssids" \
    "active-daemon seen-bssids history is honestly deferred"
assert_grep_fixed 'live-time-history' "$nm_state/timestamps" \
    "active-daemon timestamp history is honestly deferred"
assert_eq "offline
load:$changed_profile" "$(cat "$nm_fixture/nmcli.log")" \
    "active-daemon sanitation validates offline then loads only the exact file"

# If native D-Bus loading rejects the publication, the original profile must
# return byte-for-byte and no credential-bearing candidate may remain.
sed -i '/^type=wifi$/a timestamp=1900000000' "$changed_profile"
sed -i '/^mode=infrastructure$/a seen-bssids=02:00:00:00:00:02;' \
    "$changed_profile"
rollback_sha=$(sha256sum "$changed_profile" | awk '{print $1}')
: > "$nm_fixture/nmcli.log"
assert_cmd_failure "failed native profile load rejects the transaction" \
    env NMCLI_FIXTURE_LOG="$nm_fixture/nmcli.log" \
        NMCLI_FIXTURE_FAIL_LOAD=1 NM_SYSTEMCTL_STATE=active \
        NM_SYSTEMCTL_MAIN_PID=123 \
        PATH="$nm_tools:$PATH" bash "$TMPDIR/nm-privacy-fixture.sh"
assert_eq "$rollback_sha" \
    "$(sha256sum "$changed_profile" | awk '{print $1}')" \
    "failed native load restores the original profile bytes"
assert_cmd_success "failed load leaves no old-profile candidate" \
    test -z "$(find "$nm_profiles" -maxdepth 1 \
        -name '.noid-nm-profile.*' -print -quit)"

# Once the old-profile candidate is gone, a final directory-sync failure must
# be visible without attempting an impossible rollback through that vanished
# path. The fully checked sanitized profile remains the only published file.
sed -i '/^type=wifi$/a timestamp=2000000000' "$changed_profile"
sed -i '/^mode=infrastructure$/a seen-bssids=02:00:00:00:00:03;' \
    "$changed_profile"
: > "$nm_fixture/nmcli.log"
assert_cmd_failure "post-removal directory-sync failure remains visible" \
    env NMCLI_FIXTURE_LOG="$nm_fixture/nmcli.log" \
        NM_SYSTEMCTL_STATE=active NM_SYSTEMCTL_MAIN_PID=123 \
        NM_FAIL_FINAL_SYNC=1 NM_FAULT_MARKER="$nm_fixture/final-sync-fault" \
        NM_FIXTURE_PROFILE_DIR="$nm_profiles" \
        PATH="$nm_tools:$PATH" bash "$TMPDIR/nm-privacy-fixture.sh"
assert_cmd_failure "irrevocably committed profile remains sanitized" \
    grep -qE '^[[:space:]]*(timestamp|seen-bssids)[[:space:]]*=' \
        "$changed_profile"
assert_cmd_success "sync-failure path leaves no vanished-source rollback handle" \
    test -z "$(find "$nm_profiles" -maxdepth 1 \
        -name '.noid-nm-profile.*' -print -quit)"

# auditd-rotate uses audit-userspace's native signal interface.
assert_grep_fixed '/usr/bin/auditctl --signal rotate' "$KS_M42"
assert_grep_fixed 'required daily rotation failed' "$KS_M42" \
    "missing auditd makes the daily rotation unit fail visibly"
assert_not_grep 'pidof auditd' "$KS_M42" \
    "rotation does not discover or log an auditd PID"
assert_not_grep 'kill -USR1' "$KS_M42" \
    "rotation does not duplicate auditctl's native interface"

# install-logs prune covers /root/anaconda-ks.cfg + /root/original-ks.cfg
# (the latter ships the full RPM list = strong install-fingerprint).
assert_grep_fixed 'anaconda-ks.cfg' "$KS_M42"
assert_grep_fixed 'original-ks.cfg' "$KS_M42"
for exact_install_log in \
    'ks-10-authselect.err' \
    'noid-anaconda-kernel-cmdline.log' \
    'noid-firstboot-setup.log' \
    'noid-crypto-policy.err'; do
    assert_grep_fixed "-name '$exact_install_log'" \
        "$TMPDIR/INSTALL_LOGS_PRUNE_EOF.sh" \
        "install retention includes exact one-shot artifact: $exact_install_log"
done
assert_cmd_failure \
    "install retention does not broaden into arbitrary NoID Privacy logs" \
    grep -Fq -- "-name 'noid-*'" "$TMPDIR/INSTALL_LOGS_PRUNE_EOF.sh"

# Exercise the exact install-log contract against a disposable fixture.
sed -n '/^delete_aged() {$/,/^}$/p' \
    "$TMPDIR/INSTALL_LOGS_PRUNE_EOF.sh" > "$TMPDIR/install-functions.sh"
sed -n '/^delete_aged_install_logs() {$/,/^}$/p' \
    "$TMPDIR/INSTALL_LOGS_PRUNE_EOF.sh" >> "$TMPDIR/install-functions.sh"
assert_cmd_success "extracted install prune functions are valid bash" \
    bash -n "$TMPDIR/install-functions.sh"
# Generated functions extracted from the audited heredoc.
# shellcheck disable=SC1090
. "$TMPDIR/install-functions.sh"
export CUTOFF_DAYS=30
mkdir "$TMPDIR/install-fixture"
for install_name in ks-01-bootloader.log ks-10-authselect.err \
        noid-anaconda-kernel-cmdline.log noid-firstboot-setup.log \
        noid-crypto-policy.err unrelated-private.log; do
    : > "$TMPDIR/install-fixture/$install_name"
    touch -d '31 days ago' "$TMPDIR/install-fixture/$install_name"
done
: > "$TMPDIR/install-fixture/young-noid-firstboot-setup.log"
touch -d '29 days ago' "$TMPDIR/install-fixture/young-noid-firstboot-setup.log"
install_removed=$(delete_aged_install_logs "$TMPDIR/install-fixture")
assert_eq "5" "$install_removed" "exactly the five old install artifacts are pruned"
assert_file_exists "$TMPDIR/install-fixture/unrelated-private.log" \
    "unrelated old log survives install retention"
assert_file_exists "$TMPDIR/install-fixture/young-noid-firstboot-setup.log" \
    "young target survives install retention"

# Misc pruning uses exact full-path regular expressions: digit-prefix or
# date-prefix near-matches must never enter the deletion boundary.
assert_grep_fixed "-regex '.*/dnf5\\.log\\.[0-9]+(\\.gz)?'" "$KS_M42"
assert_grep_fixed "-regex '.*/dnf5\\.log-[0-9]{8}(\\.gz)?'" "$KS_M42"
assert_cmd_failure "DNF pruning has no digit-prefix glob" \
    grep -qF -- "dnf5.log.[0-9]*" "$KS_M42"
assert_cmd_failure "DNF pruning has no date-prefix glob" \
    grep -qF -- "dnf5.log-20*" "$KS_M42"

# UPower natively culls loaded-device records after seven days whenever it
# saves. M42 neither rewrites daemon-owned contents nor guesses inactivity from
# mtime: exact old files are removed only with MainPID=0 before daemon start.
assert_grep_fixed '/var/lib/upower' "$KS_M42"
assert_grep_extended "history-\\*\\.dat" "$KS_M42"
assert_grep_fixed "-regex '.*/history-[^/]+\\.dat'" "$KS_M42"
assert_not_grep 'prune_upower_file' "$KS_M42" \
    "M42 does not race UPower with an external record rewriter"
assert_grep_fixed '# M42_UPOWER_LIFECYCLE_BEGIN' "$KS_M42"
assert_grep_fixed '/usr/bin/systemctl show upower.service' "$KS_M42"
assert_grep_fixed 'DEFERRED UPower history prune: daemon owns the writer boundary' \
    "$KS_M42" "active upowerd ownership defers whole-file deletion"
assert_grep_fixed 'Before=upower.service' "$KS_M42" \
    "the misc helper is ordered before UPower can own its writer"

# Extract the complete misc helper and verify its exact relative-time boundary.
extract_heredoc "$KS_M42" "MISC_LOGS_PRUNE_EOF" "$TMPDIR/misc-prune.sh" \
    || _fail "misc prune heredoc extraction"
assert_grep_fixed '! -newermt "-${CUTOFF_DAYS} days"' "$TMPDIR/misc-prune.sh" \
    "misc file pruning uses an exact relative cutoff"
assert_not_grep 'mtime [+]30' "$TMPDIR/misc-prune.sh" \
    "misc pruning has no rounded -mtime cutoff"
assert_not_grep '/var/lib/aide/archive' "$TMPDIR/misc-prune.sh" \
    "scheduled retention cannot delete user-owned AIDE trust archives"
assert_not_grep "-name 'aide.db.*.gz'" "$TMPDIR/misc-prune.sh" \
    "AIDE database files are outside log retention"
assert_grep_fixed "-regex '.*/aide-baseline-review-[0-9]{8}-[0-9]{6}\\.[A-Za-z0-9]{6}\\.log'" "$TMPDIR/misc-prune.sh" \
    "user-review reports retain the documented 30-day log boundary"
assert_grep_fixed "-regex '.*/[^/]+\\.log\\.[0-9]+(\\.gz)?'" \
    "$TMPDIR/misc-prune.sh" \
    "numeric archive matching is exact and compression-aware"
assert_grep_fixed "-regex '.*/[^/]+\\.log-[0-9]{8}(\\.gz)?'" \
    "$TMPDIR/misc-prune.sh" \
    "dateext archive matching requires an exact YYYYMMDD suffix"
assert_cmd_failure "misc pruning never unlinks an active log basename" \
    grep -Fq -- "-type f -name '*.log*'" "$TMPDIR/misc-prune.sh"

# Exercise exact UPower filename and archive boundaries in a disposable tree.
sed -n '/^delete_aged() {$/,/^}$/p' "$TMPDIR/misc-prune.sh" \
    > "$TMPDIR/misc-delete-function.sh"
assert_cmd_success "extracted misc delete function is valid bash" \
    bash -n "$TMPDIR/misc-delete-function.sh"
# Generated function extracted from the audited heredoc.
# shellcheck disable=SC1090
. "$TMPDIR/misc-delete-function.sh"
export CUTOFF_DAYS=30
mkdir "$TMPDIR/upower-fixture" "$TMPDIR/archive-fixture"
for name in history-charge-old.dat history-charge-young.dat \
            history-charge-old.dat.keep unrelated.dat; do
    : > "$TMPDIR/upower-fixture/$name"
done
touch -d '31 days ago' "$TMPDIR/upower-fixture/history-charge-old.dat" \
    "$TMPDIR/upower-fixture/history-charge-old.dat.keep" \
    "$TMPDIR/upower-fixture/unrelated.dat"
touch -d '29 days ago' "$TMPDIR/upower-fixture/history-charge-young.dat"
upower_removed=$(delete_aged "$TMPDIR/upower-fixture" \
    -regextype posix-extended -maxdepth 1 -type f \
    -regex '.*/history-[^/]+\.dat')
assert_eq "1" "$upower_removed" "only one old exact UPower history is removed"
assert_file_exists "$TMPDIR/upower-fixture/history-charge-young.dat"
assert_file_exists "$TMPDIR/upower-fixture/history-charge-old.dat.keep"
assert_file_exists "$TMPDIR/upower-fixture/unrelated.dat"

# Exercise the exact daemon-lifecycle decision around the same filename scope.
sed -n '/# M42_UPOWER_LIFECYCLE_BEGIN/,/# M42_UPOWER_LIFECYCLE_END/p' \
    "$TMPDIR/misc-prune.sh" > "$TMPDIR/upower-lifecycle-block.sh"
cat > "$EXEC_TMPDIR/upower-systemctl" <<'UPOWER_SYSTEMCTL_FIXTURE_EOF'
#!/bin/bash
printf 'ActiveState=%s\nMainPID=%s\n' \
    "${UPOWER_TEST_STATE:?}" "${UPOWER_TEST_PID:?}"
UPOWER_SYSTEMCTL_FIXTURE_EOF
chmod 0755 "$EXEC_TMPDIR/upower-systemctl"
{
    printf '%s\n' '#!/bin/bash' 'set -u' 'CUTOFF_DAYS=30' \
        'LOG_TAG=noid-m42-test' 'DELETE_FAILURES=0'
    cat "$TMPDIR/misc-delete-function.sh"
    sed -e "s#/usr/bin/systemctl#$EXEC_TMPDIR/upower-systemctl#g" \
        -e "s#/var/lib/upower#$TMPDIR/upower-lifecycle-fixture#g" \
        -e 's/logger -t "$LOG_TAG"/:/g' \
        "$TMPDIR/upower-lifecycle-block.sh"
    printf '%s\n' '[ "$DELETE_FAILURES" -eq 0 ]'
} > "$TMPDIR/upower-lifecycle-fixture.sh"
assert_cmd_success "extracted UPower lifecycle block is valid bash" \
    bash -n "$TMPDIR/upower-lifecycle-fixture.sh"
run_upower_lifecycle_fixture() {
    UPOWER_TEST_STATE=$1 UPOWER_TEST_PID=$2 \
        bash "$TMPDIR/upower-lifecycle-fixture.sh"
}
mkdir "$TMPDIR/upower-lifecycle-fixture"
: > "$TMPDIR/upower-lifecycle-fixture/history-charge-old.dat"
touch -d '31 days ago' \
    "$TMPDIR/upower-lifecycle-fixture/history-charge-old.dat"
assert_cmd_success "active UPower lifecycle pass defers safely" \
    run_upower_lifecycle_fixture active 4242
assert_file_exists "$TMPDIR/upower-lifecycle-fixture/history-charge-old.dat" \
    "active upowerd keeps its path untouched"
assert_cmd_success "stopped UPower lifecycle pass prunes the exact old file" \
    run_upower_lifecycle_fixture activating 0
assert_cmd_success "stopped-daemon UPower history is removed" \
    test ! -e "$TMPDIR/upower-lifecycle-fixture/history-charge-old.dat"

for name in vm.log.1 vm.log.1.keep vm.log-20260701.gz \
            vm.log-20260701.keep vm.log; do
    : > "$TMPDIR/archive-fixture/$name"
    touch -d '31 days ago' "$TMPDIR/archive-fixture/$name"
done
archive_removed=$(delete_aged "$TMPDIR/archive-fixture" \
    -regextype posix-extended -maxdepth 1 -type f \
    \( -regex '.*/[^/]+\.log\.[0-9]+(\.gz)?' \
       -o -regex '.*/[^/]+\.log-[0-9]{8}(\.gz)?' \))
assert_eq "2" "$archive_removed" "only exact numeric/dateext archives are removed"
assert_file_exists "$TMPDIR/archive-fixture/vm.log.1.keep"
assert_file_exists "$TMPDIR/archive-fixture/vm.log-20260701.keep"
assert_file_exists "$TMPDIR/archive-fixture/vm.log"

# ReadWritePaths sanity — /var/log writable; package-owned prune targets use
# write-if-present where applicable. The exact-path swtpm config and list stay
# in PrivateTmp-backed /tmp and therefore need no persistent state directory.
assert_grep_fixed 'ReadWritePaths=/var/log -/var/log/libvirt -/var/log/tuned -/var/lib/upower' \
    "$KS_M42"
assert_grep_fixed 'mktemp /tmp/noid-swtpm.conf.XXXXXX' "$TMPDIR/misc-prune.sh"
assert_grep_fixed 'mktemp /tmp/noid-swtpm.list.XXXXXX' "$TMPDIR/misc-prune.sh"
assert_not_grep '/var/lib/logrotate' "$TMPDIR/misc-prune.sh" \
    "isolated swtpm rotation leaves no persistent private state"
assert_not_grep 'ReadWritePaths=.*var/lib/aide' "$KS_M42" \
    "retention service has no writable AIDE trust-state path"
assert_grep_fixed 'CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SETGID CAP_SETUID' \
    "$KS_M42" \
    "isolated swtpm rotation has only traversal and su identity capabilities"

# ----------------------------------------------------------------------------
# M42 — 5 service+timer pairs in /etc/systemd/system/
# ----------------------------------------------------------------------------
for unit in noid-install-logs-prune noid-audit-prune noid-misc-logs-prune \
            noid-nm-privacy-prune noid-auditd-rotate; do
    assert_grep_fixed "/etc/systemd/system/${unit}.service" "$KS_M42"
    assert_grep_fixed "/etc/systemd/system/${unit}.timer" "$KS_M42"
done

# Parse the exact ten generated units as one dependency graph and bind the
# root-only creation mask on every privileged service.
m42_unit_specs=(
    INSTALL_LOGS_PRUNE_SERVICE_EOF:noid-install-logs-prune.service
    INSTALL_LOGS_PRUNE_TIMER_EOF:noid-install-logs-prune.timer
    AUDIT_PRUNE_SERVICE_EOF:noid-audit-prune.service
    AUDIT_PRUNE_TIMER_EOF:noid-audit-prune.timer
    MISC_LOGS_PRUNE_SERVICE_EOF:noid-misc-logs-prune.service
    MISC_LOGS_PRUNE_TIMER_EOF:noid-misc-logs-prune.timer
    NM_PRIVACY_PRUNE_SERVICE_EOF:noid-nm-privacy-prune.service
    NM_PRIVACY_PRUNE_TIMER_EOF:noid-nm-privacy-prune.timer
    AUDITD_ROTATE_SERVICE_EOF:noid-auditd-rotate.service
    AUDITD_ROTATE_TIMER_EOF:noid-auditd-rotate.timer
)
mkdir "$TMPDIR/m42-units"
for unit_spec in "${m42_unit_specs[@]}"; do
    unit_marker=${unit_spec%%:*}
    unit_name=${unit_spec#*:}
    extract_heredoc "$KS_M42" "$unit_marker" \
        "$TMPDIR/m42-units/$unit_name" \
        || _fail "$unit_marker extraction"
done
assert_cmd_success "all ten exact M42 units pass systemd-analyze verify" \
    systemd-analyze verify "$TMPDIR/m42-units"/*
for service in "$TMPDIR"/m42-units/*.service; do
    assert_grep_fixed 'UMask=0077' "$service" \
        "$(basename "$service") creates private files by default"
done
extract_heredoc "$KS_M42" "NM_HISTORY_BOUNDARY_DROPIN_EOF" \
    "$TMPDIR/23-noid-history-boundary.conf" \
    || _fail "NetworkManager lifecycle drop-in extraction"
assert_grep_fixed '[Unit]' "$TMPDIR/23-noid-history-boundary.conf"
assert_grep_fixed 'Wants=noid-nm-privacy-prune.service' \
    "$TMPDIR/23-noid-history-boundary.conf"
assert_grep_fixed 'After=noid-nm-privacy-prune.service' \
    "$TMPDIR/23-noid-history-boundary.conf"
assert_grep_fixed 'UMask=0077' "$TMPDIR/23-noid-history-boundary.conf"
extract_heredoc "$KS_M42" "UPOWER_HISTORY_BOUNDARY_DROPIN_EOF" \
    "$TMPDIR/23-noid-upower-history-boundary.conf" \
    || _fail "UPower lifecycle drop-in extraction"
assert_grep_fixed '[Unit]' "$TMPDIR/23-noid-upower-history-boundary.conf"
assert_grep_fixed 'Wants=noid-misc-logs-prune.service' \
    "$TMPDIR/23-noid-upower-history-boundary.conf"
assert_grep_fixed 'After=noid-misc-logs-prune.service' \
    "$TMPDIR/23-noid-upower-history-boundary.conf"

extract_heredoc "$KS_M42" "INSTALL_LOGS_PRUNE_SERVICE_EOF" \
    "$TMPDIR/install-logs-prune.service" \
    || _fail "install-log service extraction"
assert_grep_fixed 'Documentation=man:find(1)' \
    "$TMPDIR/install-logs-prune.service" \
    "install-log service cites its actual pruning mechanism"
assert_not_grep 'tmpfiles.d' "$TMPDIR/install-logs-prune.service" \
    "install-log service has no stale tmpfiles documentation"
assert_grep_fixed 'ReadWritePaths=/var/log /root' \
    "$TMPDIR/install-logs-prune.service" \
    "install-log service explicitly exposes its /root targets"
assert_not_grep '/var/log/anaconda' "$TMPDIR/install-logs-prune.service" \
    "optional Anaconda directory is not a mandatory namespace path"
assert_not_grep '^ProtectHome=' "$TMPDIR/install-logs-prune.service" \
    "install-log service sees the real /root namespace for its exact targets"
assert_grep_fixed 'InaccessiblePaths=/home' \
    "$TMPDIR/install-logs-prune.service" \
    "install-log service cannot read user homes"
assert_not_grep 'noid-plymouth-firstboot' "$KS_M42" \
    "retired Plymouth firstboot log has no dead retention policy"
assert_grep_fixed 'REFUSED non-regular/symlink NetworkManager state file' \
    "$TMPDIR/NM_PRIVACY_PRUNE_EOF.sh" \
    "global NetworkManager state rejects symlinks"
assert_not_grep '^IOSchedulingPriority=7$' "$KS_M42" \
    "idle I/O class has no meaningless priority directive"

# Fedora's maintained auditctl obtains auditd's PID with AUDIT_GET over
# NETLINK_AUDIT before it sends the native rotate signal via pidfd. The service
# therefore needs both capabilities and host audit netlink, but no IP or packet
# family.
auditd_rotate_unit="$TMPDIR/m42-units/noid-auditd-rotate.service"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX AF_NETLINK' \
    "$auditd_rotate_unit" \
    "auditd rotation admits only local IPC and audit netlink families"
assert_grep_fixed 'CapabilityBoundingSet=CAP_AUDIT_CONTROL CAP_KILL' \
    "$auditd_rotate_unit" \
    "auditd rotation retains only audit query and signal capabilities"
assert_not_grep '^NoNewPrivileges=' "$auditd_rotate_unit" \
    "auditd rotation permits Fedora's maintained auditctl_t SELinux transition"
assert_grep_fixed 'NNP blocks that transition with 203/EXEC' \
    "$auditd_rotate_unit" \
    "auditd rotation records why NoNewPrivileges is intentionally omitted"
assert_not_grep '^PrivateNetwork=' "$auditd_rotate_unit" \
    "auditd rotation stays in the host namespace for the host audit plane"
assert_not_grep '^RestrictAddressFamilies=.*AF_INET' "$auditd_rotate_unit" \
    "auditd rotation cannot create IP sockets"
assert_not_grep '^RestrictAddressFamilies=.*AF_PACKET' "$auditd_rotate_unit" \
    "auditd rotation cannot create packet sockets"
assert_grep_fixed 'CapabilityBoundingSet=' "$KS_M42" \
    "M42 declares explicit service capability boundaries"
assert_grep_fixed 'systemd-analyze verify' "$KS_M42" \
    "build verification parses the complete M42 systemd graph"
assert_not_grep 'systemctl daemon-reload.*[|][|][[:space:]]*true' "$KS_M42" \
    "systemd reload failure is not swallowed"
assert_not_grep 'restorecon.*[|][|][[:space:]]*true' "$KS_M42" \
    "SELinux relabel failures are never hidden"
assert_grep_fixed 'timer_target=$(readlink -f -- "$timer_link"' "$KS_M42" \
    "timer enablement resolves the installed target"
assert_grep_fixed '[ "$timer_target" = "/etc/systemd/system/$t" ]' "$KS_M42" \
    "timer enablement requires the exact canonical target"

# ----------------------------------------------------------------------------
# M42 — strict logrotate caps for active logs + wtmp/btmp
# ----------------------------------------------------------------------------
assert_grep_fixed '/etc/logrotate.d/noid-forensic-30day' "$KS_M42"
assert_grep_fixed '/etc/logrotate.d/libvirtd.qemu' "$KS_M42"
assert_grep_fixed '/etc/logrotate.d/aide' "$KS_M42"
assert_grep_fixed '/etc/logrotate.d/wtmp' "$KS_M42"
assert_grep_fixed '/etc/logrotate.d/btmp' "$KS_M42"

for marker in NOID_FORENSIC_LOGROTATE_EOF LIBVIRTD_QEMU_LOGROTATE_EOF \
              AIDE_LOGROTATE_EOF \
              WTMP_LOGROTATE_EOF BTMP_LOGROTATE_EOF; do
    target="$TMPDIR/${marker}.conf"
    extract_heredoc "$KS_M42" "$marker" "$target" \
        || _fail "$marker heredoc extraction"
    assert_grep_extended '^[[:space:]]*daily$' "$target"
    assert_grep_extended '^[[:space:]]*rotate[[:space:]]+30$' "$target"
    assert_grep_extended '^[[:space:]]*maxage[[:space:]]+30$' "$target"
done
assert_not_grep '^[[:space:]]*minsize' "$TMPDIR/WTMP_LOGROTATE_EOF.conf" \
    "wtmp has no low-volume minsize retention bypass"
assert_grep_fixed '/var/log/libvirt/qemu/*.log {' \
    "$TMPDIR/LIBVIRTD_QEMU_LOGROTATE_EOF.conf" \
    "libvirt active logs retain their package-owned stanza"
assert_not_grep '/var/log/swtpm/' \
    "$TMPDIR/LIBVIRTD_QEMU_LOGROTATE_EOF.conf" \
    "global logrotate never traverses VM-MCS-protected swtpm basenames"
assert_grep_fixed '*:svirt_image_t:*)' "$TMPDIR/misc-prune.sh" \
    "active swtpm logs are recognized as SELinux-protected"
assert_grep_fixed '*:virt_log_t:*)' "$TMPDIR/misc-prune.sh" \
    "libvirt-restored swtpm logs are rotation-eligible"
assert_grep_fixed '*:var_log_t:*)' "$TMPDIR/misc-prune.sh" \
    "Fedora-default removed-domain swtpm logs are recognized"
assert_grep_fixed '"$SWTPM_TSS_UID:$SWTPM_TSS_GID:644:1")' \
    "$TMPDIR/misc-prune.sh" \
    "default-label swtpm scope requires exact tss ownership and safe metadata"
assert_grep_fixed 'REFUSED unsafe default-label swtpm log #' \
    "$TMPDIR/misc-prune.sh" \
    "unexpected default-label metadata remains fail-closed"
assert_grep_fixed '/usr/sbin/logrotate --force --state /dev/null' \
    "$TMPDIR/misc-prune.sh" \
    "closed swtpm rotation stores no persistent domain-name state"
assert_grep_fixed 'trap cleanup_swtpm_tmp EXIT' "$TMPDIR/misc-prune.sh" \
    "ephemeral swtpm config is removed on every exit path"
assert_grep_fixed 'su tss tss' "$TMPDIR/misc-prune.sh" \
    "isolated swtpm rotation retains native ownership"
assert_grep_fixed 'PROTECTED active-VM swtpm log #' \
    "$TMPDIR/misc-prune.sh" \
    "active swtpm deferral is visible rather than silently skipped"
assert_grep_fixed '/var/log/swtpm/libvirt/qemu' "$TMPDIR/misc-prune.sh" \
    "swtpm rotated archives share the VM trace prune boundary"
assert_cmd_success "global libvirt logrotate stanza parses without swtpm" \
    logrotate --debug --state /dev/null \
        "$TMPDIR/LIBVIRTD_QEMU_LOGROTATE_EOF.conf"

# Exercise the exact-path quoting contract with whitespace, quotes and a
# backslash. This binds the generated config grammar without touching host logs.
sed -n '/^quote_logrotate_path() {$/,/^}$/p' "$TMPDIR/misc-prune.sh" \
    > "$TMPDIR/quote-logrotate-path.sh"
assert_cmd_success "extracted logrotate quoting function is valid bash" \
    bash -n "$TMPDIR/quote-logrotate-path.sh"
# Generated function extracted from the audited heredoc.
# shellcheck disable=SC1090
. "$TMPDIR/quote-logrotate-path.sh"
swtpm_quote_fixture="$TMPDIR/swtpm quote-\"guest\"-\\path.log"
: > "$swtpm_quote_fixture"
{
    quote_logrotate_path "$swtpm_quote_fixture"
    printf ' {\n'
    printf '    su %s %s\n' "$(id -un)" "$(id -gn)"
    printf '%s\n' '    daily' '    rotate 30' '    maxage 30' '    missingok' \
        '    notifempty' '    dateext' '    dateformat -%Y%m%d' \
        '    copytruncate' '}'
} > "$TMPDIR/swtpm-quoted.conf"
assert_cmd_success "generated exact-path swtpm logrotate config parses" \
    logrotate --debug --state /dev/null "$TMPDIR/swtpm-quoted.conf"
assert_not_grep '/var/log/libvirt/qemu/' \
    "$TMPDIR/NOID_FORENSIC_LOGROTATE_EOF.conf" \
    "libvirt glob is not duplicated across logrotate stanzas"
assert_grep_fixed '/var/log/aide/aide.log {' "$TMPDIR/AIDE_LOGROTATE_EOF.conf" \
    "only the active shared AIDE log is rotated"
assert_cmd_failure \
    "AIDE per-run reports keep original mtimes for age pruning" \
    grep -Fq -- '/var/log/aide/*.log' \
        "$TMPDIR/AIDE_LOGROTATE_EOF.conf"

# The health result must rebind every final payload to the digest captured from
# its private publication candidate, not merely count scripts and timers.
assert_grep_fixed '# M42_PAYLOAD_INVENTORY_BEGIN' "$KS_M42" \
    "M42 declares an exact final-payload inventory"
sed -n \
    '/^# M42_PAYLOAD_INVENTORY_BEGIN$/,/^# M42_PAYLOAD_INVENTORY_END$/p' \
    "$KS_M42" > "$TMPDIR/m42-payload-inventory.sh"
# Generated declaration extracted from the audited source.
# shellcheck disable=SC1090
. "$TMPDIR/m42-payload-inventory.sh"
assert_eq 22 "${#M42_EXPECTED_PAYLOAD_PATHS[@]}" \
    "M42 final-payload inventory contains all 22 publications"
expected_m42_payload_paths=(
    /usr/local/bin/noid-install-logs-prune.sh
    /usr/local/bin/noid-audit-prune.sh
    /usr/local/bin/noid-misc-logs-prune.sh
    /usr/local/bin/noid-nm-privacy-prune.sh
    /usr/local/bin/noid-auditd-rotate.sh
    /etc/systemd/system/noid-install-logs-prune.service
    /etc/systemd/system/noid-install-logs-prune.timer
    /etc/systemd/system/noid-audit-prune.service
    /etc/systemd/system/noid-audit-prune.timer
    /etc/systemd/system/noid-misc-logs-prune.service
    /etc/systemd/system/noid-misc-logs-prune.timer
    /etc/systemd/system/noid-nm-privacy-prune.service
    /etc/systemd/system/noid-nm-privacy-prune.timer
    /etc/systemd/system/NetworkManager.service.d/23-noid-history-boundary.conf
    /etc/systemd/system/upower.service.d/23-noid-history-boundary.conf
    /etc/systemd/system/noid-auditd-rotate.service
    /etc/systemd/system/noid-auditd-rotate.timer
    /etc/logrotate.d/noid-forensic-30day
    /etc/logrotate.d/libvirtd.qemu
    /etc/logrotate.d/aide
    /etc/logrotate.d/wtmp
    /etc/logrotate.d/btmp
)
assert_eq "$(printf '%s\n' "${expected_m42_payload_paths[@]}")" \
    "$(printf '%s\n' "${M42_EXPECTED_PAYLOAD_PATHS[@]}")" \
    "M42 candidate-bound inventory has the exact payload order"
mapfile -t staged_m42_payload_paths < <(awk '
    /^stage_root_file[[:space:]]/ {
        line = $0
        sub(/^stage_root_file[[:space:]]+/, "", line)
        if (line == "\\") {
            getline line
            sub(/^[[:space:]]+/, "", line)
        }
        split(line, fields, /[[:space:]]+/)
        print fields[1]
    }
' "$KS_M42")
assert_eq "$(printf '%s\n' "${M42_EXPECTED_PAYLOAD_PATHS[@]}")" \
    "$(printf '%s\n' "${staged_m42_payload_paths[@]}")" \
    "M42 candidate-bound inventory follows the actual publication order"
assert_eq 22 \
    "$(printf '%s\n' "${M42_EXPECTED_PAYLOAD_PATHS[@]}" | sort -u | wc -l)" \
    "M42 candidate-bound inventory contains no duplicate path"
assert_grep_fixed 'M42_PUBLISHED_PATHS+=("$destination")' "$KS_M42" \
    "M42 records each successfully published final path"
assert_grep_fixed 'M42_PUBLISHED_SHA256+=("$source_sha")' "$KS_M42" \
    "M42 records each publication-candidate digest"

sed -n \
    '/^# M42_FINAL_PAYLOAD_BINDING_FUNCTION_BEGIN$/,/^# M42_FINAL_PAYLOAD_BINDING_FUNCTION_END$/p' \
    "$KS_M42" > "$TMPDIR/m42-payload-binding.sh"
assert_cmd_success "M42 final-payload binding function is valid bash" \
    bash -n "$TMPDIR/m42-payload-binding.sh"
# Generated function extracted from the audited source.
# shellcheck disable=SC1090
. "$TMPDIR/m42-payload-binding.sh"
binding_one="$TMPDIR/m42-binding-one"
binding_two="$TMPDIR/m42-binding-two"
printf '%s\n' first > "$binding_one"
printf '%s\n' second > "$binding_two"
binding_one_sha=$(sha256sum "$binding_one" | awk '{print $1}')
binding_two_sha=$(sha256sum "$binding_two" | awk '{print $1}')
M42_EXPECTED_PAYLOAD_PATHS=("$binding_one" "$binding_two")
M42_PUBLISHED_PATHS=("$binding_one" "$binding_two")
M42_PUBLISHED_SHA256=("$binding_one_sha" "$binding_two_sha")
# The production inventory has 22 entries; repeat these two controlled paths
# to exercise the same exact count without requiring privileged host targets.
for fixture_index in $(seq 2 21); do
    : "$fixture_index"
    M42_EXPECTED_PAYLOAD_PATHS+=("$binding_two")
    M42_PUBLISHED_PATHS+=("$binding_two")
    M42_PUBLISHED_SHA256+=("$binding_two_sha")
done
assert_cmd_success "exact final payload bytes/order pass the binding gate" \
    verify_m42_payload_binding
assert_eq 22 "$PAYLOADS_BOUND" \
    "payload binding reports the exact publication count"
assert_cmd_success "payload binding emits one SHA-256 manifest digest" \
    bash -c '[[ "$1" =~ ^[0-9a-f]{64}$ ]]' _ \
        "$PAYLOAD_MANIFEST_SHA256"
printf '%s\n' tampered > "$binding_one"
assert_cmd_failure "changed final payload bytes fail the binding gate" \
    verify_m42_payload_binding
printf '%s\n' first > "$binding_one"
M42_PUBLISHED_PATHS[0]=$binding_two
assert_cmd_failure "changed final payload order fails the binding gate" \
    verify_m42_payload_binding
M42_PUBLISHED_PATHS[0]=$binding_one
unset 'M42_PUBLISHED_SHA256[21]'
assert_cmd_failure "missing publication evidence fails the binding gate" \
    verify_m42_payload_binding

# ----------------------------------------------------------------------------
# M42 — health stamp identity and measured inventory extensions
# ----------------------------------------------------------------------------
assert_grep_fixed 'M42_STATE_DIR=/var/lib/noid-privacy' "$KS_M42" \
    "M42 binds health evidence to the canonical shared state directory"
assert_grep_fixed 'STAMP="$M42_STATE_DIR/stamp-42-forensic-retention.ok"' \
    "$KS_M42" "M42 uses the canonical health-stamp filename"
assert_grep_fixed 'module=42' "$KS_M42"
assert_grep_fixed 'name=forensic-retention' "$KS_M42"
assert_grep_fixed 'timers_enabled=$timers_enabled' "$KS_M42" \
    "stamp records the measured enabled-timer count"
assert_grep_fixed 'scripts_installed=$scripts_installed' "$KS_M42" \
    "stamp records the measured installed-script count"
assert_not_grep '^timers_enabled=5$' "$KS_M42" \
    "stamp contains no fixed enabled-timer count"
assert_not_grep '^scripts_installed=5$' "$KS_M42" \
    "stamp contains no fixed installed-script count"
assert_grep_fixed 'timers_enabled=$((timers_enabled + 1))' "$KS_M42" \
    "enabled-timer count advances only after exact target verification"
assert_grep_fixed 'scripts_installed=$((scripts_installed + 1))' "$KS_M42" \
    "installed-script count advances only after metadata verification"
assert_grep_fixed 'STAMP_CANDIDATE=$(mktemp' "$KS_M42" \
    "health stamp is staged before publication"
assert_grep_fixed 'publish_root_file "$STAMP_CANDIDATE" "$STAMP" 0644' \
    "$KS_M42" "health stamp uses the shared durable atomic publisher"
assert_grep_fixed 'prior Module 42 health stamp is absent' "$KS_M42" \
    "old M42 success evidence is retired before payload mutation"
assert_grep_fixed 'cleanup_m42_build_candidates()' "$KS_M42" \
    "all incomplete M42 publications share an exit cleanup"
assert_grep_fixed 'trap cleanup_m42_build_candidates EXIT' "$KS_M42" \
    "production M42 installs its build-candidate EXIT cleanup"
assert_grep_fixed "trap 'exit 143' TERM" "$KS_M42" \
    "production M42 routes TERM through the exact EXIT cleanup"
assert_grep_fixed 'verify_m42_health_stamp()' "$KS_M42" \
    "staged and final M42 evidence share one exact validator"
assert_grep_fixed 'matchpathcon -V "$STAMP_CANDIDATE"' "$KS_M42" \
    "M42 validates the staged stamp SELinux context"
assert_grep_fixed 'matchpathcon -V "$STAMP"' "$KS_M42" \
    "M42 validates the final stamp SELinux context"
assert_grep_fixed 'STAMP_PUBLISHED=1' "$KS_M42" \
    "M42 marks the final stamp removable until all postconditions pass"
assert_grep_fixed 'version=7' "$KS_M42" \
    "health stamp schema/version advances with the strengthened contract"
assert_grep_fixed 'payloads_bound=$PAYLOADS_BOUND' "$KS_M42" \
    "health stamp records the exact final-payload count"
assert_grep_fixed 'payload_manifest_sha256=$PAYLOAD_MANIFEST_SHA256' "$KS_M42" \
    "health stamp records the final candidate-bound manifest"
assert_not_grep_extended 'thirteenth current adopter|twelfth adopter' "$KS_M42" \
    "health-stamp comments contain no drifting adopter ordinal"

m42_invalidate_line=$(grep -nF \
    '# M42_HEALTH_INVALIDATION_BEGIN' "$KS_M42" | cut -d: -f1)
m42_first_payload_line=$(grep -nF \
    'stage_root_file /usr/local/bin/noid-install-logs-prune.sh 0755' \
    "$KS_M42" | cut -d: -f1)
m42_publish_line=$(grep -nF \
    'written atomically with exact metadata and context' \
    "$KS_M42" | cut -d: -f1)
m42_complete_line=$(grep -nF \
    'log "=== Module 42 forensic-retention complete ==="' \
    "$KS_M42" | cut -d: -f1)
if [ -n "$m42_invalidate_line" ] && [ -n "$m42_first_payload_line" ] \
   && [ -n "$m42_publish_line" ] && [ -n "$m42_complete_line" ] \
   && [ "$m42_invalidate_line" -lt "$m42_first_payload_line" ] \
   && [ "$m42_publish_line" -lt "$m42_complete_line" ]; then
    _pass "M42 retires old health before mutation and completes after publication"
else
    _fail "M42 retires old health before mutation and completes after publication"
fi

# Execute both exact production health-boundary blocks against disposable
# state. Candidate/final label and rename faults must all remain stamp-less.
m42_stamp_root="$EXEC_TMPDIR/health-stamp"
m42_stamp_state="$m42_stamp_root/state"
m42_stamp_bin="$m42_stamp_root/bin"
m42_stamp_invalidate="$m42_stamp_root/invalidate.sh"
m42_stamp_publish="$m42_stamp_root/publish.sh"
m42_stamp_uid=$(id -u)
m42_stamp_gid=$(id -g)
mkdir -p "$m42_stamp_bin"

cat > "$m42_stamp_bin/restorecon" <<'M42_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-42-forensic-retention.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M42_STAMP_RESTORECON_EOF
cat > "$m42_stamp_bin/matchpathcon" <<'M42_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M42_STAMP_MATCHPATHCON_EOF
cat > "$m42_stamp_bin/mv" <<'M42_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M42_STAMP_MV_EOF
chmod 0700 "$m42_stamp_bin/restorecon" \
    "$m42_stamp_bin/matchpathcon" "$m42_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }'
    sed -n \
        '/^# M42_HEALTH_INVALIDATION_BEGIN$/,/^# M42_HEALTH_INVALIDATION_END$/p' \
        "$KS_M42" |
        sed -e "s|/var/lib/noid-privacy|$m42_stamp_state|g" \
            -e "s/-o root -g root/-o $m42_stamp_uid -g $m42_stamp_gid/" \
            -e "s/0:0:755/$m42_stamp_uid:$m42_stamp_gid:755/"
} > "$m42_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' 'fail() { exit 1; }' \
        "M42_STATE_DIR=$m42_stamp_state" \
        'STAMP="$M42_STATE_DIR/stamp-42-forensic-retention.ok"' \
        'ROOT_PUBLICATION_TMP=""' 'M42_SOURCE_TMP=""' \
        'STAMP_CANDIDATE=""' 'STAMP_PUBLISHED=0' \
        'checks_total=46' 'verify_fail=0' \
        'timers_enabled=5' 'scripts_installed=5' \
        'PAYLOADS_BOUND=22' \
        'PAYLOAD_MANIFEST_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    sed -n \
        '/^# M42_ROOT_PUBLICATION_BEGIN$/,/^# M42_ROOT_PUBLICATION_END$/p' \
        "$KS_M42" |
        sed -e "s|/usr/sbin/restorecon|$m42_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m42_stamp_bin/matchpathcon|g" \
            -e "s/-o root -g root/-o $m42_stamp_uid -g $m42_stamp_gid/g" \
            -e "s/0:0:/$m42_stamp_uid:$m42_stamp_gid:/g"
    sed -n \
        '/^# M42_BUILD_CLEANUP_BEGIN$/,/^# M42_BUILD_CLEANUP_END$/p' \
        "$KS_M42"
    sed -n \
        '/^# M42_HEALTH_PUBLICATION_BEGIN$/,/^# M42_HEALTH_PUBLICATION_END$/p' \
        "$KS_M42" |
        sed -e "s/chown root:root/chown $m42_stamp_uid:$m42_stamp_gid/" \
            -e "s/0:0:755/$m42_stamp_uid:$m42_stamp_gid:755/" \
            -e "s/0:0:644:1/$m42_stamp_uid:$m42_stamp_gid:644:1/" \
            -e "s|/usr/sbin/restorecon|$m42_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m42_stamp_bin/matchpathcon|g"
} > "$m42_stamp_publish"
chmod 0700 "$m42_stamp_invalidate" "$m42_stamp_publish"

mkdir -m 0755 "$m42_stamp_state"
printf '%s\n' 'module=42' 'name=forensic-retention' 'status=ok' \
    > "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_cmd_success "M42 rerun invalidates its prior build-success stamp" \
    env PATH="$m42_stamp_bin:$PATH" "$m42_stamp_invalidate"
if [ ! -e "$m42_stamp_state/stamp-42-forensic-retention.ok" ]; then
    _pass "M42 old success evidence is absent before retention publication"
else
    _fail "M42 old success evidence is absent before retention publication"
fi

chmod 0777 "$m42_stamp_state"
printf '%s\n' 'must-survive' \
    > "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_cmd_failure "M42 rejects shared state-directory metadata drift" \
    env PATH="$m42_stamp_bin:$PATH" "$m42_stamp_invalidate"
assert_eq "$m42_stamp_uid:$m42_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m42_stamp_state")" \
    "M42 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok" \
    "M42 does not touch evidence through a drifted state boundary"
rm "$m42_stamp_state/stamp-42-forensic-retention.ok"
chmod 0755 "$m42_stamp_state"

assert_cmd_failure "M42 rejects a health-stamp candidate label failure" \
    env PATH="$m42_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        "$m42_stamp_publish"
if [ ! -e "$m42_stamp_state/stamp-42-forensic-retention.ok" ] \
   && [ -z "$(find "$m42_stamp_state" -maxdepth 1 \
        -name '.stamp-42-forensic-retention.*' -print -quit)" ]; then
    _pass "M42 candidate-label failure leaves no plausible health evidence"
else
    _fail "M42 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M42 retires a stamp after final-label failure" \
    env PATH="$m42_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        "$m42_stamp_publish"
if [ ! -e "$m42_stamp_state/stamp-42-forensic-retention.ok" ]; then
    _pass "M42 final-label failure removes the published success stamp"
else
    _fail "M42 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M42 rejects an atomic health-stamp rename failure" \
    env PATH="$m42_stamp_bin:$PATH" FAKE_MV_FAIL=1 "$m42_stamp_publish"
if [ ! -e "$m42_stamp_state/stamp-42-forensic-retention.ok" ] \
   && [ -z "$(find "$m42_stamp_state" -maxdepth 1 \
        -name '.stamp-42-forensic-retention.*' -print -quit)" ]; then
    _pass "M42 rename failure leaves no stamp or staged candidate"
else
    _fail "M42 rename failure leaves no stamp or staged candidate"
fi

# A pre-existing symlink at the final path must be replaced, never followed.
printf '%s\n' 'must-not-be-overwritten' > "$m42_stamp_root/symlink-victim"
ln -s "$m42_stamp_root/symlink-victim" \
    "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_cmd_success "M42 replaces rather than follows a final-path symlink" \
    env PATH="$m42_stamp_bin:$PATH" "$m42_stamp_publish"
assert_cmd_success "M42 health publication ends as a regular non-symlink" \
    bash -c '[ -f "$1" ] && [ ! -L "$1" ]' _ \
        "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_grep_fixed 'must-not-be-overwritten' "$m42_stamp_root/symlink-victim" \
    "M42 publisher leaves a symlink target untouched"
assert_grep_fixed '# NoID Privacy — Module 42 Health Stamp' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok" \
    "M42 health stamp identifies its module"
assert_grep_fixed \
    '# Written at end of %post verification when all checks pass.' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok" \
    "M42 health stamp records its success boundary"
assert_grep_fixed \
    '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok" \
    "M42 health stamp identifies its canonical schema"
assert_grep_fixed 'module=42' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_grep_fixed 'name=forensic-retention' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_grep_fixed 'checks_passed=46' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_grep_fixed 'timers_enabled=5' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_grep_fixed 'scripts_installed=5' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_grep_fixed 'payloads_bound=22' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_grep_fixed \
    'payload_manifest_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    "$m42_stamp_state/stamp-42-forensic-retention.ok"
assert_eq 14 \
    "$(wc -l < "$m42_stamp_state/stamp-42-forensic-retention.ok")" \
    "M42 published health stamp has the exact fourteen-line schema"

# ----------------------------------------------------------------------------
# M99 — EXPECTED_STAMPS extended to include M42
# ----------------------------------------------------------------------------
assert_file_exists "$KS_M99"
assert_grep_fixed '"42:forensic-retention"' "$KS_M99" \
    "M99 exact health-stamp map includes M42"
for retention_exclude in \
    '!/var/log/ks-10-authselect\.err$' \
    '!/var/log/noid-anaconda-kernel-cmdline\.log$' \
    '!/var/log/noid-firstboot-setup\.log$' \
    '!/var/log/noid-crypto-policy\.err$' \
    '!/var/log/swtpm/libvirt/qemu(/.*)?$'; do
    assert_grep_fixed "$retention_exclude" "$KS_M13" \
        "M13 AIDE excludes exact retained trace: $retention_exclude"
    assert_grep_fixed "$retention_exclude" "$KS_M99" \
        "M99 gates exact retained trace: $retention_exclude"
done

# ----------------------------------------------------------------------------
# master.ks — %include for M42 between M41 (one-shot cleanup) and M99 (finalize)
# ----------------------------------------------------------------------------
assert_file_exists "$KS_MASTER"
assert_grep_fixed '%include snippets/42-forensic-retention.ks' "$KS_MASTER"

# Ordering: M42 must come AFTER 41-anaconda-cleanup + BEFORE 99-finalize.
m41_line=$(grep -n '%include snippets/41-anaconda-cleanup.ks' "$KS_MASTER" | head -1 | cut -d: -f1)
m42_line=$(grep -n '%include snippets/42-forensic-retention.ks' "$KS_MASTER" | head -1 | cut -d: -f1)
m99_line=$(grep -n '%include snippets/99-finalize.ks' "$KS_MASTER" | head -1 | cut -d: -f1)
m41_line=${m41_line:-0}
m42_line=${m42_line:-0}
m99_line=${m99_line:-0}
assert_cmd_success "M42 include ordering (M41=$m41_line < M42=$m42_line < M99=$m99_line)" \
    test "$m41_line" -lt "$m42_line" -a "$m42_line" -lt "$m99_line"

# ----------------------------------------------------------------------------
# M20 — logrotate.d/snapper cap + NUMBER_LIMIT bumps + noid-snapper-prune
# ----------------------------------------------------------------------------
assert_file_exists "$KS_M20"
assert_cmd_success "bash -n $KS_M20" bash -n "$KS_M20"

# sed-edit caps logrotate.d/snapper to maxage 30 + rotate 30
assert_grep_fixed '/etc/logrotate.d/snapper' "$KS_M20"
assert_grep_extended 'maxage 30|rotate 30' "$KS_M20"

# NUMBER_LIMIT 5 -> 50, NUMBER_LIMIT_IMPORTANT 3 -> 5
assert_grep_fixed 'NUMBER_LIMIT="50"' "$KS_M20"
assert_grep_fixed 'NUMBER_LIMIT_IMPORTANT="5"' "$KS_M20"
# Sanity: the old NUMBER_LIMIT="5" must NOT survive in the heredoc (regression-
# guard against accidental revert)
assert_not_grep '^NUMBER_LIMIT="5"$' "$KS_M20"

# part 2 — noid-snapper-prune.sh + service + timer
assert_grep_fixed '/usr/local/sbin/noid-snapper-prune.sh' "$KS_M20"
assert_grep_fixed '/etc/systemd/system/noid-snapper-prune.service' "$KS_M20"
assert_grep_fixed '/etc/systemd/system/noid-snapper-prune.timer' "$KS_M20"
# Time-based snapshot prune logic — no important/baseline bypass; authoritative
# JSON identity/date/default/active state and explicit root config.
assert_grep_fixed 'row.get("default")' "$KS_M20"
assert_grep_fixed 'row.get("active")' "$KS_M20"
assert_grep_fixed '"$SNAPPER" -c root delete --sync' "$KS_M20" \
    "snapshot prune uses the injectable, tested Snapper binary"
extract_heredoc "$KS_M20" "SNAPPER_PRUNE_EOF" "$TMPDIR/snapper-prune.sh" \
    || _fail "snapper prune heredoc extraction"
assert_not_grep 'SKIPPED_IMPORTANT' "$TMPDIR/snapper-prune.sh" \
    "M20 has no indefinite important snapshot exception"
assert_not_grep '^[^#].*important.*yes' "$TMPDIR/snapper-prune.sh" \
    "M20 does not branch around important=yes snapshots"
assert_grep_fixed 'state=protected' "$TMPDIR/snapper-prune.sh" \
    "M20 reports active/default retention exceptions"
assert_grep_fixed 'clock-guard' "$TMPDIR/snapper-prune.sh" \
    "M20 defers destructive expiry across clock discontinuities"

# ----------------------------------------------------------------------------
# M13 — aide-check wrapper + drop-in
# ----------------------------------------------------------------------------
assert_file_exists "$KS_M13"
assert_cmd_success "bash -n $KS_M13" bash -n "$KS_M13"

assert_grep_fixed '/usr/local/sbin/noid-aide-check.sh' "$KS_M13"
assert_grep_fixed '/etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf' "$KS_M13"
# Drop-in must reset parent's ExecStart= (empty assignment) then point at wrapper.
assert_grep_extended '^ExecStart=$' "$KS_M13"
assert_grep_fixed 'ExecStart=/usr/local/sbin/noid-aide-check.sh' "$KS_M13"
# Wrapper script implements (per-run TS report + flock)
assert_grep_fixed "aide-check-" "$KS_M13"
assert_grep_fixed '/var/lock/noid-aide.lock' "$KS_M13"
assert_grep_fixed 'flock -w 3600' "$KS_M13"

# ----------------------------------------------------------------------------
# M13 — explicit user-owned baseline review
# ----------------------------------------------------------------------------
assert_grep_fixed '/usr/local/sbin/noid-aide-baseline-review' "$KS_M13"
assert_grep_fixed 'ACCEPT AIDE BASELINE $hash' "$KS_M13"
assert_grep_fixed 'candidate_sha256=' "$KS_M13"
assert_not_grep "cat > /etc/systemd/system/noid-aide-firstboot-rebaseline.service" "$KS_M13"
assert_not_grep 'systemctl enable noid-aide-firstboot-rebaseline.timer' "$KS_M13"

# ----------------------------------------------------------------------------
# M25 — check-only update evidence
# ----------------------------------------------------------------------------
assert_file_exists "$KS_M25"
assert_cmd_success "bash -n $KS_M25" bash -n "$KS_M25"
assert_grep_fixed 'sudo /usr/local/sbin/noid-aide-check.sh' "$KS_M25"
assert_grep_fixed 'the updater did NOT absorb the drift' "$KS_M25"
assert_not_grep 'aide --update' "$KS_M25"
assert_not_grep 'mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz' "$KS_M25"
assert_not_grep 'systemd-run --quiet --unit=noid-aide-rebaseline' "$KS_M25"

test_finish

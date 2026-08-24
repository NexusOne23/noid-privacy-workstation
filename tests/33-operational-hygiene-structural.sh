#!/bin/bash
# 33-operational-hygiene-structural — Module 33 regression test
#
# M33 ships 3 user docs + 2 CLI tools via heredocs inside its %post.
# This test extracts each heredoc and asserts:
#   - File is non-empty + above minimum size
#   - Structural markers are present (prevents silent truncation)
#   - CLI scripts pass bash -n after extraction
#   - CLI scripts have required function + flag coverage
#   - Module ships stamp file + no services/timers/autostart (user-invoked only)
#   - %packages is empty (doc + CLI only)

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/33-operational-hygiene.ks"

test_start "33-operational-hygiene-structural"

if [ ! -f "$KS_FILE" ]; then
    _fail "M33 snippet missing: $KS_FILE"
    test_finish
    exit 1
fi

assert_cmd_success "M33 snippet passes bash -n" bash -n "$KS_FILE"

TMPDIR="$(mktemp -d)"
# Fake SELinux/publication commands must execute on the hardened development
# host, whose /tmp is noexec.
EXEC_FIXTURE_DIR="$(mktemp -d "$PROJECT_ROOT/.test-m33-fixture.XXXXXX")"
trap 'rm -rf "$TMPDIR" "$EXEC_FIXTURE_DIR"' EXIT

# --- extract docs -----------------------------------------------------------

extract_heredoc "$KS_FILE" "OAUTH_EOF"    "$TMPDIR/33-oauth-audit-checklist.md"    || true
extract_heredoc "$KS_FILE" "FFPROFILE_EOF" "$TMPDIR/33-firefox-profile-isolation.md" || true
extract_heredoc "$KS_FILE" "ICGUIDE_EOF"   "$TMPDIR/33-integrity-check-guide.md"     || true

assert_file_min_size "$TMPDIR/33-oauth-audit-checklist.md"     4096 "oauth-audit-checklist > 4KB"
assert_file_min_size "$TMPDIR/33-firefox-profile-isolation.md" 4096 "firefox-profile-isolation > 4KB"
assert_file_min_size "$TMPDIR/33-integrity-check-guide.md"     3072 "integrity-check-guide > 3KB"
assert_grep_fixed 'system/VPN DNS by default' \
    "$TMPDIR/33-firefox-profile-isolation.md" \
    "isolated profiles inherit the current resolver contract"
assert_not_grep 'DoH Quad9' "$TMPDIR/33-firefox-profile-isolation.md" \
    "isolated-profile docs do not resurrect forced Firefox DoH"

# --- oauth-audit-checklist.md structural markers ----------------------------

assert_grep_fixed "External Account Access Audit"          "$TMPDIR/33-oauth-audit-checklist.md"
assert_grep_fixed "myaccount.google.com/connections"       "$TMPDIR/33-oauth-audit-checklist.md" "current Google connections URL"
assert_grep_fixed "github.com/settings/applications"      "$TMPDIR/33-oauth-audit-checklist.md" "GitHub URL"
assert_grep_fixed "account.proton.me"                     "$TMPDIR/33-oauth-audit-checklist.md" "Proton URL"
assert_grep_fixed "account.microsoft.com"                 "$TMPDIR/33-oauth-audit-checklist.md" "Microsoft URL"
assert_grep_fixed "RFC 9700"                              "$TMPDIR/33-oauth-audit-checklist.md" "current OAuth BCP"
assert_grep_fixed "monthly is a NoID Privacy recommendation" \
    "$TMPDIR/33-oauth-audit-checklist.md" "cadence is accurately scoped"
assert_grep_fixed "platform.claude.com/settings/keys"     "$TMPDIR/33-oauth-audit-checklist.md" "current Anthropic key route"
assert_grep_fixed "platform.openai.com/settings/organization/api-keys" \
    "$TMPDIR/33-oauth-audit-checklist.md" "current OpenAI organization-key route"
assert_grep_fixed "developers.openai.com/api/reference/overview#authentication" \
    "$TMPDIR/33-oauth-audit-checklist.md" "OpenAI authentication primary reference"
assert_not_grep 'GPT actions' "$TMPDIR/33-oauth-audit-checklist.md" \
    "OpenAI credential guidance does not conflate unrelated product controls"
assert_not_grep 'myaccount\.google\.com/permissions'      "$TMPDIR/33-oauth-audit-checklist.md" "retired Google route absent"
assert_grep_fixed 'it is inaccurate' "$TMPDIR/33-oauth-audit-checklist.md" \
    "OAuth document explicitly rejects universal token claims"
assert_not_grep_extended 'SentinelOne|ShinyHunters'       "$TMPDIR/33-oauth-audit-checklist.md" "vendor campaign claims are not load-bearing"

# --- firefox-profile-isolation.md structural markers ------------------------

assert_grep_fixed "Firefox Profile Isolation"              "$TMPDIR/33-firefox-profile-isolation.md"
assert_grep_fixed "noid-firefox-create-isolated-profile"   "$TMPDIR/33-firefox-profile-isolation.md" "CLI reference"
assert_grep_fixed "firefox -P"                             "$TMPDIR/33-firefox-profile-isolation.md" "launch command"
assert_grep_fixed "--new-instance"                         "$TMPDIR/33-firefox-profile-isolation.md" "current instance flag"
assert_grep_fixed "banking"                                "$TMPDIR/33-firefox-profile-isolation.md" "use case"
assert_grep_fixed "Multi-Account Containers"               "$TMPDIR/33-firefox-profile-isolation.md" "contrast with containers"
assert_grep_fixed "profiles.ini"                           "$TMPDIR/33-firefox-profile-isolation.md" "Firefox profile config"
assert_grep_fixed "browser-data separation, not an OS sandbox" \
    "$TMPDIR/33-firefox-profile-isolation.md" "profile security boundary is explicit"
assert_not_grep_extended 'Katz Stealer|CVE-2026-6770|-no-remote' \
    "$TMPDIR/33-firefox-profile-isolation.md" "obsolete threat and launcher claims absent"

# --- integrity-check-guide.md structural markers ----------------------------

assert_grep_fixed "noid-integrity-check"                   "$TMPDIR/33-integrity-check-guide.md"
assert_grep_fixed "rpm -Va"                                "$TMPDIR/33-integrity-check-guide.md"
assert_grep_fixed "systemd timers"                         "$TMPDIR/33-integrity-check-guide.md"
assert_grep_fixed "external-account access review"        "$TMPDIR/33-integrity-check-guide.md"
assert_grep_fixed "False positives"                        "$TMPDIR/33-integrity-check-guide.md"
assert_grep_fixed "Module 33"                             "$TMPDIR/33-integrity-check-guide.md"
assert_grep_fixed 'rpm -Va --nodeps' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "RPM guide scopes the section to package-file verification"
assert_grep_fixed 'Cronie is not installed by default on NoID Privacy' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "cron guidance describes the stock package posture"
assert_grep_fixed 'one expected yellow incomplete-evidence item' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "non-root cron limitation is explicit"
assert_grep_fixed 'snapper-cleanup.timer.d/99-noid-frequency.conf' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "expected Snapper timer override yellow is documented"
assert_grep_fixed '`generator output`' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "timer guide documents runtime generator output classification"
assert_grep_fixed '`NoID Privacy mask`' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "timer guide documents exact NoID Privacy-owned mask classification"
assert_grep_fixed 'root-owned symlink still points directly to `/dev/null`' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "timer guide states the fail-closed NoID Privacy mask boundary"
assert_not_grep 'rpm-verify-allowlist\.sha256' \
    "$TMPDIR/33-integrity-check-guide.md" "obsolete RPM override manifest is absent"
assert_grep_fixed "admin override" "$TMPDIR/33-integrity-check-guide.md" \
    "timer drop-in classification documented"
assert_grep_fixed 'systemd-tmpfiles policy' "$TMPDIR/33-integrity-check-guide.md" \
    "SUID guidance names the native M10 owner"
assert_grep_fixed '/boot/System.map-<version>' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "RPM guidance names the protected /boot System.map"
assert_grep_fixed '/usr/lib/modules/<version>/System.map' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "RPM guidance names the protected module-tree System.map"
assert_grep_fixed 'required by the native' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "RPM guidance preserves the generated-kmod target-kernel contract"
assert_grep_fixed 'investigate a missing file, content' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "System.map guidance preserves unexplained RPM evidence"
assert_grep_fixed 'Exit 0 means the requested evidence sources completed' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "integrity guide documents the successful collection contract"
assert_grep_fixed 'Exit 1 means at least one red failure' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "integrity guide documents red findings as a failing exit status"
assert_grep_fixed 'No exit status is an integrity attestation' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "integrity guide rejects a false machine-readable all-clear"
assert_grep_fixed "It deliberately retains Fedora's SUID modes for" \
    "$TMPDIR/33-integrity-check-guide.md" \
    "SUID guidance identifies the deliberate M10 retention contract"
for retained_path in chage pam_timestamp_check userhelper libgtop_server2; do
    assert_grep_fixed "\`$retained_path\`" \
        "$TMPDIR/33-integrity-check-guide.md" \
        "SUID guidance names retained path: $retained_path"
done
assert_grep_fixed 'does not carry a static allowlist' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "SUID guidance delegates attribution to the live package set"
assert_grep_fixed 'rpm -qf -- "$path"' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "SUID guidance resolves each live path to its owning package"
assert_grep_fixed 'rpm -V "$(rpm -qf' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "SUID guidance verifies the resolved owner package"
assert_not_grep 'The base set is' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "SUID guidance has no inevitably incomplete static base list"
assert_not_grep_extended 'noid-suid-harden|chage.*are \*\*not\*\* SUID' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "SUID guidance has no retired helper or false Fedora mode claim"
assert_grep_fixed 'AIDE reports only later' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "AIDE guidance respects the accepted-baseline evidence boundary"
assert_not_grep_extended 'manual AIDE status|Snapper diff|journalctl -t flatpak' \
    "$TMPDIR/33-integrity-check-guide.md" \
    "integrity guide contains no unimplemented or unsupported evidence claim"

# --- extract + validate CLI scripts ----------------------------------------

extract_heredoc "$KS_FILE" "NIC_EOF"  "$TMPDIR/noid-integrity-check"                  || true
extract_heredoc "$KS_FILE" "FFCP_EOF" "$TMPDIR/noid-firefox-create-isolated-profile"  || true

assert_file_min_size "$TMPDIR/noid-integrity-check"                 2048 "noid-integrity-check > 2KB"
assert_file_min_size "$TMPDIR/noid-firefox-create-isolated-profile" 2048 "noid-firefox-create-isolated-profile > 2KB"

assert_cmd_success "noid-integrity-check bash -n clean" \
    bash -n "$TMPDIR/noid-integrity-check"
assert_cmd_success "noid-firefox-create-isolated-profile bash -n clean" \
    bash -n "$TMPDIR/noid-firefox-create-isolated-profile"
chmod 755 "$TMPDIR/noid-integrity-check" "$TMPDIR/noid-firefox-create-isolated-profile"

# --- noid-integrity-check structural: functions + flags --------------------

for func in validate_rpm_verify_output _known_noid_system_timer \
            _known_noid_masked_system_timer _noid_timer_mask_is_exact \
            _section_rpm _section_timers \
            _section_cron _section_flatpak _section_oauth _section_suid \
            _section_services _header _print_summary; do
    assert_grep_fixed "${func}()" "$TMPDIR/noid-integrity-check" "defines: $func"
done
assert_grep_fixed 'flatpak history --system --since=30days' \
    "$TMPDIR/noid-integrity-check" \
    "Flatpak history audit cannot initialize a root user repository"
assert_grep_fixed 'flatpak history --user --since=30days' \
    "$TMPDIR/noid-integrity-check" \
    "Flatpak history audit includes an existing current-user repository"
assert_grep_fixed 'if [ -n "$user_repo" ] && [ -f "$user_repo/config" ]; then' \
    "$TMPDIR/noid-integrity-check" \
    "user history is queried only when its repository already exists"
assert_grep_fixed 'XDG_CACHE_HOME="$flatpak_cache"' \
    "$TMPDIR/noid-integrity-check" \
    "Flatpak history audit isolates its cache from the caller home"
assert_grep_fixed 'cannot read system Flatpak history' \
    "$TMPDIR/noid-integrity-check" \
    "Flatpak history failure cannot become a false no-events result"
assert_grep_fixed '_fail_line "cannot read system Flatpak history' \
    "$TMPDIR/noid-integrity-check" \
    "Flatpak history collection failure reaches the red summary"

# A failed Flatpak history query is missing evidence, must be red and must make
# the CLI fail for automation.
# shellcheck disable=SC2317,SC2329
flatpak() {
    printf '%s\n' 'fixture Flatpak history failure' >&2
    return 1
}
export -f flatpak
mkdir -p "$TMPDIR/flatpak-home"
if env HOME="$TMPDIR/flatpak-home" \
       XDG_DATA_HOME="$TMPDIR/flatpak-home/data" \
       bash "$TMPDIR/noid-integrity-check" --section flatpak \
       > "$TMPDIR/flatpak-failure-output"; then
    _fail "failed Flatpak evidence incorrectly returned success"
else
    _pass "failed Flatpak evidence returns a failing CLI status"
fi
unset -f flatpak
assert_grep_fixed 'cannot read system Flatpak history (exit 1)' \
    "$TMPDIR/flatpak-failure-output" \
    "failed Flatpak system history is explicit"
assert_grep_fixed 'fixture Flatpak history failure' \
    "$TMPDIR/flatpak-failure-output" \
    "failed Flatpak history retains a bounded diagnostic"
assert_grep_fixed 'red    1' "$TMPDIR/flatpak-failure-output" \
    "failed Flatpak system history reaches the red summary"

# An environment without HOME/XDG_DATA_HOME cannot locate a user repository,
# but the system query and final summary must still execute under set -u.
# shellcheck disable=SC2317,SC2329
flatpak() { return 0; }
export -f flatpak
assert_cmd_success "unset HOME preserves Flatpak system evidence and summary" \
    env -u HOME -u XDG_DATA_HOME \
        bash "$TMPDIR/noid-integrity-check" --section flatpak
env -u HOME -u XDG_DATA_HOME \
    bash "$TMPDIR/noid-integrity-check" --section flatpak \
    > "$TMPDIR/flatpak-home-unset-output"
unset -f flatpak
assert_grep_fixed 'HOME and XDG_DATA_HOME are unset' \
    "$TMPDIR/flatpak-home-unset-output" \
    "unset user-data roots are an explicit skip, not an unbound-variable abort"
assert_grep_fixed '=== Summary ===' "$TMPDIR/flatpak-home-unset-output" \
    "unset HOME run retains the CLI summary"
assert_grep_fixed 'yellow 1' "$TMPDIR/flatpak-home-unset-output" \
    "missing user repository location contributes one yellow review item"

# The global signal trap must remove a registered private workspace even while
# the section is blocked in a child command.
m33_signal_bin="$EXEC_FIXTURE_DIR/signal-bin"
m33_signal_tmp="$TMPDIR/signal-tmp"
mkdir -p "$m33_signal_bin" "$m33_signal_tmp/user-home" \
    "$m33_signal_tmp/user-data"
cat > "$m33_signal_bin/flatpak" <<'M33_SIGNAL_FLATPAK_EOF'
#!/usr/bin/env bash
sleep 30
M33_SIGNAL_FLATPAK_EOF
chmod 0700 "$m33_signal_bin/flatpak"
/usr/bin/setsid env PATH="$m33_signal_bin:$PATH" TMPDIR="$m33_signal_tmp" \
    HOME="$m33_signal_tmp/user-home" XDG_DATA_HOME="$m33_signal_tmp/user-data" \
    bash "$TMPDIR/noid-integrity-check" --section flatpak \
    > "$TMPDIR/flatpak-signal-output" 2>&1 &
m33_signal_pid=$!
m33_signal_cache_seen=0
for _ in {1..100}; do
    if compgen -G "$m33_signal_tmp/noid-integrity-flatpak.*" >/dev/null; then
        m33_signal_cache_seen=1
        break
    fi
    sleep 0.05
done
if [ "$m33_signal_cache_seen" -eq 1 ]; then
    _pass "Flatpak signal fixture observed the private audit workspace"
else
    _fail "Flatpak signal fixture never observed the private audit workspace"
fi
kill -TERM -- "-$m33_signal_pid" 2>/dev/null || true
if wait "$m33_signal_pid"; then
    m33_signal_rc=0
else
    m33_signal_rc=$?
fi
assert_eq 143 "$m33_signal_rc" \
    "noid-integrity-check preserves the conventional SIGTERM status"
if compgen -G "$m33_signal_tmp/noid-integrity-flatpak.*" >/dev/null; then
    _fail "SIGTERM left a private Flatpak audit workspace behind"
else
    _pass "SIGTERM removes the private Flatpak audit workspace"
fi

assert_not_grep_extended 'filter_rpm_verify_nonconfig|sha256sum --check --status.*override_manifest' \
    "$TMPDIR/noid-integrity-check" \
    "RPM evidence has no config or known-override suppression oracle"
assert_grep_fixed 'sed -n '\''1,20{s/^/      /;p;}'\'' "$rpm_tmp/stdout"' \
    "$TMPDIR/noid-integrity-check" \
    "validated RPM drift is streamed from the private evidence file"
assert_not_grep_extended 'rpm_out=|diff_out=' "$TMPDIR/noid-integrity-check" \
    "large RPM evidence is not duplicated in shell variables"

# Exercise the actual CLI section with RPM 6-style config and maintained-
# override records. Both must survive byte-for-byte into human evidence.
# shellcheck disable=SC2317,SC2329
rpm() {
    if [ "$*" = '-Va --nodeps' ]; then
        printf '%s\n' 'S.5....T.  c /etc/example.conf'
        printf '%s\n' 'S.5....T.    /usr/bin/reviewed-override'
        return 1
    fi
    return 1
}
# shellcheck disable=SC2317,SC2329
id() {
    [ "${1:-}" = '-u' ] && { printf '0\n'; return 0; }
    command id "$@"
}
export -f rpm id
bash "$TMPDIR/noid-integrity-check" --section rpm > "$TMPDIR/rpm-visible.out"
unset -f rpm id
assert_grep_fixed 'S.5....T.  c /etc/example.conf' "$TMPDIR/rpm-visible.out" \
    "RPM config drift remains visible"
assert_grep_fixed 'S.5....T.    /usr/bin/reviewed-override' "$TMPDIR/rpm-visible.out" \
    "known NoID Privacy override drift remains visible"
assert_grep_fixed '2 RPM package-file record(s)' "$TMPDIR/rpm-visible.out" \
    "complete RPM drift count remains yellow evidence"

awk '
    /^validate_rpm_verify_output\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$TMPDIR/noid-integrity-check" > "$TMPDIR/rpm-validator.sh"
# shellcheck disable=SC1090
. "$TMPDIR/rpm-validator.sh"
printf '%s\n' 'S.5....T.    /usr/bin/example' > "$TMPDIR/rpm-valid.out"
printf '%s\n' 'missing     /usr/share/example' >> "$TMPDIR/rpm-valid.out"
assert_cmd_success "RPM validator accepts structured drift and missing rows" \
    validate_rpm_verify_output < "$TMPDIR/rpm-valid.out"
printf '%s\n' 'error: cannot open Packages database' > "$TMPDIR/rpm-invalid.out"
assert_cmd_failure "RPM validator rejects diagnostic text as drift" \
    validate_rpm_verify_output < "$TMPDIR/rpm-invalid.out"
assert_cmd_failure "RPM validator rejects an empty rc=1-style stream" \
    validate_rpm_verify_output < /dev/null
assert_grep_fixed '[ "$rpm_rc" -eq 1 ] && [ -s "$rpm_tmp/stdout" ]' \
    "$TMPDIR/noid-integrity-check" \
    "RPM 6 rc=1 is accepted only with non-empty structured stdout"
assert_grep_fixed 'rpm -Va --nodeps >"$rpm_tmp/stdout" 2>"$rpm_tmp/stderr"' \
    "$TMPDIR/noid-integrity-check" \
    "RPM file verification excludes dependency diagnostics and separates stderr"
assert_grep_fixed '${TMPDIR:-/var/tmp}/noid-rpm-verify.XXXXXX' \
    "$TMPDIR/noid-integrity-check" \
    "RPM evidence defaults to disk-backed private temporary storage"

for flag in '\-\-help' '\-\-all' '\-\-section' '\-\-brief'; do
    assert_grep_extended "$flag" "$TMPDIR/noid-integrity-check" "flag: $flag"
done

# Malformed options/sections are operator errors, not green all-zero scans.
assert_cmd_failure "unknown option exits non-zero" \
    bash "$TMPDIR/noid-integrity-check" --bogus
assert_cmd_failure "unknown section exits non-zero" \
    bash "$TMPDIR/noid-integrity-check" --section does-not-exist
assert_cmd_failure "empty --section value exits non-zero" \
    bash "$TMPDIR/noid-integrity-check" --section ""
assert_cmd_failure "empty bare section value exits non-zero" \
    bash "$TMPDIR/noid-integrity-check" ""
assert_cmd_success "--brief combines with an explicit section" \
    bash "$TMPDIR/noid-integrity-check" --brief --section oauth

# FragmentPath remains a vendor path when a local .timer.d override exists.
# Mock that exact systemd state and require the CLI to surface it as yellow.
# Invoked indirectly by the extracted child shell after export -f.
# shellcheck disable=SC2317,SC2329
rpm() { return 0; }
# shellcheck disable=SC2317,SC2329
systemctl() {
    case "$*" in
        "list-unit-files --type=timer --no-pager --no-legend")
            printf '%s\n' 'vendor.timer enabled enabled'
            printf '%s\n' 'vendor-packaged.timer disabled enabled'
            printf '%s\n' 'vendor-template@.timer static disabled'
            printf '%s\n' 'generated.timer enabled enabled'
            ;;
        "show -p FragmentPath --value vendor.timer")
            printf '%s\n' '/usr/lib/systemd/system/vendor.timer'
            ;;
        "show -p DropInPaths --value vendor.timer")
            printf '%s\n' '/etc/systemd/system/vendor.timer.d/99-local.conf'
            ;;
        "show -p FragmentPath --value vendor-packaged.timer")
            printf '%s\n' '/usr/lib/systemd/system/vendor-packaged.timer'
            ;;
        "show -p DropInPaths --value vendor-packaged.timer")
            printf '%s\n' '/usr/lib/systemd/system/vendor-packaged.timer.d/10-package.conf'
            ;;
        "show -p FragmentPath --value vendor-template@noid-audit.timer")
            printf '%s\n' '/usr/lib/systemd/system/vendor-template@.timer'
            ;;
        "show -p DropInPaths --value vendor-template@noid-audit.timer")
            printf '\n'
            ;;
        "show -p FragmentPath --value generated.timer")
            printf '%s\n' '/usr/lib/systemd/system/generated.timer'
            ;;
        "show -p DropInPaths --value generated.timer")
            printf '%s\n' '/run/systemd/generator/generated.timer.d/50-runtime.conf'
            ;;
        *) return 1 ;;
    esac
}
export -f rpm systemctl
bash "$TMPDIR/noid-integrity-check" --section timers > "$TMPDIR/timer-output"
unset -f rpm systemctl
assert_grep_extended '\[admin override[[:space:]]*\] vendor\.timer' \
    "$TMPDIR/timer-output" \
    "timer classifier detects local drop-ins on vendor fragments"
assert_grep_fixed 'admin/override: 1' "$TMPDIR/timer-output" \
    "timer override contributes to the yellow summary"
assert_grep_extended '\[vendor[[:space:]]+\] vendor-packaged\.timer' \
    "$TMPDIR/timer-output" \
    "package-owned drop-ins preserve a package-owned timer's vendor source"
assert_grep_extended '\[vendor[[:space:]]+\] vendor-template@\.timer' \
    "$TMPDIR/timer-output" \
    "installed timer templates resolve through an inert synthetic instance"
assert_grep_extended '\[generator output[[:space:]]*\] generated\.timer' \
    "$TMPDIR/timer-output" \
    "systemd generator drop-ins are classified without a false red result"
assert_grep_fixed 'generator: 1' "$TMPDIR/timer-output" \
    "runtime generator output contributes to the yellow summary"
assert_not_grep 'RPM verification is skipped' "$TMPDIR/timer-output" \
    "timer-only run does not claim an unrequested RPM section was skipped"
assert_grep_fixed 'inspect_t=${t/@.timer/@noid-audit.timer}' \
    "$TMPDIR/noid-integrity-check" \
    "timer template inspection never starts or enables a real instance"

# A failed inventory is red evidence, never an empty/green timer result.
# shellcheck disable=SC2317,SC2329
systemctl() { return 1; }
export -f systemctl
if bash "$TMPDIR/noid-integrity-check" --section timers \
        > "$TMPDIR/timer-failure-output"; then
    _fail "failed timer inventory incorrectly returned success"
else
    _pass "failed timer inventory returns a failing CLI status"
fi
unset -f systemctl
assert_grep_fixed 'cannot enumerate installed system timer unit files' \
    "$TMPDIR/timer-failure-output" \
    "timer listing failure is explicit"
assert_grep_fixed 'red    1' "$TMPDIR/timer-failure-output" \
    "timer listing failure reaches the red summary"

# A per-unit source query failure must be unknown/red as well; an empty
# command-substitution result is not evidence that the unit has no drop-ins.
# shellcheck disable=SC2317,SC2329
systemctl() {
    case "$*" in
        "list-unit-files --type=timer --no-pager --no-legend")
            printf '%s\n' 'query-failure.timer enabled enabled'
            ;;
        "show -p FragmentPath --value query-failure.timer")
            printf '%s\n' '/usr/lib/systemd/system/query-failure.timer'
            ;;
        "show -p DropInPaths --value query-failure.timer")
            return 1
            ;;
        *) return 1 ;;
    esac
}
export -f systemctl
if bash "$TMPDIR/noid-integrity-check" --section timers \
        > "$TMPDIR/timer-query-failure-output"; then
    _fail "failed timer source query incorrectly returned success"
else
    _pass "failed timer source query returns a failing CLI status"
fi
unset -f systemctl
assert_grep_extended '\[unknown[[:space:]]+\] query-failure\.timer' \
    "$TMPDIR/timer-query-failure-output" \
    "timer source-query failure is classified unknown"
assert_grep_fixed 'red    1' "$TMPDIR/timer-query-failure-output" \
    "timer source-query failure reaches the red summary"

# A path merely placed under /usr/lib is not evidence of package provenance.
# shellcheck disable=SC2317,SC2329
rpm() { return 1; }
# shellcheck disable=SC2317,SC2329
systemctl() {
    case "$*" in
        "list-unit-files --type=timer --no-pager --no-legend")
            printf '%s\n' 'unowned-vendor-path.timer enabled enabled'
            ;;
        "show -p FragmentPath --value unowned-vendor-path.timer")
            printf '%s\n' '/usr/lib/systemd/system/unowned-vendor-path.timer'
            ;;
        "show -p DropInPaths --value unowned-vendor-path.timer")
            printf '\n'
            ;;
        *) return 1 ;;
    esac
}
export -f rpm systemctl
if bash "$TMPDIR/noid-integrity-check" --section timers \
        > "$TMPDIR/timer-unowned-vendor-output"; then
    _fail "unowned /usr/lib timer path incorrectly returned success"
else
    _pass "unowned /usr/lib timer path returns a failing CLI status"
fi
unset -f rpm systemctl
assert_grep_extended '\[unknown[[:space:]]+\] unowned-vendor-path\.timer' \
    "$TMPDIR/timer-unowned-vendor-output" \
    "unowned /usr/lib timer path is not mislabeled as vendor"

assert_grep_fixed '_known_noid_system_timer()' "$TMPDIR/noid-integrity-check" \
    "NoID Privacy timer classification uses an exact-name function"
assert_grep_fixed '_rpm_owns_path()' "$TMPDIR/noid-integrity-check" \
    "vendor timer classification requires RPM ownership"
assert_grep_fixed '[ "$src_line" = "$expected_path" ]' \
    "$TMPDIR/noid-integrity-check" \
    "NoID Privacy timer classification requires the exact expected fragment path"
assert_not_grep 'noid-\*\\.timer' "$TMPDIR/noid-integrity-check" \
    "NoID Privacy timer classification has no prefix wildcard"

# NoID Privacy-owned vendor-timer masks are green only at the exact expected mask
# boundary. Exercise the production predicate with private symlinks while
# supplying the fixture owner tuple explicitly; production uses root:root.
awk '
    /^_known_noid_masked_system_timer\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$TMPDIR/noid-integrity-check" > "$TMPDIR/noid-mask-predicates.sh"
awk '
    /^_noid_timer_mask_is_exact\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$TMPDIR/noid-integrity-check" >> "$TMPDIR/noid-mask-predicates.sh"
# shellcheck disable=SC1090
. "$TMPDIR/noid-mask-predicates.sh"
mask_fixture="$TMPDIR/noid-timer-mask-fixture"
mkdir -p "$mask_fixture"
fixture_state="$(id -u):$(id -g):1"
for unit in dnf-makecache.timer dnf5-makecache.timer \
            fwupd-refresh.timer plocate-updatedb.timer; do
    ln -s /dev/null "$mask_fixture/$unit"
    assert_cmd_success "exact NoID Privacy timer mask accepted: $unit" \
        _noid_timer_mask_is_exact "$unit" "$mask_fixture/$unit" \
            "$fixture_state"
done
ln -s /dev/zero "$mask_fixture/wrong-target.timer"
assert_cmd_failure "unknown NoID Privacy timer mask name is rejected" \
    _noid_timer_mask_is_exact wrong-target.timer \
        "$mask_fixture/wrong-target.timer" "$fixture_state"
rm "$mask_fixture/dnf-makecache.timer"
ln -s /dev/zero "$mask_fixture/dnf-makecache.timer"
assert_cmd_failure "known NoID Privacy timer mask with wrong target is rejected" \
    _noid_timer_mask_is_exact dnf-makecache.timer \
        "$mask_fixture/dnf-makecache.timer" "$fixture_state"
rm "$mask_fixture/dnf5-makecache.timer"
printf '%s\n' /dev/null > "$mask_fixture/dnf5-makecache.timer"
assert_cmd_failure "known NoID Privacy timer mask must remain a symlink" \
    _noid_timer_mask_is_exact dnf5-makecache.timer \
        "$mask_fixture/dnf5-makecache.timer" "$fixture_state"

# Keep the four-name classifier synchronized with its authoritative writers:
# the timer entries in M08's MASK_LIST plus M24's literal fwupd timer mask.
if noid_mask_inventory_result=$(python3 - \
        "$TMPDIR/noid-integrity-check" \
        "$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks" \
        "$PROJECT_ROOT/kickstart/snippets/24-firmware-fwupd.ks" <<'PY'
from pathlib import Path
import re
import sys

cli = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
m08 = Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
m24 = Path(sys.argv[3]).read_text(encoding="utf-8")

inside = False
known = set()
for line in cli:
    if line == "_known_noid_masked_system_timer() {":
        inside = True
        continue
    if inside and line == "}":
        break
    if not inside:
        continue
    candidate = line.strip().removesuffix("\\").removesuffix("|").removesuffix(")")
    if re.fullmatch(r"[A-Za-z0-9@_.-]+\.timer", candidate):
        known.add(candidate)

inside = False
owned = set()
for line in m08:
    if "done <<'MASK_LIST_EOF'" in line:
        inside = True
        continue
    if inside and line == "MASK_LIST_EOF":
        break
    if inside and re.fullmatch(r"[A-Za-z0-9@_.-]+\.timer", line):
        owned.add(line)
owned.update(re.findall(r"systemctl mask ([A-Za-z0-9@_.-]+\.timer)", m24))

if known != owned:
    print("classifier=" + ",".join(sorted(known)))
    print("owners=" + ",".join(sorted(owned)))
    raise SystemExit(1)
print(len(known))
PY
); then
    _pass "all $noid_mask_inventory_result owned vendor-timer masks have exact classifier names"
else
    _fail "NoID Privacy-owned timer-mask writers and the M33 classifier differ"
    printf '%s\n' "$noid_mask_inventory_result" | sed 's/^/      /'
fi

# Cross-check every literal Module-owned timer writer against the classifier.
# This catches inventory drift when another snippet adds a durable timer.
if timer_inventory_result=$(python3 - \
        "$TMPDIR/noid-integrity-check" \
        "$PROJECT_ROOT/kickstart/snippets" <<'PY'
from pathlib import Path
import re
import sys

cli = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
snippet_root = Path(sys.argv[2])

inside = False
known = set()
for line in cli:
    if line == "_known_noid_system_timer() {":
        inside = True
        continue
    if inside and line == "}":
        break
    if not inside:
        continue
    candidate = line.strip().removesuffix("\\").removesuffix("|").removesuffix(")")
    if re.fullmatch(r"[A-Za-z0-9@_.-]+\.timer", candidate):
        known.add(candidate)

writer_re = re.compile(
    r"(?:cat\s*>|stage_root_file|publish_root_file)\s+"
    r"/etc/systemd/system/([A-Za-z0-9@_.-]+\.timer)(?:\s|$)"
)
written = set()
for path in sorted(snippet_root.glob("*.ks")):
    for line in path.read_text(encoding="utf-8").splitlines():
        match = writer_re.search(line)
        if match:
            written.add(match.group(1))

missing = sorted(written - known)
stale = sorted(known - written)
if missing or stale:
    if missing:
        print("unclassified timer writers: " + ", ".join(missing))
    if stale:
        print("classifier names without a timer writer: " + ", ".join(stale))
    raise SystemExit(1)
print(len(written))
PY
); then
    _pass "all $timer_inventory_result Module-owned timer writers have exact classifier names"
else
    _fail "Module-owned timer writers and the M33 classifier differ"
    printf '%s\n' "$timer_inventory_result" | sed 's/^/      /'
fi

# Default sections list
assert_grep_fixed 'DEFAULT_SECTIONS="rpm timers cron flatpak oauth"' \
    "$TMPDIR/noid-integrity-check" "5 default sections"

# Optional extra sections
assert_grep_fixed 'EXTRA_SECTIONS="suid services"' \
    "$TMPDIR/noid-integrity-check" "2 extra sections"
assert_grep_fixed '--state=enabled,enabled-runtime' \
    "$TMPDIR/noid-integrity-check" \
    "service inventory includes persistent and runtime-enabled units"
assert_grep_fixed \
    'for root in / /home /var /var/tmp /tmp /dev/shm /boot /boot/efi; do' \
    "$TMPDIR/noid-integrity-check" \
    "SUID scan retains the exact reviewed separate-mount root list"

# The optional services section must execute its systemctl inventory, retain
# both enabled states, and make collection failures red rather than empty.
# shellcheck disable=SC2317,SC2329
systemctl() {
    case "$*" in
        "list-unit-files --state=enabled,enabled-runtime --no-pager --no-legend")
            printf '%s\n' 'fixture.service enabled enabled'
            printf '%s\n' 'runtime-fixture.service enabled-runtime enabled'
            ;;
        *) return 1 ;;
    esac
}
export -f systemctl
bash "$TMPDIR/noid-integrity-check" --section services \
    > "$TMPDIR/services-output"
unset -f systemctl
assert_grep_fixed 'fixture.service' "$TMPDIR/services-output" \
    "services section prints a persistently enabled unit"
assert_grep_fixed 'runtime-fixture.service' "$TMPDIR/services-output" \
    "services section prints a runtime-enabled unit"
assert_grep_fixed '2 enabled/enabled-runtime unit files' \
    "$TMPDIR/services-output" \
    "services section reports the complete mocked inventory"

# shellcheck disable=SC2317,SC2329
systemctl() { return 1; }
export -f systemctl
if bash "$TMPDIR/noid-integrity-check" --section services \
        > "$TMPDIR/services-failure-output"; then
    _fail "failed services inventory incorrectly returned success"
else
    _pass "failed services inventory returns a failing CLI status"
fi
unset -f systemctl
assert_grep_fixed 'cannot enumerate enabled systemd unit files' \
    "$TMPDIR/services-failure-output" \
    "services inventory failure is explicit"
assert_grep_fixed 'red    1' "$TMPDIR/services-failure-output" \
    "services inventory failure reaches the red summary"
assert_grep_fixed 'pkg=$(LC_ALL=C rpm -qf "$e"' \
    "$TMPDIR/noid-integrity-check" \
    "cron ownership classification is locale-independent"
assert_grep_fixed 'cron_files="/etc/crontab /etc/anacrontab"' \
    "$TMPDIR/noid-integrity-check" \
    "cron inventory includes the two top-level system scheduler sources"
assert_not_grep_extended 'NOID_TEST_MODE|NOID_TEST_CRON_(DIRS|FILES)' \
    "$TMPDIR/noid-integrity-check" \
    "shipped cron inventory cannot be redirected through a test environment"
assert_grep_fixed 'entries=$(find "$dir"' "$TMPDIR/noid-integrity-check" \
    "cron walker output is captured independently"
assert_grep_fixed '\( -type f -o -type l \)' \
    "$TMPDIR/noid-integrity-check" \
    "cron inventory includes accepted symlinked sources"
assert_grep_fixed '|| find_rc=$?' "$TMPDIR/noid-integrity-check" \
    "cron walker status cannot abort the complete integrity run"
assert_grep_fixed 'LC_ALL=C crontab -l >"$cron_tmp/stdout" 2>"$cron_tmp/stderr"' \
    "$TMPDIR/noid-integrity-check" \
    "current-user crontab output and diagnostics remain independently classified"
assert_grep_fixed "grep -qE '^no crontab for '" \
    "$TMPDIR/noid-integrity-check" \
    "cronie's explicit no-crontab result is distinguished from query failure"

# Exercise partial, empty-partial and clean-empty cron walks with a private
# directory. The actual section must retain discovered rows, label incomplete
# evidence yellow and reserve the green all-clear for rc=0.
# Build a test-only derivative with the two path inventories redirected to the
# fixture and current-user crontab lookup disabled. None of these variables
# exists in the shipped CLI.
cron_fixture_cli="$TMPDIR/noid-integrity-check-cron-fixture"
awk '
    $0 == "    cron_dirs=\"/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly\"" {
        print "    cron_dirs=${NOID_TEST_CRON_DIRS:?test cron directories are required}"
        next
    }
    $0 == "    cron_files=\"/etc/crontab /etc/anacrontab\"" {
        print "    cron_files=${NOID_TEST_CRON_FILES:-}"
        next
    }
    $0 == "    if command -v crontab >/dev/null 2>&1; then" {
        print "    if [ \"${NOID_TEST_SKIP_USER_CRONTAB:-1}\" = 0 ] && command -v crontab >/dev/null 2>&1; then"
        next
    }
    { print }
' "$TMPDIR/noid-integrity-check" > "$cron_fixture_cli"
chmod 0755 "$cron_fixture_cli"
assert_grep_fixed '${NOID_TEST_CRON_DIRS:?test cron directories are required}' \
    "$cron_fixture_cli" \
    "test-only cron derivative redirects its system-directory inventory"
assert_grep_fixed '${NOID_TEST_SKIP_USER_CRONTAB:-1}' \
    "$cron_fixture_cli" \
    "test-only cron derivative suppresses the real user crontab query"
cron_fixture="$TMPDIR/cron-fixture"
mkdir -p "$cron_fixture"
touch "$cron_fixture/fixture-job"
printf '%s\n' 'SHELL=/bin/bash' > "$cron_fixture/system-crontab"
ln -s -- fixture-job "$cron_fixture/fixture-link"
ln -s -- missing-target "$cron_fixture/broken-link"
# shellcheck disable=SC2317,SC2329
find() {
    case "${NOID_TEST_CRON_OUTPUT:-1}" in
        1) printf '%s\n' "$NOID_TEST_CRON_DIRS/fixture-job" ;;
        2) printf '%s\n' "$NOID_TEST_CRON_DIRS/fixture-link" ;;
        3) printf '%s\n' "$NOID_TEST_CRON_DIRS/broken-link" ;;
    esac
    return "${NOID_TEST_CRON_RC:-0}"
}
# shellcheck disable=SC2317,SC2329
rpm() { printf '%s\n' 'fixture-cron-owner'; }
export -f find rpm
partial_cron_out=$(env NOID_TEST_CRON_DIRS="$cron_fixture" \
    NOID_TEST_CRON_RC=1 NOID_TEST_CRON_OUTPUT=1 \
    bash "$cron_fixture_cli" --section cron)
assert_grep_fixed 'cron scan incomplete' <(printf '%s\n' "$partial_cron_out") \
    "partial cron walk is explicitly labeled"
assert_grep_fixed 'fixture-job' <(printf '%s\n' "$partial_cron_out") \
    "partial cron walk retains discovered entries"
assert_grep_fixed 'yellow 1' <(printf '%s\n' "$partial_cron_out") \
    "partial cron evidence reaches the yellow summary"
empty_partial_cron_out=$(env NOID_TEST_CRON_DIRS="$cron_fixture" \
    NOID_TEST_CRON_RC=1 NOID_TEST_CRON_OUTPUT=0 \
    bash "$cron_fixture_cli" --section cron)
assert_not_grep 'no cron entries' <(printf '%s\n' "$empty_partial_cron_out") \
    "errored empty cron walk cannot claim an all-clear"
clean_empty_cron_out=$(env NOID_TEST_CRON_DIRS="$cron_fixture" \
    NOID_TEST_CRON_RC=0 NOID_TEST_CRON_OUTPUT=0 \
    bash "$cron_fixture_cli" --section cron)
assert_grep_fixed 'no cron entries' <(printf '%s\n' "$clean_empty_cron_out") \
    "clean empty cron walk remains green"
# shellcheck disable=SC2317,SC2329
id() {
    [ "${1:-}" = -u ] && { printf '1000\n'; return 0; }
    command id "$@"
}
export -f id
protected_cron_out=$(env \
    NOID_TEST_CRON_DIRS='/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly' \
    NOID_TEST_CRON_RC=1 NOID_TEST_CRON_OUTPUT=0 \
    bash "$cron_fixture_cli" --section cron)
assert_eq 1 \
    "$(grep -c 'protected system cron directories were unreadable' \
        <<< "$protected_cron_out")" \
    "non-root M10 cron-directory denials are consolidated into one notice"
assert_grep_fixed '5 protected system cron directories' \
    <(printf '%s\n' "$protected_cron_out") \
    "consolidated cron notice accounts for every M10-protected directory"
assert_grep_fixed 'yellow 1' <(printf '%s\n' "$protected_cron_out") \
    "expected non-root cron limitation contributes one yellow item"
unset -f id
top_level_cron_out=$(env \
    NOID_TEST_CRON_DIRS="$cron_fixture" \
    NOID_TEST_CRON_FILES="$cron_fixture/system-crontab" \
    NOID_TEST_CRON_RC=0 NOID_TEST_CRON_OUTPUT=0 \
    bash "$cron_fixture_cli" --section cron)
assert_grep_fixed "$cron_fixture/system-crontab" \
    <(printf '%s\n' "$top_level_cron_out") \
    "top-level system crontab source remains visible"
assert_grep_fixed '1 system cron entry is package-owned' \
    <(printf '%s\n' "$top_level_cron_out") \
    "top-level package-owned system source contributes to the clean count"
symlink_cron_out=$(env NOID_TEST_CRON_DIRS="$cron_fixture" \
    NOID_TEST_CRON_RC=0 NOID_TEST_CRON_OUTPUT=2 \
    bash "$cron_fixture_cli" --section cron)
assert_grep_fixed 'fixture-link' <(printf '%s\n' "$symlink_cron_out") \
    "valid symlinked cron source remains visible"
assert_grep_fixed ' -> fixture-job' <(printf '%s\n' "$symlink_cron_out") \
    "symlinked cron source prints its target"
assert_grep_fixed '1 symlinked system cron source requires target review' \
    <(printf '%s\n' "$symlink_cron_out") \
    "valid symlinked cron source is never a green ownership shortcut"
assert_grep_fixed 'yellow 1' <(printf '%s\n' "$symlink_cron_out") \
    "valid symlinked cron source contributes a yellow review item"
if env NOID_TEST_CRON_DIRS="$cron_fixture" \
       NOID_TEST_CRON_RC=0 NOID_TEST_CRON_OUTPUT=3 \
       bash "$cron_fixture_cli" --section cron \
       > "$TMPDIR/broken-cron-output"; then
    _fail "broken cron symlink incorrectly returned success"
else
    _pass "broken cron symlink returns a failing CLI status"
fi
assert_grep_fixed 'cron directory source is not a regular file or valid symlink' \
    "$TMPDIR/broken-cron-output" \
    "broken cron symlink is explicit red evidence"
# shellcheck disable=SC2317,SC2329
rpm() { return 1; }
export -f rpm
unowned_cron_out=$(env NOID_TEST_CRON_DIRS="$cron_fixture" \
    NOID_TEST_CRON_RC=0 NOID_TEST_CRON_OUTPUT=1 \
    bash "$cron_fixture_cli" --section cron)
assert_grep_fixed '<unowned>' <(printf '%s\n' "$unowned_cron_out") \
    "unowned cron entry remains visible"
assert_grep_fixed '1 unowned system cron entry require attribution' \
    <(printf '%s\n' "$unowned_cron_out") \
    "unowned cron entry contributes a yellow review item"
unset -f find rpm
awk '
    /^_section_suid\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$TMPDIR/noid-integrity-check" > "$TMPDIR/suid-section.sh"
assert_grep_fixed \
    '-printf '\''%m %u %g %p\n'\'' 2>/dev/null | sort -u) || find_rc=$?' \
    "$TMPDIR/suid-section.sh" \
    "SUID walker status is captured at the SUID call site"

# Exercise the real full CLI with an exported find shim. A file-backed mock in
# $TMPDIR is not portable because hardened hosts mount /tmp noexec; the
# exported function follows the already-proven systemctl fixture above.
# shellcheck disable=SC2317,SC2329
find() {
if [ "${NOID_TEST_FIND_OUTPUT:-1}" -eq 1 ]; then
    printf '%s\n' '4755 root root /usr/bin/fixture-suid'
fi
return "${NOID_TEST_FIND_RC:-0}"
}
export -f find

partial_suid_out=$(env NOID_TEST_FIND_RC=1 NOID_TEST_FIND_OUTPUT=1 \
    bash "$TMPDIR/noid-integrity-check" --section suid)
assert_grep_fixed '1 SUID/SGID files (PARTIAL — find rc=1;' \
    <(printf '%s\n' "$partial_suid_out") \
    "partial SUID scan retains and labels discovered entries"
assert_grep_fixed '/usr/bin/fixture-suid' \
    <(printf '%s\n' "$partial_suid_out") \
    "partial SUID scan prints its retained evidence"
assert_grep_fixed 'yellow 1' <(printf '%s\n' "$partial_suid_out") \
    "partial SUID scan reaches the yellow Summary"

empty_partial_out=$(env NOID_TEST_FIND_RC=1 NOID_TEST_FIND_OUTPUT=0 \
    bash "$TMPDIR/noid-integrity-check" --section suid)
assert_grep_fixed 'SUID scan incomplete (find rc=1) and returned nothing' \
    <(printf '%s\n' "$empty_partial_out") \
    "empty errored SUID scan is explicitly incomplete"
assert_not_grep 'no SUID/SGID binaries found' \
    <(printf '%s\n' "$empty_partial_out") \
    "empty errored SUID scan cannot claim a green all-clear"

clean_empty_out=$(env NOID_TEST_FIND_RC=0 NOID_TEST_FIND_OUTPUT=0 \
    bash "$TMPDIR/noid-integrity-check" --section suid)
assert_grep_fixed 'no regular files carrying SUID/SGID bits found in the selected trees' \
    <(printf '%s\n' "$clean_empty_out") \
    "zero-result SUID verdict is green only after a complete walk"
unset -f find

# --- noid-firefox-create-isolated-profile structural ----------------------

assert_grep_fixed 'ensure_profile "$NAME"' "$TMPDIR/noid-firefox-create-isolated-profile" \
    "uses shared ensure_profile"
assert_grep_fixed '$NOID_FF_USERJS_BASE' "$TMPDIR/noid-firefox-create-isolated-profile" \
    "references embedded user.js from M16 via helper"
assert_grep_fixed 'apply_userjs "$NAME"' "$TMPDIR/noid-firefox-create-isolated-profile" \
    "applies user.js via shared helper"
assert_grep_fixed 'patch_ubo_pb_permission "$NAME"' "$TMPDIR/noid-firefox-create-isolated-profile" \
    "grants uBO PB permission"
assert_grep_fixed 'if firefox_process_active; then' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "isolated-profile writer ignores defunct Firefox tasks through the shared guard"
assert_grep_fixed '--list' "$TMPDIR/noid-firefox-create-isolated-profile" \
    "--list flag"
assert_grep_fixed 'profiles.ini' "$TMPDIR/noid-firefox-create-isolated-profile" \
    "uses profiles.ini"
assert_grep_fixed 'if ! records=$(list_registered_profiles); then' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "--list cannot turn a rejected profiles.ini into empty success"
assert_grep_fixed '0:0:644:1' "$TMPDIR/noid-firefox-create-isolated-profile" \
    "shared root helper requires exact ownership, mode and link count"
assert_grep_fixed '--new-instance' "$TMPDIR/noid-firefox-create-isolated-profile" \
    "launcher output uses Firefox's current instance flag"
assert_grep_fixed 'This is NOT an OS sandbox' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "CLI reports the actual profile security boundary"
assert_not_grep '-no-remote' "$TMPDIR/noid-firefox-create-isolated-profile" \
    "CLI contains no retired instance flag"
assert_grep_fixed '[!a-zA-Z0-9_-]' "$TMPDIR/noid-firefox-create-isolated-profile" \
    "name validation"
assert_grep_fixed 'mktemp "$PROFILE_DIR/.xulstore.json.XXXXXX"' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "xulstore is written through a same-directory temporary file"
assert_grep_fixed 'mv -nT -- "$XULSTORE_TMP" "$XULSTORE_FILE"' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "xulstore install is atomic and never overwrites concurrent profile state"
assert_grep_fixed 'xulstore.json postcondition failed' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "xulstore success is gated by an explicit postcondition"
assert_grep_fixed 'mktemp "$NOID_BM_DIR/.bookmarks.json.XXXXXX"' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "bookmark backup is written through a same-directory temporary file"
assert_grep_fixed 'mv -nT -- "$NOID_BM_TMP" "$NOID_BM_FILE"' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "bookmark install is atomic and never overwrites concurrent profile state"
assert_grep_fixed 'bookmarks backup postcondition failed' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "empty-bookmark success is gated by an explicit postcondition"
assert_grep_fixed 'profile creation stopped before every hardening postcondition passed' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "partial Firefox registration receives explicit recovery guidance"
assert_grep_fixed "remove it with 'firefox -P' before retrying" \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "partial-profile recovery uses Firefox's upstream profile manager"
assert_grep_fixed 'trap profile_creation_exit_notice EXIT' \
    "$TMPDIR/noid-firefox-create-isolated-profile" \
    "partial-profile recovery covers every post-create failure path"

# --- %packages must be empty (doc + CLI only) -------------------------------

if awk '/^%packages/,/^%end/' "$KS_FILE" | grep -vE '^(%|#|$|-)' | grep -qE '^[a-zA-Z]'; then
    _fail "M33 %packages contains non-comment package lines (should be doc + CLI only)"
else
    _pass "M33 %packages is empty (no package installs)"
fi

# --- No systemd service/timer/autostart files shipped ----------------------
# Analyze executable source rather than guessing artifact names. Heredoc bodies
# are skipped at each layer so prose examples cannot satisfy or trip the gate;
# the two extracted CLI payloads are scanned separately.
m33_manual_only_source() {
    python3 - "$1" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
heredoc_re = re.compile(
    r"""<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1(?:\s*(?:then)?)?\s*$"""
)
write_re = re.compile(
    r"""(?:^|[;&|]\s*)(?:sudo\s+)?(?:"""
    r"""cat|install|cp|mv|ln|touch|tee|"""
    r"""publish_root_file|publish_doc|stage_root_file|publish_bin|"""
    r"""write_file|install_file|atomic_install[A-Za-z0-9_]*)\b"""
)
forbidden_path_re = re.compile(
    r"""/(?:etc|usr/lib)/systemd/(?:system|user)/|"""
    r"""/etc/xdg/autostart/|"""
    r"""/etc/skel/\.config/(?:autostart|systemd/user)/|"""
    r"""/home/[^/\s]+/\.config/(?:autostart|systemd/user)/|"""
    r"""(?:\$HOME|\$\{HOME\}|~)/\.config/(?:autostart|systemd/user)/"""
)
enable_re = re.compile(
    r"""(?:^|[;&|]\s*)(?:sudo\s+)?systemctl\s+(?:--\S+\s+)*(?:enable|start|preset)\b"""
)
transient_re = re.compile(r"""(?:^|[;&|]\s*)(?:sudo\s+)?systemd-run\b""")

marker = None
errors = []
for number, line in enumerate(lines, 1):
    if marker is not None:
        if line.strip() == marker:
            marker = None
        continue
    stripped = line.lstrip()
    if not stripped.startswith("#"):
        if write_re.search(stripped) and forbidden_path_re.search(stripped):
            errors.append(f"{path.name}:{number}: background artifact write: {stripped}")
        if enable_re.search(stripped):
            errors.append(f"{path.name}:{number}: persistent unit activation: {stripped}")
        if transient_re.search(stripped):
            errors.append(f"{path.name}:{number}: transient background unit: {stripped}")
    match = heredoc_re.search(line)
    if match:
        marker = match.group(2)

if marker is not None:
    errors.append(f"{path.name}: unterminated heredoc {marker}")
if errors:
    print("\n".join(errors))
    raise SystemExit(1)
PY
}

if m33_manual_only_source "$KS_FILE" &&
   m33_manual_only_source "$TMPDIR/noid-integrity-check" &&
   m33_manual_only_source "$TMPDIR/noid-firefox-create-isolated-profile"; then
    _pass "M33 outer source and both CLIs create/activate no background artifacts"
else
    _fail "M33 source violates the user-invoked-only invariant"
fi

manual_only_mutation_id=0
assert_manual_only_rejects() {
    local source_file=$1 injected_line=$2 description=$3 mutated_file
    manual_only_mutation_id=$((manual_only_mutation_id + 1))
    mutated_file="$TMPDIR/33-background-mutation-${manual_only_mutation_id}.sh"
    cp -- "$source_file" "$mutated_file"
    printf '%s\n' "$injected_line" >> "$mutated_file"
    if m33_manual_only_source "$mutated_file" >/dev/null 2>&1; then
        _fail "$description"
    else
        _pass "$description"
    fi
}
assert_manual_only_rejects "$KS_FILE" \
    'cat > /etc/systemd/system/noid-integrity-check.timer <<UNIT_EOF' \
    "M33 manual-only gate rejects a direct timer writer"
assert_manual_only_rejects "$KS_FILE" \
    'publish_root_file "$UNIT_TMP" /etc/systemd/system/noid-background.timer 644' \
    "M33 manual-only gate rejects its atomic publisher targeting a timer"
assert_manual_only_rejects "$KS_FILE" \
    'publish_root_file "$AUTOSTART_TMP" /etc/xdg/autostart/noid-background.desktop 644' \
    "M33 manual-only gate rejects its atomic publisher targeting autostart"
assert_manual_only_rejects "$TMPDIR/noid-firefox-create-isolated-profile" \
    'install -m 0644 "$tmp" "$HOME/.config/autostart/noid-background.desktop"' \
    "M33 manual-only gate rejects a per-user autostart writer"
assert_manual_only_rejects "$KS_FILE" \
    'stage_root_file /etc/skel/.config/systemd/user/noid-background.service 0644 <<UNIT_EOF' \
    "M33 manual-only gate rejects a skel user-service writer"

# Installer verification must check the actual CLI stems, not the unrelated
# string "operational-hygiene".
assert_grep_fixed '-name "noid-integrity-check.${unit_kind}"' "$KS_FILE" \
    "runtime unit gate checks the integrity CLI stem"
assert_grep_fixed '-name "noid-firefox-create-isolated-profile.${unit_kind}"' "$KS_FILE" \
    "runtime unit gate checks the isolated-profile CLI stem"
assert_not_grep '\*operational-hygiene\*\.\${unit_kind}' "$KS_FILE" \
    "runtime unit gate no longer checks an impossible artifact name"

# --- Installer file and relabel postconditions -----------------------------

assert_grep_fixed 'set -euo pipefail' "$KS_FILE" \
    "M33 installer treats unset variables as errors"
assert_grep_fixed 'verify_owned_regular()' "$KS_FILE" \
    "M33 installer verifies regular-file ownership and link count"
assert_grep_fixed 'publish_root_file()' "$KS_FILE" \
    "M33 installer publishes payloads through one checked primitive"
assert_grep_fixed 'mv -fT -- "$tmp" "$target"' "$KS_FILE" \
    "M33 payload publication atomically replaces rather than follows destinations"
assert_grep_fixed 'payload parent path contains a symlink' "$KS_FILE" \
    "M33 payload publication rejects symlinks anywhere in the parent path"
for payload_tmp in OAUTH_TMP FFPROFILE_TMP ICGUIDE_TMP NIC_TMP FFCP_TMP \
                   CRON_ALLOW_TMP AT_ALLOW_TMP STAMP_TMP; do
    assert_grep_fixed "publish_root_file \"\$$payload_tmp\"" "$KS_FILE" \
        "checked atomic publication is used for: $payload_tmp"
done
assert_not_grep_extended '^cat > /(usr|etc|var)/' "$KS_FILE" \
    "M33 installer has no direct absolute-target heredoc writes"
assert_grep_fixed 'verify_owned_regular "/usr/share/doc/noid-privacy/$doc" 644' "$KS_FILE" \
    "M33 installer verifies exact documentation metadata"
assert_grep_fixed 'verify_owned_regular "$cli" 755' "$KS_FILE" \
    "M33 installer verifies exact CLI metadata"
assert_not_grep_extended '(^|[;&|[:space:]])eval([;&|[:space:]]|$)' "$KS_FILE" \
    "M33 verification executes argument vectors without eval"
assert_not_grep 'restorecon .*|| true' "$KS_FILE" \
    "M33 installer does not suppress relabel failures"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$target"' "$KS_FILE" \
    "atomic publication verifies the final payload label"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$path"' "$KS_FILE" \
    "managed directories and final metadata checks verify SELinux labels"
assert_grep_fixed 'every Module 33 payload has its canonical SELinux context' \
    "$KS_FILE" \
    "M33 final relabel pass covers every owned payload"
assert_not_grep 'restorecon not found' "$KS_FILE" \
    "M33 never skips a mandatory SELinux postcondition"
assert_grep_fixed 'publish_root_file "$CRON_ALLOW_TMP" "$CRON_ALLOW_TARGET" 644' \
    "$KS_FILE" \
    "cron.allow is readable so Cronie recognizes the root-only allowlist"
assert_grep_fixed 'publish_root_file "$AT_ALLOW_TMP" "$AT_ALLOW_TARGET" 600' \
    "$KS_FILE" \
    "at.allow stays private while Fedora at reads it through setuid-root"
assert_grep_fixed "trap 'exit 130' INT" "$KS_FILE" \
    "M33 installer maps SIGINT through the failure cleanup boundary"
assert_grep_fixed "trap 'exit 143' TERM" "$KS_FILE" \
    "M33 installer maps SIGTERM through the failure cleanup boundary"
assert_grep_fixed "trap 'exit 129' HUP" "$KS_FILE" \
    "M33 installer maps SIGHUP through the failure cleanup boundary"
assert_grep_fixed "trap '' HUP INT TERM" "$KS_FILE" \
    "M33 cleanup cannot be interrupted recursively by handled signals"

# --- Health stamp pattern (M29-M31 precedent) ------------------------------

assert_grep_fixed "stamp-33-operational-hygiene.ok"    "$KS_FILE" "stamp file path present"
assert_grep_fixed "module=33"                         "$KS_FILE" "stamp declares module=33"
assert_grep_fixed "status=ok"                          "$KS_FILE" "stamp sets status=ok"
assert_grep_fixed "/var/lib/noid-privacy"              "$KS_FILE" "stamp under /var/lib/noid-privacy/"
assert_grep_fixed 'verify_m33_health_stamp()' "$KS_FILE" \
    "M33 validates staged and final health evidence with one exact schema"
assert_grep_fixed 'STAMP_PUBLICATION_ACTIVE=1' "$KS_FILE" \
    "published M33 evidence remains removable through every final gate"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP_TMP"' "$KS_FILE" \
    "M33 verifies the staged candidate SELinux context"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M33 verifies the final stamp SELinux context"

# Historical success must be retired before the first owned payload mutation;
# replacement evidence remains after the complete verification guard.
guard_line=$(grep -n 'fails.*-gt 0' "$KS_FILE" | head -1 | cut -d: -f1 || true)
invalidate_line=$(grep -nF \
    '# M33_HEALTH_INVALIDATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
first_payload_line=$(grep -nF \
    'ensure_root_dir /usr/share/doc/noid-privacy 755' \
    "$KS_FILE" | cut -d: -f1 || true)
publish_line=$(grep -nF \
    '# M33_HEALTH_PUBLICATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
complete_line=$(grep -nF \
    'log "=== Module 33 Operational Hygiene complete ==="' \
    "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$guard_line" ] && [ -n "$invalidate_line" ] \
   && [ -n "$first_payload_line" ] && [ -n "$publish_line" ] \
   && [ -n "$complete_line" ] \
   && [ "$invalidate_line" -lt "$first_payload_line" ] \
   && [ "$guard_line" -lt "$publish_line" ] \
   && [ "$publish_line" -lt "$complete_line" ]; then
    _pass "M33 retires old health before mutation and publishes after verification"
else
    _fail "M33 health-stamp ordering is not failure-atomic"
fi

# Execute the exact production health-boundary blocks under every material
# publication failure.
m33_stamp_root="$EXEC_FIXTURE_DIR/health-stamp"
m33_stamp_state="$m33_stamp_root/state"
m33_stamp_bin="$m33_stamp_root/bin"
m33_stamp_invalidate="$m33_stamp_root/invalidate.sh"
m33_stamp_publish="$m33_stamp_root/publish.sh"
m33_stamp_uid=$(id -u)
m33_stamp_gid=$(id -g)
mkdir -p "$m33_stamp_bin"

cat > "$m33_stamp_bin/restorecon" <<'M33_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-33-operational-hygiene.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M33_STAMP_RESTORECON_EOF
cat > "$m33_stamp_bin/matchpathcon" <<'M33_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_MATCHPATHCON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-33-operational-hygiene.ok) exit 1 ;;
        esac
        ;;
esac
case "${FAKE_MATCHPATHCON_TERM:-}" in
    final)
        case "$target" in
            */stamp-33-operational-hygiene.ok)
                kill -TERM "$PPID"
                sleep 1
                ;;
        esac
        ;;
esac
exit 0
M33_STAMP_MATCHPATHCON_EOF
cat > "$m33_stamp_bin/mv" <<'M33_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M33_STAMP_MV_EOF
chmod 0700 "$m33_stamp_bin/restorecon" \
    "$m33_stamp_bin/matchpathcon" "$m33_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "STAMP_DIR=$m33_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-33-operational-hygiene.ok"'
    sed -n \
        '/^# M33_HEALTH_INVALIDATION_BEGIN$/,/^# M33_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|-o root -g root|-o $m33_stamp_uid -g $m33_stamp_gid|" \
            -e "s|0:0:755|$m33_stamp_uid:$m33_stamp_gid:755|" \
            -e "s|/usr/sbin/restorecon|$m33_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m33_stamp_bin/matchpathcon|g"
} > "$m33_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "STAMP_DIR=$m33_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-33-operational-hygiene.ok"' \
        'STAMP_TMP=' 'STAMP_PUBLICATION_ACTIVE=0' \
        'checks=47' 'fails=0'
    sed -n '/^cleanup_m33_health_stamp() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' 'trap cleanup_m33_health_stamp EXIT' \
        "trap 'exit 129' HUP" "trap 'exit 130' INT" "trap 'exit 143' TERM"
    awk '
        /^publish_root_file\(\) \{$/ { capture = 1 }
        capture { print }
        capture && /^\}$/ { exit }
    ' "$KS_FILE" |
        sed -e "s|chown root:root|chown $m33_stamp_uid:$m33_stamp_gid|g" \
            -e "s|0:0:|$m33_stamp_uid:$m33_stamp_gid:|g" \
            -e "s|/usr/sbin/restorecon|$m33_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m33_stamp_bin/matchpathcon|g"
    sed -n \
        '/^# M33_HEALTH_PUBLICATION_BEGIN$/,/^# M33_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|chown root:root|chown $m33_stamp_uid:$m33_stamp_gid|g" \
            -e "s|0:0:|$m33_stamp_uid:$m33_stamp_gid:|g" \
            -e "s|/usr/sbin/restorecon|$m33_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m33_stamp_bin/matchpathcon|g"
} > "$m33_stamp_publish"
chmod 0700 "$m33_stamp_invalidate" "$m33_stamp_publish"

mkdir -m 0755 "$m33_stamp_state"
printf '%s\n' 'module=33' 'name=operational-hygiene' 'status=ok' \
    > "$m33_stamp_state/stamp-33-operational-hygiene.ok"
assert_cmd_success "M33 rerun invalidates its prior build-success stamp" \
    env PATH="$m33_stamp_bin:$PATH" bash "$m33_stamp_invalidate"
if [ ! -e "$m33_stamp_state/stamp-33-operational-hygiene.ok" ]; then
    _pass "M33 old success evidence is absent before payload publication"
else
    _fail "M33 old success evidence is absent before payload publication"
fi

chmod 0777 "$m33_stamp_state"
printf '%s\n' 'must-survive' \
    > "$m33_stamp_state/stamp-33-operational-hygiene.ok"
assert_cmd_failure "M33 rejects shared state-directory metadata drift" \
    env PATH="$m33_stamp_bin:$PATH" bash "$m33_stamp_invalidate"
assert_eq "$m33_stamp_uid:$m33_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m33_stamp_state")" \
    "M33 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m33_stamp_state/stamp-33-operational-hygiene.ok" \
    "M33 does not traverse a drifted shared state boundary"
rm "$m33_stamp_state/stamp-33-operational-hygiene.ok"
chmod 0755 "$m33_stamp_state"

assert_cmd_failure "M33 rejects a health-stamp candidate label failure" \
    env PATH="$m33_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        bash "$m33_stamp_publish"
if [ ! -e "$m33_stamp_state/stamp-33-operational-hygiene.ok" ] \
   && [ -z "$(find "$m33_stamp_state" -maxdepth 1 \
        -name '.stamp-33-operational-hygiene.ok.*' -print -quit)" ]; then
    _pass "M33 candidate-label failure leaves no plausible health evidence"
else
    _fail "M33 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M33 retires a stamp after final-label failure" \
    env PATH="$m33_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        bash "$m33_stamp_publish"
if [ ! -e "$m33_stamp_state/stamp-33-operational-hygiene.ok" ]; then
    _pass "M33 final-label failure removes the published success stamp"
else
    _fail "M33 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M33 quarantines a published stamp on SIGTERM before final verification" \
    env PATH="$m33_stamp_bin:$PATH" FAKE_MATCHPATHCON_TERM=final \
        bash "$m33_stamp_publish"
if [ ! -e "$m33_stamp_state/stamp-33-operational-hygiene.ok" ] \
   && [ -z "$(find "$m33_stamp_state" -maxdepth 1 \
        -name '.stamp-33-operational-hygiene.ok.*' -print -quit)" ]; then
    _pass "M33 SIGTERM window leaves no published or staged success evidence"
else
    _fail "M33 SIGTERM window leaves no published or staged success evidence"
fi

assert_cmd_failure "M33 rejects an atomic health-stamp rename failure" \
    env PATH="$m33_stamp_bin:$PATH" FAKE_MV_FAIL=1 \
        bash "$m33_stamp_publish"
if [ ! -e "$m33_stamp_state/stamp-33-operational-hygiene.ok" ] \
   && [ -z "$(find "$m33_stamp_state" -maxdepth 1 \
        -name '.stamp-33-operational-hygiene.ok.*' -print -quit)" ]; then
    _pass "M33 rename failure leaves no stamp or staged candidate"
else
    _fail "M33 rename failure leaves no stamp or staged candidate"
fi

assert_cmd_success "M33 publishes exact health evidence after all gates" \
    env PATH="$m33_stamp_bin:$PATH" bash "$m33_stamp_publish"
assert_grep_fixed 'module=33' \
    "$m33_stamp_state/stamp-33-operational-hygiene.ok"
assert_grep_fixed 'name=operational-hygiene' \
    "$m33_stamp_state/stamp-33-operational-hygiene.ok"
assert_grep_fixed 'checks_passed=47' \
    "$m33_stamp_state/stamp-33-operational-hygiene.ok"
assert_grep_fixed 'checks_total=47' \
    "$m33_stamp_state/stamp-33-operational-hygiene.ok"
assert_eq 10 \
    "$(wc -l < "$m33_stamp_state/stamp-33-operational-hygiene.ok")" \
    "M33 published health stamp has the exact ten-line schema"

# --- Threat-model source attribution and claim hygiene ----------------------

assert_grep_fixed "OAuth 2.0 Security Best Current Practice (RFC 9700)" \
    "$KS_FILE" "snippet header references the current OAuth security BCP"
assert_grep_fixed "Live RPM/systemd/cron/Flatpak evidence" \
    "$KS_FILE" "snippet header distinguishes live evidence"
assert_grep_fixed "Mozilla's profile data model" \
    "$KS_FILE" "snippet header identifies the profile-data source"
assert_grep_fixed "not an OS sandbox" "$KS_FILE" \
    "snippet explicitly rejects profile-as-malware-sandbox overclaim"
assert_not_grep_extended 'SentinelOne|ShinyHunters|Katz Stealer|Chapter [125] ' \
    "$KS_FILE" "vendor campaigns and obsolete chapter claims are absent"

test_finish

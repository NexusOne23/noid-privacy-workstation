#!/bin/bash
# Module 11b regression gate: DNS diagnostics remain manual, evidence-first
# and non-mutating. This deliberately rejects the superseded timer/recovery
# design instead of merely checking that the new command exists.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/11b-dns-health.ks"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

test_start "11b-dns-diagnostics-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "kickstart shell syntax" bash -n "$KS_FILE"
assert_grep_fixed '%post --erroronfail --log=/var/log/ks-11b-dns-diagnostics.log' \
    "$KS_FILE" "diagnostics module uses the canonical Kickstart log option"
assert_not_grep '%post --erroronfail --logfile=' "$KS_FILE" \
    "diagnostics module has no one-off Kickstart log alias"
assert_grep_fixed 'set -euo pipefail' "$KS_FILE" \
    "diagnostics installation aborts on unhandled failures"
assert_grep_fixed 'historical source filename remains 11b-dns-health.ks' \
    "$KS_FILE" "legacy source name is an explicit compatibility decision"
assert_grep_fixed \
    "stat -c '%U:%G:%a:%h' /usr/local/bin/noid-dns-diagnose" \
    "$KS_FILE" "compose verification binds diagnostic CLI metadata"
assert_grep_fixed \
    '/usr/share/doc/noid-privacy/11b-dns-diagnostics.md' \
    "$KS_FILE" "compose verification covers the diagnostic documentation"
assert_grep_fixed 'root:root:755:1' "$KS_FILE" \
    "compose verification requires the exact CLI owner/mode/link contract"
assert_grep_fixed 'root:root:644:1' "$KS_FILE" \
    "compose verification requires the exact document owner/mode/link contract"

SCRIPT="$TMPDIR/noid-dns-diagnose"
DOC="$TMPDIR/11b-dns-diagnostics.md"
extract_heredoc "$KS_FILE" NOID_DNS_DIAGNOSE_SH "$SCRIPT" || _fail "diagnostic CLI extraction"
extract_heredoc "$KS_FILE" DOC_EOF "$DOC" || _fail "diagnostic documentation extraction"
chmod 0755 "$SCRIPT"

assert_cmd_success "diagnostic CLI shell syntax" bash -n "$SCRIPT"
assert_cmd_success "diagnostic CLI passes ShellCheck" shellcheck -S warning "$SCRIPT"
assert_cmd_success "help is local and succeeds" bash "$SCRIPT" help
assert_cmd_failure "help rejects trailing arguments" bash "$SCRIPT" help unexpected
assert_cmd_failure "unknown subcommand is rejected" bash "$SCRIPT" unknown-subcommand
assert_cmd_failure "option-looking probe target is rejected locally" \
    bash "$SCRIPT" probe --help

assert_grep_fixed 'status          Show local resolver, link and route state' "$SCRIPT" \
    "default status mode is locally observable"
assert_grep_fixed 'probe TARGET' "$SCRIPT" "active probe requires a supplied target"
assert_grep_fixed 'this explicit probe can send a DNS query' "$SCRIPT" \
    "active probe warns about traffic"
assert_grep_fixed 'No diagnosis is inferred from these observations.' "$SCRIPT" \
    "status output rejects causal overclaim"
assert_grep_fixed 'review it before sharing.' "$SCRIPT" \
    "the CLI itself warns before evidence leaves the machine"
assert_grep_fixed 'Preserve the complete output before changing resolver state.' "$SCRIPT" \
    "evidence preservation precedes recovery"
assert_grep_fixed 'resolvectl --no-ask-password --no-pager show-server-state' "$SCRIPT" \
    "evidence captures learned per-server feature state"
assert_grep_fixed 'if [ "$EUID" -ne 0 ]; then' "$SCRIPT" \
    "root-only server state cannot trigger an unprivileged monitor timeout"
assert_grep_fixed 'sudo noid-dns-diagnose evidence' "$SCRIPT" \
    "unprivileged evidence failure names the complete supported invocation"
for route_read in \
    'ip -4 rule show' \
    'ip -4 route show table all' \
    'ip -6 rule show' \
    'ip -6 route show table all'; do
    assert_grep_fixed "$route_read" "$SCRIPT" \
        "status captures complete local policy routing: $route_read"
done
assert_grep_fixed 'journalctl --system -u systemd-resolved.service' "$SCRIPT" \
    "evidence explicitly reads the system journal"
assert_grep_fixed '-o short-iso-precise' "$SCRIPT" \
    "journal evidence retains correlation-grade timestamps"
assert_grep_fixed 'return "$rc"' "$SCRIPT" \
    "incomplete local evidence produces a nonzero result"

for forbidden in \
    'TEST_HOST=' \
    'reset-server-features' \
    'flush-caches' \
    'systemctl restart systemd-resolved' \
    'notify-send' \
    '/var/log/noid-dns-health.log'; do
    assert_not_grep "$forbidden" "$SCRIPT" "runtime has no automatic action: $forbidden"
done

assert_not_grep 'cat > /etc/systemd/system/noid-dns-health.service' "$KS_FILE" \
    "no DNS-health service is installed"
assert_not_grep 'cat > /etc/systemd/system/noid-dns-health.timer' "$KS_FILE" \
    "no DNS-health timer is installed"
assert_not_grep 'systemctl enable noid-dns-health.timer' "$KS_FILE" \
    "no background probe is enabled"
assert_not_grep 'touch /var/lib/noid-privacy/dns-health.enabled' "$KS_FILE" \
    "no default-on sentinel is created"
assert_not_grep 'restorecon .*2>/dev/null' "$KS_FILE" \
    "diagnostic output relabel diagnostics remain visible"
assert_not_grep 'restorecon .*|| true' "$KS_FILE" \
    "diagnostic output relabel failures are not swallowed"
assert_grep_fixed 'matchpathcon -V /usr/local/bin/noid-dns-diagnose' \
    "$KS_FILE" "CLI label is verified against active SELinux policy"
assert_grep_fixed \
    'matchpathcon -V /usr/share/doc/noid-privacy/11b-dns-diagnostics.md' \
    "$KS_FILE" "documentation label is verified against active SELinux policy"

assert_grep_fixed 'A private/CGNAT DNS address is not proof' "$DOC" \
    "documentation bounds private-DNS evidence"
assert_grep_fixed 'One failed query does not distinguish route, firewall, VPN' "$DOC" \
    "documentation bounds failed-query evidence"
assert_grep_fixed 'No fixed project probe is' "$DOC" \
    "documentation states the network boundary"
assert_grep_fixed 'Only after the evidence points to stale per-server capability state' "$DOC" \
    "manual recovery is causality-gated"
assert_grep_fixed 'are not automatic fallbacks' "$DOC" \
    "destructive diagnostic fallbacks are rejected"
assert_grep_fixed 'Review it before sharing' "$DOC" \
    "documentation warns that evidence can expose local identifiers"
assert_grep_fixed 'removed routing context can limit diagnosis' "$DOC" \
    "redaction guidance states its evidence trade-off"
assert_grep_fixed 'Complete `evidence` requires root because systemd 259' "$DOC" \
    "documentation explains the privilege boundary"

assert_grep_fixed '/usr/local/bin/noid-dns-diagnose' \
    "$PROJECT_ROOT/kickstart/snippets/99-finalize.ks" \
    "finalizer requires the manual diagnostic"
assert_grep_fixed 'obsolete automatic artifact present' \
    "$PROJECT_ROOT/kickstart/snippets/99-finalize.ks" \
    "finalizer rejects superseded automatic artifacts"
assert_grep_fixed 'diagnostic CLI type, metadata, label or parser contract invalid' \
    "$PROJECT_ROOT/kickstart/snippets/99-finalize.ks" \
    "finalizer binds the installed CLI trust boundary"
assert_grep_fixed 'local evidence contract missing' \
    "$PROJECT_ROOT/kickstart/snippets/99-finalize.ks" \
    "finalizer requires every read-only evidence surface"
assert_grep_fixed 'diagnostic CLI contains an automatic query/recovery action' \
    "$PROJECT_ROOT/kickstart/snippets/99-finalize.ks" \
    "finalizer rejects automatic resolver mutation"
assert_grep_fixed 'diagnostic document type, metadata, label or privacy warning invalid' \
    "$PROJECT_ROOT/kickstart/snippets/99-finalize.ks" \
    "finalizer requires the evidence-sharing warning"

test_finish

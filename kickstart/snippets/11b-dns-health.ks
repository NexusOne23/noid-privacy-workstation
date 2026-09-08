# =============================================================================
# Module 11b — DNS diagnostics (manual, evidence-first)
# Status: LOCKED 2026-07-28 (v17) — align the interactive diagnosis CLI.
#
# The historical source filename remains 11b-dns-health.ks so the stable
# master include and paired-test convention do not churn. Every installed
# surface uses the accurate diagnostics/diagnose name; no health monitor is
# installed.
#
# A build incident previously led this module to install a default-on periodic
# probe and an automatic reset/flush/restart ladder. One incident and one
# journal phrase do not establish a general systemd-resolved failure mode, and
# a failed fixed-host query cannot identify DNSSEC, VPN, routing, firewall or
# upstream causality. Automatic recovery also destroys useful transient state.
#
# This replacement follows the repository's Root-Cause First and No
# Hype-Patches doctrines:
#   - no background timer, fixed probe target, persistent diagnostic log,
#     resolver mutation, service restart or automatic notification;
#   - default `status` and `evidence` modes read only local state;
#   - an active DNS query occurs only when the user explicitly supplies the
#     target to `probe` and is warned before traffic is generated;
#   - journal messages are evidence to correlate, never proof of root cause;
#   - recovery remains an explicit operator decision after route, resolver,
#     VPN and journal evidence has been reviewed.
#
# Covers:
#   /usr/local/bin/noid-dns-diagnose
#   /usr/share/doc/noid-privacy/11b-dns-diagnostics.md
# =============================================================================

%post --erroronfail --log=/var/log/ks-11b-dns-diagnostics.log
set -euo pipefail

echo "=============================================================="
echo "[Module 11b] Manual DNS diagnostics start"
echo "=============================================================="

# Remove artifacts from the superseded automatic design if this snippet is
# ever applied to a reused image root. Fresh composes do not contain them.
systemctl disable noid-dns-health.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/timers.target.wants/noid-dns-health.timer
rm -f /etc/systemd/system/noid-dns-health.service
rm -f /etc/systemd/system/noid-dns-health.timer
rm -f /usr/local/sbin/noid-dns-health.sh
rm -f /usr/local/bin/noid-toggle-dns-health
rm -f /var/lib/noid-privacy/dns-health.enabled
rm -f /usr/share/doc/noid-privacy/11b-dns-health-monitoring.md

cat > /usr/local/bin/noid-dns-diagnose <<'NOID_DNS_DIAGNOSE_SH'
#!/bin/bash
# Manual DNS evidence collector. Read-only unless the operator independently
# chooses and runs a recovery command after reviewing the evidence.

set -u -o pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — DNS Diagnosis" \
    NOID_FMT_AUTO_SUBTITLE="Local resolver evidence" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

usage() {
    cat <<'USAGE'
Usage: noid-dns-diagnose [status|evidence|probe TARGET|help]

  status          Show local resolver, link and route state (default; no probe)
  evidence        Root-only complete server/status/route/journal evidence
  probe TARGET    Explicitly query TARGET through the configured resolver
  help            Show this help

`probe` can generate upstream DNS traffic. The command never resets caches,
changes DNS configuration or restarts services.
USAGE
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: required command not found: $1" >&2
        exit 2
    }
}

print_status() {
    local rc=0 command_rc
    require_cmd ip
    require_cmd resolvectl
    require_cmd systemctl

    echo "== systemd-resolved service =="
    systemctl is-active systemd-resolved.service
    command_rc=$?
    if [ "$command_rc" -ne 0 ]; then
        echo "ERROR: systemd-resolved is not active (rc=$command_rc)" >&2
        rc=1
    fi

    echo
    echo "== resolver state (local observation) =="
    resolvectl --no-pager status 2>&1 || {
        command_rc=$?
        echo "ERROR: resolvectl status failed (rc=$command_rc)" >&2
        rc=1
    }

    echo
    echo "== IPv4 policy rules (local observation) =="
    ip -4 rule show 2>&1 || {
        command_rc=$?
        echo "ERROR: IPv4 policy-rule read failed (rc=$command_rc)" >&2
        rc=1
    }

    echo
    echo "== IPv4 routes, all tables (local observation) =="
    ip -4 route show table all 2>&1 || {
        command_rc=$?
        echo "ERROR: IPv4 route-table read failed (rc=$command_rc)" >&2
        rc=1
    }

    echo
    echo "== IPv6 policy rules (local observation) =="
    ip -6 rule show 2>&1 || {
        command_rc=$?
        echo "ERROR: IPv6 policy-rule read failed (rc=$command_rc)" >&2
        rc=1
    }

    echo
    echo "== IPv6 routes, all tables (local observation) =="
    ip -6 route show table all 2>&1 || {
        command_rc=$?
        echo "ERROR: IPv6 route-table read failed (rc=$command_rc)" >&2
        rc=1
    }

    cat <<'NOTE'

No diagnosis is inferred from these observations. A private DNS address does
not by itself prove VPN routing, and a journal "degraded feature set" message
does not by itself identify the cause of a resolution failure.
The output can contain local DNS addresses, interfaces, domains and routes;
review it before sharing.
NOTE
    return "$rc"
}

print_evidence() {
    local rc=0 command_rc
    if [ "$EUID" -ne 0 ]; then
        echo "ERROR: complete evidence includes root-only resolver server state." >&2
        echo "Re-run: sudo noid-dns-diagnose evidence" >&2
        return 2
    fi

    print_status || rc=1

    echo
    echo "== learned DNS server state (local observation) =="
    resolvectl --no-ask-password --no-pager show-server-state 2>&1 || {
        command_rc=$?
        echo "ERROR: resolver server-state read failed (rc=$command_rc)" >&2
        rc=1
    }

    echo
    echo "== recent systemd-resolved warnings/errors (local journal) =="
    require_cmd journalctl
    journalctl --system -u systemd-resolved.service --since "1 hour ago" \
        --priority=warning --no-pager -o short-iso-precise 2>&1 || {
        command_rc=$?
        echo "ERROR: resolved journal read failed (rc=$command_rc)" >&2
        rc=1
    }

    cat <<'NOTE'

Preserve the complete output before changing resolver state. Correlate event
time, link ownership, route/rule state, VPN state and a controlled query. Do not
classify an event as benign or causal from its process name or message alone.
NOTE
    return "$rc"
}

probe_target() {
    local target=$1
    require_cmd resolvectl

    case "$target" in
        ""|-*|*[!A-Za-z0-9._:%-]*)
            echo "ERROR: invalid probe target" >&2
            return 2
            ;;
    esac

    cat >&2 <<NOTICE
NOTICE: this explicit probe can send a DNS query for '$target' to the resolver
path selected by systemd-resolved. It does not prove VPN confinement or DNSSEC.
NOTICE

    resolvectl query "$target"
}

case "${1:-status}" in
    status)
        [ "$#" -eq 0 ] || [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        print_status
        ;;
    evidence)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        print_evidence
        ;;
    probe)
        [ "$#" -eq 2 ] || { usage >&2; exit 2; }
        probe_target "$2"
        ;;
    help|--help|-h)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
NOID_DNS_DIAGNOSE_SH

chmod 0755 /usr/local/bin/noid-dns-diagnose
chown root:root /usr/local/bin/noid-dns-diagnose
restorecon -F /usr/local/bin/noid-dns-diagnose
matchpathcon -V /usr/local/bin/noid-dns-diagnose

mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/11b-dns-diagnostics.md <<'DOC_EOF'
# DNS diagnostics (Module 11b)

NoID Privacy provides a manual DNS evidence collector:

```bash
noid-dns-diagnose status
sudo noid-dns-diagnose evidence
noid-dns-diagnose probe example.net
```

`status` is the default and reads local `systemd-resolved`, policy-rule and
all-table route state. Complete `evidence` requires root because systemd 259
exposes its learned per-server state through a privileged monitor endpoint; it
also prints recent warning/error events from the local system journal. Neither
command sends a deliberate test query or changes the system.

The output can contain DNS-server addresses, interface names, search domains,
local routes and journal messages. Review it before sharing; redact identifiers
only with the understanding that removed routing context can limit diagnosis.

`probe TARGET` is an explicit active test. The supplied name or address may be
visible to the configured resolver and network path. No fixed project probe is
scheduled in the background.

## What the tool does not claim

- A private/CGNAT DNS address is not proof that DNS is routed through a VPN.
- An active tunnel interface is not proof that all DNS or default traffic uses
  that tunnel.
- A `Using degraded feature set` message records a resolver decision; by
  itself it does not prove a permanent cache bug or the cause of a later
  `SERVFAIL`.
- One successful query does not prove leak-freedom, DNSSEC validation or
  provider availability.
- One failed query does not distinguish route, firewall, VPN, resolver,
  upstream, DNSSEC or target failure.

## Root-cause workflow

1. Save `sudo noid-dns-diagnose evidence` before changing resolver state.
2. Record the affected name, exact time and application error.
3. Use the captured routing domains, policy rules and route tables to confirm
   which resolved link owns the query and which interface reaches its DNS
   server. Inspect firewall and VPN-provider state separately when involved.
4. Run `probe TARGET` only if generating that query is acceptable.
5. Compare with a controlled known-good name and, where possible, capture both
   the local stub request and upstream path in an isolated test environment.
6. Only after the evidence points to stale per-server capability state, an
   operator may deliberately run `sudo resolvectl reset-server-features`, then
   repeat the same probe and preserve before/after evidence.

`flush-caches` and restarting `systemd-resolved` are not automatic fallbacks:
they discard state, can interrupt applications and can hide the original
failure. Use them only for a separately established reason.

## Privacy and lifecycle

The image installs no DNS-health service, timer, fixed query target, persistent
diagnostic log or desktop notification. The tool never changes DNS provider,
DNSSEC mode, VPN configuration, routes, firewall policy or resolver state.

Related controls:

- Module 05: resolver configuration and LAN-discovery policy
- Module 06: VPN-zone and optional WAN-strict controls
- Module 11: chrony NTS
- Module 23: NetworkManager link/DNS ownership
DOC_EOF

chmod 0644 /usr/share/doc/noid-privacy/11b-dns-diagnostics.md
chown root:root /usr/share/doc/noid-privacy/11b-dns-diagnostics.md
restorecon -F /usr/share/doc/noid-privacy/11b-dns-diagnostics.md
matchpathcon -V /usr/share/doc/noid-privacy/11b-dns-diagnostics.md

fail=0
if [ -f /usr/local/bin/noid-dns-diagnose ] && \
   [ ! -L /usr/local/bin/noid-dns-diagnose ] && \
   [ -x /usr/local/bin/noid-dns-diagnose ] && \
   [ "$(stat -c '%U:%G:%a:%h' /usr/local/bin/noid-dns-diagnose \
        2>/dev/null || true)" = root:root:755:1 ] && \
   bash -n /usr/local/bin/noid-dns-diagnose && \
   /usr/local/bin/noid-dns-diagnose help >/dev/null && \
   ! /usr/local/bin/noid-dns-diagnose help unexpected >/dev/null 2>&1; then
    echo "  [OK] diagnostic CLI regular/owned + syntax valid"
else
    echo "  [FAIL] diagnostic CLI missing, unsafe or invalid"
    fail=$((fail + 1))
fi
if [ -f /usr/share/doc/noid-privacy/11b-dns-diagnostics.md ] && \
   [ ! -L /usr/share/doc/noid-privacy/11b-dns-diagnostics.md ] && \
   [ "$(stat -c '%U:%G:%a:%h' \
        /usr/share/doc/noid-privacy/11b-dns-diagnostics.md \
        2>/dev/null || true)" = root:root:644:1 ] && \
   grep -qFx '# DNS diagnostics (Module 11b)' \
        /usr/share/doc/noid-privacy/11b-dns-diagnostics.md && \
   grep -qF 'Review it before sharing' \
        /usr/share/doc/noid-privacy/11b-dns-diagnostics.md; then
    echo "  [OK] diagnostic documentation regular/owned + valid"
else
    echo "  [FAIL] diagnostic documentation missing, unsafe or invalid"
    fail=$((fail + 1))
fi

for obsolete in \
    /usr/local/sbin/noid-dns-health.sh \
    /usr/local/bin/noid-toggle-dns-health \
    /etc/systemd/system/noid-dns-health.service \
    /etc/systemd/system/noid-dns-health.timer \
    /etc/systemd/system/timers.target.wants/noid-dns-health.timer \
    /var/lib/noid-privacy/dns-health.enabled \
    /usr/share/doc/noid-privacy/11b-dns-health-monitoring.md; do
    if [ -e "$obsolete" ] || [ -L "$obsolete" ]; then
        echo "  [FAIL] obsolete automatic DNS-health artifact remains: $obsolete"
        fail=$((fail + 1))
    fi
done

if [ "$fail" -gt 0 ]; then
    echo "[Module 11b] FAILED ($fail checks)"
    exit 1
fi

echo "[Module 11b] Done — manual, evidence-first DNS diagnostics installed"
echo "  Local status: noid-dns-diagnose status"
echo "  Explicit probe: noid-dns-diagnose probe TARGET"
echo "=============================================================="
%end

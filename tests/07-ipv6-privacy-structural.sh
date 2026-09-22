#!/bin/bash
# 07-ipv6-privacy-structural — M07 regression test
#
# Covers: exact gai.conf address-order policy, sysctl hardening,
# topology-authoritative WAN detection, transactional policy and sandbox.
# Would catch: partial precedence tables, name-based physical bypasses,
# unexpected active sysctls or a widened firstboot service.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/07-ipv6-privacy.ks"

test_start "07-ipv6-privacy-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"

# gai.conf: complete RFC 6724 policy with the documented IPv4 preference.
assert_grep_fixed "/etc/gai.conf" "$KS_FILE"
assert_grep_extended 'precedence.*::ffff:0:0/96.*100' "$KS_FILE"

# Core sysctl file. Its name is load-bearing: forwarding must apply before
# M02 reasserts reset-sensitive IPv4 hardening in 99-hardening.conf.
assert_grep_fixed "/etc/sysctl.d/98-privacy-network.conf" "$KS_FILE"
assert_grep_fixed "rm -f /etc/sysctl.d/99-privacy-network.conf" "$KS_FILE" \
    "M07 retires the ordering-defective sysctl filename"

# NoID Privacy pins forwarding off but does not override Linux's randomized
# per-connection TCP timestamp default.
assert_grep_extended 'net\.ipv4\.ip_forward\s*=\s*0' "$KS_FILE"

# Per-WAN disable script + its sysctl target
assert_grep_fixed "/usr/local/sbin/noid-wan-ipv6-disable.sh" "$KS_FILE"
assert_grep_fixed "/etc/sysctl.d/99-wan-ipv6-off.conf" "$KS_FILE"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
extract_heredoc "$KS_FILE" "SCRIPT_EOF" "$TMPDIR/wan-ipv6-disable.sh" \
    || _fail "WAN IPv6 helper extraction"
extract_heredoc "$KS_FILE" "SYSCTL_EOF" "$TMPDIR/98-privacy-network.conf" \
    || _fail "M07 privacy sysctl extraction"
extract_heredoc "$KS_FILE" "GAI_EOF" "$TMPDIR/gai.conf" \
    || _fail "M07 gai.conf extraction"
extract_heredoc "$KS_FILE" "IPV6_DOC_EOF" "$TMPDIR/07-physical-ipv6-boundary.md" \
    || _fail "M07 physical IPv6 boundary doc extraction"
extract_heredoc "$KS_FILE" "SVC_EOF" "$TMPDIR/wan-ipv6-firstboot.service" \
    || _fail "WAN IPv6 firstboot unit extraction"
extract_heredoc "$KS_FILE" "WAN_IPV6_TMPFILES_EOF" "$TMPDIR/wan-ipv6.tmpfiles" \
    || _fail "WAN IPv6 tmpfiles extraction"
extract_heredoc "$KS_FILE" "REFRESH_EOF" "$TMPDIR/wan-ipv6-refresh.sh" \
    || _fail "WAN IPv6 dispatcher extraction"

cat > "$TMPDIR/gai-policy.expected" <<'GAI_POLICY_EXPECTED'
label ::1/128       0
label ::/0          1
label 2002::/16     2
label ::/96         3
label ::ffff:0:0/96 4
label 2001:0::/32   5
label fc00::/7      13
label fec0::/10     11
label 3ffe::/16     12
precedence  ::1/128       50
precedence  ::/0          40
precedence  2002::/16     30
precedence ::/96           1
precedence ::ffff:0:0/96 100
precedence fec0::/10       1
precedence 3ffe::/16       1
precedence fc00::/7        3
precedence 2001:0::/32     5
scopev4 ::ffff:169.254.0.0/112  2
scopev4 ::ffff:127.0.0.0/104    2
scopev4 ::ffff:0.0.0.0/96       14
GAI_POLICY_EXPECTED
grep -E '^(label|precedence|scopev4)[[:space:]]' "$TMPDIR/gai.conf" \
    > "$TMPDIR/gai-policy.actual"
assert_cmd_success "gai.conf has exactly the complete reviewed policy" \
    diff -u "$TMPDIR/gai-policy.expected" "$TMPDIR/gai-policy.actual"
assert_not_grep '^scopev4 ::/96' "$TMPDIR/gai.conf" \
    "gai.conf contains no silently ignored non-mapped scopev4 prefix"
assert_grep_fixed 'Sorts IPv4-mapped destinations' "$TMPDIR/gai.conf" \
    "gai.conf states its actual destination-order behavior"
assert_grep_fixed 'does not control A/AAAA DNS query' "$TMPDIR/gai.conf" \
    "gai.conf does not claim to suppress DNS lookups"
assert_not_grep '1-5s\|app-startup\|prefer v4 lookups\|glibc 2\.35' "$KS_FILE" \
    "M07 contains no unmeasured DNS or latency claim"

assert_cmd_success "WAN IPv6 helper is valid bash" bash -n "$TMPDIR/wan-ipv6-disable.sh"
assert_cmd_success "WAN IPv6 dispatcher is valid bash" bash -n "$TMPDIR/wan-ipv6-refresh.sh"
assert_grep_fixed 'systemd-sysctl reload previously applied M02' "$KS_FILE" \
    "M07 records the reproduced cross-file reset mechanism"
assert_grep_fixed '98 prefix fixes the dependency using' "$KS_FILE" \
    "M07 documents native lexical convergence"
assert_not_grep 'noid-ipv4-redirect-converge\|PathChanged=/run/libvirt/network' \
    "$KS_FILE" "M07 carries no redundant runtime convergence machinery"
assert_grep_fixed 'IFACE="${1:-}"' "$TMPDIR/wan-ipv6-refresh.sh" \
    "WAN IPv6 dispatcher treats missing interface context as empty"
assert_grep_fixed 'ACTION="${2:-}"' "$TMPDIR/wan-ipv6-refresh.sh" \
    "WAN IPv6 dispatcher treats missing action context as empty"
assert_cmd_success "manual context-free WAN IPv6 invocation exits cleanly" \
    bash "$TMPDIR/wan-ipv6-refresh.sh"
assert_grep_fixed '[ -d "$SYS_CLASS_NET/$iface/device" ]' \
    "$TMPDIR/wan-ipv6-disable.sh" \
    "helper classifies physical links by sysfs hardware backing"
assert_not_grep 'case "\$iface" in' "$TMPDIR/wan-ipv6-disable.sh" \
    "administrator-controlled interface prefixes cannot bypass enforcement"
assert_grep_fixed '[[ "$IFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || exit 0' \
    "$TMPDIR/wan-ipv6-refresh.sh" \
    "dispatcher validates the kernel interface-name grammar"
assert_grep_fixed \
    "rd\\.live\\.image(=[^[:space:]]*)?([[:space:]]|$)" \
    "$TMPDIR/wan-ipv6-refresh.sh" \
    "dispatcher recognizes only the exact live-image key, optionally valued"
assert_not_grep 'case "\$IFACE" in' "$TMPDIR/wan-ipv6-refresh.sh" \
    "dispatcher has no name-based physical-device deny-list"
assert_not_grep_extended 'Description=.*(Audit|Release|#[0-9])' \
    "$TMPDIR/wan-ipv6-firstboot.service" \
    "installed firstboot unit contains no internal history anchors"
assert_not_grep '^[[:space:]]*net\.ipv4\.tcp_timestamps[[:space:]]*=' \
    "$TMPDIR/98-privacy-network.conf" \
    "M07 does not override the maintained randomized TCP timestamp default"
assert_grep_fixed 'random offset per connection' "$TMPDIR/98-privacy-network.conf" \
    "M07 records the actual Linux timestamp privacy mechanism"
assert_not_grep 'PAWS not critical\|privacy gain outweighs' "$KS_FILE" \
    "M07 makes no unmeasured protocol-cost dismissal"
assert_grep_fixed 'does not support physical-WAN IPv6 as one coherent' \
    "$TMPDIR/07-physical-ipv6-boundary.md" \
    "M07 states the actual physical IPv6 support boundary"
assert_grep_fixed 'ships no partial “re-enable” recipe' \
    "$TMPDIR/07-physical-ipv6-boundary.md" \
    "M07 does not publish a self-reverting IPv6 procedure"
assert_grep_fixed 'SLAAC, DHCPv6 and reviewed static addressing' \
    "$TMPDIR/07-physical-ipv6-boundary.md" \
    "future physical IPv6 support has an explicit qualification matrix"
assert_not_grep 'sudo nmcli connection modify\|sudo sysctl -w.*disable_ipv6=0\|sudo systemctl disable.*noid-wan-ipv6' \
    "$TMPDIR/07-physical-ipv6-boundary.md" \
    "installed boundary doc contains no partial reactivation commands"
assert_grep_fixed 'rm -f /usr/share/doc/noid-privacy/07-ipv6-reactivate.md' \
    "$KS_FILE" "rerun deletes the retired broken reactivation guide"
assert_grep_fixed \
    'ExecStart=/usr/local/sbin/noid-wan-ipv6-disable.sh --defer-missing-network' \
    "$TMPDIR/wan-ipv6-firstboot.service" \
    "firstboot requests the bounded no-NIC deferred mode explicitly"
assert_grep_fixed 'the disposable overlay' \
    "$TMPDIR/wan-ipv6-firstboot.service" \
    "Live firstboot skip is attributed to the generated sysctl overlay"
assert_not_grep 'targets the installed.*NetworkManager profiles' \
    "$TMPDIR/wan-ipv6-firstboot.service" \
    "M07 does not claim ownership of NetworkManager profiles"
assert_not_grep 'Environment=NOID_WAN_IPV6_DEFER_MISSING_NETWORK' \
    "$TMPDIR/wan-ipv6-firstboot.service" \
    "production deferred behavior is not an ambient environment override"
assert_not_grep 'NetworkManager-wait-online.service' \
    "$TMPDIR/wan-ipv6-firstboot.service" \
    "WAN IPv6 helper cannot hold boot for online state"
assert_grep_fixed 'deferred (default IPv6 disable remains active)' \
    "$TMPDIR/wan-ipv6-disable.sh" \
    "deferred state preserves the global default-disable layer"
assert_grep_fixed 'f /run/lock/noid-wan-ipv6.lock 0600 root root -' \
    "$TMPDIR/wan-ipv6.tmpfiles" \
    "tmpfiles pre-creates the exact root-private transaction lock"
assert_grep_fixed 'CapabilityBoundingSet=CAP_NET_ADMIN' \
    "$TMPDIR/wan-ipv6-firstboot.service" \
    "firstboot retains only the capability required for the network sysctl"
assert_grep_fixed 'UMask=0077' "$TMPDIR/wan-ipv6-firstboot.service" \
    "firstboot creates private transient files by default"
assert_grep_fixed 'ProtectKernelModules=yes' "$TMPDIR/wan-ipv6-firstboot.service" \
    "firstboot cannot load kernel modules"
assert_grep_fixed \
    'ReadWritePaths=/etc/sysctl.d /run/noid-privacy /run/lock/noid-wan-ipv6.lock' \
    "$TMPDIR/wan-ipv6-firstboot.service" \
    "firstboot write allow-list contains only its policy, status and exact lock"
assert_not_grep 'ReadWritePaths=.* /run/lock \|ReadWritePaths=.* /run/systemd' \
    "$TMPDIR/wan-ipv6-firstboot.service" \
    "firstboot has no broad lock or systemd runtime write access"
assert_grep_fixed "0:0:755:1" "$KS_FILE" \
    "compose verification requires exact helper ownership, mode and link count"
assert_grep_fixed "0:0:700:1" "$KS_FILE" \
    "compose verification requires a root-private dispatcher"

# NOT .all.disable_ipv6=1 (that would break VPN killswitch which needs v6)
assert_not_grep 'net\.ipv6\.conf\.all\.disable_ipv6 = 1' "$KS_FILE"

# Tunnel interfaces stay outside the physical-link policy. The behavioural
# transaction fixture exercises this boundary; reject literal tunnel-targeted
# disable directives here as a source-level regression guard.
assert_not_grep_extended \
    'disable_ipv6.*(proton|pvpnks|wg[0-9]|tun[0-9])' \
    "$TMPDIR/wan-ipv6-disable.sh" \
    "helper contains no tunnel-specific IPv6 disable directive"
assert_grep_fixed 'net/ipv6/conf/$IFACE/disable_ipv6=1' \
    "$TMPDIR/wan-ipv6-disable.sh" \
    "live sysctl writes preserve dotted interface names"
assert_grep_fixed '-net/ipv6/conf/$IFACE/disable_ipv6 = 1' \
    "$TMPDIR/wan-ipv6-disable.sh" \
    "durable sysctl policy preserves dotted interface names"
assert_grep_fixed 'preceding dot-form only for identities without a dot' \
    "$TMPDIR/wan-ipv6-disable.sh" \
    "existing lossless policy has a bounded migration path"
assert_not_grep 'net\.ipv6\.conf\.\$IFACE\.disable_ipv6' \
    "$TMPDIR/wan-ipv6-disable.sh" \
    "helper contains no lossy dot-form interface sysctl key"
assert_grep_fixed 'EPERM because SystemCallErrorNumber=EPERM is set below' \
    "$TMPDIR/wan-ipv6-firstboot.service" \
    "seccomp ordering comment states the configured denial mode"
assert_not_grep 'SIGSYS' "$TMPDIR/wan-ipv6-firstboot.service" \
    "EPERM-configured unit does not claim filtered chown raises SIGSYS"
assert_grep_fixed 'sudo cat /etc/sysctl.d/99-wan-ipv6-off.conf' \
    "$TMPDIR/07-physical-ipv6-boundary.md" \
    "diagnostics read the root-only policy through sudo"
assert_grep_fixed 'sudo journalctl -b -t noid-wan-ipv6-refresh' \
    "$TMPDIR/07-physical-ipv6-boundary.md" \
    "diagnostics query dispatcher-tag records independently"
assert_grep_fixed 'sudo journalctl -b -t noid-wan-v6' \
    "$TMPDIR/07-physical-ipv6-boundary.md" \
    "diagnostics query helper-tag records independently"
assert_grep_fixed 'sudo journalctl -b -u noid-wan-ipv6-disable-firstboot.service' \
    "$TMPDIR/07-physical-ipv6-boundary.md" \
    "diagnostics query firstboot-unit records independently"
assert_not_grep_extended 'journalctl.*-t.*\\$' \
    "$TMPDIR/07-physical-ipv6-boundary.md" \
    "diagnostics do not AND a tag match with a unit match"

# --- one locked durable state + awaited pre-activation enforcement ----------
assert_grep_fixed 'flock -x 9' "$TMPDIR/wan-ipv6-disable.sh" \
    "all IPv6 policy transitions share one lock"
assert_grep_fixed 'lock path changed during open' "$TMPDIR/wan-ipv6-disable.sh" \
    "lock acquisition detects path replacement"
assert_grep_fixed 'STAGED_FILE=$(mktemp' "$TMPDIR/wan-ipv6-disable.sh" \
    "sysctl policy is staged before publication"
assert_grep_fixed 'mv -fT "$STAGED_FILE" "$SYSCTL_FILE"' \
    "$TMPDIR/wan-ipv6-disable.sh" "validated sysctl policy is atomically renamed"
assert_grep_fixed 'NOID_WAN_IPV6_STATUS_V1' "$TMPDIR/wan-ipv6-disable.sh" \
    "helper publishes a closed machine-readable runtime status"
assert_grep_fixed 'rm -f /var/lib/noid-privacy/wan-ipv6-off.state' "$KS_FILE" \
    "rerun removes the retired second durable state file"
assert_not_grep 'STATE_FILE=.*wan-ipv6-off.state\|cat > "\$STATE_FILE"' \
    "$TMPDIR/wan-ipv6-disable.sh" \
    "helper has no second durable policy file that can disagree"
assert_grep_fixed 'runtime IPv6 disable verification failed' "$KS_FILE" \
    "helper verifies the live kernel value before durable publication"
assert_grep_fixed 'existing sysctl policy contains unexpected active directives' \
    "$TMPDIR/wan-ipv6-disable.sh" \
    "helper rejects injected active sysctls in its durable policy"
assert_grep_fixed 'case "$ACTION" in pre-up|up)' "$TMPDIR/wan-ipv6-refresh.sh" \
    "dispatcher owns both awaited pre-up enforcement and up reconciliation"
assert_grep_fixed '"${HELPER_CMD[@]}" --interface "$IFACE"' \
    "$TMPDIR/wan-ipv6-refresh.sh" \
    "dispatcher passes the event interface instead of guessing a route"
assert_not_grep '2>&1 | logger\|exit 0 on any error\|must NEVER block' \
    "$TMPDIR/wan-ipv6-refresh.sh" \
    "dispatcher cannot hide helper failure behind logger or unconditional success"
assert_grep_fixed 'exit "$rc"' "$TMPDIR/wan-ipv6-refresh.sh" \
    "dispatcher propagates the load-bearing helper failure"
assert_grep_fixed 'ln -sfn ../55-wan-ipv6-refresh' "$KS_FILE" \
    "physical pre-up invokes the same audited dispatcher"
assert_grep_fixed '/etc/NetworkManager/dispatcher.d/55-wan-ipv6-refresh' "$KS_FILE" "dispatcher 55-wan-ipv6-refresh"
assert_grep_fixed 'STEP 4b' "$KS_FILE" "STEP 4b NEW marker"

test_finish

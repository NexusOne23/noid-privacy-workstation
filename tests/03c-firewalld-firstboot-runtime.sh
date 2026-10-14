#!/bin/bash
# Isolated runtime contract for Module 03's first-boot firewalld safety net.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT=$(find_project_root)
KS_FILE="$ROOT/kickstart/snippets/03-firewalld.ks"
# The fixture executes command doubles; keep it off the image's noexec /tmp
# even when a caller exports TMPDIR=/tmp.
TMPDIR=$(mktemp -d /var/tmp/noid-test-03c.XXXXXX)
trap 'find "$TMPDIR" -depth -delete' EXIT

test_start "03c-firewalld-firstboot-runtime"

ENFORCER="$TMPDIR/noid-firewalld-zone-enforce.sh"
extract_heredoc "$KS_FILE" ENFORCE_EOF "$ENFORCER" \
    || { _fail "firstboot enforcer extraction"; test_finish; exit; }
assert_cmd_success "firstboot enforcer parses as Bash" bash -n "$ENFORCER"

MOCKBIN="$TMPDIR/bin"
SYS_NET="$TMPDIR/sys-class-net"
mkdir -p "$MOCKBIN" \
    "$SYS_NET/eth0/device" "$SYS_NET/wlan0/device" "$SYS_NET/virbr0"
printf '%s\n' 02:00:00:00:00:10 > "$SYS_NET/eth0/address"
printf '%s\n' 02:00:00:00:00:11 > "$SYS_NET/wlan0/address"
printf '%s\n' 52:54:00:aa:bb:cc > "$SYS_NET/virbr0/address"

cat > "$MOCKBIN/logger" <<'MOCK_LOGGER'
#!/bin/bash
printf 'logger %s\n' "$*" >> "$MOCK_CALLS"
MOCK_LOGGER

cat > "$MOCKBIN/firewall-cmd" <<'MOCK_FIREWALL'
#!/bin/bash
set -euo pipefail
printf 'firewall-cmd %s\n' "$*" >> "$MOCK_CALLS"
iface_arg=''
for arg in "$@"; do
    case "$arg" in --change-interface=*) iface_arg=${arg#*=} ;; esac
done

ssh_key=''
case "$*" in
    *'--zone=drop --query-service=ssh'*) ssh_key=drop ;;
    *'--zone=libvirt --query-service=ssh'*) ssh_key=libvirt ;;
    *'--policy=libvirt-to-host --query-service=ssh'*) ssh_key=libvirt-to-host ;;
esac
if [ -n "$ssh_key" ]; then
    if [ -e "$MOCK_STATE_DIR/ssh-removed-$ssh_key" ]; then
        printf '%s\n' no
        exit 1
    fi
    printf '%s\n' yes
    exit 0
fi

case "$*" in
    *'--zone=drop --remove-service=ssh'*)
        touch "$MOCK_STATE_DIR/ssh-removed-drop" ;;
    *'--zone=libvirt --remove-service=ssh'*)
        touch "$MOCK_STATE_DIR/ssh-removed-libvirt" ;;
    *'--policy=libvirt-to-host --remove-service=ssh'*)
        touch "$MOCK_STATE_DIR/ssh-removed-libvirt-to-host" ;;
    '--permanent --get-zones')
        printf '%s\n' 'drop libvirt' ;;
    '--permanent --get-policies')
        printf '%s\n' 'allow-host-ipv6 libvirt-to-host' ;;
    '--reload')
        printf '%s\n' reload >> "$MOCK_STATE_DIR/reloads" ;;
    '--permanent --zone=drop --change-interface='*)
        printf '%s\n' "$iface_arg" >> "$MOCK_STATE_DIR/permanent-ifaces" ;;
    '--zone=drop --change-interface='*)
        touch "$MOCK_STATE_DIR/runtime-$iface_arg" ;;
    '--get-zone-of-interface='*)
        iface=${1#*=}
        if [ -e "$MOCK_STATE_DIR/runtime-$iface" ]; then
            printf '%s\n' drop
        else
            printf '%s\n' public
        fi ;;
    *'--info-policy=allow-host-ipv6'*)
        printf '%s\n' \
            'allow-host-ipv6 (active)' \
            '  disable: no' \
            '  priority: -15000' \
            '  target: CONTINUE' \
            '  ingress-zones: ANY' \
            '  egress-zones: HOST' \
            '  services: ' \
            '  ports: ' \
            '  protocols: ' \
            '  masquerade: no' \
            '  forward-ports: ' \
            '  source-ports: ' \
            '  icmp-blocks: ' ;;
    '--permanent --policy=allow-host-ipv6 --get-priority')
        printf '%s\n' -15000 ;;
    '--permanent --policy=allow-host-ipv6 --get-target')
        printf '%s\n' CONTINUE ;;
    '--permanent --policy=allow-host-ipv6 --list-ingress-zones')
        printf '%s\n' ANY ;;
    '--permanent --policy=allow-host-ipv6 --list-egress-zones')
        printf '%s\n' HOST ;;
    '--policy=allow-host-ipv6 --list-rich-rules'|\
    '--permanent --policy=allow-host-ipv6 --list-rich-rules')
        printf '%s\n' \
            'rule family="ipv6" icmp-type name="mld-listener-done" accept' \
            'rule family="ipv6" icmp-type name="mld-listener-query" accept' \
            'rule family="ipv6" icmp-type name="mld-listener-report" accept' \
            'rule family="ipv6" icmp-type name="mld2-listener-report" accept' \
            'rule family="ipv6" icmp-type name="neighbour-advertisement" accept' \
            'rule family="ipv6" icmp-type name="neighbour-solicitation" accept'
        if [ "${MOCK_EXTRA_RULE:-0}" = 1 ]; then
            printf '%s\n' \
                'rule family="ipv6" icmp-type name="router-advertisement" accept'
        fi ;;
    *)
        printf 'unexpected firewall-cmd arguments: %s\n' "$*" >&2
        exit 2 ;;
esac
MOCK_FIREWALL
chmod 0755 "$MOCKBIN/logger" "$MOCKBIN/firewall-cmd"

run_enforcer() {
    local state_dir=$1 stamp=$2 extra_rule=$3
    mkdir -p "$state_dir"
    env PATH="$MOCKBIN:/usr/bin:/bin" \
        MOCK_CALLS="$state_dir/calls" MOCK_STATE_DIR="$state_dir" \
        NOID_TEST_LOGGER_BACKEND="$MOCKBIN/logger" \
        MOCK_EXTRA_RULE="$extra_rule" NOID_SYS_CLASS_NET="$SYS_NET" \
        NOID_FIREWALLD_ZONE_STAMP="$stamp" \
        bash "$ENFORCER"
}

STATE_OK="$TMPDIR/state-ok"
STAMP_OK="$TMPDIR/runtime-ok/.firewalld-zone-enforced"
assert_cmd_success "all-physical firstboot transaction succeeds" \
    run_enforcer "$STATE_OK" "$STAMP_OK" 0
assert_eq 1 "$(wc -l < "$STATE_OK/reloads")" \
    "all permanent mutations commit behind exactly one reload"
assert_eq $'eth0\nwlan0' "$(sort "$STATE_OK/permanent-ifaces")" \
    "both physical interfaces receive permanent drop bindings"
assert_grep_fixed 'firewall-cmd --zone=drop --change-interface=eth0' \
    "$STATE_OK/calls" "runtime conflict is repaired for Ethernet"
assert_grep_fixed 'firewall-cmd --zone=drop --change-interface=wlan0' \
    "$STATE_OK/calls" "runtime conflict is repaired for Wi-Fi"
assert_not_grep 'change-interface=virbr0' "$STATE_OK/calls" \
    "virtual interfaces are excluded by the hardware-backed predicate"
assert_file_exists "$STAMP_OK" "completion stamp is written after every postcheck"
assert_eq 600 "$(stat -c '%a' "$STAMP_OK")" \
    "completion stamp is root-private"

STATE_BAD="$TMPDIR/state-bad"
STAMP_BAD="$TMPDIR/runtime-bad/.firewalld-zone-enforced"
assert_cmd_failure "an extra loaded IPv6 rule fails the firstboot transaction" \
    run_enforcer "$STATE_BAD" "$STAMP_BAD" 1
if [ ! -e "$STAMP_BAD" ]; then
    _pass "failed exact-policy verification cannot publish completion"
else
    _fail "failed exact-policy verification cannot publish completion"
fi
assert_grep_fixed 'rule count is 7, expected 6' "$STATE_BAD/calls" \
    "failure evidence identifies exact IPv6 rule-count drift"

test_finish

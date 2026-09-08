#!/usr/bin/env bash
# Candidate gate for the existing-user Agent policy adapter sandbox.
set -euo pipefail

TEST_NAME=08-agent-policy-adapters-runtime
PASS_ID=${1:-}
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *) echo "Usage: bash $0 {live|fresh-install|reboot}" >&2; exit 2 ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail "run as the normal GNOME user, not root"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
[[ -n ${DBUS_SESSION_BUS_ADDRESS:-} ]] || fail "session D-Bus address is missing"

unit=/usr/lib/systemd/user/noid-agent-policy-adapters.service
gate=/usr/libexec/noid-eligible-user
[[ -f $unit && ! -L $unit && $(stat -c '%U:%G:%a' "$unit") == root:root:644 ]] || \
    fail "adapter unit metadata invalid"
[[ -f $gate && ! -L $gate && -x $gate \
   && $(stat -c '%U:%G:%a' "$gate") == root:root:755 ]] || \
    fail "persistent-user gate metadata invalid"
grep -qxF 'ExecCondition=/usr/libexec/noid-eligible-user account' "$unit" || \
    fail "adapter persistent-account condition missing"
"$gate" account || fail "normal VM user did not pass the persistent-account gate"
grep -qxF 'RestrictAddressFamilies=AF_UNIX' "$unit" || \
    fail "AF_UNIX-only sandbox boundary missing"
if grep -q '^IPAddressDeny=' "$unit"; then
    fail "unenforceable user-manager IPAddressDeny directive remains"
fi
[[ $(systemctl --user show noid-agent-policy-adapters.service -p Result --value) == success ]] || \
    fail "adapter unit did not complete successfully"
state=$HOME/.local/state/noid-privacy/agent-policy-adapters.done
[[ -f $state && ! -L $state && $(stat -c '%u:%a' "$state") == "$UID:600" ]] || \
    fail "one-time adapter state is absent or unsafe"
state_before=$(stat -c '%d:%i:%s:%y:%z' "$state")
state_hash_before=$(sha256sum "$state" | cut -d' ' -f1)
systemctl --user restart noid-agent-policy-adapters.service || \
    fail "sealed adapter service did not restart cleanly"
[[ $(systemctl --user show noid-agent-policy-adapters.service -p Result --value) == success ]] || \
    fail "sealed adapter restart result is not success"
state_after=$(stat -c '%d:%i:%s:%y:%z' "$state")
state_hash_after=$(sha256sum "$state" | cut -d' ' -f1)
[[ $state_after == "$state_before" && $state_hash_after == "$state_hash_before" ]] || \
    fail "sealed adapter state was rewritten instead of reconciling exactly once"
if journalctl --user -b --no-pager -o cat 2>/dev/null \
        | grep -F 'noid-agent-policy-adapters.service: unit configures an IP firewall' \
        >/dev/null; then
    fail "user manager still logged the unenforceable IP firewall warning"
fi

probe_code=$'import errno, socket\ntry:\n    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nexcept OSError as exc:\n    raise SystemExit(0 if exc.errno == errno.EAFNOSUPPORT else 2)\nraise SystemExit(1)\n'
probe_unit=noid-af-unix-probe-${PASS_ID//-/_}.service
systemd-run --user --wait --pipe --collect --unit="$probe_unit" \
    --property=RestrictAddressFamilies=AF_UNIX \
    /usr/bin/python3 -c "$probe_code" >/dev/null || \
    fail "AF_UNIX sandbox did not reject AF_INET socket creation"

echo "PASS  $TEST_NAME [$PASS_ID]: persistent-account gate, exact-once seal and AF_UNIX sandbox exact"

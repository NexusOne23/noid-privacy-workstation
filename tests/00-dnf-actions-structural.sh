#!/bin/bash
# Every libdnf5 plain-mode action must keep helper stdout out of the plugin IPC
# parser, preserve stderr diagnostics, and make helper/postcondition failure
# transaction-visible. Every command mutates absolute host paths, so the only
# accepted option set is the installroot-safe host-only contract.
#
# Discovery uses libdnf5-actions(8)'s closed callback vocabulary rather than the
# command path, so an action whose command lives outside /usr is still found
# and judged by the same contract.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
test_start "00-dnf-actions-structural"

ACTION_CALLBACKS='pre_base_setup|post_base_setup|repos_configured|repos_loaded|pre_add_cmdline_packages|post_add_cmdline_packages|goal_resolved|pre_transaction|post_transaction'
# shellcheck disable=SC2016  # ${conf.cachedir} is libdnf5 action syntax
VSCODIUM_ACTION='repos_configured:::enabled=host-only raise_error=1:/usr/libexec/noid-vscodium-repo-key-seed --cache-root ${conf.cachedir}'
# The only reviewed exit-status mapping: the Firefox helper's language-pack
# warning (exit 75) must not fail an otherwise completed transaction.
# shellcheck disable=SC2016  # $? is evaluated by the action's shell
FIREFOX_WARNING_COMMAND='/usr/bin/sh -c (/usr/local/sbin/noid-firefox-reassert\ ||\ [\ \$?\ -eq\ 75\ ])\ >/dev/null'

# Print every action record below a directory as path:line:record.
discover_actions() {
    grep -RHnE "^[[:space:]]*(${ACTION_CALLBACKS}):" "$1" || true
}

# Print one reason per contract violation; print nothing for a safe record.
action_violations() {
    local line=$1
    if [[ $line == "$VSCODIUM_ACTION" ]]; then
        return 0
    fi
    case "$line" in
        [[:space:]]*) printf '%s\n' 'record does not start at the callback name' ;;
    esac
    case "$line" in
        *':enabled=host-only raise_error=1:/usr/bin/sh -c '*'\ >/dev/null') ;;
        *) printf '%s\n' 'not a host-only, fail-visible, stdout-isolated action' ;;
    esac
    case "$line" in
        *'2>&1'*) printf '%s\n' 'hides helper stderr diagnostics' ;;
    esac
    case "$line" in
        *'||'*|*'&&'*|*';'*)
            if [[ ${line#*:*:*:*:} != "$FIREFOX_WARNING_COMMAND" ]]; then
                printf '%s\n' 'chains or masks the helper exit status'
            fi
            ;;
    esac
}

# Negative control: the discovery and the contract must catch an unsafe action
# whose command is outside /usr, including an indented record.
FIXTURE_DIR="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
cat > "$FIXTURE_DIR/fixture.ks" <<'ACTION_FIXTURE_EOF'
cat > /etc/dnf/libdnf5-plugins/actions.d/noid-fixture.actions <<'FIXTURE_ACTIONS_EOF'
# comment lines are not actions
post_transaction:*:in::/bin/sh -c /etc/noid-fixture 2>&1
    pre_transaction:::enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-fixture\ >/dev/null
post_transaction:fixture:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-fixture\ >/dev/null
post_transaction:masked:in:enabled=host-only raise_error=1:/usr/bin/sh -c (/usr/local/sbin/noid-fixture\ ||\ true)\ >/dev/null
FIXTURE_ACTIONS_EOF
ACTION_FIXTURE_EOF
mapfile -t fixture_lines < <(discover_actions "$FIXTURE_DIR")
assert_eq 4 "${#fixture_lines[@]}" \
    "fixture: every action record is discovered, including /bin and indented commands"
fixture_unsafe=$(action_violations "${fixture_lines[0]#*:*:}")
if [[ $fixture_unsafe == *'not a host-only'* && $fixture_unsafe == *'stderr'* ]]; then
    _pass "fixture: unsafe /bin/sh action is rejected for both contract breaches"
else
    _fail "fixture: unsafe /bin/sh action escaped the contract check"
fi
fixture_indented=$(action_violations "${fixture_lines[1]#*:*:}")
if [[ -n $fixture_indented ]]; then
    _pass "fixture: indented record is judged exactly, not normalized into a pass"
else
    _fail "fixture: indented record passed the exact contract check"
fi
assert_eq '' "$(action_violations "${fixture_lines[2]#*:*:}")" \
    "fixture: safe action produces no violation"
fixture_masked=$(action_violations "${fixture_lines[3]#*:*:}")
if [[ $fixture_masked == *'masks the helper exit status'* ]]; then
    _pass "fixture: an action that masks its helper status is rejected"
else
    _fail "fixture: an action that masks its helper status passed the contract"
fi
assert_eq '' "$(action_violations "post_transaction:firefox:in:enabled=host-only raise_error=1:$FIREFOX_WARNING_COMMAND")" \
    "fixture: the reviewed Firefox warning mapping passes the contract"

mapfile -t action_lines < <(discover_actions "$PROJECT_ROOT/kickstart/snippets")

assert_eq 50 "${#action_lines[@]}" \
    "exact complete literal libdnf5 action inventory is discoverable"

for record in "${action_lines[@]}"; do
    line=${record#*:*:}
    violations=$(action_violations "$line")
    if [[ -z $violations ]]; then
        _pass "action is host-only, fail-visible, stdout-isolated and keeps stderr"
    else
        _fail "unsafe libdnf5 action contract ($violations): $record"
    fi
done

test_finish

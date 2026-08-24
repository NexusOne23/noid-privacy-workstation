#!/bin/bash
# Every libdnf5 plain-mode action must keep helper stdout out of the plugin IPC
# parser, preserve stderr diagnostics, and make helper/postcondition failure
# transaction-visible. Every command mutates absolute host paths, so the only
# accepted option set is the installroot-safe host-only contract.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
test_start "00-dnf-actions-structural"

mapfile -t action_lines < <(
    grep -RHnE '^[a-z_]+:.*:/usr/' "$PROJECT_ROOT/kickstart/snippets" || true
)

assert_eq 22 "${#action_lines[@]}" \
    "exact complete literal libdnf5 action inventory is discoverable"

for record in "${action_lines[@]}"; do
    line=${record#*:*:}
    if [[ $line == 'repos_configured:::enabled=host-only raise_error=1:/usr/libexec/noid-vscodium-repo-key-seed --cache-root ${conf.cachedir}' ]]; then
        _pass "VSCodium pre-load action is host-only, fail-visible and shell-free"
        continue
    fi
    case "$line" in
        *':enabled=host-only raise_error=1:/usr/bin/sh -c '*'\ >/dev/null')
            _pass "action is fail-visible and stdout-isolated"
            ;;
        *)
            _fail "unsafe libdnf5 action contract: $record"
            ;;
    esac
    case "$line" in
        *'2>&1'*) _fail "action hides helper stderr diagnostics: $record" ;;
        *) _pass "action preserves stderr diagnostics" ;;
    esac
done

test_finish

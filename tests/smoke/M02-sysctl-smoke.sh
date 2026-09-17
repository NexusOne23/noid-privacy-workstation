#!/bin/bash
# M02 sysctl smoke test: extract M02 %post, run in bwrap, verify sysctl
# drop-ins get written to /etc/sysctl.d with expected keys.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

smoke_start "M02-sysctl"

PROJECT_ROOT="$(project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/02-sysctl.ks"

TMP_POST=$(mktemp --tmpdir smoke-m02-post-XXXXXX.sh)
smoke_register_temp_file "$TMP_POST"

extract_post "$KS_FILE" "$TMP_POST"

# `net.core.bpf_jit_harden` is registered only in the initial network
# namespace and is consequently absent from bwrap's deliberately isolated
# `--unshare-net` procfs. Keep the product's fail-closed parser call unchanged,
# but replace that one call in the extracted smoke copy: after the sandbox has
# generated and validated all three files, this test runs the exact same
# `sysctl --dry-run` command against those bytes in the host's initial network
# namespace. No unknown-key ignore mode is permitted.
parser_call="    sysctl --dry-run -p \"\$path\" >/dev/null \\"
[ "$(grep -Fxc "$parser_call" "$TMP_POST" || true)" -eq 1 ] \
    || { _fail "M02 parser-call contract drifted"; exit 1; }
sed -i 's|^    sysctl --dry-run -p "\$path" >/dev/null \\$|    true \\|' \
    "$TMP_POST"

# Run the %post block in sandbox
if run_in_sandbox "$TMP_POST"; then
    _pass "M02 %post executed without error"
else
    _fail "M02 %post returned non-zero"
fi

# Parse every resulting file without changing a live sysctl. This runs as the
# already-required root smoke-test caller so access control cannot be confused
# with syntax or kernel-interface support.
for config in \
        /etc/sysctl.d/99-audit-fixes.conf \
        /etc/sysctl.d/99-hardening.conf \
        /etc/sysctl.d/99-userns.conf; do
    if sysctl --dry-run -p "$SANDBOX_DIR$config" >/dev/null; then
        _pass "initial-netns parser accepts $config"
    else
        _fail "initial-netns parser rejected $config"
    fi
done

# Post-run assertions: what files were created?
assert_in_sandbox '[ -f /etc/sysctl.d/99-hardening.conf ]' "99-hardening.conf exists"

# Expected critical keys
assert_in_sandbox 'grep -q "^kernel.kptr_restrict = 2" /etc/sysctl.d/99-hardening.conf' \
    "kptr_restrict = 2"
assert_in_sandbox 'grep -q "^kernel.yama.ptrace_scope = 2" /etc/sysctl.d/99-hardening.conf' \
    "yama.ptrace_scope = 2"
assert_in_sandbox 'grep -q "^user.max_user_namespaces = 256" /etc/sysctl.d/99-userns.conf' \
    "user.max_user_namespaces = 256 in dedicated userns drop-in"

# Closed metadata/content postconditions
assert_in_sandbox 'stat -c %U /etc/sysctl.d/99-hardening.conf | grep -q "^root$"' \
    "root-owned"
assert_in_sandbox '[ "$(stat -c %a /etc/sysctl.d/99-hardening.conf)" = "640" ]' \
    "mode 640 exact"
assert_in_sandbox '[ "$(grep -cE "^-?[a-z]+\\." /etc/sysctl.d/99-hardening.conf)" -eq 101 ]' \
    "99-hardening.conf has 101 directives"
assert_in_sandbox 'grep -qxF "kernel.printk = 4 4 1 4" /etc/sysctl.d/99-hardening.conf' \
    "console threshold retains kernel errors"

smoke_finish

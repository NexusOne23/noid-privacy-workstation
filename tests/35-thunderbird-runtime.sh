#!/usr/bin/env bash
# Structural contract for the candidate-only browser runtime gate.
# The actual Firefox/Thunderbird launches live under tests/pre-ship so the
# source-host suite cannot turn an older installed host into false evidence.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT=$(find_project_root)
RUNTIME_GATE="$PROJECT_ROOT/tests/pre-ship/19-browser-runtime-parity.sh"
IMAGE_GATE="$PROJECT_ROOT/tests/pre-ship/19-browser-image-parity.sh"
LICENSE_GATE="$PROJECT_ROOT/tests/pre-ship/18-browser-license-notices.sh"

test_start "35-thunderbird-runtime-contract"
assert_file_executable "$RUNTIME_GATE" "candidate browser runtime gate is executable"
assert_file_executable "$IMAGE_GATE" "root-owned browser image parity gate is executable"
assert_file_executable "$LICENSE_GATE" "browser derivative license gate is executable"
assert_cmd_success "candidate browser runtime gate parses" bash -n "$RUNTIME_GATE"
assert_cmd_success "root-owned browser image parity gate parses" bash -n "$IMAGE_GATE"
assert_cmd_success "browser derivative license gate parses" bash -n "$LICENSE_GATE"
assert_cmd_failure "runtime gate refuses an absent VM-pass identity" bash "$RUNTIME_GATE"
assert_cmd_failure "runtime gate refuses an unknown VM-pass identity" \
    bash "$RUNTIME_GATE" source-host
assert_not_grep 'echo .*SKIP' "$RUNTIME_GATE" \
    "candidate browser runtime gate contains no success-producing skip path"
assert_not_grep 'echo .*SKIP' "$IMAGE_GATE" \
    "root-owned image gate contains no success-producing skip path"
for gate in "$RUNTIME_GATE" "$IMAGE_GATE"; do
    assert_grep_fixed 'live|fresh-install|reboot) ;;' "$gate" \
        "browser gate enforces the exact three-pass identity allowlist"
done
for contract in \
    'firefox --headless --no-remote about:newtab' \
    'firefox --headless --no-remote -P playground about:newtab' \
    'thunderbird --headless --no-remote -P default-release' \
    'uBlock0@raymondhill.net' \
    'dkim_verifier@pl' \
    'firefox-playground-init.done' \
    'extensions.json' \
    'prefs.js'; do
    assert_grep_fixed "$contract" "$RUNTIME_GATE" \
        "runtime gate enforces: $contract"
done
for contract in \
    'doh-rollout.home-region' \
    'browser.region.network.url' \
    'browser.safebrowsing.malware.enabled' \
    'browser.safebrowsing.phishing.enabled' \
    'browser.safebrowsing.downloads.enabled' \
    'browser.safebrowsing.blockedURIs.enabled' \
    'browser.safebrowsing.downloads.remote.enabled' \
    'browser.safebrowsing.update.enabled' \
    'mail.openpgp.keyserver_list' \
    'privacy.clearOnShutdown.cache' \
    'privacy.clearOnShutdown.cookies' \
    'privacy.clearOnShutdown.history' \
    'mail.external_protocol_requires_permission'; do
    assert_grep_fixed "$contract" "$RUNTIME_GATE" \
        "runtime gate enforces Thunderbird 152 effective state: $contract"
done
for contract in \
    'etc/skel/.config/mozilla/firefox/default-release/user.js' \
    'etc/skel/.thunderbird/default-release/user.js' \
    'stamp-16-firefox.ok' \
    'stamp-34-firefox-playground.ok' \
    'stamp-35-thunderbird.ok' \
    'user-playground-overrides.js' \
    '18-browser-license-notices.sh'; do
    assert_grep_fixed "$contract" "$IMAGE_GATE" \
        "root-owned image gate enforces: $contract"
done
assert_grep_fixed 'cmp -s -- "$1" "$2"' "$IMAGE_GATE" \
    "root-owned image gate performs exact installed-byte comparisons"
for gate in "$RUNTIME_GATE" "$IMAGE_GATE"; do
    assert_grep_fixed \
        '(output_path / name).write_text(matches[0], encoding="utf-8")' \
        "$gate" \
        "browser source extraction preserves the heredoc payload byte-exactly"
    if grep -qF -- 'write_text(matches[0] + "\n"' "$gate"; then
        _fail "browser source extraction cannot append a synthetic blank line"
    else
        _pass "browser source extraction cannot append a synthetic blank line"
    fi
done
assert_grep_fixed \
    '$tb_skel|etc/skel/.thunderbird/default-release/user.js|600' \
    "$IMAGE_GATE" \
    "root-owned image gate preserves the private Thunderbird skeleton seed"
assert_grep_fixed \
    'installed file traverses a symlink or non-canonical path' "$IMAGE_GATE" \
    "root-owned image gate rejects symlink traversal inside a candidate root"
assert_grep_fixed '"0:0:$mode:1"' "$IMAGE_GATE" \
    "root-owned image gate authenticates owner, mode and link count"
assert_grep_fixed 'verify_installed_label "$path" "$suffix"' "$IMAGE_GATE" \
    "root-owned image gate authenticates installed SELinux labels"
assert_grep_fixed '/var/tmp/noid-browser-image.XXXXXXXX' "$IMAGE_GATE" \
    "root-owned image gate uses a private disk-backed extraction workspace"
assert_grep_fixed 'python3 -I - "$m16_repo"' "$IMAGE_GATE" \
    "root-owned image gate isolates root-level Python validation from user environment"
assert_grep_fixed \
    'require_equal "$TEST_TMP/validate-ubo-policy.py" "$ff_ubo_policy_validator"' \
    "$IMAGE_GATE" \
    "root-owned image gate binds the installed validator to its M16 source"
assert_grep_fixed 'hashlib.sha256(xpi).hexdigest()' "$IMAGE_GATE" \
    "root-owned image gate binds both delivered uBO copies to the M16 pin"
assert_grep_fixed 'assert set(statements) == expected_statements' "$IMAGE_GATE" \
    "root-owned image gate rejects additional Firefox AutoConfig statements"
assert_grep_fixed 'datetime.strptime(match.group(1).decode()' "$IMAGE_GATE" \
    "root-owned image gate requires the exact six-line health-stamp schema"
assert_grep_fixed 'verify_playground_stamp(playground_stamp_path)' "$IMAGE_GATE" \
    "root-owned image gate requires the complete M34 health-stamp schema"
assert_grep_fixed \
    'require_equal "$TEST_TMP/user-playground-overrides.js" "$ff_playground_share"' \
    "$IMAGE_GATE" \
    "root-owned image gate binds Playground overrides to the M34 source"
assert_grep_fixed 'item.get("active") is True' "$RUNTIME_GATE" \
    "runtime gate requires active browser extensions"
assert_grep_fixed 'item.get("userDisabled") is False' "$RUNTIME_GATE" \
    "runtime gate rejects disabled browser extensions"
assert_grep_fixed 'item.get("appDisabled") is False' "$RUNTIME_GATE" \
    "runtime gate rejects application-disabled browser extensions"
assert_grep_fixed \
    'require_equal "$TEST_TMP/firefox-profiles.sh"' "$RUNTIME_GATE" \
    "runtime gate authenticates the helper before sourcing it"
assert_grep_fixed \
    'require_equal /usr/share/noid-thunderbird/dkim_verifier.xpi "$TB_DKIM"' \
    "$RUNTIME_GATE" \
    "runtime gate authenticates the profile-loaded DKIM XPI"
assert_grep_fixed \
    'require_browser_exit thunderbird_process_active Thunderbird' \
    "$RUNTIME_GATE" \
    "runtime gate rejects a detached Thunderbird process after launch"
assert_grep_fixed \
    'require_absent "$FF_PLAYGROUND_PROFILE/.noid-drm-enabled"' "$RUNTIME_GATE" \
    "runtime gate requires pristine DRM consent state in Playground"
assert_not_grep 'browser.newtabpage.activity-stream.feeds.wallpaperfeed' \
    "$RUNTIME_GATE" \
    "runtime gate does not resurrect the retired Firefox wallpaperfeed preference"
assert_grep_fixed 'installed source/notice escapes candidate root' "$LICENSE_GATE" \
    "license gate confines canonical installed paths to an offline candidate root"
assert_grep_fixed "0:0:644:1" "$LICENSE_GATE" \
    "license gate authenticates exact installed notice/source metadata"
assert_grep_fixed 'state == 2 && found_begin == 1' "$LICENSE_GATE" \
    "license gate requires one complete ordered notice-marker state machine"
assert_grep_fixed 'repository notice hash differs' "$LICENSE_GATE" \
    "license gate reports pinned notice-hash drift explicitly"

LICENSE_TMP=$(mktemp -d "$PROJECT_ROOT/.test-browser-license.XXXXXX")
trap 'rm -rf -- "$LICENSE_TMP"' EXIT
LICENSE_EXTRACTOR="$LICENSE_TMP/extract-notice.sh"
awk '
    /^extract_notice\(\) \{/ { capture=1 }
    capture { print }
    capture && /^}$/ { exit }
' "$LICENSE_GATE" > "$LICENSE_EXTRACTOR"
run_license_notice_order_fixture() {
    local source="$LICENSE_TMP/source" output="$LICENSE_TMP/output"
    printf '%s\n' BEGIN exact-notice END > "$source"
    extract_notice "$source" BEGIN END "$output" || return 1
    cmp -s -- "$output" <(printf '%s\n' exact-notice) || return 1
    printf '%s\n' END BEGIN exact-notice > "$source"
    if extract_notice "$source" BEGIN END "$output"; then
        return 1
    fi
    printf '%s\n' BEGIN BEGIN exact-notice END > "$source"
    if extract_notice "$source" BEGIN END "$output"; then
        return 1
    fi
}
# Extracted from the already syntax-checked gate immediately above.
# shellcheck source=/dev/null
. "$LICENSE_EXTRACTOR"
assert_cmd_success \
    "license notice parser accepts one ordered span and rejects reordered/duplicate markers" \
    run_license_notice_order_fixture

run_license_root_escape_fixture() {
    local root="$LICENSE_TMP/root" outside="$LICENSE_TMP/outside" output
    mkdir -p "$root/usr/share/licenses" "$outside"
    cp -- "$PROJECT_ROOT/licenses/arkenfox-user.js-MIT.txt" \
        "$outside/arkenfox-user.js-MIT.txt"
    ln -s "$outside" "$root/usr/share/licenses/noid-privacy"
    if output=$(bash "$LICENSE_GATE" "$root" 2>&1); then
        return 1
    fi
    [[ $output == *"installed source/notice escapes candidate root"* ]]
}
assert_cmd_success \
    "license gate behaviorally rejects an ancestor symlink escaping an offline root" \
    run_license_root_escape_fixture

test_finish

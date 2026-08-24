#!/usr/bin/env bash
# Root-only repository -> image -> root-owned browser seed parity gate.
# Run once in each Live/fresh-install/reboot candidate pass before the paired
# normal-user 19-browser-runtime-parity.sh launch/effective-state gate.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin
export BASH_ENV=/dev/null
export ENV=/dev/null
IFS=$' \t\n'
umask 077

TEST_NAME=19-browser-image-parity
fail() { echo "FAIL  $TEST_NAME: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "run as root"
[[ $# -ge 1 && $# -le 2 ]] || {
    echo "usage: sudo $0 {live|fresh-install|reboot} [INSTALLED_ROOT]" >&2
    exit 2
}
for required_command in \
        awk bash cmp dirname matchpathcon mktemp python3 readlink rm stat; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command missing: $required_command"
done

SCRIPT_PATH=$(readlink -e -- "$0") || fail "cannot resolve gate path"
REPO_ROOT=$(cd "$(dirname "$SCRIPT_PATH")/../.." && pwd -P) || \
    fail "cannot resolve repository root"
PASS_ID=$1
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *) fail "pass identity must be live, fresh-install or reboot" ;;
esac
INSTALLED_ROOT=${2:-/}
[[ -d $INSTALLED_ROOT && ! -L $INSTALLED_ROOT ]] || \
    fail "installed root is invalid: $INSTALLED_ROOT"
INSTALLED_ROOT=$(readlink -e -- "$INSTALLED_ROOT") || \
    fail "cannot canonicalize installed root"

root_path() {
    local suffix=$1
    if [[ $INSTALLED_ROOT == / ]]; then
        printf '/%s\n' "$suffix"
    else
        printf '%s/%s\n' "$INSTALLED_ROOT" "$suffix"
    fi
}

require_repo_regular() {
    local path=$1 canonical
    [[ -f $path && ! -L $path && -s $path ]] || \
        fail "repository source is missing, empty, non-regular or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize repository source: $path"
    [[ $canonical == "$path" ]] || \
        fail "repository source path is non-canonical: $path"
}

verify_installed_label() {
    local path=$1 suffix=$2 actual expected actual_type expected_type
    if [[ $INSTALLED_ROOT == / ]]; then
        matchpathcon -V "$path" >/dev/null || \
            fail "installed SELinux label differs from policy: $path"
        return
    fi
    actual=$(stat -c '%C' -- "$path") || \
        fail "cannot read installed SELinux label: $path"
    expected=$(matchpathcon -n "/$suffix") || \
        fail "cannot resolve expected SELinux label: /$suffix"
    IFS=: read -r _ _ actual_type _ <<< "$actual"
    IFS=: read -r _ _ expected_type _ <<< "$expected"
    [[ -n $actual_type && $actual_type == "$expected_type" ]] || \
        fail "installed SELinux type differs from policy: $path"
}

require_installed_file() {
    local path=$1 suffix=$2 mode=$3 canonical metadata
    [[ -f $path && ! -L $path && -s $path ]] || \
        fail "missing, empty, non-regular or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize installed file: $path"
    [[ $canonical == "$path" ]] || \
        fail "installed file traverses a symlink or non-canonical path: $path"
    if [[ $INSTALLED_ROOT != / ]]; then
        case "$canonical" in
            "$INSTALLED_ROOT"/*) ;;
            *) fail "installed file escapes candidate root: $path" ;;
        esac
    fi
    metadata=$(stat -c '%u:%g:%a:%h' -- "$path") || \
        fail "cannot inspect installed metadata: $path"
    [[ $metadata == "0:0:$mode:1" ]] || \
        fail "installed metadata differs: $path ($metadata)"
    verify_installed_label "$path" "$suffix"
}

require_installed_dir() {
    local path=$1 suffix=$2 mode=$3 canonical metadata
    [[ -d $path && ! -L $path ]] || \
        fail "installed directory is missing, non-directory or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize installed directory: $path"
    [[ $canonical == "$path" ]] || \
        fail "installed directory traverses a symlink or non-canonical path: $path"
    if [[ $INSTALLED_ROOT != / ]]; then
        case "$canonical" in
            "$INSTALLED_ROOT"/*) ;;
            *) fail "installed directory escapes candidate root: $path" ;;
        esac
    fi
    metadata=$(stat -c '%u:%g:%a' -- "$path") || \
        fail "cannot inspect installed directory metadata: $path"
    [[ $metadata == "0:0:$mode" ]] || \
        fail "installed directory metadata differs: $path ($metadata)"
    verify_installed_label "$path" "$suffix"
}

require_equal() {
    cmp -s -- "$1" "$2" || fail "byte mismatch: $1 != $2"
}

TEST_TMP=$(mktemp -d /var/tmp/noid-browser-image.XXXXXXXX) || \
    fail "cannot create private parity workspace"
cleanup() {
    rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

m16_repo="$REPO_ROOT/kickstart/snippets/16-firefox.ks"
m34_repo="$REPO_ROOT/kickstart/snippets/34-firefox-playground.ks"
ff_repo="$REPO_ROOT/firefox/noid-firefox-hardening.js"
tb_repo="$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"
tb_cfg_repo="$REPO_ROOT/thunderbird/mozilla.cfg"
tb_autoconfig_repo="$REPO_ROOT/thunderbird/autoconfig.js"
tb_local_repo="$REPO_ROOT/thunderbird/local-settings.js"
ff_share=$(root_path usr/share/noid-firefox/user.js)
ff_skel=$(root_path etc/skel/.config/mozilla/firefox/default-release/user.js)
ff_skel_dir=${ff_skel%/*}
ff_skel_prefs=$(root_path etc/skel/.config/mozilla/firefox/default-release/extension-preferences.json)
ff_skel_ubo=$(root_path 'etc/skel/.config/mozilla/firefox/default-release/extensions/uBlock0@raymondhill.net.xpi')
ff_playground_share=$(root_path usr/share/noid-firefox/user-playground-overrides.js)
ff_cfg_share=$(root_path usr/share/noid-firefox/mozilla.cfg)
ff_cfg=$(root_path usr/lib64/firefox/mozilla.cfg)
ff_autoconfig_share=$(root_path usr/share/noid-firefox/autoconfig.js)
ff_autoconfig=$(root_path usr/lib64/firefox/defaults/pref/autoconfig.js)
ff_managed_source=$(root_path 'usr/share/noid-firefox/uBlock0@raymondhill.net.json')
ff_managed=$(root_path 'usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json')
ff_ubo=$(root_path 'usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi')
ff_ubo_policy_validator=$(root_path usr/local/lib/noid-privacy/validate-ubo-policy.py)
tb_share=$(root_path usr/share/noid-thunderbird/user.js)
tb_skel=$(root_path etc/skel/.thunderbird/default-release/user.js)
tb_skel_dir=${tb_skel%/*}
tb_cfg_share=$(root_path usr/share/noid-thunderbird/mozilla.cfg)
tb_cfg_installed=$(root_path usr/lib64/thunderbird/mozilla.cfg)
tb_autoconfig_share=$(root_path usr/share/noid-thunderbird/autoconfig.js)
tb_autoconfig_installed=$(root_path usr/lib64/thunderbird/defaults/pref/autoconfig.js)
tb_local_share=$(root_path usr/share/noid-thunderbird/local-settings.js)
tb_local_installed=$(root_path usr/lib64/thunderbird/defaults/pref/local-settings.js)
ff_stamp=$(root_path var/lib/noid-privacy/stamp-16-firefox.ok)
ff_playground_stamp=$(root_path var/lib/noid-privacy/stamp-34-firefox-playground.ok)
tb_stamp=$(root_path var/lib/noid-privacy/stamp-35-thunderbird.ok)

for path in "$m16_repo" "$m34_repo" "$ff_repo" "$tb_repo" "$tb_cfg_repo" \
        "$tb_autoconfig_repo" "$tb_local_repo"; do
    require_repo_regular "$path"
done

while IFS='|' read -r path suffix mode; do
    require_installed_file "$path" "$suffix" "$mode"
done <<INSTALLED_FILE_SPECS
$ff_share|usr/share/noid-firefox/user.js|644
$ff_skel|etc/skel/.config/mozilla/firefox/default-release/user.js|600
$ff_skel_prefs|etc/skel/.config/mozilla/firefox/default-release/extension-preferences.json|600
$ff_skel_ubo|etc/skel/.config/mozilla/firefox/default-release/extensions/uBlock0@raymondhill.net.xpi|644
$ff_playground_share|usr/share/noid-firefox/user-playground-overrides.js|644
$ff_cfg_share|usr/share/noid-firefox/mozilla.cfg|644
$ff_cfg|usr/lib64/firefox/mozilla.cfg|644
$ff_autoconfig_share|usr/share/noid-firefox/autoconfig.js|644
$ff_autoconfig|usr/lib64/firefox/defaults/pref/autoconfig.js|644
$ff_managed_source|usr/share/noid-firefox/uBlock0@raymondhill.net.json|644
$ff_managed|usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json|644
$ff_ubo|usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi|644
$ff_ubo_policy_validator|usr/local/lib/noid-privacy/validate-ubo-policy.py|755
$tb_share|usr/share/noid-thunderbird/user.js|644
$tb_skel|etc/skel/.thunderbird/default-release/user.js|600
$tb_cfg_share|usr/share/noid-thunderbird/mozilla.cfg|644
$tb_cfg_installed|usr/lib64/thunderbird/mozilla.cfg|644
$tb_autoconfig_share|usr/share/noid-thunderbird/autoconfig.js|644
$tb_autoconfig_installed|usr/lib64/thunderbird/defaults/pref/autoconfig.js|644
$tb_local_share|usr/share/noid-thunderbird/local-settings.js|644
$tb_local_installed|usr/lib64/thunderbird/defaults/pref/local-settings.js|644
$ff_stamp|var/lib/noid-privacy/stamp-16-firefox.ok|644
$ff_playground_stamp|var/lib/noid-privacy/stamp-34-firefox-playground.ok|644
$tb_stamp|var/lib/noid-privacy/stamp-35-thunderbird.ok|644
INSTALLED_FILE_SPECS
require_installed_dir "$ff_skel_dir" \
    etc/skel/.config/mozilla/firefox/default-release 700
require_installed_dir "$tb_skel_dir" etc/skel/.thunderbird/default-release 700

require_equal "$ff_repo" "$ff_share"
require_equal "$ff_share" "$ff_skel"
require_equal "$ff_cfg_share" "$ff_cfg"
require_equal "$ff_autoconfig_share" "$ff_autoconfig"
require_equal "$ff_managed_source" "$ff_managed"
require_equal "$ff_ubo" "$ff_skel_ubo"
require_equal "$tb_repo" "$tb_share"
require_equal "$tb_share" "$tb_skel"
require_equal "$tb_cfg_repo" "$tb_cfg_share"
require_equal "$tb_cfg_share" "$tb_cfg_installed"
require_equal "$tb_autoconfig_repo" "$tb_autoconfig_share"
require_equal "$tb_autoconfig_share" "$tb_autoconfig_installed"
require_equal "$tb_local_repo" "$tb_local_share"
require_equal "$tb_local_share" "$tb_local_installed"

python3 -I - "$m16_repo" "$m34_repo" "$TEST_TMP" <<'EXTRACT_BROWSER_PYEOF' || \
    fail "cannot extract unique canonical browser payloads"
import pathlib
import re
import sys

m16_path, m34_path, output_path = map(pathlib.Path, sys.argv[1:])
for source_path, marker, name in (
    (m16_path, "AUTOCONFIG_EOF", "autoconfig.js"),
    (m16_path, "UBOMANIFEST_EOF", "ubo-policy.json"),
    (m16_path, "UBO_POLICY_VALIDATOR_PYEOF", "validate-ubo-policy.py"),
    (m16_path, "SKEL_EXTENSION_PREFS_EOF", "extension-preferences.json"),
    (m34_path, "OVERRIDES_EOF", "user-playground-overrides.js"),
):
    source = source_path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"^[^\n]*<<'{re.escape(marker)}'\n(.*?)^{re.escape(marker)}$",
        flags=re.MULTILINE | re.DOTALL,
    )
    matches = pattern.findall(source)
    assert len(matches) == 1, (marker, len(matches))
    # The non-greedy group already includes the payload's terminating
    # newline immediately before the line-anchored heredoc marker. Adding
    # another newline would manufacture a byte that was never shipped.
    (output_path / name).write_text(matches[0], encoding="utf-8")
EXTRACT_BROWSER_PYEOF

require_equal "$TEST_TMP/autoconfig.js" "$ff_autoconfig_share"
require_equal "$TEST_TMP/ubo-policy.json" "$ff_managed_source"
require_equal "$TEST_TMP/validate-ubo-policy.py" "$ff_ubo_policy_validator"
require_equal "$TEST_TMP/extension-preferences.json" "$ff_skel_prefs"
require_equal "$TEST_TMP/user-playground-overrides.js" "$ff_playground_share"

python3 -I - "$ff_managed" "$ff_skel_prefs" "$ff_repo" "$ff_cfg" \
    "$ff_ubo" "$m16_repo" "$ff_stamp" "$ff_playground_stamp" "$tb_stamp" \
    <<'BROWSER_IMAGE_PYEOF' || \
    fail "browser policy, AutoConfig, XPI pin or health-stamp contract differs"
import hashlib
import json
import pathlib
import re
import sys
from datetime import datetime
from urllib.parse import quote

(
    managed_path,
    seed_preferences_path,
    source_path,
    config_path,
    xpi_path,
    kickstart_path,
    firefox_stamp_path,
    playground_stamp_path,
    thunderbird_stamp_path,
) = map(pathlib.Path, sys.argv[1:])


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, f"duplicate JSON key: {key}"
        result[key] = value
    return result


def scalar_values(source, name, value_pattern):
    return re.findall(
        rf'^{re.escape(name)}={value_pattern}$',
        source,
        flags=re.MULTILINE,
    )


kickstart = kickstart_path.read_text(encoding="utf-8")
filter_counts = scalar_values(kickstart, "EXPECTED_FILTER_LIST_COUNT", r"([0-9]+)")
ubo_versions = scalar_values(kickstart, "UBO_VERSION", r'"([^"\n]+)"')
ubo_hashes = scalar_values(kickstart, "UBO_SHA256", r'"([0-9a-f]{64})"')
ubo_sizes = scalar_values(kickstart, "UBO_SIZE_EXPECTED", r"([0-9]+)")
assert filter_counts == ["13"]
assert ubo_versions == ["1.73.0"]
assert len(ubo_hashes) == 2 and len(set(ubo_hashes)) == 1
assert len(ubo_sizes) == 2 and len(set(ubo_sizes)) == 1

xpi = xpi_path.read_bytes()
assert len(xpi) == int(ubo_sizes[0])
assert hashlib.sha256(xpi).hexdigest() == ubo_hashes[0]

expected_lists = [
    "user-filters",
    "ublock-filters",
    "ublock-badware",
    "ublock-privacy",
    "ublock-quick-fixes",
    "ublock-unbreak",
    "easylist",
    "easyprivacy",
    "urlhaus-1",
    "plowe-0",
    "adguard-spyware-url",
    "block-lan",
    "curben-phishing",
]
assert len(expected_lists) == int(filter_counts[0])
with managed_path.open(encoding="utf-8") as handle:
    managed = json.load(handle, object_pairs_hook=strict_object)
assert managed == {
    "name": "uBlock0@raymondhill.net",
    "description": (
        "NoID Privacy Workstation 44 - uBlock Origin managed "
        "filter-list baseline (Module 16)"
    ),
    "type": "storage",
    "data": {"toOverwrite": {"filterLists": expected_lists}},
}
with seed_preferences_path.open(encoding="utf-8") as handle:
    seed_preferences = json.load(handle, object_pairs_hook=strict_object)
assert seed_preferences == {
    "uBlock0@raymondhill.net": {
        "permissions": ["internal:privateBrowsingAllowed"],
        "origins": [],
        "data_collection": [],
    }
}

source = source_path.read_text(encoding="utf-8")
config = config_path.read_text(encoding="utf-8")
assert not any(
    line.startswith('user_pref("browser.uiCustomization.state"')
    for line in source.splitlines()
)
converted = "".join(
    line.replace("user_pref(", "defaultPref(", 1)
    if line.startswith("user_pref(")
    else line
    for line in source.splitlines(keepends=True)
)
header = (
    "// NoID Privacy Workstation 44 — Firefox AutoConfig (Module 16)\n"
    "// Source of truth: firefox/noid-firefox-hardening.js (sed-derived)\n"
    "// Generated at build time. To regenerate: re-run kickstart M16.\n"
    "//\n"
)
prefix = header + converted
assert config.startswith(prefix)
suffix = config[len(prefix):]


def shell_array(name):
    match = re.search(
        rf"^{re.escape(name)}=\(\n(.*?)^\)$",
        kickstart,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match
    values = re.findall(
        r"^[ \t]+'((?:defaultPref|lockPref)\(\"[^\"\n]+\", .*\);)'$",
        match.group(1),
        flags=re.MULTILINE,
    )
    assert values and len(values) == len(set(values))
    return values


user_defaults = shell_array("USER_OWNED_DEFAULT_PREFS")
lock_prefs = shell_array("EXPECTED_LOCK_PREFS")
toolbar_matches = re.findall(
    r"^TOOLBAR_DEFAULT_PREF='(defaultPref\(\""
    r"browser\.uiCustomization\.state\", .*\);)'$",
    kickstart,
    flags=re.MULTILINE,
)
assert len(toolbar_matches) == 1
toolbar_pref = toolbar_matches[0]
fixed_defaults = [
    'defaultPref("network.trr.mode", 5);',
    toolbar_pref,
    'defaultPref("browser.newtabpage.activity-stream.topSitesRows", 4);',
]
statements = []
for line in suffix.splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith("//"):
        continue
    assert re.fullmatch(r'(?:defaultPref|lockPref)\("[^"]+", .*\);', line)
    statements.append(line)
assert len(statements) == len(set(statements))

pinned = [
    line
    for line in statements
    if line.startswith('defaultPref("browser.newtabpage.pinned", ')
]
assert len(pinned) == 1
expected_statements = set(user_defaults + lock_prefs + fixed_defaults + pinned)
assert set(statements) == expected_statements
assert len(statements) == len(expected_statements)
assert 'defaultPref("extensions.ml.enabled", false);' in user_defaults
assert not any(
    line.startswith('defaultPref("browser.ml.enable",') for line in statements
)
for default_line in user_defaults:
    key = re.fullmatch(r'defaultPref\("([^"]+)", .*\);', default_line).group(1)
    assert not re.search(
        rf'^user_pref\("{re.escape(key)}",', source, flags=re.MULTILINE
    )

toolbar_literal = re.fullmatch(
    r'defaultPref\("browser\.uiCustomization\.state", '
    r'("(?:\\.|[^"\\])*")\);',
    toolbar_pref,
)
assert toolbar_literal
toolbar = json.loads(json.loads(toolbar_literal.group(1)))
assert toolbar["currentVersion"] == 24
assert toolbar["placements"]["nav-bar"].count(
    "ublock0_raymondhill_net-browser-action"
) == 1
assert toolbar["placements"]["nav-bar"].count("reset-pbm-toolbar-button") == 1

pinned_literal = re.fullmatch(
    r'defaultPref\("browser\.newtabpage\.pinned", '
    r'("(?:\\.|[^"\\])*")\);',
    pinned[0],
)
assert pinned_literal
sites = json.loads(json.loads(pinned_literal.group(1)))
expected_sites = [
    ("https://noid-privacy.com/linux.html", "NoID Privacy", "N", "#5b4bdb", "#ffffff"),
    ("https://duckduckgo.com/", "DuckDuckGo", "D", "#de5833", "#ffffff"),
    ("https://duck.ai/", "Duck.ai", "AI", "#7a5cff", "#ffffff"),
    ("https://proton.me/mail", "Proton Mail", "P", "#6d4aff", "#ffffff"),
    ("https://signal.org/", "Signal", "S", "#3a76f0", "#ffffff"),
    ("https://mullvad.net/en", "Mullvad VPN", "M", "#ffcc00", "#111111"),
    (
        "https://www.torproject.org/download/",
        "Tor Project",
        "T",
        "#7d4698",
        "#ffffff",
    ),
    (
        "https://discuss.privacyguides.net/",
        "Privacy Guides",
        "PG",
        "#246b5a",
        "#ffffff",
    ),
]
assert len(sites) == len(expected_sites)
expected_pins = []
for url, title, label, background, foreground in expected_sites:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96">'
        f'<rect width="96" height="96" rx="20" fill="{background}"/>'
        '<text x="48" y="61" text-anchor="middle" font-family="sans-serif" '
        f'font-size="36" font-weight="700" fill="{foreground}">{label}</text>'
        "</svg>"
    )
    expected_pins.append(
        {
            "url": url,
            "title": title,
            "favicon": "data:image/svg+xml," + quote(svg, safe=""),
            "faviconSize": 96,
        }
    )
assert sites == expected_pins


def verify_stamp(path, module, name):
    stamp = path.read_bytes()
    pattern = (
        rf"# NoID Privacy — Module {module} Health Stamp\n"
        rf"module={module}\n"
        rf"name={name}\n"
        rf"version=1\n"
        rf"status=ok\n"
        rf"timestamp=([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}"
        rf"T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}Z)\n"
    ).encode()
    match = re.fullmatch(pattern, stamp)
    assert match
    datetime.strptime(match.group(1).decode(), "%Y-%m-%dT%H:%M:%SZ")


def verify_playground_stamp(path):
    stamp = path.read_bytes()
    pattern = (
        rb"# NoID Privacy \xe2\x80\x94 Module 34 Health Stamp\n"
        rb"# Written at end of %post verification when all checks pass\.\n"
        rb"# Format: shell-sourceable key=value\. "
        rb"See docs/engineering-health-stamp-pattern\.md\.\n"
        rb"module=34\n"
        rb"name=firefox-playground\n"
        rb"version=1\n"
        rb"status=ok\n"
        rb"timestamp=([0-9]{4}-[0-9]{2}-[0-9]{2}"
        rb"T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)\n"
        rb"checks_passed=([1-9][0-9]*)\n"
        rb"checks_total=([1-9][0-9]*)\n"
        rb"icon_name=firefox\n"
    )
    match = re.fullmatch(pattern, stamp)
    assert match and match.group(2) == match.group(3)
    datetime.strptime(match.group(1).decode(), "%Y-%m-%dT%H:%M:%SZ")


verify_stamp(firefox_stamp_path, 16, "firefox")
verify_playground_stamp(playground_stamp_path)
verify_stamp(thunderbird_stamp_path, 35, "thunderbird")
BROWSER_IMAGE_PYEOF

python3 -I "$ff_ubo_policy_validator" "$ff_ubo" "$ff_managed" >/dev/null || \
    fail "Firefox uBO XPI no longer supports the managed filter-list policy"
bash "$REPO_ROOT/tests/pre-ship/18-browser-license-notices.sh" \
    "$INSTALLED_ROOT" >/dev/null || fail "browser derivative license parity failed"

echo "PASS  $TEST_NAME ($PASS_ID): repository/image/root-owned skel/config/stamp bytes are exact"

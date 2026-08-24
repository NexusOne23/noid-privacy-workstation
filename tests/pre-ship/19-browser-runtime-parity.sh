#!/usr/bin/env bash
# Candidate-only Firefox/Thunderbird user-profile and real-launch gate.
# Root-owned image/skel/config bytes are checked by the paired root-only
# 19-browser-image-parity.sh gate; this script proves effective user state.
# Run once in each VM pass as the normal desktop user:
#   bash tests/pre-ship/19-browser-runtime-parity.sh live
#   bash tests/pre-ship/19-browser-runtime-parity.sh fresh-install
#   bash tests/pre-ship/19-browser-runtime-parity.sh reboot
set -euo pipefail
export LC_ALL=C
export PATH=/usr/local/bin:/usr/sbin:/usr/bin
export BASH_ENV=/dev/null
export ENV=/dev/null
IFS=$' \t\n'
umask 077
unset TMPDIR

TEST_NAME=19-browser-runtime-parity
PASS_ID=unresolved
fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
note() { echo "  [$PASS_ID] $*"; }

[[ $# -eq 1 ]] || {
    echo "usage: $0 {live|fresh-install|reboot}" >&2
    exit 2
}
PASS_ID=$1
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *) fail "pass identity must be live, fresh-install or reboot" ;;
esac
for required_command in \
        awk bash cat cmp dirname find getent grep id matchpathcon mktemp pgrep \
        python3 readlink rm sed sleep stat tail timeout; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command missing: $required_command"
done

SCRIPT_PATH=$(readlink -e -- "$0") || fail "cannot resolve gate path"
REPO_ROOT=$(cd "$(dirname "$SCRIPT_PATH")/../.." && pwd -P) || \
    fail "cannot resolve repository root"
IMAGE_PARITY_GATE="$REPO_ROOT/tests/pre-ship/19-browser-image-parity.sh"
[[ -f $IMAGE_PARITY_GATE && ! -L $IMAGE_PARITY_GATE ]] || \
    fail "paired root-owned image parity gate is missing, non-regular or symlinked"
case $(stat -c '%a' -- "$IMAGE_PARITY_GATE") in
    555|755) ;;
    *) fail "paired root-owned image parity gate mode is neither ISO-safe 555 nor checkout 755" ;;
esac

USER_UID=$(id -u)
USER_GID=$(id -g)
[[ $USER_UID -ne 0 ]] || fail "must run as the normal VM desktop user"
PASSWD_HOME=$(getent passwd "$USER_UID" | \
    awk -F: 'NR == 1 { print $6 }') || fail "cannot resolve account home"
[[ -n $PASSWD_HOME && ${HOME:-} == "$PASSWD_HOME" ]] || \
    fail "HOME differs from the account database"
[[ -d $HOME && ! -L $HOME ]] || fail "account home is missing or symlinked"
[[ $(readlink -e -- "$HOME") == "$HOME" ]] || \
    fail "account home is non-canonical"
home_metadata=$(stat -c '%u:%a' -- "$HOME") || fail "cannot inspect account home"
home_mode=${home_metadata#*:}
[[ ${home_metadata%%:*} == "$USER_UID" && $home_mode =~ ^[0-7]{3,4}$ ]] || \
    fail "account home owner or mode is invalid"
(( (8#$home_mode & 0022) == 0 )) || \
    fail "account home is group/other-writable"
[[ $(grep -c '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || true) \
    -eq 1 ]] || fail "not running inside the NoID Privacy candidate"
[[ $(command -v firefox) == /usr/local/bin/firefox ]] || \
    fail "Firefox does not resolve to the NoID Privacy-owned launcher"
[[ $(command -v thunderbird) == /usr/local/bin/thunderbird ]] || \
    fail "Thunderbird does not resolve to the NoID Privacy-owned launcher"

TEST_TMP=$(mktemp -d /tmp/noid-browser-runtime.XXXXXXXX) || \
    fail "cannot create private runtime workspace"
cleanup() {
    rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_repo_file() {
    local path=$1 canonical
    [[ -f $path && ! -L $path && -s $path ]] || \
        fail "repository source is missing, empty, non-regular or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize repository source: $path"
    [[ $canonical == "$path" ]] || \
        fail "repository source path is non-canonical: $path"
}

require_root_file() {
    local path=$1 mode=$2 canonical metadata
    [[ -f $path && ! -L $path && -s $path ]] || \
        fail "root payload is missing, empty, non-regular or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize root payload: $path"
    [[ $canonical == "$path" ]] || fail "root payload path is non-canonical: $path"
    metadata=$(stat -c '%u:%g:%a:%h' -- "$path") || \
        fail "cannot inspect root payload: $path"
    [[ $metadata == "0:0:$mode:1" ]] || \
        fail "root payload metadata differs: $path ($metadata)"
    matchpathcon -V "$path" >/dev/null || \
        fail "root payload SELinux label differs: $path"
}

require_user_dir() {
    local path=$1 canonical metadata mode
    [[ -d $path && ! -L $path ]] || \
        fail "profile directory is missing, non-directory or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize profile directory: $path"
    [[ $canonical == "$path" ]] || \
        fail "profile directory path is non-canonical: $path"
    metadata=$(stat -c '%u:%g:%a' -- "$path") || \
        fail "cannot inspect profile directory: $path"
    mode=${metadata##*:}
    [[ ${metadata%%:*:*} == "$USER_UID" && $mode =~ ^[0-7]{3,4}$ ]] || \
        fail "profile directory owner or mode is invalid: $path ($metadata)"
    (( (8#$mode & 0022) == 0 )) || \
        fail "profile directory is group/other-writable: $path"
    matchpathcon -V "$path" >/dev/null || \
        fail "profile directory SELinux label differs: $path"
}

require_user_file() {
    local path=$1 expected_mode=$2 canonical metadata
    [[ -f $path && ! -L $path && -s $path ]] || \
        fail "user payload is missing, empty, non-regular or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize user payload: $path"
    [[ $canonical == "$path" ]] || fail "user payload path is non-canonical: $path"
    metadata=$(stat -c '%u:%g:%a:%h' -- "$path") || \
        fail "cannot inspect user payload: $path"
    [[ $metadata == "$USER_UID:$USER_GID:$expected_mode:1" ]] || \
        fail "user payload metadata differs: $path ($metadata)"
    matchpathcon -V "$path" >/dev/null || \
        fail "user payload SELinux label differs: $path"
}

require_user_file_safe() {
    local path=$1 canonical metadata owner group mode links
    [[ -f $path && ! -L $path && -s $path ]] || \
        fail "browser output is missing, empty, non-regular or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize browser output: $path"
    [[ $canonical == "$path" ]] || \
        fail "browser output path is non-canonical: $path"
    metadata=$(stat -c '%u:%g:%a:%h' -- "$path") || \
        fail "cannot inspect browser output: $path"
    IFS=: read -r owner group mode links <<< "$metadata"
    [[ $owner == "$USER_UID" && $group == "$USER_GID" && $links == 1 \
       && $mode =~ ^[0-7]{3,4}$ ]] || \
        fail "browser output metadata is invalid: $path ($metadata)"
    (( (8#$mode & 0022) == 0 )) || \
        fail "browser output is group/other-writable: $path"
    matchpathcon -V "$path" >/dev/null || \
        fail "browser output SELinux label differs: $path"
}

require_equal() {
    cmp -s -- "$1" "$2" || fail "byte mismatch: $1 != $2"
}

require_absent() {
    [[ ! -e $1 && ! -L $1 ]] || fail "$2: $1"
}

m16_repo="$REPO_ROOT/kickstart/snippets/16-firefox.ks"
m34_repo="$REPO_ROOT/kickstart/snippets/34-firefox-playground.ks"
m35_repo="$REPO_ROOT/kickstart/snippets/35-thunderbird.ks"
ff_repo="$REPO_ROOT/firefox/noid-firefox-hardening.js"
tb_repo="$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"
tb_cfg_repo="$REPO_ROOT/thunderbird/mozilla.cfg"
tb_autoconfig_repo="$REPO_ROOT/thunderbird/autoconfig.js"
tb_local_repo="$REPO_ROOT/thunderbird/local-settings.js"
for path in "$m16_repo" "$m34_repo" "$m35_repo" "$ff_repo" "$tb_repo" \
        "$tb_cfg_repo" "$tb_autoconfig_repo" "$tb_local_repo"; do
    require_repo_file "$path"
done

while IFS='|' read -r path mode; do
    require_root_file "$path" "$mode"
done <<'ROOT_FILE_SPECS'
/usr/local/bin/firefox|755
/usr/local/bin/thunderbird|755
/usr/local/bin/noid-firefox-drm|755
/usr/local/lib/noid-privacy/firefox-profiles.sh|644
/usr/share/noid-firefox/user.js|644
/usr/share/noid-firefox/user-drm-overrides.js|644
/usr/share/noid-firefox/user-playground-overrides.js|644
/usr/lib64/firefox/mozilla.cfg|644
/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi|644
/usr/share/noid-thunderbird/user.js|644
/usr/share/noid-thunderbird/mozilla.cfg|644
/usr/lib64/thunderbird/mozilla.cfg|644
/usr/share/noid-thunderbird/autoconfig.js|644
/usr/lib64/thunderbird/defaults/pref/autoconfig.js|644
/usr/share/noid-thunderbird/local-settings.js|644
/usr/lib64/thunderbird/defaults/pref/local-settings.js|644
/usr/share/noid-thunderbird/dkim_verifier.xpi|644
/usr/lib64/thunderbird/distribution/extensions/dkim_verifier@pl.xpi|644
/var/lib/noid-privacy/stamp-16-firefox.ok|644
/var/lib/noid-privacy/stamp-34-firefox-playground.ok|644
/var/lib/noid-privacy/stamp-35-thunderbird.ok|644
ROOT_FILE_SPECS

python3 -I - "$m16_repo" "$m34_repo" "$TEST_TMP" <<'EXTRACT_RUNTIME_PYEOF' || \
    fail "cannot extract unique canonical runtime payloads"
import pathlib
import re
import sys

m16_path, m34_path, output_path = map(pathlib.Path, sys.argv[1:])
for source_path, marker, name in (
    (m16_path, "FF_PROFILES_EOF", "firefox-profiles.sh"),
    (m16_path, "DRM_OVERRIDES_EOF", "user-drm-overrides.js"),
    (m34_path, "OVERRIDES_EOF", "user-playground-overrides.js"),
):
    source = source_path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"^[^\n]*<<'{re.escape(marker)}'\n(.*?)^{re.escape(marker)}$",
        flags=re.MULTILINE | re.DOTALL,
    )
    matches = pattern.findall(source)
    assert len(matches) == 1, (marker, len(matches))
    # The captured heredoc payload already ends in its source newline.
    (output_path / name).write_text(matches[0], encoding="utf-8")
EXTRACT_RUNTIME_PYEOF
require_equal "$TEST_TMP/firefox-profiles.sh" \
    /usr/local/lib/noid-privacy/firefox-profiles.sh
require_equal "$TEST_TMP/user-drm-overrides.js" \
    /usr/share/noid-firefox/user-drm-overrides.js
require_equal "$TEST_TMP/user-playground-overrides.js" \
    /usr/share/noid-firefox/user-playground-overrides.js

require_equal "$ff_repo" /usr/share/noid-firefox/user.js
require_equal "$tb_repo" /usr/share/noid-thunderbird/user.js
require_equal "$tb_cfg_repo" /usr/share/noid-thunderbird/mozilla.cfg
require_equal /usr/share/noid-thunderbird/mozilla.cfg \
    /usr/lib64/thunderbird/mozilla.cfg
require_equal "$tb_autoconfig_repo" /usr/share/noid-thunderbird/autoconfig.js
require_equal /usr/share/noid-thunderbird/autoconfig.js \
    /usr/lib64/thunderbird/defaults/pref/autoconfig.js
require_equal "$tb_local_repo" /usr/share/noid-thunderbird/local-settings.js
require_equal /usr/share/noid-thunderbird/local-settings.js \
    /usr/lib64/thunderbird/defaults/pref/local-settings.js
require_equal /usr/share/noid-thunderbird/dkim_verifier.xpi \
    /usr/lib64/thunderbird/distribution/extensions/dkim_verifier@pl.xpi

python3 -I - "$m16_repo" "$m35_repo" \
    '/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi' \
    /usr/share/noid-thunderbird/dkim_verifier.xpi \
    /var/lib/noid-privacy/stamp-16-firefox.ok \
    /var/lib/noid-privacy/stamp-34-firefox-playground.ok \
    /var/lib/noid-privacy/stamp-35-thunderbird.ok <<'ROOT_RUNTIME_PYEOF' || \
    fail "browser extension pins or health-stamp schemas differ"
import datetime
import hashlib
import pathlib
import re
import sys

(
    m16_path,
    m35_path,
    ubo_path,
    dkim_path,
    firefox_stamp_path,
    playground_stamp_path,
    thunderbird_stamp_path,
) = map(pathlib.Path, sys.argv[1:])
m16 = m16_path.read_text(encoding="utf-8")
m35 = m35_path.read_text(encoding="utf-8")


def values(source, name, pattern):
    return re.findall(
        rf'^{re.escape(name)}={pattern}$',
        source,
        flags=re.MULTILINE,
    )


ubo_versions = values(m16, "UBO_VERSION", r'"([^"\n]+)"')
ubo_hashes = values(m16, "UBO_SHA256", r'"([0-9a-f]{64})"')
ubo_sizes = values(m16, "UBO_SIZE_EXPECTED", r"([0-9]+)")
assert ubo_versions == ["1.73.0"]
assert len(ubo_hashes) == 2 and len(set(ubo_hashes)) == 1
assert len(ubo_sizes) == 2 and len(set(ubo_sizes)) == 1
ubo = ubo_path.read_bytes()
assert len(ubo) == int(ubo_sizes[0])
assert hashlib.sha256(ubo).hexdigest() == ubo_hashes[0]

dkim_versions = values(m35, "DKIM_VERIFIER_VERSION", r'"([^"\n]+)"')
dkim_hashes = values(m35, "DKIM_VERIFIER_SHA256", r'"([0-9a-f]{64})"')
assert dkim_versions == ["6.3.0"]
assert len(dkim_hashes) == 1
assert hashlib.sha256(dkim_path.read_bytes()).hexdigest() == dkim_hashes[0]


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
    datetime.datetime.strptime(match.group(1).decode(), "%Y-%m-%dT%H:%M:%SZ")


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
    datetime.datetime.strptime(match.group(1).decode(), "%Y-%m-%dT%H:%M:%SZ")


verify_stamp(firefox_stamp_path, 16, "firefox")
verify_playground_stamp(playground_stamp_path)
verify_stamp(thunderbird_stamp_path, 35, "thunderbird")
ROOT_RUNTIME_PYEOF
bash "$REPO_ROOT/tests/pre-ship/18-browser-license-notices.sh" / >/dev/null || \
    fail "browser derivative license parity failed"
note "repository/public-image/browser-source/extension parity passed; root skel has a paired gate"

require_profile_helper=/usr/local/lib/noid-privacy/firefox-profiles.sh
# shellcheck source=/dev/null
. "$require_profile_helper"
declare -F firefox_process_active >/dev/null || \
    fail "shared Firefox profile helper lacks process-state detection"
declare -F profile_dir_for >/dev/null || \
    fail "shared Firefox profile helper lacks profile resolution"
firefox_process_active && fail "Firefox already running"

thunderbird_process_active() {
    local process_name process_pid status_file process_state
    for process_name in thunderbird thunderbird-bin; do
        while IFS= read -r process_pid; do
            [[ $process_pid =~ ^[0-9]+$ ]] || continue
            status_file="/proc/${process_pid}/status"
            if [[ ! -r $status_file ]]; then
                [[ -e /proc/${process_pid} ]] && return 0
                continue
            fi
            process_state=$(awk '$1 == "State:" { print $2; exit }' \
                "$status_file" 2>/dev/null || true)
            case "$process_state" in
                Z|X|x) continue ;;
                "") [[ -e /proc/${process_pid} ]] || continue ;;
            esac
            return 0
        done < <(pgrep -u "$USER_UID" -x "$process_name" 2>/dev/null || true)
    done
    return 1
}
thunderbird_process_active && fail "Thunderbird already running"

FF_PROFILE=$(profile_dir_for default-release) || \
    fail "safe default-release Firefox profile absent"
require_user_dir "$FF_PROFILE"
FF_UBO="$FF_PROFILE/extensions/uBlock0@raymondhill.net.xpi"
require_user_file "$FF_PROFILE/user.js" 600
require_user_file "$FF_UBO" 644
require_user_file "$FF_PROFILE/extension-preferences.json" 600
require_equal /usr/share/noid-firefox/user.js "$FF_PROFILE/user.js"
require_equal \
    '/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi' \
    "$FF_UBO"
require_absent "$FF_PROFILE/.noid-drm-enabled" \
    "pristine default Firefox profile carries DRM consent"
require_absent "$FF_PROFILE/.noid-firefox-hardening-disabled" \
    "pristine default Firefox profile carries a hardening opt-out"

FF_PLAYGROUND_PROFILE=
FF_PLAYGROUND_UBO=
if [[ $PASS_ID != live ]]; then
    FF_PLAYGROUND_PROFILE=$(profile_dir_for playground) || \
        fail "safe playground Firefox profile absent"
    require_user_dir "$FF_PLAYGROUND_PROFILE"
    FF_PLAYGROUND_UBO="$FF_PLAYGROUND_PROFILE/extensions/uBlock0@raymondhill.net.xpi"
    require_user_file "$FF_PLAYGROUND_PROFILE/user.js" 600
    require_user_file "$FF_PLAYGROUND_UBO" 644
    require_user_file "$FF_PLAYGROUND_PROFILE/extension-preferences.json" 600
    require_equal "$FF_PLAYGROUND_PROFILE/user.js" \
        <(cat -- /usr/share/noid-firefox/user.js \
            /usr/share/noid-firefox/user-playground-overrides.js)
    require_equal \
        '/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi' \
        "$FF_PLAYGROUND_UBO"
    require_absent "$FF_PLAYGROUND_PROFILE/.noid-drm-enabled" \
        "pristine playground Firefox profile carries DRM consent"
    require_absent "$FF_PLAYGROUND_PROFILE/.noid-firefox-hardening-disabled" \
        "pristine playground Firefox profile carries a hardening opt-out"
fi

for profile in "$FF_PROFILE" ${FF_PLAYGROUND_PROFILE:+"$FF_PLAYGROUND_PROFILE"}; do
    if [[ -n $(find "$profile" -maxdepth 1 -type d \
            \( -name gmp-widevinecdm -o -name 'gmp-widevinecdm-*' \) \
            -print -quit) ]]; then
        fail "pristine Firefox profile already contains a Widevine directory: $profile"
    fi
done

TB_ROOT="$HOME/.thunderbird"
require_user_dir "$TB_ROOT"
require_user_file "$TB_ROOT/profiles.ini" 644
TB_PROFILE=$(python3 -I - "$TB_ROOT/profiles.ini" "$TB_ROOT" "$USER_UID" \
    <<'TB_PROFILE_PYEOF'
import configparser
import os
import pathlib
import stat
import sys

ini, root = map(pathlib.Path, sys.argv[1:3])
uid = int(sys.argv[3])
parser = configparser.ConfigParser(strict=True, interpolation=None)
parser.optionxform = str
with ini.open(encoding="utf-8") as handle:
    parser.read_file(handle)
matches = [
    section
    for section in parser.sections()
    if section.startswith("Profile")
    and parser.get(section, "Name", fallback="") == "default-release"
]
assert len(matches) == 1
section = matches[0]
assert parser.get(section, "IsRelative") == "1"
relative = parser.get(section, "Path")
assert relative and not os.path.isabs(relative)
assert not any(character in relative for character in "\t\r\n")
assert os.path.normpath(relative) == relative
assert ".." not in pathlib.PurePath(relative).parts
candidate = root / relative
assert candidate.is_dir() and not candidate.is_symlink()
assert candidate.resolve(strict=True).is_relative_to(root.resolve(strict=True))
metadata = candidate.stat()
assert metadata.st_uid == uid and not metadata.st_mode & 0o022
print(candidate)
TB_PROFILE_PYEOF
) || fail "safe default-release Thunderbird profile absent"
require_user_dir "$TB_PROFILE"
require_user_file "$TB_PROFILE/user.js" 600
require_equal /usr/share/noid-thunderbird/user.js "$TB_PROFILE/user.js"
require_absent "$TB_PROFILE/.noid-thunderbird-hardening-disabled" \
    "pristine Thunderbird profile carries a hardening opt-out"

python3 -I - "$FF_PROFILE/extension-preferences.json" \
    ${FF_PLAYGROUND_PROFILE:+"$FF_PLAYGROUND_PROFILE/extension-preferences.json"} \
    <<'FF_PERMISSION_PYEOF' || fail "uBO private-window permission differs"
import json
import pathlib
import sys


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result
        result[key] = value
    return result


expected = {
    "permissions": ["internal:privateBrowsingAllowed"],
    "origins": [],
    "data_collection": [],
}
for path in map(pathlib.Path, sys.argv[1:]):
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle, object_pairs_hook=strict_object)
    assert data["uBlock0@raymondhill.net"] == expected
FF_PERMISSION_PYEOF

if [[ $PASS_ID != live ]]; then
    FF_STATE="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy/firefox-setup.done"
    FF_PLAYGROUND_STATE="${XDG_CONFIG_HOME:-$HOME/.config}/noid-privacy/firefox-playground-init.done"
    require_user_file "$FF_STATE" 600
    require_user_file "$FF_PLAYGROUND_STATE" 600
    python3 -I - "$FF_STATE" "$FF_PLAYGROUND_STATE" "$FF_PROFILE" \
        /usr/share/noid-firefox/user.js \
        '/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi' \
        <<'FF_STATE_PYEOF' || fail "Firefox setup evidence differs"
import hashlib
import pathlib
import sys

state_path, playground_path, profile_path, userjs_path, ubo_path = map(
    pathlib.Path, sys.argv[1:]
)
expected = [
    "NOID_FIREFOX_SETUP_V1",
    f"profile={profile_path}",
    f"userjs_sha256={hashlib.sha256(userjs_path.read_bytes()).hexdigest()}",
    f"ubo_sha256={hashlib.sha256(ubo_path.read_bytes()).hexdigest()}",
]
assert state_path.read_text(encoding="utf-8").splitlines() == expected
assert (
    playground_path.read_bytes()
    == b"NOID_FIREFOX_PLAYGROUND_READY_V1\n"
)
FF_STATE_PYEOF
fi

run_browser() {
    local name=$1
    shift
    local rc
    set +e
    timeout --signal=TERM --kill-after=3s 10s "$@" \
        >"$TEST_TMP/$name.stdout" 2>"$TEST_TMP/$name.stderr"
    rc=$?
    set -e
    case "$rc" in
        0|124) ;;
        *)
            tail -n 200 "$TEST_TMP/$name.stderr" | sed 's/^/    /' >&2
            fail "$name real headless launch failed with rc=$rc"
            ;;
    esac
}

require_browser_exit() {
    local checker=$1 label=$2 attempt
    for ((attempt = 0; attempt < 30; attempt++)); do
        if ! "$checker"; then
            return
        fi
        sleep 0.1
    done
    fail "$label launch left a live process after the 3-second settlement window"
}

# about:newtab deliberately initializes weather, wallpaper and TopSites code.
# The paired VM packet-capture audit remains the network-attempt oracle; this
# gate proves effective preferences, extensions and disk outcomes.
run_browser firefox-default \
    /usr/local/bin/firefox --headless --no-remote about:newtab
require_browser_exit firefox_process_active "default Firefox"
if [[ $PASS_ID != live ]]; then
    run_browser firefox-playground \
        /usr/local/bin/firefox --headless --no-remote -P playground about:newtab
    require_browser_exit firefox_process_active "playground Firefox"
fi
run_browser thunderbird \
    /usr/local/bin/thunderbird --headless --no-remote -P default-release about:blank
require_browser_exit thunderbird_process_active Thunderbird
note "real managed Firefox profile(s) and Thunderbird headless launches completed"

for profile in "$FF_PROFILE" ${FF_PLAYGROUND_PROFILE:+"$FF_PLAYGROUND_PROFILE"}; do
    if [[ -n $(find "$profile" -maxdepth 1 -type d \
            \( -name gmp-widevinecdm -o -name 'gmp-widevinecdm-*' \) \
            -print -quit) ]]; then
        fail "pristine Firefox launch installed Widevine: $profile"
    fi
done

require_user_file_safe "$FF_PROFILE/prefs.js"
require_user_file_safe "$FF_PROFILE/extensions.json"
FF_PLAYGROUND_PREFS=/dev/null
FF_PLAYGROUND_EXTENSIONS=/dev/null
if [[ $PASS_ID != live ]]; then
    require_user_file_safe "$FF_PLAYGROUND_PROFILE/prefs.js"
    require_user_file_safe "$FF_PLAYGROUND_PROFILE/extensions.json"
    FF_PLAYGROUND_PREFS="$FF_PLAYGROUND_PROFILE/prefs.js"
    FF_PLAYGROUND_EXTENSIONS="$FF_PLAYGROUND_PROFILE/extensions.json"
fi
require_user_file_safe "$TB_PROFILE/prefs.js"
require_user_file_safe "$TB_PROFILE/extensions.json"
TB_DKIM="$TB_PROFILE/extensions/dkim_verifier@pl.xpi"
require_user_file_safe "$TB_DKIM"
require_equal /usr/share/noid-thunderbird/dkim_verifier.xpi "$TB_DKIM"

python3 -I - \
    "$FF_PROFILE/prefs.js" /usr/lib64/firefox/mozilla.cfg \
    "$FF_PROFILE/extensions.json" "$FF_UBO" \
    "$FF_PLAYGROUND_PREFS" "$FF_PLAYGROUND_EXTENSIONS" \
    "${FF_PLAYGROUND_UBO:-/dev/null}" \
    "$TB_PROFILE/prefs.js" /usr/lib64/thunderbird/mozilla.cfg \
    "$TB_PROFILE/extensions.json" "$TB_DKIM" \
    "$PASS_ID" <<'BROWSER_STATE_PYEOF' || \
    fail "effective browser preference/extension state differs"
import json
import pathlib
import re
import sys


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result
        result[key] = value
    return result


def pref_calls(path, call):
    result = {}
    pattern = re.compile(
        rf'^{re.escape(call)}\(("(?:\\.|[^"\\])*")\s*,\s*(.*?)\);'
        rf'\s*(?://.*)?$'
    )
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            match = pattern.match(raw.rstrip("\n"))
            if not match:
                continue
            key = json.loads(match.group(1))
            raw_value = match.group(2)
            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError:
                continue
            # Arkenfox-style section parrot markers intentionally reuse this
            # non-policy key; every actual preference remains unique.
            assert key not in result or key == "_user.js.parrot"
            result[key] = value
    return result


def effective(defaults_path, user_path):
    # A serialized user value wins; otherwise AutoConfig's default remains.
    result = pref_calls(defaults_path, "defaultPref")
    result.update(pref_calls(user_path, "user_pref"))
    return result


def addon(path, addon_id, version, expected_xpi):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle, object_pairs_hook=strict_object)
    matches = [
        item for item in data.get("addons", []) if item.get("id") == addon_id
    ]
    assert len(matches) == 1
    item = matches[0]
    assert item.get("version") == version
    assert item.get("type") == "extension"
    assert item.get("active") is True
    assert item.get("userDisabled") is False
    assert item.get("appDisabled") is False
    recorded_path = pathlib.Path(item["path"])
    assert recorded_path.is_absolute()
    assert recorded_path.resolve(strict=True) == pathlib.Path(expected_xpi).resolve(
        strict=True
    )


def verify_firefox_common(ff):
    assert ff["signon.rememberSignons"] is False
    assert ff["media.peerconnection.enabled"] is False
    assert ff["network.trr.mode"] == 5
    assert ff["doh-rollout.home-region"] == "global"
    assert ff["network.dns.disableIPv6"] is False
    assert ff["browser.region.network.url"] == ""
    assert ff["browser.region.network.scan"] is False
    assert ff["browser.region.update.enabled"] is False
    assert ff["browser.safebrowsing.malware.enabled"] is True
    assert ff["browser.safebrowsing.phishing.enabled"] is True
    assert ff["browser.safebrowsing.downloads.enabled"] is True
    assert ff["browser.safebrowsing.blockedURIs.enabled"] is True
    assert ff["browser.safebrowsing.downloads.remote.enabled"] is False
    assert ff.get("browser.safebrowsing.update.enabled", True) is True
    assert ff["browser.pagethumbnails.capturing_disabled"] is True
    assert ff["extensions.ml.enabled"] is False
    assert ff["browser.ai.control.default"] == "blocked"
    assert "browser.ml.enable" not in ff
    assert ff["media.eme.enabled"] is False
    assert ff["media.gmp-manager.updateEnabled"] is False
    assert ff["media.gmp-widevinecdm.enabled"] is False
    assert ff["media.gmp-widevinecdm.allow-chromium-update"] is False
    assert ff["dom.private-attribution.submission.enabled"] is False
    assert ff["privacy.fingerprintingProtection"] is True
    assert ff["privacy.resistFingerprinting"] is False
    assert ff["security.tls.enable_kyber"] is True
    assert ff["security.remote_settings.crlite_filters.enabled"] is True
    assert ff["security.pki.crlite_mode"] == 2


(
    ff_prefs,
    ff_defaults,
    ff_extensions,
    ff_ubo,
    playground_prefs,
    playground_extensions,
    playground_ubo,
    tb_prefs,
    tb_defaults,
    tb_extensions,
    tb_dkim,
    pass_id,
) = sys.argv[1:]

ff = effective(ff_defaults, ff_prefs)
verify_firefox_common(ff)
assert ff["browser.newtabpage.activity-stream.feeds.weatherfeed"] is False
assert ff["browser.newtabpage.activity-stream.showWeather"] is False
assert ff["browser.newtabpage.activity-stream.system.showWeather"] is False
assert ff["browser.newtabpage.activity-stream.widgets.weather.enabled"] is False
assert ff["browser.newtabpage.activity-stream.widgets.weatherForecast.enabled"] is False
assert (
    ff["browser.newtabpage.activity-stream.widgets.system.weather.enabled"]
    is False
)
assert (
    ff[
        "browser.newtabpage.activity-stream.widgets.system.weatherForecast.enabled"
    ]
    is False
)
assert ff["browser.urlbar.weather.featureGate"] is False
assert ff["browser.urlbar.suggest.weather"] is False
assert ff["browser.newtabpage.activity-stream.newtabWallpapers.enabled"] is False
assert (
    ff["browser.newtabpage.activity-stream.newtabWallpapers.user.enabled"]
    is False
)
pins = json.loads(ff["browser.newtabpage.pinned"])
expected_urls = [
    "https://noid-privacy.com/linux.html",
    "https://duckduckgo.com/",
    "https://duck.ai/",
    "https://proton.me/mail",
    "https://signal.org/",
    "https://mullvad.net/en",
    "https://www.torproject.org/download/",
    "https://discuss.privacyguides.net/",
]
assert [pin["url"] for pin in pins] == expected_urls
assert all(set(pin) == {"url", "title", "favicon", "faviconSize"} for pin in pins)
assert all(pin["favicon"].startswith("data:image/svg+xml,%3Csvg") for pin in pins)
assert all(pin["faviconSize"] == 96 for pin in pins)
addon(ff_extensions, "uBlock0@raymondhill.net", "1.73.0", ff_ubo)

if pass_id != "live":
    playground = effective(ff_defaults, playground_prefs)
    verify_firefox_common(playground)
    assert playground["_noid.profile.kind"] == "playground"
    assert playground["browser.privatebrowsing.autostart"] is True
    assert playground["privacy.sanitize.sanitizeOnShutdown"] is True
    for key in (
        "privacy.clearOnShutdown_v2.cookiesAndStorage",
        "privacy.clearOnShutdown_v2.browsingHistoryAndDownloads",
        "privacy.clearOnShutdown_v2.cache",
        "privacy.clearOnShutdown_v2.formdata",
        "privacy.clearOnShutdown_v2.siteSettings",
    ):
        assert playground[key] is True
    assert playground["places.history.enabled"] is False
    assert playground["browser.sessionstore.resume_from_crash"] is False
    assert playground["browser.sessionstore.max_tabs_undo"] == 0
    assert playground["browser.sessionstore.max_windows_undo"] == 0
    assert playground["browser.sessionstore.privacy_level"] == 2
    assert playground["browser.cache.disk.enable"] is False
    assert playground["browser.startup.homepage"] == "about:blank"
    assert playground["browser.startup.page"] == 0
    assert playground["browser.newtabpage.enabled"] is False
    assert playground["identity.fxaccounts.enabled"] is False
    addon(
        playground_extensions,
        "uBlock0@raymondhill.net",
        "1.73.0",
        playground_ubo,
    )

tb = effective(tb_defaults, tb_prefs)
assert tb["network.trr.mode"] == 5
assert tb["network.dns.disableIPv6"] is False
assert tb["doh-rollout.home-region"] == "global"
assert tb["browser.region.network.url"] == ""
assert tb["browser.region.network.scan"] is False
assert tb["browser.region.update.enabled"] is False
assert tb["browser.safebrowsing.malware.enabled"] is True
assert tb["browser.safebrowsing.phishing.enabled"] is True
assert tb["browser.safebrowsing.downloads.enabled"] is True
assert tb["browser.safebrowsing.blockedURIs.enabled"] is True
assert tb["browser.safebrowsing.downloads.remote.enabled"] is False
assert tb.get("browser.safebrowsing.update.enabled", True) is True
assert tb["dom.private-attribution.submission.enabled"] is False
assert tb["privacy.sanitize.sanitizeOnShutdown"] is True
assert tb["privacy.clearOnShutdown.cache"] is True
assert tb["privacy.clearOnShutdown.cookies"] is True
assert tb["privacy.clearOnShutdown.history"] is False
assert tb["privacy.sanitize.timeSpan"] == 0
assert tb["mail.external_protocol_requires_permission"] is True
assert tb["mail.openpgp.keyserver_list"] == (
    "vks://keys.openpgp.org, hkps://keys.mailvelope.com"
)
assert tb["mailnews.message_display.disable_remote_image"] is True
assert tb["javascript.enabled"] is False
assert tb["security.tls.enable_kyber"] is True
assert tb["toolkit.telemetry.unified"] is False
addon(tb_extensions, "dkim_verifier@pl", "6.3.0", tb_dkim)
BROWSER_STATE_PYEOF

echo "PASS  $TEST_NAME [$PASS_ID]: exact image/profile bytes + real managed-profile launches + effective state"

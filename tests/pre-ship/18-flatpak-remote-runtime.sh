#!/usr/bin/env bash
# Candidate-only exact Flatpak remote trust and Fedora-auto-add suppression gate.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin
umask 077
ulimit -c 0

TEST_NAME=18-flatpak-remote-runtime
PASS_ID=${1:-}
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *)
        echo "Usage: sudo bash $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac
fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "run as root"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null \
    || fail "not running inside the NoID Privacy candidate"

for command_name in awk cmp dirname env flatpak getcap grep head matchpathcon \
                    mkdir mktemp python3 readlink rm rpm sha256sum sort stat \
                    systemctl; do
    command -v "$command_name" >/dev/null 2>&1 \
        || fail "required command missing: $command_name"
done

script_path=$(readlink -e -- "$0") || fail "cannot canonicalize runtime gate"
repo_root=$(cd "$(dirname -- "$script_path")/../.." && pwd -P) \
    || fail "cannot resolve repository root"
repo_policy=$repo_root/scripts/noid-flatpak-remote-policy.sh
repo_descriptor=$repo_root/manifests/flathub.flatpakrepo
repo_module=$repo_root/kickstart/snippets/18-flatpak-sandboxing.ks
for repo_file in "$repo_policy" "$repo_descriptor" "$repo_module"; do
    [[ -f $repo_file && ! -L $repo_file ]] \
        || fail "canonical repository source is missing or unsafe: $repo_file"
done

fixture_root=$(mktemp -d /var/tmp/noid-flatpak-runtime.XXXXXXXX) \
    || fail "cannot create private Flatpak runtime fixture"
cleanup_fixture() { rm -rf -- "$fixture_root"; }
trap cleanup_fixture EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

version_at_least() {
    local actual=$1 required=$2
    [[ $(printf '%s\n%s\n' "$actual" "$required" | sort -V | head -n 1) == "$required" ]]
}

policy=/usr/local/libexec/noid-flatpak-remote-policy
toggle=/usr/local/sbin/noid-toggle-fedora-flatpaks
descriptor=/usr/share/noid-flatpak/flathub.flatpakrepo
mask=/etc/systemd/system/flatpak-add-fedora-repos.service
trust_doc=/usr/share/doc/noid-privacy/18-flatpak-trust-model.md
remote_config=/var/lib/flatpak/repo/config
full_key=/var/lib/flatpak/repo/flathub.trustedkeys.gpg
verified_key=/var/lib/flatpak/repo/flathub-verified.trustedkeys.gpg
global_override=/var/lib/flatpak/overrides/global
flatpak_binary=/usr/bin/flatpak
bwrap_binary=/usr/bin/bwrap
portal_binary=/usr/libexec/xdg-desktop-portal

verify_root_file() {
    local path=$1 mode=$2
    [[ -f $path && ! -L $path \
       && $(stat -c '%u:%g:%a:%h' -- "$path") == "0:0:$mode:1" ]] \
        || fail "root-owned file metadata differs: $path"
    matchpathcon -V "$path" >/dev/null 2>&1 \
        || fail "SELinux context differs: $path"
}

verify_root_file "$policy" 750
verify_root_file "$toggle" 755
verify_root_file "$descriptor" 644
verify_root_file "$trust_doc" 644
verify_root_file "$remote_config" 644
verify_root_file "$full_key" 644
verify_root_file "$verified_key" 644
verify_root_file "$global_override" 644
[[ -x $policy && -x $toggle ]] \
    || fail "Flatpak policy controller or opt-in helper is not executable"
cmp -s -- "$policy" "$toggle" \
    || fail "controller and user-facing helper bytes differ"
cmp -s -- "$repo_policy" "$policy" \
    || fail "installed controller differs from canonical repository source"
cmp -s -- "$repo_policy" "$toggle" \
    || fail "installed opt-in helper differs from canonical repository source"
cmp -s -- "$repo_descriptor" "$descriptor" \
    || fail "installed Flathub descriptor differs from canonical repository source"

expected_trust_doc=$fixture_root/18-flatpak-trust-model.md
awk -v start="cat > /usr/share/doc/noid-privacy/18-flatpak-trust-model.md <<'TRUSTDOC_EOF'" \
    -v end=TRUSTDOC_EOF '
    $0 == start {
        starts++
        if (starts != 1 || open || ended) invalid=1
        open=1
        next
    }
    $0 == end {
        ends++
        if (!open) invalid=1
        open=0
        ended=1
        next
    }
    open { print }
    END {
        exit !(starts == 1 && ends == 1 && ended && !open && !invalid)
    }
' "$repo_module" > "$expected_trust_doc" \
    || fail "cannot extract one complete canonical Flatpak trust guide"
cmp -s -- "$expected_trust_doc" "$trust_doc" \
    || fail "installed Flatpak trust guide differs from canonical repository source"

fedora_key=dbfcf71c6d9f90a6
platform_packages=(
    flatpak
    flatpak-selinux
    flatpak-session-helper
    bubblewrap
    xdg-desktop-portal
    xdg-desktop-portal-gnome
    xdg-desktop-portal-gtk
)
for package in "${platform_packages[@]}"; do
    package_record=$(rpm -q --qf \
        '%{NAME}|%{EPOCHNUM}|%{RELEASE}|%{VENDOR}|%{RSAHEADER:pgpsig}\n' \
        "$package" 2>/dev/null) || fail "required package missing: $package"
    [[ $package_record != *$'\n'* ]] \
        || fail "multiple installed package records found: $package"
    IFS='|' read -r package_name package_epoch package_release \
        package_vendor package_signature <<<"$package_record"
    [[ $package_name == "$package" \
       && $package_epoch == 0 \
       && $package_release == *.fc44 \
       && $package_vendor == "Fedora Project" \
       && ${package_signature,,} == *"key id $fedora_key"* ]] \
        || fail "package provenance differs from Fedora 44: $package"
done
rpm_verify=$(rpm -V "${platform_packages[@]}" 2>&1) \
    || fail "Flatpak platform package verification reported drift"
[[ -z $rpm_verify ]] \
    || fail "Flatpak platform package payload differs from its RPM record"

for binary_spec in \
    "flatpak|$flatpak_binary" \
    "bubblewrap|$bwrap_binary" \
    "xdg-desktop-portal|$portal_binary"; do
    IFS='|' read -r expected_package binary <<<"$binary_spec"
    verify_root_file "$binary" 755
    [[ $(rpm -qf --qf '%{NAME}' "$binary" 2>/dev/null) == "$expected_package" ]] \
        || fail "executable has the wrong RPM owner: $binary"
done
[[ -z $(getcap "$flatpak_binary" "$bwrap_binary" "$portal_binary") ]] \
    || fail "Flatpak platform executable carries unexpected file capabilities"

flatpak_version=$(rpm -q --queryformat '%{VERSION}' flatpak 2>/dev/null) \
    || fail "cannot query Flatpak package version"
[[ $(flatpak --version 2>/dev/null) == "Flatpak $flatpak_version" ]] \
    || fail "Flatpak executable and package versions differ"
version_at_least "$flatpak_version" 1.18.1 \
    || fail "Flatpak is below the 1.18.1 security baseline"
portal_version=$(rpm -q --queryformat '%{VERSION}' xdg-desktop-portal 2>/dev/null) \
    || fail "cannot query xdg-desktop-portal version"
version_at_least "$portal_version" 1.22.1 \
    || fail "xdg-desktop-portal is below the 1.22.1 security baseline"
[[ -x $bwrap_binary && ! -u $bwrap_binary ]] \
    || fail "bubblewrap is missing, non-executable or setuid"
[[ $(stat -c '%s' -- "$descriptor") == 4040 ]] \
    || fail "pinned Flathub descriptor size is wrong"
[[ $(sha256sum -- "$descriptor" | awk '{print $1}') == \
    3371dd250e61d9e1633630073fefda153cd4426f72f4afa0c3373ae2e8fea03a ]] \
    || fail "pinned Flathub descriptor digest is wrong"

[[ -L $mask && $(stat -c '%u:%g:%h' -- "$mask") == 0:0:1 ]] \
    || fail "Fedora Flatpak auto-add mask metadata is invalid"
[[ $(readlink -- "$mask") == /dev/null ]] \
    || fail "Fedora Flatpak auto-add mask is not the direct /dev/null link"
matchpathcon -V "$mask" >/dev/null 2>&1 \
    || fail "Fedora Flatpak auto-add mask SELinux context differs"
[[ $(systemctl is-enabled flatpak-add-fedora-repos.service 2>/dev/null || true) == masked ]] \
    || fail "systemd does not report Fedora Flatpak auto-add as masked"
[[ $(systemctl is-active flatpak-add-fedora-repos.service 2>/dev/null || true) != active ]] \
    || fail "masked Fedora Flatpak auto-add unit is unexpectedly active"
[[ ! -e /var/lib/flatpak/.fedora-initialized \
   && ! -L /var/lib/flatpak/.fedora-initialized ]] \
    || fail "Fedora private initialization sentinel was forged"

remote_inventory=$(flatpak remotes --system --show-disabled --columns=name) \
    || fail "cannot enumerate default system remotes"
mapfile -t remote_names < <(printf '%s\n' "$remote_inventory" | LC_ALL=C sort)
[[ ${#remote_names[@]} -eq 2 ]] \
    || fail "default system remote count is not exactly two"
[[ ${remote_names[0]} == flathub && ${remote_names[1]} == flathub-verified ]] \
    || fail "default system remote names are not the exact NoID Privacy set"

python3 - "$remote_config" <<'PY_EOF' \
    || fail "legacy per-remote HTTP transport override remains"
import configparser
import sys

config = configparser.ConfigParser(interpolation=None, strict=True)
with open(sys.argv[1], "r", encoding="utf-8") as stream:
    config.read_file(stream)
for name in ("flathub", "flathub-verified"):
    section = f'remote "{name}"'
    if config.has_option(section, "http2"):
        raise SystemExit(1)
PY_EOF

"$policy" verify-default --online \
    || fail "exact URL/config/GPG-key/online-catalog policy failed"
"$toggle" status | grep -qxF 'Fedora Flatpaks: disabled (NoID Privacy default)' \
    || fail "explicit Fedora Flatpaks helper does not report the default disabled state"

overrides=$(flatpak override --system --show 2>/dev/null) \
    || fail "cannot read effective global Flatpak overrides"
override_rendered=$fixture_root/global-overrides.rendered
printf '%s\n' "$overrides" > "$override_rendered"
cmp -s -- "$override_rendered" "$global_override" \
    || fail "Flatpak CLI and stored global override bytes differ"
python3 - "$override_rendered" <<'PY_EOF' \
    || fail "global Flatpak overrides are not the exact six-rule policy"
import configparser
import sys

config = configparser.ConfigParser(interpolation=None, strict=True)
config.optionxform = str
with open(sys.argv[1], "r", encoding="utf-8") as stream:
    config.read_file(stream)

expected = {
    "Context": {"filesystems": "!~/.ssh;!~/.gnupg;"},
    "Session Bus Policy": {
        "org.freedesktop.Flatpak": "none",
        "org.freedesktop.systemd1": "none",
    },
    "System Bus Policy": {
        "org.freedesktop.PackageKit": "none",
        "org.freedesktop.systemd1": "none",
    },
}
if config.defaults() or set(config.sections()) != set(expected):
    raise SystemExit(1)
for section, values in expected.items():
    if dict(config.items(section, raw=True)) != values:
        raise SystemExit(1)
PY_EOF

[[ -f $trust_doc && ! -L $trust_doc ]] \
    || fail "Flatpak trust-model guide is missing or is a symlink"
grep -qxF '## The effective sandbox is per app' "$trust_doc" \
    || fail "trust guide does not distinguish effective per-app permissions"
grep -qF 'interface is an implementation vulnerability.' "$trust_doc" \
    || fail "trust guide misclassifies the intentional host interface"
grep -qF 'Flatpak, not a NoID Privacy trust anchor.' "$trust_doc" \
    || fail "trust guide carries a mutable Flatseal safety verdict"
! grep -qF 'Flatpak provides no security boundary that protects the OS' "$trust_doc" \
    || fail "fabricated Flatpak quotation survived in the installed guide"

# Validate every documented per-app exception/revocation shape against the
# candidate Flatpak binary without touching a real user's override state.
fixture_home=$fixture_root/home
fixture_data=$fixture_root/data
mkdir -p "$fixture_home" "$fixture_data"
fixture_app=com.example.NoIDAuditFixture
fixture_env=(env HOME="$fixture_home" XDG_DATA_HOME="$fixture_data")

"${fixture_env[@]}" flatpak override --user \
    --socket=ssh-auth --socket=gpg-agent \
    --filesystem='~/.ssh:ro' --filesystem='~/.gnupg:ro' \
    --talk-name=org.freedesktop.Flatpak "$fixture_app" \
    || fail "documented per-app permission grants were rejected"
fixture_show=$("${fixture_env[@]}" flatpak override --user --show "$fixture_app") \
    || fail "cannot read isolated per-app grants"
grep -qF 'gpg-agent' <<<"$fixture_show" || fail "GPG-agent grant did not serialize"
grep -qF 'ssh-auth' <<<"$fixture_show" || fail "SSH-agent grant did not serialize"
# shellcheck disable=SC2088
home_relative_ssh_ro='~/.ssh:ro'
# shellcheck disable=SC2088
home_relative_gnupg_ro='~/.gnupg:ro'
grep -qF "$home_relative_ssh_ro" <<<"$fixture_show" \
    || fail "read-only SSH path did not serialize"
grep -qF "$home_relative_gnupg_ro" <<<"$fixture_show" \
    || fail "read-only GPG path did not serialize"
grep -qF 'org.freedesktop.Flatpak=talk' <<<"$fixture_show" \
    || fail "reviewed host-interface exception did not serialize"

"${fixture_env[@]}" flatpak override --user \
    --nosocket=ssh-auth --nosocket=gpg-agent \
    --nofilesystem='~/.ssh' --nofilesystem='~/.gnupg' \
    --no-talk-name=org.freedesktop.Flatpak "$fixture_app" \
    || fail "documented per-app permission revocations were rejected"
fixture_show=$("${fixture_env[@]}" flatpak override --user --show "$fixture_app") \
    || fail "cannot read isolated per-app revocations"
grep -qF '!gpg-agent' <<<"$fixture_show" || fail "GPG-agent revoke did not serialize"
grep -qF '!ssh-auth' <<<"$fixture_show" || fail "SSH-agent revoke did not serialize"
grep -qF '!~/.ssh' <<<"$fixture_show" || fail "SSH path revoke did not serialize"
grep -qF '!~/.gnupg' <<<"$fixture_show" || fail "GPG path revoke did not serialize"
grep -qF 'org.freedesktop.Flatpak=none' <<<"$fixture_show" \
    || fail "host-interface revoke did not serialize"

"${fixture_env[@]}" flatpak override --user --reset "$fixture_app" \
    || fail "documented per-app reset was rejected"
[[ ! -e $fixture_data/flatpak/overrides/$fixture_app ]] \
    || fail "per-app reset left the isolated user override file behind"

# M18 resets only the compose-owned global layer before publishing its exact
# six defaults. Prove the native no-APP reset does not erase per-app state.
"${fixture_env[@]}" flatpak override --user --share=network \
    || fail "isolated global override setup failed"
"${fixture_env[@]}" flatpak override --user --socket=x11 "$fixture_app" \
    || fail "isolated per-app reset-boundary setup failed"
"${fixture_env[@]}" flatpak override --user --reset \
    || fail "isolated global-only reset failed"
[[ ! -e $fixture_data/flatpak/overrides/global \
   && -f $fixture_data/flatpak/overrides/$fixture_app ]] \
    || fail "global reset removed per-app state or retained global state"
"${fixture_env[@]}" flatpak override --user --reset "$fixture_app" \
    || fail "isolated per-app cleanup failed"
[[ ! -e $fixture_data/flatpak/overrides/$fixture_app ]] \
    || fail "isolated per-app cleanup left override state behind"

echo "PASS  $TEST_NAME [$PASS_ID]: Fedora-authenticated Flatpak platform, repo-identical NoID Privacy assets, non-setuid bubblewrap, exact pinned Flathub trust with upstream-default object transport, native Fedora mask, exact six global denies, accurate trust guide and isolated exception/revocation/reset boundaries verified"

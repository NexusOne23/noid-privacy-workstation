#!/usr/bin/env bash
# Reconcile and verify NoID Privacy's system Flatpak remotes.  The default compose is
# exactly two GPG-verified views of the same pinned Flathub repository:
# the full catalog and the publisher-verified subset at higher priority.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

program=${0##*/}
if [ "$program" = noid-toggle-fedora-flatpaks ]; then
    # shellcheck source=/dev/null
    [ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
        NOID_FMT_AUTO_TITLE="NoID Privacy — Fedora Flatpaks" \
        NOID_FMT_AUTO_SUBTITLE="Optional Fedora remote" \
        . /usr/local/lib/noid-privacy/agent-install-format.sh
fi

fail() {
    echo "$program: $*" >&2
    exit 1
}

FLATPAK=${NOID_FLATPAK_BIN:-/usr/bin/flatpak}
GPG=${NOID_GPG_BIN:-/usr/bin/gpg}
PYTHON=${NOID_PYTHON_BIN:-/usr/bin/python3}
SHA256SUM=${NOID_SHA256SUM_BIN:-/usr/bin/sha256sum}
STAT=${NOID_STAT_BIN:-/usr/bin/stat}
DESCRIPTOR=${NOID_FLATHUB_DESCRIPTOR:-/usr/share/noid-flatpak/flathub.flatpakrepo}
SYSTEM_ROOT=${NOID_FLATPAK_SYSTEM_ROOT:-/var/lib/flatpak}
REPO_ROOT="$SYSTEM_ROOT/repo"
CONFIG="$REPO_ROOT/config"

DESCRIPTOR_BYTES=4040
DESCRIPTOR_SHA256=3371dd250e61d9e1633630073fefda153cd4426f72f4afa0c3373ae2e8fea03a
TRUSTED_KEY_EXPORT_BYTES=2844
TRUSTED_KEY_EXPORT_SHA256=8bdc20abc4e19c0796460beb5bfe0e7aa4138716999e19c6f2dbdd78cc41aeaa
TRUSTED_KEY_FINGERPRINT=6E5C05D979C76DAF93C081354184DD4D907A7CAE
FLATHUB_URL=https://dl.flathub.org/repo/
FEDORA_URL=oci+https://registry.fedoraproject.org
ONLINE_CATALOG_ATTEMPTS=3
ONLINE_CATALOG_RETRY_SECONDS=3
KEY_VERIFY_TMPDIR=${NOID_FLATPAK_KEY_TMPDIR:-/var/tmp}
SYSTEM_REMOTE_NAMES=()
[ -z "${NOID_FLATPAK_POLICY_TEST_MODE:-}" ] \
    || ONLINE_CATALOG_RETRY_SECONDS=0

usage() {
    cat <<'USAGE_EOF'
Usage:
  noid-flatpak-remote-policy apply-default
  noid-flatpak-remote-policy verify-default [--online]
  noid-flatpak-remote-policy fedora-on|fedora-off|fedora-status
  noid-toggle-fedora-flatpaks on|off|status

The default policy keeps only flathub and flathub-verified.  Fedora Flatpaks
are an explicit opt-in; the stock auto-add unit remains masked in every state.
verify-default proves that exact default and therefore fails by design while
the Fedora opt-in is enabled; use fedora-status to verify the opt-in state.
USAGE_EOF
}

require_command() {
    [ -x "$1" ] || fail "required executable missing: $1"
}

require_root() {
    [ -z "${NOID_FLATPAK_POLICY_TEST_MODE:-}" ] || return 0
    [ "$EUID" -eq 0 ] || fail "this operation requires root"
}

sha256_of() {
    "$SHA256SUM" -- "$1" | awk '{print $1}'
}

load_system_remote_names() {
    local output remote
    output=$("$FLATPAK" remotes --system --show-disabled --columns=name) \
        || fail "cannot enumerate system Flatpak remotes"
    SYSTEM_REMOTE_NAMES=()
    while IFS= read -r remote; do
        [ -n "$remote" ] || continue
        SYSTEM_REMOTE_NAMES+=("$remote")
    done <<< "$output"
}

system_remote_exists() {
    local expected=$1 remote
    for remote in "${SYSTEM_REMOTE_NAMES[@]}"; do
        [ "$remote" != "$expected" ] || return 0
    done
    return 1
}

verify_regular_file() {
    local path=$1 expected_bytes=$2 expected_sha=$3 owner_mode=$4
    [ -f "$path" ] && [ ! -L "$path" ] \
        || fail "missing, non-regular or symlinked policy artifact: $path"
    [ "$("$STAT" -c '%s' -- "$path")" = "$expected_bytes" ] \
        || fail "unexpected byte count for $path"
    [ "$(sha256_of "$path")" = "$expected_sha" ] \
        || fail "SHA-256 mismatch for $path"
    if [ -z "${NOID_FLATPAK_POLICY_TEST_MODE:-}" ]; then
        [ "$("$STAT" -c '%u:%g:%a' -- "$path")" = "$owner_mode" ] \
            || fail "unexpected ownership or mode for $path"
    fi
}

verify_descriptor() {
    verify_regular_file "$DESCRIPTOR" "$DESCRIPTOR_BYTES" \
        "$DESCRIPTOR_SHA256" 0:0:644
}

verify_remote_config() {
    [ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] \
        || fail "Flatpak repository config is missing or not a regular file"
    if [ -z "${NOID_FLATPAK_POLICY_TEST_MODE:-}" ]; then
        [ "$("$STAT" -c '%u:%g:%a' -- "$CONFIG")" = 0:0:644 ] \
            || fail "Flatpak repository config ownership/mode is not root:root 0644"
    fi

    "$PYTHON" - "$CONFIG" "$FLATHUB_URL" <<'PY_EOF' \
        || fail "Flatpak remote configuration is not the exact default policy"
import configparser
import os
import stat
import sys

path, expected_url = sys.argv[1:]
config = configparser.ConfigParser(interpolation=None, strict=True)
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(path, flags)
source_stat = os.fstat(fd)
if not stat.S_ISREG(source_stat.st_mode):
    os.close(fd)
    raise SystemExit("repository config is not a regular file")
if not os.environ.get("NOID_FLATPAK_POLICY_TEST_MODE"):
    metadata = (
        source_stat.st_uid,
        source_stat.st_gid,
        stat.S_IMODE(source_stat.st_mode),
    )
    if metadata != (0, 0, 0o644):
        os.close(fd)
        raise SystemExit("repository config metadata is not root:root 0644")
with os.fdopen(fd, "r", encoding="utf-8") as stream:
    config.read_file(stream)

expected_names = {"flathub", "flathub-verified"}
remote_sections = {
    section[len('remote "'):-1]: section
    for section in config.sections()
    if section.startswith('remote "') and section.endswith('"')
}
if set(remote_sections) != expected_names:
    raise SystemExit("unexpected remote set")

common_values = {
    "url": expected_url,
    "xa.title": "Flathub",
    "gpg-verify": "true",
    "gpg-verify-summary": "true",
    "xa.comment": "Central repository of Flatpak applications",
    "xa.description": "Central repository of Flatpak applications",
    "xa.icon": "https://dl.flathub.org/repo/logo.svg",
    "xa.homepage": "https://flathub.org/",
}
expected_keys = {
    "flathub": set(common_values) | {"xa.prio"},
    "flathub-verified": set(common_values)
    | {"xa.subset", "xa.subset-is-set", "xa.prio"},
}

def value(section, key, default=None):
    return config.get(section, key, fallback=default)

def enabled_bool(section, key, default):
    return config.getboolean(section, key, fallback=default)

for name in sorted(expected_names):
    section = remote_sections[name]
    actual_keys = set(config.options(section))
    if actual_keys != expected_keys[name]:
        missing = sorted(expected_keys[name] - actual_keys)
        extra = sorted(actual_keys - expected_keys[name])
        raise SystemExit(
            f"{name}: unexpected key set (missing={missing}, extra={extra})"
        )
    for key, expected in common_values.items():
        if value(section, key) != expected:
            raise SystemExit(f"{name}: {key} mismatch")
    if value(section, "url") != expected_url:
        raise SystemExit(f"{name}: URL mismatch")
    if not enabled_bool(section, "gpg-verify", False):
        raise SystemExit(f"{name}: commit GPG verification disabled")
    if not enabled_bool(section, "gpg-verify-summary", False):
        raise SystemExit(f"{name}: summary GPG verification disabled")
    if enabled_bool(section, "xa.disable", False):
        raise SystemExit(f"{name}: remote disabled")
    if enabled_bool(section, "xa.noenumerate", False):
        raise SystemExit(f"{name}: enumeration disabled")
    if enabled_bool(section, "xa.nodeps", False):
        raise SystemExit(f"{name}: dependency use disabled")
    if value(section, "collection-id") not in (None, ""):
        raise SystemExit(f"{name}: unexpected collection ID")
    if value(section, "xa.filter") not in (None, ""):
        raise SystemExit(f"{name}: unexpected local filter")

full = remote_sections["flathub"]
if value(full, "xa.subset") not in (None, ""):
    raise SystemExit("flathub: unexpected subset")
if int(value(full, "xa.prio", "1")) != 1:
    raise SystemExit("flathub: priority mismatch")

verified = remote_sections["flathub-verified"]
if value(verified, "xa.subset") != "verified":
    raise SystemExit("flathub-verified: subset mismatch")
if not enabled_bool(verified, "xa.subset-is-set", False):
    raise SystemExit("flathub-verified: subset marker missing")
if int(value(verified, "xa.prio", "1")) != 2:
    raise SystemExit("flathub-verified: priority mismatch")
PY_EOF
}

verify_one_trusted_key() (
    local remote=$1 path=$2 work='' exported bytes fingerprint sha

    trap '[ -z "$work" ] || rm -rf -- "$work"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    # GnuPG keyrings may contain deterministic trust-cache packets that are
    # not part of the upstream public-key export.  Export the complete public
    # keyring and compare those canonical bytes to the descriptor.  Exporting
    # only the expected fingerprint would fail to detect an additional trusted
    # signing key.
    work=$(mktemp -d "$KEY_VERIFY_TMPDIR/noid-flatpak-key.XXXXXXXX") \
        || fail "cannot create private key-verification directory"
    chmod 0700 "$work" \
        || fail "cannot protect private key-verification directory"
    exported="$work/export.gpg"
    "$GPG" --batch --no-options --homedir "$work" \
        --no-default-keyring --keyring "$path" --lock-never \
        --export > "$exported" \
        || fail "cannot export complete trusted keyring for $remote"
    fingerprint=$("$GPG" --batch --no-options --homedir "$work" \
        --with-colons --show-keys "$exported" 2>/dev/null \
        | awk -F: '$1 == "fpr" { print $10; exit }') \
        || fail "cannot inspect canonical trusted key for $remote"
    [ "$fingerprint" = "$TRUSTED_KEY_FINGERPRINT" ] \
        || fail "canonical trusted-key fingerprint mismatch for $remote"
    bytes=$("$STAT" -c '%s' -- "$exported") \
        || fail "cannot measure canonical trusted key for $remote"
    sha=$(sha256_of "$exported") \
        || fail "cannot hash canonical trusted key for $remote"
    [ "$bytes" = "$TRUSTED_KEY_EXPORT_BYTES" ] \
        || fail "canonical trusted-key byte count mismatch for $remote"
    [ "$sha" = "$TRUSTED_KEY_EXPORT_SHA256" ] \
        || fail "canonical trusted-key SHA-256 mismatch for $remote"
)

verify_trusted_keys() {
    local remote path owner_mode
    for remote in flathub flathub-verified; do
        path="$REPO_ROOT/$remote.trustedkeys.gpg"
        [ -f "$path" ] && [ ! -L "$path" ] \
            || fail "missing, non-regular or symlinked trusted key: $path"
        if [ -z "${NOID_FLATPAK_POLICY_TEST_MODE:-}" ]; then
            owner_mode=$("$STAT" -c '%u:%g:%a' -- "$path")
            [ "$owner_mode" = 0:0:644 ] \
                || fail "unexpected ownership or mode for $path"
        fi
        verify_one_trusted_key "$remote" "$path"
    done
}

catalog_count() {
    local remote=$1 mode=${2:-online} cached=() output
    local attempt=1 attempts=1
    [ "$mode" != cached ] || cached=(--cached)
    [ "$mode" = cached ] || attempts=$ONLINE_CATALOG_ATTEMPTS
    while ! output=$("$FLATPAK" remote-ls --system "${cached[@]}" \
            --columns=ref "$remote"); do
        [ "$attempt" -lt "$attempts" ] || return 1
        echo "noid-flatpak-remote-policy: $remote catalog transport failed; retry $((attempt + 1))/$attempts in ${ONLINE_CATALOG_RETRY_SECONDS}s" >&2
        sleep "$ONLINE_CATALOG_RETRY_SECONDS"
        attempt=$((attempt + 1))
    done
    awk 'NF { count++ } END { print count + 0 }' <<< "$output"
}

verify_catalogs() {
    local mode=$1 remote count
    for remote in flathub flathub-verified; do
        count=$(catalog_count "$remote" "$mode") \
            || fail "$remote catalog query failed ($mode)"
        [ "$count" -gt 0 ] \
            || fail "$remote catalog contains no usable refs ($mode)"
        echo "noid-flatpak-remote-policy: $remote catalog: $count refs ($mode)"
    done
}

verify_default() {
    local mode=${1:-cached}
    verify_descriptor
    verify_remote_config
    verify_trusted_keys
    verify_catalogs "$mode"
    echo "noid-flatpak-remote-policy: exact default remote policy verified"
}

apply_default() {
    local installed_refs remote
    require_root
    verify_descriptor
    installed_refs=$("$FLATPAK" list --system --columns=ref) \
        || fail "cannot enumerate installed system Flatpak refs"
    if [ -n "$installed_refs" ]; then
        fail "refusing remote reconciliation while system Flatpak refs are installed"
    fi

    load_system_remote_names
    for remote in "${SYSTEM_REMOTE_NAMES[@]}"; do
        # Do not use --force: Flatpak must independently refuse deletion if a
        # ref appears after the inventory check.
        "$FLATPAK" remote-delete --system "$remote" \
            || fail "cannot remove pre-existing system remote: $remote"
    done

    "$FLATPAK" remote-add --system --from --prio=1 \
        flathub "$DESCRIPTOR" \
        || fail "cannot add pinned full Flathub remote"
    "$FLATPAK" remote-add --system --from --prio=2 --subset=verified \
        flathub-verified "$DESCRIPTOR" \
        || fail "cannot add pinned verified-subset Flathub remote"
    verify_default online
}

fedora_in_use() {
    local origins
    origins=$("$FLATPAK" list --system --columns=origin) \
        || fail "cannot enumerate installed system Flatpak origins"
    grep -Fxq fedora <<< "$origins"
}

verify_fedora_remote() {
    "$PYTHON" - "$CONFIG" "$FEDORA_URL" <<'PY_EOF'
import configparser
import os
import stat
import sys

path, expected_url = sys.argv[1:]
config = configparser.ConfigParser(interpolation=None, strict=True)
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(path, flags)
source_stat = os.fstat(fd)
if not stat.S_ISREG(source_stat.st_mode):
    os.close(fd)
    raise SystemExit(1)
if not os.environ.get("NOID_FLATPAK_POLICY_TEST_MODE"):
    metadata = (
        source_stat.st_uid,
        source_stat.st_gid,
        stat.S_IMODE(source_stat.st_mode),
    )
    if metadata != (0, 0, 0o644):
        os.close(fd)
        raise SystemExit("Fedora remote config metadata is not root:root 0644")
with os.fdopen(fd, "r", encoding="utf-8") as stream:
    config.read_file(stream)
section = 'remote "fedora"'
if not config.has_section(section):
    raise SystemExit(1)
required_keys = {"url", "xa.title", "xa.title-is-set"}
optional_keys = {"xa.prio"}
actual_keys = set(config.options(section))
if not required_keys <= actual_keys or not (actual_keys - required_keys) <= optional_keys:
    raise SystemExit(1)
if config.get(section, "url", fallback="") != expected_url:
    raise SystemExit(1)
if config.get(section, "xa.title", fallback="") != "Fedora Flatpaks":
    raise SystemExit(1)
if not config.getboolean(section, "xa.title-is-set", fallback=False):
    raise SystemExit(1)
if config.getint(section, "xa.prio", fallback=1) != 1:
    raise SystemExit(1)
for key in ("xa.disable", "xa.noenumerate", "xa.nodeps"):
    if config.getboolean(section, key, fallback=False):
        raise SystemExit(1)
for key in ("collection-id", "xa.filter", "xa.subset"):
    if config.get(section, key, fallback=""):
        raise SystemExit(1)
PY_EOF
}

fedora_on() {
    local added=0
    require_root
    load_system_remote_names
    if system_remote_exists fedora-testing; then
        fail "fedora-testing is outside the explicit stable Fedora opt-in"
    fi
    if system_remote_exists fedora; then
        verify_fedora_remote \
            || fail "existing fedora remote has an unexpected identity; remove it explicitly first"
    else
        "$FLATPAK" remote-add --system --title='Fedora Flatpaks' \
            fedora "$FEDORA_URL" \
            || fail "cannot add the Fedora Flatpaks OCI remote"
        added=1
    fi
    if ! verify_fedora_remote; then
        if [ "$added" -eq 1 ]; then
            "$FLATPAK" remote-delete --system fedora \
                || fail "new Fedora remote failed verification and rollback failed"
            fail "new Fedora remote failed verification and was rolled back"
        fi
        fail "Fedora Flatpaks remote verification failed"
    fi
    echo "Fedora Flatpaks enabled explicitly; stock auto-add remains masked."
}

fedora_off() {
    require_root
    load_system_remote_names
    if system_remote_exists fedora-testing; then
        "$FLATPAK" remote-delete --system fedora-testing \
            || fail "cannot remove fedora-testing; remove its installed refs first"
    fi
    if system_remote_exists fedora; then
        fedora_in_use \
            && fail "fedora is in use; uninstall or migrate its refs before disabling it"
        "$FLATPAK" remote-delete --system fedora \
            || fail "cannot remove Fedora Flatpaks remote"
    fi
    echo "Fedora Flatpaks disabled; stock auto-add remains masked."
}

fedora_status() {
    load_system_remote_names
    if system_remote_exists fedora-testing; then
        echo "Fedora Flatpaks: DRIFT (fedora-testing is present)" >&2
        return 1
    fi
    if system_remote_exists fedora; then
        if verify_fedora_remote; then
            echo "Fedora Flatpaks: enabled (explicit stable remote)"
            return 0
        fi
        echo "Fedora Flatpaks: DRIFT (unexpected remote identity)" >&2
        return 1
    fi
    echo "Fedora Flatpaks: disabled (NoID Privacy default)"
}

require_command "$FLATPAK"
require_command "$GPG"
require_command "$PYTHON"
require_command "$SHA256SUM"
require_command "$STAT"

if [ "$program" = noid-toggle-fedora-flatpaks ]; then
    [ "$#" -eq 1 ] || { usage >&2; exit 2; }
    case "$1" in
        on) set -- fedora-on ;;
        off) set -- fedora-off ;;
        status) set -- fedora-status ;;
        -h|--help|help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
fi

action=${1:-}
case "$action" in
    apply-default)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        apply_default
        ;;
    verify-default)
        case "$#" in
            1) verify_default cached ;;
            2)
                [ "$2" = --online ] || { usage >&2; exit 2; }
                verify_default online
                ;;
            *) usage >&2; exit 2 ;;
        esac
        ;;
    fedora-on)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        fedora_on
        ;;
    fedora-off)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        fedora_off
        ;;
    fedora-status)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        fedora_status
        ;;
    -h|--help|help)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

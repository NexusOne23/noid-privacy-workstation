# ==============================================================================
# Module 18 — Flatpak sandboxing and repository trust
# Status: LOCKED 2026-08-14 (v35) — require Flatpak 1.18.1 security fixes.
#
# Covers:
#   - Phase 1: required Flatpak and portal packages
#   - Phase 2: maintained security-version baselines
#   - Phase 3: a reviewed, byte-pinned Flathub descriptor plus one canonical
#     policy controller embedded byte-identically from repository sources
#   - Phase 3a: native systemd disable+mask of Fedora's automatic OCI-remote
#     unit; no forged private implementation sentinel
#   - Phase 3b: fail-closed reconciliation to exactly two GPG-verified Flathub
#     views (full priority 1; publisher-verified subset priority 2), exact
#     config/key verification and live catalog proof
#   - Phase 4: global sandbox overrides
#   - Phase 5: installed trust-model and explicit Fedora opt-in documentation
#   - Phase 6: complete local postcondition verification
#
# Deliberate policy:
#   - Both the full Flathub catalog and its verified subset remain available.
#     Publisher verification is preferred, not misrepresented as a code audit.
#   - Flatseal is not bundled or auto-installed: first-boot acquisition would
#     violate the Silent-Machine default.  The user documentation carries
#     explicit commands.
#   - Fedora Flatpaks are disabled by default.  The stock auto-add service is
#     masked in /etc, while noid-toggle-fedora-flatpaks provides an explicit,
#     reversible stable-remote opt-in without ever enabling fedora-testing.
#
# Trust invariants:
#   - --if-not-exists is forbidden for NoID Privacy-owned remotes because a hostile
#     pre-existing name must never satisfy the policy.
#   - A fresh compose must have no installed system Flatpak refs before remote
#     reconciliation.  This makes deletion/recreation safe and deterministic.
#   - Descriptor bytes, the complete canonical trusted-key export, exact remote
#     key/value sets, URL, GPG verification, subset, priority and catalog
#     usability are all hard postconditions.
#   - The literal '~/' in --nofilesystem remains single-quoted so Flatpak
#     stores a per-user home-relative rule. Bash does not currently expand it
#     after this option name; quoting is defensive across shells/refactors.
#   - The compose-owned system-global override is reset and rebuilt exactly;
#     Flatpak's no-APP reset leaves system per-app overrides untouched.
#
# Cross-reference:
#   - M08 owns GNOME Software dconf preference only; M18 exclusively owns
#     Flatpak remote provisioning.  M17 owns location-portal policy.  M25 owns
#     explicit user-run Flatpak updates and unused-runtime cleanup.
#
# Package modifications: none beyond the base workstation environment.
# ==============================================================================

%packages --exclude-weakdeps
# No explicit additions. Base @workstation-product-environment supplies:
#   - flatpak, flatpak-selinux, flatpak-session-helper, bubblewrap
#   - xdg-desktop-portal, xdg-desktop-portal-gnome, xdg-desktop-portal-gtk
# Fedora's flatpak RPM Recommends p11-kit-server as a weak dependency. The
# image-wide --exclude-weakdeps policy intentionally does not promote it to a
# hard requirement: Flatpak retains its runtime CA bundle without it, while
# the package adds an on-demand local Unix-socket server that exports the host
# PKCS#11 trust module into compatible sandboxes. It is unrelated to X11 and
# to org.freedesktop.secrets. Do not add it solely to silence the session
# helper warning; install it deliberately when host PKCS#11 trust propagation
# is required by a supported application workflow.
# M26 separately adds jq for M25 + documented M29/M30 JSON checks.
# Empty block documents that this Module adds zero RPM packages.
%end

%post --log=/var/log/ks-18-flatpak-sandboxing.log --erroronfail
# ==============================================================================
# Module 18 — Flatpak Sandboxing (%post)
# ==============================================================================
set -e
set -o pipefail

PHASE=""

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [M18] ${PHASE}: $*"; }
die() { log "FAIL: $*"; exit 1; }

log "=== Module 18 Flatpak Sandboxing start ==="

# ------------------------------------------------------------------------------
# Phase 1 — Package presence verification
# ------------------------------------------------------------------------------
PHASE="P1-packages"
log "Verifying flatpak + bubblewrap + xdg-desktop-portal packages"

REQUIRED_PACKAGES=(
    flatpak
    flatpak-selinux
    flatpak-session-helper
    bubblewrap
    xdg-desktop-portal
    xdg-desktop-portal-gnome
    xdg-desktop-portal-gtk
)
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if ! rpm -q "$pkg" >/dev/null 2>&1; then
        die "Required package $pkg not installed"
    fi
done
log "All ${#REQUIRED_PACKAGES[@]} required packages present"

# ------------------------------------------------------------------------------
# Phase 2 — Maintained Flatpak/portal baseline + non-setuid bubblewrap
# ------------------------------------------------------------------------------
PHASE="P2-version"
log "Checking flatpak version >= 1.18.1 (security baseline on the supported stable branch)"

if ! FP_VER=$(flatpak --version 2>/dev/null | awk '{print $2}'); then
    die "flatpak --version failed"
fi
if [ -z "$FP_VER" ]; then
    die "Cannot determine flatpak version"
fi

MIN_VER="1.18.1"
LOWEST=$(printf '%s\n%s\n' "$FP_VER" "$MIN_VER" | sort -V | head -n 1)
if [ "$LOWEST" != "$MIN_VER" ]; then
    die "flatpak $FP_VER is below security baseline $MIN_VER"
fi
log "flatpak $FP_VER OK (>= $MIN_VER)"

# xdg-desktop-portal 1.22.1 fixes CVE-2026-55888 (arbitrary write access to
# nonexistent host files through FileChooser.SaveFiles) and CVE-2026-55889
# (drag-and-drop/copy-paste theft through a predictable FileTransfer key).
# Upstream documents no mitigation other than updating. Keep the explicit
# floor even though 1.20.x remains an otherwise maintained old-stable branch.
if ! XDP_VER=$(rpm -q --queryformat '%{VERSION}' xdg-desktop-portal 2>/dev/null); then
    die "rpm query for xdg-desktop-portal failed"
fi
if [ -z "$XDP_VER" ]; then
    die "Cannot determine xdg-desktop-portal version"
fi
XDP_MIN_VER="1.22.1"
XDP_LOWEST=$(printf '%s\n%s\n' "$XDP_VER" "$XDP_MIN_VER" | sort -V | head -n 1)
if [ "$XDP_LOWEST" != "$XDP_MIN_VER" ]; then
    die "xdg-desktop-portal $XDP_VER is below $XDP_MIN_VER (CVE-2026-55888/55889)"
fi
log "xdg-desktop-portal $XDP_VER OK (>= $XDP_MIN_VER)"

# CVE-2026-41163 affects bubblewrap 0.11.0 only when installed setuid.
# NoID Privacy enables bounded unprivileged user namespaces, so it has no
# compatibility reason to retain the deprecated setuid mode. Reject it
# regardless of version instead of accepting an unnecessary privileged path.
if [ ! -x /usr/bin/bwrap ]; then
    die "bubblewrap executable missing or not executable"
fi
if [ -u /usr/bin/bwrap ]; then
    die "setuid bubblewrap is forbidden (deprecated privileged mode; CVE-2026-41163)"
fi
log "bubblewrap uses the non-setuid user-namespace path"

# ------------------------------------------------------------------------------
# Phase 3 — Install the reviewed descriptor and canonical policy controller
# ------------------------------------------------------------------------------
PHASE="P3-policy-assets"
log "Installing pinned Flathub descriptor and Flatpak policy controller"

mkdir -p /usr/share/noid-flatpak /usr/local/libexec /usr/local/sbin

cat > /usr/share/noid-flatpak/flathub.flatpakrepo <<'NOID_FLATHUB_DESCRIPTOR_EOF'
[Flatpak Repo]
Title=Flathub
Url=https://dl.flathub.org/repo/
Homepage=https://flathub.org/
Comment=Central repository of Flatpak applications
Description=Central repository of Flatpak applications
Icon=https://dl.flathub.org/repo/logo.svg
GPGKey=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
NOID_FLATHUB_DESCRIPTOR_EOF
chmod 0644 /usr/share/noid-flatpak/flathub.flatpakrepo
chown root:root /usr/share/noid-flatpak/flathub.flatpakrepo

cat > /usr/local/libexec/noid-flatpak-remote-policy <<'NOID_FLATPAK_POLICY_EOF'
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
NOID_FLATPAK_POLICY_EOF
chmod 0750 /usr/local/libexec/noid-flatpak-remote-policy
chown root:root /usr/local/libexec/noid-flatpak-remote-policy
# 0755 (repo-wide noid-toggle convention): the read-only `status` verb is
# deliberately unprivileged (fedora_status has no require_root); on/off verbs
# self-gate on EUID and refuse without sudo.
install -o root -g root -m 0755     /usr/local/libexec/noid-flatpak-remote-policy     /usr/local/sbin/noid-toggle-fedora-flatpaks

# ------------------------------------------------------------------------------
# Phase 3a — Suppress Fedora OCI auto-registration through native systemd policy
# ------------------------------------------------------------------------------
PHASE="P3a-fedora-unit"
log "Disabling and masking flatpak-add-fedora-repos.service"

systemctl disable flatpak-add-fedora-repos.service >/dev/null 2>&1     || die "cannot disable flatpak-add-fedora-repos.service"
systemctl mask flatpak-add-fedora-repos.service >/dev/null 2>&1     || die "cannot mask flatpak-add-fedora-repos.service"
systemctl daemon-reload     || die "systemd daemon-reload failed after Flatpak unit mask"

# The sentinel is an implementation detail owned by Fedora's unit.  Never forge
# it to simulate a successful vendor initialization.
rm -f -- /var/lib/flatpak/.fedora-initialized
[ -L /etc/systemd/system/flatpak-add-fedora-repos.service ]     || die "Fedora Flatpak auto-add unit mask is not a symlink"
[ "$(readlink -f /etc/systemd/system/flatpak-add-fedora-repos.service)" = /dev/null ]     || die "Fedora Flatpak auto-add unit is not masked to /dev/null"
[ "$(systemctl is-enabled flatpak-add-fedora-repos.service 2>/dev/null || true)" = masked ]     || die "systemd does not report the Fedora Flatpak auto-add unit as masked"

# ------------------------------------------------------------------------------
# Phase 3b — Reconcile and prove the exact default remote trust policy
# ------------------------------------------------------------------------------
PHASE="P3b-remotes"
log "Reconciling exact pinned Flathub remote set and querying both catalogs"

/usr/local/libexec/noid-flatpak-remote-policy apply-default     || die "exact Flatpak remote reconciliation or live catalog proof failed"

log "Remotes verified: flathub priority 1 + flathub-verified subset priority 2"

# ------------------------------------------------------------------------------
# Phase 4 — Global overrides (D-Bus + sensitive-dir, deny-by-default)
# ------------------------------------------------------------------------------
PHASE="P4-overrides"
log "Setting global D-Bus and sensitive-directory overrides"

# The image owns the system-global layer. Remove inherited global drift before
# publishing the exact six-rule default. With no APP argument, Flatpak resets
# only the global override and preserves every system per-app override.
flatpak override --system --reset \
    || die "cannot reset the compose-owned system-global Flatpak override"

# Block 1a: systemd1 on the SYSTEM bus — blocks StartUnit/StopUnit against PID 1.
flatpak override --system --system-no-talk-name=org.freedesktop.systemd1 \
    2>&1 \
    || die "override --system-no-talk-name=org.freedesktop.systemd1 failed"

# Block 1b: systemd1 on the SESSION bus — the per-user manager owns the very
# same well-known name there (verified: `busctl --user list` shows
# org.freedesktop.systemd1 owned by user@1000.service). --system-no-talk-name
# writes only into [System Bus Policy], so without this twin an app whose
# manifest declares --talk-name=org.freedesktop.systemd1 kept full access to
# the user manager, and StartTransientUnit on that manager spawns a process on
# the host outside the sandbox -- the same total-escape class this module
# already closes for org.freedesktop.Flatpak in Block 3, which is why the
# omission was an asymmetry rather than a deliberate scope choice.
flatpak override --system --no-talk-name=org.freedesktop.systemd1 \
    2>&1 \
    || die "override --no-talk-name=org.freedesktop.systemd1 failed"

# Block 2: PackageKit — prevents sandboxed apps from RPM install calls
flatpak override --system --system-no-talk-name=org.freedesktop.PackageKit \
    2>&1 \
    || die "override --system-no-talk-name=org.freedesktop.PackageKit failed"

# Block 3: org.freedesktop.Flatpak — subtract the intentionally privileged
# flatpak-spawn --host interface from every app by default. This is a policy
# reduction for apps that declare the talk permission, not a vulnerability fix.
flatpak override --system --no-talk-name=org.freedesktop.Flatpak \
    2>&1 \
    || die "override --no-talk-name=org.freedesktop.Flatpak failed"

# Block 4+5: revoke SSH + GPG private-key directories from every app by default.
# Git/SSH, IDE, mail, signing and key-management workflows can legitimately need
# agent sockets or selected files; the installed guide documents narrow per-app
# recovery and rollback. A targeted deny avoids the broad breakage of denying all
# home access. Keep the literal '~/' single-quoted so Flatpak stores and expands
# a per-user home-relative rule. Bash does not currently tilde-expand it after
# this hyphenated option name; quoting is defensive across shells and refactors.
flatpak override --system --nofilesystem='~/.ssh' \
    2>&1 \
    || die "override --nofilesystem=~/.ssh failed"

flatpak override --system --nofilesystem='~/.gnupg' \
    2>&1 \
    || die "override --nofilesystem=~/.gnupg failed"

log "Global D-Bus and sensitive-directory overrides applied"

# ------------------------------------------------------------------------------
# Phase 5 — Trust-model documentation
# ------------------------------------------------------------------------------
PHASE="P5-trustdoc"
log "Writing trust-model documentation"

mkdir -p /usr/share/doc/noid-privacy

cat > /usr/share/doc/noid-privacy/18-flatpak-trust-model.md <<'TRUSTDOC_EOF'
# Flatpak Trust Model — NoID Privacy Workstation

This guide separates Flatpak's restrictive default sandbox from the permissions
that an actual app receives. Read it before installing an app or changing an
override.

## The effective sandbox is per app

Flatpak uses bubblewrap, namespaces, bind mounts, seccomp filtering, dropped
capabilities and filtered D-Bus access to construct an app sandbox. With no
additional grants, the upstream default has no host-file, network, host-device
or outside-process access and only limited bus access. Portals can mediate
selected operations such as choosing a file, printing or taking a screenshot.
Choosing a file deliberately gives that app access to the selected object
through the document portal. Such user-mediated grants are separate from static
filesystem overrides and must be reviewed or revoked separately.

Useful apps normally receive additional static permissions. The real boundary
for one launch is therefore determined by all of these layers:

1. the app's signed Flatpak metadata;
2. system-wide global and per-app overrides;
3. per-user global and per-app overrides;
4. dynamic portal grants; and
5. explicit one-run `flatpak run` arguments.

A manifest can deliberately grant network, X11, devices, home or host paths and
sensitive D-Bus interfaces. Do not generalize the empty default sandbox to every
installed app. Inspect static metadata with `flatpak info --show-permissions`,
override layers with `flatpak override --show`, and dynamic portal state with
`flatpak permissions`.

## Defense in depth and implementation defects

Flatpak describes increased desktop security through application isolation as
one of its main goals. That does not make every permission set appropriate for
every threat model, and the sandbox still relies on the host kernel, Flatpak,
bubblewrap and portal implementations. Keep those components updated.

Distinguish two different cases:

- A sandbox bug bypasses the intended permission model and needs a software fix.
- An app using a broad permission that its manifest or an override intentionally
  granted is not, by itself, a sandbox escape. It is an authority decision that
  must be reviewed and narrowed where practical.

The build enforces Flatpak 1.18.1 or newer on the supported 1.18.x stable
branch. Flatpak 1.18.1 is a security release which closes multiple sandbox,
system-helper and extraction boundary failures. The build also requires
`xdg-desktop-portal` 1.22.1 or newer and rejects setuid bubblewrap. These
component floors include fixes for the following known implementation defects;
they do not audit app permissions.

| Component / CVE | Impact | Fixed in |
|---|---|---|
| Flatpak CVE-2024-32462 | Host command execution through a portal flaw | 1.10.9 / 1.12.9 / 1.14.6 / 1.15.8 |
| Flatpak CVE-2024-42472 | Symlink following in `--persist` | 1.14.10 / 1.15.10 |
| Flatpak GHSA-2fxp-43j9-pwvc | OCI system-helper symlink following permits arbitrary file reads | 1.16.4 |
| Flatpak CVE-2026-34078 | `sandbox-expose` symlink sandbox escape | 1.16.4 |
| Flatpak CVE-2026-34079 | Host-file deletion through loader-cache handling | 1.16.4 |
| Flatpak GHSA-8688-9x26-hhxj | Host-filesystem access through app-data symlink traversal | 1.18.1 |
| Flatpak GHSA-qrwq-7qwx-q9rp | Local root escalation through revokefs traversal and commit tampering | 1.18.1 |
| Flatpak GHSA-fqx6-vh4p-42cg | Arbitrary root write through extra-data extraction traversal | 1.18.1 |
| Flatpak GHSA-8qxj-x646-phcm | Arbitrary root write through `build-init` path traversal | 1.18.1 |
| Flatpak GHSA-9rww-v4mm-x4jg | Host-file read through OCI hardlink traversal | 1.18.1 |
| Flatpak GHSA-v2gw-v9h5-9q4x | Appstream path traversal through an unvalidated architecture | 1.18.1 |
| Flatpak GHSA-jr92-2v97-wgvc | 32-bit OCI delta path-name buffer overflow | 1.18.1 |
| Flatpak GHSA-99wv-m8rp-g58x | Fixed-filename write through a loader-cache symlink | 1.18.1 |
| Flatpak GHSA-w69g-9x8j-7p8f | Extension-metadata traversal and unintended mounts | 1.18.1 |
| Flatpak GHSA-q4gr-vc25-57m5 | System-app anti-downgrade bypass | 1.18.1 |
| Portal CVE-2026-55888 | Arbitrary write access to nonexistent host files | 1.22.1 |
| Portal CVE-2026-55889 | Drag-and-drop/copy-paste theft via predictable transfer key | 1.22.1 |
| Bubblewrap CVE-2026-41163 | Privileged setup manipulation in deprecated setuid mode | 0.11.2, or non-setuid mode |

## Flathub "verified" badge

[Flathub](https://flathub.org/) distributes both verified and unverified apps.
According to Flathub's verification contract, a verified app is published by
its original developer or an authorized party. The publisher proves control of
the app-ID domain or an eligible source-hosting identity. Unverified apps can be
published by community members or other third parties.

The badge is publisher authorization for that app ID. It does **NOT** mean:

- The code has been audited
- The build is reproducible
- The package is free of vulnerabilities
- Each individual Flatpak commit carries a separate upstream signature or
  per-build attestation

This image ships both the full `flathub` remote and a
`flathub-verified` view restricted to Flathub's `verified` subset.  The subset
has priority 2 while the full catalog has priority 1, and GNOME Software prefers
the verified origin.  The full catalog deliberately remains available when the
user chooses an app whose publisher has not completed identity verification.
Verified is a preference, not a lock or a security attestation.

## Repository identity and Fedora opt-in

Module 18 imports one reviewed `.flatpakrepo` descriptor whose exact byte count
and SHA-256 are pinned in the image source.  Both remotes must use its exact URL,
presentation metadata, priority and subset fields, enable GPG verification for
commits and summaries, and expose only the exact reviewed public-key fingerprint
and canonical export bytes.  Additional trusted signing keys and unreviewed
remote options — including alternate content/proxy/TLS authority — fail closed.
GnuPG-local trust-cache packets are deliberately excluded from the identity
comparison.  An existing remote name is never trusted by name alone: on the
fresh compose root, all pre-existing remotes are enumerated successfully before
mutation, then removed without bypassing Flatpak's installed-ref protection and
both views are recreated from the pinned local descriptor.  The build then
requires a successful live catalog query for each view.  Lifecycle release
tests repeat that signed online proof explicitly: Flatpak may legitimately
discard cached summaries after ordinary transactions, so cache presence is not
treated as durable repository trust state.

NoID Privacy does not pin an HTTP protocol for these remotes. Transport
negotiation follows the maintained OSTree/libcurl default, so CDN and client
updates can select a currently working protocol without an image-specific
compatibility override. An explicit per-remote protocol option in either
direction is outside the reviewed remote schema and fails exact verification.
This does not relax TLS, commit/summary GPG verification, the trusted key,
catalog identity, priorities, or the separate Fedora OCI boundary.

Fedora's stock automatic OCI-remote unit is disabled and masked in `/etc`.
NoID Privacy does not forge `/var/lib/flatpak/.fedora-initialized`.  To opt into the
stable Fedora Flatpaks remote explicitly, use:

```bash
sudo noid-toggle-fedora-flatpaks on
noid-toggle-fedora-flatpaks status
sudo noid-toggle-fedora-flatpaks off
```

The opt-in does not enable `fedora-testing` and does not unmask the automatic
vendor unit.  Turning it off refuses while installed system Flatpaks still use
that origin, so applications cannot silently lose their update source.  A
failed remote or installed-origin inventory aborts before mutation, and status
reports an unexpected `fedora-testing` remote as drift rather than as a healthy
disabled state.

The Fedora source is an OCI registry remote, not an OSTree repository.  It does
not use the pinned `.flatpakrepo` descriptor and OSTree GPG-key contract applied
to the two Flathub views above.  NoID Privacy verifies its exact
`oci+https://registry.fedoraproject.org` URL, title and enablement flags;
Flatpak then uses the registry transport and its configured CA/client-certificate
trust.  This is a deliberately separate trust boundary, not equivalent evidence
to the pinned Flathub key proof.

`noid-flatpak-remote-policy verify-default` proves the exact two-remote default,
so it is expected to fail while the Fedora opt-in adds a third remote.  Use
`noid-toggle-fedora-flatpaks status` to verify that opt-in.  Turning Fedora off
restores the exact default that `verify-default` checks.

## Fedora RPMs in GNOME Software

The normal **Software** launcher is intentionally Flatpak-only. That keeps an
explicit store session fast and avoids starting the DNF5 daemon just to browse
Flatpaks. Native packages are not disabled or removed: DNF remains the primary
system-package path, and the official Fedora RPM for an application is often
the better choice when a Flatpak needs broad host permissions.

For one deliberate mixed-catalog session, open **NoID Privacy Setup -> GNOME
Software Sources -> Open GNOME Software with Fedora RPMs**, or right-click
**Software** in the app grid and choose **Open GNOME Software with Fedora
RPMs**. The equivalent command is:

```bash
/usr/local/bin/noid-gnome-software-rpm
```

This adds only GNOME Software's `appstream` and `dnf5` plugins to the reviewed
Flatpak plugin set for that process. It writes no preference, adds or enables no
repository, does not enable firmware handling, and does not change the next
launch. The DNF5 plugin reads **all currently enabled DNF repositories**, not
only Fedora's official repositories. Check the source shown by GNOME Software
and use `dnf repolist --enabled` when repository origin matters.

GNOME Software and Fedora 44's DNF5 daemon can remain resident after the last
window closes. Right-click **Software** and choose **Quit completely** when the
RPM session is finished. That action uses upstream's graceful quit path and
stops the backend only after it proves that no package-manager session remains.
While an RPM catalog job is settling, the desktop's busy indicator can remain
visible for several seconds. The helper observes that teardown every 250 ms for
at most 90 seconds; it fails closed instead of killing a session that remains
active.

## AppImage: per-application opt-in only

NoID Privacy does not install `appimaged`, scan directories for AppImages,
create launchers for them, or run an AppImage updater in the background. An
AppImage is a vendor binary bundle, not an RPM signature, Flatpak sandbox, or
automatic security-update contract. Its permissions are those of the desktop
user unless the application provides and you deliberately use a separate
sandbox.

Use an AppImage only as an explicit exception when no suitable maintained RPM
or reviewed Flatpak exists:

1. Download it from the application's official release channel.
2. Verify a vendor-published signature or checksum when available. A locally
   computed hash alone records the bytes you received; it does not prove who
   published them.
3. Record the exact version and provenance, review the vendor's update and
   privacy behavior, and keep responsibility for future security updates.
4. Store it in a user-owned directory, make only that file executable with
   `chmod 0700 APP.AppImage`, and launch it manually. Do not run it from
   `/tmp`, which is intentionally mounted `noexec` on NoID Privacy.
5. Remove the file and any application-created configuration/cache when the
   exception is no longer needed. Deleting the bundle alone does not remove
   data it wrote elsewhere in the home directory.

Automatic menu integration would turn a one-file exception into persistent
support state without adding a security boundary, so it remains outside the
default image. AppImage's own documentation also treats desktop integration,
signing and update information as optional facilities supplied per application,
not universal guarantees.

## Recommended workflow

1. Prefer the publisher-verified subset, while remembering that verification
   proves publisher identity rather than code safety.
2. Before installing, query the current signed catalog rather than trusting a
   copied version, commit or permission list:

   ```bash
   flatpak remote-info --system flathub-verified APP_ID
   flatpak remote-info --system --show-commit flathub-verified APP_ID
   flatpak remote-info --system --show-metadata flathub-verified APP_ID
   ```

3. Read the current Flathub manifest and explain every `finish-args` grant.
4. After installation, inspect the manifest permissions, every applicable
   override layer and dynamic grants. No single one of those views is a complete
   merged runtime proof.
5. Narrow broad permissions per app. For example, replace home access with
   `xdg-download` when that is all the workflow needs.
6. Remove unused runtimes with `flatpak uninstall --unused` and follow Flatpak's
   maintained security advisories.

## Why NoID Privacy blocks `org.freedesktop.Flatpak` globally

`flatpak-spawn --host` intentionally runs a command unsandboxed on the host and
requires access to the `org.freedesktop.Flatpak` session D-Bus interface. NoID Privacy's
global override subtracts that talk permission from all apps by default.

This is a deliberate reduction of an upstream interface, not a claim that the
interface is an implementation vulnerability. Apps that never request the
interface are unaffected. Developer tools, IDEs, terminals and container or SDK
frontends that intentionally integrate with the host can be affected. Prefer a
reviewed host RPM for such workflows, or make a narrowly reviewed per-app
exception with full awareness that it enables unsandboxed host command execution.

```bash
flatpak override --user --talk-name=org.freedesktop.Flatpak APP_ID
flatpak override --user --show APP_ID
# Revoke the exception:
flatpak override --user --no-talk-name=org.freedesktop.Flatpak APP_ID
```

## Why we block host service-management interfaces globally

The global policy also denies three host-management interfaces that an app may
have requested in its manifest:

- `org.freedesktop.systemd1` on the session bus, which can ask the per-user
  manager to create scopes, services or transient units outside the sandbox;
- `org.freedesktop.systemd1` on the system bus, which addresses PID 1; and
- `org.freedesktop.PackageKit` on the system bus, which can request host RPM
  operations subject to the host authorization policy.

No Flatpak apps are preinstalled, so this compatibility cost begins only after
a user installs one. Background-helper, development or package-management
features can fail when an app genuinely relies on one of these interfaces.
Review the app's signed metadata and the requested method surface before
granting only the bus name it needs to one exact app:

```bash
APP_ID=com.example.App
# User-manager integration:
flatpak override --user --talk-name=org.freedesktop.systemd1 "$APP_ID"
# PID 1 integration (rare and high authority):
flatpak override --user --system-talk-name=org.freedesktop.systemd1 "$APP_ID"
# Host package-management integration:
flatpak override --user --system-talk-name=org.freedesktop.PackageKit "$APP_ID"
flatpak override --user --show "$APP_ID"
```

Revoke only those exceptions without resetting unrelated per-app choices:

```bash
flatpak override --user --no-talk-name=org.freedesktop.systemd1 "$APP_ID"
flatpak override --user --system-no-talk-name=org.freedesktop.systemd1 "$APP_ID"
flatpak override --user --system-no-talk-name=org.freedesktop.PackageKit "$APP_ID"
```

## Why we block `~/.ssh` and `~/.gnupg` globally

This image also sets two global filesystem overrides that deny every Flatpak app
access to private-key directories by default:

- `~/.ssh` — SSH private keys, `known_hosts`, client config
- `~/.gnupg` — GPG private keys, trust database

This is a high-value default, but it has real compatibility cost. Git clients,
IDEs, SSH frontends, mail clients, signing tools and key managers can
legitimately need an agent socket or selected credential files. A broad
`filesystem=home` grant does not cancel these more specific denies; conversely,
a higher-precedence per-app grant can override a global rule.

Prefer agent sockets when the workflow supports them because they do not expose
the private-key files. They still delegate cryptographic authority: an app with
`ssh-auth` can request SSH-agent signatures, and `gpg-agent` can permit signing,
decryption or other privileged GPG operations subject to the agent's policy and
cached authentication. Grant either socket only to a reviewed app that needs
that authority:

```bash
APP_ID=com.example.App
flatpak override --user --socket=ssh-auth "$APP_ID"
flatpak override --user --socket=gpg-agent "$APP_ID"
```

Only if the reviewed workflow genuinely needs direct files, grant the minimum
directory read-only to that one app. Some workflows that update `known_hosts`,
trust state or key material will require write access; do not grant it silently.

```bash
flatpak override --user --filesystem='~/.ssh:ro' "$APP_ID"
flatpak override --user --filesystem='~/.gnupg:ro' "$APP_ID"
```

Audit all layers and the app's declared metadata:

```bash
flatpak info --show-permissions "$APP_ID"
flatpak override --system --show
flatpak override --system --show "$APP_ID"
flatpak override --user --show
flatpak override --user --show "$APP_ID"
```

Revoke only these exceptions while preserving unrelated per-app overrides:

```bash
flatpak override --user --nosocket=ssh-auth "$APP_ID"
flatpak override --user --nosocket=gpg-agent "$APP_ID"
flatpak override --user --nofilesystem='~/.ssh' "$APP_ID"
flatpak override --user --nofilesystem='~/.gnupg' "$APP_ID"
```

`flatpak override --user --reset "$APP_ID"` removes every per-app user override,
including unrelated ones. Manifest and system-wide overrides still apply.

This does **not** globally block `filesystem=home` or the X11 socket because
some packaged apps and workflows still require them. Tighten those **per-app**
after checking the current signed metadata and testing native Wayland and
portal-based file access with Flatseal or `flatpak override --user`.

## Optional Flatseal inspection UI

Flatseal is **not bundled or automatically installed** in this image
(Silent-Machine policy — no automatic first-boot acquisition and no otherwise
unused GNOME runtime). It is a useful permissions UI and mutable third-party
Flatpak, not a NoID Privacy trust anchor. It does not add a second sandbox.
Before each install, confirm that its ID is still
present in `flathub-verified`, record the current signed commit and inspect its
current metadata. A verification badge establishes publisher identity only; it
is not a code audit or blanket safety verdict.

```bash
flatpak remote-info --system flathub-verified com.github.tchx84.Flatseal
flatpak remote-info --system --show-commit flathub-verified com.github.tchx84.Flatseal
flatpak remote-info --system --show-metadata flathub-verified com.github.tchx84.Flatseal
flatpak install --system flathub-verified com.github.tchx84.Flatseal
```

Flatseal necessarily reads installed-app metadata and writes per-user Flatpak
override state. Per-app user overrides can deliberately relax a system-global
default for that app, so every change remains a user trust decision. Flatseal
package identity, permissions and source are mutable and must be reviewed at
installation time; this guide intentionally carries no timeless permission
verdict for it.

Alternative: if you prefer zero additional Flatpaks, use the CLI instead of
Flatseal:

```bash
flatpak info --show-permissions <app-id>
flatpak override --user --nofilesystem=host <app-id>   # revoke host filesystem
flatpak override --user --nosocket=x11 <app-id>        # revoke X11 socket
flatpak override --user --nodevice=all <app-id>        # revoke device access
flatpak permissions                                     # list all portal grants
```

## Permission audit with Flatseal

Flatseal provides a GUI over static permissions and overrides. Desktop settings
can expose some portal-managed permissions; coverage differs by desktop and
release. Neither UI replaces checking the signed app metadata and all override
scopes.

For every Flatpak app you install, open Flatseal, select the app, and review:

- **Filesystem** — revoke broad grants (`host`, `home`), keep narrow ones
  (`xdg-download`, `xdg-documents`)
- **Session Bus** — remove talk names you don't understand
- **System Bus** — high-risk host-service authority; justify each talk name
- **Features** — disable `devel`, `bluetooth`, `smartcard` unless needed
- **Shared** — `network` can be removed for offline-only apps
- **Sockets** — justify each socket against the workflow; audio, printing,
  smartcard and SSH/GPG-agent sockets can all carry sensitive authority

## CLI permission management

For users who prefer CLI over GUI:

```
# Show all permissions for an app
flatpak info --show-permissions <app-id>

# List all portal permissions ever granted
flatpak permissions

# Reset all portal permissions for an app
flatpak permission-reset <app-id>

# Set a user-level override (persists across updates)
flatpak override --user --nofilesystem=home <app-id>
flatpak override --user --no-talk-name=org.freedesktop.secrets <app-id>

# Show current overrides for an app
flatpak override --user --show <app-id>

# Remove all per-app user overrides (manifest and system overrides still apply)
flatpak override --user --reset <app-id>
```

## References

- [Flatpak sandbox permissions](https://docs.flatpak.org/en/latest/sandbox-permissions.html)
- [Flatpak command reference](https://docs.flatpak.org/en/latest/flatpak-command-reference.html)
- [Flatpak CVE Advisories](https://github.com/flatpak/flatpak/security/advisories)
- [OSTree repository configuration](https://ostreedev.github.io/ostree/man/ostree.repo-config.html)
- [Flathub Verification](https://docs.flathub.org/docs/for-users/verification)
- [Flathub permission review](https://docs.flathub.org/docs/for-users/permissions)
- [Flatseal Documentation](https://github.com/tchx84/Flatseal)
- [Bubblewrap](https://github.com/containers/bubblewrap)
TRUSTDOC_EOF

chmod 0644 /usr/share/doc/noid-privacy/18-flatpak-trust-model.md
log "Trust-model doc written"

# ------------------------------------------------------------------------------
# Phase 6 — Verification block
# ------------------------------------------------------------------------------
# NOTE: the former Flatseal auto-install phase was REMOVED (Silent-Machine:
# first-boot acquisition and a potentially new GNOME runtime without user
# action). The trust-model doc carries the manual install command; the checks
# below assert the auto-installer artifacts stay ABSENT.
PHASE="P6-verify"
log "Running verification block"

checks=0
fails=0

check() {
    checks=$((checks + 1))
    if eval "$1" >/dev/null 2>&1; then
        log "  [OK] $2"
    else
        fails=$((fails + 1))
        log "  [FAIL] $2"
    fi
}

remote_absent() {
    ! grep -Fxq "$1" <<< "$REMOTE_INVENTORY"
}

verify_exact_global_overrides() {
    python3 - /var/lib/flatpak/overrides/global <<'PY_EOF'
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
}

# Packages
check "rpm -q flatpak" "flatpak package present"
check "rpm -q flatpak-selinux" "flatpak-selinux present (SELinux policy module)"
check "rpm -q flatpak-session-helper" "flatpak-session-helper present"
check "rpm -q bubblewrap" "bubblewrap present"
check "[ ! -u /usr/bin/bwrap ]" "bubblewrap executable is not setuid"
check "rpm -q xdg-desktop-portal" "xdg-desktop-portal present"
check "rpm -q xdg-desktop-portal-gnome" "xdg-desktop-portal-gnome present"
check "rpm -q xdg-desktop-portal-gtk" "xdg-desktop-portal-gtk present (Lockdown iface)"

# Native Fedora-remote suppression and absence of forged implementation state
check "[ -L /etc/systemd/system/flatpak-add-fedora-repos.service ]"     "Fedora Flatpak auto-add unit has an /etc mask"
check "[ \"\$(readlink -f /etc/systemd/system/flatpak-add-fedora-repos.service)\" = /dev/null ]"     "Fedora Flatpak auto-add unit mask resolves to /dev/null"
check "[ \"\$(systemctl is-enabled flatpak-add-fedora-repos.service 2>/dev/null || true)\" = masked ]"     "systemd reports Fedora Flatpak auto-add unit masked"
check "[ ! -e /var/lib/flatpak/.fedora-initialized ]"     "Fedora private initialization sentinel is not forged"
REMOTE_INVENTORY=$(flatpak remotes --system --show-disabled --columns=name) \
    || die "cannot enumerate system Flatpak remotes during final verification"
check "remote_absent fedora"     "fedora OCI remote absent by default"
check "remote_absent fedora-testing"     "fedora-testing OCI remote absent by default"

# Exact descriptor, config, key bytes and cached catalog usability
check "[ -x /usr/local/libexec/noid-flatpak-remote-policy ]"     "canonical Flatpak remote policy controller installed"
check "[ -x /usr/local/sbin/noid-toggle-fedora-flatpaks ]"     "explicit Fedora Flatpaks opt-in helper installed"
check "cmp -s /usr/local/libexec/noid-flatpak-remote-policy /usr/local/sbin/noid-toggle-fedora-flatpaks"     "Flatpak controller and user-facing helper are byte-identical"
check "/usr/local/libexec/noid-flatpak-remote-policy verify-default"     "exact GPG-verified Flathub remote policy and cached catalogs verified"

# Global overrides — prove the CLI can enumerate the system layer, then parse
# the stored INI with an exact section/key/value allowlist.
flatpak override --system --show >/dev/null 2>&1 \
    || die "cannot enumerate global Flatpak overrides during final verification"
check "verify_exact_global_overrides" \
    "system-global override is exactly the six-rule NoID Privacy policy"

# Artifacts
check "[ -f /usr/share/doc/noid-privacy/18-flatpak-trust-model.md ]" \
    "trust-model doc written (includes Flatseal manual-install instructions)"

# Silent-Machine policy — Flatseal NOT auto-installed
check "[ ! -x /usr/local/bin/noid-flatseal-install.sh ]" \
    "noid-flatseal-install.sh ABSENT (Silent-Machine: no auto-install)"
check "[ ! -f /etc/systemd/system/noid-flatseal-install.service ]" \
    "noid-flatseal-install.service ABSENT (Silent-Machine: no auto-install)"
check "[ ! -L /etc/systemd/system/multi-user.target.wants/noid-flatseal-install.service ]" \
    "noid-flatseal-install symlink ABSENT (Silent-Machine: no auto-install)"

log "Verification: $((checks - fails))/$checks passed"
if [ "$fails" -gt 0 ]; then
    die "$fails verification check(s) FAILED"
fi

log "=== Module 18 Flatpak Sandboxing complete ==="
%end

#!/bin/bash
# tests/smoke/prep-rootfs.sh — one-time rootfs preparation
#
# Creates a minimal Fedora 44 rootfs for smoke tests under
# /var/cache/noid-smoke/rootfs-f44. Run once; re-run only when you want
# to refresh the cached rootfs against current Fedora packages.
#
# Requirements:
#   - sudo
#   - dnf
#   - redhat-rpm-config (Fedora vendor rpmrc + macros)
#   - ~2 GB free for the prepared rootfs
#   - Network (first run only)
set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin
umask 022

ROOTFS_DIR="${NOID_SMOKE_ROOTFS:-/var/cache/noid-smoke/rootfs-f44}"
RELEASEVER="${NOID_SMOKE_RELEASEVER:-44}"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
ROOTFS_OWNER_MARKER=".noid-smoke-rootfs-owner"

[[ "$RELEASEVER" =~ ^[0-9]+$ ]] || {
    echo "ERR: NOID_SMOKE_RELEASEVER must be an unsigned Fedora release number" >&2
    exit 2
}
[[ "$ROOTFS_DIR" = /* ]] || {
    echo "ERR: NOID_SMOKE_ROOTFS must be an absolute path" >&2
    exit 2
}
expected_rootfs_leaf="rootfs-f${RELEASEVER}"
[ "$(basename -- "$ROOTFS_DIR")" = "$expected_rootfs_leaf" ] || {
    echo "ERR: smoke rootfs target must end in /${expected_rootfs_leaf}" >&2
    exit 2
}
ROOTFS_PARENT="$(dirname -- "$ROOTFS_DIR")"
[ "$ROOTFS_PARENT" != / ] || {
    echo "ERR: smoke rootfs target cannot be a direct child of /" >&2
    exit 2
}
[ ! -L "$ROOTFS_DIR" ] || {
    echo "ERR: smoke rootfs target must not be a symlink: $ROOTFS_DIR" >&2
    exit 2
}

if [ "$(id -u)" -ne 0 ]; then
    echo "ERR: must run as root (dnf --installroot requires it)" >&2
    exit 1
fi

# The closed RPM configuration below deliberately names Fedora's vendor tiers.
# Refuse a partial host toolchain before creating or replacing any fixture.
FEDORA_RPM_CONFIG_FILES=(
    /usr/lib/rpm/redhat/rpmrc
    /usr/lib/rpm/redhat/macros
)
for config_file in "${FEDORA_RPM_CONFIG_FILES[@]}"; do
    if [ ! -f "$config_file" ]; then
        echo "ERR: Fedora RPM vendor configuration missing: $config_file" >&2
        echo "     Install the Fedora package: sudo dnf install redhat-rpm-config" >&2
        exit 1
    fi
done

validate_private_root_directory() {
    local path=$1 label=$2 canonical metadata owner group mode
    [ -d "$path" ] && [ ! -L "$path" ] || {
        echo "ERR: $label must be a real directory: $path" >&2
        return 1
    }
    canonical="$(readlink -e -- "$path" 2>/dev/null || true)"
    [ "$canonical" = "$path" ] || {
        echo "ERR: $label must use its direct canonical path: $path" >&2
        return 1
    }
    metadata="$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null || true)"
    IFS=: read -r owner group mode <<< "$metadata"
    if [ "${owner:-}" != 0 ] || [ "${group:-}" != 0 ] \
            || ! [[ "${mode:-}" =~ ^[0-7]{3,4}$ ]] \
            || (( (8#$mode & 0022) != 0 )); then
        echo "ERR: $label must be root-owned and not group/other-writable: $path" >&2
        return 1
    fi
}

# Create at most the one dedicated cache parent. Never use recursive mkdir on
# an environment-selected root path: every pre-existing ancestor must already
# be a canonical, root-owned, non-writable directory.
if [ ! -e "$ROOTFS_PARENT" ] && [ ! -L "$ROOTFS_PARENT" ]; then
    ROOTFS_GRANDPARENT="$(dirname -- "$ROOTFS_PARENT")"
    validate_private_root_directory "$ROOTFS_GRANDPARENT" \
        "smoke rootfs parent ancestor"
    mkdir --mode 0755 -- "$ROOTFS_PARENT"
fi
validate_private_root_directory "$ROOTFS_PARENT" "smoke rootfs parent"

# Minimal package set — matches what the four smoke modules need to run in a
# sandbox. Avoid unrelated heavy deps and systemd boot plumbing, but retain the
# Fedora packages whose vendor bytes the modules verify. M27 also proves the
# installed kernel configuration before disabling TuneD's inherited modules
# plug-in, so the fixture needs kernel-core's /usr/lib/modules/*/config payload
# evidence even when install scriptlets do not populate /boot.
PACKAGES=(
    # Core
    bash coreutils cpio gzip util-linux findutils gawk grep sed procps-ng sudo
    glibc-common filesystem
    # Package tools (so dnf interaction in %post doesn't crash)
    rpm rpm-build-libs dnf5 dnf5-plugins
    # Systemd for unit-file parsing (not running)
    systemd systemd-libs systemd-udev
    # File integrity + restorecon for %post SELinux calls. restorecon/setfiles
    # ship in policycoreutils, NOT libselinux-utils; M17's launcher-sync helper
    # hard-requires restorecon and validates the published launcher with
    # `matchpathcon -V`, which needs the file_contexts DB from
    # selinux-policy-targeted — exactly as the SELinux-enforcing image provides.
    libselinux libselinux-utils policycoreutils selinux-policy-targeted
    # For M13 AIDE heredoc assertions (AIDE not run, just parse)
    # aide — excluded; too heavy + triggers database build
    # For M17 GNOME dconf compile, validated launcher publication, the
    # RPM-owned gnome-shell privacy-producer contract, and its M14
    # static-notifier integration gate
    glib2 dconf desktop-file-utils pipewire-utils usbguard-notifier
    gnome-shell gnome-text-editor
    # M17 authenticates and transforms the exact Fedora Live-installer payload.
    anaconda-core anaconda-live
    # M17's RPM-backed seven-descriptor D-Bus integrity contract
    gnome-software gnome-online-accounts localsearch tinysparql
    # For M14 USBGuard lib heredoc parsing
    # usbguard daemon — excluded; service heavy. The notifier's vendor user
    # unit is retained above because M17 verifies M14's exact static link.
    # For M11 systemd-resolved config parsing
    systemd-resolved
    # Module-specific packages whose %post verification checks rpm/unit files.
    NetworkManager
    earlyoom tuned tuned-ppd zram-generator zram-generator-defaults
    kernel-core udisks2
    # M27 STEP 2c presets Fedora's thermald unit and cross-checks the M08
    # intel_lpmd mask via `systemctl --root=/`; the unit files must be present
    # exactly as the real image installs them (27-hardware-tuning.ks
    # %packages: thermald intel-lpmd — lpmd unit itself is M08-masked).
    thermald intel-lpmd
)

echo "[prep-rootfs] Installing Fedora ${RELEASEVER} minimal rootfs to ${ROOTFS_DIR}"
echo "[prep-rootfs] This will take 2-5 minutes and ~500 MB download."

if [ -e "$ROOTFS_DIR" ] || [ -L "$ROOTFS_DIR" ]; then
    validate_private_root_directory "$ROOTFS_DIR" "existing smoke rootfs"
    if /usr/bin/mountpoint -q -- "$ROOTFS_DIR"; then
        echo "ERR: refusing to remove a mounted smoke rootfs: $ROOTFS_DIR" >&2
        exit 2
    fi
    owner_marker="$ROOTFS_DIR/$ROOTFS_OWNER_MARKER"
    legacy_manifest="$ROOTFS_DIR/.noid-smoke-rootfs-manifest"
    marker_ok=0
    if [ -e "$owner_marker" ] || [ -L "$owner_marker" ]; then
        if [ -f "$owner_marker" ] && [ ! -L "$owner_marker" ] \
                && [ "$(stat -Lc '%u:%g:%a:%h' -- "$owner_marker" 2>/dev/null || true)" = 0:0:644:1 ] \
                && [ "$(cat -- "$owner_marker")" = "NOID_SMOKE_ROOTFS_V1 releasever=$RELEASEVER" ]; then
            marker_ok=1
        fi
    elif [ -f "$legacy_manifest" ] && [ ! -L "$legacy_manifest" ]; then
        # One-way compatibility with rootfs caches created before the owner
        # marker and explicit umask existed. A hardened caller umask produced
        # mode 0640 while the ordinary default produced 0644; both are
        # root-owned, single-link and non-writable outside root.
        legacy_metadata="$(stat -Lc '%u:%g:%a:%h' -- \
            "$legacy_manifest" 2>/dev/null || true)"
        case "$legacy_metadata" in
            0:0:640:1|0:0:644:1)
                if [ "$(grep -cFx -- "releasever=$RELEASEVER" \
                        "$legacy_manifest" 2>/dev/null || true)" -eq 1 ]; then
                    marker_ok=1
                fi
                ;;
        esac
    fi
    [ "$marker_ok" -eq 1 ] || {
        echo "ERR: refusing to remove an unmarked smoke rootfs: $ROOTFS_DIR" >&2
        exit 2
    }
    echo "[prep-rootfs] Existing rootfs at $ROOTFS_DIR — removing for fresh install"
    rm -rf --one-file-system -- "$ROOTFS_DIR"
    [ ! -e "$ROOTFS_DIR" ] && [ ! -L "$ROOTFS_DIR" ] || {
        echo "ERR: smoke rootfs removal did not complete: $ROOTFS_DIR" >&2
        exit 2
    }
fi

mkdir --mode 0755 -- "$ROOTFS_DIR"
printf '%s\n' "NOID_SMOKE_ROOTFS_V1 releasever=$RELEASEVER" \
    > "$ROOTFS_DIR/$ROOTFS_OWNER_MARKER"
chmod 0644 "$ROOTFS_DIR/$ROOTFS_OWNER_MARKER"

# Bootstrap Fedora's usr-merge layout before rpm/dnf touch the empty root.
# Without this, dnf5 may create /lib64 as a real directory for its own runtime
# helpers; the filesystem RPM then correctly refuses to replace it with the
# required symlink and the entire transaction fails.
mkdir -p "$ROOTFS_DIR/usr/bin" "$ROOTFS_DIR/usr/sbin" \
         "$ROOTFS_DIR/usr/lib" "$ROOTFS_DIR/usr/lib64" \
         "$ROOTFS_DIR/usr/lib/sysimage/rpm"
ln -s usr/bin "$ROOTFS_DIR/bin"
ln -s usr/sbin "$ROOTFS_DIR/sbin"
ln -s usr/lib "$ROOTFS_DIR/lib"
ln -s usr/lib64 "$ROOTFS_DIR/lib64"

# rpmdb runs in rpmdb_t on an enforcing Fedora host. A cache-rooted installroot
# otherwise inherits var_t, which rpmdb_t correctly cannot write. Label only
# the fixture database directory from Fedora's native RPM database reference;
# do not weaken enforcing mode or install a persistent host fcontext rule.
chcon --reference=/usr/lib/sysimage/rpm "$ROOTFS_DIR/usr/lib/sysimage/rpm"

# Seed the exact Fedora release/architecture key into the installroot before
# DNF resolves any package. A smoke fixture built without package signature
# verification cannot support release evidence, so absence/import failure is
# terminal rather than a reason to weaken the transaction.
HOST_GPG_KEY="/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-${RELEASEVER}-x86_64"
ROOT_GPG_KEY="/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-${RELEASEVER}-x86_64"
if [ ! -f "$HOST_GPG_KEY" ]; then
    echo "ERR: Fedora ${RELEASEVER} x86_64 signing key missing: $HOST_GPG_KEY" >&2
    exit 1
fi
mkdir -p "$ROOTFS_DIR/etc/pki/rpm-gpg"
install -m 0644 "$HOST_GPG_KEY" "$ROOTFS_DIR$ROOT_GPG_KEY"
# RPM's default configuration hierarchy ends in a per-user rpmrc and macro
# tier.  The rootfs bootstrap is a system transaction and must not inspect the
# invoking account's home (or inherit an untrusted user macro).  Retain the
# Fedora factory, vendor and host tiers explicitly and close the user tier for
# every bootstrap operation.
RPM_BOOTSTRAP_CONFIG_HOME="$ROOTFS_DIR/.noid-rpm-config"
install -d -m 0755 -o root -g root "$RPM_BOOTSTRAP_CONFIG_HOME"
RPM_BOOTSTRAP_RCFILES='/usr/lib/rpm/rpmrc:/usr/lib/rpm/redhat/rpmrc'
RPM_BOOTSTRAP_MACROFILES='/usr/lib/rpm/macros:/usr/lib/rpm/macros.d/macros.*:/usr/lib/rpm/platform/%{_target}/macros:/usr/lib/rpm/fileattrs/*.attr:/usr/lib/rpm/redhat/macros:/etc/rpm/macros.*:/etc/rpm/macros:/etc/rpm/%{_target}/macros'
RPM_BOOTSTRAP=(env XDG_CONFIG_HOME="$RPM_BOOTSTRAP_CONFIG_HOME" \
    rpm --rcfile "$RPM_BOOTSTRAP_RCFILES" \
    --macros "$RPM_BOOTSTRAP_MACROFILES" --root="$ROOTFS_DIR")
"${RPM_BOOTSTRAP[@]}" --initdb
"${RPM_BOOTSTRAP[@]}" --import "$ROOT_GPG_KEY"
"${RPM_BOOTSTRAP[@]}" -q gpg-pubkey >/dev/null
echo "[prep-rootfs] Imported Fedora ${RELEASEVER} x86_64 key → fail-closed install"

# dnf5 needs --use-host-config to discover repos for a fresh installroot.
# Restrict that inherited config to Fedora base+updates so unrelated host
# repos are never contacted. This rootfs is a file-level bwrap fixture, not a
# bootable system; noscripts avoids RPM-6 scriptlets trying to chroot before
# the minimal /usr/bin + /bin layout is complete.
env XDG_CONFIG_HOME="$RPM_BOOTSTRAP_CONFIG_HOME" dnf --installroot="$ROOTFS_DIR" \
    --releasever="$RELEASEVER" \
    --use-host-config \
    --repo=fedora \
    --repo=updates \
    --setopt=install_weak_deps=False \
    --setopt=tsflags=noscripts,notriggers \
    --assumeyes \
    install \
    "${PACKAGES[@]}"

# Lorax supplies this root-owned, non-writable parent in a real Live compose.
# M17 fails closed before publishing its native Anaconda updates image if that
# trust boundary is absent or unsafe, so the isolated rootfs must model it.
install -d -m 0755 -o root -g root "$ROOTFS_DIR/boot/loader"

# Minimal /etc/resolv.conf so %post's rare DNS lookups don't fail
# (sandbox disables --share-net anyway, but some %post blocks grep
#  /etc/resolv.conf for existing config)
echo "nameserver 127.0.0.1" > "$ROOTFS_DIR/etc/resolv.conf"

# Mark the rootfs ready only after the signed package transaction completed.
# Bind the cache to the complete preparation definition: otherwise a package
# added above can leave an older, superficially valid rootfs silently in use.
definition_sha256="$(sha256sum "$SCRIPT_PATH" | awk '{print $1}')"
{
    echo "manifest-version=2"
    echo "releasever=$RELEASEVER"
    echo "definition-sha256=$definition_sha256"
    echo "prepared-at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$ROOTFS_DIR/.noid-smoke-rootfs-manifest"
chmod 0644 "$ROOTFS_DIR/.noid-smoke-rootfs-manifest"

# Report size
size=$(du -sh "$ROOTFS_DIR" | awk '{print $1}')
echo "[prep-rootfs] Done. Rootfs size: ${size}, path: ${ROOTFS_DIR}"
echo "[prep-rootfs] Run smoke tests: sudo ./tests/smoke/run-all.sh"

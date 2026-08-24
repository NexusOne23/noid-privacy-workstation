#!/usr/bin/env bash
#
# NoID Privacy Workstation — ISO build wrapper
#
# Wraps livemedia-creator with:
#   - Kickstart flattening (ksflatten)
#   - Mandatory, SHA256-verified branding/payload staging over a
#     loopback-only build server
#   - Reproducible build args (SOURCE_DATE_EPOCH)
#   - Write-once unsigned candidate output; signing is a separate post-VM gate
#
# Usage:
#   sudo -v && scripts/build-iso.sh         # canonical KVM build
#   scripts/build-iso.sh --with-assets      # deprecated compatibility alias
#   scripts/build-iso.sh --no-virt          # dirinstall inside an Enforcing build VM
#
# Requirements:
#   - Fedora 44 build host
#   - lorax-lmc-virt (default KVM mode) + lorax-lmc-novirt (--no-virt),
#     anaconda, pykickstart and patch
#
# Branding status: the repository payload is a mandatory canonical-build
# input. KVM guests reach the host's loopback server through qemu user-mode
# NAT; --no-virt is restricted to an Enforcing virtualized build host and
# rewrites the disposable flattened kickstart to loopback.

set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

show_help() {
    cat <<'HELP_EOF'
NoID Privacy Workstation ISO build wrapper

Options:
  --with-assets    Deprecated compatibility alias. Canonical builds always
                   stage and verify the repository payload.
  --no-virt        Run Anaconda dirinstall inside a virtualized build host.
                   This development path requires SELinux Enforcing and is
                   not a release-qualified replacement for the KVM compose.
  -h, --help       Show this help without inspecting or changing the checkout.

Output:
  Each successful build is published once under a new directory:
  build-output/candidates/unsigned-candidate-<build-id>-<random>/
    noid-privacy-workstation-44-<version>-x86_64.iso
    SHA256SUMS
    private-build-evidence/
  Existing candidates and archived evidence are never removed or overwritten.
  This wrapper never signs a candidate. After VM sign-off, sign SHA256SUMS in
  that exact published directory without rebuilding or moving the ISO.
HELP_EOF
}

# Parse the complete CLI before repository, keyring, Git, sudo or filesystem
# checks. In particular, --help must stay usable in a dirty checkout and with
# deliberately invalid build environment variables.
WITH_ASSETS_ALIAS=0
NO_VIRT=0
for argument in "$@"; do
    case "$argument" in
        -h|--help) show_help; exit 0 ;;
    esac
done
while [ "$#" -gt 0 ]; do
    case "$1" in
        --with-assets) WITH_ASSETS_ALIAS=1 ;;
        --no-virt) NO_VIRT=1 ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
# The canonical invocation runs as the release user after `sudo -v`; privileged
# steps call sudo individually. Preserve compatibility with a full sudo
# invocation by resolving its invoking user's home instead of sudo's /root.
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    # `|| true`: under `set -euo pipefail` a getent failure (SUDO_USER absent
    # from passwd) would abort here before the $HOME fallback below could fire.
    REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6 2>/dev/null || true)"
    [ -z "$REAL_HOME" ] && REAL_HOME="$HOME"
else
    REAL_HOME="$HOME"
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CANDIDATE_TRANSACTION_LIB="${REPO_ROOT}/scripts/lib/candidate-transaction.sh"
BUILD_HOST_LOCK_LIB="${REPO_ROOT}/scripts/lib/build-host-lock.sh"
PARTITION_COLLAPSE_AWK="${REPO_ROOT}/scripts/collapse-live-partition-layout.awk"
[ -f "$CANDIDATE_TRANSACTION_LIB" ] && [ ! -L "$CANDIDATE_TRANSACTION_LIB" ] \
    || { echo "ERROR: candidate transaction library is missing or symlinked" >&2; exit 2; }
[ -f "$BUILD_HOST_LOCK_LIB" ] && [ ! -L "$BUILD_HOST_LOCK_LIB" ] \
    || { echo "ERROR: build host lock library is missing or symlinked" >&2; exit 2; }
[ -f "$PARTITION_COLLAPSE_AWK" ] && [ ! -L "$PARTITION_COLLAPSE_AWK" ] \
    || { echo "ERROR: partition-collapse program is missing or symlinked" >&2; exit 2; }
# shellcheck source=scripts/lib/candidate-transaction.sh
. "$CANDIDATE_TRANSACTION_LIB"
# shellcheck source=scripts/lib/build-host-lock.sh
. "$BUILD_HOST_LOCK_LIB"
KS_MASTER="${REPO_ROOT}/kickstart/master.ks"
BUILD_OUTPUT_ROOT="${REPO_ROOT}/build-output"
RESULT_DIR=""
# shellcheck disable=SC2034 # consumed by the sourced candidate library.
CANDIDATE_PARENT=""
CANDIDATE_DIR=""
CANDIDATE_NAME=""
TRANSACTION_ROOT=""
PROJECT_NAME="NoID Privacy Workstation"
# ECMA-119 Primary Volume Descriptor: at most 32 d-characters [A-Z0-9_].
# Keep this fixed and standards-compliant so xorriso does not silently retain a
# relaxed, warning-producing label in an otherwise successful candidate.
VOLID="NOID_PRIVACY_F44"
BUG_URL="https://github.com/NexusOne23/noid-privacy-workstation/issues"
RELEASEVER=44
: "${NOID_REQUIRE_SIGNATURE:=0}"
if [ "$NOID_REQUIRE_SIGNATURE" != 0 ]; then
    echo "ERROR: build-iso.sh only produces unsigned candidates" >&2
    echo "ERROR: sign the exact published SHA256SUMS after VM sign-off; do not rebuild" >&2
    exit 2
fi
# ISO filename carries the release version (single source of truth = M32
# NOID_VERSION baked into /etc/noid-build-info) so the build output IS the
# publishable artifact — no manual rename-on-publish (which once risked
# mislabeling an rc build as final). Only the output FILENAME is versioned;
# VOLID (the in-ISO volume label, 32-char-limited) stays generic, so the ISO
# content + its SHA256 are unaffected by the name.
NOID_VERSION="$(sed -nE 's/^NOID_VERSION="([^"]+)".*/\1/p' "${REPO_ROOT}/kickstart/snippets/32-branding.ks" | head -1)"
[ -n "$NOID_VERSION" ] || { echo "ERROR: could not read NOID_VERSION from 32-branding.ks" >&2; exit 1; }
PRODUCT_RELEASE="$NOID_VERSION"
ISO_NAME="noid-privacy-workstation-${RELEASEVER}-${NOID_VERSION}-x86_64.iso"
BUILD_MODE="canonical-assets"

# Reproducibility: fix build timestamp if not set
: "${SOURCE_DATE_EPOCH:=$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || {
    echo "ERROR: SOURCE_DATE_EPOCH must be an unsigned integer" >&2
    exit 1
}
export SOURCE_DATE_EPOCH

# Canonical artifacts are always attributable to one committed source tree.
# Refuse dirty/untracked inputs: a commit SHA that does not describe the bytes
# being built is false provenance and cannot be reproduced by another builder.
NOID_SOURCE_COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify HEAD 2>/dev/null || true)"
[[ "$NOID_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
    echo "ERROR: canonical build requires a Git checkout with a full source commit" >&2
    exit 1
}
if [ -n "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all 2>/dev/null)" ]; then
    echo "ERROR: canonical build requires a clean source tree; commit or remove all changes first" >&2
    exit 1
fi
# Same commit + canonical epoch intentionally yields the same readable ID.
NOID_BUILD_ID="${NOID_SOURCE_COMMIT:0:12}-${SOURCE_DATE_EPOCH}"
NOID_BASE_ISO_SHA256=""

# Build-variance reduction environment. These values are useful inputs, not a
# claim that the complete Lorax/Anaconda pipeline is reproducible.
# Alongside SOURCE_DATE_EPOCH, set TZ=UTC (timezone),
# PYTHONHASHSEED=0 (Python hash randomization disabled), PERL_HASH_SEED=0
# (Perl hash seed deterministic). Defense-in-depth — most build steps are
# SDE-aware, but Python/Perl tools in the build pipeline can leak hash-
# dependent output without these.
export TZ=UTC PYTHONHASHSEED=0 PERL_HASH_SEED=0

# All host-side build intermediates live below one private directory on a
# disk-backed filesystem. The default intentionally avoids hardened /tmp,
# which is commonly a small tmpfs. A builder may override the parent, but the
# preflight below rejects memory-backed filesystems rather than risking a late,
# misleading squashfs/install.img failure.
: "${NOID_ISO_TMPDIR:=/var/tmp}"
ISO_BUILD_TMP_ROOT=""
BUILD_STAGE_DIR=""
HTTP_ROOT=""
BRANDING_STAGE_DIR=""
UPDATES_IMG=""
CODIUM_STAGE_LOG=""
HTTP_LOG=""
LMC_LOG=""
LMC_PROGRAM_LOG=""
LMC_VIRT_LOG=""
COMPOSE_LOG_REPORT=""
LMC_SUCCESS_REPORT=""
LORAX_OVERRIDE_DIR=""
LORAX_OVERRIDE_EVIDENCE=""
LORAX_TEMPLATE_DIR=""
LORAX_TEMPLATE_EVIDENCE=""
LIVE_BOOT_CONFIG_EVIDENCE=""
ROOTFS_HYGIENE_REPORT=""
COMPOSE_LOG_POLICY="${REPO_ROOT}/manifests/compose-log-policy-v1.json"
BASE_ISO_VERIFIER="${REPO_ROOT}/scripts/verify-fedora-base-iso.sh"
KARG_CONTRACT="${REPO_ROOT}/tests/01-karg-contract.py"
KARG_MANIFEST="${REPO_ROOT}/manifests/kernel-cmdline.tsv"
KARG_SOURCE="${REPO_ROOT}/kickstart/snippets/01-bootloader.ks"

# Minimal inst.updates overlay: native Anaconda profile configuration plus a
# build-installer-only BRLTTY mask. RPM transaction handling is never replaced.
# See scripts/anaconda-patch/README.md for the retired-bypass rationale.
HTTP_PORT=8000
HTTP_PID=""

copy_failed_build_evidence() {
    local source=$1 destination=$2 owner
    [ -n "$source" ] || return 0
    [ -f "$source" ] && [ ! -L "$source" ] || return 0
    if [ -r "$source" ]; then
        install -m 0600 -- "$source" "$destination"
        return
    fi
    owner="$(id -u):$(id -g)"
    sudo -n install -m 0600 -- "$source" "$destination" \
        && sudo -n chown -- "$owner" "$destination"
}

retain_failed_iso_build_evidence() {
    local exit_status=$1 failure_parent failure_dir copy_complete=1 evidence_file
    [ -n "${BUILD_STAGE_DIR:-}" ] && [ -d "$BUILD_STAGE_DIR" ] \
        && [ ! -L "$BUILD_STAGE_DIR" ] || return 0
    failure_parent="${BUILD_OUTPUT_ROOT}/failures"
    if [ -L "$BUILD_OUTPUT_ROOT" ] || [ -L "$failure_parent" ] \
            || { [ -e "$failure_parent" ] && [ ! -d "$failure_parent" ]; }; then
        echo "[build-iso] ERROR: unsafe failed-build evidence parent" >&2
        return 1
    fi
    mkdir -p -- "$failure_parent" || return 1
    chmod 0700 "$failure_parent" || return 1
    failure_dir=$(mktemp -d \
        "${failure_parent}/failed-build-${NOID_BUILD_ID}.XXXXXX") || return 1
    chmod 0700 "$failure_dir" || return 1

    copy_failed_build_evidence "$CODIUM_STAGE_LOG" \
        "$failure_dir/codium-stage.log" || copy_complete=0
    copy_failed_build_evidence "$HTTP_LOG" \
        "$failure_dir/build-http.log" || copy_complete=0
    copy_failed_build_evidence "$LMC_LOG" \
        "$failure_dir/livemedia.log" || copy_complete=0
    copy_failed_build_evidence "$LMC_PROGRAM_LOG" \
        "$failure_dir/program.log" || copy_complete=0
    copy_failed_build_evidence "$LMC_VIRT_LOG" \
        "$failure_dir/virt-install.log" || copy_complete=0
    copy_failed_build_evidence "$COMPOSE_LOG_REPORT" \
        "$failure_dir/compose-log-audit.json" || copy_complete=0
    copy_failed_build_evidence "$LMC_SUCCESS_REPORT" \
        "$failure_dir/livemedia-success-audit.json" || copy_complete=0
    copy_failed_build_evidence "$ROOTFS_HYGIENE_REPORT" \
        "$failure_dir/rootfs-hygiene-audit.json" || copy_complete=0
    copy_failed_build_evidence "$LORAX_OVERRIDE_EVIDENCE" \
        "$failure_dir/lorax-overrides.txt" || copy_complete=0
    copy_failed_build_evidence "$LORAX_TEMPLATE_EVIDENCE" \
        "$failure_dir/lorax-templates.txt" || copy_complete=0
    {
        printf '%s\n' \
            'NOID_ISO_FAILURE_EVIDENCE_V1' \
            "exit_status=$exit_status" \
            "build_id=$NOID_BUILD_ID" \
            "source_commit=$NOID_SOURCE_COMMIT" \
            "evidence_copy_complete=$copy_complete"
    } > "$failure_dir/FAILURE-METADATA"
    chmod 0600 "$failure_dir/FAILURE-METADATA" || return 1
    (
        cd "$failure_dir"
        evidence_files=()
        for evidence_file in *; do
            [ "$evidence_file" = SHA256SUMS ] \
                || evidence_files+=("$evidence_file")
        done
        sha256sum -- "${evidence_files[@]}" > SHA256SUMS
        chmod 0600 SHA256SUMS
        for evidence_file in "${evidence_files[@]}" SHA256SUMS; do
            sync -- "$evidence_file"
        done
    ) || return 1
    sync -- "$failure_dir" || return 1
    sync -- "$failure_parent" || return 1
    echo "[build-iso] Failure evidence retained at: $failure_dir"
}

cleanup() {
    local exit_status=$?
    trap - EXIT
    if [ -n "${HTTP_PID:-}" ]; then
        kill "$HTTP_PID" 2>/dev/null || true
        HTTP_PID=""
    fi
    if [ "$exit_status" -ne 0 ]; then
        retain_failed_iso_build_evidence "$exit_status" \
            || echo "[build-iso] ERROR: failed to retain private build evidence" >&2
    fi
    if [ -n "${BUILD_STAGE_DIR:-}" ] && [ -d "$BUILD_STAGE_DIR" ]; then
        # Codium staging deliberately contains root-owned files. Try
        # the unprivileged removal first, then the already-authorized sudo
        # path. Never broaden this cleanup beyond the mktemp-created tree.
        rm -rf -- "$BUILD_STAGE_DIR" 2>/dev/null \
            || sudo -n rm -rf -- "$BUILD_STAGE_DIR" 2>/dev/null \
            || true
    fi
    if [ -n "${TRANSACTION_ROOT:-}" ] && [ -d "$TRANSACTION_ROOT" ]; then
        # The unpublished Lorax result can be root-owned after a failed run.
        # The path is an mktemp-created direct child of CANDIDATE_PARENT.
        rm -rf -- "$TRANSACTION_ROOT" 2>/dev/null \
            || sudo -n rm -rf -- "$TRANSACTION_ROOT" 2>/dev/null \
            || true
    fi
    exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
log() { echo "[build-iso] $*"; }

log "=== NoID Privacy Workstation ISO build ==="
log "Mode:       ${BUILD_MODE}"
log "Kickstart:  ${KS_MASTER}"
log "Output root: ${BUILD_OUTPUT_ROOT}"
log "Project:    ${PROJECT_NAME}"
log "Volid:      ${VOLID}"
log "Release:    ${RELEASEVER} / ${PRODUCT_RELEASE}"
log "Bug URL:    ${BUG_URL}"
log "SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH}"
if [ "$WITH_ASSETS_ALIAS" = "1" ]; then
    log "NOTICE: --with-assets is deprecated; canonical builds always include branding assets"
fi

# Reject ambiguous compose identity before sudo, staging or the expensive
# build. xorriso accepts relaxed labels but emits a warning because the
# ECMA-119 volume-id field is restricted to 32 d-characters. Lorax otherwise
# also injects its generic bug-report placeholder into product metadata.
[[ "$VOLID" =~ ^[A-Z0-9_]{1,32}$ ]] || {
    log "ERROR: VOLID must contain 1-32 ECMA-119 d-characters [A-Z0-9_]"
    exit 15
}
[ "$PROJECT_NAME" = "NoID Privacy Workstation" ] || {
    log "ERROR: unexpected compose project identity: $PROJECT_NAME"
    exit 15
}
[[ "$PRODUCT_RELEASE" =~ ^v[0-9]+\.[0-9]+([.][0-9]+)?$ ]] || {
    log "ERROR: invalid NoID Privacy product release metadata: $PRODUCT_RELEASE"
    exit 15
}
[ "$BUG_URL" = "https://github.com/NexusOne23/noid-privacy-workstation/issues" ] || {
    log "ERROR: unexpected NoID Privacy bug-report boundary: $BUG_URL"
    exit 15
}

# Keep the wrapper in the invoking user's context. livemedia-creator itself is
# elevated below; a root invocation would redirect user-relative build inputs
# and caches into root's account.
if [ "${EUID}" -eq 0 ]; then
    log "ERROR: do not run this wrapper as root"
    log "  Run 'sudo -v' once, then invoke ./scripts/build-iso.sh as your normal user"
    exit 13
fi

# Lorax has supported no-virt with SELinux Enforcing since version 30.7. Do
# not turn that support into permission to weaken the real build host: direct
# Anaconda dirinstall is development-only and upstream warns that a bug can
# operate on real devices. Require both Enforcing and a full virtual machine,
# before sudo, staging or network work. Containers are not sufficient because
# no-virt needs real loop devices, mounts and correct SELinux labeling.
if [ "$NO_VIRT" = "1" ]; then
    selinux_mode=$(getenforce 2>/dev/null || true)
    if [ "$selinux_mode" != "Enforcing" ]; then
        log "ERROR: --no-virt requires SELinux=Enforcing (observed: ${selinux_mode:-unavailable})"
        log "Do not weaken SELinux; use an Enforcing disposable build VM or the default KVM build."
        exit 8
    fi
    no_virt_vm_type=$(systemd-detect-virt --vm 2>/dev/null || true)
    if [ -z "$no_virt_vm_type" ] || [ "$no_virt_vm_type" = "none" ]; then
        log "ERROR: --no-virt is restricted to a virtualized build host"
        log "Use an Enforcing disposable build VM or the default KVM build."
        exit 8
    fi
    if [ ! -d /sys/firmware/efi ]; then
        log "ERROR: --no-virt build VM must itself be booted with UEFI firmware"
        log "The NoID Privacy Kickstart intentionally rejects a BIOS-booted installer environment."
        exit 8
    fi
    log "No-virt host guard: SELinux=Enforcing, virtualization=${no_virt_vm_type}, firmware=UEFI"
fi

# Serialize every checkout owned by this release user before sudo, network,
# staging or candidate work. The canonical builder uses fixed host services
# (including its loopback payload port), so two otherwise independent Git
# worktrees are not independent build environments.
BUILD_RUNTIME_DIR="/run/user/$(id -u)"
BUILD_LOCK_FILE="$BUILD_RUNTIME_DIR/noid-privacy-iso-build.lock"
if noid_build_lock_acquire "$BUILD_LOCK_FILE"; then
    log "Host build lock: acquired ($BUILD_LOCK_FILE)"
else
    lock_status=$?
    log "ERROR: cannot acquire the canonical ISO build lock"
    log "  Lock: $BUILD_LOCK_FILE"
    exit "$lock_status"
fi

# Verify sudo upfront.
# livemedia-creator runs as `sudo livemedia-creator ...` after 5+ minutes of
# setup (ksflatten + sed edits + branding stage + http server start). If the
# sudo credential cache expired during setup, Anaconda would block on a
# password prompt mid-build — worst-case in unattended/CI runs.
#
# Switched from `sudo -v` to `sudo -n true`. Reason:
# `sudo -v` validates the user's PAM stack which requires interactive
# auth even with password-bypass sudoers configs. `sudo -n true` (non-
# interactive, trivial command) succeeds when the bypass applies to the
# actual ops we'll run via sudo (livemedia-creator). For password-required
# configs, this also fails fast just like the original — but no false
# negatives on bypass setups.
log "sudo upfront check (livemedia-creator needs root)"
sudo -n true || { log "ERROR: sudo authentication required (run 'sudo -v' once interactively, then rerun this script)"; exit 13; }

# Canonicalize and validate the parent before creating anything beneath it.
# `stat -f` follows symlinks, so /var/tmp -> /tmp is correctly detected as
# tmpfs and rejected. The 12-GiB floor matches the documented minimum needed
# for the flattened KS, payloads, Anaconda extraction and Lorax intermediates.
[[ "$NOID_ISO_TMPDIR" = /* ]] || {
    log "ERROR: NOID_ISO_TMPDIR must be an absolute path"
    exit 5
}
ISO_BUILD_TMP_ROOT="$(readlink -f -- "$NOID_ISO_TMPDIR" 2>/dev/null || true)"
if [ -z "$ISO_BUILD_TMP_ROOT" ] || [ ! -d "$ISO_BUILD_TMP_ROOT" ] \
        || [ ! -w "$ISO_BUILD_TMP_ROOT" ]; then
    log "ERROR: ISO staging parent must be an existing writable directory: $NOID_ISO_TMPDIR"
    exit 5
fi
ISO_BUILD_TMP_FSTYPE="$(stat -f -c %T -- "$ISO_BUILD_TMP_ROOT" 2>/dev/null || true)"
case "$ISO_BUILD_TMP_FSTYPE" in
    tmpfs|ramfs)
        log "ERROR: ISO staging parent is memory-backed ($ISO_BUILD_TMP_FSTYPE): $ISO_BUILD_TMP_ROOT"
        log "  Select a disk-backed path with NOID_ISO_TMPDIR"
        exit 5
        ;;
    "")
        log "ERROR: could not determine filesystem type for ISO staging parent: $ISO_BUILD_TMP_ROOT"
        exit 5
        ;;
esac
ISO_BUILD_TMP_FREE_KIB="$(df -Pk -- "$ISO_BUILD_TMP_ROOT" | awk 'NR==2 {print $4}')"
ISO_BUILD_TMP_MIN_KIB=$((12 * 1024 * 1024))
if ! [[ "$ISO_BUILD_TMP_FREE_KIB" =~ ^[0-9]+$ ]] \
        || [ "$ISO_BUILD_TMP_FREE_KIB" -lt "$ISO_BUILD_TMP_MIN_KIB" ]; then
    log "ERROR: ISO staging parent needs at least 12 GiB free: $ISO_BUILD_TMP_ROOT"
    log "  Available: ${ISO_BUILD_TMP_FREE_KIB:-unknown} KiB"
    exit 5
fi
BUILD_STAGE_DIR="$(mktemp -d -p "$ISO_BUILD_TMP_ROOT" noid-iso-stage.XXXXXX)"
chmod 0700 "$BUILD_STAGE_DIR"
# Keep the build VM's loopback-visible document root separate from private
# host-side state. Only the intended payload tree and updates image live here;
# the flattened Kickstart, Lorax override and compose logs remain unreachable
# through the transient HTTP server.
HTTP_ROOT="$BUILD_STAGE_DIR/http-root"
BRANDING_STAGE_DIR="$HTTP_ROOT/branding"
UPDATES_IMG="$HTTP_ROOT/noid-anaconda-updates.img"
FLAT_KS="$BUILD_STAGE_DIR/noid-privacy-flattened.ks"
CODIUM_STAGE_LOG="$BUILD_STAGE_DIR/codium-stage.log"
HTTP_LOG="$BUILD_STAGE_DIR/build-http.log"
LMC_LOG="$BUILD_STAGE_DIR/livemedia.log"
LMC_PROGRAM_LOG="$BUILD_STAGE_DIR/program.log"
LMC_VIRT_LOG="$BUILD_STAGE_DIR/virt-install.log"
COMPOSE_LOG_REPORT="$BUILD_STAGE_DIR/compose-log-audit.json"
LMC_SUCCESS_REPORT="$BUILD_STAGE_DIR/livemedia-success-audit.json"
LIVE_BOOT_CONFIG_EVIDENCE="$BUILD_STAGE_DIR/live-boot-config-audit.txt"
ROOTFS_HYGIENE_REPORT="$BUILD_STAGE_DIR/rootfs-hygiene-audit.json"
LORAX_OVERRIDE_DIR="$BUILD_STAGE_DIR/lorax-python-override"
LORAX_OVERRIDE_EVIDENCE="$LORAX_OVERRIDE_DIR/NOID-LORAX-OVERRIDE-EVIDENCE"
LORAX_TEMPLATE_DIR="$BUILD_STAGE_DIR/lorax-template-override"
LORAX_TEMPLATE_EVIDENCE="$LORAX_TEMPLATE_DIR/NOID-LORAX-TEMPLATE-EVIDENCE"
log "ISO staging: $BUILD_STAGE_DIR ($ISO_BUILD_TMP_FSTYPE, disk-backed)"

# Required tools
for tool in flock isoinfo ksflatten livemedia-creator losetup mount mountpoint \
        patch python3 unsquashfs umount xorriso; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        log "ERROR: required tool missing: $tool"
        log "  Install: sudo dnf install lorax-lmc-virt lorax-lmc-novirt anaconda pykickstart genisoimage patch squashfs-tools util-linux-core xorriso"
        exit 3
    fi
done
[ -x "${REPO_ROOT}/scripts/audit-compose-log.py" ] \
    || { log "ERROR: compose-log classifier is missing or not executable"; exit 3; }
[ -x "${REPO_ROOT}/scripts/verify-livemedia-success.py" ] \
    || { log "ERROR: livemedia success auditor is missing or not executable"; exit 3; }
[ -x "${REPO_ROOT}/scripts/verify-live-image-hygiene.sh" ] \
    && [ ! -L "${REPO_ROOT}/scripts/verify-live-image-hygiene.sh" ] \
    && [ -x "${REPO_ROOT}/scripts/verify-rootfs-hygiene.py" ] \
    && [ ! -L "${REPO_ROOT}/scripts/verify-rootfs-hygiene.py" ] || {
    log "ERROR: final Live image-hygiene verifier is missing or unsafe"
    exit 3
}
[ -x "$KARG_CONTRACT" ] && [ ! -L "$KARG_CONTRACT" ] \
    || { log "ERROR: kernel-command-line verifier is missing, symlinked or non-executable"; exit 3; }
[ -f "$KARG_MANIFEST" ] && [ ! -L "$KARG_MANIFEST" ] \
    && [ -f "$KARG_SOURCE" ] && [ ! -L "$KARG_SOURCE" ] \
    || { log "ERROR: kernel-command-line source contract is missing or unsafe"; exit 3; }
[ -f "$COMPOSE_LOG_POLICY" ] && [ ! -L "$COMPOSE_LOG_POLICY" ] \
    || { log "ERROR: canonical compose-log policy is missing or symlinked"; exit 3; }
[ -x "$BASE_ISO_VERIFIER" ] && [ ! -L "$BASE_ISO_VERIFIER" ] \
    || { log "ERROR: Fedora base-ISO verifier is missing, symlinked or non-executable"; exit 3; }
BASE_ISO_NAME="$("$BASE_ISO_VERIFIER" --print-expected-name)" || {
    log "ERROR: cannot read the canonical Fedora base-ISO name"
    exit 3
}
[[ "$BASE_ISO_NAME" =~ ^Fedora-Server-netinst-x86_64-[A-Za-z0-9._-]+\.iso$ ]] || {
    log "ERROR: unsafe canonical Fedora base-ISO name: $BASE_ISO_NAME"
    exit 3
}
[ -x "${REPO_ROOT}/scripts/stage-lorax-overrides.sh" ] \
    && [ -x "${REPO_ROOT}/scripts/stage-lorax-templates.sh" ] \
    && [ -x "${REPO_ROOT}/scripts/verify-lorax-monitor-drain.py" ] \
    && [ -x "${REPO_ROOT}/scripts/verify-lorax-live-required-space.py" ] \
    && [ -x "${REPO_ROOT}/scripts/verify-lorax-cancel-cleanup.py" ] || {
    log "ERROR: Lorax override staging or a semantic verifier is missing"
    exit 3
}

# Fedora Lorax 44.6 stops its virtio-log handler as soon as shutdown sets the
# kill flag, before queued bytes and a final partial record are consumed. It
# also owns the final mounted root immediately before SquashFS creation, which
# is the native one-time point for NoID Privacy's Live required-space
# manifest. Its callback runner also returns without terminating or reaping
# QEMU when the log monitor cancels a failed installation. Keep the vendor
# installation immutable: stage the exact package tree privately, apply all
# hash/NEVRA-gated patches with zero fuzz, and verify their semantics.
mkdir -m 0700 "$LORAX_OVERRIDE_DIR"
"${REPO_ROOT}/scripts/stage-lorax-overrides.sh" "$LORAX_OVERRIDE_DIR"

# Fedora's generic Live templates deliberately default to the media-check
# entry with a 60-second countdown. Keep that integrity path available, while
# making the normal graphical Live entry the three-second default. Stage the
# complete exact RPM-owned template tree privately, with closed NEVRA/source
# hashes and a zero-fuzz patch; never mutate the build host's vendor payload.
mkdir -m 0700 "$LORAX_TEMPLATE_DIR"
"${REPO_ROOT}/scripts/stage-lorax-templates.sh" "$LORAX_TEMPLATE_DIR"
chmod 0700 "$LORAX_TEMPLATE_DIR"

# Kickstart exists
if [ ! -f "$KS_MASTER" ]; then
    log "ERROR: kickstart master missing: $KS_MASTER"
    exit 4
fi

# The branded image is the supported product, so silently falling back to a
# text-only derivative would produce a mislabeled artifact.
if [ ! -d "${REPO_ROOT}/branding" ]; then
    log "ERROR: mandatory branding/ directory missing"
    exit 6
fi
log "  branding/ payload: present ($(du -sh "${REPO_ROOT}/branding" | awk '{print $1}'))"

# Lorax requires its result directory not to exist. Give each run a private
# transaction inside the final output filesystem and publish only the complete
# directory. Existing outputs, signatures and audit evidence are never cleanup
# targets.
candidate_class=unsigned-candidate
noid_candidate_begin "$BUILD_OUTPUT_ROOT" "$NOID_BUILD_ID" "$candidate_class" \
    || { log "ERROR: cannot create candidate transaction"; exit 5; }
log "Candidate transaction: $CANDIDATE_NAME"
log "Pending result:       $RESULT_DIR"
log "Final publication:    $CANDIDATE_DIR"

# ---------------------------------------------------------------------------
# Flatten kickstart (handles %include chain) — written to the private staging
# tree so RESULT_DIR remains absent until Lorax creates it.
# ---------------------------------------------------------------------------
log "Flattening kickstart → ${FLAT_KS}"
ksflatten --config "$KS_MASTER" --output "$FLAT_KS" --version F44

# Make installed build-info use the same explicit epoch instead of wall-clock
# time inside Anaconda. This removes one known source of same-input variance.
sed -i "s/@@NOID_BUILD_EPOCH@@/${SOURCE_DATE_EPOCH}/g" "$FLAT_KS"
sed -i "s/@@NOID_SOURCE_COMMIT@@/${NOID_SOURCE_COMMIT}/g" "$FLAT_KS"
sed -i "s/@@NOID_BUILD_ID@@/${NOID_BUILD_ID}/g" "$FLAT_KS"
if grep -qE '@@NOID_(BUILD_EPOCH|SOURCE_COMMIT|BUILD_ID)@@' "$FLAT_KS"; then
    log "ERROR: failed to inject canonical source/build provenance"
    exit 1
fi

# lorax KVM builds require `shutdown`; the shipped installer kickstart correctly
# uses `reboot`. Change only the first top-level directive in the disposable
# flattened build copy, never identical text inside a %post documentation block.
log "Swapping top-level 'reboot' → 'shutdown' in build flat-ks (section-aware; lorax KVM-mode)"
awk '
/^%(pre|post|packages|addon|onerror|traceback)/ { sec=1; print; next }
/^%end/                                          { sec=0; print; next }
(!done && sec==0 && $0=="reboot")                { print "shutdown"; done=1; next }
{ print }
' "$FLAT_KS" > "${FLAT_KS}.tmp" && mv "${FLAT_KS}.tmp" "$FLAT_KS"

# Master.ks ships a 3-partition layout (ESP+/boot+/) for end-user install via
# Anaconda UI. But for build-time KVM live-ISO mode, lorax phase 2 (squashfs+ISO
# assembly) only mounts the rootfs partition — if /boot is separate, kernels are
# invisible → "No kernels found, cannot rebuild_initrds" failure. Plus, anaconda
# in --virt-uefi mode without ESP would hang 30+ min trying to install GRUB to
# nowhere. Solution: collapse to single-partition + bootloader --location=none
# only in BUILD copy. End-user install uses master.ks's full 3-partition layout
# via Anaconda UI which is unaffected by this build-only transformation.
log "Build-only edit: remove --location=mbr (live ISO uses --location=none)"
sed -i 's| --location=mbr||' "$FLAT_KS"
log "Build-only edit: set --location=none on the first bootloader directive"
# The first match is the top-level build directive. Later matches are shipped
# installer heredoc content and must retain the end-user bootloader policy.
sed -i '0,/^bootloader /s|^bootloader |bootloader --location=none |' "$FLAT_KS"
log "Build-only edit: collapse the lorax phase-2 layout to one root partition"
# ksflatten normalizes part directives to: part /path --fstype="ext4" --size=N
# (fstype first, double-quoted, size after). Match must respect that exact format.
# The dedicated program validates the complete marker topology before emitting
# output, preventing a partial or over-broad range replacement.
awk -v no_virt="$NO_VIRT" -f "$PARTITION_COLLAPSE_AWK" "$FLAT_KS" > "${FLAT_KS}.tmp" \
    || { log "ERROR: partition-collapse anchors are missing, duplicated, reordered or drifted — refusing partial edit"; rm -f "${FLAT_KS}.tmp"; exit 12; }
mv "${FLAT_KS}.tmp" "$FLAT_KS"

# Post-edit verification.
# `sed -i` exits 0 even if a pattern did not match (silent no-op), while the
# partition program has its own closed marker contract. Verify the published
# output of every build-only edit before livemedia-creator can consume it:
log "verify: build-only edit integrity checks"
grep -q '^shutdown$' "$FLAT_KS" \
    || { log "ERROR: reboot→shutdown sed-edit failed (no 'shutdown' line found)"; exit 12; }
# Presence alone does not prove the top-level command was changed. Also assert
# that no top-level (outside-%section) `reboot` remains.
awk '/^%(pre|post|packages|addon|onerror|traceback)/{s=1} /^%end/{s=0} (s==0 && $0=="reboot"){f=1} END{exit f}' "$FLAT_KS" \
    || { log "ERROR: a top-level 'reboot' command survived the swap (mis-anchored)"; exit 12; }
grep -q '^bootloader --location=none' "$FLAT_KS" \
    || { log "ERROR: bootloader --location=none sed-edit failed"; exit 12; }
if grep -q -- '--location=mbr' "$FLAT_KS"; then
    log "ERROR: --location=mbr survived the build-only edit"
    exit 12
fi
if [ "$NO_VIRT" = "1" ]; then
    [ "$(grep -c '^zerombr$' "$FLAT_KS")" -eq 0 ] \
        || { log "ERROR: no-virt partition collapse retained zerombr"; exit 12; }
    [ "$(grep -c '^clearpart --all --initlabel$' "$FLAT_KS")" -eq 1 ] \
        || { log "ERROR: no-virt partition collapse did not publish generic clearpart"; exit 12; }
    [ "$(grep -c '^part / --fstype="ext4" --size=12000$' "$FLAT_KS")" -eq 1 ] \
        || { log "ERROR: no-virt partition collapse did not publish generic root"; exit 12; }
    if awk '
        /^%(pre|post|packages|addon|onerror|traceback)/ { sec=1; next }
        /^%end/ { sec=0; next }
        !sec && /^(clearpart|part )/ && /--(drives|ondisk)=/ { found=1 }
        END { exit !found }
    ' "$FLAT_KS"; then
        log "ERROR: no-virt kickstart retained a physical-disk binding"
        exit 12
    fi
else
    [ "$(grep -c '^zerombr$' "$FLAT_KS")" -eq 1 ] \
        || { log "ERROR: partition collapse did not retain exactly one zerombr"; exit 12; }
    [ "$(grep -c '^clearpart --all --initlabel --drives=sda$' "$FLAT_KS")" -eq 1 ] \
        || { log "ERROR: partition collapse did not publish exactly one clearpart"; exit 12; }
    [ "$(grep -c '^part / --fstype="ext4" --size=12000 --ondisk=sda$' "$FLAT_KS")" -eq 1 ] \
        || { log "ERROR: partition collapse did not publish exactly one root partition"; exit 12; }
    if grep -q '^part / --fstype="ext4" --size=12000$' "$FLAT_KS"; then
        log "ERROR: original partition-collapse end anchor survived publication"
        exit 12
    fi
fi
log "  [OK] all 4 build-only edits applied + verified"

# ---------------------------------------------------------------------------
# Live-Boot kernel-args hardening
# ---------------------------------------------------------------------------
# The Live-Boot does NOT receive the `bootloader --append=`
# directive from Module 01 STEP 1 — that only applies to the Anaconda install
# into the installed system's GRUB. Lorax builds the Live-ISO with its own
# bootloader templates that carry only ~5 default args (rd.live.image, root=,
# quiet).
#
# Pass the project-owned KSPP hardening token list as --extra-boot-args to lmc; lmc
# adds them to the Live-ISO bootloader-config templates (isolinux.cfg +
# grub.cfg of the FINAL ISO) → the Live-Boot gets the same KSPP hardening as
# the installed system.
#
# --kernel-args applies to the Anaconda build VM. --extra-boot-args targets
# the bootloader templates of the final Live ISO.
#
# Security tokens mirror Module 01 STEP 1 bootloader --append= directive,
# plus plymouth.use-simpledrm for Live. Lorax's maintained normal/basic
# templates already append the UX-only `rhgb` token, while its media-check
# entry deliberately omits it. Therefore `rhgb` MUST NOT be repeated in
# --extra-boot-args. Hardware-conditional flags
# (Intel/AMD/notebook) are NOT set here — Module 01 STEP 4 %post applies them
# to the installed system via firstboot grubby; the Live-Boot session only
# sees the unconditional baseline.
#
# Keep this list synchronized with M01's canonical unconditional bootloader
# manifest. Hardware-conditional flags remain installed-system-only.
#
# Two manifest tokens are deliberately absent here: `rhgb` and `quiet`. Lorax's
# maintained Live templates emit them per menu entry (quiet on all three, rhgb
# on every entry except the media check). Repeating either through
# --extra-boot-args would put a duplicate token into the final GRUB config, and
# tests/01-karg-contract.py rejects exactly that. See LORAX_ENTRY_TOKENS there.
KSPP_KERNEL_ARGS="plymouth.use-simpledrm=1 init_on_alloc=1 init_on_free=1 slab_nomerge pti=on vsyscall=none vdso32=0 debugfs=off page_alloc.shuffle=1 randomize_kstack_offset=on spec_store_bypass_disable=on module.sig_enforce=1 iommu.strict=1 iommu.passthrough=0 lockdown=integrity mitigations=auto proc_mem.force_override=never hash_pointers=always hardened_usercopy=1 kfence.sample_interval=100 kfence.deferrable=1 efi=disable_early_pci_dma ia32_emulation=0 bdev_allow_write_mounted=0 rd.emergency=halt rd.shell=0 loglevel=4 systemd.ssh_auto=no random.trust_cpu=off random.trust_bootloader=off audit=1 audit_backlog_limit=8192 zswap.enabled=0 intel_iommu=on kvm.nx_huge_pages=force mmio_stale_data=full retbleed=auto gather_data_sampling=force reg_file_data_sampling=on indirect_target_selection=force vmscape=force efi_pstore.pstore_disable=1 erst_disable spectre_v2=on spectre_bhi=on mds=full tsx_async_abort=full srbds=on spec_rstack_overflow=safe-ret tsa=on"

# ---------------------------------------------------------------------------
# Build invocation
# ---------------------------------------------------------------------------
LMC_ARGS=(
    --make-iso
    --iso-only
    --iso-name "$ISO_NAME"
    --ks "$FLAT_KS"
    --resultdir "$RESULT_DIR"
    --project "$PROJECT_NAME"
    --release "$PRODUCT_RELEASE"
    --bugurl "$BUG_URL"
    --volid "$VOLID"
    --releasever "$RELEASEVER"
    --logfile "$LMC_LOG"
    --macboot
    --lorax-templates "$LORAX_TEMPLATE_DIR"
    --extra-boot-args "$KSPP_KERNEL_ARGS"
    # Preserve the raw image for post-mortem inspection in either compose mode.
    # --tmp keeps Lorax work on the same validated disk-backed parent as every
    # other host-side build intermediate.
    --keep-image
    --tmp "$ISO_BUILD_TMP_ROOT"
)

stage_reduced_dependency_cache() {
    [ -n "${NOID_BUILD_CACHE_DIR:-}" ] || return 0

    local version="1.73.0"
    local expected_sha="bccc51a773150af4af6e1fd62c7bfdeb7238b79ff2381b998fa9f2e38f64786a"
    local expected_size=4679419
    local filename="uBlock0_${version}.firefox.signed.xpi"
    local src="${NOID_BUILD_CACHE_DIR}/ubo/${version}/${filename}"
    local dest_dir="$BRANDING_STAGE_DIR/cache/ubo/${version}"
    local actual_sha actual_size cache_base

    [ -f "$src" ] || {
        log "ERROR: reduced-dependency cache missing required uBO XPI: $src"
        return 1
    }
    actual_sha=$(sha256sum "$src" | awk '{print $1}')
    actual_size=$(stat -c%s "$src")
    if [ "$actual_sha" != "$expected_sha" ] || [ "$actual_size" -ne "$expected_size" ]; then
        log "ERROR: cached uBO XPI failed the source-pinned SHA256/size gate"
        return 1
    fi
    mkdir -p "$dest_dir" || {
        log "ERROR: cannot create reduced-dependency cache destination"
        return 1
    }
    cp "$src" "$dest_dir/$filename" || {
        log "ERROR: cannot stage the verified uBO cache payload"
        return 1
    }

    if [ "$NO_VIRT" = "1" ]; then
        cache_base="http://127.0.0.1:${HTTP_PORT}/branding/cache"
    else
        cache_base="http://10.0.2.2:${HTTP_PORT}/branding/cache"
    fi
    sed -i "s#^NOID_CACHE_BASE_URL=.*#NOID_CACHE_BASE_URL=\"${cache_base}\"#" "$FLAT_KS"
    if ! grep -qF "NOID_CACHE_BASE_URL=\"${cache_base}\"" "$FLAT_KS"; then
        log "ERROR: failed to wire the reduced-dependency cache into flattened kickstart"
        return 1
    fi
    log "  [OK] cached uBO XPI staged behind loopback-only build payload server"
}

start_build_http() {
    log "Build payload server: starting on 127.0.0.1:${HTTP_PORT}..."
    [ -d "$HTTP_ROOT" ] && [ ! -L "$HTTP_ROOT" ] || {
        log "ERROR: private build payload document root is missing or unsafe"
        return 1
    }
    ( cd "$HTTP_ROOT" && exec python3 -m http.server --bind 127.0.0.1 "$HTTP_PORT" \
        >"$HTTP_LOG" 2>&1 ) &
    HTTP_PID=$!
    sleep 2
    if ! kill -0 "$HTTP_PID" 2>/dev/null || \
       ! ss -lnt 2>/dev/null | grep -q "127.0.0.1:${HTTP_PORT}\b"; then
        log "ERROR: HTTP server failed to bind 127.0.0.1:${HTTP_PORT}"
        return 1
    fi
    log "  HTTP server PID: ${HTTP_PID} (loopback-only, logs: $HTTP_LOG)"
}

stage_branding_payload() {
    # The build server's CWD is the private staging tree. Copy only the
    # published payload rather than arbitrary hidden/editor files from source.
    if ! bash "${REPO_ROOT}/scripts/regen-branding-shasums.sh" --check >/dev/null 2>&1; then
        log "ERROR: branding/SHA256SUMS drift detected"
        log "  Run: bash scripts/regen-branding-shasums.sh"
        return 1
    fi

    log "Branding delivery: staging mandatory branding/ payload"
    rm -rf -- "$BRANDING_STAGE_DIR" 2>/dev/null || true
    mkdir -p "$BRANDING_STAGE_DIR/plymouth" "$BRANDING_STAGE_DIR/icons" || {
        log "ERROR: cannot create mandatory branding staging directories"
        return 1
    }
    cp "${REPO_ROOT}/branding/"*.png "$BRANDING_STAGE_DIR/" || {
        log "ERROR: cannot stage mandatory top-level branding PNGs"
        return 1
    }
    cp "${REPO_ROOT}/branding/plymouth/"* "$BRANDING_STAGE_DIR/plymouth/" || {
        log "ERROR: cannot stage mandatory Plymouth branding"
        return 1
    }
    cp "${REPO_ROOT}/branding/icons/"*.png "$BRANDING_STAGE_DIR/icons/" || {
        log "ERROR: cannot stage mandatory application icons"
        return 1
    }
    cp "${REPO_ROOT}/branding/SHA256SUMS" "$BRANDING_STAGE_DIR/SHA256SUMS" || {
        log "ERROR: cannot stage the mandatory branding manifest"
        return 1
    }
    log "  [OK] branding payload staged ($(du -sh "$BRANDING_STAGE_DIR" | awk '{print $1}'); $(grep -cv '^#' "$BRANDING_STAGE_DIR/SHA256SUMS") manifest entries)"
}

stage_noid_audit() {
    # Fetch the exact reviewed public source revision without modification.
    # The full commit appears in the immutable URL; byte count and digest are
    # independent fail-closed gates. NOID_AUDIT_SRC is an offline/CI override
    # and must provide the same reviewed bytes.
    local source_commit="e204bb68a7ac3ce08acc685fb56356d460ba3710"
    local source_url="https://raw.githubusercontent.com/NexusOne23/noid-privacy-linux/${source_commit}/noid-privacy-linux.sh"
    local expected_size="600495"
    local expected_sha="724213827287ed4d203bbd6c6d2706b7f60225bde5134c63a6c525bf6e46f0ac"
    local version="v3.7.2"
    local audit_candidate="$BRANDING_STAGE_DIR/noid-privacy-linux.sh"
    local source_override="${NOID_AUDIT_SRC:-}"
    local actual_sha
    local actual_size

    if [ -n "$source_override" ]; then
        if [ ! -f "$source_override" ] || [ -L "$source_override" ]; then
            log "ERROR: NOID_AUDIT_SRC must be a regular, non-symlink file"
            return 1
        fi
        cp -- "$source_override" "$audit_candidate" || {
            log "ERROR: cannot stage NOID_AUDIT_SRC"
            return 1
        }
        log "Audit payload: validating explicit offline/CI source override"
    else
        log "Audit payload: fetching immutable public $version commit"
        if ! curl --fail --silent --show-error --location \
                --proto '=https' --proto-redir '=https' --tlsv1.2 \
                --connect-timeout 20 --max-time 120 \
                --output "$audit_candidate" "$source_url"; then
            log "ERROR: cannot fetch the pinned public noid-audit payload"
            return 1
        fi
    fi
    if ! bash -n "$audit_candidate"; then
        log "ERROR: exact noid-audit payload has invalid shell syntax"
        return 1
    fi
    actual_size=$(stat -c %s -- "$audit_candidate")
    if [ "$actual_size" != "$expected_size" ]; then
        log "ERROR: exact noid-privacy-linux.sh byte count mismatch"
        log "  expected: $expected_size"
        log "  actual:   $actual_size"
        return 1
    fi
    actual_sha=$(sha256sum -- "$audit_candidate" | awk '{print $1}')
    if [ "$actual_sha" != "$expected_sha" ]; then
        log "ERROR: exact noid-privacy-linux.sh SHA256 mismatch"
        log "  expected: $expected_sha"
        log "  actual:   $actual_sha"
        return 1
    fi
    log "  [OK] exact public noid-audit $version verified ($source_commit; $expected_size bytes)"
}

stage_codium_rpm() {
    # This is an availability optimization, not a trust bypass: Module 08
    # verifies the package signature and retains its signed remote fallback.
    log "codium RPM: pre-staging signed local-mirror candidate"
    if ! sudo -n dnf clean expire-cache >/dev/null 2>&1; then
        log "  [INFO] host DNF expire-cache failed; continuing to signed download attempt"
    fi
    if ! sudo -n dnf makecache --refresh --setopt=fastestmirror=1 >/dev/null 2>&1; then
        log "  [INFO] host DNF makecache refresh failed; Module 08 retains its signed remote fallback"
    fi

    local stage_dir="$BRANDING_STAGE_DIR/codium"
    local rpm_path=""
    local rpm_size
    rm -rf "$stage_dir" 2>/dev/null || true
    mkdir -p "$stage_dir"
    # The log target is inside the private user-owned stage; sudo is needed
    # only by dnf, not by the shell-owned redirection.
    # shellcheck disable=SC2024
    if sudo -n dnf download --arch=x86_64 --destdir="$stage_dir" codium \
            >"$CODIUM_STAGE_LOG" 2>&1; then
        rpm_path=$(find "$stage_dir" -maxdepth 1 -type f -name 'vscodium-*.rpm' -print -quit)
        if [ -n "$rpm_path" ]; then
            sudo -n chmod 0644 "$rpm_path"
            sudo -n chown root:root "$rpm_path"
            rpm_size=$(stat -c%s "$rpm_path")
            log "  [OK] codium RPM staged: $(basename "$rpm_path") ($rpm_size bytes)"
            return 0
        fi
        log "  [WARN] dnf download returned success but produced no vscodium RPM"
    else
        log "  [WARN] host dnf download failed (see $CODIUM_STAGE_LOG)"
    fi
    log "         Module 08 will use its signed remote fallback"
}

# These payloads are common to KVM and --no-virt. Stage them before branching
# so neither build mode can accidentally produce a text-only or audit-less ISO.
stage_branding_payload || exit 11
stage_noid_audit || exit 11
stage_codium_rpm

if [ "$NO_VIRT" = "1" ]; then
    NOID_BASE_ISO_SHA256="not-applicable"
    log "NOTICE: --no-virt development mode is running inside an Enforcing build VM"
    LMC_ARGS+=(--no-virt)
    # No qemu NAT exists in --no-virt mode. Patch only the disposable flattened
    # kickstart so all build-time payload consumers reach loopback directly.
    sed -i "s#BRANDING_HTTP_URL=\"http://10.0.2.2:${HTTP_PORT}/branding\"#BRANDING_HTTP_URL=\"http://127.0.0.1:${HTTP_PORT}/branding\"#" "$FLAT_KS"
    sed -i "s#NOID_AUDIT_URL=\"http://10.0.2.2:${HTTP_PORT}/branding/noid-privacy-linux.sh\"#NOID_AUDIT_URL=\"http://127.0.0.1:${HTTP_PORT}/branding/noid-privacy-linux.sh\"#" "$FLAT_KS"
    sed -i "s#CODIUM_LOCAL_BASE=\"http://10.0.2.2:${HTTP_PORT}/branding/codium\"#CODIUM_LOCAL_BASE=\"http://127.0.0.1:${HTTP_PORT}/branding/codium\"#" "$FLAT_KS"
    grep -qF "BRANDING_HTTP_URL=\"http://127.0.0.1:${HTTP_PORT}/branding\"" "$FLAT_KS" \
        || { log "ERROR: no-virt branding rewrite failed"; exit 12; }
    grep -qF "NOID_AUDIT_URL=\"http://127.0.0.1:${HTTP_PORT}/branding/noid-privacy-linux.sh\"" "$FLAT_KS" \
        || { log "ERROR: no-virt audit-bundle rewrite failed"; exit 12; }
    grep -qF "CODIUM_LOCAL_BASE=\"http://127.0.0.1:${HTTP_PORT}/branding/codium\"" "$FLAT_KS" \
        || { log "ERROR: no-virt codium-mirror rewrite failed"; exit 12; }
    stage_reduced_dependency_cache || exit 11
    start_build_http || exit 10
else
    # KVM-mode (default) requires the exact reviewed Fedora Server netinst ISO
    # to boot the build qemu. Auto-detect it from /var/tmp first, then
    # ${REAL_HOME}/Downloads (= invoking-user's home; see the sudo
    # HOME mapping fix at script top), else fail with a clear message.
    INSTALL_ISO=""
    for candidate in \
        "/var/tmp/${BASE_ISO_NAME}" \
        "${REAL_HOME}/Downloads/${BASE_ISO_NAME}"; do
        if [ -f "$candidate" ]; then
            INSTALL_ISO="$candidate"
            break
        fi
    done
    if [ -z "$INSTALL_ISO" ]; then
        log "ERROR: KVM-mode build needs the reviewed F44 Server netinst ISO:"
        log "  /var/tmp/${BASE_ISO_NAME}"
        log "Or use --no-virt inside an Enforcing disposable build VM."
        exit 8
    fi
    log "  install ISO: ${INSTALL_ISO}"
    if ! "$BASE_ISO_VERIFIER" "$INSTALL_ISO"; then
        log "ERROR: Fedora base-ISO provenance/integrity verification failed"
        exit 8
    fi
    NOID_BASE_ISO_SHA256="$(sha256sum -- "$INSTALL_ISO" | awk '{print $1}')"
    # These options belong exclusively to Lorax's nested build QEMU. Passing
    # --virt-uefi to --no-virt still triggers Lorax's OVMF-path validation and
    # breaks an otherwise valid host dirinstall before Anaconda starts.
    # Environment overrides support hosts where the default 16384 MiB guest
    # would overcommit RAM.
    LMC_ARGS+=(
        --virt-uefi
        --ram "${QEMU_RAM:-16384}"
        --vcpus "${QEMU_VCPUS:-8}"
        --iso "$INSTALL_ISO"
    )

    # -----------------------------------------------------------------------
    # Build the authenticated minimal updates image and serve it over the
    # loopback-only payload channel. It selects the NoID Privacy Anaconda profile and
    # masks BRLTTY only inside the fixed build installer; package/scriptlet
    # failures retain Anaconda's stock fatal behavior.
    # -----------------------------------------------------------------------
    log "Building minimal authenticated Anaconda updates image..."
    if ! NOID_ANACONDA_PATCH_TMPDIR="$ISO_BUILD_TMP_ROOT" \
            bash "${REPO_ROOT}/scripts/anaconda-patch/build-updates-img.sh" "$INSTALL_ISO" "$UPDATES_IMG"; then
        log "ERROR: Anaconda updates image build failed"
        exit 9
    fi
    if [ ! -f "$UPDATES_IMG" ]; then
        log "ERROR: updates.img not found at $UPDATES_IMG after build"
        exit 9
    fi

    stage_reduced_dependency_cache || exit 11

    # `exec` so the subshell's PID becomes python3's PID — kill $HTTP_PID in
    # cleanup() then actually terminates http.server (not just an idle subshell).
    # CWD = the dedicated document root serving only updates.img (for
    # inst.updates=) and branding/ (Module 32's mandatory build-stage
    # transport). Private logs, the flattened Kickstart and Lorax code remain
    # outside that HTTP boundary.
    # Explicit --bind 127.0.0.1 prevents LAN
    # exposure of build-time payload. qemu user-mode NAT translates 10.0.2.2
    # → 127.0.0.1 inside the inner VM, so loopback-only is sufficient.
    start_build_http || exit 10

    # qemu user-mode NAT: host's 127.0.0.1 appears as 10.0.2.2 to inner VM.
    # inst.profile=noid-privacy-workstation forces Anaconda to load our profile
    # directly (= /etc/anaconda/profile.d/noid-privacy.conf) instead of falling
    # back to the base ISO's fedora-server profile. The install.img inherits
    # /etc/os-release from the Fedora-Server-netinst base where ID=fedora +
    # VARIANT_ID=server, so auto-detection picks fedora-server even though our
    # squashfs has the correct NoID Privacy os-release. Explicit kernel-arg bypasses
    # the auto-detection — matches Anaconda's documented profile-override
    # mechanism. (Reproduced install-time profile mismatch.)
    #
    # Fedora's 6.19.10-300.fc44 netinst kernel can hit a bochs DRM vblank WARN
    # on QEMU's implicit standard VGA while the RPM transaction is active. In
    # the reproduced failure that severed Anaconda's virtio log channel and
    # made Lorax abort, although the package transaction itself had no error.
    # Exclude only that build-VM display driver in both dracut and the normal
    # module loader. These are --kernel-args for the transient installer; they
    # are deliberately absent from --extra-boot-args and the resulting image.
    LMC_ARGS+=(--kernel-args \
        "inst.updates=http://10.0.2.2:${HTTP_PORT}/$(basename "$UPDATES_IMG") inst.profile=noid-privacy-workstation rd.driver.blacklist=bochs modprobe.blacklist=bochs")
fi

# The base digest is selected only after its signed-manifest verification.
# Inject into the disposable flat kickstart immediately before LMC consumes it.
sed -i "s/@@NOID_BASE_ISO_SHA256@@/${NOID_BASE_ISO_SHA256}/g" "$FLAT_KS"
if grep -qE '@@NOID_[A-Z0-9_]+@@' "$FLAT_KS"; then
    log "ERROR: unresolved canonical provenance placeholder remains in flattened kickstart"
    exit 12
fi

log "Invoking livemedia-creator..."
log "Command: livemedia-creator ${LMC_ARGS[*]}"

# The supported NoID Privacy interactive shell uses umask 0027 and sudo deliberately
# preserves it.  Lorax/dracut creates public systemd units and drop-in
# directories with ordinary redirects/mkdir; inheriting 0027 therefore embeds
# 0640/0750 configuration in the first installed initramfs and systemd reports
# every affected unit as world-inaccessible.  Scope Fedora's normal public
# system-metadata umask to the elevated compose process.  Private staging,
# logs and retained evidence keep their explicit 0700/0600 modes.
sudo -n /usr/bin/sh -c 'umask 022; exec "$@"' noid-lmc \
    /usr/bin/env PYTHONPATH="$LORAX_OVERRIDE_DIR" \
    /usr/bin/livemedia-creator "${LMC_ARGS[@]}"

# Lorax writes its logs as the elevated process. Return only these private
# compose logs to the invoking user, then verify the actual parser/template
# state rather than trusting the shell argument array alone. The complete log
# publication boundary is handled separately by the release-evidence gate.
compose_logs=("$LMC_LOG" "$LMC_PROGRAM_LOG")
if [ "$NO_VIRT" = "0" ]; then
    compose_logs+=("$LMC_VIRT_LOG")
fi
sudo -n chown -- "$(id -u):$(id -g)" "${compose_logs[@]}"
chmod 0600 "${compose_logs[@]}"
for compose_log in "$LMC_LOG" "$LMC_PROGRAM_LOG"; do
    [ -s "$compose_log" ] || {
        log "ERROR: required compose log is missing or empty: $compose_log"
        exit 15
    }
    if grep -Fq 'your distribution provided bug reporting tool' "$compose_log"; then
        log "ERROR: Lorax placeholder bug-report metadata survived in $(basename "$compose_log")"
        exit 15
    fi
    if grep -Fq -- '-volid text does not comply to ISO 9660 / ECMA 119 rules' "$compose_log"; then
        log "ERROR: xorriso rejected the compose volume-id contract in $(basename "$compose_log")"
        exit 15
    fi
done
grep -Fq "release='${PRODUCT_RELEASE}'" "$LMC_LOG" \
    || { log "ERROR: compose log does not confirm NoID Privacy release metadata"; exit 15; }
grep -Fq "bugurl='${BUG_URL}'" "$LMC_LOG" \
    || { log "ERROR: compose log does not confirm the NoID Privacy bug-report boundary"; exit 15; }
grep -Fq "volid='${VOLID}'" "$LMC_LOG" \
    || { log "ERROR: compose log does not confirm the ECMA-119 volume ID"; exit 15; }

# The guest's asynchronous Anaconda Boss logger can reach transport EOF after
# exact M99 completion without emitting its redundant queue-complete tail.
# Bind canonical success to Lorax's mode-specific host-side result instead.
# KVM emits "Installation finished without errors."; Anaconda's no-virt
# dirinstall emits "Complete!". In both modes the first marker must be followed
# exactly once by Lorax's "Disk Image install successful" result. The dedicated
# auditor rejects missing, duplicated, reordered or format-drifted evidence and
# binds the mode plus exact livemedia log hash in a retained JSON report.
if [ "$NO_VIRT" = "1" ]; then
    LMC_SUCCESS_MODE="no-virt"
else
    LMC_SUCCESS_MODE="kvm"
fi
if ! python3 "${REPO_ROOT}/scripts/verify-livemedia-success.py" \
        --mode "$LMC_SUCCESS_MODE" \
        --log "$LMC_LOG" --report "$LMC_SUCCESS_REPORT"; then
    log "ERROR: livemedia success evidence is incomplete or invalid"
    exit 15
fi

# A successful Anaconda/LMC exit is not sufficient evidence. Classify every
# high-severity, AVC and nonzero event in the canonical KVM installer log under
# the closed, versioned Fedora-44 policy. The exact Anaconda version and
# NoID Privacy profile remain mandatory, as does M99 completion, even when
# the redundant guest-side Boss tail is absent. BRLTTY's historical error
# flood is deliberately not allowlisted: the build-installer-only native mask
# must make its count zero.
# The no-virt development path has no virt-install log and is therefore never
# represented as having passed this KVM release gate.
if [ "$NO_VIRT" = "0" ]; then
    log "Auditing canonical KVM installer log against compose policy v1..."
    if ! python3 "${REPO_ROOT}/scripts/audit-compose-log.py" \
            --policy "$COMPOSE_LOG_POLICY" \
            --log "$LMC_VIRT_LOG" \
            --report "$COMPOSE_LOG_REPORT"; then
        log "ERROR: compose installer log contains an unclassified, ambiguous or over-budget event"
        exit 16
    fi
else
    log "NOTICE: --no-virt has no KVM virt-install.log; KVM compose-log release gate not applicable"
fi

# Return the artifact tree to the release user before checksumming and atomic
# publication. Otherwise root-run livemedia-creator leaves a root-owned result
# that cannot be completed in the user-owned candidate transaction.
sudo -n chown -R -- "$(id -u):$(id -g)" "$RESULT_DIR"

# `--extra-boot-args` is interpolated into Lorax's entry-specific templates.
# Audit both final GRUB surfaces rather than trusting the argument array: all
# three entries must carry the exact managed security set, normal/basic must
# have one vendor-owned rhgb, and media-check must retain Lorax's no-rhgb form.
log "Auditing final BIOS/UEFI Live boot arguments..."
printf '%s\n' \
    'NOID_LIVE_BOOT_CONFIG_AUDIT_V1' \
    "source_commit=$NOID_SOURCE_COMMIT" > "$LIVE_BOOT_CONFIG_EVIDENCE"
for config_spec in \
    'efi|/EFI/BOOT/grub.cfg' \
    'bios|/boot/grub2/grub.cfg'; do
    config_label=${config_spec%%|*}
    config_path=${config_spec#*|}
    config_extract="$BUILD_STAGE_DIR/live-grub-${config_label}.cfg"
    if ! isoinfo -R -i "$RESULT_DIR/$ISO_NAME" -x "$config_path" \
            > "$config_extract" || [ ! -s "$config_extract" ]; then
        log "ERROR: cannot extract final $config_label Live boot config: $config_path"
        exit 15
    fi
    if ! python3 "$KARG_CONTRACT" live-config \
            "$config_extract" "$KARG_MANIFEST" "$KARG_SOURCE"; then
        log "ERROR: final $config_label Live boot arguments violate the source contract"
        exit 15
    fi
    printf '%s_sha256=%s\n' "$config_label" \
        "$(sha256sum "$config_extract" | awk '{print $1}')" \
        >> "$LIVE_BOOT_CONFIG_EVIDENCE"
done
chmod 0600 "$LIVE_BOOT_CONFIG_EVIDENCE"

# Inspect the actual root tree nested in the final ISO. The compose-time Lorax
# hook is necessary but not self-authenticating evidence: this independent
# extraction gate proves that the compressed artifact contains no build host
# identity, secret key, NetworkManager/chrony state or compose logs. It also
# validates systemd's canonical empty machine-id contract.
log "Auditing final compressed rootfs image hygiene..."
if ! sudo -n "${REPO_ROOT}/scripts/verify-live-image-hygiene.sh" \
        "$RESULT_DIR/$ISO_NAME" "$ROOTFS_HYGIENE_REPORT"; then
    log "ERROR: final compressed rootfs contains composed host state or could not be audited"
    exit 17
fi
[ -f "$ROOTFS_HYGIENE_REPORT" ] && [ ! -L "$ROOTFS_HYGIENE_REPORT" ] \
    && grep -qF '"verdict": "pass"' "$ROOTFS_HYGIENE_REPORT" || {
    log "ERROR: final rootfs hygiene report lacks its exact pass verdict"
    exit 17
}

# Retain the complete private logs and their machine-readable classification
# beside the candidate, but outside the ISO checksum/signature set. They may
# contain builder-local paths and are local audit evidence, not publication
# artifacts. SHA256SUMS inside this 0700 directory binds the exact reviewed
# bytes; the public candidate checksum below continues to cover only the ISO.
PRIVATE_BUILD_EVIDENCE="$RESULT_DIR/private-build-evidence"
install -d -m 0700 "$PRIVATE_BUILD_EVIDENCE"
for evidence_log in "${compose_logs[@]}"; do
    install -m 0600 "$evidence_log" "$PRIVATE_BUILD_EVIDENCE/$(basename "$evidence_log")"
done
install -m 0600 "$LORAX_OVERRIDE_EVIDENCE" \
    "$PRIVATE_BUILD_EVIDENCE/lorax-overrides.txt"
install -m 0600 "$LORAX_TEMPLATE_EVIDENCE" \
    "$PRIVATE_BUILD_EVIDENCE/lorax-templates.txt"
install -m 0600 "$LIVE_BOOT_CONFIG_EVIDENCE" \
    "$PRIVATE_BUILD_EVIDENCE/live-boot-config-audit.txt"
install -m 0600 "$ROOTFS_HYGIENE_REPORT" \
    "$PRIVATE_BUILD_EVIDENCE/rootfs-hygiene-audit.json"
install -m 0600 "$LMC_SUCCESS_REPORT" \
    "$PRIVATE_BUILD_EVIDENCE/livemedia-success-audit.json"
if [ "$NO_VIRT" = "0" ]; then
    install -m 0600 "$COMPOSE_LOG_REPORT" "$PRIVATE_BUILD_EVIDENCE/compose-log-audit.json"
    install -m 0600 "$COMPOSE_LOG_POLICY" "$PRIVATE_BUILD_EVIDENCE/compose-log-policy-v1.json"
fi
(
    cd "$PRIVATE_BUILD_EVIDENCE"
    evidence_files=()
    for evidence_file in *; do
        [ "$evidence_file" = SHA256SUMS ] || evidence_files+=("$evidence_file")
    done
    sha256sum "${evidence_files[@]}" > SHA256SUMS
    chmod 0600 SHA256SUMS
)

# ---------------------------------------------------------------------------
# Checksum; ISO signature is deliberately a later operation on these bytes.
# ---------------------------------------------------------------------------
cd "$RESULT_DIR"
if [ -f "$ISO_NAME" ]; then
    log "ISO assembled in unpublished transaction: $RESULT_DIR/$ISO_NAME"
    log "  Size: $(du -h "$ISO_NAME" | cut -f1)"
    sha256sum "$ISO_NAME" > SHA256SUMS
    log "  SHA256: $(awk '{print $1}' SHA256SUMS)"

    rm -f SHA256SUMS.asc
    log "  Candidate checksum intentionally unsigned; sign these exact bytes only after VM sign-off"
else
    log "ERROR: ISO build failed — $ISO_NAME not found in $RESULT_DIR"
    exit 7
fi

# Publication is the only transition that makes a candidate visible at its
# final path. The helper proves both paths share the candidate filesystem and
# performs one atomic directory rename; collisions never replace prior output.
cd "$REPO_ROOT"
noid_candidate_publish \
    || { log "ERROR: candidate publication transaction failed"; exit 5; }
log "Candidate published atomically: $RESULT_DIR"
log "  ISO:      $RESULT_DIR/$ISO_NAME"
log "  Checksum: $RESULT_DIR/SHA256SUMS"

log "=== Build complete ==="

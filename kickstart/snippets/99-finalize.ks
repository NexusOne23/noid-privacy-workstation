# ============================================================================
# Module 99 — Finalize (cross-module checks; no AIDE trust mutation)
# Status: LOCKED 2026-08-23 (v172) — bind final verification to the NTS retry/backoff contract.
#
# Purpose: this snippet MUST run as the FINAL %post block in the master
# kickstart, AFTER all other modules (M01-M37 + M40 + M41 + M42) have
# completed their file writes. It performs explicit cross-module sanity checks
# for artifact presence, mask symlinks, config keys, package
# presence/absence and the exact EXPECTED_STAMPS adopter loop. If anything
# fails, the whole kickstart fails (--erroronfail) and the image build aborts
# with a clear log.
#
# The image deliberately ships without an active AIDE database. Candidate
# generation and activation are user-owned trust decisions performed through
# M13's hash-confirmed `noid-aide-baseline-review` workflow after installation.
#
# Constraint notes (keep on future edits):
#   - M99 has NO health stamp by design (it IS the verifier — a stamp
#     would be circular). EXPECTED_STAMPS lists the 14 adopter modules;
#     `fail` is the sole dynamic error accumulator.
#   - Cross-checks must be SYNCED in the same commit when a module
#     refactors its artifacts (path renames, count bumps, dropped files) —
#     the recurring failure class here is a finalize check hardcoded
#     against OLD module state (multiple build aborts had exactly this
#     root cause). M21 uses an exact stateful manifest; M99 must compare
#     generated directives to that manifest rather than preserve a raw minimum.
#   - Per-check rationale comments live next to the checks below — keep
#     them when editing (they document REMOVED checks + fallback-aware
#     accept-states that must not be re-added or re-tightened).
#
# Cross-references: M13 (aide.conf, check wrapper and explicit baseline review)
# · M25 (check-only post-update evidence).
# ============================================================================

%post --erroronfail --log=/var/log/ks-99-finalize.log

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [Module 99] $*"
}

log "=== Start Module 99: Finalize (sanity checks; AIDE trust uninitialized) ==="

# ----------------------------------------------------------------------------
# Phase 1: Architecture sanity check
# ----------------------------------------------------------------------------
# This image is built + tested for x86_64 only. Fedora does build aarch64
# + ppc64le + s390x + riscv64, but Module-specific assumptions (Intel ME
# mitigation, arkenfox pinned files, paulcarroty VSCodium repo, many udev
# rules, AMD PSP PCI IDs, etc.) do not transfer. Fail loud if someone
# accidentally routes this kickstart at a non-x86_64 build.

ARCH=$(uname -m 2>/dev/null || echo unknown)
if [ "$ARCH" != "x86_64" ]; then
    log "FAIL: architecture is $ARCH, expected x86_64"
    log "      NoID Privacy Workstation v1.x is x86_64-only. Aborting finalize."
    log "      See docs/build.md for supported architectures."
    exit 1
fi
log "Phase 1: Architecture check OK (x86_64)"

# ----------------------------------------------------------------------------
# Phase 2: Preserve Anaconda's stock fatal RPM-transaction semantics
# ----------------------------------------------------------------------------
# The retired v7 override accepted broad package/scriptlet pairs and could hide
# a future unrelated failure. The successful reference compose emitted no
# script_error acceptance event, and codium is installed later in %post where
# the payload callback cannot affect it. Keep native Anaconda behavior: any RPM
# transaction error remains fatal. The inst.updates image contains only profile
# configuration and the build-installer-local BRLTTY mask.

log "Phase 2: Verify stock Anaconda RPM-transaction handling"
ANACONDA_TP=/usr/lib64/python3.14/site-packages/pyanaconda/modules/payloads/payload/dnf/transaction_progress.py
if [ ! -f "$ANACONDA_TP" ]; then
    log "  FAIL: Anaconda transaction handler missing at $ANACONDA_TP"
    exit 1
fi
if grep -qE 'NoID Privacy PATCH|_noid_safe_script_errors|_noid_safe_pkg' "$ANACONDA_TP"; then
    log "  FAIL: retired RPM scriptlet-error bypass is present"
    exit 1
fi
log "  [OK] stock Anaconda transaction handler retained; no scriptlet bypass"

# ----------------------------------------------------------------------------
# Phase 3: Apply M10's native permission policy after every package scriptlet
# ----------------------------------------------------------------------------
# M26 runs after M10 and may install cronie or another owning package whose RPM
# payload restores vendor modes. Apply the declarative tmpfiles policy once at
# the final compose boundary. Boot-time tmpfiles and package-scoped dnf5
# actions own later reconciliation; no periodic custom chmod service exists.

log "Phase 3: Apply native M10 permission policy after package installation"
M10_PERMISSION_POLICY=/etc/tmpfiles.d/90-noid-permission-policy.conf
if [ -f "$M10_PERMISSION_POLICY" ] && \
   systemd-tmpfiles --create "$M10_PERMISSION_POLICY"; then
    log "  [OK] M10 tmpfiles policy applied after all package scriptlets"
else
    log "  FAIL: M10 native permission policy missing or failed"
    exit 1
fi

# ----------------------------------------------------------------------------
# Phase 4: Preserve ACL contracts across the SquashFS transport boundary
# ----------------------------------------------------------------------------
# Fedora's F44 mksquashfs emits "Unrecognised xattr prefix" for the two POSIX
# ACL namespaces and drops the nontrivial ACLs from the live payload. The raw
# compose root has the vendor-created ACLs, but the Live session and a target
# copied from that payload do not. systemd-tmpfiles eventually reapplies the
# vendor rules, but systemd-journal-flush.service runs before the general
# tmpfiles setup and may use /var/log/journal first.
#
# Record the complete reviewed ACLs as data, apply them to the raw compose root,
# and ship a rollback-capable early-boot restore ordered before the persistent
# journal flush. The helper validates both paths before mutation, backs up all
# ACL/owner/mode state, applies the complete ACLs, verifies exact canonical
# output, and restores every path if any operation or postcondition fails.

log "Phase 4: Install and verify live-payload ACL replacement contract"
install -d -m 0755 -o root -g root /usr/share/noid-privacy /usr/libexec

cat > /usr/share/noid-privacy/live-payload-acls.tsv <<'LIVE_PAYLOAD_ACLS_EOF'
/var/lib/tpm2-tss/system/keystore|2775|tss|tss|user::rwx,group::rwx,other::r-x|default:user::rwx,default:group::rwx,default:group:tss:rwx,default:mask::rwx,default:other::r-x
/var/log/journal|2755|root|systemd-journal|user::rwx,group::r-x,group:adm:r-x,group:wheel:r-x,mask::r-x,other::r-x|default:user::rwx,default:group::r-x,default:group:adm:r-x,default:group:wheel:r-x,default:mask::r-x,default:other::r-x
LIVE_PAYLOAD_ACLS_EOF
chown root:root /usr/share/noid-privacy/live-payload-acls.tsv
chmod 0644 /usr/share/noid-privacy/live-payload-acls.tsv

cat > /usr/libexec/noid-restore-live-payload-acls <<'ACL_RESTORE_EOF'
#!/usr/bin/bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$#" -ne 0 ]; then
    echo 'Usage: noid-restore-live-payload-acls' >&2
    exit 2
fi

ROOT="${NOID_ACL_ROOT:-/}"
MANIFEST="${NOID_ACL_MANIFEST:-/usr/share/noid-privacy/live-payload-acls.tsv}"

die() {
    echo "noid-live-payload-acls: $*" >&2
    exit 1
}

for tool in getfacl setfacl stat chown chmod readlink mktemp find rmdir; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

[ -d "$ROOT" ] && [ ! -L "$ROOT" ] || die "root is not a real directory: $ROOT"
ROOT=$(readlink -f -- "$ROOT")
[ -n "$ROOT" ] || die "cannot canonicalize root"
if [ "$ROOT" = "/" ]; then
    [ "${EUID}" -eq 0 ] || die "installed-root repair requires root"
    [ ! -L "$MANIFEST" ] && [ -f "$MANIFEST" ] \
        || die "canonical manifest is missing, non-regular or symlinked"
    [ "$(stat -c '%a:%U:%G' -- "$MANIFEST" 2>/dev/null || true)" = \
      "644:root:root" ] || die "canonical manifest metadata drift"
else
    # A non-root prefix is supported only for the repository's isolated
    # negative/rollback fixtures. The installed unit never sets these values.
    [ "${NOID_ACL_TEST_MODE:-0}" = "1" ] \
        || die "alternate roots require NOID_ACL_TEST_MODE=1"
    [ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] \
        || die "fixture manifest is missing, non-regular or symlinked"
fi

declare -a PATHS MODES OWNERS OWNER_GROUPS ACCESS_ACLS DEFAULT_ACLS FULL_PATHS
declare -A SEEN
count=0
while IFS='|' read -r path mode owner group access_acl default_acl extra; do
    [ -n "$path" ] || die "blank manifest row"
    [ -z "$extra" ] || die "manifest row has extra fields: $path"
    case "$path" in
        /var/lib/tpm2-tss/system/keystore|/var/log/journal) ;;
        *) die "path outside the closed ACL contract: $path" ;;
    esac
    [ -z "${SEEN[$path]:-}" ] || die "duplicate manifest path: $path"
    SEEN[$path]=1
    [[ "$mode" =~ ^[0-7]{4}$ ]] || die "invalid mode for $path"
    [[ "$owner" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid owner for $path"
    [[ "$group" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid group for $path"
    [[ "$access_acl" =~ ^[a-z0-9_:-]+(,[a-z0-9_:-]+)*$ ]] \
        || die "invalid access ACL for $path"
    [[ "$default_acl" =~ ^default:[a-z0-9_:-]+(,default:[a-z0-9_:-]+)*$ ]] \
        || die "invalid default ACL for $path"

    full_path="${ROOT%/}${path}"
    [ -d "$full_path" ] && [ ! -L "$full_path" ] \
        || die "required ACL path is missing, non-directory or symlinked: $full_path"
    [ "$(readlink -f -- "$full_path")" = "$full_path" ] \
        || die "ACL path traverses a symlink: $full_path"

    PATHS+=("$path")
    MODES+=("$mode")
    OWNERS+=("$owner")
    OWNER_GROUPS+=("$group")
    ACCESS_ACLS+=("$access_acl")
    DEFAULT_ACLS+=("$default_acl")
    FULL_PATHS+=("$full_path")
    count=$((count + 1))
done < "$MANIFEST"

[ "$count" -eq 2 ] \
    && [ -n "${SEEN[/var/lib/tpm2-tss/system/keystore]:-}" ] \
    && [ -n "${SEEN[/var/log/journal]:-}" ] \
    || die "manifest must contain exactly the two canonical ACL paths"

stage_parent="${NOID_ACL_STAGE_PARENT:-${ROOT%/}/run}"
[ -d "$stage_parent" ] && [ ! -L "$stage_parent" ] \
    || die "private rollback parent is unavailable: $stage_parent"
stage_parent=$(readlink -f -- "$stage_parent")
[ -n "$stage_parent" ] || die "cannot canonicalize private rollback parent"
if [ "$ROOT" = "/" ]; then
    case "$stage_parent" in
        /run|/run/noid-live-payload-acls) ;;
        *) die "installed-root rollback parent is outside the closed contract: $stage_parent" ;;
    esac
elif [ "$stage_parent" != "${ROOT%/}/run" ]; then
    die "fixture rollback parent is outside the supplied root: $stage_parent"
fi
umask 077
stage=$(mktemp -d -p "$stage_parent" noid-live-payload-acls.XXXXXX)
declare -a BACKUPS
rollback=1

cleanup() {
    rc=$? cleanup_failed=0
    trap - EXIT HUP INT TERM
    if [ "$rollback" -eq 1 ]; then
        for backup in "${BACKUPS[@]:-}"; do
            [ -n "$backup" ] || continue
            setfacl -P --restore="$backup" >/dev/null 2>&1 || rc=1
        done
    fi
    # Never hide a cleanup failure: these root-private files contain the
    # pre-repair ACL/owner/mode state and the RuntimeDirectory stays present
    # while this RemainAfterExit unit is active. Stay on the mktemp-created
    # filesystem boundary and remove the exact task-owned directory last.
    find "$stage" -xdev -mindepth 1 -delete || cleanup_failed=1
    rmdir -- "$stage" || cleanup_failed=1
    if [ "$cleanup_failed" -ne 0 ]; then
        echo "noid-live-payload-acls: rollback scratch cleanup failed: $stage" >&2
        [ "$rc" -ne 0 ] || rc=1
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for i in "${!FULL_PATHS[@]}"; do
    backup="$stage/$i.acl"
    getfacl -p -- "${FULL_PATHS[$i]}" > "$backup"
    BACKUPS+=("$backup")
done

for i in "${!FULL_PATHS[@]}"; do
    full_path=${FULL_PATHS[$i]}
    chown --no-dereference "${OWNERS[$i]}:${OWNER_GROUPS[$i]}" -- "$full_path"
    chmod "${MODES[$i]}" -- "$full_path"
    setfacl -P --set="${ACCESS_ACLS[$i]},${DEFAULT_ACLS[$i]}" -- "$full_path"
    actual=$(getfacl -cp -- "$full_path" | sed '/^$/d' | paste -sd, -)
    expected="${ACCESS_ACLS[$i]},${DEFAULT_ACLS[$i]}"
    [ "$actual" = "$expected" ] \
        || die "exact ACL verification failed for ${PATHS[$i]}"
    [ "$(stat -c '%a:%U:%G' -- "$full_path")" = \
      "${MODES[$i]}:${OWNERS[$i]}:${OWNER_GROUPS[$i]}" ] \
        || die "owner/mode verification failed for ${PATHS[$i]}"
done

rollback=0
echo "noid-live-payload-acls: exact two-path ACL contract restored"
ACL_RESTORE_EOF
chown root:root /usr/libexec/noid-restore-live-payload-acls
chmod 0755 /usr/libexec/noid-restore-live-payload-acls

cat > /usr/lib/systemd/system/noid-live-payload-acl-restore.service <<'ACL_UNIT_EOF'
[Unit]
Description=Restore ACLs lost at the live-payload SquashFS boundary
Documentation=man:setfacl(1) man:systemd-journald.service(8)
DefaultDependencies=no
After=systemd-remount-fs.service
Before=systemd-journal-flush.service systemd-tmpfiles-setup.service sysinit.target
RequiresMountsFor=/var/log/journal /var/lib/tpm2-tss/system/keystore

[Service]
Type=oneshot
ExecStart=/usr/libexec/noid-restore-live-payload-acls
RemainAfterExit=yes
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
# PrivateTmp=yes implicitly orders a service after systemd-tmpfiles-setup,
# which would cycle against the required early Before= edge above. This helper
# never uses /tmp; systemd creates one narrow writable /run parent directly.
Environment=NOID_ACL_STAGE_PARENT=/run/noid-live-payload-acls
RuntimeDirectory=noid-live-payload-acls
RuntimeDirectoryMode=0700
# The TPM keystore is a required helper postcondition, but prefix it optional
# for namespace construction so an absent package-owned directory reaches the
# helper's explicit diagnostic instead of failing opaquely with 226/NAMESPACE.
ReadWritePaths=/run/noid-live-payload-acls /var/log/journal -/var/lib/tpm2-tss/system/keystore
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID
RestrictAddressFamilies=AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=sysinit.target
ACL_UNIT_EOF
chown root:root /usr/lib/systemd/system/noid-live-payload-acl-restore.service
chmod 0644 /usr/lib/systemd/system/noid-live-payload-acl-restore.service
systemctl enable noid-live-payload-acl-restore.service >/dev/null

# Establish and prove the raw-compose side of the parity contract. SquashFS
# will drop these ACL xattrs; the enabled early-boot service reconstructs them.
/usr/libexec/noid-restore-live-payload-acls
systemd-analyze verify /usr/lib/systemd/system/noid-live-payload-acl-restore.service
log "  [OK] raw ACL manifest exact; early restore enabled before journal flush"

# ----------------------------------------------------------------------------
# Phase 5: Final cross-module sanity verification
# ----------------------------------------------------------------------------
# Verify that the most critical artifacts from each Module are in place.
# This catches cascading failures where an early module silently skipped
# a step but didn't `exit 1`.

log "Phase 5: Cross-module sanity verification"

fail=0

# Live-payload ACL transport replacement — all artifacts and the explicit
# runtime dependency are release-critical. The raw root must still match the
# complete canonical manifest after every producer module has finished.
for f in /usr/share/noid-privacy/live-payload-acls.tsv \
         /usr/libexec/noid-restore-live-payload-acls \
         /usr/lib/systemd/system/noid-live-payload-acl-restore.service; do
    if [ ! -f "$f" ] || [ -L "$f" ]; then
        log "  FAIL: live-payload ACL replacement artifact invalid: $f"
        fail=$((fail + 1))
    fi
done
if ! rpm -q acl >/dev/null 2>&1; then
    log "  FAIL: explicit ACL runtime dependency is missing"
    fail=$((fail + 1))
fi
if [ "$(readlink -f /etc/systemd/system/sysinit.target.wants/noid-live-payload-acl-restore.service 2>/dev/null || true)" != \
     "/usr/lib/systemd/system/noid-live-payload-acl-restore.service" ]; then
    log "  FAIL: live-payload ACL restore is not enabled in sysinit.target"
    fail=$((fail + 1))
fi
if ! grep -qxF 'Before=systemd-journal-flush.service systemd-tmpfiles-setup.service sysinit.target' \
        /usr/lib/systemd/system/noid-live-payload-acl-restore.service 2>/dev/null; then
    log "  FAIL: live-payload ACL restore is not ordered before persistent journal use"
    fail=$((fail + 1))
fi
if grep -qxE 'PrivateTmp=(yes|true|1|on|y|t)' \
        /usr/lib/systemd/system/noid-live-payload-acl-restore.service 2>/dev/null \
   || ! grep -qxF 'Environment=NOID_ACL_STAGE_PARENT=/run/noid-live-payload-acls' \
        /usr/lib/systemd/system/noid-live-payload-acl-restore.service 2>/dev/null \
   || ! grep -qxF 'RuntimeDirectory=noid-live-payload-acls' \
        /usr/lib/systemd/system/noid-live-payload-acl-restore.service 2>/dev/null \
   || ! grep -qxF 'RuntimeDirectoryMode=0700' \
        /usr/lib/systemd/system/noid-live-payload-acl-restore.service 2>/dev/null \
   || ! grep -qxF 'ReadWritePaths=/run/noid-live-payload-acls /var/log/journal -/var/lib/tpm2-tss/system/keystore' \
        /usr/lib/systemd/system/noid-live-payload-acl-restore.service 2>/dev/null \
   || ! grep -qxF 'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID' \
        /usr/lib/systemd/system/noid-live-payload-acl-restore.service 2>/dev/null; then
    log "  FAIL: live-payload ACL restore scratch/ordering sandbox is unsafe"
    fail=$((fail + 1))
fi
if ! /usr/libexec/noid-restore-live-payload-acls >/dev/null; then
    log "  FAIL: final raw-compose ACL manifest verification failed"
    fail=$((fail + 1))
else
    log "  [OK] final raw-compose ACL manifest is exact"
fi

# Module 01 — grub cmdline + dnf conf
# /boot/grub2/grub.cfg was removed from this check.
# Module 01 STEP 6 (which generated grub.cfg in %post) was removed in
# an earlier implementation caused gen_grub_cfgstub script failure on
# real-hardware end-user installs. The grub.cfg is now
# generated by Anaconda's own bootloader-install step AFTER all %post
# sections complete — by the time Module 99 runs, /boot/grub2/grub.cfg
# does NOT yet exist on the target rootfs. /etc/default/grub +
# /etc/dnf/dnf.conf still verify here — those ARE written by Module 01.
for f in /etc/default/grub /etc/dnf/dnf.conf \
         /usr/share/anaconda/interactive-defaults.ks \
         /usr/share/anaconda/noid-target-kernel-cmdline.ks \
         /usr/libexec/noid-verify-target-karg-payload \
         /usr/libexec/noid-canonicalize-kernel-cmdline \
         /usr/libexec/noid-rebind-firstboot-rootflags \
         /usr/libexec/noid-firstboot-cmdline-transition \
         /usr/local/sbin/noid-firstboot-cmdline.sh \
         /etc/systemd/system/noid-firstboot-cmdline.service \
         /usr/local/sbin/noid-grub-password \
         /etc/kernel/install.d/99-noid-protect-system-map.install; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 01 missing: $f"
        fail=$((fail + 1))
    fi
done
interactive_timezone_count=$(grep -Ec '^[[:space:]]*timezone[[:space:]]' \
    /usr/share/anaconda/interactive-defaults.ks 2>/dev/null || true)
interactive_utc_count=$(grep -cEx 'timezone UTC --utc' \
    /usr/share/anaconda/interactive-defaults.ks 2>/dev/null || true)
if [ "$interactive_timezone_count" -ne 1 ] \
   || [ "$interactive_utc_count" -ne 1 ]; then
    log "  FAIL: Module 01 interactive installer timezone is not exactly neutral UTC"
    fail=$((fail + 1))
fi
if [ -e /etc/kernel/install.d/99-noid-remove-system-map.install ] \
   || [ -L /etc/kernel/install.d/99-noid-remove-system-map.install ]; then
    log "  FAIL: Module 01 obsolete System.map deletion hook remains"
    fail=$((fail + 1))
fi
if [ -e /usr/share/anaconda/post-scripts/90-noid-kernel-cmdline.ks ] \
   || [ -L /usr/share/anaconda/post-scripts/90-noid-kernel-cmdline.ks ]; then
    log "  FAIL: Module 01 obsolete detached target-karg script remains"
    fail=$((fail + 1))
fi
if ! grep -qF 'expected_bls_options="$merged \$tuned_params"' \
        /usr/share/anaconda/noid-target-kernel-cmdline.ks 2>/dev/null \
   || ! grep -qF 'bls_options="$merged \$tuned_params"' \
        /usr/libexec/noid-canonicalize-kernel-cmdline 2>/dev/null \
   || ! grep -qF 'awk -v options="$bls_options"' \
        /usr/libexec/noid-canonicalize-kernel-cmdline 2>/dev/null; then
    log "  FAIL: Module 01 Fedora tuned/BLS transport boundary invalid"
    fail=$((fail + 1))
fi

# Module 02 — sysctl hardening (3 files)
for f in /etc/sysctl.d/99-hardening.conf /etc/sysctl.d/99-audit-fixes.conf /etc/sysctl.d/99-userns.conf; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 02 missing: $f"
        fail=$((fail + 1))
    fi
done

# Module 03 — firewalld
for f in /etc/firewalld/firewalld.conf \
         /etc/firewalld/policies/block-lan-out.xml \
         /etc/firewalld/policies/allow-host-ipv6.xml \
         /etc/firewalld/zones/noid-vpn.xml \
         /etc/nftables.d/noid-lan-topology.nft \
         /usr/lib/noid-privacy/noid-lan-xdp.bpf.o \
         /usr/local/sbin/noid-lan-xdp \
         /usr/local/bin/noid-lan-xdp-notify \
         /usr/local/sbin/noid-lan-topology-refresh.sh \
         /usr/local/sbin/noid-lan-topology-boot-refresh.sh \
         /etc/xdg/autostart/noid-lan-xdp-health.desktop \
         /etc/NetworkManager/dispatcher.d/pre-up.d/30-noid-lan-topology-guard \
         /etc/NetworkManager/dispatcher.d/no-wait.d/30-noid-lan-topology-guard \
         /etc/systemd/system/noid-lan-topology-guard.service \
         /etc/NetworkManager/conf.d/03-vpn-zone.conf; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 03 missing: $f"
        fail=$((fail + 1))
    fi
done
if [ "$(readlink /etc/NetworkManager/dispatcher.d/30-noid-lan-topology-guard 2>/dev/null)" \
        != no-wait.d/30-noid-lan-topology-guard ] \
   || ! cmp -s \
        /etc/NetworkManager/dispatcher.d/pre-up.d/30-noid-lan-topology-guard \
        /etc/NetworkManager/dispatcher.d/no-wait.d/30-noid-lan-topology-guard; then
    log "  FAIL: Module 03 awaited/no-wait dispatcher placement is inconsistent"
    fail=$((fail + 1))
fi

if ! command -v bpftool >/dev/null 2>&1; then
    log "  FAIL: Module 03 bpftool runtime dependency is missing"
    fail=$((fail + 1))
fi
mapfile -t noid_lan_xdp_hashes < <(sed -n \
    's/^OBJECT_SHA256=\([0-9a-f]\{64\}\)$/\1/p' \
    /usr/local/sbin/noid-lan-xdp 2>/dev/null)
if [ "${#noid_lan_xdp_hashes[@]}" -ne 1 ]; then
    log "  FAIL: Module 03 controller has no unique object digest"
    fail=$((fail + 1))
elif ! printf '%s  %s\n' \
        "${noid_lan_xdp_hashes[0]}" \
        /usr/lib/noid-privacy/noid-lan-xdp.bpf.o | sha256sum -c - >/dev/null 2>&1; then
    log "  FAIL: Module 03 physical-link BPF object hash mismatch"
    fail=$((fail + 1))
fi
if ! grep -qF 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_PERFMON' \
        /etc/systemd/system/noid-lan-topology-guard.service 2>/dev/null \
   || ! grep -qF 'SystemCallFilter=@system-service bpf' \
        /etc/systemd/system/noid-lan-topology-guard.service 2>/dev/null; then
    log "  FAIL: Module 03 topology service cannot load the required BPF boundary"
    fail=$((fail + 1))
fi

if ! grep -q '<zone target="DROP">' /etc/firewalld/zones/noid-vpn.xml 2>/dev/null; then
    log "  FAIL: Module 03 noid-vpn zone is not target DROP"
    fail=$((fail + 1))
fi
if grep -qE '1699[2-5]' /etc/firewalld/policies/block-lan-out.xml 2>/dev/null; then
    log "  FAIL: Module 03 still misrepresents host firewall as AMT OOB filtering"
    fail=$((fail + 1))
fi

# Module 03 — allow-host-ipv6 hardened (6 types, RA+redirect dropped).
# grep patterns check <icmp-type> rules only (not description text).
if [ -f /etc/firewalld/policies/allow-host-ipv6.xml ]; then
    if grep -qE '<icmp-type name="router-advertisement"' /etc/firewalld/policies/allow-host-ipv6.xml; then
        log "  FAIL: Module 03 allow-host-ipv6.xml still contains router-advertisement rule (Rogue-RA attack surface)"
        fail=$((fail + 1))
    fi
    if grep -qE '<icmp-type name="redirect"' /etc/firewalld/policies/allow-host-ipv6.xml; then
        log "  FAIL: Module 03 allow-host-ipv6.xml still contains redirect rule (ICMPv6-redirect attack surface)"
        fail=$((fail + 1))
    fi
fi

# Module 04 — exact pin tool + pre-network state guard + firstboot service
for f in /usr/local/sbin/noid-arp-hardening.sh \
         /usr/local/sbin/noid-arp-state-guard.sh \
         /usr/local/libexec/noid-network-readiness \
         /etc/NetworkManager/dispatcher.d/25-noid-arp-initial-learn \
         /usr/share/noid-privacy/arp-hardening/90-arp-hardening.template \
         /etc/systemd/system/noid-arp-state-guard.service \
         /etc/systemd/system/noid-arp-hardening-firstboot.service; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 04 missing/not a regular file: $f"
        fail=$((fail + 1))
    fi
done
for retired in \
    /usr/share/noid-privacy/arp-hardening/arp-hardening.nft.template \
    /usr/share/noid-privacy/arp-hardening/arp-bootstrap.nft \
    /usr/share/noid-privacy/arp-hardening/arp-hardening-firewalld-reload.conf.template \
    /etc/nftables/arp-hardening.nft \
    /etc/systemd/system/firewalld.service.d/arp-hardening-firewalld-reload.conf \
    /usr/local/sbin/noid-arp-bootstrap.sh \
    /etc/systemd/system/noid-arp-bootstrap.service \
    /etc/systemd/system/NetworkManager.service.d/21-noid-arp-bootstrap.conf \
    /etc/NetworkManager/dispatcher.d/25-noid-arp-bootstrap-learn \
    /etc/NetworkManager/dispatcher.d/pre-up.d/25-noid-arp-bootstrap-learn; do
    if [ -e "$retired" ] || [ -L "$retired" ]; then
        log "  FAIL: Module 04 retired non-enforcing artifact remains: $retired"
        fail=$((fail + 1))
    fi
done
if ! systemctl is-enabled noid-arp-state-guard.service >/dev/null 2>&1 \
   || ! grep -qF 'Requires=noid-arp-state-guard.service' \
        /etc/systemd/system/NetworkManager.service.d/21-noid-arp-state-guard.conf \
        2>/dev/null; then
    log "  FAIL: Module 04 pre-network state guard is not a required enabled boundary"
    fail=$((fail + 1))
fi
m04_initial=/etc/NetworkManager/dispatcher.d/25-noid-arp-initial-learn
m04_template=/usr/share/noid-privacy/arp-hardening/90-arp-hardening.template
if ! grep -qxF \
        'ACTIVATION_MARKER_CONTENT="NOID_ARP_ACTIVATION_READY_V1"' \
        "$m04_template" \
   || ! grep -qF \
        'gateway revalidation deferred until activation up event' \
        "$m04_template" \
   || ! grep -qF '&& ! publish_activation_marker; then' "$m04_template" \
   || ! grep -qxF 'if [ -e "$STATE" ]; then' "$m04_initial" \
   || ! grep -qxF '        "$NETWORK_READINESS" ready || exit 1' \
        "$m04_initial"; then
    log "  FAIL: Module 04 event-generation coalescing contract is incomplete"
    fail=$((fail + 1))
fi
unset m04_initial m04_template

# Module 05 — LAN isolation
for f in /etc/systemd/resolved.conf.d/99-privacy.conf \
         /etc/NetworkManager/conf.d/99-privacy.conf \
         /etc/dconf/db/distro.d/04-noid-lan-discovery \
         /etc/dconf/db/distro.d/locks/04-noid-lan-discovery; do
    if [ ! -f "$f" ] || [ -L "$f" ]; then
        log "  FAIL: Module 05 missing: $f"
        fail=$((fail + 1))
    fi
done

# Module 05 — hostname-mode=none (local transient-hostname ownership only)
if ! grep -q 'hostname-mode=none' /etc/NetworkManager/conf.d/99-privacy.conf 2>/dev/null; then
    log "  FAIL: Module 05 hostname-mode=none missing in NM privacy config"
    fail=$((fail + 1))
fi

# Module 05 — native GVfs discovery policy; package-owned mount definitions
# must remain pristine so vendor verification and upgrades retain meaning.
if ! grep -qx "display-mode='disabled'" /etc/dconf/db/distro.d/04-noid-lan-discovery 2>/dev/null \
        || ! grep -qx "display-local='disabled'" /etc/dconf/db/distro.d/04-noid-lan-discovery 2>/dev/null \
        || ! grep -qx '/org/gnome/system/wsdd/display-mode' /etc/dconf/db/distro.d/locks/04-noid-lan-discovery 2>/dev/null \
        || ! grep -qx '/org/gnome/system/dns-sd/display-local' /etc/dconf/db/distro.d/locks/04-noid-lan-discovery 2>/dev/null; then
    log "  FAIL: Module 05 native GVfs discovery policy/locks missing"
    fail=$((fail + 1))
fi
if ! gvfs_verify=$(rpm -V gvfs 2>&1); then
    log "  FAIL: Module 05 gvfs package drift detected: $gvfs_verify"
    fail=$((fail + 1))
fi

# Module 05 — closed runtime/state ownership and narrowed service writes
if ! grep -qxF 'd /run/noid-privacy 0755 root root -' \
        /etc/tmpfiles.d/noid-runtime.conf 2>/dev/null \
   || ! grep -qxF \
        'f /run/noid-privacy/lan-topology-refresh.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-runtime.conf 2>/dev/null \
   || ! grep -qxF \
        'f /run/noid-privacy/lan-exceptions.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-runtime.conf 2>/dev/null \
   || ! grep -qxF \
        'f /run/noid-privacy/usbguard-add-user.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-runtime.conf 2>/dev/null \
   || ! grep -qxF \
        'z /run/noid-privacy/usbguard-add-user.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-runtime.conf 2>/dev/null \
   || ! grep -qxF \
        'f /run/noid-privacy/displaylink.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-runtime.conf 2>/dev/null \
   || ! grep -qxF \
        'z /run/noid-privacy/displaylink.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-runtime.conf 2>/dev/null \
   || ! grep -qxF \
        'ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy -/sys/fs/bpf' \
        /etc/systemd/system/noid-lan-expiry-reconcile.service 2>/dev/null; then
    log "  FAIL: Module 05 runtime lock/service write boundary is incomplete"
    fail=$((fail + 1))
fi

# Module 05 — LAN escape-hatch
if [ ! -x /usr/local/bin/noid-lan-allow ] \
   || [ -L /usr/local/bin/noid-lan-allow ] \
   || [ "$(stat -c '%u:%g:%a:%h:%F' \
        /usr/local/bin/noid-lan-allow 2>/dev/null || true)" \
        != '0:0:755:1:regular file' ]; then
    log "  FAIL: Module 05 missing: /usr/local/bin/noid-lan-allow"
    fail=$((fail + 1))
elif ! grep -qF \
        'ARP_HARDENING_STATE="${NOID_ARP_HARDENING_STATE:-/var/lib/noid-privacy/arp-hardening.state}"' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        'next_temporary_schedule()' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        'publish_expiry_schedule()' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        'ip neigh replace "$ip" lladdr "$PROTECTED_GATEWAY_MAC"' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        '[ "$observed" = "$PROTECTED_GATEWAY_MAC" ] || return 1' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        '[ "$PROTECTED_GATEWAY_ENABLED" = 1 ]' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        '[ -x "$ARP_STATE_GUARD" ] && "$ARP_STATE_GUARD" || return 1' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        'valid_global_allow_marker()' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        'read_global_runtime_state()' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        'exec 8<>"$LAN_EXCEPTION_LOCK"' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        'raw ARP and kernel neighbour identity disagree' \
        /usr/local/bin/noid-lan-allow \
     || ! grep -qF \
        'observed=$(exact_permanent_neighbour_mac "$ip" "$iface"' \
        /usr/local/bin/noid-lan-allow; then
    log "  FAIL: Module 05 LAN state/peer identity contract is incomplete"
    fail=$((fail + 1))
fi
if [ ! -x /usr/lib/systemd/system-generators/noid-lan-expiry-generator ] \
   || [ -L /usr/lib/systemd/system-generators/noid-lan-expiry-generator ] \
   || [ "$(stat -c '%u:%g:%a:%h:%F' \
        /usr/lib/systemd/system-generators/noid-lan-expiry-generator \
        2>/dev/null || true)" != '0:0:755:1:regular file' ] \
   || ! bash -n /usr/lib/systemd/system-generators/noid-lan-expiry-generator \
   || ! grep -qF '"OnActiveSec=${delay}s"' \
        /usr/lib/systemd/system-generators/noid-lan-expiry-generator \
   || ! grep -qF '"OnCalendar=@${epoch}"' \
        /usr/lib/systemd/system-generators/noid-lan-expiry-generator; then
    log "  FAIL: Module 05 LAN expiry deadline generator is missing or invalid"
    fail=$((fail + 1))
fi

# Module 06 — VPN zone dispatcher
if [ ! -x /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce ]; then
    log "  FAIL: Module 06 missing: /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce"
    fail=$((fail + 1))
fi
if [ ! -L /etc/NetworkManager/dispatcher.d/pre-up.d/50-vpn-zone-enforce ]; then
    log "  FAIL: Module 06 VPN dispatcher missing pre-up registration"
    fail=$((fail + 1))
fi
if ! grep -q 'connection.zone noid-vpn' \
        /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce 2>/dev/null; then
    log "  FAIL: Module 06 VPN dispatcher does not persist noid-vpn zone"
    fail=$((fail + 1))
fi
if [ ! -x /etc/NetworkManager/dispatcher.d/55-wan-strict-scan-on-network-up ]; then
    log "  FAIL: Module 06 physical-up endpoint scanner dispatcher missing"
    fail=$((fail + 1))
fi
if [ ! -x /usr/local/sbin/noid-wireguard-mtu-reconcile ] \
   || [ -L /usr/local/sbin/noid-wireguard-mtu-reconcile ] \
   || [ "$(stat -c '%u:%g:%a:%h' \
        /usr/local/sbin/noid-wireguard-mtu-reconcile 2>/dev/null || true)" \
        != 0:0:755:1 ] \
   || ! bash -n /usr/local/sbin/noid-wireguard-mtu-reconcile \
   || [ "$(stat -c '%u:%g:%a:%h' \
        /etc/NetworkManager/dispatcher.d/pre-up.d/45-noid-wireguard-mtu \
        2>/dev/null || true)" != 0:0:700:1 ] \
   || [ "$(stat -c '%u:%g:%a:%h' \
        /etc/NetworkManager/dispatcher.d/no-wait.d/45-noid-wireguard-mtu \
        2>/dev/null || true)" != 0:0:700:1 ] \
   || ! cmp -s \
        /etc/NetworkManager/dispatcher.d/pre-up.d/45-noid-wireguard-mtu \
        /etc/NetworkManager/dispatcher.d/no-wait.d/45-noid-wireguard-mtu \
   || [ "$(readlink \
        /etc/NetworkManager/dispatcher.d/45-noid-wireguard-mtu 2>/dev/null)" \
        != no-wait.d/45-noid-wireguard-mtu ]; then
    log "  FAIL: Module 06 WireGuard MTU live-reconciliation contract invalid"
    fail=$((fail + 1))
fi
if [ -e /etc/NetworkManager/dispatcher.d/80-vpn-keepalive ]; then
    log "  FAIL: Module 06 obsolete universal WireGuard keepalive mutator present"
    fail=$((fail + 1))
fi
if [ -e /etc/NetworkManager/dispatcher.d/70-pvpn-killswitch-dns-fix ]; then
    log "  FAIL: Module 06 obsolete Proton kill-switch profile mutator present"
    fail=$((fail + 1))
fi
for f in /etc/nftables.d/noid-wan-strict.nft \
         /etc/tmpfiles.d/noid-wan-strict.conf \
         /usr/local/sbin/noid-wireguard-mtu-reconcile \
         /usr/local/sbin/noid-wan-strict-bootstrap.sh \
         /usr/local/sbin/noid-wan-strict-scan-profiles.sh \
         /usr/local/libexec/noid-wan-strict-endpoints \
         /etc/systemd/system/noid-wan-strict.service \
         /etc/systemd/system/noid-wan-strict-status-publish.service \
         /etc/systemd/system/noid-wan-strict-scan-profiles.path \
         /etc/systemd/system/noid-wan-strict-scan-profiles.service \
         /etc/systemd/system/noid-wan-strict-endpoint-expiry.service \
         /etc/systemd/system/noid-wan-strict-endpoint-expiry.timer; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 06 missing: $f"
        fail=$((fail + 1))
    fi
done
if ! grep -qxF 'f /run/lock/noid-wan-strict.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-wan-strict.conf 2>/dev/null \
   || ! grep -qxF 'f /run/lock/noid-wireguard-mtu.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-wan-strict.conf 2>/dev/null \
   || ! grep -qxF \
        'd /run/noid-privacy/wan-strict-active 0700 root root -' \
        /etc/tmpfiles.d/noid-wan-strict.conf 2>/dev/null \
   || ! grep -qxF \
        'ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock' \
        /etc/systemd/system/noid-wan-strict.service 2>/dev/null \
   || ! grep -qxF \
        'ConditionPathExists=!/var/lib/noid-privacy/wan-strict-disabled.flag' \
        /etc/systemd/system/noid-wan-strict.service 2>/dev/null \
   || ! grep -qxF \
        'ExecStart=/usr/local/sbin/noid-wan-strict-publish-status' \
        /etc/systemd/system/noid-wan-strict-status-publish.service 2>/dev/null \
   || ! grep -qxF 'Before=multi-user.target graphical.target' \
        /etc/systemd/system/noid-wan-strict-status-publish.service 2>/dev/null \
   || ! systemctl is-enabled --quiet \
        noid-wan-strict-status-publish.service 2>/dev/null \
   || ! grep -qxF 'ProtectSystem=strict' \
        /etc/systemd/system/noid-wan-strict-scan-profiles.service 2>/dev/null \
   || ! grep -qxF 'ProtectSystem=strict' \
        /etc/systemd/system/noid-wan-strict-endpoint-expiry.service 2>/dev/null; then
    log "  FAIL: Module 06 runtime lock/service write boundary is incomplete"
    fail=$((fail + 1))
fi
if ! grep -q 'oifname @physical_ifaces meta nfproto ipv4' \
        /etc/nftables.d/noid-wan-strict.nft 2>/dev/null \
   || ! grep -q 'oifname @physical_ifaces meta nfproto ipv6' \
        /etc/nftables.d/noid-wan-strict.nft 2>/dev/null; then
    log "  FAIL: Module 06 WAN final drops are not hardware-interface scoped"
    fail=$((fail + 1))
fi
if grep -q ' log prefix ' /etc/nftables.d/noid-wan-strict.nft 2>/dev/null; then
    log "  FAIL: Module 06 logs blocked destination metadata"
    fail=$((fail + 1))
fi
if [ ! -x /usr/local/libexec/noid-wan-strict-endpoints ] \
   || ! grep -qF 'NM.Client.new(None)' \
        /usr/local/libexec/noid-wan-strict-endpoints 2>/dev/null \
   || ! grep -qF 'def nft_json(*arguments: str) -> list[object]:' \
        /usr/local/libexec/noid-wan-strict-endpoints 2>/dev/null \
   || ! grep -qF 'def derive_runtime_mode() -> str:' \
        /usr/local/libexec/noid-wan-strict-endpoints 2>/dev/null \
   || ! grep -qF 'raise fail("WAN strict is explicitly disabled")' \
        /usr/local/libexec/noid-wan-strict-endpoints 2>/dev/null \
   || grep -qE 'getent|awk -F=.*endpoint' \
        /usr/local/sbin/noid-wan-strict-scan-profiles.sh \
        /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin 2>/dev/null; then
    log "  FAIL: Module 06 endpoint authority is not the installed libnm reconciler"
    fail=$((fail + 1))
fi
if ! grep -qF 'PROFILE_PATH=noid-wan-strict-scan-profiles.path' \
        /usr/local/sbin/noid-toggle-wan-strict 2>/dev/null \
   || ! grep -qF 'EXPIRY_TIMER=noid-wan-strict-endpoint-expiry.timer' \
        /usr/local/sbin/noid-toggle-wan-strict 2>/dev/null \
   || ! grep -qF 'PROFILE_SERVICE=noid-wan-strict-scan-profiles.service' \
        /usr/local/sbin/noid-toggle-wan-strict 2>/dev/null \
   || ! grep -qF 'EXPIRY_SERVICE=noid-wan-strict-endpoint-expiry.service' \
        /usr/local/sbin/noid-toggle-wan-strict 2>/dev/null \
   || ! grep -qF 'AUTORESUME_SERVICE=noid-wan-strict-autoresume.service' \
        /usr/local/sbin/noid-toggle-wan-strict 2>/dev/null \
   || ! grep -qF 'quiesce_auxiliary_units' \
        /usr/local/sbin/noid-toggle-wan-strict 2>/dev/null; then
    log "  FAIL: Module 06 opt-out leaves background lifecycle units enabled"
    fail=$((fail + 1))
fi
if grep -qF 'nft delete table inet noid_wan_strict' \
        /usr/local/sbin/noid-wan-strict-bootstrap.sh 2>/dev/null \
   || ! grep -qF 'destroy table inet noid_wan_strict' \
        /usr/local/libexec/noid-wan-strict-endpoints 2>/dev/null \
   || ! grep -qF '"pause", "resume", "disable", "enable", "publish-status"' \
        /usr/local/libexec/noid-wan-strict-endpoints 2>/dev/null; then
    log "  FAIL: Module 06 WAN lifecycle is not one atomic locked controller"
    fail=$((fail + 1))
fi
if grep -qF 'ships an always-active' \
        /usr/local/libexec/noid-wan-strict-endpoints \
        /usr/share/doc/noid-privacy/wan-egress-strict.md 2>/dev/null \
   || ! grep -qF 'not described as malware-proof' \
        /usr/share/doc/noid-privacy/wan-egress-strict.md 2>/dev/null \
   || ! grep -qF 'CAP_NET_RAW' \
        /usr/share/doc/noid-privacy/wan-egress-strict.md 2>/dev/null \
   || ! grep -qF 'no automatic wall-clock expiry' \
        /usr/share/doc/noid-privacy/wan-egress-strict.md 2>/dev/null; then
    log "  FAIL: Module 06 WAN threat/onboarding boundary is overstated or incomplete"
    fail=$((fail + 1))
fi
if ! grep -qF 'type ipv4_addr . inet_proto . inet_service' \
        /etc/nftables.d/noid-wan-strict.nft 2>/dev/null \
   || ! grep -qF 'ip daddr . meta l4proto . th dport @vpn_endpoints_v4' \
        /etc/nftables.d/noid-wan-strict.nft 2>/dev/null \
   || ! grep -qF 'vpn_candidates_v4' \
        /etc/nftables.d/noid-wan-strict.nft 2>/dev/null \
   || ! grep -qF 'timeout 2m' \
        /etc/nftables.d/noid-wan-strict.nft 2>/dev/null; then
    log "  FAIL: Module 06 VPN endpoint exception is broader than address+transport+port"
    fail=$((fail + 1))
fi

# Module 07 — IPv6 bundle
for contract in \
    644:/etc/gai.conf \
    640:/etc/sysctl.d/98-privacy-network.conf \
    644:/etc/tmpfiles.d/noid-wan-ipv6.conf \
    644:/etc/systemd/system/noid-wan-ipv6-disable-firstboot.service \
    755:/usr/local/sbin/noid-wan-ipv6-disable.sh \
    700:/etc/NetworkManager/dispatcher.d/55-wan-ipv6-refresh \
    644:/usr/share/doc/noid-privacy/07-physical-ipv6-boundary.md; do
    expected_mode=${contract%%:*}
    f=${contract#*:}
    if [ ! -f "$f" ] || [ -L "$f" ] || \
       [ "$(stat -c '%u:%g:%a:%h' "$f" 2>/dev/null || true)" != \
         "0:0:${expected_mode}:1" ]; then
        log "  FAIL: Module 07 artifact missing or unsafe: $f"
        fail=$((fail + 1))
    fi
done
if grep -Eq '^[[:space:]]*net\.ipv4\.tcp_timestamps[[:space:]]*=' \
        /etc/sysctl.d/98-privacy-network.conf 2>/dev/null \
   || ! grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*0([[:space:]]*(#.*)?)?$' \
        /etc/sysctl.d/98-privacy-network.conf 2>/dev/null \
   || [ -e /etc/sysctl.d/99-privacy-network.conf ] \
   || ! grep -qxF 'scopev4 ::ffff:0.0.0.0/96       14' /etc/gai.conf 2>/dev/null \
   || grep -Eq '^[[:space:]]*scopev4[[:space:]]+::/96[[:space:]]+14([[:space:]]*(#.*)?)?$' \
        /etc/gai.conf 2>/dev/null; then
    log "  FAIL: Module 07 sysctl or gai.conf policy is incomplete/invalid"
    fail=$((fail + 1))
fi
if [ -e /usr/share/doc/noid-privacy/07-ipv6-reactivate.md ] \
   || grep -Eq 'sudo (nmcli connection modify.*ipv6\.method auto|sysctl -w.*disable_ipv6=0|systemctl disable.*noid-wan-ipv6)' \
        /usr/share/doc/noid-privacy/07-physical-ipv6-boundary.md 2>/dev/null \
   || ! grep -qF 'does not support physical-WAN IPv6 as one coherent' \
        /usr/share/doc/noid-privacy/07-physical-ipv6-boundary.md 2>/dev/null; then
    log "  FAIL: Module 07 publishes a partial or overstated physical IPv6 mode"
    fail=$((fail + 1))
fi
if [ -e /var/lib/noid-privacy/wan-ipv6-off.state ] \
   || [ ! -L /etc/NetworkManager/dispatcher.d/pre-up.d/55-wan-ipv6-refresh ] \
   || [ "$(readlink /etc/NetworkManager/dispatcher.d/pre-up.d/55-wan-ipv6-refresh 2>/dev/null || true)" != ../55-wan-ipv6-refresh ] \
   || ! grep -qF 'flock -x 9' /usr/local/sbin/noid-wan-ipv6-disable.sh 2>/dev/null \
   || ! grep -qF 'NOID_WAN_IPV6_STATUS_V1' /usr/local/sbin/noid-wan-ipv6-disable.sh 2>/dev/null \
   || ! grep -qF 'existing sysctl policy contains unexpected active directives' \
        /usr/local/sbin/noid-wan-ipv6-disable.sh 2>/dev/null \
   || grep -qF 'case "$iface" in' \
        /usr/local/sbin/noid-wan-ipv6-disable.sh 2>/dev/null \
   || ! grep -qF 'mv -fT "$STAGED_FILE" "$SYSCTL_FILE"' \
        /usr/local/sbin/noid-wan-ipv6-disable.sh 2>/dev/null \
   || ! grep -qF 'exit "$rc"' \
        /etc/NetworkManager/dispatcher.d/55-wan-ipv6-refresh 2>/dev/null; then
    log "  FAIL: Module 07 IPv6-off transition is not one locked pre-activation policy"
    fail=$((fail + 1))
fi
wan_ipv6_unit=/etc/systemd/system/noid-wan-ipv6-disable-firstboot.service
if ! grep -qxF 'f /run/lock/noid-wan-ipv6.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-wan-ipv6.conf 2>/dev/null \
   || ! grep -qxF 'CapabilityBoundingSet=CAP_NET_ADMIN' \
        "$wan_ipv6_unit" 2>/dev/null \
   || ! grep -qxF 'UMask=0077' "$wan_ipv6_unit" 2>/dev/null \
   || ! grep -qxF 'ProtectKernelModules=yes' "$wan_ipv6_unit" 2>/dev/null \
   || ! grep -qxF \
        'ReadWritePaths=/etc/sysctl.d /run/noid-privacy /run/lock/noid-wan-ipv6.lock' \
        "$wan_ipv6_unit" 2>/dev/null \
   || ! grep -qxF \
        'ExecStart=/usr/local/sbin/noid-wan-ipv6-disable.sh --defer-missing-network' \
        "$wan_ipv6_unit" 2>/dev/null \
   || grep -qF ' /run/systemd' "$wan_ipv6_unit" 2>/dev/null; then
    log "  FAIL: Module 07 runtime lock or firstboot sandbox is over-broad"
    fail=$((fail + 1))
fi

# Module 08 — service masks + coredump + hardening drop-ins + dconf gnome-software
# bluetooth.service NOT masked (M08 BT-pivot: Type=dbus disable was no-op;
# replaced with rfkill-block + unmask). Verified via tests/08-mask-list-structural.sh
# negative-regression-check (bluetooth.service must be absent from MASK_LIST).

# Existing-user agent-policy adapters are also owned by Module 08.
[ -x /usr/libexec/noid-agent-policy-adapters ] \
    && [ "$(stat -c '%U:%G:%a' /usr/libexec/noid-agent-policy-adapters)" = root:root:755 ] \
    || { log "  FAIL: Module 08 existing-user agent-policy adapter helper invalid"; fail=$((fail + 1)); }
[ -f /usr/lib/systemd/user/noid-agent-policy-adapters.service ] \
    && [ ! -L /usr/lib/systemd/user/noid-agent-policy-adapters.service ] \
    && [ "$(stat -c '%U:%G:%a' /usr/lib/systemd/user/noid-agent-policy-adapters.service)" = root:root:644 ] \
    || { log "  FAIL: Module 08 existing-user agent-policy adapter unit invalid"; fail=$((fail + 1)); }
[ "$(readlink /etc/systemd/user/default.target.wants/noid-agent-policy-adapters.service 2>/dev/null || true)" = /usr/lib/systemd/user/noid-agent-policy-adapters.service ] \
    || { log "  FAIL: Module 08 existing-user agent-policy adapter global enablement invalid"; fail=$((fail + 1)); }
grep -qF 'validate_state()' /usr/libexec/noid-agent-policy-adapters \
    && ! grep -qF 'ConditionPathExists=!%h/.local/state/noid-privacy/agent-policy-adapters.done' \
        /usr/lib/systemd/user/noid-agent-policy-adapters.service \
    && grep -qxF 'RestrictAddressFamilies=AF_UNIX' \
        /usr/lib/systemd/user/noid-agent-policy-adapters.service \
    && ! grep -q '^IPAddressDeny=' \
        /usr/lib/systemd/user/noid-agent-policy-adapters.service \
    || { log "  FAIL: Module 08 existing-user agent-policy one-shot validation boundary invalid"; fail=$((fail + 1)); }

for unit in atd.service ModemManager.service \
            systemd-homed.service systemd-oomd.service systemd-coredump.socket; do
    if [ ! -L "/etc/systemd/system/$unit" ] || \
       [ "$(readlink "/etc/systemd/system/$unit")" != "/dev/null" ]; then
        log "  FAIL: Module 08 mask missing: $unit"
        fail=$((fail + 1))
    fi
done

for f in /etc/systemd/coredump.conf.d/99-noid-disable.conf \
         /etc/systemd/system/firewalld.service.d/99-noid-hardening.conf \
         /etc/dconf/db/distro.d/00-noid-gnome-software \
         /etc/dconf/db/distro.d/locks/00-noid-gnome-software; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 08 missing: $f"
        fail=$((fail + 1))
    fi
done
iscsi_dispatcher=/etc/NetworkManager/dispatcher.d/04-iscsi
if [ ! -f "$iscsi_dispatcher" ] || [ -L "$iscsi_dispatcher" ] \
   || [ "$(stat -c '%U:%G:%a' "$iscsi_dispatcher" 2>/dev/null || true)" != root:root:755 ] \
   || ! bash -n "$iscsi_dispatcher" 2>/dev/null \
   || ! grep -qxF 'exit 0' "$iscsi_dispatcher" \
   || [ -e /etc/tmpfiles.d/noid-disable-iscsi-dispatcher.conf ]; then
    log "  FAIL: Module 08 native iSCSI dispatcher precedence contract invalid"
    fail=$((fail + 1))
fi
unset iscsi_dispatcher
# Module 08 — dnf-makecache timer mask (privacy fix)
# At least one of {dnf,dnf5}-makecache.timer must be masked (which one exists
# depends on dnf version — mask both as defense-in-depth).
dnf_makecache_masked=0
for unit in dnf-makecache.timer dnf5-makecache.timer; do
    path="/etc/systemd/system/$unit"
    if [ -L "$path" ] && [ "$(readlink "$path" 2>/dev/null)" = "/dev/null" ]; then
        dnf_makecache_masked=$((dnf_makecache_masked + 1))
    fi
done
if [ "$dnf_makecache_masked" -eq 0 ]; then
    log "  FAIL: Module 08 dnf-makecache.timer mask missing (neither dnf- nor dnf5- variant masked)"
    fail=$((fail + 1))
fi

# Module 08 — Step 1b TimeoutStopSec=15s drop-ins
for f in /etc/systemd/system/dnf5daemon-server.service.d/10-noid-shutdown-timeout.conf \
         /etc/systemd/system/systemd-resolved.service.d/10-noid-shutdown-timeout.conf; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 08 shutdown-timeout drop-in missing: $f"
        fail=$((fail + 1))
    elif ! grep -q '^TimeoutStopSec=15s' "$f"; then
        log "  FAIL: Module 08 $f does not have TimeoutStopSec=15s (Step 1b middle-ground)"
        fail=$((fail + 1))
    fi
done
# Module 08 — Step 1e wireplumber bluez5 disable
# grep made whitespace-tolerant — the M08 template can
# evolve indentation without breaking this verify. The directive itself
# (hardware.bluetooth = disabled) is what matters, not the leading spaces.
if [ ! -f /etc/wireplumber/wireplumber.conf.d/50-noid-disable-bluez.conf ]; then
    log "  FAIL: Module 08 Step 1e wireplumber bluez5 disable file missing"
    fail=$((fail + 1))
elif ! grep -qE '^\s*hardware\.bluetooth\s*=\s*disabled\b' /etc/wireplumber/wireplumber.conf.d/50-noid-disable-bluez.conf; then
    log "  FAIL: Module 08 wireplumber bluez5 disable directive missing (hardware.bluetooth=disabled)"
    fail=$((fail + 1))
fi
# Module 08 — Bluetooth default-OFF persistence (udev rfkill-enforcer +
# apply-default script). This is the mechanism that survives cold boot; the
# install-time rfkill block does not persist into the booted system.
for f in /usr/local/sbin/noid-bluetooth-apply-default \
         /etc/udev/rules.d/99-zz-noid-bluetooth-default.rules; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 08 BT default-OFF mechanism missing: $f"
        fail=$((fail + 1))
    fi
done
if [ -f /etc/udev/rules.d/99-zz-noid-bluetooth-default.rules ] && \
   ! grep -q 'noid-bluetooth-apply-default' /etc/udev/rules.d/99-zz-noid-bluetooth-default.rules; then
    log "  FAIL: Module 08 BT rfkill-enforcer udev rule malformed"
    fail=$((fail + 1))
fi

# Module 08 — Step 1e wireplumber dir mode (must be 0755 for non-root stat)
wp_dir_mode=$(stat -c '%a' /etc/wireplumber/wireplumber.conf.d 2>/dev/null || echo "")
if [ "$wp_dir_mode" != "755" ]; then
    log "  FAIL: Module 08 /etc/wireplumber/wireplumber.conf.d mode is '$wp_dir_mode', expected 755 (Welcome dialog status check breaks at 0750)"
    fail=$((fail + 1))
fi

# Module 08 — Step 1e wireplumber bluez5 template (single source-of-truth)
if [ ! -f /usr/share/doc/noid-privacy/wireplumber-disable-bluez.conf ]; then
    log "  FAIL: Module 08 wireplumber-bluez template missing at /usr/share/doc/noid-privacy/"
    fail=$((fail + 1))
fi

# Module 08 — Step 1f Privacy Toggle Infrastructure
# 1f.1 + 1f.2: toggle CLIs
for f in /usr/local/sbin/noid-toggle-bluetooth /usr/local/sbin/noid-toggle-location; do
    if [ ! -x "$f" ]; then
        log "  FAIL: Module 08 Step 1f toggle CLI missing or not executable: $f"
        fail=$((fail + 1))
    fi
done
# 1f.3: polkit rule
if [ ! -f /etc/polkit-1/rules.d/60-noid-toggle-privacy-services.rules ]; then
    log "  FAIL: Module 08 Step 1f polkit rule missing"
    fail=$((fail + 1))
elif ! grep -qF 'return polkit.Result.AUTH_ADMIN;' /etc/polkit-1/rules.d/60-noid-toggle-privacy-services.rules; then
    log "  FAIL: Module 08 polkit rule does not pin uncached AUTH_ADMIN"
    fail=$((fail + 1))
elif grep -qF 'return polkit.Result.AUTH_ADMIN_KEEP;' /etc/polkit-1/rules.d/60-noid-toggle-privacy-services.rules; then
    log "  FAIL: Module 08 polkit rule retains unsafe generic-pkexec authorization"
    fail=$((fail + 1))
fi
# 1f.4: only Bluetooth uses a durable flag. Location's sole user-choice source
# is org.gnome.system.location.enabled; a stale flag would contradict it.
if [ ! -f /var/lib/noid-privacy/bluetooth-disabled.flag ]; then
    log "  FAIL: Module 08 Bluetooth privacy-default flag missing"
    fail=$((fail + 1))
fi
if [ -e /var/lib/noid-privacy/location-disabled.flag ]; then
    log "  FAIL: obsolete Location flag exists; gsettings must remain authoritative"
    fail=$((fail + 1))
fi

# Module 09 — SSH client hardening + server opt-in template
if [ ! -f /etc/ssh/ssh_config.d/99-noid-hardening.conf ]; then
    log "  FAIL: Module 09 missing: /etc/ssh/ssh_config.d/99-noid-hardening.conf"
    fail=$((fail + 1))
fi
for f in /etc/ssh/sshd_config.d/01-noid-hardening.conf \
         /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf \
         /usr/share/doc/noid-privacy/ssh-server-opt-in.md \
         /usr/share/doc/noid-privacy/ssh-client-hardening.md; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 09 missing: $f"
        fail=$((fail + 1))
    fi
done
for ssh_meta in \
    /etc/ssh/ssh_config.d:root:root:755 \
    /etc/ssh/ssh_config.d/99-noid-hardening.conf:root:root:644 \
    /etc/ssh/sshd_config.d:root:root:700 \
    /etc/ssh/sshd_config.d/01-noid-hardening.conf:root:root:600 \
    /usr/share/doc/noid-privacy/ssh-server-opt-in:root:root:755 \
    /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf:root:root:644 \
    /usr/share/doc/noid-privacy/ssh-server-opt-in.md:root:root:644 \
    /usr/share/doc/noid-privacy/ssh-client-hardening.md:root:root:644; do
    ssh_path=${ssh_meta%%:*}
    ssh_expected=${ssh_meta#*:}
    if [ -L "$ssh_path" ] \
       || [ "$(stat -Lc '%U:%G:%a' "$ssh_path" 2>/dev/null || true)" != "$ssh_expected" ]; then
        log "  FAIL: Module 09 SSH path is symlinked or has wrong metadata: $ssh_path"
        fail=$((fail + 1))
    fi
done
for f in /etc/ssh/ssh_config.d/99-noid-hardening.conf \
         /etc/ssh/sshd_config.d/01-noid-hardening.conf \
         /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf; do
    if ! grep -qF 'sk-ssh-ed25519@openssh.com' "$f" 2>/dev/null \
       || ! grep -qF 'sk-ssh-ed25519-cert-v01@openssh.com' "$f" 2>/dev/null; then
        log "  FAIL: Module 09 FIDO Ed25519 signature/certificate parity missing: $f"
        fail=$((fail + 1))
    fi
done
for f in /etc/ssh/sshd_config.d/01-noid-hardening.conf \
         /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf; do
    if ! grep -qxF 'PubkeyAuthOptions touch-required' "$f" 2>/dev/null; then
        log "  FAIL: Module 09 FIDO physical-presence policy missing: $f"
        fail=$((fail + 1))
    fi
done
for f in /etc/ssh/sshd_config.d/01-noid-hardening.conf \
         /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf; do
    for ssh_policy in \
        'AuthenticationMethods publickey' \
        'StrictModes yes' \
        'HostbasedAuthentication no' \
        'AllowStreamLocalForwarding no' \
        'DisableForwarding yes' \
        'Compression no'; do
        if ! grep -qxF "$ssh_policy" "$f" 2>/dev/null; then
            log "  FAIL: Module 09 closed server policy missing ($ssh_policy): $f"
            fail=$((fail + 1))
        fi
    done
done
if ! grep -qxF \
    '    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512' \
    /etc/ssh/ssh_config.d/99-noid-hardening.conf 2>/dev/null; then
    log "  FAIL: Module 09 client does not prefer reviewed host certificates"
    fail=$((fail + 1))
fi
if command -v sshd >/dev/null 2>&1 \
   || find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key' -print -quit 2>/dev/null \
        | grep -q .; then
    log "  FAIL: Module 09 client-only image contains sshd or a private host-key path"
    fail=$((fail + 1))
fi
if [ -e /etc/ssh/moduli ]; then
    moduli_owner=$(rpm -qf --qf '%{NAME}\n' /etc/ssh/moduli \
        2>/dev/null || true)
    moduli_verify=$(rpm -Vf /etc/ssh/moduli 2>/dev/null || true)
    if [ "$moduli_owner" != openssh ] \
       || printf '%s\n' "$moduli_verify" \
            | grep -qE '(^|[[:space:]])/etc/ssh/moduli$'; then
        log "  FAIL: Module 09 changed RPM-owned /etc/ssh/moduli despite closed non-DH-GEX policy"
        fail=$((fail + 1))
    fi
fi
SSH_OPT_IN_GUIDE=/usr/share/doc/noid-privacy/ssh-server-opt-in.md
for required in \
    'ssh-copy-id` cannot bootstrap this flow' \
    'sudo mv -fT -- "$AUTH_TMP" "$AUTH_KEYS"' \
    'sudo mv -fT -- "$AUTH_RESTORE" "$AUTH_KEYS"' \
    'test "$(sudo stat -Lc '\''%u:%g:%a'\'' -- "$CONFIG")" = 0:0:600' \
    'if [ "$SSH_PORT" -ne 22 ]; then' \
    'sudo systemctl mask sshd.socket sshd-unix-local.socket' \
    'sudo sshd -T -C' \
    'sudo noid-lan-allow --add "$CLIENT_IP" --direction inbound' \
    '--protocol tcp --ports "$SSH_PORT" --temp 30' \
    '-p "$SSH_PORT" "${SSH_USER}@192.168.1.10"' \
    'sudo systemctl start sshd.service' \
    'sudo systemctl enable sshd.service' \
    'sudo systemctl disable --now sshd.service' \
    'WAN exposure is outside this workflow' \
    'Calendar-only rotation'; do
    if ! grep -qF -- "$required" "$SSH_OPT_IN_GUIDE" 2>/dev/null; then
        log "  FAIL: Module 09 lockout-safe opt-in transaction missing: $required"
        fail=$((fail + 1))
    fi
done
if grep -qF 'systemctl unmask sshd-unix-local.socket' "$SSH_OPT_IN_GUIDE" 2>/dev/null \
   || grep -qE 'PasswordAuthentication yes|KbdInteractiveAuthentication yes' \
        "$SSH_OPT_IN_GUIDE" 2>/dev/null \
   || grep -qF 'KexAlgorithms +diffie-hellman-group14-sha256' \
        /usr/share/doc/noid-privacy/ssh-client-hardening.md 2>/dev/null; then
    log "  FAIL: Module 09 opt-in guide weakens bootstrap auth or unmasks the extra socket"
    fail=$((fail + 1))
fi
SSH_CLIENT_GUIDE=/usr/share/doc/noid-privacy/ssh-client-hardening.md
for required in \
    'ordinary hostname A/AAAA resolution still occurs' \
    'gives up a possible DNSSEC-authenticated SSHFP' \
    'authenticated out-of-band value before typing `yes`' \
    'but similar-looking RandomArt' \
    'is not unambiguous proof' \
    'rm -f -- ~/.ssh/known_hosts.old' \
    'it is **not** a secure-erasure claim' \
    'expected `/home` is Btrfs'; do
    if ! grep -qF -- "$required" "$SSH_CLIENT_GUIDE" 2>/dev/null; then
        log "  FAIL: Module 09 mechanism-accurate SSH client guidance missing: $required"
        fail=$((fail + 1))
    fi
done
if grep -qE 'shred[[:space:]]+-u|prevents passive DNS-leak|would indicate MITM' \
        "$SSH_CLIENT_GUIDE" 2>/dev/null; then
    log "  FAIL: Module 09 SSH client guide overclaims DNS, visual proof or secure deletion"
    fail=$((fail + 1))
fi

# Module 10 — PAM + logind + sudo + core dump + native permission policy
for f in /etc/security/faillock.conf \
         /etc/security/pwquality.conf \
         /etc/security/pwhistory.conf \
         /etc/security/opasswd \
         /etc/security/access.conf \
         /etc/security/pam_env-sudo.conf \
         /etc/pam.d/sudo \
         /etc/sudoers.d/99-noid-hardening \
         /etc/sudoers.d/99-noid-no-fqdn \
         /etc/systemd/system.conf.d/50-coredump.conf \
         /etc/systemd/logind.conf.d/99-noid-hardening.conf \
         /etc/profile.d/98-noid-bash-history.sh \
         /usr/local/libexec/noid-bash-history-compact \
         /usr/local/bin/noid-toggle-bash-history \
         /usr/share/doc/noid-privacy/10-bash-history.md \
         /etc/skel/.gnupg/gpg.conf \
         /etc/tmpfiles.d/90-noid-permission-policy.conf \
         /etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions; do
         # logind drop-in RE-ADDED to check list —
         # live-test confirmed it works on F44 systemd 259.5.
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 10 missing: $f"
        fail=$((fail + 1))
    fi
done
for obsolete in /usr/local/sbin/noid-suid-harden.sh \
                /etc/systemd/system/noid-suid-harden.service \
                /etc/systemd/system/noid-suid-harden.timer; do
    if [ -e "$obsolete" ] || [ -L "$obsolete" ]; then
        log "  FAIL: Module 10 obsolete periodic permission mutator present: $obsolete"
        fail=$((fail + 1))
    fi
done
for permission_spec in \
    '/usr/bin/chfn|711|util-linux' \
    '/usr/bin/chsh|711|util-linux' \
    '/usr/bin/gpasswd|755|shadow-utils' \
    '/usr/bin/newgrp|755|shadow-utils' \
    '/usr/bin/fusermount-glusterfs|755|glusterfs-fuse' \
    '/usr/bin/chage|4755|shadow-utils' \
    '/usr/bin/pam_timestamp_check|4755|pam' \
    '/usr/bin/userhelper|4711|usermode' \
    '/usr/libexec/libgtop_server2|4755|libgtop2'; do
    IFS='|' read -r permission_path permission_mode permission_pkg <<< "$permission_spec"
    permission_owner=$(rpm -qf --qf '%{NAME}' "$permission_path" 2>/dev/null || true)
    permission_actual=$(stat -c '%a' "$permission_path" 2>/dev/null || true)
    if [ ! -f "$permission_path" ] || [ -L "$permission_path" ] || \
       [ "$permission_owner" != "$permission_pkg" ] || \
       [ "$permission_actual" != "$permission_mode" ]; then
        log "  FAIL: Module 10 permission contract invalid: $permission_path owner=$permission_owner mode=$permission_actual"
        fail=$((fail + 1))
    fi
done
unset obsolete permission_spec permission_path permission_mode permission_pkg \
    permission_owner permission_actual
if [ "$(stat -c '%U:%G:%a' /etc/tmpfiles.d/90-noid-permission-policy.conf 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(stat -c '%U:%G:%a' /etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(grep -c '^post_transaction:' /etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions 2>/dev/null || true)" -ne 5 ]; then
    log "  FAIL: Module 10 native permission policy/action metadata or trigger count invalid"
    fail=$((fail + 1))
fi
for permission_pkg in util-linux shadow-utils glusterfs-fuse cronie sudo; do
    if ! grep -qxF \
        "post_transaction:${permission_pkg}:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/bin/systemd-tmpfiles\\ --create\\ /etc/tmpfiles.d/90-noid-permission-policy.conf\\ >/dev/null" \
        /etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions 2>/dev/null; then
        log "  FAIL: Module 10 exact dnf5 permission trigger missing: $permission_pkg"
        fail=$((fail + 1))
    fi
done
unset permission_pkg
for permission_dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
                      /etc/cron.monthly /etc/cron.d /etc/sudoers.d; do
    if [ -d "$permission_dir" ] && \
       [ "$(stat -c '%U:%G:%a' "$permission_dir" 2>/dev/null || true)" != root:root:700 ]; then
        log "  FAIL: Module 10 root-only policy directory invalid: $permission_dir"
        fail=$((fail + 1))
    fi
done
unset permission_dir
if grep -qE '^[[:space:]]*InhibitorsMax=' \
        /etc/systemd/logind.conf \
        /etc/systemd/logind.conf.d/*.conf 2>/dev/null; then
    log "  FAIL: Module 10 overrides systemd's maintained inhibitor capacity"
    fail=$((fail + 1))
fi
if grep -qE '^[[:space:]]*(IdleAction(Sec)?|Handle(Power|Suspend|Hibernate|Lid)[A-Za-z]*)=' \
        /etc/systemd/logind.conf \
        /etc/systemd/logind.conf.d/*.conf 2>/dev/null; then
    log "  FAIL: image overrides GNOME/vendor idle, key or lid ownership"
    fail=$((fail + 1))
fi
m10_login_defs_ok=1
while read -r m10_login_defs_key m10_login_defs_value; do
    if [ "$(grep -Ec "^${m10_login_defs_key}[[:space:]]+${m10_login_defs_value}$" \
            /etc/login.defs 2>/dev/null || true)" -ne 1 ]; then
        m10_login_defs_ok=0
    fi
done <<'M10_LOGIN_DEFS_EOF'
LOG_OK_LOGINS no
LOG_UNKFAIL_ENAB no
FAIL_DELAY 4
UMASK 022
HOME_MODE 0700
CREATE_HOME yes
ENCRYPT_METHOD YESCRYPT
PASS_MAX_DAYS 99999
M10_LOGIN_DEFS_EOF
if [ "$m10_login_defs_ok" -ne 1 ]; then
    log "  FAIL: Module 10 login.defs privacy/local-account policy is not exact and unique"
    fail=$((fail + 1))
fi
unset m10_login_defs_key m10_login_defs_ok m10_login_defs_value
if ! grep -qxF 'Defaults !fqdn' /etc/sudoers.d/99-noid-no-fqdn 2>/dev/null; then
    log "  FAIL: Module 10 defensive sudo !fqdn state missing"
    fail=$((fail + 1))
fi
for m10_dnf_command in /usr/bin/dnf /usr/bin/dnf5; do
    if ! grep -qxF \
            "Defaults!${m10_dnf_command} umask=0022, umask_override" \
            /etc/sudoers.d/99-noid-hardening 2>/dev/null; then
        log "  FAIL: Module 10 command-scoped DNF umask missing: $m10_dnf_command"
        fail=$((fail + 1))
    fi
done
unset m10_dnf_command
if ! grep -qF 'case $- in' /etc/profile.d/99-noid-security-umask.sh 2>/dev/null \
   || ! grep -qF '*i*) umask 027 ;;' /etc/profile.d/99-noid-security-umask.sh 2>/dev/null \
   || grep -qxF 'umask 027' /etc/profile.d/99-noid-security-umask.sh 2>/dev/null; then
    log "  FAIL: Module 10 interactive-only umask guard invalid"
    fail=$((fail + 1))
fi
M10_FC_PREFIX_LITERAL=$(cat <<'M10_FC_PREFIX_EOF'
[[ "${history_value:0:2}" == $'\''\t '\'' ]] || exit 2
M10_FC_PREFIX_EOF
)
if [ ! -x /usr/local/libexec/noid-bash-history-compact ] \
   || [ ! -x /usr/local/bin/noid-toggle-bash-history ] \
   || ! bash -n /etc/profile.d/98-noid-bash-history.sh \
        /usr/local/libexec/noid-bash-history-compact \
        /usr/local/bin/noid-toggle-bash-history 2>/dev/null \
   || ! grep -qF 'flock -x "$lock_fd"' /etc/profile.d/98-noid-bash-history.sh 2>/dev/null \
   || ! grep -qF 'builtin history -a' /etc/profile.d/98-noid-bash-history.sh 2>/dev/null \
   || ! grep -qF '/usr/local/libexec/noid-bash-history-compact "$history_file" 100' \
        /etc/profile.d/98-noid-bash-history.sh 2>/dev/null \
   || ! grep -qF 'HISTFILESIZE=-1' /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'unset HISTFILE HISTSIZE HISTFILESIZE HISTTIMEFORMAT' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF '[[ "$history_line" =~ ^#[0-9]+$ ]]' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'if (( timestamp_framing == 1 )); then' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF "printf '#0\\n' > \"\$parse_tmp\"" \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF '"$history_dir/.${history_base}.noid-parse."*' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF '[[ -f "$stale_tmp" && ! -L "$stale_tmp" && -O "$stale_tmp" ]]' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'HISTSIZE=-1 HISTFILESIZE=-1' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'declare -a retained_reversed=()' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'for ((history_offset=1;' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'builtin fc -ln -- "-${history_offset}" "-${history_offset}"' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF "$M10_FC_PREFIX_LITERAL" \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'if [[ "$history_value" == "$retained_value" ]]; then' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF '(( duplicate == 1 )) || retained_reversed+=("$history_value")' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'builtin history -s -- "${retained_reversed[history_index]}"' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'builtin history -w "$1"' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'mv -fT -- "$tmp" "$history_file"' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || ! grep -qF 'rm -f -- "$parse_tmp"' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || grep -qF 'builtin history -p "!${history_index}"' \
        /usr/local/libexec/noid-bash-history-compact 2>/dev/null \
   || grep -qE 'unset[[:space:]]+PROMPT_COMMAND|PROMPT_COMMAND="history -a' \
        /etc/profile.d/98-noid-bash-history.sh \
        /usr/local/bin/noid-toggle-bash-history 2>/dev/null; then
    log "  FAIL: Module 10 locked/atomic Bash history contract invalid"
    fail=$((fail + 1))
fi
for m10_history_meta in \
    '/etc/profile.d/98-noid-bash-history.sh|root:root:644' \
    '/usr/local/libexec/noid-bash-history-compact|root:root:755' \
    '/usr/local/bin/noid-toggle-bash-history|root:root:755' \
    '/usr/share/doc/noid-privacy/10-bash-history.md|root:root:644'; do
    m10_history_path=${m10_history_meta%%|*}
    m10_history_expected=${m10_history_meta#*|}
    if [ "$(stat -c '%U:%G:%a' "$m10_history_path" 2>/dev/null || true)" != \
         "$m10_history_expected" ]; then
        log "  FAIL: Module 10 Bash history metadata invalid: $m10_history_path"
        fail=$((fail + 1))
    fi
done
unset m10_history_meta m10_history_path m10_history_expected

# Module 10 — GnuPG defaults inherited by newly created local users.
if [ ! -f /etc/skel/.gnupg/gpg.conf ] \
   || [ -L /etc/skel/.gnupg/gpg.conf ] \
   || [ "$(stat -c '%U:%G:%a:%h' /etc/skel/.gnupg/gpg.conf 2>/dev/null || true)" != root:root:600:1 ] \
   || [ "$(stat -c '%U:%G:%a' /etc/skel/.gnupg 2>/dev/null || true)" != root:root:700 ] \
   || [ "$(awk '!/^[[:space:]]*($|#)/ {count++} END {print count+0}' \
            /etc/skel/.gnupg/gpg.conf 2>/dev/null || true)" -ne 10 ]; then
    log "  FAIL: Module 10 GnuPG skel policy or metadata invalid"
    fail=$((fail + 1))
fi

# Module 10 — exact password policy and maintained Fedora hashing path.
if ! grep -qxF 'minlen = 15' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qxF 'minclass = 0' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qxF 'maxrepeat = 0' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qxF 'maxclassrepeat = 0' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qxF 'maxsequence = 0' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qxF 'dcredit = 0' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qxF 'ucredit = 0' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qxF 'lcredit = 0' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qxF 'ocredit = 0' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qE '^dictcheck = 1([[:space:]]|$)' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qE '^usercheck = 1([[:space:]]|$)' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qE '^gecoscheck = 1([[:space:]]|$)' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qxF 'enforcing = 1' /etc/security/pwquality.conf 2>/dev/null \
   || ! grep -qxF 'enforce_for_root' /etc/security/pwquality.conf 2>/dev/null; then
    log "  FAIL: Module 10 password length/composition/root policy invalid"
    fail=$((fail + 1))
fi
if [ "$(grep -Ec '^YESCRYPT_COST_FACTOR[[:space:]]+8$' \
        /etc/login.defs 2>/dev/null || true)" -ne 1 ]; then
    log "  FAIL: Module 10 native YESCRYPT cost 8 is not exact and unique"
    fail=$((fail + 1))
fi
m10_pwhistory_rules=$(
    awk '!/^[[:space:]]*($|#)/ {gsub(/[[:space:]]/, ""); print}' \
        /etc/security/pwhistory.conf 2>/dev/null || true
)
if [ "$m10_pwhistory_rules" != $'remember=10\nenforce_for_root' ] \
   || [ -L /etc/security/pwhistory.conf ] \
   || [ -L /etc/security/opasswd ] \
   || [ "$(stat -c '%U:%G:%a:%h' /etc/security/pwhistory.conf 2>/dev/null || true)" != root:root:644:1 ] \
   || [ "$(stat -c '%U:%G:%a:%h' /etc/security/opasswd 2>/dev/null || true)" != root:root:600:1 ]; then
    log "  FAIL: Module 10 password-history policy or backing-store metadata invalid"
    fail=$((fail + 1))
fi
unset m10_pwhistory_rules
m10_access_rules=$(
    awk '/^[[:space:]]*[+-]:/ {gsub(/[[:space:]]/, ""); print}' \
        /etc/security/access.conf 2>/dev/null || true
)
if [ "$m10_access_rules" != $'+:(wheel):ALL\n+:root:ALL\n-:ALL:ALL' ] \
   || [ -L /etc/security/access.conf ] \
   || [ "$(stat -c '%U:%G:%a:%h' /etc/security/access.conf 2>/dev/null || true)" != root:root:644:1 ]; then
    log "  FAIL: Module 10 pam_access policy or metadata invalid"
    fail=$((fail + 1))
fi
unset m10_access_rules
m10_sudo_pam=/etc/pam.d/sudo
m10_sudo_pam_env=/etc/security/pam_env-sudo.conf
m10_sudo_pam_line='session    optional     pam_env.so conffile=/etc/security/pam_env-sudo.conf readenv=0 user_readenv=0'
m10_sudo_pam_env_rules=$(
    awk '!/^[[:space:]]*($|#)/ {print}' "$m10_sudo_pam_env" 2>/dev/null || true
)
if [ ! -f "$m10_sudo_pam" ] || [ -L "$m10_sudo_pam" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$m10_sudo_pam" 2>/dev/null || true)" != \
        root:root:644:1 ] \
   || [ ! -f "$m10_sudo_pam_env" ] || [ -L "$m10_sudo_pam_env" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$m10_sudo_pam_env" 2>/dev/null || true)" != \
        root:root:644:1 ] \
   || [ "$m10_sudo_pam_env_rules" != \
        'XDG_SESSION_CLASS DEFAULT=none OVERRIDE=none' ] \
   || [ "$(grep -cFx "$m10_sudo_pam_line" "$m10_sudo_pam" 2>/dev/null || true)" -ne 1 ] \
   || [ "$(grep -Ec \
        '^session[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$' \
        "$m10_sudo_pam" 2>/dev/null || true)" -ne 1 ] \
   || [ "$(rpm -qf --qf '%{NAME}' "$m10_sudo_pam" 2>/dev/null || true)" != sudo ] \
   || ! awk -v env_line="$m10_sudo_pam_line" '
        $0 == env_line { env_nr=NR }
        /^session[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$/ {
            include_nr=NR
        }
        END { exit !(env_nr > 0 && include_nr > env_nr) }
   ' "$m10_sudo_pam"; then
    log "  FAIL: Module 10 sudo PAM non-login session contract invalid"
    fail=$((fail + 1))
fi
unset m10_sudo_pam m10_sudo_pam_env m10_sudo_pam_line \
    m10_sudo_pam_env_rules
M10_AUTHSELECT_EXPECTED='local with-silent-lastlog without-nullok with-faillock with-pwhistory with-pamaccess'
m10_authselect_raw=$(authselect current -r) || m10_authselect_raw=""
if ! authselect check >/dev/null \
   || [ "$m10_authselect_raw" != "$M10_AUTHSELECT_EXPECTED" ] \
   || [ -L /var/log/ks-10-authselect.err ] \
   || [ "$(stat -c '%U:%G:%a:%h' /var/log/ks-10-authselect.err 2>/dev/null || true)" != root:root:600:1 ]; then
    log "  FAIL: Module 10 exact five-feature authselect state or private evidence invalid"
    fail=$((fail + 1))
fi
unset M10_AUTHSELECT_EXPECTED m10_authselect_raw
for pam_file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    if ! grep -qE '^password[[:space:]]+.*pam_unix\.so[^#]*[[:space:]]yescrypt([[:space:]]|$)' "$pam_file" 2>/dev/null \
       || grep -qE '^password[[:space:]]+.*pam_unix\.so[^#]*[[:space:]]rounds=' "$pam_file" 2>/dev/null \
       || grep -qF 'pam_oddjob_mkhomedir.so' "$pam_file" 2>/dev/null; then
        log "  FAIL: Module 10 vendor yescrypt or self-contained PAM path invalid: $pam_file"
        fail=$((fail + 1))
    fi
done

# Module 10 — core dump Layer 5 (limits.conf)
if ! grep -qE "^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0" /etc/security/limits.conf 2>/dev/null; then
    log "  FAIL: Module 10 limits.conf missing '* hard core 0' (Coredump Layer 5)"
    fail=$((fail + 1))
fi

# Module 10 — sudo timestamp_timeout=3 syntax validation
if [ -f /etc/sudoers.d/99-noid-hardening ]; then
    if ! visudo -cf /etc/sudoers.d/99-noid-hardening >/dev/null 2>&1; then
        log "  FAIL: Module 10 /etc/sudoers.d/99-noid-hardening invalid sudoers syntax"
        fail=$((fail + 1))
    fi
fi

# Module 11 — chrony NTS
if [ ! -f /etc/chrony.conf ]; then
    log "  FAIL: Module 11 missing: /etc/chrony.conf"
    fail=$((fail + 1))
fi
if ! grep -q 'iburst nts' /etc/chrony.conf 2>/dev/null; then
    log "  FAIL: Module 11 /etc/chrony.conf has no NTS servers"
    fail=$((fail + 1))
fi
m11_source_manifest=/usr/share/doc/noid-privacy/11-nts-sources.tsv
if [ "$(stat -c '%U:%G:%a' "$m11_source_manifest" 2>/dev/null || true)" != \
     root:root:644 ] \
   || ! awk -F '\t' '
        NR == 1 {
            if ($0 != "hostname\toperator\tcountry\toperator_status\toperator_source\treviewed_on") exit 1
            next
        }
        NR == 2 { review_date=$6 }
        NF != 6 || $1 !~ /^[a-z0-9.-]+$/ || $2 !~ /^[A-Za-z-]+$/ ||
        $3 !~ /^(DE|SE|NL)$/ || $4 !~ /^(public-service|production)$/ ||
        $5 !~ /^https:\/\// || $6 !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/ ||
        $6 != review_date || seen[$1]++ { bad=1 }
        END { exit !(NR == 7 && review_date != "" && bad == 0) }
    ' "$m11_source_manifest" \
   || ! cmp -s \
        <(awk -F '\t' \
            'NR > 1 {print "server " $1 " iburst nts ipv4 maxpoll 11 offline"}' \
            "$m11_source_manifest") \
        <(grep '^server ' /etc/chrony.conf) \
   || grep -qE '^server ntppool[34]\.time\.nl ' /etc/chrony.conf; then
    log "  FAIL: Module 11 dated NTS operator manifest/config contract invalid"
    fail=$((fail + 1))
fi
if [ "$(stat -c '%U:%G:%a' /usr/local/sbin/noid-time-recovery 2>/dev/null || true)" != \
     "root:root:755" ] \
   || [ "$(stat -c '%U:%G:%a' /usr/share/doc/noid-privacy/11-time-recovery.md 2>/dev/null || true)" != \
      "root:root:644" ] \
   || ! bash -n /usr/local/sbin/noid-time-recovery 2>/dev/null \
   || grep -qE '^[[:space:]]*nocerttimecheck([[:space:]]|$)' /etc/chrony.conf 2>/dev/null \
   || ! grep -qF 'use a physical Linux VT such as /dev/tty3' \
        /usr/local/sbin/noid-time-recovery 2>/dev/null \
   || ! grep -qF 'candidate UTC predates the immutable image timestamp' \
        /usr/local/sbin/noid-time-recovery 2>/dev/null \
   || ! grep -qF 'candidate UTC exceeds the image-relative five-year recovery horizon' \
        /usr/local/sbin/noid-time-recovery 2>/dev/null; then
    log "  FAIL: Module 11 local-VT authenticated time-recovery boundary invalid"
    fail=$((fail + 1))
fi

# The NTS daemon uses Fedora's purpose-built restricted client as its sole
# sandbox owner. Keep both package-owned inputs byte-identical to the signed
# RPM payload, retain the vendor -F 2 filter, and bind timedated to this exact
# service so a later `timedatectl set-ntp true` cannot select the ordinary one.
rpm_payload_file_pristine() {
    local package=$1 path=$2 expected actual
    [ "$(rpm -q --qf '%{FILEDIGESTALGO}' "$package" 2>/dev/null || true)" = 8 ] \
        || return 1
    expected=$(rpm -q --qf '[%{FILENAMES}\t%{FILEDIGESTS}\n]' "$package" \
        2>/dev/null | awk -F '\t' -v target="$path" '
            $1 == target { count++; digest=$2 }
            END { if (count != 1 || digest == "") exit 1; print digest }
        ') || return 1
    actual=$(sha256sum -- "$path" 2>/dev/null) || return 1
    actual=${actual%% *}
    [ "$actual" = "$expected" ]
}

m11_native_fail=0
m11_restricted_unit=/usr/lib/systemd/system/chronyd-restricted.service
m11_provider_file=/etc/systemd/ntp-units.d/50-chronyd.list
m11_preset_file=/etc/systemd/system-preset/05-noid-chrony.preset
m11_offline_readiness_unit=/etc/systemd/system/noid-chrony-network-offline.service
m11_readiness_unit=/etc/systemd/system/noid-chrony-network-online.service
m11_readiness_helper=/usr/local/libexec/noid-network-readiness
if [ "$(rpm -qf --qf '%{NAME}\n' "$m11_restricted_unit" 2>/dev/null || true)" != chrony ] \
   || [ "$(stat -c '%U:%G:%a' "$m11_restricted_unit" 2>/dev/null || true)" != \
      root:root:644 ] \
   || ! rpm_payload_file_pristine chrony "$m11_restricted_unit"; then
    m11_native_fail=1
fi
for m11_native_line in \
    'ExecStart=/usr/sbin/chronyd -n -U $OPTIONS' \
    'SELinuxContext=system_u:system_r:chronyd_restricted_t:s0' \
    'User=chrony' \
    'AmbientCapabilities=CAP_SYS_TIME' \
    'CapabilityBoundingSet=CAP_SYS_TIME' \
    'DevicePolicy=closed' \
    'MemoryDenyWriteExecute=yes' \
    'NoNewPrivileges=yes' \
    'PrivateDevices=yes' \
    'ProtectHome=yes' \
    'ProtectProc=invisible' \
    'ProtectSystem=strict' \
    'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX' \
    'SystemCallArchitectures=native' \
    'UMask=0077'; do
    grep -qxF "$m11_native_line" "$m11_restricted_unit" 2>/dev/null || \
        m11_native_fail=1
done
unset m11_native_line
if [ "$(rpm -qf --qf '%{NAME}\n' /etc/sysconfig/chronyd 2>/dev/null || true)" != chrony ] \
   || [ "$(stat -c '%U:%G:%a' /etc/sysconfig/chronyd 2>/dev/null || true)" != \
      root:root:644 ] \
   || ! rpm_payload_file_pristine chrony /etc/sysconfig/chronyd \
   || [ "$(grep -cE '^[[:space:]]*OPTIONS=' /etc/sysconfig/chronyd 2>/dev/null || true)" != 1 ] \
   || ! grep -qxF 'OPTIONS="-F 2"' /etc/sysconfig/chronyd; then
    m11_native_fail=1
fi
if [ "$(stat -c '%U:%G:%a' /etc/systemd/ntp-units.d 2>/dev/null || true)" != \
     root:root:755 ] \
   || [ "$(stat -c '%U:%G:%a' "$m11_provider_file" 2>/dev/null || true)" != \
      root:root:644 ] \
   || [ "$(grep -cEv '^[[:space:]]*(#|$)' "$m11_provider_file" 2>/dev/null || true)" != 1 ] \
   || [ "$(grep -cFx 'chronyd-restricted.service' "$m11_provider_file" 2>/dev/null || true)" != 1 ]; then
    m11_native_fail=1
fi
if [ "$(stat -c '%U:%G:%a' "$m11_preset_file" 2>/dev/null || true)" != \
     root:root:644 ] \
   || [ "$(cat "$m11_preset_file" 2>/dev/null || true)" != \
      $'disable chronyd.service\nenable chronyd-restricted.service' ]; then
    m11_native_fail=1
fi
if ! systemctl is-enabled chronyd-restricted.service >/dev/null 2>&1 \
   || ! systemctl is-enabled noid-chrony-network-online.service >/dev/null 2>&1 \
   || [ "$(systemctl is-enabled noid-chrony-network-offline.service \
        2>/dev/null || true)" != static ] \
   || systemctl is-enabled chronyd.service >/dev/null 2>&1 \
   || [ ! -L /etc/systemd/system/systemd-timesyncd.service ] \
   || [ "$(readlink /etc/systemd/system/systemd-timesyncd.service 2>/dev/null || true)" != /dev/null ]; then
    m11_native_fail=1
fi
if [ ! -f "$m11_offline_readiness_unit" ] \
   || [ -L "$m11_offline_readiness_unit" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$m11_offline_readiness_unit" \
        2>/dev/null || true)" != root:root:644:1 ] \
   || ! grep -qxF 'Requires=chronyd-restricted.service' \
        "$m11_offline_readiness_unit" \
   || ! grep -qxF 'After=chronyd-restricted.service' \
        "$m11_offline_readiness_unit" \
   || ! grep -qxF 'Before=noid-chrony-network-online.service' \
        "$m11_offline_readiness_unit" \
   || ! grep -qxF \
        'ExecStart=/usr/local/libexec/noid-network-readiness offline-consumer' \
        "$m11_offline_readiness_unit" \
   || ! grep -qxF 'User=chrony' "$m11_offline_readiness_unit" \
   || ! grep -qxF 'Group=chrony' "$m11_offline_readiness_unit" \
   || ! grep -qxF 'ReadWritePaths=/run/chrony' "$m11_offline_readiness_unit" \
   || grep -q '^RuntimeDirectory=' "$m11_offline_readiness_unit" \
   || grep -qxF 'NoNewPrivileges=yes' "$m11_offline_readiness_unit" \
   || grep -qF 'WantedBy=' "$m11_offline_readiness_unit" \
   || [ ! -f "$m11_readiness_unit" ] || [ -L "$m11_readiness_unit" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$m11_readiness_unit" \
        2>/dev/null || true)" != root:root:644:1 ] \
   || ! grep -qxF 'Requires=chronyd-restricted.service' "$m11_readiness_unit" \
   || ! grep -qxF 'After=chronyd-restricted.service' "$m11_readiness_unit" \
   || ! grep -qxF \
        'ConditionPathExists=/run/noid-privacy/gateway-xdp.ready' \
        "$m11_readiness_unit" \
   || ! grep -qxF \
        'ExecStart=/usr/local/libexec/noid-network-readiness online-consumer' \
        "$m11_readiness_unit" \
   || ! grep -qxF 'Restart=on-failure' "$m11_readiness_unit" \
   || ! grep -qxF 'RestartSec=30s' "$m11_readiness_unit" \
   || ! grep -qxF 'RestartSteps=4' "$m11_readiness_unit" \
   || ! grep -qxF 'RestartMaxDelaySec=15min' "$m11_readiness_unit" \
   || ! grep -qxF 'User=chrony' "$m11_readiness_unit" \
   || ! grep -qxF 'Group=chrony' "$m11_readiness_unit" \
   || ! grep -qxF 'ReadWritePaths=/run/chrony' "$m11_readiness_unit" \
   || grep -q '^RuntimeDirectory=' "$m11_readiness_unit" \
   || ! grep -qxF \
        'ExecStartPre=!/usr/local/libexec/noid-network-readiness consumer-precheck' \
        "$m11_readiness_unit" \
   || ! grep -qxF 'WantedBy=chronyd-restricted.service' "$m11_readiness_unit" \
   || [ ! -f "$m11_readiness_helper" ] || [ -L "$m11_readiness_helper" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$m11_readiness_helper" \
        2>/dev/null || true)" != root:root:755:1 ] \
   || ! bash -n "$m11_readiness_helper" \
   || ! grep -qxF \
        'CHRONY_OFFLINE_UNIT=noid-chrony-network-offline.service' \
        "$m11_readiness_helper" \
   || ! grep -qxF \
        'CHRONY_TRANSITION_LOCK=/run/chrony/noid-network-readiness.lock' \
        "$m11_readiness_helper" \
   || ! grep -qxF \
        '        if ! systemctl start "$CHRONY_OFFLINE_UNIT"; then' \
        "$m11_readiness_helper" \
   || ! grep -qxF '    /usr/bin/flock --exclusive 9' \
        "$m11_readiness_helper" \
   || [ "$(grep -xcF '        lock_chrony_transition' \
        "$m11_readiness_helper")" -ne 2 ] \
   || ! grep -qxF '        valid_ready || exit 0' \
        "$m11_readiness_helper" \
   || [ -e /etc/systemd/system/noid-chrony-network-online.path ] \
   || [ -L /etc/systemd/system/noid-chrony-network-online.path ]; then
    m11_native_fail=1
fi
if [ -e /etc/systemd/system/chronyd.service.d/99-noid-hardening.conf ] \
   || [ -L /etc/systemd/system/chronyd.service.d/99-noid-hardening.conf ] \
   || [ -e /etc/systemd/system/chronyd-restricted.service.d/99-noid-hardening.conf ] \
   || [ -L /etc/systemd/system/chronyd-restricted.service.d/99-noid-hardening.conf ] \
   || ! grep -qF '/usr/bin/systemctl stop chronyd-restricted.service' \
        /usr/local/sbin/noid-time-recovery 2>/dev/null \
   || ! grep -qF '/usr/bin/systemctl start chronyd-restricted.service' \
        /usr/local/sbin/noid-time-recovery 2>/dev/null \
   || grep -qE 'systemctl (start|stop) chronyd\.service' \
        /usr/local/sbin/noid-time-recovery 2>/dev/null; then
    m11_native_fail=1
fi
if [ "$m11_native_fail" -ne 0 ]; then
    log "  FAIL: Module 11 native restricted chronyd service/provider contract invalid"
    fail=$((fail + 1))
fi

# Module 11b — manual, evidence-first DNS diagnostics.
M11B_CLI=/usr/local/bin/noid-dns-diagnose
M11B_DOC=/usr/share/doc/noid-privacy/11b-dns-diagnostics.md
if [ ! -f "$M11B_CLI" ] || [ -L "$M11B_CLI" ] || [ ! -x "$M11B_CLI" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$M11B_CLI" 2>/dev/null || true)" != root:root:755:1 ] \
   || ! bash -n "$M11B_CLI" \
   || ! "$M11B_CLI" help >/dev/null \
   || "$M11B_CLI" help unexpected >/dev/null 2>&1 \
   || ! matchpathcon -V "$M11B_CLI" >/dev/null 2>&1; then
    log "  FAIL: Module 11b diagnostic CLI type, metadata, label or parser contract invalid"
    fail=$((fail + 1))
fi
for m11b_required in \
    'resolvectl --no-pager status' \
    'resolvectl --no-ask-password --no-pager show-server-state' \
    'if [ "$EUID" -ne 0 ]; then' \
    'sudo noid-dns-diagnose evidence' \
    'ip -4 rule show' \
    'ip -4 route show table all' \
    'ip -6 rule show' \
    'ip -6 route show table all' \
    'journalctl --system -u systemd-resolved.service' \
    '-o short-iso-precise' \
    'this explicit probe can send a DNS query' \
    'review it before sharing.'; do
    if ! grep -qF -- "$m11b_required" "$M11B_CLI" 2>/dev/null; then
        log "  FAIL: Module 11b local evidence contract missing: $m11b_required"
        fail=$((fail + 1))
    fi
done
unset m11b_required
if [ "$(grep -cFx '    resolvectl query "$target"' "$M11B_CLI" 2>/dev/null || true)" -ne 1 ] \
   || grep -qE 'TEST_HOST=|resolvectl[[:space:]]+(reset-server-features|flush-caches)|systemctl[[:space:]]+restart[[:space:]]+systemd-resolved|notify-send' \
        "$M11B_CLI" 2>/dev/null; then
    log "  FAIL: Module 11b diagnostic CLI contains an automatic query/recovery action"
    fail=$((fail + 1))
fi
if [ ! -f "$M11B_DOC" ] || [ -L "$M11B_DOC" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$M11B_DOC" 2>/dev/null || true)" != root:root:644:1 ] \
   || ! grep -qFx '# DNS diagnostics (Module 11b)' "$M11B_DOC" 2>/dev/null \
   || ! grep -qF 'Review it before sharing' "$M11B_DOC" 2>/dev/null \
   || ! grep -qF 'Complete `evidence` requires root because systemd 259' "$M11B_DOC" 2>/dev/null \
   || ! matchpathcon -V "$M11B_DOC" >/dev/null 2>&1; then
    log "  FAIL: Module 11b diagnostic document type, metadata, label or privacy warning invalid"
    fail=$((fail + 1))
fi
for obsolete in /usr/local/sbin/noid-dns-health.sh \
                /usr/local/bin/noid-toggle-dns-health \
                /etc/systemd/system/noid-dns-health.service \
                /etc/systemd/system/noid-dns-health.timer \
                /etc/systemd/system/timers.target.wants/noid-dns-health.timer \
                /var/lib/noid-privacy/dns-health.enabled \
                /usr/share/doc/noid-privacy/11b-dns-health-monitoring.md; do
    if [ -e "$obsolete" ] || [ -L "$obsolete" ]; then
        log "  FAIL: Module 11b obsolete automatic artifact present: $obsolete"
        fail=$((fail + 1))
    fi
done
unset M11B_CLI M11B_DOC

# Module 12 — SELinux + auditd (+ audit-notify integration)
for f in /etc/audit/auditd.conf /etc/audit/rules.d/99-hardening.rules /etc/audit/rules.d/audit.rules /etc/selinux/config; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 12 missing: $f"
        fail=$((fail + 1))
    fi
done
if ! grep -qxF 'SELINUX=enforcing' /etc/selinux/config \
   || ! grep -qxF 'SELINUXTYPE=targeted' /etc/selinux/config; then
    log "  FAIL: Module 12 persistent SELinux enforcing/targeted config invalid"
    fail=$((fail + 1))
fi
if m12_boolean_overrides=$(semanage boolean -E 2>/dev/null); then
    for m12_boolean in selinuxuser_execstack selinuxuser_execmod; do
        if [ "$(printf '%s\n' "$m12_boolean_overrides" | \
                grep -xcF "boolean -m -0 $m12_boolean" || true)" -ne 1 ]; then
            log "  FAIL: Module 12 exact persistent boolean override missing: $m12_boolean"
            fail=$((fail + 1))
        fi
    done
else
    log "  FAIL: Module 12 persistent SELinux boolean overrides are unreadable"
    fail=$((fail + 1))
fi
unset m12_boolean_overrides m12_boolean
if ! grep -q '^-e 2$' /etc/audit/rules.d/99-hardening.rules 2>/dev/null; then
    log "  FAIL: Module 12 -e 2 immutable not set"
    fail=$((fail + 1))
fi
if [ "$(grep -cE '^-a ' /etc/audit/rules.d/99-hardening.rules 2>/dev/null || true)" -ne 132 ] \
   || grep -qE '^-w ' /etc/audit/rules.d/99-hardening.rules \
   || ! cmp -s \
        <(grep '^-a .*arch=b64' /etc/audit/rules.d/99-hardening.rules | \
            sed 's/arch=b64/arch=ABI/' | sort) \
        <(grep '^-a .*arch=b32' /etc/audit/rules.d/99-hardening.rules | \
            sed 's/arch=b32/arch=ABI/' | sort) \
   || grep -qE '^-a never,exit' /etc/audit/rules.d/99-hardening.rules \
   || [ "$(grep -cE '^-a always,exit -F arch=b(32|64) -S adjtimex -S settimeofday -S clock_settime -S clock_adjtime -k time_change$' \
        /etc/audit/rules.d/99-hardening.rules 2>/dev/null || true)" -ne 2 ]; then
    log "  FAIL: Module 12 audit ABI/time-adjustment coverage contract invalid"
    fail=$((fail + 1))
fi
if [ ! -d /etc/chrony.d ] || [ -L /etc/chrony.d ] \
   || [ "$(stat -c '%U:%G:%a' /etc/chrony.d 2>/dev/null || true)" != root:root:755 ]; then
    log "  FAIL: Module 12 optional /etc/chrony.d audit target invalid"
    fail=$((fail + 1))
fi
if [ ! -d /var/lib/aide ] || [ -L /var/lib/aide ] \
   || [ "$(stat -c '%U:%G:%a' /var/lib/aide 2>/dev/null || true)" != root:root:700 ]; then
    log "  FAIL: Module 12 /var/lib/aide audit target invalid"
    fail=$((fail + 1))
fi
for audit_target in \
    '-F path=/etc/aide.conf -F perm=wa -F obj_type=etc_t -k aide_integrity' \
    '-F dir=/var/lib/aide -F perm=wa -k aide_integrity' \
    '-F path=/run/utmp -F perm=wa -F obj_type=initrc_var_run_t -k session' \
    '-F path=/var/log/wtmp -F perm=wa -F obj_type=wtmp_t -k session' \
    '-F path=/var/log/btmp -F perm=wa -F obj_type=faillog_t -k logins' \
    '-F path=/var/log/lastlog -F perm=wa -F obj_type=lastlog_t -k logins' \
    '-F dir=/var/lib/faillock -F perm=wa -k logins' \
    '-F dir=/var/lib/lastlog -F perm=wa -k logins'; do
    if [ "$(grep -cF -- "$audit_target" \
            /etc/audit/rules.d/99-hardening.rules 2>/dev/null || true)" -ne 2 ]; then
        log "  FAIL: Module 12 login/session audit target lacks its exact ABI pair: $audit_target"
        fail=$((fail + 1))
    fi
done
if [ "$(stat -c '%U:%G:%a' /usr/local/sbin/noid-audit-space-alert 2>/dev/null || true)" != \
     root:root:755 ] \
   || [ "$(stat -c '%U:%G:%a' /usr/local/libexec/noid-auditd-live-thresholds 2>/dev/null || true)" != \
        root:root:755 ] \
   || [ "$(stat -c '%U:%G:%a' /etc/systemd/system/auditd.service.d/10-noid-live-thresholds.conf 2>/dev/null || true)" != \
        root:root:644 ] \
   || ! bash -n /usr/local/sbin/noid-audit-space-alert 2>/dev/null \
   || ! bash -n /usr/local/libexec/noid-auditd-live-thresholds 2>/dev/null \
   || ! grep -qxF 'ExecStartPre=-/usr/local/libexec/noid-auditd-live-thresholds' \
        /etc/systemd/system/auditd.service.d/10-noid-live-thresholds.conf \
   || ! grep -qF "case \"\$token\" in" /usr/local/libexec/noid-auditd-live-thresholds \
   || ! grep -qF 'rd.live.image|rd.live.image=*) live_image=1' \
        /usr/local/libexec/noid-auditd-live-thresholds \
   || ! grep -qF 'print "space_left = 15%"' \
        /usr/local/libexec/noid-auditd-live-thresholds \
   || ! grep -qF 'print "admin_space_left = 10%"' \
        /usr/local/libexec/noid-auditd-live-thresholds \
   || ! grep -qxF 'q_depth = 2000' /etc/audit/auditd.conf \
   || ! grep -qxF 'max_log_file = 64' /etc/audit/auditd.conf \
   || ! grep -qxF 'num_logs = 10' /etc/audit/auditd.conf \
   || ! grep -qxF 'space_left = 8192' /etc/audit/auditd.conf \
   || ! grep -qxF 'space_left_action = EXEC /usr/local/sbin/noid-audit-space-alert' \
        /etc/audit/auditd.conf \
   || ! grep -qxF 'admin_space_left = 4096' /etc/audit/auditd.conf \
   || ! grep -qxF 'admin_space_left_action = EXEC /usr/local/sbin/noid-audit-space-critical' \
        /etc/audit/auditd.conf \
   || ! grep -qxF 'disk_full_action = ROTATE' /etc/audit/auditd.conf \
   || ! grep -qxF 'disk_error_action = EXEC /usr/local/sbin/noid-audit-space-critical' \
        /etc/audit/auditd.conf \
   || [ "$(stat -c '%U:%G:%a' /usr/local/sbin/noid-audit-space-critical 2>/dev/null || true)" != \
        root:root:755 ] \
   || ! bash -n /usr/local/sbin/noid-audit-space-critical 2>/dev/null \
   || grep -qE '^[[:space:]]*(if ! )?auditctl --signal resume' \
        /usr/local/sbin/noid-audit-space-critical \
   || [ "$(stat -c '%U:%G:%a:%h' /usr/local/libexec/noid-audit-storage-notify 2>/dev/null || true)" != \
        root:root:755:1 ] \
   || ! bash -n /usr/local/libexec/noid-audit-storage-notify 2>/dev/null \
   || [ "$(stat -c '%U:%G:%a:%h' /etc/systemd/system/noid-audit-storage-notify.service 2>/dev/null || true)" != \
        root:root:644:1 ] \
   || [ "$(stat -c '%U:%G:%a:%h' /etc/systemd/system/noid-audit-storage-notify.path 2>/dev/null || true)" != \
        root:root:644:1 ] \
   || ! matchpathcon -V /usr/local/libexec/noid-audit-storage-notify \
        /etc/systemd/system/noid-audit-storage-notify.service \
        /etc/systemd/system/noid-audit-storage-notify.path >/dev/null 2>&1 \
   || ! grep -qxF 'PathModified=/run/noid-privacy/audit-storage-degraded' \
        /etc/systemd/system/noid-audit-storage-notify.path \
   || ! grep -qxF 'CapabilityBoundingSet=CAP_SETGID CAP_SETUID' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   || ! grep -qxF 'TimeoutStartSec=30s' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   || ! grep -qxF 'ProtectSystem=strict' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   || ! grep -qxF 'InaccessiblePaths=/home /root' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   || ! grep -qxF 'ProtectHome=read-only' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   || ! grep -qxF 'RestrictAddressFamilies=AF_UNIX' \
        /etc/systemd/system/noid-audit-storage-notify.service \
   || ! grep -qF -- '--property=LockedHint' \
        /usr/local/libexec/noid-audit-storage-notify \
   || ! grep -qF '/usr/bin/setpriv' \
        /usr/local/libexec/noid-audit-storage-notify \
   || ! grep -qF -- \
        '--reset-env /usr/bin/timeout --signal=TERM --kill-after=1s 5s' \
        /usr/local/libexec/noid-audit-storage-notify \
   || grep -qF 'loginctl list-users' \
        /usr/local/libexec/noid-audit-storage-notify \
   || [ "$(systemctl is-enabled noid-audit-storage-notify.path 2>/dev/null)" != enabled ] \
   || [ -e /run/noid-privacy/audit-storage-degraded ]; then
    log "  FAIL: Module 12 measured retention/degradation action contract invalid"
    fail=$((fail + 1))
fi
# The custom policy is selected exactly once at priority 400 and must be the
# byte-equivalent CIL translation of M12's retained package. This catches a
# missing/failed install, module-store replacement and a higher-priority shadow.
m12_policy_dir=/var/lib/noid-privacy/selinux
m12_te=$m12_policy_dir/noid-selinux-fixes.te
m12_pp=$m12_policy_dir/noid-selinux-fixes.pp
m12_reconcile=/usr/local/sbin/noid-selinux-policy-reconcile
m12_action=/etc/dnf/libdnf5-plugins/actions.d/noid-selinux-policy.actions
m12_action_contract='post_transaction:selinux-policy-targeted:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-selinux-policy-reconcile\ >/dev/null'
m12_module_fail=0
if [ "$(stat -c '%U:%G:%a' "$m12_te" 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(stat -c '%U:%G:%a' "$m12_pp" 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(stat -c '%U:%G:%a' "$m12_reconcile" 2>/dev/null || true)" != root:root:755 ] \
   || ! bash -n "$m12_reconcile" 2>/dev/null \
   || [ "$(stat -c '%U:%G:%a' "$m12_action" 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(grep -c '^post_transaction:' "$m12_action" 2>/dev/null || true)" -ne 1 ] \
   || ! grep -qxF "$m12_action_contract" "$m12_action" \
   || [ ! -x /usr/libexec/selinux/hll/pp ] \
   || ! grep -qxF 'module noid-selinux-fixes 1.9;' "$m12_te" \
   || ! grep -qxF 'allow init_t auditd_etc_t:dir mounton;' "$m12_te" \
   || ! grep -qxF 'allow passwd_t hugetlbfs_t:file { read write map };' "$m12_te" \
   || ! grep -qxF 'allow chkpwd_t hugetlbfs_t:file { read write map };' "$m12_te" \
   || ! grep -qxF 'allow updpwd_t hugetlbfs_t:file { read write map };' "$m12_te" \
   || grep -qE 'unconfined_t|user_tmp_t|execmod' "$m12_te"; then
    m12_module_fail=1
fi
m12_expected_checksum=""
if [ "$m12_module_fail" -eq 0 ]; then
    m12_expected_checksum=$(
        /usr/libexec/selinux/hll/pp "$m12_pp" 2>/dev/null | \
            sha256sum | awk '{print "sha256:" $1}'
    ) || m12_module_fail=1
fi
m12_module_records=""
if [ "$m12_module_fail" -eq 0 ]; then
    m12_module_records=$(semodule -lfull -m 2>/dev/null | \
        awk '$2 == "noid-selinux-fixes" {print}') || m12_module_fail=1
fi
if [ "$m12_module_fail" -eq 0 ] \
   && [ "$(printf '%s\n' "$m12_module_records" | grep -c . || true)" -eq 1 ]; then
    read -r m12_priority m12_name m12_lang m12_checksum m12_extra \
        <<< "$m12_module_records"
    if [ "$m12_priority" != 400 ] \
       || [ "$m12_name" != noid-selinux-fixes ] \
       || [ "$m12_lang" != pp ] \
       || [ "$m12_checksum" != "$m12_expected_checksum" ] \
       || [ -n "${m12_extra:-}" ]; then
        m12_module_fail=1
    fi
else
    m12_module_fail=1
fi
if [ "$m12_module_fail" -ne 0 ]; then
    log "  FAIL: Module 12 selected SELinux module/update-reconcile contract invalid"
    fail=$((fail + 1))
fi
unset m12_reconcile m12_action m12_action_contract
if [ -e /usr/bin/liveinst ]; then
    if [ -L /usr/bin/liveinst ] \
       || [ "$(rpm -qf --qf '%{NAME}\n' /usr/bin/liveinst 2>/dev/null || true)" != \
            anaconda-live ] \
       || [ "$(stat -c '%U:%G:%a' /usr/bin/liveinst 2>/dev/null || true)" != \
            root:root:755 ] \
       || ! rpm_payload_file_pristine anaconda-live /usr/bin/liveinst; then
        log "  FAIL: Module 12 Fedora liveinst RPM payload is not pristine"
        fail=$((fail + 1))
    fi
fi
# Module 12 — auditd/auparse notification integration files
for f in /usr/local/bin/audit-notify.sh \
         /usr/local/sbin/noid-audit-notify-controller \
         /etc/audit/plugins.d/noid-notify.conf \
         /etc/systemd/system/audit-notify.service \
         /usr/local/libexec/noid-audit-event-notify \
         /etc/systemd/system/noid-audit-event-notify.service \
         /etc/systemd/system/noid-audit-event-notify.path; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 12 audit-notify missing/not regular: $f"
        fail=$((fail + 1))
    fi
done
if [ "$(stat -c '%U:%G:%a' /usr/local/bin/audit-notify.sh 2>/dev/null || true)" != \
     root:root:755 ] \
   || ! python3 -c 'path="/usr/local/bin/audit-notify.sh"; compile(open(path, encoding="utf-8").read(), path, "exec")' \
   || ! grep -qF 'auparse.AuParser(auparse.AUSOURCE_FEED, None)' \
        /usr/local/bin/audit-notify.sh \
   || ! grep -qF 'row.get("uid") != uid' /usr/local/libexec/noid-audit-event-notify \
   || ! grep -qF 'LockedHint' /usr/local/libexec/noid-audit-event-notify \
   || [ -L /usr/local/libexec/noid-audit-event-notify ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' /usr/local/libexec/noid-audit-event-notify 2>/dev/null || true)" != \
        0:0:755:1 ] \
   || [ -L /etc/systemd/system/noid-audit-event-notify.service ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' /etc/systemd/system/noid-audit-event-notify.service 2>/dev/null || true)" != \
        0:0:644:1 ] \
   || [ -L /etc/systemd/system/noid-audit-event-notify.path ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' /etc/systemd/system/noid-audit-event-notify.path 2>/dev/null || true)" != \
        0:0:644:1 ] \
   || ! matchpathcon -V /usr/local/libexec/noid-audit-event-notify \
        /etc/systemd/system/noid-audit-event-notify.service \
        /etc/systemd/system/noid-audit-event-notify.path >/dev/null 2>&1 \
   || ! python3 -c 'path="/usr/local/libexec/noid-audit-event-notify"; compile(open(path, encoding="utf-8").read(), path, "exec")' \
   || ! grep -qF '/usr/bin/setpriv' /usr/local/libexec/noid-audit-event-notify \
   || grep -qF '/usr/bin/setpriv' /usr/local/bin/audit-notify.sh \
   || grep -qF '/usr/bin/notify-send' /usr/local/bin/audit-notify.sh \
   || ! grep -qxF 'DirectoryNotEmpty=/run/noid-privacy/audit-notify.d' \
        /etc/systemd/system/noid-audit-event-notify.path \
   || ! grep -qF 'os.O_RDONLY | os.O_DIRECTORY' \
        /usr/local/bin/audit-notify.sh \
   || ! grep -qF 'notification-worker-{type(error).__name__}' \
        /usr/local/bin/audit-notify.sh \
   || ! grep -qF 'initial-health-write-failed' /usr/local/bin/audit-notify.sh \
   || ! grep -qF 'final-health-write-failed' /usr/local/bin/audit-notify.sh \
   || ! grep -qF '"aide_integrity",' /usr/local/bin/audit-notify.sh \
   || [ "$(systemctl is-enabled noid-audit-event-notify.path 2>/dev/null)" != enabled ] \
   || [ "$(stat -c '%U:%G:%a' /usr/local/sbin/noid-audit-notify-controller 2>/dev/null || true)" != \
        root:root:755 ] \
   || ! bash -n /usr/local/sbin/noid-audit-notify-controller \
   || [ "$(stat -c '%U:%G:%a' /etc/audit/plugins.d/noid-notify.conf 2>/dev/null || true)" != \
        root:root:640 ] \
   || ! grep -qxF 'active = no' /etc/audit/plugins.d/noid-notify.conf \
   || ! grep -qxF 'path = /usr/local/bin/audit-notify.sh' \
        /etc/audit/plugins.d/noid-notify.conf \
   || ! grep -qxF 'type = always' /etc/audit/plugins.d/noid-notify.conf \
   || ! grep -qxF 'format = string' /etc/audit/plugins.d/noid-notify.conf \
   || [ -e /run/noid-privacy/audit-notify-degraded ]; then
    log "  FAIL: Module 12 complete-event/local-session notification contract invalid"
    fail=$((fail + 1))
fi
# Module 12 — audit-notify.service installed (
# OPT-IN via Python welcome dialog → service must NOT be enabled at install
# time. Inverted check: FAIL if enabled, OK if installed-but-disabled)
if [ -L /etc/systemd/system/multi-user.target.wants/audit-notify.service ]; then
    log "  FAIL: Module 12 audit-notify.service is enabled (must be opt-in)"
    fail=$((fail + 1))
elif [ ! -f /etc/systemd/system/audit-notify.service ]; then
    log "  FAIL: Module 12 audit-notify.service not installed"
    fail=$((fail + 1))
fi

# Module 13 — AIDE config + timer + welcome + user tools
for f in /etc/systemd/system/aide-check.service /etc/systemd/system/aide-check.timer \
         /etc/systemd/system/aide-check.service.d/exitcode.conf \
         /usr/share/doc/noid-privacy/aide-notify-dropin.conf \
         /usr/share/doc/noid-privacy/aide-schedule-override.conf \
         /usr/share/doc/noid-privacy/notifications.md \
         /usr/local/bin/aide-notify.sh /usr/local/bin/noid-welcome.sh \
         /usr/local/lib/noid-privacy/agent-install-format.sh \
         /usr/local/bin/noid-autostart-netwait \
         /usr/local/bin/noid-status /usr/local/bin/noid-toggle-aide-popup \
         /usr/local/bin/noid-toggle-aide \
         /etc/xdg/autostart/noid-welcome.desktop; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 13 missing/not a regular file: $f"
        fail=$((fail + 1))
    fi
done
if [ -L /usr/local/bin/aide-notify.sh ] \
   || [ "$(stat -Lc '%U:%G:%a:%h' /usr/local/bin/aide-notify.sh \
            2>/dev/null || true)" != root:root:755:1 ] \
   || ! bash -n /usr/local/bin/aide-notify.sh \
   || ! grep -qF 'list-sessions --json=short' /usr/local/bin/aide-notify.sh \
   || ! grep -qF '/usr/bin/timeout --signal=TERM --kill-after=1s 3s' \
        /usr/local/bin/aide-notify.sh \
   || ! grep -qF -- '--property=LockedHint' /usr/local/bin/aide-notify.sh \
   || ! grep -qF 'show-seat "$seat"' /usr/local/bin/aide-notify.sh \
   || ! grep -qF '[ "$uid" -le 4294967294 ]' /usr/local/bin/aide-notify.sh \
   || ! grep -qF 'notified_uids["$uid"]=1' /usr/local/bin/aide-notify.sh \
   || ! grep -qF '"_SYSTEMD_INVOCATION_ID=${INVOCATION_ID}"' \
        /usr/local/bin/aide-notify.sh \
   || ! grep -qF '/usr/bin/stat -c '\''%F:%u'\'' "$dbus_sock"' \
        /usr/local/bin/aide-notify.sh \
   || ! grep -qF '/usr/bin/setpriv' /usr/local/bin/aide-notify.sh \
   || grep -qF '/run/systemd/users/' /usr/local/bin/aide-notify.sh \
   || grep -qF 'sudo -u' /usr/local/bin/aide-notify.sh; then
    log "  FAIL: Module 13 AIDE local-session notification contract invalid"
    fail=$((fail + 1))
fi
if [ ! -x /usr/libexec/noid-aide-status ] \
   || [ -L /usr/libexec/noid-aide-status ] \
   || [ "$(stat -Lc '%U:%G:%a:%h' /usr/libexec/noid-aide-status \
            2>/dev/null || true)" != root:root:755:1 ] \
   || ! grep -qF 'NOID_AIDE_STATE_V1' /usr/libexec/noid-aide-status \
   || ! visudo -cf /etc/sudoers.d/91-noid-aide-status >/dev/null \
   || ! grep -qxF 'Cmnd_Alias NOID_AIDE_STATUS = /usr/libexec/noid-aide-status ""' \
        /etc/sudoers.d/91-noid-aide-status \
   || ! grep -qxF 'f /run/lock/noid-aide.lock 0600 root root -' \
        /usr/lib/tmpfiles.d/noid-aide-lock.conf; then
    log "  FAIL: Module 13 read-only AIDE state or mutex boundary invalid"
    fail=$((fail + 1))
fi

# Module 13 — notify.conf drop-in MUST NOT be installed by default (opt-in)
if [ -f /etc/systemd/system/aide-check.service.d/notify.conf ]; then
    log "  FAIL: Module 13 notify.conf drop-in present at build time (should be opt-in template only)"
    fail=$((fail + 1))
fi

# Module 13 — aide-check wrapper + drop-in.
# The wrapper noid-aide-check.sh provides per-run TS-named report file
# + external flock /var/lock/noid-aide.lock (mutex). The drop-in overrides
# aide-check.service's ExecStart to invoke the wrapper. Drop-in survives aide
# RPM upgrades. Verify presence + the drop-in actually redirects ExecStart.
if [ ! -x /usr/local/sbin/noid-aide-check.sh ]; then
    log "  FAIL: Module 13 wrapper /usr/local/sbin/noid-aide-check.sh missing or not executable"
    fail=$((fail + 1))
fi
if [ ! -f /etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf ]; then
    log "  FAIL: Module 13 drop-in /etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf missing"
    fail=$((fail + 1))
elif ! grep -qE '^ExecStart=/usr/local/sbin/noid-aide-check\.sh$' /etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf; then
    log "  FAIL: Module 13 drop-in does not redirect ExecStart to the wrapper"
    fail=$((fail + 1))
fi
if ! grep -qF 'COVERAGE_MANIFEST=/usr/lib/noid-privacy/aide-secure-paths.tsv' \
        /usr/local/sbin/noid-aide-check.sh 2>/dev/null \
   || ! grep -qF -- '--path-check="$file_type:$probe_path"' \
        /usr/local/sbin/noid-aide-check.sh 2>/dev/null; then
    log "  FAIL: Module 13 wrapper lacks the runtime coverage re-probe"
    fail=$((fail + 1))
fi

# Public shell tools share one TTY-only presentation contract. These exact
# markers bind the remaining quiet/machine-oriented helpers that otherwise
# have no visible formatter calls in their normal service execution paths.
if [ -L /usr/local/lib/noid-privacy/agent-install-format.sh ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' \
        /usr/local/lib/noid-privacy/agent-install-format.sh 2>/dev/null || true)" \
        != 0:0:644:1 ] \
   || ! grep -qF 'NOID_FMT_AUTO_TITLE="NoID Privacy — Network Gate"' \
        /usr/local/bin/noid-autostart-netwait 2>/dev/null \
   || ! grep -qF 'NOID_FMT_AUTO_TITLE="NoID Privacy — AIDE Check"' \
        /usr/local/sbin/noid-aide-check.sh 2>/dev/null \
   || ! grep -qF 'NOID_FMT_AUTO_TITLE="NoID Privacy — LAN XDP Boundary"' \
        /usr/local/sbin/noid-lan-xdp 2>/dev/null; then
    log "  FAIL: public CLI shared presentation contract invalid"
    fail=$((fail + 1))
fi

# Module 13 — explicit baseline review and absence of automatic replacement.
if [ ! -x /usr/local/sbin/noid-aide-baseline-review ]; then
    log "  FAIL: Module 13 /usr/local/sbin/noid-aide-baseline-review missing"
    fail=$((fail + 1))
fi
for obsolete in /usr/local/sbin/noid-aide-firstboot-rebaseline.sh \
                /etc/systemd/system/noid-aide-firstboot-rebaseline.service \
                /etc/systemd/system/noid-aide-firstboot-rebaseline.timer \
                /etc/systemd/system/timers.target.wants/noid-aide-firstboot-rebaseline.timer \
                /var/lib/noid-privacy/aide-firstboot-rebaselined.flag; do
    if [ -e "$obsolete" ] || [ -L "$obsolete" ]; then
        log "  FAIL: obsolete automatic AIDE trust-replacement artifact present: $obsolete"
        fail=$((fail + 1))
    fi
done
if [ -L /etc/systemd/system/timers.target.wants/aide-check.timer ]; then
    log "  FAIL: aide-check.timer enabled before a user-owned baseline exists"
    fail=$((fail + 1))
fi

# Module 14 — USBGuard daemon conf + firstboot service + mask + user escape-hatches
for f in /etc/usbguard/usbguard-daemon.conf /etc/usbguard/rules.conf \
         /usr/local/bin/noid-usbguard-firstboot.sh \
         /usr/local/bin/noid-usbguard-add-user.sh \
         /usr/local/bin/noid-usbguard-allow-device \
         /usr/local/bin/noid-usbguard-devices \
         /usr/local/bin/noid-install-displaylink \
         /usr/libexec/noid-usbguard-login-catchup \
         /usr/local/sbin/noid-usbguard-remove-gnome-wildcard \
         /usr/share/doc/noid-privacy/14-usbguard.md \
         /usr/share/doc/noid-privacy/docking-stations.md \
         /etc/systemd/system/noid-usbguard-firstboot.service \
         /etc/systemd/system/noid-usbguard-live-init.service \
         /etc/systemd/system/noid-usbguard-remove-gnome-wildcard.service \
         /usr/lib/systemd/user/noid-usbguard-login-catchup.service \
         /etc/systemd/user-preset/50-noid-usbguard.preset; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 14 missing/not a regular file: $f"
        fail=$((fail + 1))
    fi
done
if [ -L /etc/usbguard/usbguard-daemon.conf ] || \
   [ "$(stat -Lc '%u:%g:%a:%h' /etc/usbguard/usbguard-daemon.conf \
        2>/dev/null || true)" != 0:0:600:1 ]; then
    log "  FAIL: Module 14 USBGuard daemon config metadata is not root:root 0600 nlink=1"
    fail=$((fail + 1))
fi
if grep -Eq '^[[:space:]]*(IPCAllowedGroups|IPCAllowedUsers)[[:space:]]*=' \
        /etc/usbguard/usbguard-daemon.conf \
   || ! grep -qxF 'IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/' \
        /etc/usbguard/usbguard-daemon.conf \
   || ! grep -qF "'Policy=list'" /usr/local/bin/noid-usbguard-firstboot.sh \
   || ! grep -qF "'Parameters=list,listen'" \
        /usr/local/bin/noid-usbguard-firstboot.sh \
   || ! grep -qF '/usr/bin/gpasswd -d "$username" usbguard' \
        /usr/local/bin/noid-usbguard-add-user.sh; then
    log "  FAIL: Module 14 least-privilege named IPC contract invalid"
    fail=$((fail + 1))
fi
if [ ! -x /usr/local/bin/noid-usbguard-devices ] \
   || [ -L /usr/local/bin/noid-usbguard-devices ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' /usr/local/bin/noid-usbguard-devices \
        2>/dev/null || true)" != 0:0:755:1 ] \
   || ! python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("/usr/local/bin/noid-usbguard-devices").read_text())' \
   || ! /usr/local/bin/noid-usbguard-devices --help 2>/dev/null \
        | grep -qF 'sudo noid-usbguard-devices revoke [rule-id]' \
   || ! grep -qF 'runtime-only rules are loaded; refusing a save' \
        /usr/local/bin/noid-usbguard-devices \
   || ! grep -qF 'ordered_parity = [rule.body for rule in rules] == durable_bodies' \
        /usr/local/bin/noid-usbguard-devices \
   || ! grep -qF 'run_usbguard("list-rules", "-d")' \
        /usr/local/bin/noid-usbguard-devices \
   || grep -qF 'run_usbguard("list-devices", match_query)' \
        /usr/local/bin/noid-usbguard-devices \
   || ! grep -qF 'os.execv(ALLOW_HELPER' \
        /usr/local/bin/noid-usbguard-devices \
   || ! grep -qF 'fmt_section("Blocked USB devices")' \
        /usr/local/bin/noid-usbguard-devices \
   || ! grep -qF 'def rule_display_name(' \
        /usr/local/bin/noid-usbguard-devices; then
    log "  FAIL: Module 14 unified USBGuard manager contract invalid"
    fail=$((fail + 1))
fi
if [ ! -L /etc/systemd/system/multi-user.target.wants/noid-usbguard-live-init.service ]; then
    log "  FAIL: Module 14 live USBGuard pre-session initializer is not enabled"
    fail=$((fail + 1))
fi

if [ ! -L /etc/systemd/system/usbguard.service ] || \
   [ "$(readlink /etc/systemd/system/usbguard.service)" != "/dev/null" ]; then
    log "  FAIL: Module 14 usbguard.service not masked"
    fail=$((fail + 1))
fi
# usbguard-dbus.service must also be masked at
# build-time. The firstboot service unmasks both together after policy is
# in place, so build-time mask is the symmetric guard.
if [ ! -L /etc/systemd/system/usbguard-dbus.service ] || \
   [ "$(readlink /etc/systemd/system/usbguard-dbus.service)" != "/dev/null" ]; then
    log "  FAIL: Module 14 usbguard-dbus.service not masked at build-time"
    fail=$((fail + 1))
fi
# Package presence is required for D-Bus org.usbguard.Devices1
# activation (GNOME gsd-usb-protection driver).
if ! rpm -q usbguard-dbus >/dev/null 2>&1; then
    log "  FAIL: Module 14 usbguard-dbus package not installed (GNOME USB UI broken)"
    fail=$((fail + 1))
fi

# Module 15 — Intel ME mitigation + MEI escape-hatch
for f in /etc/modprobe.d/noid-mei-submodules.conf \
         /etc/udev/rules.d/99-noid-mei-kt-block.rules \
         /etc/dracut.conf.d/noid-mei-blacklist.conf \
         /usr/libexec/noid-mei-kt-enforce \
         /etc/systemd/system/noid-mei-kt-enforce.service \
         /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md \
         /var/lib/noid-privacy/mei-status.txt; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 15 missing: $f"
        fail=$((fail + 1))
    fi
done
if [ "$(grep -c '^STATUS_LIFECYCLE=build-time-placeholder$' \
        /var/lib/noid-privacy/mei-status.txt 2>/dev/null || true)" -ne 1 ] \
   || ! grep -qF 'pending (Live/build-time placeholder; target-boot refresh not run)' \
        /usr/local/bin/noid-status 2>/dev/null; then
    log "  FAIL: Module 15 staged platform-status lifecycle contract invalid"
    fail=$((fail + 1))
fi
if [ ! -x /usr/local/bin/noid-mei-restore-submodules ]; then
    log "  FAIL: Module 15 missing: /usr/local/bin/noid-mei-restore-submodules"
    fail=$((fail + 1))
fi
if grep -qxF 'ProtectKernelModules=yes' \
        /etc/systemd/system/noid-cpu-vendor-detect-firstboot.service \
   || ! grep -qxF 'CapabilityBoundingSet=~CAP_SYS_MODULE' \
        /etc/systemd/system/noid-cpu-vendor-detect-firstboot.service \
   || ! grep -qxF 'SystemCallFilter=~@module' \
        /etc/systemd/system/noid-cpu-vendor-detect-firstboot.service \
   || ! grep -qxF 'SystemCallErrorNumber=EPERM' \
        /etc/systemd/system/noid-cpu-vendor-detect-firstboot.service \
   || ! grep -qF 'detect_mei_submodule_policy' \
        /usr/local/sbin/noid-cpu-vendor-detect.sh; then
    log "  FAIL: Module 15 platform detector sandbox/schema contract invalid"
    fail=$((fail + 1))
fi
if [ ! -x /usr/libexec/noid-mei-kt-enforce ] ||
   ! NOID_MEI_KT_CHECK_ONLY=1 /usr/libexec/noid-mei-kt-enforce >/dev/null; then
    log "  FAIL: Module 15 KT/SOL host binding is not enforced"
    fail=$((fail + 1))
fi
if [ ! -L /etc/systemd/system/sysinit.target.wants/noid-mei-kt-enforce.service ]; then
    log "  FAIL: Module 15 early KT/SOL verification service not enabled"
    fail=$((fail + 1))
fi

# M25's update-suppression authority must be a process/argv/fd/flock proof,
# never an existence-only /run marker. M12 and M19 both depend on this helper.
if [ ! -x /usr/libexec/noid-update-lock-guardian ] \
        || [ -L /usr/libexec/noid-update-lock-guardian ] \
        || [ ! -x /usr/libexec/noid-update-window-active ] \
        || [ -L /usr/libexec/noid-update-window-active ] \
        || ! grep -qF 'process_matches || inactive' \
            /usr/libexec/noid-update-window-active \
        || ! grep -qF '/proc/locks' /usr/libexec/noid-update-window-active \
        || ! grep -qF 'flock --nonblock 9' \
            /usr/libexec/noid-update-window-active; then
    log "  FAIL: Module 25 process/lock-bound update-window validator missing or incomplete"
    fail=$((fail + 1))
fi
# The embedded view below is generated/tested against the one repository
# manifest. Exact config lines are necessary but not sufficient: `--path-check`
# also rejects a later negative/weak rule that shadows the intended coverage.
# The deployed copy under /usr/lib/noid-privacy feeds the daily wrapper's
# runtime re-probe and must stay byte-identical to this view.
aide_probe_manifest=$(mktemp)
cat > "$aide_probe_manifest" <<'AIDE_SECURE_PATHS_EOF'
/etc/modprobe.d/|f|/etc/modprobe.d/.noid-aide-coverage-probe
/etc/udev/rules.d|f|/etc/udev/rules.d/.noid-aide-coverage-probe
/etc/dracut.conf.d/|f|/etc/dracut.conf.d/.noid-aide-coverage-probe
/etc/firewalld/|f|/etc/firewalld/.noid-aide-coverage-probe
/etc/NetworkManager/conf.d|f|/etc/NetworkManager/conf.d/.noid-aide-coverage-probe
/etc/NetworkManager/dispatcher.d|f|/etc/NetworkManager/dispatcher.d/.noid-aide-coverage-probe
/etc/nftables|f|/etc/nftables/.noid-aide-coverage-probe
/etc/sysctl.d/|f|/etc/sysctl.d/.noid-aide-coverage-probe
/etc/dconf|f|/etc/dconf/.noid-aide-coverage-probe
/etc/dbus-1/session.d|f|/etc/dbus-1/session.d/.noid-aide-coverage-probe
/etc/systemd/resolved.conf.d|f|/etc/systemd/resolved.conf.d/.noid-aide-coverage-probe
/etc/systemd/coredump.conf.d|f|/etc/systemd/coredump.conf.d/.noid-aide-coverage-probe
/etc/systemd/logind.conf.d|f|/etc/systemd/logind.conf.d/.noid-aide-coverage-probe
/etc/systemd/system/|f|/etc/systemd/system/.noid-aide-coverage-probe
/etc/systemd/system.control|f|/etc/systemd/system.control/.noid-aide-coverage-probe
/etc/systemd/user|f|/etc/systemd/user/.noid-aide-coverage-probe
=/etc/chrony.conf|f|/etc/chrony.conf
/etc/ssh/ssh_config.d|f|/etc/ssh/ssh_config.d/.noid-aide-coverage-probe
/etc/ssh/sshd_config.d|f|/etc/ssh/sshd_config.d/.noid-aide-coverage-probe
=/etc/security/pam_env-sudo.conf|f|/etc/security/pam_env-sudo.conf
/etc/sudoers.d/48-noid-gnome-software-quit|f|/etc/sudoers.d/48-noid-gnome-software-quit
/etc/sudoers.d/90-noid-boot-mutation-fd|f|/etc/sudoers.d/90-noid-boot-mutation-fd
=/etc/sudoers.d/91-noid-aide-status|f|/etc/sudoers.d/91-noid-aide-status
/etc/audit/|f|/etc/audit/.noid-aide-coverage-probe
/etc/usbguard/|f|/etc/usbguard/.noid-aide-coverage-probe
/etc/tmpfiles.d/|f|/etc/tmpfiles.d/.noid-aide-coverage-probe
/etc/dnf/libdnf5-plugins/actions.d|f|/etc/dnf/libdnf5-plugins/actions.d/.noid-aide-coverage-probe
/etc/codex|f|/etc/codex/.noid-aide-coverage-probe
/etc/environment.d|f|/etc/environment.d/.noid-aide-coverage-probe
/etc/wireplumber/wireplumber.conf.d|f|/etc/wireplumber/wireplumber.conf.d/.noid-aide-coverage-probe
/usr/libexec/noid-mei-kt-enforce|f|/usr/libexec/noid-mei-kt-enforce
/usr/libexec/noid-platform-policy-sha256|f|/usr/libexec/noid-platform-policy-sha256
/usr/libexec/noid-update-lock-guardian|f|/usr/libexec/noid-update-lock-guardian
/usr/libexec/noid-update-window-active|f|/usr/libexec/noid-update-window-active
/usr/libexec/noid-boot-mutation-guard|f|/usr/libexec/noid-boot-mutation-guard
/usr/libexec/noid-dracut-regenerate-all|f|/usr/libexec/noid-dracut-regenerate-all
/usr/libexec/noid-dracut-hostonly-configure|f|/usr/libexec/noid-dracut-hostonly-configure
/usr/libexec/noid-mark-hostonly-boot-success|f|/usr/libexec/noid-mark-hostonly-boot-success
/usr/libexec/noid-gsk-hybrid-match|f|/usr/libexec/noid-gsk-hybrid-match
/usr/libexec/noid-gsk-session-environment|f|/usr/libexec/noid-gsk-session-environment
/usr/libexec/noid-codium-launch|f|/usr/libexec/noid-codium-launch
/usr/libexec/noid-vscodium-repo-key-seed|f|/usr/libexec/noid-vscodium-repo-key-seed
=/usr/libexec/noid-aide-status|f|/usr/libexec/noid-aide-status
/usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer|f|/usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer
/usr/lib/systemd/user/noid-hostonly-boot-success.path|f|/usr/lib/systemd/user/noid-hostonly-boot-success.path
/usr/lib/systemd/user/noid-hostonly-boot-success.service|f|/usr/lib/systemd/user/noid-hostonly-boot-success.service
/usr/lib/systemd/user/noid-gsk-session-environment.service|f|/usr/lib/systemd/user/noid-gsk-session-environment.service
/usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf|f|/usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf
/usr/lib/tmpfiles.d/noid-identity-bls-refresh.conf|f|/usr/lib/tmpfiles.d/noid-identity-bls-refresh.conf
=/usr/lib/tmpfiles.d/noid-aide-lock.conf|f|/usr/lib/tmpfiles.d/noid-aide-lock.conf
/usr/local/sbin/noid-restore-identity|f|/usr/local/sbin/noid-restore-identity
/usr/local/sbin/noid-gnome-software-backend-stop|f|/usr/local/sbin/noid-gnome-software-backend-stop
/usr/local/sbin/noid-gnome-software-launcher-sync|f|/usr/local/sbin/noid-gnome-software-launcher-sync
/usr/local/sbin/noid-codium-launcher-sync|f|/usr/local/sbin/noid-codium-launcher-sync
/usr/local/sbin/noid-verify-gnome-privacy-contract|f|/usr/local/sbin/noid-verify-gnome-privacy-contract
/usr/local/sbin/noid-lan-xdp|f|/usr/local/sbin/noid-lan-xdp
/usr/local/sbin/noid-wireguard-mtu-reconcile|f|/usr/local/sbin/noid-wireguard-mtu-reconcile
/usr/local/bin/gnome-software|f|/usr/local/bin/gnome-software
/usr/local/bin/noid-gnome-software-quit|f|/usr/local/bin/noid-gnome-software-quit
/usr/local/bin/noid-gnome-software-rpm|f|/usr/local/bin/noid-gnome-software-rpm
/usr/local/bin/noid-lan-xdp-notify|f|/usr/local/bin/noid-lan-xdp-notify
/usr/local/bin/noid-toggle-gsk-gl|f|/usr/local/bin/noid-toggle-gsk-gl
/usr/local/bin/noid-toggle-microphone|f|/usr/local/bin/noid-toggle-microphone
/usr/local/bin/noid-host-identity|f|/usr/local/bin/noid-host-identity
/usr/local/libexec/noid-gnome-privacy-cleanup|f|/usr/local/libexec/noid-gnome-privacy-cleanup
/usr/local/libexec/noid-wan-strict-endpoints|f|/usr/local/libexec/noid-wan-strict-endpoints
/usr/local/share/dbus-1/services|f|/usr/local/share/dbus-1/services/.noid-aide-coverage-probe
/usr/local/share/applications|f|/usr/local/share/applications/.noid-aide-coverage-probe
/usr/local/share/wireplumber/scripts|f|/usr/local/share/wireplumber/scripts/.noid-aide-coverage-probe
/usr/lib/noid-privacy/noid-lan-xdp.bpf.o|f|/usr/lib/noid-privacy/noid-lan-xdp.bpf.o
=/usr/lib/noid-privacy/noid_ui.py|f|/usr/lib/noid-privacy/noid_ui.py
/etc/xdg/autostart/noid-lan-xdp-health.desktop|f|/etc/xdg/autostart/noid-lan-xdp-health.desktop
=/usr/lib/noid-privacy/aide-secure-paths.tsv|f|/usr/lib/noid-privacy/aide-secure-paths.tsv
AIDE_SECURE_PATHS_EOF
if [ "$(stat -c '%u:%g:%a' /usr/lib/noid-privacy/aide-secure-paths.tsv 2>/dev/null || true)" != 0:0:644 ] \
   || ! cmp -s "$aide_probe_manifest" /usr/lib/noid-privacy/aide-secure-paths.tsv; then
    log "  FAIL: deployed AIDE coverage manifest differs from the finalize view"
    fail=$((fail + 1))
fi
while IFS='|' read -r aide_rule_path aide_file_type aide_probe_path; do
    if ! grep -qxF "$aide_rule_path SECURE" /etc/aide.conf 2>/dev/null; then
        log "  FAIL: canonical AIDE SECURE rule missing: $aide_rule_path"
        fail=$((fail + 1))
        continue
    fi
    if ! aide_match=$(LC_ALL=C aide --config=/etc/aide.conf \
            --path-check="$aide_file_type:$aide_probe_path" 2>&1) || \
       ! grep -qF sha256 <<<"$aide_match" || \
       ! grep -qF sha512 <<<"$aide_match"; then
        log "  FAIL: canonical AIDE coverage weak or shadowed: $aide_probe_path"
        fail=$((fail + 1))
    fi
done < "$aide_probe_manifest"
rm -f -- "$aide_probe_manifest"
if [ ! -x /usr/local/bin/noid-mei-lockdown ]; then
    log "  FAIL: Module 15 missing: /usr/local/bin/noid-mei-lockdown (max-paranoia escape-hatch)"
    fail=$((fail + 1))
fi

# Module 16 — Firefox hardening + FPP relax escape-hatch + user doc.
# The locally maintained arkenfox-derived user.js is one consolidated source.
# A system XPI seed feeds the supported registered-profile lifecycle because
# Firefox does not auto-install a regular distribution-bundled extension.
# policies.json contains only the reviewed default-search policy; extension
# installation remains profile-local. The active managed-storage copy is
# mandatory in the composed image but may be removed later through M16's
# documented system-wide list-policy opt-out.
m16_ubo_xpi="/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi"
m16_ubo_policy_source=/usr/share/noid-firefox/uBlock0@raymondhill.net.json
m16_ubo_policy_active=/usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json
m16_ubo_policy_validator=/usr/local/lib/noid-privacy/validate-ubo-policy.py
for f in /usr/share/noid-firefox/user.js \
         "$m16_ubo_xpi" \
         "$m16_ubo_policy_source" \
         "$m16_ubo_policy_active" \
         "$m16_ubo_policy_validator" \
         /usr/local/bin/noid-firefox-setup.sh \
         /usr/local/bin/noid-firefox-relax-fpp \
         /usr/local/bin/noid-firefox-harden-profile \
         /etc/xdg/autostart/noid-firefox-setup.desktop \
         /usr/share/doc/noid-privacy/16-firefox-hardening.md; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 16 missing/not a regular file: $f"
        fail=$((fail + 1))
    fi
done
if [ -L "$m16_ubo_xpi" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' "$m16_ubo_xpi" 2>/dev/null || true)" != \
        0:0:644:1 ] \
   || [ "$(stat -Lc '%s' "$m16_ubo_xpi" 2>/dev/null || true)" != 4679419 ] \
   || [ "$(sha256sum "$m16_ubo_xpi" 2>/dev/null | awk '{print $1}')" != \
        bccc51a773150af4af6e1fd62c7bfdeb7238b79ff2381b998fa9f2e38f64786a ] \
   || [ -L "$m16_ubo_policy_source" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' "$m16_ubo_policy_source" \
        2>/dev/null || true)" != 0:0:644:1 ] \
   || [ -L "$m16_ubo_policy_active" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' "$m16_ubo_policy_active" \
        2>/dev/null || true)" != 0:0:644:1 ] \
   || [ -L "$m16_ubo_policy_validator" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' "$m16_ubo_policy_validator" \
        2>/dev/null || true)" != 0:0:755:1 ] \
   || ! cmp -s -- "$m16_ubo_policy_source" "$m16_ubo_policy_active" \
   || ! python3 -c \
        'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_text(), str(p), "exec")' \
        "$m16_ubo_policy_validator" 2>/dev/null \
   || ! "$m16_ubo_policy_validator" "$m16_ubo_xpi" \
        "$m16_ubo_policy_source" >/dev/null; then
    log "  FAIL: Module 16 uBO seed/policy/validator contract invalid"
    fail=$((fail + 1))
fi
unset m16_ubo_xpi m16_ubo_policy_source m16_ubo_policy_active \
    m16_ubo_policy_validator

# Module 17 — GNOME hardening. Two fallback-only session-bus admin descriptors
# route GOA/Identity activation to one static mask. Software and Tracker keep
# Fedora's native SystemdService routes to their separately masked units. The
# fallback reference-bus policy and every RPM-owned descriptor must stay exact.
for f in /etc/dconf/db/distro.d/10-noid-gnome-privacy \
         /etc/dconf/db/distro.d/locks/10-noid-gnome-privacy \
         /usr/share/gnome-initial-setup/vendor.conf \
         /etc/xdg/autostart/org.gnome.Tour.desktop \
         /var/lib/livesys/livesys-session-extra; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 17 missing: $f"
        fail=$((fail + 1))
    fi
done
if ! grep -qF 'AutomaticLoginEnable=true' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || ! grep -qF 'AutomaticLogin=liveuser' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || ! grep -qF 'TimedLoginEnable=true' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || ! grep -qF 'TimedLogin=liveuser' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || ! grep -qF 'TimedLoginDelay=1' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || grep -qF 'disable-log-out=true' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || grep -qF '/org/gnome/desktop/lockdown/disable-log-out' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null; then
    log "  FAIL: Module 17 Live power/logout lifecycle contract invalid"
    fail=$((fail + 1))
fi

# Module 14 — notifier activation belongs to the actual graphical session,
# never the early default target or a one-shot environment race.
m14_notifier_dropin=/etc/systemd/user/usbguard-notifier.service.d/10-noid-wait.conf
m14_notifier_wants=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service
m14_catchup_unit=/usr/lib/systemd/user/noid-usbguard-login-catchup.service
m14_catchup_wants=/usr/lib/systemd/user/graphical-session.target.wants/noid-usbguard-login-catchup.service
if [ "$(stat -c '%U:%G:%a' "$m14_notifier_dropin" 2>/dev/null || true)" != root:root:644 ] \
   || ! grep -qxF 'ConditionUser=!@system' "$m14_notifier_dropin" \
   || grep -qF 'ConditionEnvironment=XDG_SESSION_CLASS=user' "$m14_notifier_dropin" \
   || ! grep -qxF 'PartOf=graphical-session.target' "$m14_notifier_dropin" \
   || ! grep -qxF 'After=graphical-session.target' "$m14_notifier_dropin" \
   || ! grep -qxF 'ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target' \
        "$m14_notifier_dropin" \
   || [ "$(readlink "$m14_notifier_wants" 2>/dev/null || true)" != \
        /usr/lib/systemd/user/usbguard-notifier.service ] \
   || [ "$(stat -c '%U:%G:%a' "$m14_catchup_unit" 2>/dev/null || true)" != root:root:644 ] \
   || ! grep -qxF 'PartOf=graphical-session.target' "$m14_catchup_unit" \
   || ! grep -qxF 'ExecStart=/usr/libexec/noid-usbguard-login-catchup' "$m14_catchup_unit" \
   || grep -q '^IPAddressDeny=' "$m14_catchup_unit" \
   || [ "$(readlink "$m14_catchup_wants" 2>/dev/null || true)" != \
        /usr/lib/systemd/user/noid-usbguard-login-catchup.service ] \
   || ! bash -n /usr/libexec/noid-usbguard-login-catchup \
   || ! grep -qF -- '--action=review="Open USBGuard Devices"' \
        /usr/libexec/noid-usbguard-login-catchup \
   || ! grep -qF '/usr/bin/systemd-run --user --collect --wait --quiet' \
        /usr/libexec/noid-usbguard-login-catchup \
   || ! grep -qF -- '--expand-environment=no' \
        /usr/libexec/noid-usbguard-login-catchup \
   || ! grep -qF '/usr/bin/sudo -- /usr/local/bin/noid-usbguard-devices' \
        /usr/libexec/noid-usbguard-login-catchup \
   || grep -qF 'noid-tools' /usr/libexec/noid-usbguard-login-catchup \
   || grep -Eq 'usbguard[[:space:]]+(allow-device|append-rule)' \
        /usr/libexec/noid-usbguard-login-catchup; then
    log "  FAIL: Module 14 USBGuard graphical notification contract invalid"
    fail=$((fail + 1))
fi

dbus_admin_dir=/usr/local/share/dbus-1/services
dbus_vendor_dir=/usr/share/dbus-1/services
dbus_policy=/etc/dbus-1/session.d/20-noid-blocked-services.conf
dbus_block_unit=/etc/systemd/user/noid-blocked-session-service.service
gnome_software_admin_service="$dbus_admin_dir/org.gnome.Software.service"
gnome_software_vendor_service="$dbus_vendor_dir/org.gnome.Software.service"
dbus_admin_names=(
    org.gnome.OnlineAccounts
    org.gnome.Identity
)
dbus_tracker_names=(
    org.freedesktop.Tracker3.Miner.Files
    org.freedesktop.Tracker3.Miner.Files.Control
    org.freedesktop.Tracker3.Writeback
    org.freedesktop.portal.Tracker
)
dbus_policy_names=(
    org.gnome.OnlineAccounts
    org.gnome.Identity
    "${dbus_tracker_names[@]}"
)
dbus_specs=(
    'org.gnome.Software|gnome-software'
    'org.gnome.OnlineAccounts|gnome-online-accounts'
    'org.gnome.Identity|gnome-online-accounts'
    'org.freedesktop.Tracker3.Miner.Files|localsearch'
    'org.freedesktop.Tracker3.Miner.Files.Control|localsearch'
    'org.freedesktop.Tracker3.Writeback|localsearch'
    'org.freedesktop.portal.Tracker|tinysparql'
)
m17_dbus_fail=0
if [ ! -L "$dbus_block_unit" ] \
   || [ "$(readlink "$dbus_block_unit" 2>/dev/null || true)" != /dev/null ] \
   || [ -e "$gnome_software_admin_service" ] \
   || [ -L "$gnome_software_admin_service" ] \
   || ! grep -qxF 'SystemdService=gnome-software.service' \
        "$gnome_software_vendor_service"; then
    m17_dbus_fail=1
fi
for service_name in "${dbus_admin_names[@]}"; do
    admin_file="$dbus_admin_dir/${service_name}.service"
    if [ "$(stat -c '%U:%G:%a' "$admin_file" 2>/dev/null || true)" != \
         root:root:644 ] \
       || [ "$(wc -l < "$admin_file" 2>/dev/null || true)" -ne 4 ] \
       || ! grep -qxF '[D-BUS Service]' "$admin_file" \
       || ! grep -qxF "Name=$service_name" "$admin_file" \
       || ! grep -qxF 'Exec=/bin/false' "$admin_file" \
       || ! grep -qxF \
            'SystemdService=noid-blocked-session-service.service' "$admin_file" \
       || ! matchpathcon -V "$admin_file" >/dev/null 2>&1; then
        m17_dbus_fail=1
    fi
done
for service_name in "${dbus_tracker_names[@]}"; do
    admin_file="$dbus_admin_dir/${service_name}.service"
    if [ -e "$admin_file" ] || [ -L "$admin_file" ]; then
        m17_dbus_fail=1
    fi
done
if [ "$(stat -c '%U:%G:%a' "$dbus_policy" 2>/dev/null || true)" != \
     root:root:644 ] \
   || [ "$(grep -c '^[[:space:]]*<deny send_destination=' \
        "$dbus_policy" 2>/dev/null || true)" -ne "${#dbus_policy_names[@]}" ] \
   || ! grep -qxF '  <policy context="mandatory">' "$dbus_policy" \
   || ! matchpathcon -V "$dbus_policy" >/dev/null 2>&1; then
    m17_dbus_fail=1
fi
for service_name in "${dbus_policy_names[@]}"; do
    if ! grep -qxF \
            "    <deny send_destination=\"$service_name\"/>" "$dbus_policy"; then
        m17_dbus_fail=1
    fi
done
for spec in "${dbus_specs[@]}"; do
    IFS='|' read -r service_name vendor_package <<< "$spec"
    vendor_file="$dbus_vendor_dir/${service_name}.service"
    if [ ! -f "$vendor_file" ] || [ -L "$vendor_file" ] \
       || [ "$(rpm -qf --qf '%{NAME}\n' "$vendor_file" 2>/dev/null || true)" != \
            "$vendor_package" ]; then
        m17_dbus_fail=1
        continue
    fi
    dump_record=$(rpm -q --dump "$vendor_package" 2>/dev/null | \
        awk -v path="$vendor_file" '$1 == path {print; found=1} END {exit !found}') || \
        dump_record=""
    read -r dump_path expected_size expected_mtime expected_sha expected_mode \
        expected_owner expected_group dump_config dump_doc dump_rdev dump_caps \
        dump_extra <<< "$dump_record"
    if [ "$dump_path" != "$vendor_file" ] \
       || [ "$expected_mode" != 0100644 ] \
       || [ "${dump_config:-}:${dump_doc:-}:${dump_rdev:-}:${dump_caps:-}" != \
            0:0:0:X ] \
       || [ -n "${dump_extra:-}" ] \
       || [ "$(stat -c '%s:%Y:%U:%G:%a' "$vendor_file" 2>/dev/null || true)" != \
            "$expected_size:$expected_mtime:$expected_owner:$expected_group:644" ] \
       || [ "$(sha256sum "$vendor_file" | awk '{print $1}')" != "$expected_sha" ]; then
        m17_dbus_fail=1
    fi
done
if [ "$m17_dbus_fail" -ne 0 ]; then
    log "  FAIL: Module 17 immediate D-Bus denial/vendor-integrity contract invalid"
    fail=$((fail + 1))
fi

# GNOME Software uses a deliberately split XDG contract. Fedora's native
# session-bus descriptor routes unsolicited activation to the global unit
# mask. A separate admin desktop entry is generated from the exact RPM
# launcher with DBusActivatable=false plus standard actions for the named
# Fedora-RPM one-shot and GNOME Software's graceful --quit path with an
# idle-only DNF5 release, so an intentional app-grid click follows Exec instead
# of the denied service path. The package-scoped action keeps that copy current.
m17_gs_vendor_desktop=/usr/share/applications/org.gnome.Software.desktop
m17_gs_admin_desktop=/usr/local/share/applications/org.gnome.Software.desktop
m17_gs_sync=/usr/local/sbin/noid-gnome-software-launcher-sync
m17_gs_action=/etc/dnf/libdnf5-plugins/actions.d/noid-gnome-software-launcher.actions
m17_gs_quit=/usr/local/bin/noid-gnome-software-quit
m17_gs_rpm=/usr/local/bin/noid-gnome-software-rpm
m17_gs_backend_stop=/usr/local/sbin/noid-gnome-software-backend-stop
m17_gs_sudoers=/etc/sudoers.d/48-noid-gnome-software-quit
m17_gs_expected=$(mktemp -d /var/tmp/noid-m99-gs-launcher.XXXXXXXX)
m17_gs_fail=0
if [ "$(stat -c '%U:%G:%a' "$m17_gs_sync" 2>/dev/null || true)" != \
     root:root:755 ] \
   || ! grep -qF 'rpm -q --dump "$EXPECTED_PACKAGE"' "$m17_gs_sync" \
   || ! grep -qF 'mv -fT -- "$candidate" "$ADMIN_FILE"' "$m17_gs_sync" \
   || [ ! -f "$m17_gs_quit" ] \
   || [ -L "$m17_gs_quit" ] \
   || [ "$(stat -c '%U:%G:%a' "$m17_gs_quit" 2>/dev/null || true)" != \
        root:root:755 ] \
   || ! bash -n "$m17_gs_quit" \
   || ! grep -qxF \
        '/usr/bin/sudo -n /usr/local/sbin/noid-gnome-software-backend-stop' \
        "$m17_gs_quit" \
   || [ ! -f "$m17_gs_rpm" ] \
   || [ -L "$m17_gs_rpm" ] \
   || [ "$(stat -c '%U:%G:%a' "$m17_gs_rpm" 2>/dev/null || true)" != \
        root:root:755 ] \
   || ! bash -n "$m17_gs_rpm" \
   || ! grep -qxF \
        'RPM_PLUGINS=flatpak,appstream,dnf5,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates' \
        "$m17_gs_rpm" \
   || ! grep -qxF 'exec "$SOFTWARE"' "$m17_gs_rpm" \
   || grep -qF 'fwupd' "$m17_gs_rpm" \
   || [ ! -f "$m17_gs_backend_stop" ] \
   || [ -L "$m17_gs_backend_stop" ] \
   || [ "$(stat -c '%U:%G:%a' "$m17_gs_backend_stop" 2>/dev/null || true)" != \
        root:root:755 ] \
   || ! bash -n "$m17_gs_backend_stop" \
   || ! grep -qF "expected_tree=\$'/\\n/org\\n/org/rpm\\n/org/rpm/dnf\\n/org/rpm/dnf/v0'" \
        "$m17_gs_backend_stop" \
   || ! grep -qxF '/usr/bin/systemctl stop "$unit"' "$m17_gs_backend_stop" \
   || [ ! -f "$m17_gs_sudoers" ] \
   || [ -L "$m17_gs_sudoers" ] \
   || [ "$(stat -c '%U:%G:%a' "$m17_gs_sudoers" 2>/dev/null || true)" != \
        root:root:440 ] \
   || [ "$(grep -cEv '^[[:space:]]*(#|$)' \
        "$m17_gs_sudoers" 2>/dev/null || true)" -ne 1 ] \
   || ! grep -qxF \
        '%wheel ALL=(root) NOPASSWD: /usr/local/sbin/noid-gnome-software-backend-stop ""' \
        "$m17_gs_sudoers" \
   || ! visudo -cf "$m17_gs_sudoers" >/dev/null 2>&1 \
   || [ "$(stat -c '%U:%G:%a' "$m17_gs_action" 2>/dev/null || true)" != \
        root:root:644 ] \
   || ! grep -qxF \
        'post_transaction:gnome-software:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-gnome-software-launcher-sync\ >/dev/null' \
        "$m17_gs_action"; then
    m17_gs_fail=1
fi
if [ ! -f "$m17_gs_vendor_desktop" ] \
   || [ -L "$m17_gs_vendor_desktop" ] \
   || [ "$(rpm -qf --qf '%{NAME}\n' "$m17_gs_vendor_desktop" 2>/dev/null || true)" != \
        gnome-software ]; then
    m17_gs_fail=1
else
    dump_record=$(rpm -q --dump gnome-software 2>/dev/null | \
        awk -v path="$m17_gs_vendor_desktop" \
            '$1 == path {print; found=1} END {exit !found}') || dump_record=""
    read -r dump_path expected_size expected_mtime expected_sha expected_mode \
        expected_owner expected_group dump_config dump_doc dump_rdev dump_caps \
        dump_extra <<< "$dump_record"
    if [ "$dump_path" != "$m17_gs_vendor_desktop" ] \
       || [ "$expected_mode" != 0100644 ] \
       || [ "${dump_config:-}:${dump_doc:-}:${dump_rdev:-}:${dump_caps:-}" != \
            0:0:0:X ] \
       || [ -n "${dump_extra:-}" ] \
       || [ "$(stat -c '%s:%Y:%U:%G:%a' "$m17_gs_vendor_desktop" 2>/dev/null || true)" != \
            "$expected_size:$expected_mtime:$expected_owner:$expected_group:644" ] \
       || [ "$(sha256sum "$m17_gs_vendor_desktop" | awk '{print $1}')" != \
            "$expected_sha" ]; then
        m17_gs_fail=1
    fi
fi
m17_gs_vendor_actions_count=$(awk '
    $0 == "[Desktop Entry]" { in_entry=1; next }
    /^\[/ { in_entry=0 }
    in_entry && /^Actions=/ { count++ }
    END { print count + 0 }
' "$m17_gs_vendor_desktop" 2>/dev/null || true)
m17_gs_vendor_actions_count=${m17_gs_vendor_actions_count:-0}
m17_gs_vendor_actions=$(awk '
    $0 == "[Desktop Entry]" { in_entry=1; next }
    /^\[/ { in_entry=0 }
    in_entry && /^Actions=/ { print substr($0, 9) }
' "$m17_gs_vendor_desktop" 2>/dev/null || true)
m17_gs_vendor_actions=${m17_gs_vendor_actions%;}
if [ -n "$m17_gs_vendor_actions" ]; then
    m17_gs_admin_actions="$m17_gs_vendor_actions;NoIDFedoraRPM;NoIDQuit;"
else
    m17_gs_admin_actions='NoIDFedoraRPM;NoIDQuit;'
fi
m17_gs_expected_file="$m17_gs_expected/org.gnome.Software.desktop"
m17_gs_expected_ok=1
if [ "$m17_gs_vendor_actions_count" -gt 1 ] \
   || [[ ";$m17_gs_vendor_actions;" == *';NoIDFedoraRPM;'* ]] \
   || [[ ";$m17_gs_vendor_actions;" == *';NoIDQuit;'* ]] \
   || grep -Eq '^\[Desktop Action (NoIDFedoraRPM|NoIDQuit)\]$' \
        "$m17_gs_vendor_desktop" \
   || ! desktop-file-install --dir="$m17_gs_expected" --mode=0644 \
        --set-key=DBusActivatable --set-value=false \
        "$m17_gs_vendor_desktop" \
   || ! printf '\n[Desktop Action NoIDFedoraRPM]\nName=Open GNOME Software with Fedora RPMs\nName[de]=GNOME Software mit Fedora-RPMs öffnen\nExec=/usr/local/bin/noid-gnome-software-rpm\n\n[Desktop Action NoIDQuit]\nName=Quit completely\nName[de]=Vollständig beenden\nExec=/usr/local/bin/noid-gnome-software-quit\n' \
        >> "$m17_gs_expected_file" \
   || ! desktop-file-edit --set-key=Actions \
        --set-value="$m17_gs_admin_actions" "$m17_gs_expected_file"; then
    m17_gs_expected_ok=0
fi
if [ "$m17_gs_expected_ok" -ne 1 ] \
   || [ "$(stat -c '%U:%G:%a' "$m17_gs_admin_desktop" 2>/dev/null || true)" != \
        root:root:644 ] \
   || ! matchpathcon -V "$m17_gs_admin_desktop" >/dev/null 2>&1 \
   || ! desktop-file-validate "$m17_gs_admin_desktop" \
   || ! cmp -s "$m17_gs_expected_file" \
        "$m17_gs_admin_desktop" \
   || ! grep -qxF 'DBusActivatable=false' "$m17_gs_admin_desktop" \
   || ! grep -qxF 'Exec=gnome-software %U' "$m17_gs_admin_desktop" \
   || ! grep -qxF "Actions=$m17_gs_admin_actions" \
        "$m17_gs_admin_desktop" \
   || [ "$(grep -c '^\[Desktop Action NoIDQuit\]$' \
        "$m17_gs_admin_desktop")" -ne 1 ] \
   || [ "$(grep -c '^\[Desktop Action NoIDFedoraRPM\]$' \
        "$m17_gs_admin_desktop")" -ne 1 ] \
   || ! grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-rpm' \
        "$m17_gs_admin_desktop" \
   || ! grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-quit' \
        "$m17_gs_admin_desktop"; then
    m17_gs_fail=1
fi
rm -rf -- "$m17_gs_expected"
if [ "$m17_gs_fail" -ne 0 ]; then
    log "  FAIL: Module 17 GNOME Software Flatpak/RPM/complete-quit split invalid"
    fail=$((fail + 1))
fi
unset m17_gs_vendor_desktop m17_gs_admin_desktop m17_gs_sync m17_gs_action \
    m17_gs_quit m17_gs_rpm m17_gs_backend_stop m17_gs_sudoers \
    m17_gs_expected m17_gs_fail m17_gs_vendor_actions_count \
    m17_gs_vendor_actions m17_gs_admin_actions m17_gs_expected_file \
    m17_gs_expected_ok
for obsolete in /usr/local/sbin/noid-dbus-suppress-reassert \
                /etc/dnf/libdnf5-plugins/actions.d/noid-dbus-suppress.actions; do
    if [ -e "$obsolete" ] || [ -L "$obsolete" ]; then
        log "  FAIL: Module 17 retired RPM rewrite artifact present: $obsolete"
        fail=$((fail + 1))
    fi
done

# Module 17 — first-login setup has three separately committed tasks. The
# update reminder is preset-enabled; M14's notifier is instead a root-owned
# static graphical-session link. Reject the former false-success sentinel,
# open-ended preset-all transaction and any attempt to preset the notifier.
m17_firstrun=/usr/local/libexec/noid-user-firstrun
m17_firstrun_unit=/usr/lib/systemd/user/noid-user-firstrun.service
m17_firstrun_wants=/usr/lib/systemd/user/graphical-session.target.wants/noid-user-firstrun.service
m17_firstrun_notifier=/usr/lib/systemd/user/usbguard-notifier.service
m17_firstrun_notifier_wants=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service
if [ "$(stat -c '%U:%G:%a' "$m17_firstrun" 2>/dev/null || true)" != root:root:755 ] \
   || [ "$(stat -c '%U:%G:%a' "$m17_firstrun_unit" 2>/dev/null || true)" != root:root:644 ] \
   || grep -qF 'preset-all' "$m17_firstrun" 2>/dev/null \
   || grep -qF 'ConditionPathExists=' "$m17_firstrun_unit" 2>/dev/null \
   || ! grep -qxF 'UPDATE_UNIT=noid-update-reminder.timer' "$m17_firstrun" \
   || ! grep -qxF 'NOTIFIER_UNIT=usbguard-notifier.service' "$m17_firstrun" \
   || ! grep -qxF 'NOTIFIER_WANTS=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service' "$m17_firstrun" \
   || ! grep -qxF 'NOTIFIER_TARGET=/usr/lib/systemd/user/usbguard-notifier.service' "$m17_firstrun" \
   || ! grep -qF 'systemctl --user preset "$UPDATE_UNIT"' "$m17_firstrun" \
   || ! grep -qF 'systemctl --user start "$UPDATE_UNIT"' "$m17_firstrun" \
   || ! grep -qF 'systemctl --user is-enabled --quiet "$UPDATE_UNIT"' "$m17_firstrun" \
   || ! grep -qF 'systemctl --user is-active --quiet "$UPDATE_UNIT"' "$m17_firstrun" \
   || grep -qF 'preset "$NOTIFIER_UNIT"' "$m17_firstrun" \
   || grep -qF 'is-enabled --quiet "$NOTIFIER_UNIT"' "$m17_firstrun" \
   || ! grep -qF '[[ -L "$NOTIFIER_WANTS" ]]' "$m17_firstrun" \
   || ! grep -qF 'readlink -- "$NOTIFIER_WANTS"' "$m17_firstrun" \
   || ! grep -qF 'systemctl --user start "$NOTIFIER_UNIT"' "$m17_firstrun" \
   || ! grep -qF 'systemctl --user is-active --quiet "$NOTIFIER_UNIT"' "$m17_firstrun" \
   || ! grep -qF 'mark_done complete' "$m17_firstrun" \
   || ! grep -qxF 'PartOf=graphical-session.target' "$m17_firstrun_unit" \
   || ! grep -qxF 'ConditionEnvironment=XDG_SESSION_CLASS=user' "$m17_firstrun_unit" \
   || ! grep -qxF 'ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target' \
        "$m17_firstrun_unit" \
   || ! grep -qF 'if [ "${XDG_SESSION_CLASS:-}" != user ]; then' "$m17_firstrun" \
   || ! grep -qF 'Restart=on-failure' "$m17_firstrun_unit" \
   || [ ! -L "$m17_firstrun_wants" ] \
   || [ "$(readlink "$m17_firstrun_wants" 2>/dev/null || true)" != "$m17_firstrun_unit" ] \
   || [ "$(stat -c '%U:%G:%a' "$m17_firstrun_notifier" 2>/dev/null || true)" != root:root:644 ] \
   || [ ! -L "$m17_firstrun_notifier_wants" ] \
   || [ "$(stat -c '%U:%G' "$m17_firstrun_notifier_wants" 2>/dev/null || true)" != root:root ] \
   || [ "$(readlink "$m17_firstrun_notifier_wants" 2>/dev/null || true)" != \
        "$m17_firstrun_notifier" ]; then
    log "  FAIL: Module 17 transactional per-task first-login contract invalid"
    fail=$((fail + 1))
fi

# Module 17 — microphone privacy has one native WirePlumber owner. The config
# component is required, the default is fail-closed, the control path is
# transactional, and every artifact of the retired one-shot must be absent.
m17_mic_conf=/etc/wireplumber/wireplumber.conf.d/90-noid-microphone-privacy.conf
m17_mic_lua=/usr/local/share/wireplumber/scripts/noid-microphone-privacy.lua
m17_mic_toggle=/usr/local/bin/noid-toggle-microphone
if [ "$(stat -c '%U:%G:%a' "$m17_mic_conf" 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(stat -c '%U:%G:%a' "$m17_mic_lua" 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(stat -c '%U:%G:%a' "$m17_mic_toggle" 2>/dev/null || true)" != root:root:755 ] \
   || ! spa-json-dump "$m17_mic_conf" >/dev/null 2>&1 \
   || ! bash -n "$m17_mic_toggle" \
   || ! grep -qF 'noid.microphone.privacy = required' "$m17_mic_conf" \
   || ! grep -qF 'api.mixer' "$m17_mic_conf" \
   || ! grep -qF 'default = true' "$m17_mic_conf" \
   || ! grep -qF 'ENFORCEMENT_INTERVAL_MSEC = 1000' "$m17_mic_lua" \
   || ! grep -qF 'Plugin.find ("mixer-api")' "$m17_mic_lua" \
   || ! grep -qF 'mixer:connect ("changed"' "$m17_mic_lua" \
   || ! grep -qF 'mixer:call ("set-volume"' "$m17_mic_lua" \
   || ! grep -qF 'wpctl settings --save "$WP_KEY" "$value"' "$m17_mic_toggle"; then
    log "  FAIL: Module 17 persistent WirePlumber microphone policy invalid"
    fail=$((fail + 1))
fi
for obsolete_mic in \
    /usr/local/libexec/noid-mic-privacy-enforce \
    /usr/lib/systemd/user/noid-mic-privacy-enforce.service \
    /usr/lib/systemd/user/graphical-session.target.wants/noid-mic-privacy-enforce.service; do
    if [ -e "$obsolete_mic" ] || [ -L "$obsolete_mic" ]; then
        log "  FAIL: Module 17 retired one-shot microphone enforcer present: $obsolete_mic"
        fail=$((fail + 1))
    fi
done

# Module 17 — GNOME privacy cleanup is a shutdown action, not a concurrent
# graphical-target ExecStop. It never owns Mozilla recovery locks, and the
# recursive cache path is bounded by the kernel's openat2 resolver. Missing
# per-user files are a valid clean state; the package-owned producer contract
# makes an upstream schema rename transaction-visible instead.
m17_privacy_contract=/usr/local/sbin/noid-verify-gnome-privacy-contract
m17_privacy_action=/etc/dnf/libdnf5-plugins/actions.d/noid-gnome-privacy-contract.actions
m17_cleanup=/usr/local/libexec/noid-gnome-privacy-cleanup
m17_cleanup_unit=/etc/systemd/user/noid-gnome-shell-privacy-cleanup.service
m17_cleanup_wants=/etc/systemd/user/gnome-session-shutdown.target.wants/noid-gnome-shell-privacy-cleanup.service
m17_cleanup_old_wants=/etc/systemd/user/graphical-session.target.wants/noid-gnome-shell-privacy-cleanup.service
if [ "$(stat -c '%U:%G:%a' "$m17_privacy_contract" 2>/dev/null || true)" != root:root:755 ] \
   || ! bash -n "$m17_privacy_contract" \
   || ! grep -qF 'for state_name in application_state session-active-history.json' \
        "$m17_privacy_contract" \
   || [ "$(stat -c '%U:%G:%a' "$m17_privacy_action" 2>/dev/null || true)" != root:root:644 ] \
   || ! grep -qxF \
        'post_transaction:gnome-shell:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-verify-gnome-privacy-contract\ >/dev/null' \
        "$m17_privacy_action" \
   || ! "$m17_privacy_contract" >/dev/null \
   || [ "$(stat -c '%U:%G:%a' "$m17_cleanup" 2>/dev/null || true)" != root:root:755 ] \
   || [ "$(stat -c '%U:%G:%a' "$m17_cleanup_unit" 2>/dev/null || true)" != root:root:644 ] \
   || ! python3 -c 'import pathlib; p=pathlib.Path("/usr/local/libexec/noid-gnome-privacy-cleanup"); compile(p.read_bytes(), str(p), "exec")' \
   || ! grep -qF 'RESOLVE_NO_XDEV' "$m17_cleanup" \
   || ! grep -qF 'RESOLVE_NO_SYMLINKS' "$m17_cleanup" \
   || ! grep -qF '_preflight_tree(tree_fd, label)' "$m17_cleanup" \
   || grep -Eq '\.thunderbird|\.parentlock|\.mozilla/firefox|\.config/mozilla/firefox' "$m17_cleanup" \
   || ! grep -qxF 'DefaultDependencies=no' "$m17_cleanup_unit" \
   || ! grep -qxF 'Slice=-.slice' "$m17_cleanup_unit" \
   || ! grep -qxF 'Before=gnome-session-shutdown.target gnome-session-restart-dbus.service' "$m17_cleanup_unit" \
   || ! grep -qxF 'ExecStart=/usr/local/libexec/noid-gnome-privacy-cleanup' "$m17_cleanup_unit" \
   || ! grep -qxF 'WantedBy=gnome-session-shutdown.target' "$m17_cleanup_unit" \
   || grep -q '^ExecStop=' "$m17_cleanup_unit" \
   || [ ! -L "$m17_cleanup_wants" ] \
   || [ "$(readlink -f "$m17_cleanup_wants" 2>/dev/null || true)" != "$m17_cleanup_unit" ] \
   || [ -e "$m17_cleanup_old_wants" ] || [ -L "$m17_cleanup_old_wants" ]; then
    log "  FAIL: Module 17 GNOME privacy producer/cleanup contract invalid"
    fail=$((fail + 1))
fi
unset m17_privacy_contract m17_privacy_action

# Module 17 — GJS/WebKitGTK JIT disablement is a measured, reversible
# application default, not a memory-safety or sandbox substitute.
m17_jit_env=/etc/environment.d/40-noid-disable-jit.conf
m17_gnome_doc=/usr/share/doc/noid-privacy/17-gnome-hardening.md
if [ "$(stat -c '%U:%G:%a' "$m17_jit_env" 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(grep -Ec '^(JavaScriptCoreUseJIT|GJS_DISABLE_JIT)=' "$m17_jit_env" 2>/dev/null || true)" -ne 2 ] \
   || ! grep -qxF 'JavaScriptCoreUseJIT=0' "$m17_jit_env" \
   || ! grep -qxF 'GJS_DISABLE_JIT=1' "$m17_jit_env" \
   || [ "$(stat -c '%U:%G:%a' "$m17_gnome_doc" 2>/dev/null || true)" != root:root:644 ] \
   || ! grep -qF 'It does not make either engine memory-safe' "$m17_gnome_doc" \
   || ! grep -qF 'env -u GJS_DISABLE_JIT gjs-application' "$m17_gnome_doc" \
   || ! grep -qF 'env JavaScriptCoreUseJIT=1 webkit-application' "$m17_gnome_doc"; then
    log "  FAIL: Module 17 evidence-bounded application-overridable JIT defaults invalid"
    fail=$((fail + 1))
fi

# Module 17 — GTK/Qt native-Wayland selection is a strict application default,
# not an enforcement boundary. Bind the installed bytes to the documented,
# explicit Xwayland recovery paths so a future edit cannot silently turn the
# compatibility default into an overclaim or an unrecoverable setting.
m17_wayland_env=/etc/environment.d/45-noid-wayland.conf
m17_gnome_doc=/usr/share/doc/noid-privacy/17-gnome-hardening.md
if [ "$(stat -c '%U:%G:%a' "$m17_wayland_env" 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(grep -Ec '^(GDK_BACKEND|QT_QPA_PLATFORM)=' "$m17_wayland_env" 2>/dev/null || true)" -ne 2 ] \
   || ! grep -qxF 'GDK_BACKEND=wayland' "$m17_wayland_env" \
   || ! grep -qxF 'QT_QPA_PLATFORM=wayland' "$m17_wayland_env" \
   || [ "$(stat -c '%U:%G:%a' "$m17_gnome_doc" 2>/dev/null || true)" != root:root:644 ] \
   || ! grep -qF 'they are not an enforcement or anti-downgrade boundary' "$m17_gnome_doc" \
   || ! grep -qF 'env GDK_BACKEND=x11 gtk-application' "$m17_gnome_doc" \
   || ! grep -qF 'env QT_QPA_PLATFORM=xcb qt-application' "$m17_gnome_doc" \
   || ! grep -qF 'qt-application -platform xcb' "$m17_gnome_doc"; then
    log "  FAIL: Module 17 strict application-overridable Wayland defaults invalid"
    fail=$((fail + 1))
fi

# Module 17 — Live-mode default.target = graphical.target
m17_default=$(systemctl get-default 2>/dev/null || echo "unknown")
if [ "$m17_default" != "graphical.target" ]; then
    log "  FAIL: Module 17 default.target is $m17_default (expected graphical.target)"
    fail=$((fail + 1))
fi

# Module 18 — Flatpak sandboxing, exact remote trust and Silent-Machine policy
if [ ! -f /usr/share/doc/noid-privacy/18-flatpak-trust-model.md ]; then
    log "  FAIL: Module 18 missing: /usr/share/doc/noid-privacy/18-flatpak-trust-model.md"
    fail=$((fail + 1))
fi
# Silent-Machine: firstboot script + service must ABSENT (auto-install removed)
for f in /usr/local/bin/noid-flatseal-install.sh \
         /etc/systemd/system/noid-flatseal-install.service \
         /etc/systemd/system/multi-user.target.wants/noid-flatseal-install.service; do
    if [ -e "$f" ]; then
        log "  FAIL: Module 18 Silent-Machine violation — $f should be ABSENT"
        fail=$((fail + 1))
    fi
done
# Module 18 — Flatpak global overrides must be set (binary check via flatpak CLI)
# grep patterns updated to match flatpak override --show
# INI output format ([System Bus Policy] / [Session Bus Policy] sections with
# `key=none`), NOT the CLI option names. Same fix as M18 verification.
if ! command -v flatpak >/dev/null 2>&1; then
    log "  FAIL: Module 18 flatpak binary missing"
    fail=$((fail + 1))
else
    fp_version=$(flatpak --version 2>/dev/null | awk '{print $2}' || true)
    fp_lowest=$(printf '%s\n%s\n' "$fp_version" 1.18.1 | sort -V | head -n 1)
    if [ -z "$fp_version" ] || [ "$fp_lowest" != 1.18.1 ]; then
        log "  FAIL: Module 18 Flatpak version below 1.18.1 security baseline: ${fp_version:-unknown}"
        fail=$((fail + 1))
    fi
    if ! portal_version=$(rpm -q --queryformat '%{VERSION}' \
            xdg-desktop-portal 2>/dev/null); then
        portal_version=""
    fi
    portal_lowest=$(printf '%s\n%s\n' "$portal_version" 1.22.1 | sort -V | head -n 1)
    if [ -z "$portal_version" ] || [ "$portal_lowest" != 1.22.1 ]; then
        log "  FAIL: Module 18 xdg-desktop-portal version below 1.22.1 security baseline: ${portal_version:-unknown}"
        fail=$((fail + 1))
    fi
    if [ ! -x /usr/bin/bwrap ] || [ -u /usr/bin/bwrap ]; then
        log "  FAIL: Module 18 bubblewrap missing, non-executable or setuid"
        fail=$((fail + 1))
    fi
    fp_overrides=$(flatpak override --show 2>/dev/null || true)
    # Section-scoped, not a bare substring: org.freedesktop.systemd1 is owned
    # on BOTH buses -- by PID 1 on the system bus and by the per-user manager
    # on the session bus -- and a substring grep is satisfied by either entry
    # alone. That is exactly how the missing session-bus deny survived review
    # while StartTransientUnit on the user manager still spawned host
    # processes out of the sandbox.
    fp_session_policy=$(printf '%s\n' "$fp_overrides" \
        | awk '/^\[Session Bus Policy\]$/{f=1;next} /^\[/{f=0} f')
    fp_system_policy=$(printf '%s\n' "$fp_overrides" \
        | awk '/^\[System Bus Policy\]$/{f=1;next} /^\[/{f=0} f')
    for ov in "org.freedesktop.systemd1=none" \
              "org.freedesktop.Flatpak=none"; do
        if ! printf '%s\n' "$fp_session_policy" | grep -qxF -- "$ov"; then
            log "  FAIL: Module 18 session-bus override missing: $ov"
            fail=$((fail + 1))
        fi
    done
    for ov in "org.freedesktop.systemd1=none" \
              "org.freedesktop.PackageKit=none"; do
        if ! printf '%s\n' "$fp_system_policy" | grep -qxF -- "$ov"; then
            log "  FAIL: Module 18 system-bus override missing: $ov"
            fail=$((fail + 1))
        fi
    done
    if [ ! -f /usr/local/libexec/noid-flatpak-remote-policy ] \
       || [ -L /usr/local/libexec/noid-flatpak-remote-policy ] \
       || [ ! -x /usr/local/libexec/noid-flatpak-remote-policy ]; then
        log "  FAIL: Module 18 exact remote-policy controller missing or invalid"
        fail=$((fail + 1))
    elif ! /usr/local/libexec/noid-flatpak-remote-policy verify-default \
            >/dev/null 2>&1; then
        log "  FAIL: Module 18 exact Flathub config/key/catalog policy failed"
        fail=$((fail + 1))
    fi
    if [ ! -L /etc/systemd/system/flatpak-add-fedora-repos.service ] \
       || [ "$(readlink -f /etc/systemd/system/flatpak-add-fedora-repos.service 2>/dev/null || true)" != /dev/null ] \
       || [ "$(systemctl is-enabled flatpak-add-fedora-repos.service 2>/dev/null || true)" != masked ]; then
        log "  FAIL: Module 18 Fedora Flatpak auto-add unit is not natively masked"
        fail=$((fail + 1))
    fi
    if [ -e /var/lib/flatpak/.fedora-initialized ]; then
        log "  FAIL: Module 18 forged Fedora Flatpak initialization sentinel present"
        fail=$((fail + 1))
    fi
fi

# Module 19 — NVIDIA + Secure Boot MOK documentation and opt-in workflow.
for f in /usr/share/doc/noid-privacy/19-nvidia-drivers.md \
         /usr/share/doc/noid-privacy/19-secure-boot-mok.md; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 19 doc missing: $f"
        fail=$((fail + 1))
    fi
done
# Module 19 — sanity: docs must have non-trivial content (not empty heredoc)
for f in /usr/share/doc/noid-privacy/19-nvidia-drivers.md \
         /usr/share/doc/noid-privacy/19-secure-boot-mok.md; do
    if [ -f "$f" ]; then
        size=$(stat -c %s "$f" 2>/dev/null || echo 0)
        size=${size:-0}
        if [ "$size" -lt 1024 ]; then
            log "  FAIL: Module 19 doc $f too small (${size} bytes, expected >1KB)"
            fail=$((fail + 1))
        fi
    fi
done
# Module 19 — sanity: image must NOT have accidentally installed NVIDIA RPMs
nvidia_rpm_count=$(rpm -qa 2>/dev/null | grep -ciE '^(akmod-nvidia|kmod-nvidia|nvidia-settings|nvidia-persistenced|xorg-x11-drv-nvidia)' || true)
nvidia_rpm_count=${nvidia_rpm_count:-0}
if [ "$nvidia_rpm_count" -gt 0 ]; then
    log "  FAIL: Module 19 defers NVIDIA install to user, but $nvidia_rpm_count NVIDIA RPM(s) found in image"
    fail=$((fail + 1))
fi
# Module 19 — Stage 1 install helper noid-nvidia-install.sh
if [ ! -f /usr/local/bin/noid-nvidia-install.sh ]; then
    log "  FAIL: Module 19 install helper missing: /usr/local/bin/noid-nvidia-install.sh"
    fail=$((fail + 1))
fi
if [ ! -x /usr/local/bin/noid-nvidia-install.sh ]; then
    log "  FAIL: Module 19 install helper not executable"
    fail=$((fail + 1))
fi
nvi_perm=$(stat -c %a /usr/local/bin/noid-nvidia-install.sh 2>/dev/null || echo 000)
if [ "$nvi_perm" != "755" ]; then
    log "  FAIL: Module 19 install helper wrong perms ($nvi_perm, expected 755)"
    fail=$((fail + 1))
fi
for nvidia_action_pkg in akmod-nvidia akmod-nvidia-580xx; do
    if ! grep -qxF \
        "post_transaction:${nvidia_action_pkg}:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/libexec/noid-nvidia-initramfs-dnf-action\\ >/dev/null" \
        /usr/local/bin/noid-nvidia-install.sh 2>/dev/null; then
        log "  FAIL: Module 19 NVIDIA installer lacks host-scoped action: $nvidia_action_pkg"
        fail=$((fail + 1))
    fi
done
unset nvidia_action_pkg
# Module 19 — exact portable NVIDIA-offload GTK renderer policy.
gsk_toggle=/usr/local/bin/noid-toggle-gsk-gl
gsk_matcher=/usr/libexec/noid-gsk-hybrid-match
gsk_wrapper=/usr/local/bin/gnome-control-center
gsk_software_wrapper=/usr/local/bin/gnome-software
gsk_session_helper=/usr/libexec/noid-gsk-session-environment
gsk_session_unit=/usr/lib/systemd/user/noid-gsk-session-environment.service
gsk_session_enable=/etc/systemd/user/gnome-session.target.wants/noid-gsk-session-environment.service
gsk_launcher_sync=/usr/libexec/noid-gsk-settings-launcher-sync
gsk_launcher=/usr/local/share/applications/org.gnome.Settings.desktop
gsk_action=/etc/dnf/libdnf5-plugins/actions.d/noid-gsk-settings-launcher.actions
verify_gsk_user_unit() {
    local unit_path="$1" runtime_parent="${2:-/run}"
    local runtime_dir metadata unit_dir rc=0
    [ -f "$unit_path" ] && [ ! -L "$unit_path" ] || return 1
    [ -d "$runtime_parent" ] && [ ! -L "$runtime_parent" ] || return 1
    runtime_dir=$(mktemp -d \
        "$runtime_parent/noid-m19-systemd-verify.XXXXXX") || return 1
    metadata=$(LC_ALL=C stat -c '%u:%g:%a:%F' "$runtime_dir" \
        2>/dev/null || true)
    [ "$metadata" = \
        "$(id -u):$(id -g):700:directory" ] || rc=1
    unit_dir=$(dirname -- "$unit_path")
    if [ "$rc" -eq 0 ] \
       && ! /usr/bin/env -i \
            PATH=/usr/sbin:/usr/bin HOME="$runtime_parent" LC_ALL=C \
            XDG_RUNTIME_DIR="$runtime_dir" \
            SYSTEMD_UNIT_PATH="$unit_dir:/etc/systemd/user:/usr/lib/systemd/user" \
            /usr/bin/systemd-analyze --user --recursive-errors=no \
            verify "$unit_path"; then
        rc=1
    fi
    # systemd-analyze creates XDG_RUNTIME_DIR/systemd during offline verify.
    # Delete only children of this freshly created, private mount boundary.
    if ! find "$runtime_dir" -xdev -mindepth 1 -delete 2>/dev/null \
       || ! rmdir -- "$runtime_dir" 2>/dev/null; then
        rc=1
    fi
    return "$rc"
}
if [ ! -f "$gsk_toggle" ] || [ -L "$gsk_toggle" ] || [ ! -x "$gsk_toggle" ]; then
    log "  FAIL: Module 19 GTK renderer toggle missing, symlinked or not executable"
    fail=$((fail + 1))
elif [ "$(stat -c '%U:%G:%a' "$gsk_toggle" 2>/dev/null || true)" != root:root:755 ] \
        || ! bash -n "$gsk_toggle" 2>/dev/null \
        || ! grep -qF "GSK_RENDERER=gl" "$gsk_toggle" \
        || grep -qF "GSK_RENDERER=ngl" "$gsk_toggle"; then
    log "  FAIL: Module 19 GTK renderer toggle bytes or metadata are invalid"
    fail=$((fail + 1))
fi
for gsk_policy_file in "$gsk_matcher" "$gsk_wrapper" "$gsk_software_wrapper" \
        "$gsk_session_helper" "$gsk_launcher_sync"; do
    if [ ! -f "$gsk_policy_file" ] || [ -L "$gsk_policy_file" ] \
            || [ ! -x "$gsk_policy_file" ] \
            || [ "$(stat -c '%U:%G:%a' "$gsk_policy_file" 2>/dev/null || true)" != root:root:755 ] \
            || ! bash -n "$gsk_policy_file" 2>/dev/null; then
        log "  FAIL: Module 19 GTK topology policy file is invalid: $gsk_policy_file"
        fail=$((fail + 1))
    fi
done
if grep -qE 'systemctl|--gapplication-service|--autostart' \
        "$gsk_software_wrapper" 2>/dev/null; then
    log "  FAIL: Module 19 GNOME Software wrapper can manage/background-start the service"
    fail=$((fail + 1))
fi
if ! grep -qxF \
        'NOID_SOFTWARE_PLUGINS=flatpak,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates' \
        "$gsk_software_wrapper" 2>/dev/null \
   || ! grep -qxF \
        '    export GNOME_SOFTWARE_PLUGINS_ALLOWLIST="$NOID_SOFTWARE_PLUGINS"' \
        "$gsk_software_wrapper" 2>/dev/null; then
    log "  FAIL: Module 19 GNOME Software explicit Flatpak-store scope is invalid"
    fail=$((fail + 1))
fi
if [ ! -f "$gsk_session_unit" ] || [ -L "$gsk_session_unit" ] \
        || [ "$(stat -c '%U:%G:%a' "$gsk_session_unit" 2>/dev/null || true)" != root:root:644 ] \
        || ! verify_gsk_user_unit "$gsk_session_unit" \
            >/dev/null 2>&1; then
    log "  FAIL: Module 19 post-Shell GTK user unit is invalid"
    fail=$((fail + 1))
fi
if ! grep -qxF 'RestrictAddressFamilies=AF_UNIX' "$gsk_session_unit" \
        || grep -qE '^(PrivateNetwork|IPAddressDeny)=' "$gsk_session_unit"; then
    log "  FAIL: Module 19 GTK session user unit network boundary is invalid"
    fail=$((fail + 1))
fi
if [ ! -L "$gsk_session_enable" ] \
        || [ "$(readlink "$gsk_session_enable" 2>/dev/null || true)" != \
             "$gsk_session_unit" ]; then
    log "  FAIL: Module 19 post-Shell GTK user unit global enablement is invalid"
    fail=$((fail + 1))
fi
if [ -e /etc/systemd/user/noid-gsk-session-environment.service ] \
        || [ -L /etc/systemd/user/noid-gsk-session-environment.service ]; then
    log "  FAIL: Module 19 distribution GTK user unit has an administrator shadow"
    fail=$((fail + 1))
fi
if [ ! -f "$gsk_launcher" ] || [ -L "$gsk_launcher" ] \
        || [ "$(stat -c '%U:%G:%a' "$gsk_launcher" 2>/dev/null || true)" != root:root:644 ] \
        || ! grep -qxF 'Exec=/usr/local/bin/gnome-control-center' "$gsk_launcher" \
        || ! grep -qxF 'DBusActivatable=false' "$gsk_launcher" \
        || grep -q '^DBusActivatable=true$' "$gsk_launcher" \
        || ! desktop-file-validate "$gsk_launcher" >/dev/null 2>&1; then
    log "  FAIL: Module 19 GNOME Settings XDG launcher contract is invalid"
    fail=$((fail + 1))
fi
if ! grep -qxF \
        'post_transaction:gnome-control-center:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/libexec/noid-gsk-settings-launcher-sync\ >/dev/null' \
        "$gsk_action" 2>/dev/null; then
    log "  FAIL: Module 19 GNOME Settings launcher dnf5 action is invalid"
    fail=$((fail + 1))
fi
if [ -e /usr/local/share/dbus-1/services/org.gnome.Settings.service ] \
        || [ -L /usr/local/share/dbus-1/services/org.gnome.Settings.service ]; then
    log "  FAIL: Module 19 obsolete duplicate GNOME Settings D-Bus shadow exists"
    fail=$((fail + 1))
fi
if [ -e /etc/environment.d/90-noid-gsk-renderer.conf ] \
        || [ -L /etc/environment.d/90-noid-gsk-renderer.conf ]; then
    log "  FAIL: Module 19 GTK renderer static override was activated during compose"
    fail=$((fail + 1))
fi
if [ -e /etc/xdg/noid-privacy/gsk-renderer.mode ] \
        || [ -L /etc/xdg/noid-privacy/gsk-renderer.mode ]; then
    log "  FAIL: Module 19 GTK renderer mode override was activated during compose"
    fail=$((fail + 1))
fi
if [ -e /usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer ] \
        || [ -L /usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer ]; then
    log "  FAIL: Module 19 retired GTK renderer vendor generator exists"
    fail=$((fail + 1))
fi
if [ -e /etc/systemd/user-environment-generators/55-noid-gsk-renderer ] \
        || [ -L /etc/systemd/user-environment-generators/55-noid-gsk-renderer ]; then
    log "  FAIL: Module 19 legacy GTK generator override exists during compose"
    fail=$((fail + 1))
fi

# Module 22 — LUKS backup wrapper noid-luks-backup.sh
if [ ! -f /usr/local/bin/noid-luks-backup.sh ]; then
    log "  FAIL: Module 22 helper missing: /usr/local/bin/noid-luks-backup.sh"
    fail=$((fail + 1))
fi
if [ ! -x /usr/local/bin/noid-luks-backup.sh ]; then
    log "  FAIL: Module 22 helper not executable"
    fail=$((fail + 1))
fi
luks_perm=$(stat -c %a /usr/local/bin/noid-luks-backup.sh 2>/dev/null || echo 000)
if [ "$luks_perm" != "755" ]; then
    log "  FAIL: Module 22 helper wrong perms ($luks_perm, expected 755)"
    fail=$((fail + 1))
fi

# All 3 shell-based action helpers MUST be regular executable files and have the
# return_to_menu_prompt pattern (unified UX: after each helper action, user
# gets a Y/n prompt to reopen welcome).
for helper in /usr/local/bin/noid-luks-backup.sh \
              /usr/local/bin/noid-complete-setup.sh \
              /usr/local/bin/noid-nvidia-install.sh; do
    if [ ! -f "$helper" ] || [ -L "$helper" ] || [ ! -x "$helper" ]; then
        log "  FAIL: helper missing/not regular executable: $helper"
        fail=$((fail + 1))
        continue
    fi
    if ! grep -qF 'return_to_menu_prompt' "$helper"; then
        log "  FAIL: $helper missing return_to_menu_prompt pattern"
        fail=$((fail + 1))
    fi
done

# welcome.sh verify Python shebang
# (former bash version had `LANG=C.UTF-8 export` lines for zenity locale
# consistency; Python version uses GLib/Gtk locale automatically — no manual
# env force needed. Verify checks that the script is the new Python version.)
# noid-setup-wizard was removed — see Module 13 verify
# section 10.7b for rationale. Welcome dialog absorbed the wizard's
# Hardware-Privacy toggles (mic/cam).
for script in /usr/local/bin/noid-welcome.sh; do
    if [ -f "$script" ]; then
        if ! grep -qF '#!/usr/bin/python3' "$script"; then
            log "  FAIL: $script not Python (should start with #!/usr/bin/python3)"
            fail=$((fail + 1))
        fi
    fi
done

# Module 08 — RPM Fusion + VSCodium + codec-swap firstboot service
# NOTE: ffmpeg swap is DEFERRED to firstboot service (legal defensive — image
# does not distribute patent-encumbered codec binaries). So image ships with
# ffmpeg-free (Fedora default) present, NOT full ffmpeg.
# rpmfusion-*-release is split out; accept the deferred .repo state
# (consistent with the M08 Step 10 fallback-aware pattern).
# Build env can fail to install rpmfusion-*-release directly with "no OpenPGP
# keys configured" (chicken-egg: GPG key ships INSIDE the RPM); M08 Step 7
# fallback writes /etc/yum.repos.d/rpmfusion-*.repo for first-boot install.
for pkg in rpmfusion-free-release rpmfusion-nonfree-release; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
        :
    elif [ -f "/etc/yum.repos.d/${pkg%-release}.repo" ]; then
        :  # deferred state OK
    else
        log "  FAIL: Module 08 package missing AND no fallback .repo: $pkg"
        fail=$((fail + 1))
    fi
done
for pkg in codium ffmpeg-free python3-libdnf5; do
    if ! rpm -q "$pkg" >/dev/null 2>&1; then
        log "  FAIL: Module 08 package missing: $pkg"
        fail=$((fail + 1))
    fi
done
# Module 08 — full ffmpeg MUST be absent at build time (deferred to firstboot)
if rpm -q ffmpeg >/dev/null 2>&1; then
    log "  FAIL: Module 08 — ffmpeg (full) unexpectedly present in image (should be firstboot-only)"
    fail=$((fail + 1))
fi
# Module 08 — VSCodium repo config must exist
if [ ! -f /etc/yum.repos.d/vscodium.repo ]; then
    log "  FAIL: Module 08 — /etc/yum.repos.d/vscodium.repo missing"
    fail=$((fail + 1))
fi
# Module 08 — DNF5 keeps repository-metadata keys in per-user, per-repository
# cache keyrings. The proactive user seed and host-only repos_configured action
# must derive or receive the current cache path without loading metadata or
# opening network sockets, and install only the already fingerprint-pinned
# local key. A valid evidence record must not suppress later cache repair.
if [ ! -x /usr/libexec/noid-vscodium-repo-key-seed ] \
   || [ "$(stat -c '%U:%G:%a' /usr/libexec/noid-vscodium-repo-key-seed \
        2>/dev/null || true)" != root:root:755 ]; then
    log "  FAIL: Module 08 VSCodium per-user metadata-key helper invalid"
    fail=$((fail + 1))
fi
if [ ! -f /usr/lib/systemd/user/noid-vscodium-repo-key-seed.service ] \
   || [ -L /usr/lib/systemd/user/noid-vscodium-repo-key-seed.service ] \
   || [ "$(stat -c '%U:%G:%a' \
        /usr/lib/systemd/user/noid-vscodium-repo-key-seed.service \
        2>/dev/null || true)" != root:root:644 ]; then
    log "  FAIL: Module 08 VSCodium per-user metadata-key unit invalid"
    fail=$((fail + 1))
fi
if [ "$(readlink \
        /etc/systemd/user/default.target.wants/noid-vscodium-repo-key-seed.service \
        2>/dev/null || true)" != \
        /usr/lib/systemd/user/noid-vscodium-repo-key-seed.service ]; then
    log "  FAIL: Module 08 VSCodium metadata-key seed is not globally enabled"
    fail=$((fail + 1))
fi
if [ ! -f /etc/dnf/libdnf5-plugins/actions.d/noid-vscodium-repo-key.actions ] \
   || [ -L /etc/dnf/libdnf5-plugins/actions.d/noid-vscodium-repo-key.actions ] \
   || [ "$(stat -c '%U:%G:%a' \
        /etc/dnf/libdnf5-plugins/actions.d/noid-vscodium-repo-key.actions \
        2>/dev/null || true)" != root:root:644 ] \
   || ! grep -qxF 'repos_configured:::enabled=host-only raise_error=1:/usr/libexec/noid-vscodium-repo-key-seed --cache-root ${conf.cachedir}' \
        /etc/dnf/libdnf5-plugins/actions.d/noid-vscodium-repo-key.actions \
        2>/dev/null; then
    log "  FAIL: Module 08 VSCodium DNF cache-reconciliation action invalid"
    fail=$((fail + 1))
fi
if ! grep -qF 'EXPECTED_FINGERPRINT=1302DE60231889FE1EBACADC54678CF75A278D9C' \
        /usr/libexec/noid-vscodium-repo-key-seed 2>/dev/null \
   || ! grep -qF 'create_repos_from_system_configuration()' \
        /usr/libexec/noid-vscodium-repo-key-seed 2>/dev/null \
   || ! grep -qF 'valid_state || fail "existing state record is unsafe or invalid"' \
        /usr/libexec/noid-vscodium-repo-key-seed 2>/dev/null \
   || ! grep -qF 'if [[ $repo_dir == NOID_VSCODIUM_REPO_DISABLED ]]; then' \
        /usr/libexec/noid-vscodium-repo-key-seed 2>/dev/null \
   || ! grep -qF '*/dnf5daemon-server)' \
        /usr/libexec/noid-vscodium-repo-key-seed 2>/dev/null \
   || grep -qE '^[[:space:]]*base.*load_repos' \
        /usr/libexec/noid-vscodium-repo-key-seed 2>/dev/null \
   || ! grep -qxF 'RestrictAddressFamilies=AF_UNIX' \
        /usr/lib/systemd/user/noid-vscodium-repo-key-seed.service 2>/dev/null \
   || grep -qE '^(PrivateNetwork|IPAddressDeny)=' \
        /usr/lib/systemd/user/noid-vscodium-repo-key-seed.service 2>/dev/null; then
    log "  FAIL: Module 08 VSCodium metadata-key trust/offline boundary invalid"
    fail=$((fail + 1))
fi
# Module 08 — normal VSCodium desktop and URL launches follow the
# switcheroo-control platform-default GPU, while explicit PRIME/Vulkan
# selectors remain untouched. Admin overlays must be byte-identical to the
# current signed RPM desktop payload after reversing only the Exec target.
codium_launcher_finalize_ok=1
if [ ! -f /usr/libexec/noid-codium-launch ] \
   || [ -L /usr/libexec/noid-codium-launch ] \
   || [ "$(stat -c '%U:%G:%a' /usr/libexec/noid-codium-launch \
        2>/dev/null || true)" != root:root:755 ] \
   || ! bash -n /usr/libexec/noid-codium-launch \
   || ! grep -qF 'exec "$SWITCHEROOCTL" launch --gpu=0 "$VENDOR_EXECUTABLE" "$@"' \
        /usr/libexec/noid-codium-launch \
   || ! grep -qF '    DRI_PRIME' /usr/libexec/noid-codium-launch \
   || ! grep -qF '    VK_LOADER_DRIVERS_SELECT' \
        /usr/libexec/noid-codium-launch \
   || [ ! -f /usr/local/sbin/noid-codium-launcher-sync ] \
   || [ -L /usr/local/sbin/noid-codium-launcher-sync ] \
   || [ "$(stat -c '%U:%G:%a' /usr/local/sbin/noid-codium-launcher-sync \
        2>/dev/null || true)" != root:root:755 ] \
   || ! bash -n /usr/local/sbin/noid-codium-launcher-sync \
   || ! grep -qF 'rpm -q --dump "$EXPECTED_PACKAGE"' \
        /usr/local/sbin/noid-codium-launcher-sync \
   || [ ! -f /etc/dnf/libdnf5-plugins/actions.d/noid-codium-launcher.actions ] \
   || [ -L /etc/dnf/libdnf5-plugins/actions.d/noid-codium-launcher.actions ] \
   || [ "$(stat -c '%U:%G:%a' \
        /etc/dnf/libdnf5-plugins/actions.d/noid-codium-launcher.actions \
        2>/dev/null || true)" != root:root:644 ] \
   || ! grep -qxF \
        'post_transaction:codium:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-codium-launcher-sync\ >/dev/null' \
        /etc/dnf/libdnf5-plugins/actions.d/noid-codium-launcher.actions; then
    codium_launcher_finalize_ok=0
fi
for codium_desktop_name in codium.desktop codium-url-handler.desktop; do
    codium_vendor_desktop=/usr/share/applications/$codium_desktop_name
    codium_admin_desktop=/usr/local/share/applications/$codium_desktop_name
    codium_vendor_exec_count=$(grep -c \
        '^Exec=/usr/share/codium/codium\([[:space:]]\|$\)' \
        "$codium_vendor_desktop" 2>/dev/null || true)
    if [ "$codium_vendor_exec_count" -lt 1 ] \
       || [ ! -f "$codium_admin_desktop" ] \
       || [ -L "$codium_admin_desktop" ] \
       || [ "$(stat -c '%U:%G:%a' "$codium_admin_desktop" \
            2>/dev/null || true)" != root:root:644 ] \
       || ! matchpathcon -V "$codium_admin_desktop" >/dev/null 2>&1 \
       || ! desktop-file-validate "$codium_admin_desktop" \
       || [ "$(grep -c \
            '^Exec=/usr/libexec/noid-codium-launch\([[:space:]]\|$\)' \
            "$codium_admin_desktop" 2>/dev/null || true)" -ne \
            "$codium_vendor_exec_count" ] \
       || ! sed -E \
            's#^Exec=/usr/libexec/noid-codium-launch([[:space:]]|$)#Exec=/usr/share/codium/codium\1#' \
            "$codium_admin_desktop" | cmp -s - "$codium_vendor_desktop" \
       || ! rpm -Vf "$codium_vendor_desktop" >/dev/null 2>&1; then
        codium_launcher_finalize_ok=0
    fi
done
if [ "$codium_launcher_finalize_ok" -ne 1 ]; then
    log "  FAIL: Module 08 VSCodium default-GPU launcher contract invalid"
    fail=$((fail + 1))
fi
unset codium_launcher_finalize_ok codium_desktop_name codium_vendor_desktop \
    codium_admin_desktop codium_vendor_exec_count
# Module 08 — firstboot-setup service files (earlier unified ffmpeg + unrar +
# p7zip-plugins, then minimalist dropped unrar + p7zip-plugins
# in favor of pre-installed Fedora-main FOSS alternatives unar + 7zip; current
# effective scope is ffmpeg-swap-only firstboot service)
for f in /usr/local/bin/noid-firstboot-setup.sh \
         /etc/systemd/system/noid-firstboot-setup.service; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 08 firstboot-setup missing/not regular: $f"
        fail=$((fail + 1))
    fi
done
# Module 08 Silent-Machine — firstboot-setup service must NOT be auto-enabled
# Design: user opts in via /usr/local/bin/noid-complete-setup.sh (no automatic egress).
if [ -L /etc/systemd/system/multi-user.target.wants/noid-firstboot-setup.service ]; then
    log "  FAIL: Module 08 firstboot-setup auto-enabled (Silent-Machine: must be opt-in)"
    fail=$((fail + 1))
fi
# Module 08 — legacy codec-swap artifacts must be ABSENT (refactor cleanup)
for legacy in /usr/local/bin/noid-firstboot-codec-swap.sh \
              /etc/systemd/system/noid-firstboot-codec-swap.service \
              /etc/systemd/system/multi-user.target.wants/noid-firstboot-codec-swap.service; do
    if [ -e "$legacy" ]; then
        log "  FAIL: Module 08 legacy codec-swap artifact present: $legacy"
        fail=$((fail + 1))
    fi
done

# ===========================================================================
# Module 20 — Snapper snapshots + CLI rollback
# ===========================================================================
# Packages required (python3-snapper removed in F44 — D-Bus migration)
for pkg in snapper; do
    if ! rpm -q "$pkg" >/dev/null 2>&1; then
        log "  FAIL: Module 20 package missing: $pkg"
        fail=$((fail + 1))
    fi
done
# Packages that MUST be absent (dnf4-only plugin + broken grub-btrfs)
for pkg in python3-dnf-plugin-snapper grub-btrfs; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
        log "  FAIL: Module 20 package must be absent: $pkg"
        fail=$((fail + 1))
    fi
done
# snapper config root must exist with correct key settings
if [ ! -f /etc/snapper/configs/root ]; then
    log "  FAIL: Module 20 /etc/snapper/configs/root missing"
    fail=$((fail + 1))
else
    # NUMBER_LIMIT was increased from 5 to 50 in M20 (the
    # rolling time-based cap via noid-snapper-prune.timer is now the primary
    # mechanism; NUMBER_LIMIT is a safety cap for multi-update-per-day
    # workflows that previously trapped users at 5 snapshots).
    if ! grep -q '^NUMBER_LIMIT="50"' /etc/snapper/configs/root; then
        log "  FAIL: Module 20 snapper root config NUMBER_LIMIT!=50 (M20 source requires 50)"
        fail=$((fail + 1))
    fi
    if ! grep -q '^TIMELINE_CREATE="no"' /etc/snapper/configs/root; then
        log "  FAIL: Module 20 snapper root config TIMELINE_CREATE!=no (privacy)"
        fail=$((fail + 1))
    fi
    # Snapshot mutation remains root-only. M13 obtains only the fixed sanitized
    # status schema through M20's exact sudo command boundary.
    if ! grep -q '^ALLOW_GROUPS=""' /etc/snapper/configs/root; then
        log "  FAIL: Module 20 snapper root config grants a non-root group"
        fail=$((fail + 1))
    fi
    if ! grep -q '^SYNC_ACL="no"' /etc/snapper/configs/root; then
        log "  FAIL: Module 20 snapper root config synchronizes a non-root ACL"
        fail=$((fail + 1))
    fi
    # Qgroups and ranged count limits are deliberately disabled, so these
    # numeric defaults do not claim active quota enforcement. Keep them valid:
    # snapper-cleanup parses both values before determining applicability and
    # logs errors for empty strings.
    for snapper_config_entry in \
        'QGROUP=""' \
        'SPACE_LIMIT="0.5"' \
        'FREE_LIMIT="0.2"'; do
        if ! grep -qxF "$snapper_config_entry" /etc/snapper/configs/root; then
            log "  FAIL: Module 20 Snapper quota-hint config drifted: $snapper_config_entry"
            fail=$((fail + 1))
        fi
    done
    unset snapper_config_entry
    # NOTE: EXCLUDE_PATTERN check REMOVED — snapper has no
    # config-level exclude directive (the EXCLUDE_PATTERN= line in /etc/
    # snapper/configs/root is silently ignored by snapperd, so M20 correctly
    # dropped it). M20's nodatacow subvolume keeps guest images out of root
    # snapshots; M13 separately excludes only images/ and qemu/ high-churn
    # state from AIDE while preserving /etc/libvirt coverage. Keeping this
    # obsolete config-key check would always FAIL.
fi

# /etc/logrotate.d/snapper is capped to maxage 30 and
# rotate 30 by M20 Step 11d sed-edit. The snapper RPM ships maxage 60 + rotate
# 99 (~6+ months), which breaches the 30-day forensic posture. If the file is
# absent (= snapper-libs not installed on this image variant) we skip; if
# present, the cap must be applied.
if [ -f /etc/logrotate.d/snapper ]; then
    if ! grep -qE '^[[:space:]]*maxage[[:space:]]+30$' /etc/logrotate.d/snapper; then
        log "  FAIL: Module 20 /etc/logrotate.d/snapper maxage not capped to 30 (forensic-retention policy)"
        fail=$((fail + 1))
    fi
    if ! grep -qE '^[[:space:]]*rotate[[:space:]]+30$' /etc/logrotate.d/snapper; then
        log "  FAIL: Module 20 /etc/logrotate.d/snapper rotate not capped to 30 (forensic-retention policy)"
        fail=$((fail + 1))
    fi
fi

# noid-snapper-prune provides measured time-based snapshot cleanup. It
# consumes authoritative Snapper JSON and calls delete --sync only for an old,
# eligible root. Active/default roots remain protected and visible rather than
# being misreported as deleted. Companion to the NUMBER_LIMIT bump above.
for f in /usr/local/sbin/noid-snapper-prune.sh \
         /etc/systemd/system/noid-snapper-prune.service \
         /etc/systemd/system/noid-snapper-prune.timer; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 20 missing: $f (noid-snapper-prune)"
        fail=$((fail + 1))
    fi
done
if [ -x /usr/local/sbin/noid-snapper-prune.sh ]; then
    if ! grep -qF '"$SNAPPER" -c root delete --sync "$num"' /usr/local/sbin/noid-snapper-prune.sh; then
        log "  FAIL: Module 20 noid-snapper-prune.sh missing snapper delete invocation"
        fail=$((fail + 1))
    fi
fi
if ! grep -qF 'RequiresMountsFor=/.snapshots' /etc/systemd/system/noid-snapper-prune.service 2>/dev/null \
        || ! grep -qF 'ConditionPathExists=/.snapshots/.noid-state/init.done' \
            /etc/systemd/system/noid-snapper-prune.service 2>/dev/null; then
    log "  FAIL: Module 20 pruner is not bound to the stable snapshot-state mount"
    fail=$((fail + 1))
fi
if [ ! -L /etc/systemd/system/timers.target.wants/noid-snapper-prune.timer ]; then
    log "  FAIL: Module 20 noid-snapper-prune.timer not in timers.target.wants (build-time baseline must be enabled)"
    fail=$((fail + 1))
fi
# /etc/sysconfig/snapper lists the root config (the corrected path:
# Fedora reads /etc/sysconfig/snapper, not /etc/default/snapper).
if [ ! -f /etc/sysconfig/snapper ] || ! grep -q '^SNAPPER_CONFIGS="root"' /etc/sysconfig/snapper; then
    log "  FAIL: Module 20 /etc/sysconfig/snapper missing or root not listed"
    fail=$((fail + 1))
fi
# Helper scripts exist + executable (incl. checked create/status/rollback path)
for script in /usr/local/bin/noid-snapper-init.sh \
              /usr/local/bin/noid-snap-pre \
              /usr/local/sbin/noid-snap-rollback \
              /usr/libexec/noid-snapper-create \
              /usr/libexec/noid-snapper-status \
              /usr/libexec/noid-snapper-rollback; do
    if [ ! -x "$script" ]; then
        log "  FAIL: Module 20 helper script missing or not executable: $script"
        fail=$((fail + 1))
    fi
done
if ! grep -qF 'BOOT_LOCK=/run/lock/noid-boot-mutation.lock' \
        /usr/libexec/noid-snapper-rollback 2>/dev/null \
        || ! grep -qF 'BOOT_GUARD=/usr/libexec/noid-boot-mutation-guard' \
            /usr/libexec/noid-snapper-rollback 2>/dev/null \
        || ! grep -qF 'guard_args=(--snapper-resume)' \
            /usr/libexec/noid-snapper-rollback 2>/dev/null; then
    log "  FAIL: Module 20 rollback bypasses the shared boot-mutation contract"
    fail=$((fail + 1))
fi
if [ ! -f /etc/sudoers.d/noid-snapper-status ] \
        || [ "$(stat -c '%U:%G:%a' /etc/sudoers.d/noid-snapper-status 2>/dev/null)" != root:root:440 ] \
        || [ "$(grep -cEv '^[[:space:]]*(#|$)' /etc/sudoers.d/noid-snapper-status 2>/dev/null)" -ne 2 ] \
        || ! grep -qxF 'Cmnd_Alias NOID_SNAPPER_STATUS = /usr/libexec/noid-snapper-status ""' \
            /etc/sudoers.d/noid-snapper-status 2>/dev/null \
        || ! grep -qxF '%wheel ALL=(root) NOPASSWD: NOID_SNAPPER_STATUS' \
            /etc/sudoers.d/noid-snapper-status 2>/dev/null; then
    log "  FAIL: Module 20 fixed read-only Snapper sudo boundary drifted"
    fail=$((fail + 1))
fi
# Systemd service unit exists
if [ ! -f /etc/systemd/system/noid-snapper-init.service ]; then
    log "  FAIL: Module 20 service unit missing: /etc/systemd/system/noid-snapper-init.service"
    fail=$((fail + 1))
fi
# Service must be enabled (symlink in target.wants)
if [ ! -L /etc/systemd/system/multi-user.target.wants/noid-snapper-init.service ]; then
    log "  FAIL: Module 20 service not enabled (symlink missing): noid-snapper-init.service"
    fail=$((fail + 1))
fi
# Recovery documentation must exist with non-trivial size
if [ ! -f /usr/share/doc/noid-privacy/20-rollback-recovery.md ]; then
    log "  FAIL: Module 20 recovery doc missing"
    fail=$((fail + 1))
else
    rec_size=$(stat -c %s /usr/share/doc/noid-privacy/20-rollback-recovery.md 2>/dev/null || echo 0)
    if [ "$rec_size" -lt 2000 ]; then
        log "  FAIL: Module 20 recovery doc too small (${rec_size} bytes, expected >2KB)"
        fail=$((fail + 1))
    fi
fi
if grep -qE 'snapper[[:space:]]+-c[[:space:]]+root[[:space:]]+rollback' \
        /usr/share/doc/noid-privacy/20-rollback-recovery.md 2>/dev/null; then
    log "  FAIL: Module 20 recovery guide bypasses the checked rollback wrapper"
    fail=$((fail + 1))
fi

# Module 13 — /.snapshots exclusion in aide.conf
if ! grep -qF '!/\.snapshots(/.*)?$' /etc/aide.conf 2>/dev/null; then
    log "  FAIL: Module 13 — /.snapshots exclusion missing in /etc/aide.conf"
    fail=$((fail + 1))
fi

# Module 13 paired cross-check —
# 10 aide.conf exclusions for M42-managed 30-day forensic-retention paths.
# Without these exclusions, daily aide-check at 07:00 reports thousands of
# added/removed/changed entries for files rotated/pruned by M42 timers
# (noid-aide-check log dir + Anaconda and exact NoID Privacy install logs + libvirt
# qemu/swtpm per-VM logs + tuned daemon logs). Alarm fatigue is the actual
# security risk (= masks real intrusions).
# This block fails the build if M13 source-port to /etc/aide.conf is
# incomplete — same ship-blocker class as the NUMBER_LIMIT ship-blocker and
# the M13 wrapper artifacts cross-check.
for excl_pattern in \
    '!/var/log/aide(/.*)?$' \
    '!/var/log/anaconda(/.*)?$' \
    '!/var/log/ks-[^/]*\.log$' \
    '!/var/log/ks-10-authselect\.err$' \
    '!/var/log/noid-anaconda-kernel-cmdline\.log$' \
    '!/var/log/noid-firstboot-setup\.log$' \
    '!/var/log/noid-crypto-policy\.err$' \
    '!/var/log/libvirt(/.*)?$' \
    '!/var/log/swtpm/libvirt/qemu(/.*)?$' \
    '!/var/log/tuned(/.*)?$'; do
    if ! grep -qF "$excl_pattern" /etc/aide.conf 2>/dev/null; then
        log "  FAIL: Module 13 retention exclusion missing in /etc/aide.conf: $excl_pattern"
        fail=$((fail + 1))
    fi
done

# Module 21 — exact stateful policy, not a raw minimum count.
M21_POLICY=/usr/share/noid-privacy/kernel-module-policy.tsv
M21_CONFIG=/etc/modprobe.d/noid-security-blacklist.conf
if [ -f "$M21_POLICY" ] && [ -f "$M21_CONFIG" ]; then
    policy_rows=$(awk -F '\t' '!/^#/ && NF { n++ } END { print n+0 }' "$M21_POLICY")
    deny_rows=$(awk -F '\t' '$2 == "deny-loadable" { n++ } END { print n+0 }' "$M21_POLICY")
    builtin_rows=$(awk -F '\t' '$2 == "unaffected-builtin" { n++ } END { print n+0 }' "$M21_POLICY")
    absent_rows=$(awk -F '\t' '$2 == "unaffected-absent" { n++ } END { print n+0 }' "$M21_POLICY")
    alias_rows=$(awk -F '\t' '$2 == "alias-denied-via-target" { n++ } END { print n+0 }' "$M21_POLICY")
    supported_rows=$(awk -F '\t' '$2 == "supported" { n++ } END { print n+0 }' "$M21_POLICY")
    expected_directives=$(mktemp /var/tmp/noid-m99-m21-expected.XXXXXX)
    actual_directives=$(mktemp /var/tmp/noid-m99-m21-actual.XXXXXX)
    awk -F '\t' '$2 == "deny-loadable" {
        printf "blacklist %s\ninstall %s /bin/false\n", $1, $1
    }' "$M21_POLICY" > "$expected_directives"
    grep -E '^(blacklist|install) ' "$M21_CONFIG" > "$actual_directives" || true
    if [ "$policy_rows" -eq 134 ] && [ "$deny_rows" -eq 53 ] && \
       [ "$builtin_rows" -eq 8 ] && [ "$absent_rows" -eq 43 ] && \
       [ "$alias_rows" -eq 2 ] && [ "$supported_rows" -eq 28 ] && \
       cmp -s "$expected_directives" "$actual_directives"; then
        log "  OK: Module 21 exact policy: 53 deny + 8 built-in + 43 absent + 2 aliases + 28 supported"
    else
        log "  FAIL: Module 21 policy cardinality or generated directives drifted"
        fail=$((fail + 1))
    fi
    rm -f -- "$expected_directives" "$actual_directives"
else
    log "  FAIL: Module 21 policy manifest or generated config missing"
    fail=$((fail + 1))
fi

# Generic Live/installer and host-only installed-system boundaries.
if [ ! -f /etc/dracut.conf.d/noid-security-blacklist.conf ] || \
   ! grep -qx 'omit_drivers+=" firewire_core firewire_net firewire_ohci firewire_sbp2 "' \
       /etc/dracut.conf.d/99-omit-firewire.conf 2>/dev/null; then
    log "  FAIL: Module 21 blacklist embed or canonical FireWire omit missing"
    fail=$((fail + 1))
fi
if [ -e /etc/dracut.conf.d/99-noid-omit-storage.conf ] || \
   [ -e /etc/dracut.conf.d/99-noid-compress.conf ] || \
   [ -e /etc/dracut.conf.d/99-noid-hostonly.conf ] || \
   [ -e /etc/noid-privacy/initramfs-hostonly ]; then
    log "  FAIL: Module 21 Live/installer boundary contains installed-only or retired Dracut policy"
    fail=$((fail + 1))
fi
if [ ! -x /usr/libexec/noid-boot-mutation-guard ] || \
   [ ! -x /usr/libexec/noid-dracut-regenerate-all ] || \
   [ ! -x /usr/libexec/noid-dracut-hostonly-configure ] || \
   [ ! -x /usr/libexec/noid-mark-hostonly-boot-success ] || \
   [ -L /usr/libexec/noid-mark-hostonly-boot-success ] || \
   [ "$(stat -c '%U:%G:%a' /usr/libexec/noid-mark-hostonly-boot-success 2>/dev/null)" != root:root:755 ] || \
   [ ! -f /usr/lib/systemd/user/noid-hostonly-boot-success.service ] || \
   [ -L /usr/lib/systemd/user/noid-hostonly-boot-success.service ] || \
   [ "$(stat -c '%U:%G:%a' /usr/lib/systemd/user/noid-hostonly-boot-success.service 2>/dev/null)" != root:root:644 ] || \
   [ ! -f /usr/lib/systemd/user/noid-hostonly-boot-success.path ] || \
   [ -L /usr/lib/systemd/user/noid-hostonly-boot-success.path ] || \
   [ "$(stat -c '%U:%G:%a' /usr/lib/systemd/user/noid-hostonly-boot-success.path 2>/dev/null)" != root:root:644 ] || \
   [ "$(readlink /usr/lib/systemd/user/noid-user-firstrun.service.wants/noid-hostonly-boot-success.service 2>/dev/null)" != /usr/lib/systemd/user/noid-hostonly-boot-success.service ] || \
   [ "$(readlink /usr/lib/systemd/user/noid-user-firstrun.service.wants/noid-hostonly-boot-success.path 2>/dev/null)" != /usr/lib/systemd/user/noid-hostonly-boot-success.path ] || \
   [ ! -f /usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf ] || \
   ! grep -qF 'f /run/lock/noid-boot-mutation.lock 0660 root wheel -' \
       /usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf || \
   [ "$(stat -c '%U:%G:%a' /run/lock/noid-boot-mutation.lock 2>/dev/null)" != root:wheel:660 ] || \
   [ "$(stat -c '%U:%G:%a' /etc/sudoers.d/90-noid-boot-mutation-fd 2>/dev/null)" != root:root:440 ] || \
   ! grep -qxF 'Defaults!/usr/libexec/noid-dracut-regenerate-all closefrom_override' \
       /etc/sudoers.d/90-noid-boot-mutation-fd || \
   ! visudo -cf /etc/sudoers.d/90-noid-boot-mutation-fd >/dev/null || \
   ! grep -qF 'complete) basis=hostonly' /usr/libexec/noid-boot-mutation-guard || \
   ! grep -qF 'recovered-generic) basis=generic' /usr/libexec/noid-boot-mutation-guard || \
   ! grep -qF 'validate_snapper_record "$SNAPPER_PENDING" pending' \
       /usr/libexec/noid-boot-mutation-guard || \
   ! grep -qF 'a Snapper rollback root is selected; reboot before changing /boot' \
       /usr/libexec/noid-boot-mutation-guard || \
   ! grep -qF 'basis_record=$(/usr/libexec/noid-boot-mutation-guard)' \
       /usr/libexec/noid-dracut-regenerate-all || \
   ! grep -qF 'mv -fT -- "$candidate" "$final"' \
       /usr/libexec/noid-dracut-regenerate-all || \
   ! grep -qF 'candidate for $kernel lacks root-path driver' \
       /usr/libexec/noid-dracut-regenerate-all || \
   ! grep -qF 'enrolled NVIDIA identity verification failed for $kernel' \
       /usr/libexec/noid-dracut-regenerate-all || \
   [ ! -f /etc/systemd/system/noid-dracut-hostonly-firstboot.service ] || \
   [ ! -f /etc/systemd/system/noid-dracut-hostonly-firstboot.timer ] || \
   [ ! -L /etc/systemd/system/multi-user.target.wants/noid-dracut-hostonly-firstboot.timer ] || \
   [ -e /etc/systemd/system/multi-user.target.wants/noid-dracut-hostonly-firstboot.service ] || \
   ! grep -q -- '--hostonly-mode sloppy' /usr/libexec/noid-dracut-hostonly-configure || \
   ! grep -qF 'FALLBACK_BLS=/boot/loader/entries/noid-generic-fallback-$kernel.conf' \
       /usr/libexec/noid-dracut-hostonly-configure || \
   ! grep -qF 'write_state pending-reboot' /usr/libexec/noid-dracut-hostonly-configure || \
   ! grep -qF 'BOOT_SUCCESS_REQUEST=/run/noid-privacy/hostonly-boot-success-needed' \
       /usr/libexec/noid-dracut-hostonly-configure || \
   grep -qF 'grub2-set-bootflag menu_show_once' \
       /usr/libexec/noid-dracut-hostonly-configure || \
   ! grep -qF '"$BOOTFLAG" boot_success' \
       /usr/libexec/noid-mark-hostonly-boot-success || \
   grep -qF 'menu_show_once' /usr/libexec/noid-mark-hostonly-boot-success || \
   ! grep -qxF 'Requires=noid-user-firstrun.service' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service || \
   ! grep -qxF 'After=noid-user-firstrun.service' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service || \
   ! grep -qxF 'ConditionKernelCommandLine=!rd.live.image' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service || \
   ! grep -qxF 'ConditionPathExists=/run/noid-privacy/hostonly-boot-success-needed' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service || \
   ! grep -qxF 'RemainAfterExit=yes' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service || \
   ! grep -qxF 'PathExists=/run/noid-privacy/hostonly-boot-success-needed' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.path || \
   ! grep -qxF 'Unit=noid-hostonly-boot-success.service' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.path || \
   ! grep -qxF 'ExecStart=/usr/libexec/noid-mark-hostonly-boot-success' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service || \
   ! grep -qF 'restore_generic "$kernel"' /usr/libexec/noid-dracut-hostonly-configure || \
   grep -qF 'ConditionPathExists=!/var/lib/noid-privacy/dracut-hostonly.state' \
       /etc/systemd/system/noid-dracut-hostonly-firstboot.service; then
    log "  FAIL: Module 21 convergence/shared boot-mutation contract is incomplete"
    fail=$((fail + 1))
fi

# Native binfmt activation masks replace the retired udev special-file race.
for binfmt_unit in proc-sys-fs-binfmt_misc.automount systemd-binfmt.service; do
    if [ "$(readlink "/etc/systemd/system/$binfmt_unit" 2>/dev/null || true)" != /dev/null ]; then
        log "  FAIL: Module 21 $binfmt_unit is not exactly masked"
        fail=$((fail + 1))
    fi
done
if [ -e /usr/lib/udev/rules.d/99-noid-binfmt-disable.rules ]; then
    log "  FAIL: Module 21 retired binfmt_misc udev rule remains"
    fail=$((fail + 1))
fi
if [ ! -f /usr/share/doc/noid-privacy/21-kernel-module-blacklist.md ]; then
    log "  FAIL: Module 21 documentation missing"
    fail=$((fail + 1))
fi

# M01 prerequisite at compose time: validate the end-user target writers, not
# the intentionally build-topology-specific Live-image BLS. Effective Live and
# installed BLS arguments remain mandatory pre-ship runtime claims.
if [ ! -f /usr/libexec/noid-verify-target-karg-payload ] || \
        [ -L /usr/libexec/noid-verify-target-karg-payload ] || \
        [ "$(stat -c '%U:%G:%a' /usr/libexec/noid-verify-target-karg-payload 2>/dev/null)" != root:root:755 ] || \
        ! /usr/libexec/noid-verify-target-karg-payload >/dev/null; then
    log "  FAIL: Module 21/M01 target-install module.sig_enforce=1 payload invalid"
    fail=$((fail + 1))
fi

# Module 22 — Mount hardening firstboot
if [ ! -x /usr/local/bin/noid-mount-hardening.sh ]; then
    log "  FAIL: Module 22 mount hardening script missing"
    fail=$((fail + 1))
fi
if [ ! -f /etc/systemd/system/noid-mount-hardening.service ]; then
    log "  FAIL: Module 22 service unit missing"
    fail=$((fail + 1))
fi
if [ ! -L /etc/systemd/system/basic.target.wants/noid-mount-hardening.service ]; then
    log "  FAIL: Module 22 service not enabled"
    fail=$((fail + 1))
fi
if [ ! -x /usr/local/bin/noid-live-mount-hardening.sh ] \
   || [ ! -f /etc/systemd/system/noid-live-mount-hardening.service ] \
   || [ ! -L /etc/systemd/system/basic.target.wants/noid-live-mount-hardening.service ]; then
    log "  FAIL: Module 22 live-media mount hardening is incomplete"
    fail=$((fail + 1))
fi
if [ ! -f /usr/share/doc/noid-privacy/22-disk-encryption.md ]; then
    log "  FAIL: Module 22 documentation missing"
    fail=$((fail + 1))
fi

# Module 23 — NetworkManager MAC randomization
if [ ! -f /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf ]; then
    log "  FAIL: Module 23 MAC randomization config missing"
    fail=$((fail + 1))
else
    if ! grep -q 'cloned-mac-address=stable' /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf; then
        log "  FAIL: Module 23 cloned-mac-address=stable missing in config"
        fail=$((fail + 1))
    fi
    if ! grep -q 'wifi.scan-rand-mac-address=yes' /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf; then
        log "  FAIL: Module 23 wifi.scan-rand-mac-address=yes missing in config"
        fail=$((fail + 1))
    fi
fi

# Module 23 — IPv6 per-connection defaults (ethernet+wifi only)
# NM 1.54+ rejects ipv6.method= as a connection-default in NM.conf [connection-*]
# sections; the wireguard/vpn ipv6 method handling is now done by NM dispatcher
# /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults via nmcli at
# first connection up. Only the ip6-privacy + addr-gen-mode defaults stay in
# 01-noid-ipv6.conf for ethernet+wifi (defense-in-depth in case user re-enables
# IPv6 via nmcli on a physical interface).
if [ ! -f /etc/NetworkManager/conf.d/01-noid-ipv6.conf ]; then
    log "  FAIL: Module 23 IPv6 per-connection defaults config missing"
    fail=$((fail + 1))
else
    for section in connection-ethernet-ipv6 connection-wifi-ipv6; do
        if ! grep -qE "^\[${section}\]" /etc/NetworkManager/conf.d/01-noid-ipv6.conf; then
            log "  FAIL: Module 23 section [${section}] missing in 01-noid-ipv6.conf"
            fail=$((fail + 1))
        fi
    done
    # Defense-in-depth ip6-privacy + numeric stable-privacy addr-gen-mode on
    # ethernet+wifi (2x each). NM.conf does not accept nmcli's enum nick here.
    priv_cnt=$(grep -cFx 'ipv6.ip6-privacy=2' /etc/NetworkManager/conf.d/01-noid-ipv6.conf 2>/dev/null || true)
    priv_cnt=${priv_cnt:-0}
    agm_cnt=$(grep -cFx 'ipv6.addr-gen-mode=1' /etc/NetworkManager/conf.d/01-noid-ipv6.conf 2>/dev/null || true)
    agm_cnt=${agm_cnt:-0}
    # Logic OR-trigger-fail (fail if
    # EITHER count <2), but message clarified — BOTH directives are required
    # ≥2× (one for ethernet, one for wifi).
    if [ "$priv_cnt" -lt 2 ] || [ "$agm_cnt" -lt 2 ]; then
        log "  FAIL: Module 23 — BOTH ip6-privacy=2 AND addr-gen-mode=1 (stable-privacy) must appear ≥2× on ethernet+wifi (priv=${priv_cnt} agm=${agm_cnt})"
        fail=$((fail + 1))
    fi
fi

# Modules 23 + 27 — Wake-on-LAN ownership + device default off
# NetworkManager.conf's numeric `ignore` flag (32768) leaves WoL unchanged.
# The actual disable control is M27's first-matching systemd.link
# WakeOnLan=off; together they keep the device off while preserving explicit
# per-connection opt-in.
if [ -f /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf ]; then
    if ! grep -qFx 'ethernet.wake-on-lan=32768' /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf; then
        log "  FAIL: Module 23 NetworkManager WoL ownership boundary missing"
        fail=$((fail + 1))
    fi
fi
if [ ! -f /etc/systemd/network/10-noid-no-wol.link ] || \
   ! grep -q '^WakeOnLan=off$' /etc/systemd/network/10-noid-no-wol.link || \
   grep -q '^\[EnergyEfficientEthernet\]$' /etc/systemd/network/10-noid-no-wol.link || \
   [ -e /etc/systemd/network/10-noid-no-eee.link ] || \
   [ -L /etc/systemd/network/10-noid-no-eee.link ]; then
    log "  FAIL: Module 27 WoL policy or vendor-owned EEE boundary invalid"
    fail=$((fail + 1))
fi
if [ ! -f /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf ]; then
    log "  FAIL: Module 23 /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf missing (LLDP defaults)"
    fail=$((fail + 1))
elif ! grep -qE '^connection\.lldp=0' /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf; then
    log "  FAIL: Module 23 connection.lldp=0 missing in 02-noid-connection-defaults.conf"
    fail=$((fail + 1))
fi

# Module 23 — NM dispatcher 40-noid-connection-defaults
# NM 1.54+ workaround: dispatcher applies ipv4.ignore-auto-routes/dns +
# ipv6.method=disabled + ipv6.ignore-auto-routes/dns + connection.lldp/mdns/llmnr
# per-connection at first up. CRITICAL for TunnelVision CVE-2024-3661 mitigation.
if [ ! -x /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults ]; then
    log "  FAIL: Module 23 NM dispatcher 40-noid-connection-defaults missing or not executable (TunnelVision mitigation broken)"
    fail=$((fail + 1))
elif ! grep -q 'firewall-cmd --zone=drop --change-interface=' \
        /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults \
     || ! grep -q 'connection.zone drop' \
        /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults; then
    log "  FAIL: Module 23 physical connections are not forced into drop zone"
    fail=$((fail + 1))
fi
if [ ! -L /etc/NetworkManager/dispatcher.d/pre-up.d/40-noid-connection-defaults ]; then
    log "  FAIL: Module 23 physical-zone dispatcher missing pre-up registration"
    fail=$((fail + 1))
fi

# Module 24 — fwupd telemetry lockdown
if [ -f /etc/fwupd/remotes.d/lvfs.conf ]; then
    if ! grep -q 'AutomaticReports=false' /etc/fwupd/remotes.d/lvfs.conf || \
       ! grep -q 'AutomaticSecurityReports=false' /etc/fwupd/remotes.d/lvfs.conf; then
        log "  FAIL: Module 24 LVFS telemetry not disabled"
        fail=$((fail + 1))
    fi
else
    log "  FAIL: Module 24 /etc/fwupd/remotes.d/lvfs.conf missing"
    fail=$((fail + 1))
fi
if [ -f /etc/fwupd/remotes.d/lvfs-testing.conf ]; then
    if ! grep -q 'Enabled=false' /etc/fwupd/remotes.d/lvfs-testing.conf; then
        log "  FAIL: Module 24 LVFS testing remote not disabled"
        fail=$((fail + 1))
    fi
fi
if [ ! -f /usr/share/doc/noid-privacy/24-firmware-updates.md ]; then
    log "  FAIL: Module 24 documentation missing"
    fail=$((fail + 1))
fi
# Module 24 — fwupd.conf (privacy + bounded on-demand lifecycle)
if [ -f /etc/fwupd/fwupd.conf ]; then
    if ! grep -q 'P2pPolicy=nothing' /etc/fwupd/fwupd.conf; then
        log "  FAIL: Module 24 P2pPolicy=nothing missing in fwupd.conf"
        fail=$((fail + 1))
    fi
    if ! grep -qxF 'DisabledPlugins=redfish;android_boot' /etc/fwupd/fwupd.conf; then
        log "  FAIL: Module 24 closed DisabledPlugins list missing in fwupd.conf"
        fail=$((fail + 1))
    fi
    # UpdateMotd off (AIDE noise reduction)
    if ! grep -q 'UpdateMotd=false' /etc/fwupd/fwupd.conf; then
        log "  FAIL: Module 24 UpdateMotd=false missing in fwupd.conf (AIDE noise)"
        fail=$((fail + 1))
    fi
    # ShowDevicePrivate off (privacy default explicit)
    if ! grep -q 'ShowDevicePrivate=false' /etc/fwupd/fwupd.conf; then
        log "  FAIL: Module 24 ShowDevicePrivate=false missing in fwupd.conf"
        fail=$((fail + 1))
    fi
    if ! grep -q '^IdleTimeout=300$' /etc/fwupd/fwupd.conf \
       || ! grep -q '^IdleInhibitStartupThreshold=0$' /etc/fwupd/fwupd.conf; then
        log "  FAIL: Module 24 bounded on-demand daemon policy missing"
        fail=$((fail + 1))
    fi
else
    log "  FAIL: Module 24 /etc/fwupd/fwupd.conf missing"
    fail=$((fail + 1))
fi
if [ -e /etc/systemd/system/fwupd.service.d/99-noid-keep-warm.conf ] \
   || [ -L /etc/systemd/system/fwupd.service.d/99-noid-keep-warm.conf ] \
   || [ -e /etc/systemd/system/multi-user.target.wants/fwupd.service ] \
   || [ -L /etc/systemd/system/multi-user.target.wants/fwupd.service ] \
   || [ "$(systemctl is-enabled fwupd.service 2>/dev/null || true)" != static ]; then
    log "  FAIL: Module 24 fwupd is not purely static/on-demand"
    fail=$((fail + 1))
fi

# Module 24 — fwupd-refresh.timer must be masked (no background LVFS fetch before VPN)
if [ -L /etc/systemd/system/fwupd-refresh.timer ]; then
    refresh_target=$(readlink /etc/systemd/system/fwupd-refresh.timer 2>/dev/null || true)
    if [ "$refresh_target" != "/dev/null" ]; then
        log "  FAIL: Module 24 fwupd-refresh.timer not masked (points to $refresh_target)"
        fail=$((fail + 1))
    fi
else
    log "  FAIL: Module 24 fwupd-refresh.timer mask symlink missing"
    fail=$((fail + 1))
fi

# Module 25 — update process + canonical reboot-readiness presentation
# (Silent-Machine: no auto-security-update timer — all updates user-initiated
# via update-all.sh). Activation remains a live comparison; boot safety is a
# separate fail-closed, boot-scoped state axis.
for f in /usr/local/bin/noid-update-all.sh \
         /usr/local/lib/noid-privacy/validate-webextension.py \
         /usr/local/lib/noid-privacy/validate-ubo-policy.py \
         /usr/local/lib/noid-privacy/verify-firefox-xpi-signature \
         /usr/libexec/noid-reboot-block-state \
         /usr/libexec/noid-reboot-readiness \
         /usr/local/bin/noid-pending-reboot-check.sh \
         /etc/systemd/user/noid-update-reminder.service \
         /etc/systemd/user/noid-update-reminder.timer \
         /etc/systemd/user-preset/50-noid-update.preset \
         /etc/xdg/autostart/noid-pending-reboot.desktop; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 25 missing/not a regular file: $f"
        fail=$((fail + 1))
    fi
done
if ! bash -n /usr/libexec/noid-reboot-block-state 2>/dev/null \
   || ! bash -n /usr/libexec/noid-reboot-readiness 2>/dev/null \
   || ! bash -n /usr/local/bin/noid-pending-reboot-check.sh 2>/dev/null \
   || ! grep -qF 'STATE_DIR=/run/noid-privacy' \
        /usr/libexec/noid-reboot-block-state 2>/dev/null \
   || ! grep -qF 'STATE=$STATE_DIR/reboot-blocked' \
        /usr/libexec/noid-reboot-block-state 2>/dev/null \
   || ! grep -qF 'block_state=/run/noid-privacy/reboot-blocked' \
        /usr/libexec/noid-reboot-readiness 2>/dev/null \
   || ! grep -qF 'firstboot_marker=/var/lib/noid-privacy/.firstboot-cmdline-reboot-required' \
        /usr/libexec/noid-reboot-readiness 2>/dev/null \
   || ! grep -qF 'nvidia_degraded=$nvidia_state_dir/degraded' \
        /usr/libexec/noid-reboot-readiness 2>/dev/null \
   || ! grep -qF 'case "$guard_rc:$guard_state" in' \
        /usr/libexec/noid-reboot-readiness 2>/dev/null \
   || ! grep -qF '/usr/libexec/noid-reboot-readiness' \
        /usr/local/bin/noid-pending-reboot-check.sh 2>/dev/null \
   || ! grep -qF '/usr/libexec/noid-reboot-readiness' \
        /usr/local/bin/noid-status 2>/dev/null \
   || ! grep -qF 'REBOOT_STATE=$(read_reboot_state)' \
        /usr/local/bin/noid-status 2>/dev/null; then
    log "  FAIL: Module 25 canonical reboot-readiness contract invalid"
    fail=$((fail + 1))
fi
if ! grep -qF 'settle_fwupd_daemon()' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'sudo LC_ALL=C fwupdmgr quit' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || grep -qF 'systemctl stop fwupd.service' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null; then
    log "  FAIL: Module 25 native fwupd settlement contract invalid"
    fail=$((fail + 1))
fi
if ! bash -n /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! bash -n /usr/local/lib/noid-privacy/verify-firefox-xpi-signature 2>/dev/null \
   || ! python3 -c 'import pathlib; p=pathlib.Path("/usr/local/lib/noid-privacy/validate-webextension.py"); compile(p.read_text(), str(p), "exec")' 2>/dev/null \
   || ! python3 -c 'import pathlib; p=pathlib.Path("/usr/local/lib/noid-privacy/validate-ubo-policy.py"); compile(p.read_text(), str(p), "exec")' 2>/dev/null \
   || ! grep -qF 'UBO_POLICY_VALIDATOR=/usr/local/lib/noid-privacy/validate-ubo-policy.py' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'UBO_POLICY_SOURCE=/usr/share/noid-firefox/uBlock0@raymondhill.net.json' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'ubo_candidate_action()' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF '"$UBO_POLICY_VALIDATOR" "$LATEST_XPI_PATH"' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF '"$UBO_POLICY_VALIDATOR" "$ubo_target"' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || grep -qF 'UBO_MANAGED_POLICY=' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'MARKETPLACE_XPI_RELEASE_PY' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'FIREFOX_XPI_SIGNATURE_VERIFIER=' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || grep -qF 'https://api.github.com/repos/gorhill/uBlock/releases/latest' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || grep -qF 'https://api.github.com/repos/lieser/dkim_verifier/releases/latest' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'https://addons.mozilla.org/api/v5/addons/search/' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'https://services.addons.thunderbird.net/api/v4/addons/search/' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'fetch_latest_xpi ubo' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'fetch_latest_xpi dkim' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'update_marketplace_extensions firefox amo' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'update_marketplace_extensions thunderbird atn' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'BROWSER_EXTENSION_INVENTORY_PY' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'TB_DKIM_CURRENT_VALID=0' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'EGO update check unavailable; installed extension left unchanged' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'Open-VSX REST channel unavailable for' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'extension-updates.log' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'extension-checks' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'record_extension_check() {' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'record_extension_check firefox-ubo' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'record_extension_check thunderbird-dkim' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'record_extension_check "${product}-marketplace"' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'JP_SEED_VERSION=' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || grep -qF '[ "$ext_path" = "$JP_PATH" ] && continue' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF -- "--data-urlencode \"uuid=\${ego_uuid}\"" \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'EGO_VALIDATE_PY' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'RENAME_EXCHANGE' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'managed agent extensions present; using per-extension native updates' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'no additional VSCodium extensions require Open-VSX reconciliation' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'VSX_VERSION_PY' /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'installed ${ext_ver} is newer than registry ${latest}; no downgrade' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || ! grep -qF 'installed_exact=$(codium --list-extensions --show-versions' \
        /usr/local/bin/noid-update-all.sh 2>/dev/null \
   || grep -qF 'sudo unzip' /usr/local/bin/noid-update-all.sh 2>/dev/null; then
    log "  FAIL: Module 25 extension update transaction/identity contract invalid"
    fail=$((fail + 1))
fi
for thunderbird_update_pref in \
    'defaultPref("app.update.auto", false);' \
    'defaultPref("app.update.silent", false);' \
    'defaultPref("extensions.update.enabled", false);' \
    'defaultPref("extensions.update.autoUpdateDefault", false);' \
    'defaultPref("extensions.systemAddon.update.enabled", false);'; do
    if ! grep -qFx "$thunderbird_update_pref" \
            /usr/share/noid-thunderbird/mozilla.cfg 2>/dev/null; then
        log "  FAIL: Module 35 Thunderbird background update suppression missing: $thunderbird_update_pref"
        fail=$((fail + 1))
    fi
done
for firefox_update_pref in \
    'defaultPref("app.update.auto", false);' \
    'defaultPref("extensions.update.enabled", false);' \
    'defaultPref("extensions.update.autoUpdateDefault", false);' \
    'defaultPref("extensions.systemAddon.update.enabled", false);'; do
    if ! grep -qFx "$firefox_update_pref" \
            /usr/lib64/firefox/mozilla.cfg 2>/dev/null; then
        log "  FAIL: Module 16 Firefox background update suppression missing: $firefox_update_pref"
        fail=$((fail + 1))
    fi
done
for mozilla_dns_contract in \
    "/usr/lib64/firefox/mozilla.cfg|/usr/share/noid-firefox/user.js|Firefox" \
    "/usr/lib64/thunderbird/mozilla.cfg|/usr/share/noid-thunderbird/user.js|Thunderbird"; do
    IFS='|' read -r mozilla_cfg mozilla_userjs mozilla_name \
        <<< "$mozilla_dns_contract"
    if ! grep -qFx 'defaultPref("network.trr.mode", 5);' \
            "$mozilla_cfg" 2>/dev/null || \
       ! grep -qFx 'defaultPref("doh-rollout.home-region", "global");' \
            "$mozilla_cfg" 2>/dev/null || \
       grep -Eq '^defaultPref\("network\.trr\.(uri|custom_uri|bootstrapAddr)"' \
            "$mozilla_cfg" 2>/dev/null || \
       grep -Eq '^[[:space:]]*user_pref\("network\.trr\.' \
            "$mozilla_userjs" 2>/dev/null; then
        log "  FAIL: $mozilla_name provider-compatible, user-overridable DNS contract invalid"
        fail=$((fail + 1))
    fi
done

# Four-app first-party suite — one shared design/runtime contract,
# four exact identities, no symlink substitution and complete Python syntax.
for app in /usr/local/bin/noid-welcome.sh \
           /usr/local/bin/noid-update \
           /usr/local/bin/noid-network \
           /usr/local/bin/noid-tools; do
    if [ ! -f "$app" ] || [ -L "$app" ] || [ ! -x "$app" ] \
            || ! python3 -c 'import pathlib,sys; p=sys.argv[1]; compile(pathlib.Path(p).read_text(), p, "exec")' \
                "$app" 2>/dev/null \
            || ! grep -q '^import noid_ui$' "$app"; then
        log "  FAIL: first-party app contract incomplete: $app"
        fail=$((fail + 1))
    fi
done
if [ ! -f /usr/lib/noid-privacy/noid_ui.py ] \
        || [ -L /usr/lib/noid-privacy/noid_ui.py ] \
        || [ "$(stat -c '%U:%G:%a' /usr/lib/noid-privacy/noid_ui.py 2>/dev/null || true)" != 'root:root:644' ] \
        || ! python3 -c 'import pathlib,sys; p=sys.argv[1]; compile(pathlib.Path(p).read_text(), p, "exec")' \
            /usr/lib/noid-privacy/noid_ui.py 2>/dev/null; then
    log "  FAIL: shared first-party application design contract missing/invalid"
    fail=$((fail + 1))
fi
if ! grep -qF 'def accessible(widget, label, description=' \
        /usr/lib/noid-privacy/noid_ui.py \
   || ! grep -qF 'Gtk.AccessibleProperty.DESCRIPTION' \
        /usr/lib/noid-privacy/noid_ui.py \
   || ! grep -qF 'Gtk.AccessibleRelation.LABELLED_BY' \
        /usr/lib/noid-privacy/noid_ui.py \
   || ! grep -qF 'Gtk.AccessibleRelation.DESCRIBED_BY' \
        /usr/lib/noid-privacy/noid_ui.py \
   || ! grep -qF 'Gtk.AccessibleList.new_from_list' \
        /usr/lib/noid-privacy/noid_ui.py \
   || ! grep -qF 'def accessible_row(row, description=None)' \
        /usr/lib/noid-privacy/noid_ui.py \
   || ! grep -qF 'def _prepare_row_text_labels(row)' \
        /usr/lib/noid-privacy/noid_ui.py \
   || ! grep -qF "not child.has_css_class('noid-emoji')" \
        /usr/lib/noid-privacy/noid_ui.py \
   || ! grep -qF "not child.has_css_class('noid-step-num')" \
        /usr/lib/noid-privacy/noid_ui.py \
   || ! grep -qF 'def bind_view_switcher_accessibility' \
        /usr/lib/noid-privacy/noid_ui.py \
   || ! grep -qF 'noid_ui.accessible(' /usr/local/bin/noid-update \
   || ! grep -qF 'noid_ui.accessible_row(' /usr/local/bin/noid-network; then
    log "  FAIL: first-party explicit accessibility contract incomplete"
    fail=$((fail + 1))
fi
for desktop_contract in \
    '/usr/share/applications/noid-welcome.desktop|noid-privacy-setup|com.noidprivacy.Welcome' \
    '/usr/share/applications/noid-update-all.desktop|noid-privacy-update|com.noidprivacy.Update' \
    '/usr/share/applications/noid-network.desktop|noid-privacy-network|com.noidprivacy.Network' \
    '/usr/share/applications/noid-tools.desktop|noid-privacy-tools|com.noidprivacy.Tools'; do
    IFS='|' read -r desktop icon wmclass <<<"$desktop_contract"
    if [ ! -f "$desktop" ] || [ -L "$desktop" ] \
            || ! grep -qxF "Icon=$icon" "$desktop" \
            || ! grep -qxF "StartupWMClass=$wmclass" "$desktop" \
            || { command -v desktop-file-validate >/dev/null 2>&1 \
                 && ! desktop-file-validate "$desktop" >/dev/null 2>&1; }; then
        log "  FAIL: first-party desktop identity incomplete: $desktop"
        fail=$((fail + 1))
    fi
    app_icon_found=0
    for app_icon_payload in \
            /usr/share/icons/hicolor/*/apps/"$icon".png \
            /usr/share/icons/hicolor/*/apps/"$icon".svg \
            /usr/share/pixmaps/"$icon".png \
            /usr/share/pixmaps/"$icon".svg; do
        if [ -f "$app_icon_payload" ] && [ ! -L "$app_icon_payload" ]; then
            app_icon_found=1
            break
        fi
    done
    if [ "$app_icon_found" -ne 1 ]; then
        log "  FAIL: first-party desktop icon has no regular payload: $icon"
        fail=$((fail + 1))
    fi
done

# Module 26 — Package set consolidation (explicit deps + Tier-1 v2)
# p7zip → 7zip (matches M26 source migration +
# M26 verification fix). Was stale duplicate check.
# gnome-tweaks was removed from the optional base-package surface
# and then removed from this package-presence loop. System dconf locks remain
# authoritative if a user installs Tweaks later. The stale verification entry
# caused an install failure.
for pkg in libnotify python3-audit zenity curl \
           python3-gobject gtk4 libadwaita vte291-gtk4 \
           thunderbird keepassxc qt5-qtwayland btop 7zip nmap tmux \
           btrfs-assistant; do
    if ! rpm -q "$pkg" >/dev/null 2>&1; then
        log "  FAIL: Module 26 package missing: $pkg"
        fail=$((fail + 1))
    fi
done
if [ "$(rpm -qf --qf '%{NAME}' /usr/lib64/qt5/plugins/platforms/libqwayland-generic.so 2>/dev/null || true)" != qt5-qtwayland ]; then
    log "  FAIL: Module 26 Qt5 Wayland platform plugin missing or wrong RPM owner"
    fail=$((fail + 1))
fi
# Module 26 — `unar` is selected; every package named `unrar` stays absent.
# `p7zip-plugins` does not exist in the Fedora 44 repositories and must not be
# counted as automatic-green evidence.
if rpm -q unrar >/dev/null 2>&1; then
    log "  FAIL: Module 26 Silent-Machine/legal violation — unrar present"
    fail=$((fail + 1))
fi
# PipeWire's optional RAOP configuration loads an Avahi-backed Zeroconf
# discoverer on every audio-service start. Base audio does not require it.
if rpm -q pipewire-config-raop >/dev/null 2>&1; then
    log "  FAIL: Module 26 Silent-Machine violation — PipeWire RAOP discovery config present"
    fail=$((fail + 1))
fi
# Module 26 — optional packages documentation
if [ ! -f /usr/share/doc/noid-privacy/26-optional-packages.md ]; then
    log "  FAIL: Module 26 missing: /usr/share/doc/noid-privacy/26-optional-packages.md"
    fail=$((fail + 1))
fi

# Module 27 — Hardware abstraction. Performance policy remains with Fedora,
# the kernel and tuned; NoID Privacy owns only the explicit functional/stability
# controls documented by M27.
if ! rpm -q earlyoom >/dev/null 2>&1; then
    log "  FAIL: Module 27 earlyoom package missing"
    fail=$((fail + 1))
fi
if [ -e /etc/udev/rules.d/60-noid-iosched.rules ]; then
    log "  FAIL: Module 27 retired I/O scheduler override still exists"
    fail=$((fail + 1))
fi
if [ -e /etc/tmpfiles.d/noid-hwp-dynamic-boost.conf ]; then
    log "  FAIL: Module 27 retired Intel HWP override still exists"
    fail=$((fail + 1))
fi
m27_iosched_vendor=/usr/lib/udev/rules.d/60-block-scheduler.rules
if [ ! -f "$m27_iosched_vendor" ] || [ -L "$m27_iosched_vendor" ] || \
   [ "$(rpm -qf --qf '%{NAME}' "$m27_iosched_vendor" 2>/dev/null || true)" != systemd-udev ]; then
    log "  FAIL: Module 27 Fedora scheduler policy missing or wrong owner"
    fail=$((fail + 1))
fi
if [ -e /etc/systemd/zram-generator.conf ] || \
   [ -e /etc/systemd/zram-generator.conf.d/99-noid-privacy.conf ]; then
    log "  FAIL: Module 27 retired zram override still exists"
    fail=$((fail + 1))
fi
m27_zram_vendor=/usr/lib/systemd/zram-generator.conf
if ! rpm -q zram-generator-defaults >/dev/null 2>&1 || \
   [ ! -f "$m27_zram_vendor" ] || [ -L "$m27_zram_vendor" ] || \
   [ "$(rpm -qf --qf '%{NAME}' "$m27_zram_vendor" 2>/dev/null || true)" != zram-generator-defaults ]; then
    log "  FAIL: Module 27 Fedora zram-generator-defaults policy missing or wrong owner"
    fail=$((fail + 1))
fi
if [ ! -f /etc/default/earlyoom ]; then
    log "  FAIL: Module 27 earlyoom config missing"
    fail=$((fail + 1))
fi
# Native UDisks USB/SD noexec mounts plus external NTFS driver preference.
# Both former sync/cache rules must be gone; neither BDI nor queue cache-view
# mutation is an acceptable substitute for supported UDisks power-off.
m27_external_storage_rule=/etc/udev/rules.d/99-noid-external-storage-mount.rules
m27_usb_sync_legacy_rule=/etc/udev/rules.d/99-noid-usb-sync-mount.rules
m27_usb_cache_legacy_rule=/etc/udev/rules.d/99-noid-usb-write-through.rules
if [ ! -f "$m27_external_storage_rule" ] || [ -L "$m27_external_storage_rule" ] || \
   [ "$(stat -Lc '%u:%g:%a:%h' "$m27_external_storage_rule" 2>/dev/null || true)" != 0:0:644:1 ] || \
   [ -e "$m27_usb_sync_legacy_rule" ] || [ -L "$m27_usb_sync_legacy_rule" ] || \
   [ -e "$m27_usb_cache_legacy_rule" ] || [ -L "$m27_usb_cache_legacy_rule" ]; then
    log "  FAIL: Module 27 UDisks external-storage ownership/retirement contract failed"
    fail=$((fail + 1))
elif ! udevadm verify --no-style "$m27_external_storage_rule" >/dev/null 2>&1 || \
     ! grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
         "$m27_external_storage_rule" || \
     ! grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
         "$m27_external_storage_rule" || \
     ! grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
         "$m27_external_storage_rule" || \
     ! grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
         "$m27_external_storage_rule" || \
     ! grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
         "$m27_external_storage_rule" || \
     ! grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
         "$m27_external_storage_rule" || \
     grep -q 'ID_DRIVE_FLASH_MMC' "$m27_external_storage_rule" || \
     grep -Eq '^[^#].*UDISKS_MOUNT_OPTIONS_DEFAULTS.*sync' \
         "$m27_external_storage_rule" || \
     grep -Eq '^[^#].*(RUN\+?=.*queue/write_cache|ATTR\{queue/write_cache\}|echo[[:space:]]+write[[:space:]]+through[[:space:]]*>)' \
         "$m27_external_storage_rule" || \
     grep -Eq '^[^#].*bdi/(max_bytes|min_bytes|strict_limit)' \
         "$m27_external_storage_rule" || \
     ! rpm -q udisks2 >/dev/null 2>&1; then
    log "  FAIL: Module 27 UDisks external-storage noexec/NTFS rule malformed or backend missing"
    fail=$((fail + 1))
fi

# Module 27 — Fedora/upstream own thermal and Intel active-idle hardware
# applicability; NoID Privacy verifies the effective vendor-service states.
if ! rpm -q thermald intel-lpmd tuned tuned-ppd >/dev/null 2>&1; then
    log "  FAIL: Module 27 Fedora hardware/power package set is incomplete"
    fail=$((fail + 1))
fi
for unit in thermald.service tuned.service tuned-ppd.service; do
    m27_power_state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    if [ "$m27_power_state" != enabled ]; then
        log "  FAIL: Module 27 $unit does not follow Fedora enabled preset (state=$m27_power_state)"
        fail=$((fail + 1))
    fi
done
m08_lpmd_state=$(systemctl is-enabled intel_lpmd.service 2>/dev/null || true)
if [ "$m08_lpmd_state" != masked ]; then
    log "  FAIL: intel_lpmd.service is not masked (state=$m08_lpmd_state) — M08 single-EPP-writer policy"
    fail=$((fail + 1))
fi

# Module 28 — Local AI Stack documentation (doc-only, optional opt-in)
if [ ! -f /usr/share/doc/noid-privacy/28-local-ai.md ]; then
    log "  FAIL: Module 28 doc missing: /usr/share/doc/noid-privacy/28-local-ai.md"
    fail=$((fail + 1))
else
    ai_doc_size=$(stat -c %s /usr/share/doc/noid-privacy/28-local-ai.md 2>/dev/null || echo 0)
    ai_doc_size=${ai_doc_size:-0}
    if [ "$ai_doc_size" -lt 8192 ]; then
        log "  FAIL: Module 28 doc too small (${ai_doc_size} bytes, expected >8KB for full guide)"
        fail=$((fail + 1))
    fi
fi
# Module 28 — sanity: image must NOT have any AI-stack RPMs installed (doc-only)
ai_rpm_count=$(rpm -qa 2>/dev/null | grep -ciE '^(ollama|lm-studio|ramalama)' || true)
ai_rpm_count=${ai_rpm_count:-0}
if [ "$ai_rpm_count" -gt 0 ]; then
    log "  FAIL: Module 28 is doc-only, but $ai_rpm_count AI-stack RPM(s) found in image"
    fail=$((fail + 1))
fi

# ----------------------------------------------------------------------------
# Module 29 — Tier-A user docs (00-README + 01-getting-started + 06-vpn-setup)
# ----------------------------------------------------------------------------
# Each doc is a hard pre-requisite for first-boot user onboarding. Each
# must exist AND have a minimum size that excludes empty / truncated writes.
# The enhanced noid-welcome.sh (Module 13) references these paths.

# 00-README.md — master index
if [ ! -f /usr/share/doc/noid-privacy/00-README.md ]; then
    log "  FAIL: Module 29 doc missing: /usr/share/doc/noid-privacy/00-README.md"
    fail=$((fail + 1))
else
    readme_size=$(stat -c %s /usr/share/doc/noid-privacy/00-README.md 2>/dev/null || echo 0)
    readme_size=${readme_size:-0}
    if [ "$readme_size" -lt 4096 ]; then
        log "  FAIL: Module 29 00-README.md too small (${readme_size} bytes, expected >4KB)"
        fail=$((fail + 1))
    fi
    # Must reference the other two Tier-A docs (integrity of the index)
    if ! grep -q '01-getting-started.md' /usr/share/doc/noid-privacy/00-README.md; then
        log "  FAIL: Module 29 00-README.md does not reference 01-getting-started.md"
        fail=$((fail + 1))
    fi
    if ! grep -q '06-vpn-setup.md' /usr/share/doc/noid-privacy/00-README.md; then
        log "  FAIL: Module 29 00-README.md does not reference 06-vpn-setup.md"
        fail=$((fail + 1))
    fi
fi

# 01-getting-started.md — first-day checklist
if [ ! -f /usr/share/doc/noid-privacy/01-getting-started.md ]; then
    log "  FAIL: Module 29 doc missing: /usr/share/doc/noid-privacy/01-getting-started.md"
    fail=$((fail + 1))
else
    getstart_size=$(stat -c %s /usr/share/doc/noid-privacy/01-getting-started.md 2>/dev/null || echo 0)
    getstart_size=${getstart_size:-0}
    if [ "$getstart_size" -lt 4096 ]; then
        log "  FAIL: Module 29 01-getting-started.md too small (${getstart_size} bytes, expected >4KB)"
        fail=$((fail + 1))
    fi
    # Must contain the three priority tiers
    for tier in CRITICAL IMPORTANT RECOMMENDED; do
        if ! grep -q "$tier" /usr/share/doc/noid-privacy/01-getting-started.md; then
            log "  FAIL: Module 29 01-getting-started.md missing tier marker: $tier"
            fail=$((fail + 1))
        fi
    done
fi

# 06-vpn-setup.md — VPN import + killswitch verification
if [ ! -f /usr/share/doc/noid-privacy/06-vpn-setup.md ]; then
    log "  FAIL: Module 29 doc missing: /usr/share/doc/noid-privacy/06-vpn-setup.md"
    fail=$((fail + 1))
else
    vpn_size=$(stat -c %s /usr/share/doc/noid-privacy/06-vpn-setup.md 2>/dev/null || echo 0)
    vpn_size=${vpn_size:-0}
    if [ "$vpn_size" -lt 6144 ]; then
        log "  FAIL: Module 29 06-vpn-setup.md too small (${vpn_size} bytes, expected >6KB)"
        fail=$((fail + 1))
    fi
    # Must cover all four import paths + killswitch verification
    # Case-insensitive grep keeps the required topic check formatting-neutral.
    for kw in ProtonVPN Mullvad "Generic WireGuard" OpenVPN "nmcli connection import" killswitch; do
        if ! grep -qi "$kw" /usr/share/doc/noid-privacy/06-vpn-setup.md; then
            log "  FAIL: Module 29 06-vpn-setup.md missing keyword: $kw"
            fail=$((fail + 1))
        fi
    done
fi

# ----------------------------------------------------------------------------
# Module 15 — AMD PSP companion doc (for
# AMD-awareness; Intel MEI config shipped here is inert on AMD hosts)
# ----------------------------------------------------------------------------
if [ ! -f /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md ]; then
    log "  FAIL: Module 15 AMD PSP doc missing"
    fail=$((fail + 1))
else
    amd_doc_size=$(stat -c %s /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md 2>/dev/null || echo 0)
    amd_doc_size=${amd_doc_size:-0}
    if [ "$amd_doc_size" -lt 3072 ]; then
        log "  FAIL: Module 15 AMD PSP doc too small (${amd_doc_size} bytes, expected >3KB)"
        fail=$((fail + 1))
    fi
    # Regression guard for the corrected platform-specific boundaries.
    for kw in "CVE-2025-2884" "ccp" "A separate card alone is not a guarantee" "There is no single"; do
        if ! grep -qi "$kw" /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md; then
            log "  FAIL: Module 15 AMD PSP doc missing: $kw"
            fail=$((fail + 1))
        fi
    done
fi

# The old Welcome implementation carried a dead MEI_STATUS_FILE anchor. M13's
# current contract deliberately centralizes platform state in noid-status;
# verify both the root-owned schema path and the call that publishes it.
if [ -x /usr/local/bin/noid-status ]; then
    if ! grep -qF 'local file="${1:-/var/lib/noid-privacy/mei-status.txt}"' /usr/local/bin/noid-status \
       || ! grep -qF 'PLATFORM_STATUS=$(read_platform_status)' /usr/local/bin/noid-status; then
        log "  FAIL: Module 13 noid-status missing Module 15 platform-status consumer"
        fail=$((fail + 1))
    fi
fi

# Add-on patch-age surface. M16/M35 disable every browser-owned background
# extension update, so this line is the only thing that tells a user their
# add-ons are stale. Two producers, one consumer and one file path: verify the
# path is literally identical on both sides, because a silent divergence would
# render a permanently reassuring "never checked" instead of a real age.
if [ -x /usr/local/bin/noid-status ]; then
    ext_check_path='${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy/extension-checks'
    if ! grep -qF "EXTENSION_CHECK_STATE_FILE=\"$ext_check_path\"" \
            /usr/local/bin/noid-status \
       || ! grep -qF 'read_extension_check_state' /usr/local/bin/noid-status \
       || ! grep -qF 'fmt_kv_warn "Add-on updates"' /usr/local/bin/noid-status \
       || ! grep -qF "EXTENSION_CHECK_STATE=\"$ext_check_path\"" \
            /usr/local/bin/noid-update-all.sh 2>/dev/null; then
        log "  FAIL: Module 13/25 add-on patch-age surface contract invalid"
        fail=$((fail + 1))
    fi
    unset ext_check_path
fi

# ----------------------------------------------------------------------------
# Module 31 — Tier-C user docs (99-troubleshooting + 00-architecture)
# ----------------------------------------------------------------------------
for tier_c_pair in \
    "99-troubleshooting.md:5120" \
    "00-architecture.md:5120"; do
    tc_file="${tier_c_pair%:*}"
    tc_min="${tier_c_pair#*:}"
    tc_path="/usr/share/doc/noid-privacy/$tc_file"
    if [ ! -f "$tc_path" ]; then
        log "  FAIL: Module 31 doc missing: $tc_path"
        fail=$((fail + 1))
    else
        tc_sz=$(stat -c %s "$tc_path" 2>/dev/null || echo 0)
        tc_sz=${tc_sz:-0}
        if [ "$tc_sz" -lt "$tc_min" ]; then
            log "  FAIL: Module 31 $tc_file too small (${tc_sz} bytes, expected >${tc_min})"
            fail=$((fail + 1))
        fi
    fi
done

# ----------------------------------------------------------------------------
# Module 30 — Tier-B user docs + noid-help CLI
# ----------------------------------------------------------------------------
# 5 Module-specific user-docs + cheatsheet + noid-help CLI navigator.
# Each doc min 3KB; cheatsheet min 4KB; CLI must be executable.

for tier_b_pair in \
    "02-system-security.md:3072" \
    "03-firewall-zones.md:3072" \
    "05-lan-isolation.md:3072" \
    "08-masked-services.md:3072" \
    "11-dns-custom.md:3072" \
    "00-cheatsheet.md:4096"; do
    tb_file="${tier_b_pair%:*}"
    tb_min="${tier_b_pair#*:}"
    tb_path="/usr/share/doc/noid-privacy/$tb_file"

    if [ ! -f "$tb_path" ]; then
        log "  FAIL: Module 30 doc missing: $tb_path"
        fail=$((fail + 1))
    else
        tb_sz=$(stat -c %s "$tb_path" 2>/dev/null || echo 0)
        tb_sz=${tb_sz:-0}
        if [ "$tb_sz" -lt "$tb_min" ]; then
            log "  FAIL: Module 30 $tb_file too small (${tb_sz} bytes, expected >${tb_min})"
            fail=$((fail + 1))
        fi
    fi
done

if [ ! -x /usr/local/bin/noid-help ]; then
    log "  FAIL: Module 30 /usr/local/bin/noid-help missing or not executable"
    fail=$((fail + 1))
elif ! bash -n /usr/local/bin/noid-help 2>/dev/null; then
    log "  FAIL: Module 30 noid-help syntax error"
    fail=$((fail + 1))
else
    # Must support the 3 modes (list/open/search)
    for mode in "_list_topics" "_open_topic" "_search"; do
        if ! grep -q "$mode" /usr/local/bin/noid-help; then
            log "  FAIL: Module 30 noid-help missing function: $mode"
            fail=$((fail + 1))
        fi
    done
fi

# ----------------------------------------------------------------------------
# Health stamp sanity — pattern
# (current = 14 adopters —
#  see EXPECTED_STAMPS below for authoritative live list)
# ----------------------------------------------------------------------------
# Per docs/engineering-health-stamp-pattern.md, Modules write
# /var/lib/noid-privacy/stamp-NN-*.ok on successful completion. 99-finalize
# verifies each exact filename and binds it to its one expected module/name
# tuple plus status=ok. Wildcard existence alone is insufficient: a renamed or
# copied stamp for another module must never satisfy the gate.
#
# Adopters: M16 + M28 + M29 (proof-of-concept) + M30 + M31 + M32 + M33 +
# M34 + M35 + M36 + M37 + M40 + M41 + M42 = 14 modules.
# Pattern strongly canonical.
#
# EXPECTED_STAMPS closes both the late-addition gap and filename/content
# substitution. Any new adopter must be added with its canonical name here.
# M28 was added through its paired retrofit; later M37 and M42 additions were
# likewise paired with their canonical module:name entry here.

EXPECTED_STAMPS=(
    "16:firefox"
    "28:local-ai-docs"
    "29:user-docs"
    "30:user-docs-tier-b"
    "31:user-docs-tier-c"
    "32:branding"
    "33:operational-hygiene"
    "34:firefox-playground"
    "35:thunderbird"
    "36:noid-network-app"
    "37:noid-tools-app"
    "40:audit-bundle"
    "41:anaconda-cleanup"
    "42:forensic-retention"
)
expected_stamp_paths=" "
for stamp_spec in "${EXPECTED_STAMPS[@]}"; do
    stamp_id=${stamp_spec%%:*}
    stamp_name_expected=${stamp_spec#*:}
    case "$stamp_id" in
        36) stamp_file=/var/lib/noid-privacy/stamp-36-noid-network.ok ;;
        *)  stamp_file="/var/lib/noid-privacy/stamp-${stamp_id}-${stamp_name_expected}.ok" ;;
    esac
    expected_stamp_paths+="${stamp_file} "

    if [ ! -f "$stamp_file" ] || [ -L "$stamp_file" ]; then
        log "  FAIL: exact health stamp missing or not a regular non-symlink: $stamp_file"
        fail=$((fail + 1))
        continue
    fi
    stamp_meta=$(stat -c '%u:%g:%a' "$stamp_file" 2>/dev/null || true)
    if [ "$stamp_meta" != "0:0:644" ]; then
        log "  FAIL: stamp $stamp_file metadata is '$stamp_meta' (expected 0:0:644)"
        fail=$((fail + 1))
        continue
    fi
    if [ "$(grep -c '^module=' "$stamp_file" || true)" -ne 1 ] \
       || [ "$(grep -c '^name=' "$stamp_file" || true)" -ne 1 ] \
       || [ "$(grep -c '^status=' "$stamp_file" || true)" -ne 1 ] \
       || ! grep -qxF "module=${stamp_id}" "$stamp_file" \
       || ! grep -qxF "name=${stamp_name_expected}" "$stamp_file" \
       || ! grep -qxF 'status=ok' "$stamp_file"; then
        log "  FAIL: stamp filename/content binding invalid: $stamp_file"
        fail=$((fail + 1))
        continue
    fi
    log "  [OK] exact health stamp M${stamp_id} (${stamp_name_expected}): status=ok"
done

# Stale/unknown stamps are not harmless: they make a generic wildcard audit
# ambiguous and can conceal a removed adopter. Require the directory to match
# the canonical set exactly.
for stamp_file in /var/lib/noid-privacy/stamp-*.ok; do
    [ -e "$stamp_file" ] || continue
    case "$expected_stamp_paths" in
        *" $stamp_file "*) ;;
        *)
            log "  FAIL: unexpected health stamp outside canonical set: $stamp_file"
            fail=$((fail + 1))
            ;;
    esac
done

# ----------------------------------------------------------------------------
# Module 13 — noid-welcome.sh enhanced (--again flag)
# ----------------------------------------------------------------------------
# The welcome script must (a) handle --again, (b) import GTK4/libadwaita,
# (c) know the documentation directory and (d) launch 01-getting-started.md.
# These checks guard against the retired notification-only implementation.

if [ ! -x /usr/local/bin/noid-welcome.sh ]; then
    log "  FAIL: Module 13 noid-welcome.sh missing or not executable"
    fail=$((fail + 1))
else
    if ! grep -q -- '--again' /usr/local/bin/noid-welcome.sh; then
        log "  FAIL: Module 13 noid-welcome.sh missing --again flag support"
        fail=$((fail + 1))
    fi
    # zenity check replaced by libadwaita check
    # (welcome rewritten in Python GTK4 + libadwaita, no longer uses zenity)
    if ! grep -q "gi.require_version.*Adw" /usr/local/bin/noid-welcome.sh; then
        log "  FAIL: Module 13 noid-welcome.sh missing libadwaita import"
        fail=$((fail + 1))
    fi
    if ! grep -q '/usr/share/doc/noid-privacy' /usr/local/bin/noid-welcome.sh; then
        log "  FAIL: Module 13 noid-welcome.sh missing doc-dir reference"
        fail=$((fail + 1))
    fi
    if ! grep -q '01-getting-started.md' /usr/local/bin/noid-welcome.sh; then
        log "  FAIL: Module 13 noid-welcome.sh does not launch getting-started guide"
        fail=$((fail + 1))
    fi
fi

# Compiled dconf database
if [ ! -f /etc/dconf/db/distro ]; then
    log "  FAIL: /etc/dconf/db/distro binary database not compiled"
    fail=$((fail + 1))
fi

# ----------------------------------------------------------------------------
# Module 32 — Fedora trademark rebrand (os-release + issue + system-release)
# ----------------------------------------------------------------------------
# Phase 1 verifies the text rebrand. M32 must have rewritten /etc/os-release,
# /etc/issue and /etc/system-release and installed the trademark disclaimer;
# mandatory Plymouth/avatar assets are checked separately below.

if [ ! -f /etc/os-release ]; then
    log "  FAIL: Module 32 /etc/os-release missing"
    fail=$((fail + 1))
elif ! grep -q '^NAME="NoID Privacy Workstation"' /etc/os-release; then
    log "  FAIL: Module 32 /etc/os-release not rebranded (NAME missing)"
    fail=$((fail + 1))
elif ! grep -q '^ID=noid-privacy-workstation' /etc/os-release; then
    log "  FAIL: Module 32 /etc/os-release not rebranded (ID missing)"
    fail=$((fail + 1))
fi

# VARIANT_ID is required for Anaconda profile
# detection. Without it, Anaconda falls back to default config which sets
# efi_dir=default, breaking gen_grub_cfgstub bootloader install. Also
# required for full lang-list in Welcome screen (use_geolocation=False).
if ! grep -q '^VARIANT_ID=workstation$' /etc/os-release; then
    log "  FAIL: Module 32 /etc/os-release VARIANT_ID=workstation missing (SHIP-CRITICAL)"
    log "        Anaconda profile detection requires (ID, VARIANT_ID) tuple"
    fail=$((fail + 1))
fi

# /etc/anaconda/profile.d/noid-privacy.conf
# is the second half of profile detection. Without it, even with VARIANT_ID
# in os-release, Anaconda finds no matching profile config.
if [ ! -f /etc/anaconda/profile.d/noid-privacy.conf ]; then
    log "  FAIL: Module 32 /etc/anaconda/profile.d/noid-privacy.conf missing (SHIP-CRITICAL)"
    fail=$((fail + 1))
elif ! grep -q '^profile_id = noid-privacy-workstation$' /etc/anaconda/profile.d/noid-privacy.conf; then
    log "  FAIL: Module 32 anaconda profile.d profile_id mismatch"
    fail=$((fail + 1))
elif ! grep -q '^variant_id = workstation$' /etc/anaconda/profile.d/noid-privacy.conf; then
    log "  FAIL: Module 32 anaconda profile.d variant_id mismatch (must match os-release)"
    fail=$((fail + 1))
elif ! grep -q '^use_geolocation = False$' /etc/anaconda/profile.d/noid-privacy.conf; then
    log "  FAIL: Module 32 anaconda profile.d use_geolocation should be False (privacy)"
    fail=$((fail + 1))
fi

# Every package and representative locale named by the
# canonical repository manifest is required. An aggregate package count is not
# equivalent: a duplicate/unrelated langpack could conceal a missing promised
# language, and package presence alone does not prove --inst-langs retained the
# locale data during compose.
if AVAILABLE_LOCALES=$(locale -a 2>/dev/null); then
    :
else
    AVAILABLE_LOCALES=""
    log "  FAIL: locale -a failed; cannot verify installed locale data"
    fail=$((fail + 1))
fi
LANGPACK_EXPECTED=0
LANGPACK_COMPLETE=0
while IFS='|' read -r langpack_pkg locale_name; do
    [ -n "$langpack_pkg" ] || continue
    LANGPACK_EXPECTED=$((LANGPACK_EXPECTED + 1))
    if ! rpm -q "$langpack_pkg" >/dev/null 2>&1; then
        log "  FAIL: required locale package missing: $langpack_pkg"
        fail=$((fail + 1))
        continue
    fi
    if ! grep -Fxq "$locale_name" <<< "$AVAILABLE_LOCALES"; then
        log "  FAIL: required locale data missing: $locale_name ($langpack_pkg)"
        fail=$((fail + 1))
        continue
    fi
    LANGPACK_COMPLETE=$((LANGPACK_COMPLETE + 1))
done <<'REQUIRED_GLIBC_LANGPACKS_EOF'
glibc-langpack-en|en_US.utf8
glibc-langpack-de|de_DE.utf8
glibc-langpack-fr|fr_FR.utf8
glibc-langpack-es|es_ES.utf8
glibc-langpack-it|it_IT.utf8
glibc-langpack-pt|pt_BR.utf8
glibc-langpack-nl|nl_NL.utf8
glibc-langpack-pl|pl_PL.utf8
glibc-langpack-ru|ru_RU.utf8
glibc-langpack-zh|zh_CN.utf8
glibc-langpack-ja|ja_JP.utf8
glibc-langpack-ko|ko_KR.utf8
glibc-langpack-ar|ar_SA.utf8
REQUIRED_GLIBC_LANGPACKS_EOF
if [ "$LANGPACK_COMPLETE" -eq "$LANGPACK_EXPECTED" ]; then
    log "  OK: complete canonical locale payload (${LANGPACK_COMPLETE}/${LANGPACK_EXPECTED})"
fi

# Obsolete verification removed (see master.ks NOTE about
# colon-separated --inst-langs in %packages section:
# stale line ref "master.ks line 364" replaced with semantic anchor):
# Original check `rpm -q langtable-data` failed because that package doesn't
# exist on F44. `python3-langtable` is auto-installed as anaconda dep and
# provides the data via /usr/lib/python3.14/site-packages/langtable/data/.
# Anaconda's Welcome lang picker uses `list_all_locales()` (returns 336) and
# `list_locales(languageId=X)` (returns N per language) — both work fine
# without any extra packages beyond the canonical glibc-langpack-XX list.

if [ ! -f /etc/issue ]; then
    log "  FAIL: Module 32 /etc/issue missing"
    fail=$((fail + 1))
elif ! grep -q 'NoID Privacy Workstation' /etc/issue; then
    log "  FAIL: Module 32 /etc/issue not rebranded"
    fail=$((fail + 1))
fi

if [ ! -f /etc/system-release ]; then
    log "  FAIL: Module 32 /etc/system-release missing"
    fail=$((fail + 1))
elif ! grep -q 'NoID Privacy Workstation' /etc/system-release; then
    log "  FAIL: Module 32 /etc/system-release not rebranded"
    fail=$((fail + 1))
fi

# Runtime fedora-release recovery may restore identity files inside DNF, but
# its BLS write is a durable post-transaction request. The service is ordered
# after M21 and publishes under both the global boot lock and its queue-handoff
# lock; the compose seeds exactly one first-install request.
for identity_artifact in \
        /usr/local/sbin/noid-restore-identity \
        /usr/lib/tmpfiles.d/noid-identity-bls-refresh.conf \
        /etc/systemd/system/noid-identity-bls-refresh.service \
        /etc/systemd/system/noid-identity-bls-refresh.path; do
    if [ ! -f "$identity_artifact" ] || [ -L "$identity_artifact" ]; then
        log "  FAIL: Module 32 guarded identity/BLS artifact missing or unsafe: $identity_artifact"
        fail=$((fail + 1))
    fi
done
identity_action=/etc/dnf/libdnf5-plugins/actions.d/noid-identity.actions
branding_action=/etc/dnf/libdnf5-plugins/actions.d/noid-branding.actions
if [ "$(stat -c '%U:%G:%a' "$identity_action" 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(grep -c '^post_transaction:' "$identity_action" 2>/dev/null || true)" -ne 1 ] \
   || ! grep -qxF \
        'post_transaction:fedora-release*:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-identity\ >/dev/null' \
        "$identity_action" \
   || [ "$(stat -c '%U:%G:%a' "$branding_action" 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(grep -c '^post_transaction:' "$branding_action" 2>/dev/null || true)" -ne 2 ] \
   || ! grep -qxF \
        'post_transaction:generic-logos*:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-branding\ >/dev/null' \
        "$branding_action" \
   || ! grep -qxF \
        'post_transaction:plymouth-theme-spinner:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-branding\ >/dev/null' \
        "$branding_action"; then
    log "  FAIL: Module 32 host-scoped identity/branding action contract invalid"
    fail=$((fail + 1))
fi
unset identity_action branding_action
if ! grep -qF 'exec 9>"$BOOT_LOCK"' /usr/local/sbin/noid-restore-identity \
        || ! grep -qF 'basis_record=$("$GUARD"' /usr/local/sbin/noid-restore-identity \
        || ! grep -qF 'mv -fT -- "$temporary" "$bls"' /usr/local/sbin/noid-restore-identity \
        || ! grep -qF 'ReadWritePaths=/boot /var/lib/noid-privacy /run/lock/noid-identity-bls-refresh.lock /run/lock/noid-boot-mutation.lock' \
            /etc/systemd/system/noid-identity-bls-refresh.service \
        || grep -qxF 'ProtectKernelModules=yes' \
            /etc/systemd/system/noid-identity-bls-refresh.service \
        || ! grep -qxF 'ProtectKernelModules=no' \
            /etc/systemd/system/noid-identity-bls-refresh.service \
        || ! grep -qxF 'CapabilityBoundingSet=~CAP_SYS_MODULE' \
            /etc/systemd/system/noid-identity-bls-refresh.service \
        || ! grep -qxF 'SystemCallFilter=~@module' \
            /etc/systemd/system/noid-identity-bls-refresh.service \
        || ! grep -qxF 'SystemCallErrorNumber=EPERM' \
            /etc/systemd/system/noid-identity-bls-refresh.service; then
    log "  FAIL: Module 32 runtime BLS writer bypasses the shared guarded publication contract"
    fail=$((fail + 1))
fi
if [ ! -L /etc/systemd/system/multi-user.target.wants/noid-identity-bls-refresh.service ] \
        || [ ! -L /etc/systemd/system/multi-user.target.wants/noid-identity-bls-refresh.path ]; then
    log "  FAIL: Module 32 durable identity BLS service/path is not enabled"
    fail=$((fail + 1))
fi
if [ ! -f /var/lib/noid-privacy/identity-bls-refresh.pending ] \
        || [ -L /var/lib/noid-privacy/identity-bls-refresh.pending ] \
        || [ "$(stat -c '%U:%G:%a:%h' \
            /var/lib/noid-privacy/identity-bls-refresh.pending 2>/dev/null || true)" \
            != root:root:600:1 ] \
        || [ "$(cat /var/lib/noid-privacy/identity-bls-refresh.pending 2>/dev/null || true)" \
            != version=1 ]; then
    log "  FAIL: Module 32 initial durable identity BLS request is missing or malformed"
    fail=$((fail + 1))
fi

# Module 32 — trademark-notice.md (Fedora trademark disclosure document).
# M99 cross-verifies this trademark-correctness addition.
if [ ! -f /usr/share/doc/noid-privacy/trademark-notice.md ]; then
    log "  FAIL: Module 32 trademark-notice.md missing (Fedora trademark disclosure)"
    fail=$((fail + 1))
else
    tn_size=$(stat -c %s /usr/share/doc/noid-privacy/trademark-notice.md 2>/dev/null || echo 0)
    tn_size=${tn_size:-0}
    if [ "$tn_size" -lt 4096 ]; then
        log "  FAIL: Module 32 trademark-notice.md too small (${tn_size} bytes, expected >4KB)"
        fail=$((fail + 1))
    fi
    # Must reference Fedora trademark guidelines + Red Hat IP context
    # Case-insensitive grep keeps the disclosure check formatting-neutral.
    for kw in "Fedora" "trademark" "Red Hat"; do
        if ! grep -qi "$kw" /usr/share/doc/noid-privacy/trademark-notice.md; then
            log "  FAIL: Module 32 trademark-notice.md missing keyword: $kw"
            fail=$((fail + 1))
        fi
    done
fi

# /etc/issue.d/00-noid-trademark.issue check REMOVED.
# Drop-in file was redundant text-clutter on tty1; trademark notice now lives
# in /etc/os-release (UPSTREAM_BASE), trademark-notice.md, and welcome dialog.

# Module 32 — mandatory Plymouth theme assets
for f in /usr/share/pixmaps/system-logo-white.png \
         /usr/share/plymouth/themes/spinner/watermark.png \
         /etc/plymouth/plymouthd.conf; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 32 mandatory Plymouth asset missing/not regular: $f"
        fail=$((fail + 1))
    fi
done

if [ -f /etc/plymouth/plymouthd.conf ]; then
    if ! grep -qE '^Theme=bgrt$' /etc/plymouth/plymouthd.conf; then
        log "  FAIL: Module 32 plymouthd.conf Theme= not set to bgrt"
        fail=$((fail + 1))
    fi
    # UseSimpledrmNoLuks is a no-LUKS-only renderer policy; Plymouth ignores it
    # when rd.luks.uuid is present. M32 must inherit Fedora's maintained value
    # instead of carrying the retired, falsely described local override.
    if grep -qE '^UseSimpledrmNoLuks=' /etc/plymouth/plymouthd.conf; then
        log "  FAIL: Module 32 plymouthd.conf carries an unexpected local UseSimpledrmNoLuks override"
        fail=$((fail + 1))
    fi
fi

# M21 is the sole first-boot target-kernel Dracut writer. M32's Plymouth
# assets must be part of its pre-publication candidate gate; none of the
# retired competing writer/cleanup artifacts may survive.
if ! grep -qF 'usr/share/plymouth/themes/spinner/watermark.png' \
        /usr/libexec/noid-dracut-hostonly-configure 2>/dev/null; then
    log "  FAIL: Module 21 lacks the M32 Plymouth candidate-content gate"
    fail=$((fail + 1))
fi
for retired in \
    /usr/local/sbin/noid-plymouth-firstboot.sh \
    /usr/local/sbin/noid-plymouth-firstboot-cleanup.sh \
    /etc/systemd/system/noid-plymouth-firstboot.service \
    /etc/systemd/system/noid-plymouth-firstboot-cleanup.service \
    /etc/systemd/system/multi-user.target.wants/noid-plymouth-firstboot.service \
    /etc/systemd/system/multi-user.target.wants/noid-plymouth-firstboot-cleanup.service; do
    if [ -e "$retired" ] || [ -L "$retired" ]; then
        log "  FAIL: retired competing Plymouth Dracut writer remains: $retired"
        fail=$((fail + 1))
    fi
done

# Module 32 — mandatory avatar branding
# Removed verification of /etc/dconf/db/distro.d/42-noid-
# login-logo + its dconf-content-check (login-screen-logo dconf override removed
# per user choice — distro branding cluttered GDM lock-screen with oversized
# overlay; user-avatar via M32 STEP 4 + AccountsService Icon= now carries NoID Privacy
# identity instead).
for f in /etc/skel/.face \
         /etc/skel/.face.icon \
         /usr/share/pixmaps/faces/noid-privacy.png; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 32 mandatory avatar asset missing: $f"
        fail=$((fail + 1))
    fi
done

# Defensive check: login-logo dconf MUST be absent.
if [ -f /etc/dconf/db/distro.d/42-noid-login-logo ]; then
    log "  FAIL: Module 32 stale 42-noid-login-logo dconf present"
    fail=$((fail + 1))
fi

# ----------------------------------------------------------------------------
# Module 33 — Operational Hygiene (user docs + CLIs)
# ----------------------------------------------------------------------------
# M33 ships a health stamp (caught by the stamp loop above) plus 3 user docs
# and 2 CLIs. The stamp loop already covers the status=ok check; here we add
# path-existence verification for the shipped artifacts.

for f in /usr/share/doc/noid-privacy/33-oauth-audit-checklist.md \
         /usr/share/doc/noid-privacy/33-firefox-profile-isolation.md \
         /usr/share/doc/noid-privacy/33-integrity-check-guide.md \
         /usr/local/bin/noid-integrity-check \
         /usr/local/bin/noid-firefox-create-isolated-profile; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 33 missing/not a regular file: $f"
        fail=$((fail + 1))
    fi
done

# ----------------------------------------------------------------------------
# Module 34 — Firefox Playground (amnesic profile)
# ----------------------------------------------------------------------------
# M34 ships a health stamp (caught by the stamp loop above) plus the
# playground overrides JS, .desktop launcher, dconf default, init script and
# XDG autostart. The launcher resolves Fedora's packaged `firefox` icon; no
# separate Playground icon is part of the current artifact contract.

# The /etc/skel/.config/mozilla/firefox/playground/user.js
# entry removed — M34 reverted to runtime per-user playground init via Phase 7
# (noid-firefox-playground-init.sh creates the playground profile on first
# login, not pre-seeded into /etc/skel). Stale verify entry was left over from
# pre-revert M34 design.
for f in /usr/share/noid-firefox/user-playground-overrides.js \
         /usr/share/applications/firefox-playground.desktop \
         /etc/dconf/db/distro.d/16-noid-firefox-playground \
         /usr/local/bin/noid-firefox-playground-init.sh \
         /etc/xdg/autostart/noid-firefox-playground-init.desktop; do
    if [ ! -f "$f" ]; then
        log "  FAIL: Module 34 missing/not a regular file: $f"
        fail=$((fail + 1))
    fi
done

# M34 packaged-icon contract. Keep this synchronized with M34 Phase 3:
# freedesktop icon-name lookup must resolve a Fedora Firefox payload, the
# desktop file must request exactly that name, and no retired NoID Privacy
# `firefox-playground.png` alias may survive an upgrade.
if ! grep -qxF 'Icon=firefox' \
        /usr/share/applications/firefox-playground.desktop 2>/dev/null; then
    log "  FAIL: Module 34 launcher does not use the packaged Firefox icon"
    fail=$((fail + 1))
fi

m34_firefox_icon_found=0
for m34_firefox_icon in \
    /usr/share/icons/hicolor/*/apps/firefox.png \
    /usr/share/icons/hicolor/symbolic/apps/firefox*-symbolic.svg
do
    if [ -f "$m34_firefox_icon" ] && [ ! -L "$m34_firefox_icon" ] && \
       [ "$(rpm -qf --qf '%{NAME}' -- "$m34_firefox_icon" 2>/dev/null || true)" = firefox ]; then
        m34_firefox_icon_found=1
        break
    fi
done
if [ "$m34_firefox_icon_found" -ne 1 ]; then
    log "  FAIL: Module 34 packaged Firefox icon lookup has no payload"
    fail=$((fail + 1))
fi

m34_legacy_icons=()
shopt -s nullglob
m34_legacy_icons=(/usr/share/icons/hicolor/*/apps/firefox-playground.png)
shopt -u nullglob
if [ "${#m34_legacy_icons[@]}" -ne 0 ]; then
    log "  FAIL: Module 34 legacy custom icon alias remains: ${m34_legacy_icons[*]}"
    fail=$((fail + 1))
fi

# ----------------------------------------------------------------------------
# Phase 6: Build-version metadata files
# ----------------------------------------------------------------------------
# Writes /etc/noid-privacy-release and /var/lib/noid-privacy/version with
# release/build/install metadata. The Phase 1 audit found:
# `/etc/noid-privacy-release` and `/var/lib/noid-privacy/version` were missing
# → no build-identification possible besides `os-release` VERSION_ID=44 (no
# build-number marker). This makes audit/support cross-reference impossible
# (which Build is this? When deployed? Which kernel?).
#
# Two files for two audiences:
#   /etc/noid-privacy-release      = os-release-style (ID format), human-read,
#                                    cross-references with /etc/os-release
#                                    (UPSTREAM_BASE, NAME, ID match).
#   /var/lib/noid-privacy/version  = machine-readable key=value (parseable
#                                    by noid-audit, noid-status, welcome dialog).
#
# BUILD_DATE and INSTALL_DATE derive from M32's NOID_BUILD_TIMESTAMP field in
# /etc/noid-build-info, itself bound to the build wrapper's SOURCE_DATE_EPOCH.
# Module 41 re-stamps INSTALL_DATE / install_date with the real installed-system
# first-boot time; M99 must preserve the reproducible build-time source here.
log "Phase 6: Build-version metadata files"

# M32 owns the canonical installed-image kernel selection: it version-sorts
# every installed kernel-core version-release-architecture and records the
# newest one. Consume that reviewed field instead of relying on rpm query
# output order a second time.
# Omitting `head -1` also makes duplicate provenance fields fail closed.
BUILD_INFO=/etc/noid-build-info
KERNEL_VER=unknown
BUILD_ID_VALUE=unknown
BUILD_TIMESTAMP_VALUE=unknown
SOURCE_COMMIT_VALUE=unknown
BASE_ISO_SHA256_VALUE=unknown
BUILD_PROVENANCE_OK=0
if [ -f "$BUILD_INFO" ] && [ ! -L "$BUILD_INFO" ] \
   && [ "$(stat -Lc '%u:%g:%a:%h' -- "$BUILD_INFO" 2>/dev/null || true)" = \
        0:0:644:1 ]; then
    KERNEL_VER=$(sed -nE 's/^NOID_KERNEL="([^"]+)"$/\1/p' "$BUILD_INFO")
    BUILD_ID_VALUE=$(sed -nE 's/^NOID_BUILD_ID="([^"]+)"$/\1/p' "$BUILD_INFO")
    BUILD_TIMESTAMP_VALUE=$(sed -nE 's/^NOID_BUILD_TIMESTAMP="([^"]+)"$/\1/p' "$BUILD_INFO")
    SOURCE_COMMIT_VALUE=$(sed -nE 's/^NOID_SOURCE_COMMIT="([^"]+)"$/\1/p' "$BUILD_INFO")
    BASE_ISO_SHA256_VALUE=$(sed -nE 's/^NOID_BASE_ISO_SHA256="([^"]+)"$/\1/p' "$BUILD_INFO")
    BUILD_PROVENANCE_OK=1
fi
[[ "$KERNEL_VER" =~ ^[0-9][0-9A-Za-z._+~-]*-[0-9][0-9A-Za-z._+~-]*\.x86_64$ ]] \
    || BUILD_PROVENANCE_OK=0
[[ "$BUILD_ID_VALUE" =~ ^[0-9a-f]{12}-[0-9]+$ ]] \
    || BUILD_PROVENANCE_OK=0
[[ "$BUILD_TIMESTAMP_VALUE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
    || BUILD_PROVENANCE_OK=0
[[ "$SOURCE_COMMIT_VALUE" =~ ^[0-9a-f]{40}$ ]] \
    || BUILD_PROVENANCE_OK=0
[[ "$BASE_ISO_SHA256_VALUE" == "not-applicable" \
   || "$BASE_ISO_SHA256_VALUE" =~ ^[0-9a-f]{64}$ ]] \
    || BUILD_PROVENANCE_OK=0
if [ "$BUILD_PROVENANCE_OK" -ne 1 ]; then
    log "  FAIL: canonical build provenance is missing, duplicated or malformed in /etc/noid-build-info"
    fail=$((fail + 1))
fi

cat > /etc/noid-privacy-release <<EOF
NAME="NoID Privacy Workstation"
ID=noid-privacy-workstation
VERSION=44
VARIANT_ID=workstation
UPSTREAM_BASE="Fedora Linux 44"
BUILD_ID=${BUILD_ID_VALUE}
BUILD_DATE=${BUILD_TIMESTAMP_VALUE%%T*}
INSTALL_DATE=${BUILD_TIMESTAMP_VALUE}
SOURCE_COMMIT=${SOURCE_COMMIT_VALUE}
BASE_ISO_SHA256=${BASE_ISO_SHA256_VALUE}
KERNEL="${KERNEL_VER}"
HOME_URL="https://noid-privacy.com"
SUPPORT_URL="https://github.com/NexusOne23/noid-privacy-workstation/issues"
EOF
chmod 0644 /etc/noid-privacy-release
chown root:root /etc/noid-privacy-release

# `/var/lib/noid-privacy` is a shared schema container consumed by unprivileged
# status/UI code and written by multiple root services. Finalize detects drift;
# it must not silently normalize an unsafe or cross-module-inconsistent state.
NOID_STATE_DIR=/var/lib/noid-privacy
NOID_STATE_DIR_OK=1
if [ ! -d "$NOID_STATE_DIR" ] || [ -L "$NOID_STATE_DIR" ]; then
    log "  FAIL: shared NoID Privacy state directory is missing, non-directory or symlinked"
    fail=$((fail + 1))
    NOID_STATE_DIR_OK=0
elif [ "$(stat -c '%a:%U:%G' "$NOID_STATE_DIR" 2>/dev/null || true)" != \
       "755:root:root" ]; then
    log "  FAIL: shared NoID Privacy state directory must be 0755 root:root"
    fail=$((fail + 1))
    NOID_STATE_DIR_OK=0
else
    log "  [OK] shared NoID Privacy state directory is 0755 root:root"
fi

if [ "$NOID_STATE_DIR_OK" -eq 1 ]; then
cat > "$NOID_STATE_DIR/version" <<EOF
build_id=${BUILD_ID_VALUE}
build_date=${BUILD_TIMESTAMP_VALUE%%T*}
install_date=${BUILD_TIMESTAMP_VALUE}
source_commit=${SOURCE_COMMIT_VALUE}
base_iso_sha256=${BASE_ISO_SHA256_VALUE}
upstream=fedora-44
fedora_version_id=44
kernel=${KERNEL_VER}
EOF
chmod 0644 "$NOID_STATE_DIR/version"
chown root:root "$NOID_STATE_DIR/version"
fi

# Verify both closed schemas, including file identity and the exact values that
# M41 later updates atomically. A merely non-empty file is not valid release
# metadata and must never reach the first-boot consumer.
RELEASE_EXPECTED=(
    'NAME="NoID Privacy Workstation"'
    'ID=noid-privacy-workstation'
    'VERSION=44'
    'VARIANT_ID=workstation'
    'UPSTREAM_BASE="Fedora Linux 44"'
    "BUILD_ID=${BUILD_ID_VALUE}"
    "BUILD_DATE=${BUILD_TIMESTAMP_VALUE%%T*}"
    "INSTALL_DATE=${BUILD_TIMESTAMP_VALUE}"
    "SOURCE_COMMIT=${SOURCE_COMMIT_VALUE}"
    "BASE_ISO_SHA256=${BASE_ISO_SHA256_VALUE}"
    "KERNEL=\"${KERNEL_VER}\""
    'HOME_URL="https://noid-privacy.com"'
    'SUPPORT_URL="https://github.com/NexusOne23/noid-privacy-workstation/issues"'
)
VERSION_EXPECTED=(
    "build_id=${BUILD_ID_VALUE}"
    "build_date=${BUILD_TIMESTAMP_VALUE%%T*}"
    "install_date=${BUILD_TIMESTAMP_VALUE}"
    "source_commit=${SOURCE_COMMIT_VALUE}"
    "base_iso_sha256=${BASE_ISO_SHA256_VALUE}"
    'upstream=fedora-44'
    'fedora_version_id=44'
    "kernel=${KERNEL_VER}"
)
RELEASE_METADATA_OK=1
for metadata_spec in \
    "/etc/noid-privacy-release:${#RELEASE_EXPECTED[@]}" \
    "$NOID_STATE_DIR/version:${#VERSION_EXPECTED[@]}"; do
    metadata_path=${metadata_spec%:*}
    metadata_lines=${metadata_spec##*:}
    if [ ! -f "$metadata_path" ] || [ -L "$metadata_path" ] \
       || [ "$(stat -Lc '%u:%g:%a:%h' -- "$metadata_path" 2>/dev/null || true)" != \
            0:0:644:1 ] \
       || [ "$(wc -l < "$metadata_path" 2>/dev/null || true)" -ne \
            "$metadata_lines" ] \
       || ! matchpathcon -V "$metadata_path" >/dev/null 2>&1; then
        RELEASE_METADATA_OK=0
    fi
done
for expected_line in "${RELEASE_EXPECTED[@]}"; do
    [ "$(grep -cFx -- "$expected_line" /etc/noid-privacy-release 2>/dev/null || true)" -eq 1 ] \
        || RELEASE_METADATA_OK=0
done
for expected_line in "${VERSION_EXPECTED[@]}"; do
    [ "$(grep -cFx -- "$expected_line" "$NOID_STATE_DIR/version" 2>/dev/null || true)" -eq 1 ] \
        || RELEASE_METADATA_OK=0
done
if [ "$RELEASE_METADATA_OK" -eq 1 ]; then
    log "  [OK] /etc/noid-privacy-release written ($(wc -l < /etc/noid-privacy-release) lines)"
    log "  [OK] /var/lib/noid-privacy/version written ($(wc -l < /var/lib/noid-privacy/version) lines)"
else
    log "  FAIL: build-version metadata schema, bytes, metadata or SELinux label invalid"
    fail=$((fail + 1))
fi

# ----------------------------------------------------------------------------
# Phase 7: Verify RPM evidence boundaries without normalizing state
# ----------------------------------------------------------------------------
# A finalizer may detect an unexpected package-owned state but must never repair
# it in place or generate an allowlist from the same bytes it is meant to
# inspect. The producer module must establish these postconditions earlier.
log "Phase 7: RPM state + auditor default-run boundary"

if [ ! -d /boot/grub2 ]; then
    log "  FAIL: expected RPM-owned directory missing: /boot/grub2"
    fail=$((fail + 1))
elif [ "$(stat -c '%a:%U:%G' /boot/grub2 2>/dev/null)" != "700:root:root" ]; then
    log "  FAIL: /boot/grub2 differs from required 0700 root:root state"
    fail=$((fail + 1))
else
    log "  [OK] /boot/grub2 already has required 0700 root:root state"
fi

if [ "$(readlink /etc/sysconfig/grub 2>/dev/null)" != "../default/grub" ]; then
    log "  FAIL: /etc/sysconfig/grub is not the required ../default/grub symlink"
    fail=$((fail + 1))
else
    log "  [OK] /etc/sysconfig/grub already has the required symlink target"
fi

audit_payload=/usr/local/bin/noid-privacy-linux.sh
audit_wrapper=/usr/local/bin/noid-audit
audit_version_marker=/etc/noid/audit-version
audit_stamp=/var/lib/noid-privacy/stamp-40-audit-bundle.ok
if [ ! -f "$audit_payload" ] || [ -L "$audit_payload" ] \
   || [ ! -x "$audit_payload" ] \
   || [ "$(readlink -e -- "$audit_payload" 2>/dev/null || true)" != \
        "$audit_payload" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' "$audit_payload" 2>/dev/null || true)" != \
        0:0:755:1 ] \
   || ! matchpathcon -V "$audit_payload" >/dev/null 2>&1; then
    log "  FAIL: bundled audit tool trust contract invalid"
    fail=$((fail + 1))
elif [ ! -f "$audit_wrapper" ] || [ -L "$audit_wrapper" ] \
   || [ ! -x "$audit_wrapper" ] \
   || [ "$(readlink -e -- "$audit_wrapper" 2>/dev/null || true)" != \
        "$audit_wrapper" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' "$audit_wrapper" 2>/dev/null || true)" != \
        0:0:755:1 ] \
   || ! matchpathcon -V "$audit_wrapper" >/dev/null 2>&1 \
   || ! /usr/bin/bash -n "$audit_wrapper" 2>/dev/null \
   || [ ! -f "$audit_version_marker" ] || [ -L "$audit_version_marker" ] \
   || [ "$(readlink -e -- "$audit_version_marker" 2>/dev/null || true)" != \
        "$audit_version_marker" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' "$audit_version_marker" \
            2>/dev/null || true)" != 0:0:644:1 ] \
   || ! matchpathcon -V "$audit_version_marker" >/dev/null 2>&1 \
   || [ ! -f "$audit_stamp" ] || [ -L "$audit_stamp" ] \
   || [ "$(readlink -e -- "$audit_stamp" 2>/dev/null || true)" != \
        "$audit_stamp" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' "$audit_stamp" 2>/dev/null || true)" != \
        0:0:644:1 ] \
   || ! matchpathcon -V "$audit_stamp" >/dev/null 2>&1; then
    log "  FAIL: bundled auditor wrapper/stamp contract missing"
    fail=$((fail + 1))
else
    audit_expected_sha=$(sed -n 's/^audit_sha256=//p' "$audit_stamp")
    audit_expected_size=$(sed -n 's/^audit_size=//p' "$audit_stamp")
    audit_expected_wrapper_sha=$(
        sed -n 's/^wrapper_sha256=//p' "$audit_stamp"
    )
    audit_expected_version_marker_sha=$(
        sed -n 's/^version_marker_sha256=//p' "$audit_stamp"
    )
    audit_actual_sha=$(sha256sum "$audit_payload" | awk '{print $1}')
    audit_actual_size=$(stat -c %s "$audit_payload" 2>/dev/null || true)
    audit_actual_wrapper_sha=$(sha256sum "$audit_wrapper" | awk '{print $1}')
    audit_actual_version_marker_sha=$(
        sha256sum "$audit_version_marker" | awk '{print $1}'
    )
    if [ "$(grep -c '^audit_sha256=' "$audit_stamp" || true)" -ne 1 ] \
       || [ "$(grep -c '^audit_size=' "$audit_stamp" || true)" -ne 1 ] \
       || [ "$(grep -c '^wrapper_sha256=' "$audit_stamp" || true)" -ne 1 ] \
       || [ "$(grep -c '^version_marker_sha256=' "$audit_stamp" || true)" \
                -ne 1 ] \
       || [[ ! "$audit_expected_sha" =~ ^[0-9a-f]{64}$ ]] \
       || [[ ! "$audit_expected_size" =~ ^[1-9][0-9]*$ ]] \
       || [[ ! "$audit_expected_wrapper_sha" =~ ^[0-9a-f]{64}$ ]] \
       || [[ ! "$audit_expected_version_marker_sha" =~ ^[0-9a-f]{64}$ ]] \
       || [ "$audit_actual_sha" != "$audit_expected_sha" ] \
       || [ "$audit_actual_size" != "$audit_expected_size" ] \
       || [ "$audit_actual_wrapper_sha" != "$audit_expected_wrapper_sha" ] \
       || [ "$audit_actual_version_marker_sha" != \
            "$audit_expected_version_marker_sha" ]; then
        log "  FAIL: bundled auditor integration bytes differ from M40 evidence"
        fail=$((fail + 1))
    elif ! grep -qFx 'readonly ENV_BIN="/usr/bin/env"' "$audit_wrapper" \
       || ! grep -qFx \
            '    exec "$SUDO" -- "$ENV_BIN" "${root_environment[@]}" "$BASH_BIN" "$SCRIPT" "$@"' \
            "$audit_wrapper" \
       || ! grep -qFx '    AUDIT_ARGS=(--ai)' "$audit_wrapper" \
       || ! grep -qFx \
            'run_root_audit --offline "${AUDIT_ARGS[@]}"' "$audit_wrapper" \
       || ! grep -qFx \
            '    [ "$AIDE_LIVE" -eq 0 ] || root_environment+=(NOID_AIDE_LIVE=1)' \
            "$audit_wrapper" \
       || ! grep -qFx \
            '        init) root_environment+=(NOID_RPM_BASELINE_INIT=1) ;;' \
            "$audit_wrapper" \
       || ! grep -qFx \
            '        update) root_environment+=(NOID_RPM_BASELINE_UPDATE=1) ;;' \
            "$audit_wrapper"; then
        log "  FAIL: noid-audit default/explicit opt-in contract is incomplete"
        fail=$((fail + 1))
    else
        # M40 evidence owns the requested auditor pin; this gate makes no
        # external publication-state claim.
        # Ambient evidence variables are removed after sudo. The wrapper adds
        # exact value 1 only for a matching, explicit user-supplied option.
        log "  [OK] bundled auditor integration exact; default is non-remediating/offline"
    fi
fi

for forbidden_rpm_trust_state in \
    /usr/share/noid-privacy/rpm-managed-paths.txt \
    /etc/noid/rpm-expected-drift-v1.tsv \
    /var/lib/noid-privacy/rpm-baseline.txt; do
    if [ -e "$forbidden_rpm_trust_state" ] || [ -L "$forbidden_rpm_trust_state" ]; then
        log "  FAIL: forbidden self-generated RPM trust state present: $forbidden_rpm_trust_state"
        fail=$((fail + 1))
    fi
done

# ----------------------------------------------------------------------------
# Phase 8: Image package manifest (transparency record)
# ----------------------------------------------------------------------------
# Record the exact RPM set of this image (squashfs state, before the installed
# system's first-boot anaconda cleanup) so a running system can be diffed
# against what the image shipped. Deterministically sorted, no timestamps
# (reproducibility posture: docs/build-reproducibility.md). This is a
# transparency record, never a trust or suppression input.
log "Phase 8: Writing image package manifest"

PACKAGE_MANIFEST=/usr/share/doc/noid-privacy/package-manifest.txt
rpm -qa --qf '%{NAME}-%{EVR}.%{ARCH}\n' 2>/dev/null | LC_ALL=C sort > "$PACKAGE_MANIFEST"
manifest_count=$(grep -c . "$PACKAGE_MANIFEST" || true)
if [ "$manifest_count" -ge 800 ]; then
    chmod 644 "$PACKAGE_MANIFEST"
    chown root:root "$PACKAGE_MANIFEST"
    log "  [OK] package manifest written ($manifest_count RPMs)"
else
    log "  FAIL: package manifest suspiciously small ($manifest_count entries)"
    fail=$((fail + 1))
fi

# ----------------------------------------------------------------------------
# Phase 9: Reject any cross-module failure before the final trust check
# ----------------------------------------------------------------------------

log "Phase 9: Cross-module verification result"

if [ "$fail" -gt 0 ]; then
    log "=== Module 99 FAILED with $fail cross-module verification errors ==="
    log "    Image is incomplete — review previous module logs for root cause"
    exit 1
fi

# ----------------------------------------------------------------------------
# Phase 10: Preserve the user-owned AIDE trust boundary
# ----------------------------------------------------------------------------
# A compose-time database would bless the mutable installer/build environment
# before the installed owner can inspect it. Reject active/candidate databases
# and leave the daily timer disabled until the explicit review workflow commits
# an exact candidate hash.
log "Phase 10: Verifying AIDE trust remains uninitialized"

[ -f /etc/aide.conf ] || { log "  FAIL: /etc/aide.conf missing"; exit 1; }
command -v aide >/dev/null 2>&1 \
    || { log "  FAIL: aide binary not installed"; exit 1; }
install -d -m 0700 -o root -g root /var/lib/aide
if [ -L /var/log/aide ]; then
    log "  FAIL: /var/log/aide must not be a symlink"
    exit 1
fi
install -d -m 0700 -o root -g root /var/log/aide
if [ ! -d /var/log/aide ] || [ -L /var/log/aide ] \
   || [ "$(stat -c '%U:%G:%a' /var/log/aide 2>/dev/null || true)" != \
        root:root:700 ]; then
    log "  FAIL: /var/log/aide metadata contract is not a real root:root 0700 directory"
    exit 1
fi
for db_state in /var/lib/aide/aide.db.gz \
                /var/lib/aide/aide.db.new.gz \
                /var/lib/aide/aide.db.new.review; do
    if [ -e "$db_state" ]; then
        log "  FAIL: compose produced forbidden AIDE trust state: $db_state"
        exit 1
    fi
done
if [ -L /etc/systemd/system/timers.target.wants/aide-check.timer ]; then
    log "  FAIL: aide-check.timer enabled without an active reviewed database"
    exit 1
fi

log "=== Module 99: Finalize COMPLETE ==="
log "    AIDE baseline: uninitialized; explicit user review required"
log "    All cross-module artifacts verified present"
log "    Image is ready for runtime audit, not release-signing"

%end

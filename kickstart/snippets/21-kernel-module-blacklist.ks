# ============================================================================
# Module 21 — Kernel Module Blacklisting
# Status: LOCKED 2026-08-01 (v47) — close remaining module-policy audit contracts.
#
# Covers:
#   - /usr/share/noid-privacy/kernel-module-policy.tsv: normalized inventory
#     with explicit deny-loadable, built-in, absent, alias and supported states.
#   - /etc/modprobe.d/noid-security-blacklist.conf: generated dual enforcement
#     for the 53 canonical modules that are actually loadable in the target
#     Fedora kernel; raw declarations are never presented as effective blocks.
#   - /etc/dracut.conf.d/noid-security-blacklist.conf — install_items bakes
#     the blacklist into the initramfs (early-boot enforcement)
#   - /etc/dracut.conf.d/99-omit-firewire.conf — omit_drivers for the four
#     canonical loadable FireWire drivers.
#   - /etc/dracut.conf.d/98-noid-intel-gsc.conf — include, without forcing,
#     Intel's MEI transport and GSC proxy so i915 can finish GSC setup inside
#     the initramfs instead of waiting for the real-root module tree.
#   - systemd masks for binfmt_misc automount/registration, replacing a racy
#     udev write to a special control file.
#   - noid-dracut-hostonly-firstboot.service: leaves the Live/installer image
#     generic, then stages and atomically publishes a sloppy host-only candidate
#     from the completed installed topology before the first normal login. The
#     Generic BLS entry is the saved default while the candidate gets one trial
#     boot; only a real successful candidate reboot retires Generic recovery.
#     A first-login user unit marks the already-running installed boot successful
#     only after the transactional NoID Privacy user setup succeeds. The planned trial
#     therefore stays hidden, while a failed candidate still exposes Generic on
#     the following power cycle because GRUB resets boot_success at trial start.
#     It is the sole first-boot target-kernel Dracut writer and validates the
#     already-installed M32 Plymouth configuration, bgrt theme and watermark.
#     This preserves the single-disk mdraid-shutdown-hang fix without breaking
#     mdraid/iSCSI/FCoE/NBD installations through a global omit.
#   - STEP 2e: forced generic compose-time initramfs regeneration after the
#     blacklist/firewire writes; the installed-system service owns host-only.
#   - user doc 21-kernel-module-blacklist.md (DOC_EOF) with opt-in sections
#
# Deliberate compatibility decisions:
#   - squashfs is NOT blacklisted: NoID Privacy's own Live-ISO uses it for the
#     LiveOS rootfs (tests/21 asserts its absence from the blacklist).
#   - Intel PMT modules are NOT blocked: Fedora's intel_pmc_core module has a
#     direct pmt_telemetry dependency, matching upstream's Kconfig dependency.
#     The maintained platform power-state telemetry/diagnostic stack remains
#     intact instead of claiming an unmeasured compatibility/security trade.
#   - NOT blacklisted (generic hardware / other modules own them): bluetooth +
#     bt* (OFF via rfkill+flag, M08 — modules stay loadable), usb_storage
#     (USBGuard M14 governs per-device), thunderbolt (USB4/PCIe support kept;
#     firmware-reported authorization + IOMMU are the default boundary),
#     xe, uvcvideo, sr_mod/cdrom, joydev (Gaming-Mode opt-in), ntfs/ntfs3/
#     f2fs/erofs (modern removable media), nouveau/nova_core (M19 default GPU),
#     mei/mei_me/mei_hdcp/mei_pxp/mei_wdt (M15 owns MEI — NO default
#     sub-module blacklist; verify 5.6 guards against cross-contamination).
#     msr/can/vesafb and the five AF_ALG user-API identities are built into
#     Fedora's target kernel, so modprobe policy cannot disable them. They
#     remain explicit inventory and make the build fail for review if a future
#     target kernel changes their state.
#   - User-doc opt-in blocks (BT, usb_storage, thunderbolt, optical, joydev)
#     stay manual appends — never defaults.
#
# Invariants (keep when editing):
#   - The six EXPECTED_* constants are release gates. Any policy-state change
#     must update the manifest, constants, tests, M99 and user documentation in
#     the same commit.
#   - kernel-core %posttrans (kernel-install -> dracut) fires BEFORE this
#     %post, so the deployed dracut confs do NOT affect the installed
#     initramfs without STEP 2e's forced --regenerate-all.
#   - Never ship a static storage omit: generic Live/installer portability and
#     host-only installed-system correctness are separate trust boundaries.
#   - The firstboot service passes explicit host-only arguments, stages outside
#     /boot, validates content, proves headroom, publishes a durable BLS
#     fallback first, and accepts bootability only after a later real reboot.
#   - LZ4 is not forced without a measured boot-time and /boot-headroom gate;
#     Fedora's maintained compression default remains authoritative.
#   - module.sig_enforce=1 is fatal at every applicable phase: the compose
#     proves the target-install payload, while the Live and installed passes
#     prove their effective command line and BLS entries at runtime.
#
# Cross-reference:
#   - M01: lockdown + sig_enforce kargs. M02: binfmt sysctl history. M14:
#     USBGuard per-device policy. M15: MEI ownership. M19: nouveau default.
#     M15/M19/M25 delegate every maintained later image rebuild to this
#     module's locked validator. M27's former cAVS Dracut workaround is retired.
# Primary basis: upstream Linux, kmod, Dracut and systemd semantics plus ANSSI
# GNU/Linux guidance; exact maintained links are shipped in the module document.
# ============================================================================

# ---------------------------------------------------------------------------
# %post — Module 21 kernel module blacklisting
# ---------------------------------------------------------------------------
%post --erroronfail --log=/var/log/ks-21-kernel-module-blacklist.log
set -euo pipefail

log() { echo "[noid-21-modblacklist] $*"; }
log "=== Module 21 post-install: kernel module blacklisting ==="

# Release-gated state cardinalities for the normalized manifest.
EXPECTED_POLICY_ROWS=134
EXPECTED_DENY_COUNT=53
EXPECTED_BUILTIN_COUNT=8
EXPECTED_ABSENT_COUNT=43
EXPECTED_ALIAS_COUNT=2
EXPECTED_SUPPORTED_COUNT=28

# ====================================================================
# STEP 1: Canonical normalized module-policy manifest + generated deny config
# ====================================================================
# The manifest distinguishes real enforcement from built-in/absent inventory,
# historical aliases and deliberately supported hardware. Only deny-loadable
# rows generate modprobe policy; no raw-line count is presented as security.

POLICY_MANIFEST=/usr/share/noid-privacy/kernel-module-policy.tsv
BLACKLIST_CONFIG=/etc/modprobe.d/noid-security-blacklist.conf
log "STEP 1: publishing and validating the normalized kernel-module policy"

for command in modinfo modprobe; do
    command -v "$command" >/dev/null 2>&1 \
        || { log "  [FAIL] required kmod command missing: $command"; exit 1; }
done

install -d -m 0755 -o root -g root /usr/share/noid-privacy
cat > "$POLICY_MANIFEST" <<'KERNEL_MODULE_POLICY_EOF'
# module	policy_state	canonical_target
9p	deny-loadable	-
adfs	unaffected-absent	-
af_802154	unaffected-absent	-
af_alg	unaffected-builtin	-
affs	deny-loadable	-
algif_aead	unaffected-builtin	-
algif_hash	unaffected-builtin	-
algif_rng	unaffected-builtin	-
algif_skcipher	unaffected-builtin	-
appletalk	deny-loadable	-
ath_pci	unaffected-absent	-
atm	deny-loadable	-
ax25	unaffected-absent	-
batman_adv	deny-loadable	-
befs	deny-loadable	-
bfs	unaffected-absent	-
bluetooth	supported	-
btbcm	supported	-
btintel	supported	-
btmtk	supported	-
btrtl	supported	-
btusb	supported	-
can	unaffected-builtin	-
cdrom	supported	-
ceph	deny-loadable	-
cifs	deny-loadable	-
coda	deny-loadable	-
cramfs	unaffected-absent	-
cyber2000fb	unaffected-absent	-
cyblafb	unaffected-absent	-
dccp	unaffected-absent	-
decnet	unaffected-absent	-
dv1394	unaffected-absent	-
econet	unaffected-absent	-
ecryptfs	deny-loadable	-
efs	unaffected-absent	-
erofs	supported	-
esp4	deny-loadable	-
esp4_offload	deny-loadable	-
esp6	deny-loadable	-
esp6_offload	deny-loadable	-
exofs	unaffected-absent	-
f2fs	supported	-
firewire_core	deny-loadable	-
firewire_net	deny-loadable	-
firewire_ohci	deny-loadable	-
firewire_sbp2	deny-loadable	-
floppy	deny-loadable	-
freevxfs	unaffected-absent	-
gfs2	deny-loadable	-
gnss	deny-loadable	-
gnss_mtk	deny-loadable	-
gnss_serial	deny-loadable	-
gnss_sirf	deny-loadable	-
gnss_ubx	deny-loadable	-
gnss_usb	deny-loadable	-
gx1fb	unaffected-absent	-
hfs	deny-loadable	-
hfsplus	deny-loadable	-
hgafb	unaffected-absent	-
hpfs	unaffected-absent	-
ipx	unaffected-absent	-
jffs2	deny-loadable	-
jfs	deny-loadable	-
joydev	supported	-
kafs	deny-loadable	-
ksmbd	unaffected-absent	-
l2tp_eth	deny-loadable	-
l2tp_netlink	deny-loadable	-
l2tp_ppp	deny-loadable	-
lxfb	unaffected-absent	-
matroxfb_base	unaffected-absent	-
mei	supported	-
mei_hdcp	supported	-
mei_me	supported	-
mei_pxp	supported	-
mei_wdt	supported	-
minix	deny-loadable	-
msr	unaffected-builtin	-
n_hdlc	deny-loadable	-
neofb	unaffected-absent	-
netrom	unaffected-absent	-
nf_conntrack_helper	unaffected-absent	-
nfs	deny-loadable	-
nfsv3	deny-loadable	-
nfsv4	deny-loadable	-
nilfs2	deny-loadable	-
nouveau	supported	-
nova_core	supported	-
ntfs	supported	-
ntfs3	supported	-
ocfs2	deny-loadable	-
ohci1394	alias-denied-via-target	firewire_ohci
omfs	unaffected-absent	-
orangefs	deny-loadable	-
p8022	unaffected-absent	-
p8023	unaffected-absent	-
pm2fb	unaffected-absent	-
pmt_class	supported	-
pmt_crashlog	supported	-
pmt_telemetry	supported	-
psnap	deny-loadable	-
qnx4	unaffected-absent	-
qnx6	unaffected-absent	-
raw1394	unaffected-absent	-
rds	deny-loadable	-
reiserfs	unaffected-absent	-
rndis_host	deny-loadable	-
romfs	deny-loadable	-
rose	unaffected-absent	-
rxrpc	deny-loadable	-
s1d13xxxfb	unaffected-absent	-
sbp2	alias-denied-via-target	firewire_sbp2
sctp	deny-loadable	-
sisfb	unaffected-absent	-
squashfs	supported	-
sr_mod	supported	-
sysv	unaffected-absent	-
thunderbolt	supported	-
tipc	deny-loadable	-
ubifs	deny-loadable	-
udf	deny-loadable	-
udlfb	unaffected-absent	-
ufs	deny-loadable	-
usb_f_rndis	unaffected-absent	-
usb_storage	supported	-
uvcvideo	supported	-
vesafb	unaffected-builtin	-
vfb	unaffected-absent	-
video1394	unaffected-absent	-
vivid	deny-loadable	-
vt8623fb	unaffected-absent	-
x25	unaffected-absent	-
xe	supported	-
KERNEL_MODULE_POLICY_EOF
chown root:root "$POLICY_MANIFEST"
chmod 0644 "$POLICY_MANIFEST"

if ! awk -F '\t' '
    BEGIN {
        allowed["deny-loadable"] = 1
        allowed["unaffected-builtin"] = 1
        allowed["unaffected-absent"] = 1
        allowed["alias-denied-via-target"] = 1
        allowed["supported"] = 1
    }
    /^#/ || NF == 0 { next }
    NF != 3 {
        print "invalid field count at policy line " NR > "/dev/stderr"
        bad = 1
        next
    }
    $1 !~ /^[a-z0-9][a-z0-9_]*$/ {
        print "non-normalized module identity at policy line " NR > "/dev/stderr"
        bad = 1
    }
    !($2 in allowed) {
        print "unknown policy state at line " NR > "/dev/stderr"
        bad = 1
    }
    seen[$1]++ {
        print "duplicate module identity at line " NR > "/dev/stderr"
        bad = 1
    }
    $2 == "alias-denied-via-target" {
        if ($3 !~ /^[a-z0-9][a-z0-9_]*$/ || $3 == $1) {
            print "invalid alias target at line " NR > "/dev/stderr"
            bad = 1
        }
        next
    }
    $3 != "-" {
        print "unexpected canonical target at line " NR > "/dev/stderr"
        bad = 1
    }
    { rows++ }
    END {
        if (rows == 0) bad = 1
        exit bad
    }
' "$POLICY_MANIFEST"; then
    log "  [FAIL] normalized kernel-module policy schema is invalid"
    exit 1
fi

while IFS=$'\t' read -r module state target; do
    case "$module" in ''|'#'*) continue ;; esac
    [ "$state" = alias-denied-via-target ] || continue
    if ! awk -F '\t' -v target="$target" '
        $1 == target && $2 == "deny-loadable" { found = 1 }
        END { exit !found }
    ' "$POLICY_MANIFEST"; then
        log "  [FAIL] alias $module does not resolve to a declared deny target"
        exit 1
    fi
done < "$POLICY_MANIFEST"

blacklist_tmp=$(mktemp /etc/modprobe.d/.noid-security-blacklist.XXXXXX)
if ! {
    printf '%s\n' \
        '# NoID Privacy — generated effective module deny policy (Module 21)' \
        '# Canonical source: /usr/share/noid-privacy/kernel-module-policy.tsv' \
        '# Ordinary modprobe resolution is denied; privileged root can bypass' \
        '# or replace local policy and is outside this boundary.'
    awk -F '\t' '
        $2 == "deny-loadable" {
            printf "blacklist %s\ninstall %s /bin/false\n", $1, $1
        }
    ' "$POLICY_MANIFEST"
} > "$blacklist_tmp"; then
    rm -f -- "$blacklist_tmp"
    log "  [FAIL] cannot render effective module deny policy"
    exit 1
fi
chown root:root "$blacklist_tmp"
chmod 0644 "$blacklist_tmp"
mv -fT -- "$blacklist_tmp" "$BLACKLIST_CONFIG"

deny_count=$(awk -F '\t' '$2 == "deny-loadable" { n++ } END { print n+0 }' \
    "$POLICY_MANIFEST")
builtin_count=$(awk -F '\t' '$2 == "unaffected-builtin" { n++ } END { print n+0 }' \
    "$POLICY_MANIFEST")
absent_count=$(awk -F '\t' '$2 == "unaffected-absent" { n++ } END { print n+0 }' \
    "$POLICY_MANIFEST")
alias_count=$(awk -F '\t' '$2 == "alias-denied-via-target" { n++ } END { print n+0 }' \
    "$POLICY_MANIFEST")
supported_count=$(awk -F '\t' '$2 == "supported" { n++ } END { print n+0 }' \
    "$POLICY_MANIFEST")
policy_rows=$((deny_count + builtin_count + absent_count + alias_count + supported_count))
if [ "$policy_rows" -ne "$EXPECTED_POLICY_ROWS" ] || \
   [ "$deny_count" -ne "$EXPECTED_DENY_COUNT" ] || \
   [ "$builtin_count" -ne "$EXPECTED_BUILTIN_COUNT" ] || \
   [ "$absent_count" -ne "$EXPECTED_ABSENT_COUNT" ] || \
   [ "$alias_count" -ne "$EXPECTED_ALIAS_COUNT" ] || \
   [ "$supported_count" -ne "$EXPECTED_SUPPORTED_COUNT" ]; then
    log "  [FAIL] policy cardinality drift: rows=$policy_rows deny=$deny_count built-in=$builtin_count absent=$absent_count aliases=$alias_count supported=$supported_count"
    exit 1
fi
actual_bl=$(grep -c '^blacklist ' "$BLACKLIST_CONFIG" 2>/dev/null || true)
actual_inst=$(grep -c '^install .* /bin/false$' "$BLACKLIST_CONFIG" 2>/dev/null || true)
actual_bl=${actual_bl:-0}
actual_inst=${actual_inst:-0}
if [ "$actual_bl" -ne "$deny_count" ] || [ "$actual_inst" -ne "$deny_count" ]; then
    log "  [FAIL] generated deny config does not match the canonical manifest"
    exit 1
fi

validate_policy_for_kernel() {
    local kernel=$1 module state target path canonical resolution
    while IFS=$'\t' read -r module state target; do
        case "$module" in ''|'#'*) continue ;; esac
        case "$state" in
            deny-loadable)
                path=$(modinfo -k "$kernel" -n "$module" 2>/dev/null) \
                    || { log "  [FAIL] $module is not loadable for $kernel"; return 1; }
                [ "$path" != '(builtin)' ] \
                    || { log "  [FAIL] $module became built-in for $kernel"; return 1; }
                canonical=$(modinfo -k "$kernel" -F name "$module" 2>/dev/null | head -n 1)
                canonical=${canonical//-/_}
                [ "$canonical" = "$module" ] \
                    || { log "  [FAIL] $module resolves to $canonical for $kernel"; return 1; }
                resolution=$(modprobe --set-version "$kernel" --dry-run \
                    --verbose "$module" 2>&1) \
                    || { log "  [FAIL] modprobe cannot resolve $module for $kernel"; return 1; }
                awk '$1 == "install" && $2 == "/bin/false" && NF == 2 {
                        denied = 1
                    }
                    END { exit !denied }
                ' <<<"$resolution" \
                    || { log "  [FAIL] $module is not effectively denied for $kernel"; return 1; }
                if awk -v path="$path" '$1 == "insmod" && $2 == path {
                        inserted = 1
                    }
                    END { exit !inserted }
                ' <<<"$resolution"; then
                    log "  [FAIL] modprobe still resolves $module to target insertion for $kernel"
                    return 1
                fi
                ;;
            unaffected-builtin)
                path=$(modinfo -k "$kernel" -n "$module" 2>/dev/null) \
                    || { log "  [FAIL] built-in inventory $module vanished for $kernel"; return 1; }
                [ "$path" = '(builtin)' ] \
                    || { log "  [FAIL] $module is no longer built-in for $kernel"; return 1; }
                ;;
            unaffected-absent)
                if modinfo -k "$kernel" -n "$module" >/dev/null 2>&1; then
                    log "  [FAIL] absent inventory $module became available for $kernel"
                    return 1
                fi
                ;;
            alias-denied-via-target)
                canonical=$(modinfo -k "$kernel" -F name "$module" 2>/dev/null | head -n 1) \
                    || { log "  [FAIL] alias $module vanished for $kernel"; return 1; }
                canonical=${canonical//-/_}
                [ "$canonical" = "$target" ] \
                    || { log "  [FAIL] alias $module resolves to $canonical, not $target"; return 1; }
                ;;
            supported)
                if grep -qE "^(blacklist|install)[[:space:]]+${module}([[:space:]]|$)" \
                        "$BLACKLIST_CONFIG"; then
                    log "  [FAIL] supported module $module entered the deny config"
                    return 1
                fi
                ;;
        esac
    done < "$POLICY_MANIFEST"
}

checked_kernels=0
for modules_dir in /usr/lib/modules/*; do
    [ -d "$modules_dir" ] || continue
    [ ! -L "$modules_dir" ] || {
        log "  [FAIL] symlinked kernel module tree: $modules_dir"
        exit 1
    }
    kernel=${modules_dir##*/}
    validate_policy_for_kernel "$kernel" || exit 1
    checked_kernels=$((checked_kernels + 1))
done
if [ "$checked_kernels" -eq 0 ]; then
    log "  [FAIL] no installed kernel module tree was available"
    exit 1
fi

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$POLICY_MANIFEST" "$BLACKLIST_CONFIG" \
        || { log "  [FAIL] initial policy SELinux reconciliation failed"; exit 1; }
else
    log "  [FAIL] restorecon is unavailable"
    exit 1
fi
log "  [OK] policy: $deny_count enforced + $builtin_count built-in + $absent_count absent + $alias_count aliases + $supported_count supported across $checked_kernels kernel tree(s)"

# STEP 2: Dracut config — force blacklist into initramfs
# ====================================================================
# Ensures blacklist takes effect at early boot BEFORE systemd-udevd starts
# probing hardware. Dracut by default includes /etc/modprobe.d/ files, but
# explicit install_items guarantees our file is present regardless of
# dracut module changes.

log "STEP 2: writing /etc/dracut.conf.d/noid-security-blacklist.conf"

cat > /etc/dracut.conf.d/noid-security-blacklist.conf <<'DRACUT_EOF'
# NoID Privacy — Force security blacklist into initramfs (Module 21)
# Ensures module blacklist is active before systemd-udevd probes hardware.
install_items+=" /etc/modprobe.d/noid-security-blacklist.conf "
DRACUT_EOF

chmod 644 /etc/dracut.conf.d/noid-security-blacklist.conf
chown root:root /etc/dracut.conf.d/noid-security-blacklist.conf
log "  [OK] /etc/dracut.conf.d/noid-security-blacklist.conf written"

# ====================================================================
# STEP 2a: Intel GSC initramfs dependency closure
# ====================================================================
# Meteor Lake i915 can request the GSC proxy before Dracut's host-only probe
# has seen its MEI transport. Include both signed in-tree modules in Generic
# and installed images. add_drivers does not force-load them on AMD, older
# Intel or other systems without matching devices.

log "STEP 2a: writing /etc/dracut.conf.d/98-noid-intel-gsc.conf"

cat > /etc/dracut.conf.d/98-noid-intel-gsc.conf <<'INTEL_GSC_DRACUT_EOF'
# NoID Privacy — Intel GSC early-boot dependency closure
# i915 can initialize GSC inside the initramfs before Dracut's host-only probe
# discovers the MEI transport and proxy. Include the signed in-tree drivers;
# add_drivers does not force-load them on hardware without matching devices.
add_drivers+=" mei_me mei_gsc_proxy "
INTEL_GSC_DRACUT_EOF

chmod 0644 /etc/dracut.conf.d/98-noid-intel-gsc.conf
chown root:root /etc/dracut.conf.d/98-noid-intel-gsc.conf
log "  [OK] Intel GSC early-boot drivers selected without forced loading"

# ====================================================================
# STEP 2b: Dracut omit_drivers — firewire
# ====================================================================
# Belt-and-suspenders with the generated modprobe policy: remove only the four
# canonical FireWire drivers that the target kernel actually ships loadably.

log "STEP 2b: writing /etc/dracut.conf.d/99-omit-firewire.conf"

cat > /etc/dracut.conf.d/99-omit-firewire.conf <<'DRACUT_OMIT_EOF'
# NoID Privacy — omit firewire drivers from initramfs (Module 21)
#
# The image has no supported FireWire workflow. Blocking at the initramfs
# level removes this DMA-capable legacy bus before the real root is mounted.
#
# Upstream Linux and fwupd guidance treat FireWire/Thunderbolt PCIe peripherals
# as DMA-capable and rely on an active IOMMU for memory isolation. FireWire has
# no supported image workflow, so omitting its drivers is additional reduction.
#
# Note: thunderbolt is NOT omitted because legitimate USB4/eGPU use.
# Thunderbolt is not FireWire and remains available for USB4 docks/eGPU.
# Users who deliberately want to omit Thunderbolt can add a reviewed drop-in,
# then run: sudo /usr/libexec/noid-dracut-regenerate-all
omit_drivers+=" firewire_core firewire_net firewire_ohci firewire_sbp2 "
DRACUT_OMIT_EOF

chmod 644 /etc/dracut.conf.d/99-omit-firewire.conf
chown root:root /etc/dracut.conf.d/99-omit-firewire.conf
log "  [OK] /etc/dracut.conf.d/99-omit-firewire.conf written"

# ====================================================================
# STEP 2c: Disable automatic binfmt_misc registration with native units
# ====================================================================
# `fs.binfmt_misc.status` is a special file that exists only after the
# filesystem is mounted. A udev RUN write races that mount and was never an
# authoritative control. Fedora's actual automatic activation path is the
# automount plus systemd-binfmt; mask both and keep an explicit documented
# opt-in for Wine/cross-architecture workflows.

log "STEP 2c: masking automatic binfmt_misc mount and registration"
rm -f -- /usr/lib/udev/rules.d/99-noid-binfmt-disable.rules
for unit in proc-sys-fs-binfmt_misc.automount systemd-binfmt.service; do
    if ! systemctl mask "$unit" >/dev/null; then
        log "  [FAIL] could not mask $unit"
        exit 1
    fi
    if [ "$(readlink "/etc/systemd/system/$unit" 2>/dev/null || true)" != /dev/null ]; then
        log "  [FAIL] $unit mask is not an exact /dev/null link"
        exit 1
    fi
done
log "  [OK] binfmt_misc automatic activation is masked"

# ====================================================================
# STEP 2d: Installed-system host-only Dracut convergence
# ====================================================================
# The Live/installer image must remain generic. The final storage topology does
# not exist yet during compose, so a global mdraid/iSCSI/FCoE/NBD omit is unsafe.
# On the first installed boot this service forces sloppy host-only generation
# from the real topology. A simple single-device LUKS2+Btrfs install must then
# contain none of those four modules; other topologies are permitted to retain
# what Dracut detects. The command-line -H is the precedence authority.

log "STEP 2d: installing target-topology host-only Dracut convergence"
rm -f -- /etc/dracut.conf.d/99-noid-omit-storage.conf \
    /etc/dracut.conf.d/99-noid-compress.conf

# One lock and one completion predicate protect every supported NoID Privacy
# writer of initramfs, BLS or GRUB one-shot state.  The predicate intentionally
# does not try to prove a newly built image bootable; M21's real reboot did that
# before phase=complete was published.
cat > /usr/libexec/noid-boot-mutation-guard <<'BOOT_MUTATION_GUARD_EOF'
#!/usr/bin/bash
set -euo pipefail
# `stat -c %F` is translated; this guard compares it against English literals.
# systemd hands services the installation's LANG, so pin the parse locale.
LC_ALL=C.UTF-8
export LC_ALL

STATE=/var/lib/noid-privacy/dracut-hostonly.state
CONFIG=/etc/dracut.conf.d/99-noid-hostonly.conf
MARKER=/etc/noid-privacy/initramfs-hostonly
SNAPPER_STATE=/.snapshots/.noid-state
SNAPPER_PENDING=$SNAPPER_STATE/rollback.pending
SNAPPER_READY=$SNAPPER_STATE/rollback.ready

fail() {
    echo "noid-boot-mutation-guard: $*" >&2
    exit 1
}
state_value() {
    local key=$1
    awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }' \
        "$STATE"
}

allow_snapper_resume=0
case "$#:${1:-}" in
    0:) ;;
    1:--snapper-resume) allow_snapper_resume=1 ;;
    *) fail "usage: noid-boot-mutation-guard [--snapper-resume]" ;;
esac
[ "$(id -u)" -eq 0 ] || fail "must run as root"
grep -Fqw -- rd.live.image /proc/cmdline \
    && fail "boot mutations are forbidden in the Live/installer environment"

for command in awk cmp grep lsinitrd matchpathcon modinfo readlink stat uname wc; do
    command -v "$command" >/dev/null 2>&1 \
        || fail "required command missing: $command"
done

[ -f "$STATE" ] && [ ! -L "$STATE" ] \
    || fail "M21 completion state is missing or unsafe"
[ "$(stat -c '%U:%G:%a' "$STATE")" = root:root:600 ] \
    || fail "M21 completion state metadata drifted"
[ "$(wc -l < "$STATE")" -eq 5 ] \
    || fail "M21 completion state has an unexpected schema"
for key in policy_version phase root_class target_kernel prepared_boot_id; do
    [ "$(awk -F= -v key="$key" '$1 == key { count++ } END { print count + 0 }' \
        "$STATE")" -eq 1 ] || fail "M21 state key is missing or duplicated: $key"
done
awk -F= '
    !/^[a-z_]+=[A-Za-z0-9._+-]+$/ { bad=1 }
    $1 != "policy_version" && $1 != "phase" && $1 != "root_class" &&
    $1 != "target_kernel" && $1 != "prepared_boot_id" { bad=1 }
    END { exit bad }
' "$STATE" || fail "M21 completion state contains an unknown or malformed row"
[ "$(state_value policy_version)" = 2 ] \
    || fail "M21 state policy version is not supported"
phase=$(state_value phase)
case "$phase" in
    complete) basis=hostonly ;;
    recovered-generic) basis=generic ;;
    *) fail "M21 still requires recovery, an explicit retry or a real reboot" ;;
esac
case "$(state_value root_class)" in
    simple-single-device-luks2-btrfs|other-hostonly) ;;
    *) fail "M21 root-class state is invalid" ;;
esac
case "$(state_value target_kernel)" in
    ''|*[!A-Za-z0-9._+-]*) fail "M21 target-kernel state is invalid" ;;
esac
prepared_boot_id=$(state_value prepared_boot_id)
[[ "$prepared_boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || fail "M21 prepared boot ID is invalid"

if [ "$basis" = hostonly ]; then
    [ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] \
        && [ "$(stat -c '%U:%G:%a' "$CONFIG")" = root:root:644 ] \
        || fail "M21 host-only Dracut config is missing or unsafe"
    cmp -s "$CONFIG" <(cat <<'EXPECTED_CONFIG_EOF'
# NoID Privacy — installed-system initramfs policy (Module 21)
# Firstboot publishes a staged -H candidate with a bootable generic BLS
# fallback. This drop-in makes later kernel/NVIDIA rebuilds follow the host.
hostonly="yes"
hostonly_mode="sloppy"
hostonly_cmdline="no"
install_items+=" /etc/noid-privacy/initramfs-hostonly "
EXPECTED_CONFIG_EOF
) || fail "M21 host-only Dracut config bytes drifted"
    [ -f "$MARKER" ] && [ ! -L "$MARKER" ] \
        && [ "$(stat -c '%U:%G:%a' "$MARKER")" = root:root:644 ] \
        || fail "M21 initramfs marker is missing or unsafe"
    [ "$(cat "$MARKER")" = $'policy_version=2\nmode=hostonly-sloppy' ] \
        || fail "M21 initramfs marker bytes drifted"
else
    [ ! -e "$CONFIG" ] && [ ! -L "$CONFIG" ] \
        || fail "recovered Generic basis retained the host-only Dracut config"
    [ ! -e "$MARKER" ] && [ ! -L "$MARKER" ] \
        || fail "recovered Generic basis retained the host-only marker"
fi

running_image=/boot/initramfs-$(uname -r).img
[ -f "$running_image" ] && [ ! -L "$running_image" ] \
    || fail "the running kernel's initramfs is missing or unsafe"
listing=$(mktemp /run/noid-boot-mutation-listing.XXXXXX)
trap 'rm -f "$listing"' EXIT
lsinitrd "$running_image" >"$listing" 2>/dev/null \
    || fail "the running kernel's initramfs cannot be inspected"
if [ "$basis" = hostonly ]; then
    grep -qF 'etc/noid-privacy/initramfs-hostonly' "$listing" \
        || fail "the running kernel did not boot the confirmed host-only policy"
elif grep -qF 'etc/noid-privacy/initramfs-hostonly' "$listing"; then
    fail "the recovered Generic basis still contains the host-only marker"
fi
grep -qF 'etc/modprobe.d/noid-security-blacklist.conf' "$listing" \
    || fail "the running kernel's initramfs lacks the security blacklist"
for required in mei_me mei_gsc_proxy; do
    module_path=$(modinfo -k "$(uname -r)" -n "$required" 2>/dev/null || true)
    [ -n "$module_path" ] && [ "$module_path" != '(builtin)' ] \
        || fail "cannot resolve required Intel GSC dependency: $required"
    module_path=$(readlink -f "$module_path")
    [ -f "$module_path" ] \
        || fail "required Intel GSC dependency is not a regular file: $required"
    module_rel=${module_path#/}
    cmp -s "$module_path" \
        <(lsinitrd -f "$module_rel" "$running_image" 2>/dev/null) \
        || fail "the running initramfs lacks exact Intel GSC dependency bytes: $required"
done

grep -Fqw -- noid.initramfs=generic-fallback /proc/cmdline \
    && fail "the machine is running the temporary Generic recovery entry"
for pattern in \
        '/boot/initramfs-*.noid-generic-fallback.img' \
        '/boot/loader/entries/noid-generic-fallback-*.conf' \
        '/boot/.initramfs-*.noid-publish.tmp' \
        '/boot/.initramfs-*.noid-fallback.tmp'; do
    compgen -G "$pattern" >/dev/null \
        && fail "M21 recovery/publication artifact is still active: $pattern"
done
# The GRUB environment block is a plain-text file; read it directly.
# grub2-editenv probes block devices through libgrub and exits non-zero
# under PrivateDevices=yes service sandboxes even for a read-only list,
# and that failure must stay visible instead of dying in a quiet pipe.
# A missing file simply means no one-shot entry is armed.
GRUBENV=/boot/grub2/grubenv
next_entry=
if [ -e "$GRUBENV" ] || [ -L "$GRUBENV" ]; then
    [ -f "$GRUBENV" ] && [ ! -L "$GRUBENV" ] \
        || fail "the GRUB environment block is not a regular file"
    next_entry=$(awk -F= '$1 == "next_entry" { print substr($0, 12); exit }' \
        "$GRUBENV") || fail "the GRUB environment block cannot be read"
fi
[ -z "$next_entry" ] || fail "a GRUB one-shot boot entry is still armed"

# Snapper changes the next boot's root while /boot remains outside the
# snapshot. A published or interrupted selection therefore blocks every later
# /boot writer until the selected root is actually running. The rollback
# helper alone may resume its persistent transaction while holding this same
# global lock; every M21 basis check above remains mandatory.
validate_snapper_record() {
    local path=$1 kind=$2
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%F' "$path")" = \
            '0:0:600:1:regular file' ] \
        && matchpathcon -V "$path" >/dev/null \
        && [ "$(wc -l < "$path")" -eq 3 ] \
        || fail "Snapper $kind record is missing, symlinked or has unsafe metadata"
    case "$kind" in
        pending)
            awk -F= '
                $1 == "TARGET" && $2 ~ /^[1-9][0-9]*$/ { target++; next }
                $1 == "ORIGINAL_DEFAULT_ID" && $2 ~ /^[1-9][0-9]*$/ { original++; next }
                $1 == "REQUESTED_AT" && $2 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/ { stamp++; next }
                { bad=1 }
                END { exit bad || target != 1 || original != 1 || stamp != 1 }
            ' "$path" || fail "Snapper pending record is malformed"
            ;;
        ready)
            awk -F= '
                $1 == "TARGET" && $2 ~ /^[1-9][0-9]*$/ { target++; next }
                $1 == "DEFAULT_SNAPSHOT" && $2 ~ /^[1-9][0-9]*$/ { selected++; next }
                $1 == "VERIFIED_AT" && $2 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/ { stamp++; next }
                { bad=1 }
                END { exit bad || target != 1 || selected != 1 || stamp != 1 }
            ' "$path" || fail "Snapper ready record is malformed"
            ;;
        *) fail "internal Snapper record type is invalid" ;;
    esac
}

snapper_pending=0
snapper_ready=0
if [ -e "$SNAPPER_PENDING" ] || [ -L "$SNAPPER_PENDING" ]; then
    validate_snapper_record "$SNAPPER_PENDING" pending
    snapper_pending=1
fi
if [ -e "$SNAPPER_READY" ] || [ -L "$SNAPPER_READY" ]; then
    validate_snapper_record "$SNAPPER_READY" ready
    snapper_ready=1
fi
if [ "$snapper_pending" -eq 1 ] || [ "$snapper_ready" -eq 1 ]; then
    [ -d "$SNAPPER_STATE" ] && [ ! -L "$SNAPPER_STATE" ] \
        && [ "$(stat -c '%u:%g:%a:%F' "$SNAPPER_STATE")" = \
            '0:0:700:directory' ] \
        && matchpathcon -V /.snapshots >/dev/null \
        && matchpathcon -V "$SNAPPER_STATE" >/dev/null \
        || fail "Snapper stable state directory metadata or SELinux label differs"
fi
if [ "$allow_snapper_resume" -eq 1 ] && [ "$snapper_pending" -ne 1 ]; then
    fail "Snapper resume was requested without a pending transaction"
fi
if [ "$snapper_pending" -eq 1 ] || [ "$snapper_ready" -eq 1 ]; then
    [ -f /usr/libexec/noid-snapper-status ] \
        && [ ! -L /usr/libexec/noid-snapper-status ] \
        && [ -x /usr/libexec/noid-snapper-status ] \
        || fail "Snapper boot-state helper is missing or unsafe"
    snapper_status=$(/usr/libexec/noid-snapper-status) \
        || fail "Snapper boot state cannot be verified"
    case "$snapper_status" in
        *' boot=ready '*) ;;
        *' boot=reboot-required '*)
            [ "$allow_snapper_resume" -eq 1 ] \
                || fail "a Snapper rollback root is selected; reboot before changing /boot"
            ;;
        *) fail "Snapper boot state is degraded or malformed" ;;
    esac
    if [ "$snapper_pending" -eq 1 ] && [ "$allow_snapper_resume" -ne 1 ]; then
        fail "a Snapper rollback is pending; use noid-snap-rollback --resume"
    fi
fi
printf 'basis=%s\n' "$basis"
BOOT_MUTATION_GUARD_EOF
chmod 0755 /usr/libexec/noid-boot-mutation-guard
chown root:root /usr/libexec/noid-boot-mutation-guard

mkdir -p /usr/lib/tmpfiles.d /run/lock
cat > /usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf <<'BOOT_MUTATION_TMPFILES_EOF'
f /run/lock/noid-boot-mutation.lock 0660 root wheel -
BOOT_MUTATION_TMPFILES_EOF
chmod 0644 /usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf
chown root:root /usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf
install -m 0660 -o root -g wheel /dev/null /run/lock/noid-boot-mutation.lock

# The two normal-user orchestrators hold the shared lock on descriptor 7.
# Preserve that exact open file description across sudo so the privileged
# regenerator cannot outlive its kernel-enforced lease if the parent dies.
command -v visudo >/dev/null 2>&1 || {
    log "  [FAIL] visudo is required for the boot-lock descriptor contract"
    exit 1
}
sudoers_candidate=$(mktemp /etc/sudoers.d/.90-noid-boot-mutation-fd.XXXXXX)
cat > "$sudoers_candidate" <<'BOOT_MUTATION_SUDOERS_EOF'
Defaults!/usr/libexec/noid-dracut-regenerate-all closefrom_override
BOOT_MUTATION_SUDOERS_EOF
chown root:root "$sudoers_candidate"
chmod 0440 "$sudoers_candidate"
visudo -cf "$sudoers_candidate" >/dev/null \
    || { rm -f -- "$sudoers_candidate"; exit 1; }
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$sudoers_candidate"
fi
sync -- "$sudoers_candidate"
mv -fT -- "$sudoers_candidate" /etc/sudoers.d/90-noid-boot-mutation-fd
sync -- /etc/sudoers.d/90-noid-boot-mutation-fd
sync -- /etc/sudoers.d

cat > /usr/libexec/noid-dracut-regenerate-all <<'GUARDED_REGENERATE_EOF'
#!/usr/bin/bash
# Rebuild each published kernel image through a same-filesystem candidate.
# Interruption therefore leaves either the prior image or a complete inspected
# replacement at every BLS path; a later invocation completes any remaining
# kernels.
set -euo pipefail

LOCK=/run/lock/noid-boot-mutation.lock
fail() {
    echo "noid-dracut-regenerate-all: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ -f "$LOCK" ] && [ ! -L "$LOCK" ] \
    || fail "shared boot-mutation lock is missing or unsafe"

lock_fd=
only_kernel=
allow_pending_mok=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --lock-held=*)
            [ -z "$lock_fd" ] || fail "duplicate lock authority"
            lock_fd=${1#--lock-held=}
            case "$lock_fd" in
                ''|*[!0-9]*) fail "invalid inherited lock descriptor" ;;
            esac
            ;;
        --kernel=*)
            [ -z "$only_kernel" ] || fail "duplicate kernel selector"
            only_kernel=${1#--kernel=}
            case "$only_kernel" in
                ''|*[!A-Za-z0-9._+-]*) fail "invalid kernel selector" ;;
            esac
            ;;
        --allow-pending-mok)
            [ "$allow_pending_mok" -eq 0 ] \
                || fail "duplicate pending-MOK exception"
            allow_pending_mok=1
            ;;
        *)
            fail "usage: noid-dracut-regenerate-all [--lock-held=FD] [--kernel=KERNEL] [--allow-pending-mok]"
            ;;
    esac
    shift
done
for command in awk basename btrfs chown chmod cmp cryptsetup dracut findmnt flock \
        grep lsblk lsinitrd mktemp modinfo mv readlink restorecon rm sed sort \
        stat sync tr wc; do
    command -v "$command" >/dev/null 2>&1 \
        || fail "required command missing: $command"
done
if [ -n "$lock_fd" ]; then
    [ "$(readlink -f "/proc/self/fd/$lock_fd" 2>/dev/null || true)" = "$LOCK" ] \
        || fail "inherited descriptor does not name the boot-mutation lock"
    flock -n "$lock_fd" || fail "inherited boot-mutation lock is not held"
else
    exec 9>"$LOCK"
    flock -w 1800 9 || fail "timed out waiting for another boot mutation"
fi
basis_record=$(/usr/libexec/noid-boot-mutation-guard)
case "$basis_record" in
    basis=hostonly)
        basis=hostonly
        dracut_basis_args=(--hostonly --hostonly-mode sloppy --no-hostonly-cmdline)
        ;;
    basis=generic)
        basis=generic
        dracut_basis_args=(--no-hostonly)
        ;;
    *) fail "boot-mutation guard returned an invalid basis" ;;
esac

candidate=
listing=
modules=
cleanup() {
    rm -f -- "${candidate:-}" "${listing:-}" "${modules:-}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# SHARED-LOGIC-MARKER: root-class detection; keep in sync with
# noid-dracut-hostonly-configure's detect_root_class().
ROOT_SOURCE=$(findmnt -nro SOURCE / 2>/dev/null || true)
ROOT_SOURCE=${ROOT_SOURCE%%\[*}
ROOT_FSTYPE=$(findmnt -nro FSTYPE / 2>/dev/null || true)
ROOT_TYPES=
ROOT_CLASS=other-hostonly
if [ -b "$ROOT_SOURCE" ]; then
    ROOT_TYPES=$(lsblk -s -nro TYPE "$ROOT_SOURCE" 2>/dev/null \
        | sort -u | tr '\n' ' ')
fi
if [ "$ROOT_FSTYPE" = btrfs ] && [ -b "$ROOT_SOURCE" ] \
        && [ "$(lsblk -dnro TYPE "$ROOT_SOURCE" 2>/dev/null || true)" = crypt ]; then
    btrfs_show=$(btrfs filesystem show --raw / 2>/dev/null || true)
    btrfs_devices=$(grep -c '^[[:space:]]*devid[[:space:]]' \
        <<<"$btrfs_show" || true)
    btrfs_devices=${btrfs_devices:-0}
    crypt_name=${ROOT_SOURCE#/dev/mapper/}
    if [ "$btrfs_devices" -eq 1 ] \
            && ! grep -q 'MISSING' <<<"$btrfs_show" \
            && cryptsetup status "$crypt_name" 2>/dev/null \
                | grep -q 'type:[[:space:]]*LUKS2' \
            && grep -qw disk <<<"$ROOT_TYPES" \
            && ! grep -Eq '(^|[[:space:]])(raid[^[:space:]]*|lvm|mpath|loop)([[:space:]]|$)' \
                <<<"$ROOT_TYPES"; then
        ROOT_CLASS=simple-single-device-luks2-btrfs
    fi
fi

# A hard power loss can leave an unreferenced candidate, but never a partial
# image at a BLS path. Once the shared lock is held, these reserved NoID Privacy
# names cannot belong to another supported writer and are safe to retire.
if [ -n "$only_kernel" ]; then
    stale_candidates=("/boot/.initramfs-${only_kernel}.noid-candidate."*)
else
    stale_candidates=(/boot/.initramfs-*.noid-candidate.*)
fi
stale_removed=0
for stale in "${stale_candidates[@]}"; do
    [ -e "$stale" ] || [ -L "$stale" ] || continue
    [ -f "$stale" ] && [ ! -L "$stale" ] \
        || fail "reserved stale candidate is not a regular file: $stale"
    rm -f -- "$stale"
    stale_removed=1
done
[ "$stale_removed" -eq 0 ] || sync -- /boot

# SHARED-LOGIC-MARKER: integrated root-driver classification; keep in sync
# with noid-dracut-hostonly-configure.
root_driver_is_kernel_integrated() {
    local module=$1 module_root
    case "$module" in
        ''|*[!A-Za-z0-9_-]*) return 1 ;;
    esac
    module_root=/sys/module/$module
    # A driver/module link proves that the running kernel owns this driver.
    # Dynamically loaded modules receive the kernel's `initstate` modinfo
    # attribute; a kernel-owned module directory without it is integrated.
    # This exception applies only after target-kernel modinfo found no object.
    [ -d "$module_root" ] && [ ! -L "$module_root" ] \
        && [ ! -e "$module_root/initstate" ] \
        && [ ! -L "$module_root/initstate" ]
}

validate_candidate() {
    local image=$1 kernel=$2 required module_path module_file module_rel
    local block_name block_type device_path parent_path module_link
    local controller_module controller_path controller_file nvidia_base
    candidate_nvidia_verified=0

    listing=$(mktemp /run/noid-regenerate-listing.XXXXXX)
    modules=$(mktemp /run/noid-regenerate-modules.XXXXXX)
    lsinitrd "$image" >"$listing" 2>/dev/null \
        || fail "Dracut candidate cannot be inspected for $kernel"
    lsinitrd -m "$image" >"$modules" 2>/dev/null \
        || fail "Dracut module inventory cannot be inspected for $kernel"

    for required in \
            etc/modprobe.d/noid-security-blacklist.conf \
            etc/modprobe.d/noid-mei-submodules.conf \
            etc/udev/rules.d/99-noid-mei-kt-block.rules \
            usr/libexec/noid-mei-kt-enforce \
            etc/plymouth/plymouthd.conf \
            usr/share/plymouth/themes/bgrt/bgrt.plymouth \
            usr/share/plymouth/themes/spinner/watermark.png; do
        grep -qF "$required" "$listing" \
            || fail "candidate for $kernel lacks required artifact: $required"
        [ -f "/$required" ] && [ ! -L "/$required" ] \
            || fail "host artifact is missing or unsafe: /$required"
        cmp -s "/$required" <(lsinitrd -f "$required" "$image" 2>/dev/null) \
            || fail "candidate for $kernel has stale artifact bytes: $required"
    done
    for required in kernel-modules rootfs-block plymouth; do
        grep -qx "$required" "$modules" \
            || fail "candidate for $kernel lacks required Dracut module: $required"
    done
    for required in mei_me mei_gsc_proxy; do
        module_path=$(modinfo -k "$kernel" -n "$required" 2>/dev/null || true)
        [ -n "$module_path" ] && [ "$module_path" != '(builtin)' ] \
            || fail "cannot resolve Intel GSC dependency for $kernel: $required"
        module_path=$(readlink -f "$module_path")
        [ -f "$module_path" ] \
            || fail "Intel GSC dependency is not a regular file for $kernel: $required"
        module_rel=${module_path#/}
        cmp -s "$module_path" \
            <(lsinitrd -f "$module_rel" "$image" 2>/dev/null) \
            || fail "candidate for $kernel lacks exact Intel GSC dependency bytes: $required"
    done
    if [ "$basis" = hostonly ]; then
        grep -qF 'etc/noid-privacy/initramfs-hostonly' "$listing" \
            || fail "host-only candidate for $kernel lacks the M21 marker"
        cmp -s /etc/noid-privacy/initramfs-hostonly \
            <(lsinitrd -f etc/noid-privacy/initramfs-hostonly "$image" 2>/dev/null) \
            || fail "host-only candidate for $kernel has stale M21 marker bytes"
    elif grep -qF 'etc/noid-privacy/initramfs-hostonly' "$listing"; then
        fail "Generic candidate for $kernel unexpectedly contains the M21 marker"
    fi
    if [ "$ROOT_FSTYPE" = btrfs ]; then
        grep -qx btrfs "$modules" \
            || fail "candidate for $kernel lacks the Btrfs root module"
    fi
    if grep -qw crypt <<<"$ROOT_TYPES"; then
        for required in crypt dm systemd-cryptsetup; do
            grep -qx "$required" "$modules" \
                || fail "candidate for $kernel lacks root mapper module: $required"
        done
        for required in \
                usr/bin/systemd-cryptsetup \
                usr/lib/systemd/system-generators/systemd-cryptsetup-generator; do
            grep -qF "$required" "$listing" \
                || fail "candidate for $kernel lacks root unlock artifact: $required"
        done
        for required in dm_crypt drbg; do
            module_path=$(modinfo -k "$kernel" -n "$required" 2>/dev/null || true)
            [ -n "$module_path" ] \
                || fail "cannot resolve root unlock component for $kernel: $required"
            if [ "$module_path" != '(builtin)' ]; then
                module_file=${module_path##*/}
                grep -qF "/$module_file" "$listing" \
                    || fail "candidate for $kernel lacks root unlock object: $module_file"
            fi
        done
    fi
    if grep -Eq '/firewire-(core|net|ohci|sbp2)\.ko(\.(xz|zst|gz))?$' \
            "$listing"; then
        fail "candidate for $kernel retained an omitted FireWire object"
    fi
    if [ "$basis" = hostonly ] \
            && [ "$ROOT_CLASS" = simple-single-device-luks2-btrfs ] \
            && grep -Eq '^(mdraid|iscsi|fcoe|nbd)$' "$modules"; then
        fail "host-only candidate for $kernel retained unused storage modules"
    fi

    # SHARED-LOGIC-MARKER: root-path driver walk; keep in sync with
    # noid-dracut-hostonly-configure's validate_image().
    if [ -n "$ROOT_SOURCE" ] && [ -b "$ROOT_SOURCE" ]; then
        while read -r block_name block_type; do
            [ "$block_type" = disk ] || continue
            device_path=$(readlink -f "/sys/class/block/$block_name/device" \
                2>/dev/null || true)
            while [[ "$device_path" == /sys/devices/* ]]; do
                module_link=$device_path/driver/module
                if [ -L "$module_link" ]; then
                    controller_module=$(basename "$(readlink -f "$module_link")")
                    controller_path=$(modinfo -k "$kernel" -n "$controller_module" \
                        2>/dev/null || true)
                    if [ -z "$controller_path" ]; then
                        root_driver_is_kernel_integrated "$controller_module" \
                            || fail "cannot classify root-path driver for $kernel: $controller_module"
                    elif [ "$controller_path" != '(builtin)' ]; then
                        controller_file=${controller_path##*/}
                        grep -qF "/$controller_file" "$listing" \
                            || fail "candidate for $kernel lacks root-path driver: $controller_file"
                    fi
                fi
                parent_path=${device_path%/*}
                [ "$parent_path" != "$device_path" ] || break
                device_path=$parent_path
            done
        done < <(lsblk -s -nro KNAME,TYPE "$ROOT_SOURCE" 2>/dev/null)
    fi

    nvidia_base=/usr/lib/modules/$kernel/extra/nvidia/nvidia.ko
    if [ -f /etc/dracut.conf.d/99-noid-nvidia-initramfs.conf ] \
            && { [ -e "$nvidia_base" ] || [ -e "${nvidia_base}.xz" ] \
                || [ -e "${nvidia_base}.zst" ] || [ -e "${nvidia_base}.gz" ]; }; then
        [ -x /usr/libexec/noid-nvidia-verify ] \
            || fail "NVIDIA Dracut policy exists without its verifier"
        if [ "$allow_pending_mok" -eq 1 ]; then
            /usr/libexec/noid-nvidia-verify "$kernel" >/dev/null 2>&1 \
                || fail "NVIDIA identity verification failed for $kernel"
        else
            /usr/libexec/noid-nvidia-verify "$kernel" --require-enrolled \
                >/dev/null 2>&1 \
                || fail "enrolled NVIDIA identity verification failed for $kernel"
        fi
        for required in nvidia.ko nvidia-modeset.ko nvidia-drm.ko nvidia-uvm.ko; do
            grep -qF "$required" "$listing" \
                || fail "candidate for $kernel lacks NVIDIA object: $required"
        done
        for required in nvidia nvidia_modeset nvidia_drm nvidia_uvm; do
            module_path=$(modinfo -k "$kernel" -n "$required" 2>/dev/null || true)
            [ -n "$module_path" ] && [ "$module_path" != '(builtin)' ] \
                || fail "cannot resolve managed NVIDIA object for $kernel: $required"
            module_path=$(readlink -f "$module_path")
            module_file=${module_path#/}
            cmp -s "$module_path" \
                <(lsinitrd -f "$module_file" "$image" 2>/dev/null) \
                || fail "candidate for $kernel has stale NVIDIA object bytes: $required"
        done
        candidate_nvidia_verified=1
    elif grep -Eq '/nvidia(-drm|-modeset|-uvm)?\.ko(\.(xz|zst|gz))?$' \
            "$listing"; then
        fail "candidate for $kernel retained unmanaged proprietary NVIDIA objects"
    fi

    rm -f -- "$listing" "$modules"
    listing=
    modules=
}

rebuilt=0
if [ -n "$only_kernel" ]; then
    [ -d "/usr/lib/modules/$only_kernel" ] \
        || fail "selected kernel module tree is missing: $only_kernel"
    module_dirs=("/usr/lib/modules/$only_kernel")
else
    module_dirs=(/usr/lib/modules/*)
fi
for module_dir in "${module_dirs[@]}"; do
    [ -d "$module_dir" ] || continue
    kernel=${module_dir##*/}
    case "$kernel" in ''|*[!A-Za-z0-9._+-]*) fail "invalid kernel directory: $kernel" ;; esac
    final=/boot/initramfs-$kernel.img
    if [ -n "$only_kernel" ]; then
        [ -f "$final" ] && [ ! -L "$final" ] \
            || fail "selected kernel initramfs is missing or unsafe: $kernel"
    else
        [ -f "$final" ] && [ ! -L "$final" ] || continue
    fi

    candidate=$(mktemp "/boot/.initramfs-${kernel}.noid-candidate.XXXXXX")
    if ! dracut --force "${dracut_basis_args[@]}" "$candidate" "$kernel"; then
        fail "Dracut candidate build failed for $kernel"
    fi
    validate_candidate "$candidate" "$kernel"
    chown root:root "$candidate"
    chmod 0600 "$candidate"
    restorecon -F "$candidate" >/dev/null
    sync -- "$candidate"
    mv -fT -- "$candidate" "$final"
    candidate=
    sync -- "$final"
    sync -- /boot
    if [ "$candidate_nvidia_verified" -eq 1 ]; then
        evidence_helper=/usr/libexec/noid-nvidia-rebind-evidence
        [ -f "$evidence_helper" ] && [ ! -L "$evidence_helper" ] \
            && [ -x "$evidence_helper" ] \
            || fail "managed NVIDIA candidate lacks its M19 evidence bridge"
        [ "$(stat -c '%u:%g:%a:%h' "$evidence_helper" 2>/dev/null)" \
                = '0:0:755:1' ] \
            || fail "M19 NVIDIA evidence bridge metadata is invalid"
        "$evidence_helper" "$kernel" \
            || fail "NVIDIA pre-reboot evidence reconciliation failed for $kernel"
    fi
    rebuilt=$((rebuilt + 1))
done
[ "$rebuilt" -gt 0 ] || fail "no published kernel initramfs was found"
echo "NoID Privacy: atomically rebuilt and inspected $rebuilt initramfs image(s)."
GUARDED_REGENERATE_EOF
chmod 0755 /usr/libexec/noid-dracut-regenerate-all
chown root:root /usr/libexec/noid-dracut-regenerate-all

cat > /usr/libexec/noid-dracut-hostonly-configure <<'HOSTONLY_SCRIPT_EOF'
#!/usr/bin/bash
set -euo pipefail

LOG_TAG=noid-dracut-hostonly
POLICY_VERSION=2
STATE_DIR=/var/lib/noid-privacy
STATE_FILE=$STATE_DIR/dracut-hostonly.state
CONFIG=/etc/dracut.conf.d/99-noid-hostonly.conf
MARKER=/etc/noid-privacy/initramfs-hostonly
LOCK=/run/lock/noid-boot-mutation.lock
BOOT_SUCCESS_REQUEST=/run/noid-privacy/hostonly-boot-success-needed
FALLBACK_ARG=noid.initramfs=generic-fallback
RETRY=0

log() {
    echo "[$LOG_TAG] $*"
    logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true
}
fail() {
    log "FAIL: $*"
    exit 1
}

case "${1-}" in
    '') ;;
    --retry) RETRY=1 ;;
    *) fail "usage: noid-dracut-hostonly-configure [--retry]" ;;
esac
[ "$#" -le 1 ] || fail "usage: noid-dracut-hostonly-configure [--retry]"

if grep -qw 'rd.live.image' /proc/cmdline; then
    fail "refusing to make the Live/installer initramfs host-specific"
fi
[ -d /boot ] && [ -w /boot ] || fail "/boot is not writable"
for command in awk basename btrfs chmod chown cmp cp cryptsetup df dracut findmnt \
        flock grep grub2-editenv grub2-reboot grub2-set-default install lsblk \
        lsinitrd mktemp modinfo mv readlink restorecon stat sync uname wc; do
    command -v "$command" >/dev/null 2>&1 || fail "required command missing: $command"
done

exec 9>"$LOCK"
flock -w 300 9 || fail "timed out waiting for the Dracut convergence lock"

install -d -m 0755 -o root -g root /etc/dracut.conf.d \
    /run/noid-privacy "$STATE_DIR"

# M08 owns /etc/noid-privacy as a private root boundary because it can contain
# the local FSS verification-key receipt. Older M21 revisions widened that
# directory to 0755 while staging the non-secret initramfs marker. Accept only
# that exact legacy state, tighten it once, and never follow an unexpected
# path merely to make first-boot convergence succeed.
if [ ! -e /etc/noid-privacy ] && [ ! -L /etc/noid-privacy ]; then
    install -d -m 0700 -o root -g root /etc/noid-privacy
fi
[ -d /etc/noid-privacy ] && [ ! -L /etc/noid-privacy ] \
    && [ "$(readlink -e /etc/noid-privacy 2>/dev/null)" = /etc/noid-privacy ] \
    || fail "private NoID Privacy state directory is unsafe"
noid_etc_meta=$(stat -Lc '%u:%g:%a' /etc/noid-privacy 2>/dev/null || true)
case "$noid_etc_meta" in
    0:0:700) ;;
    0:0:755)
        chmod 0700 /etc/noid-privacy \
            || fail "cannot tighten the legacy NoID Privacy state directory"
        ;;
    *) fail "private NoID Privacy state directory metadata is unsafe: $noid_etc_meta" ;;
esac
[ "$(stat -Lc '%u:%g:%a' /etc/noid-privacy 2>/dev/null || true)" = 0:0:700 ] \
    || fail "private NoID Privacy state directory did not converge to 0700"

state_value() {
    local key=$1
    awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }' \
        "$STATE_FILE" 2>/dev/null
}

write_state() {
    local phase=$1 root_class=$2 target_kernel=$3 prepared_boot_id=$4
    local tmp
    tmp=$(mktemp "$STATE_DIR/.dracut-hostonly.state.XXXXXX") || return 1
    if ! printf 'policy_version=%s\nphase=%s\nroot_class=%s\ntarget_kernel=%s\nprepared_boot_id=%s\n' \
            "$POLICY_VERSION" "$phase" "$root_class" "$target_kernel" \
            "$prepared_boot_id" > "$tmp" || \
       ! chown root:root "$tmp" || ! chmod 0600 "$tmp" || \
       ! restorecon -F "$tmp" >/dev/null || ! sync -- "$tmp" || \
       ! mv -fT -- "$tmp" "$STATE_FILE" || ! sync -- "$STATE_FILE" || \
       ! sync -- "$STATE_DIR"; then
        rm -f -- "$tmp"
        return 1
    fi
}

validate_state_file() {
    local key phase root_class target_kernel prepared_boot_id
    [ -f "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] \
        || fail "invalid state-file type"
    [ "$(stat -c '%U:%G:%a' "$STATE_FILE")" = root:root:600 ] \
        || fail "invalid state-file ownership or mode"
    [ "$(wc -l < "$STATE_FILE")" -eq 5 ] \
        || fail "state file has an unexpected schema"
    for key in policy_version phase root_class target_kernel prepared_boot_id; do
        [ "$(awk -F= -v key="$key" '$1 == key { count++ } END { print count + 0 }' \
            "$STATE_FILE")" -eq 1 ] || fail "state key is missing or duplicated: $key"
    done
    awk -F= '
        !/^[a-z_]+=[A-Za-z0-9._+-]+$/ { bad=1 }
        $1 != "policy_version" && $1 != "phase" && $1 != "root_class" &&
        $1 != "target_kernel" && $1 != "prepared_boot_id" { bad=1 }
        END { exit bad }
    ' "$STATE_FILE" || fail "state file contains an unknown or malformed row"
    [ "$(state_value policy_version)" = "$POLICY_VERSION" ] \
        || fail "unknown state policy version"
    phase=$(state_value phase)
    case "$phase" in
        pending-reboot|recovered-generic|complete) ;;
        *) fail "unknown state phase: $phase" ;;
    esac
    root_class=$(state_value root_class)
    case "$root_class" in
        simple-single-device-luks2-btrfs|other-hostonly) ;;
        *) fail "invalid root class in state" ;;
    esac
    target_kernel=$(state_value target_kernel)
    case "$target_kernel" in
        *[!A-Za-z0-9._+-]*|'') fail "invalid target kernel in state" ;;
    esac
    prepared_boot_id=$(state_value prepared_boot_id)
    [[ "$prepared_boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
        || fail "invalid prepared boot ID in state"
}

# SHARED-LOGIC-MARKER: root-class detection; keep in sync with
# noid-dracut-regenerate-all's inline classification.
detect_root_class() {
    local source fstype btrfs_show btrfs_devices root_types crypt_name
    source=$(findmnt -nro SOURCE / 2>/dev/null || true)
    source=${source%%\[*}
    fstype=$(findmnt -nro FSTYPE / 2>/dev/null || true)
    ROOT_SOURCE=$source
    ROOT_FSTYPE=$fstype
    ROOT_TYPES=
    ROOT_CLASS=other-hostonly
    if [ -b "$source" ]; then
        ROOT_TYPES=$(lsblk -s -nro TYPE "$source" 2>/dev/null | sort -u | tr '\n' ' ')
    fi
    if [ "$fstype" = btrfs ] && [ -b "$source" ] && \
       [ "$(lsblk -dnro TYPE "$source" 2>/dev/null || true)" = crypt ]; then
        btrfs_show=$(btrfs filesystem show --raw / 2>/dev/null || true)
        btrfs_devices=$(grep -c '^[[:space:]]*devid[[:space:]]' <<<"$btrfs_show" || true)
        btrfs_devices=${btrfs_devices:-0}
        root_types=$ROOT_TYPES
        crypt_name=${source#/dev/mapper/}
        if [ "$btrfs_devices" -eq 1 ] && \
           ! grep -q 'MISSING' <<<"$btrfs_show" && \
           cryptsetup status "$crypt_name" 2>/dev/null | \
               grep -q 'type:[[:space:]]*LUKS2' && \
           grep -qw disk <<<"$root_types" && \
           ! grep -Eq '(^|[[:space:]])(raid[^[:space:]]*|lvm|mpath|loop)([[:space:]]|$)' \
               <<<"$root_types"; then
            ROOT_CLASS=simple-single-device-luks2-btrfs
        fi
    fi
}

# SHARED-LOGIC-MARKER: integrated root-driver classification; keep in sync
# with noid-dracut-regenerate-all.
root_driver_is_kernel_integrated() {
    local module=$1 module_root
    case "$module" in
        ''|*[!A-Za-z0-9_-]*) return 1 ;;
    esac
    module_root=/sys/module/$module
    # Dynamic modules have the kernel's `initstate` modinfo attribute. A
    # driver/module owner without it is integrated into the running kernel.
    # Callers use this only when target-kernel modinfo found no loadable object.
    [ -d "$module_root" ] && [ ! -L "$module_root" ] \
        && [ ! -e "$module_root/initstate" ] \
        && [ ! -L "$module_root/initstate" ]
}

validate_image() {
    local image=$1 kernel=$2 root_class=$3 listing modules required
    local block_name block_type device_path parent_path module_link
    local controller_module controller_path controller_file
    local module_path module_file module_rel
    listing=$(mktemp /var/tmp/noid-hostonly-listing.XXXXXX)
    modules=$(mktemp /var/tmp/noid-hostonly-modules.XXXXXX)
    if ! lsinitrd "$image" >"$listing" 2>&1 || \
       ! lsinitrd -m "$image" >"$modules" 2>&1; then
        rm -f -- "$listing" "$modules"
        return 1
    fi
    for required in \
        etc/noid-privacy/initramfs-hostonly \
        etc/modprobe.d/noid-security-blacklist.conf \
        etc/modprobe.d/noid-mei-submodules.conf \
        etc/udev/rules.d/99-noid-mei-kt-block.rules \
        usr/libexec/noid-mei-kt-enforce \
        etc/plymouth/plymouthd.conf \
        usr/share/plymouth/themes/bgrt/bgrt.plymouth \
        usr/share/plymouth/themes/spinner/watermark.png; do
        if ! grep -qF "$required" "$listing" \
                || [ ! -f "/$required" ] || [ -L "/$required" ] \
                || ! cmp -s "/$required" \
                    <(lsinitrd -f "$required" "$image" 2>/dev/null); then
            log "candidate $image lacks exact current artifact bytes: $required"
            rm -f -- "$listing" "$modules"
            return 1
        fi
    done
    for required in kernel-modules rootfs-block; do
        if ! grep -qx "$required" "$modules"; then
            log "candidate $image lacks required Dracut module: $required"
            rm -f -- "$listing" "$modules"
            return 1
        fi
    done
    if ! grep -qx plymouth "$modules"; then
        log "candidate $image lacks the Plymouth Dracut module"
        rm -f -- "$listing" "$modules"
        return 1
    fi
    for required in mei_me mei_gsc_proxy; do
        module_path=$(modinfo -k "$kernel" -n "$required" 2>/dev/null || true)
        if [ -z "$module_path" ] || [ "$module_path" = '(builtin)' ]; then
            log "cannot resolve Intel GSC dependency for $kernel: $required"
            rm -f -- "$listing" "$modules"
            return 1
        fi
        module_path=$(readlink -f "$module_path")
        module_rel=${module_path#/}
        if [ ! -f "$module_path" ] || ! cmp -s "$module_path" \
                <(lsinitrd -f "$module_rel" "$image" 2>/dev/null); then
            log "candidate $image lacks exact Intel GSC dependency bytes: $required"
            rm -f -- "$listing" "$modules"
            return 1
        fi
    done
    if [ "${ROOT_FSTYPE-}" = btrfs ] && ! grep -qx btrfs "$modules"; then
        log "candidate $image lacks the root filesystem Dracut module: btrfs"
        rm -f -- "$listing" "$modules"
        return 1
    fi
    if grep -qw crypt <<<"${ROOT_TYPES-}"; then
        for required in crypt dm systemd-cryptsetup; do
            if ! grep -qx "$required" "$modules"; then
                log "candidate $image lacks root-mapper Dracut module: $required"
                rm -f -- "$listing" "$modules"
                return 1
            fi
        done
        for required in \
            usr/bin/systemd-cryptsetup \
            usr/lib/systemd/system-generators/systemd-cryptsetup-generator; do
            if ! grep -qF "$required" "$listing"; then
                log "candidate $image lacks root-unlock artifact: $required"
                rm -f -- "$listing" "$modules"
                return 1
            fi
        done
        # Fedora Dracut's crypt module unconditionally installs dm_crypt and
        # drbg, then sloppy host-only installs the full =crypto module class.
        # Require the two named loadable objects when they are not built in;
        # the real reboot remains the proof that the active cipher works.
        for required in dm_crypt drbg; do
            module_path=$(modinfo -k "$kernel" -n "$required" 2>/dev/null || true)
            [ -n "$module_path" ] || {
                log "cannot resolve root-unlock kernel component: $required"
                rm -f -- "$listing" "$modules"
                return 1
            }
            if [ "$module_path" != '(builtin)' ]; then
                module_file=${module_path##*/}
                if ! grep -qF "/$module_file" "$listing"; then
                    log "candidate lacks root-unlock kernel object: $module_file"
                    rm -f -- "$listing" "$modules"
                    return 1
                fi
            fi
        done
    fi
    if grep -Eq '/firewire-(core|net|ohci|sbp2)\.ko(\.(xz|zst|gz))?$' "$listing"; then
        log "candidate $image retained an omitted FireWire kernel object"
        rm -f -- "$listing" "$modules"
        return 1
    fi
    if [ "$root_class" = simple-single-device-luks2-btrfs ] && \
       grep -Eq '^(mdraid|iscsi|fcoe|nbd)$' "$modules"; then
        log "candidate retained unused storage modules on the simple root"
        rm -f -- "$listing" "$modules"
        return 1
    fi

    # Verify every loadable driver on each underlying root disk's device path.
    # The closest driver can be sd_mod/virtio_blk while the controller lives at
    # an ancestor (AHCI/NVMe/virtio_pci), so a direct block-device lookup is not
    # sufficient. Built-in ancestors need no initramfs object.
    # SHARED-LOGIC-MARKER: root-path driver walk; keep in sync with
    # noid-dracut-regenerate-all's validate_candidate().
    if [ -n "${ROOT_SOURCE-}" ] && [ -b "$ROOT_SOURCE" ]; then
        while read -r block_name block_type; do
            [ "$block_type" = disk ] || continue
            device_path=$(readlink -f "/sys/class/block/$block_name/device" 2>/dev/null || true)
            while [[ "$device_path" == /sys/devices/* ]]; do
                module_link=$device_path/driver/module
                if [ -L "$module_link" ]; then
                    controller_module=$(basename "$(readlink -f "$module_link")")
                    controller_path=$(modinfo -k "$kernel" -n "$controller_module" \
                        2>/dev/null || true)
                    if [ -z "$controller_path" ] \
                            && ! root_driver_is_kernel_integrated "$controller_module"; then
                        log "cannot classify root-path driver module $controller_module"
                        rm -f -- "$listing" "$modules"
                        return 1
                    fi
                    if [ -n "$controller_path" ] \
                            && [ "$controller_path" != '(builtin)' ]; then
                        controller_file=${controller_path##*/}
                        if ! grep -qF "/$controller_file" "$listing"; then
                            log "candidate lacks root-path driver object: $controller_file"
                            rm -f -- "$listing" "$modules"
                            return 1
                        fi
                    fi
                fi
                parent_path=${device_path%/*}
                [ "$parent_path" != "$device_path" ] || break
                device_path=$parent_path
            done
        done < <(lsblk -s -nro KNAME,TYPE "$ROOT_SOURCE" 2>/dev/null)
    fi
    rm -f -- "$listing" "$modules"
    return 0
}

validate_generic_image() {
    local image=$1 kernel=$2 listing required module_path module_rel
    [ -f "$image" ] && [ ! -L "$image" ] || return 1
    listing=$(mktemp /var/tmp/noid-generic-listing.XXXXXX)
    if ! lsinitrd "$image" >"$listing" 2>&1 || \
       grep -q 'etc/noid-privacy/initramfs-hostonly' "$listing"; then
        rm -f -- "$listing"
        return 1
    fi
    for required in \
        etc/modprobe.d/noid-security-blacklist.conf \
        etc/modprobe.d/noid-mei-submodules.conf \
        etc/udev/rules.d/99-noid-mei-kt-block.rules \
        usr/libexec/noid-mei-kt-enforce; do
        if ! grep -qF "$required" "$listing" \
                || [ ! -f "/$required" ] || [ -L "/$required" ] \
                || ! cmp -s "/$required" \
                    <(lsinitrd -f "$required" "$image" 2>/dev/null); then
            rm -f -- "$listing"
            return 1
        fi
    done
    for required in mei_me mei_gsc_proxy; do
        module_path=$(modinfo -k "$kernel" -n "$required" 2>/dev/null || true)
        if [ -z "$module_path" ] || [ "$module_path" = '(builtin)' ]; then
            rm -f -- "$listing"
            return 1
        fi
        module_path=$(readlink -f "$module_path")
        module_rel=${module_path#/}
        if [ ! -f "$module_path" ] || ! cmp -s "$module_path" \
                <(lsinitrd -f "$module_rel" "$image" 2>/dev/null); then
            rm -f -- "$listing"
            return 1
        fi
    done
    rm -f -- "$listing"
    return 0
}

publish_hostonly_inputs() {
    local config_tmp marker_tmp
    config_tmp=$(mktemp /etc/dracut.conf.d/.99-noid-hostonly.XXXXXX)
    marker_tmp=$(mktemp /etc/noid-privacy/.initramfs-hostonly.XXXXXX)
    cat > "$config_tmp" <<'HOSTONLY_CONFIG_EOF'
# NoID Privacy — installed-system initramfs policy (Module 21)
# Firstboot publishes a staged -H candidate with a bootable generic BLS
# fallback. This drop-in makes later kernel/NVIDIA rebuilds follow the host.
hostonly="yes"
hostonly_mode="sloppy"
hostonly_cmdline="no"
install_items+=" /etc/noid-privacy/initramfs-hostonly "
HOSTONLY_CONFIG_EOF
    printf 'policy_version=%s\nmode=hostonly-sloppy\n' "$POLICY_VERSION" > "$marker_tmp"
    chown root:root "$config_tmp" "$marker_tmp"
    chmod 0644 "$config_tmp" "$marker_tmp"
    restorecon -F "$config_tmp" "$marker_tmp" >/dev/null
    sync -- "$config_tmp" "$marker_tmp"
    mv -fT -- "$config_tmp" "$CONFIG"
    mv -fT -- "$marker_tmp" "$MARKER"
    sync -- "$CONFIG"
    sync -- "$MARKER"
    sync -- /etc/dracut.conf.d /etc/noid-privacy
}

image_has_hostonly_marker() {
    local image=$1 listing rc=1
    listing=$(mktemp /var/tmp/noid-marker-listing.XXXXXX)
    if lsinitrd "$image" >"$listing" 2>&1 && \
       grep -q 'etc/noid-privacy/initramfs-hostonly' "$listing"; then
        rc=0
    fi
    rm -f -- "$listing"
    return "$rc"
}

fallback_paths() {
    local kernel=$1
    STANDARD_IMAGE=/boot/initramfs-$kernel.img
    FALLBACK_IMAGE=/boot/initramfs-$kernel.noid-generic-fallback.img
    FALLBACK_BLS=/boot/loader/entries/noid-generic-fallback-$kernel.conf
    PUBLISH_TMP=/boot/.initramfs-$kernel.noid-publish.tmp
    FALLBACK_TMP=/boot/.initramfs-$kernel.noid-fallback.tmp
    FALLBACK_BLS_ID=noid-generic-fallback-$kernel
}

resolve_source_bls() {
    local kernel=$1
    local -a matches=()
    [ -d /boot/loader/entries ] && [ ! -L /boot/loader/entries ] || {
        log "BLS entry directory is missing or unsafe"
        return 1
    }
    mapfile -t matches < <(
        grep -l -x "version $kernel" /boot/loader/entries/*.conf 2>/dev/null | sort
    )
    [ "${#matches[@]}" -eq 1 ] || {
        log "expected exactly one BLS entry for running kernel $kernel"
        return 1
    }
    SOURCE_BLS=${matches[0]}
    [ -f "$SOURCE_BLS" ] && [ ! -L "$SOURCE_BLS" ] || {
        log "running-kernel BLS entry is missing or unsafe"
        return 1
    }
    case "$(stat -c '%U:%G:%a' "$SOURCE_BLS")" in
        root:root:600|root:root:644) ;;
        *)
            log "running-kernel BLS entry metadata differs"
            return 1
            ;;
    esac
    SOURCE_BLS_ID=$(basename "$SOURCE_BLS" .conf)
    case "$SOURCE_BLS_ID" in
        *[!A-Za-z0-9._+-]*|'')
            log "invalid running-kernel BLS identifier"
            return 1
            ;;
    esac
}

grub_env_value() {
    local key=$1 grub_env
    grub_env=$(grub2-editenv - list) || return 1
    awk -F= -v key="$key" '$1 == key {
        print substr($0, length(key) + 2)
        exit
    }' <<<"$grub_env"
}

set_saved_entry() {
    local entry=$1
    grub2-set-default "$entry" >/dev/null || return 1
    [ "$(grub_env_value saved_entry)" = "$entry" ] || return 1
    [ -z "$(grub_env_value next_entry)" ] || return 1
    sync -- /boot/grub2/grubenv || return 1
    sync -- /boot/grub2 || return 1
    sync -- /boot || return 1
}

set_next_entry() {
    local entry=$1
    grub2-reboot "$entry" >/dev/null || return 1
    [ "$(grub_env_value next_entry)" = "$entry" ] || return 1
    sync -- /boot/grub2/grubenv || return 1
    sync -- /boot/grub2 || return 1
    sync -- /boot || return 1
}

clear_next_entry() {
    local next_entry
    next_entry=$(grub_env_value next_entry) || return 1
    if [ -n "$next_entry" ]; then
        grub2-editenv - unset next_entry >/dev/null || return 1
        next_entry=$(grub_env_value next_entry) || return 1
        [ -z "$next_entry" ] || return 1
        sync -- /boot/grub2/grubenv || return 1
        sync -- /boot/grub2 || return 1
        sync -- /boot || return 1
    fi
}

restore_generic() {
    local kernel=$1
    fallback_paths "$kernel"
    resolve_source_bls "$kernel" || return 1
    if [ -e "$FALLBACK_IMAGE" ] || [ -L "$FALLBACK_IMAGE" ]; then
        [ -f "$FALLBACK_IMAGE" ] && [ ! -L "$FALLBACK_IMAGE" ] \
            && [ "$(stat -c '%U:%G:%a' "$FALLBACK_IMAGE")" = root:root:600 ] \
            || return 1
        validate_generic_image "$FALLBACK_IMAGE" "$kernel" || return 1
    fi
    # First retire any already-armed one-shot candidate while the persistent
    # Generic entry and its image are still intact. Then copy Generic through
    # a same-filesystem candidate to the standard path; never move away the
    # image still named by the saved fallback entry.
    clear_next_entry || return 1
    if [ -f "$FALLBACK_IMAGE" ]; then
        rm -f -- "$PUBLISH_TMP" "$FALLBACK_TMP" || return 1
        install -m 0600 -o root -g root "$FALLBACK_IMAGE" "$PUBLISH_TMP" \
            || return 1
        restorecon -F "$PUBLISH_TMP" >/dev/null || return 1
        sync -- "$PUBLISH_TMP" || return 1
        mv -fT -- "$PUBLISH_TMP" "$STANDARD_IMAGE" || return 1
        sync -- "$STANDARD_IMAGE" || return 1
        sync -- /boot || return 1
    fi
    set_saved_entry "$SOURCE_BLS_ID" || return 1
    rm -f -- "$FALLBACK_BLS" "$FALLBACK_IMAGE" \
        "$PUBLISH_TMP" "$FALLBACK_TMP" "$CONFIG" "$MARKER" || return 1
    sync -- /boot/loader/entries || return 1
    sync -- /boot || return 1
    sync -- /etc/dracut.conf.d /etc/noid-privacy || return 1
}

if [ -e "$STATE_FILE" ]; then
    validate_state_file
    phase=$(state_value phase)
    root_class=$(state_value root_class)
    target_kernel=$(state_value target_kernel)
    prepared_boot_id=$(state_value prepared_boot_id)
    case "$phase" in
        complete)
            log "host-only boot was already confirmed for $target_kernel"
            exit 0
            ;;
        recovered-generic)
            if [ "$RETRY" -eq 0 ]; then
                log "generic fallback was restored; inspect the prior failure, then use --retry"
                exit 0
            fi
            rm -f -- "$STATE_FILE"
            sync -- "$STATE_DIR"
            ;;
        pending-reboot)
            current_boot_id=$(cat /proc/sys/kernel/random/boot_id)
            if [ "$current_boot_id" = "$prepared_boot_id" ]; then
                fallback_paths "$target_kernel"
                resolve_source_bls "$target_kernel" \
                    || fail "cannot resolve the pending normal BLS entry"
                [ "$(grub_env_value saved_entry)" = "$FALLBACK_BLS_ID" ] && \
                [ "$(grub_env_value next_entry)" = "$SOURCE_BLS_ID" ] \
                    || fail "pending GRUB saved/next entry state drifted"
                log "host-only candidate published; reboot required for boot confirmation"
                exit 0
            fi
            if [ "$(uname -r)" != "$target_kernel" ]; then
                log "pending candidate $target_kernel was not booted; confirmation deferred"
                exit 0
            fi
            detect_root_class
            fallback_paths "$target_kernel"
            if grep -Fqw -- "$FALLBACK_ARG" /proc/cmdline; then
                restore_generic "$target_kernel"
                write_state recovered-generic "$root_class" "$target_kernel" "$prepared_boot_id"
                log "generic recovery boot detected; generic image restored as the default"
                exit 0
            fi
            # A hard cut can land after Generic was atomically copied back to
            # the standard path but before the pending record was replaced.
            # Accept only a fully validated Generic image that actually booted;
            # an arbitrary marker-less candidate remains a hard failure.
            if ! image_has_hostonly_marker "$STANDARD_IMAGE"; then
                validate_generic_image "$STANDARD_IMAGE" "$target_kernel" \
                    || fail "marker-less pending image is not a valid Generic recovery"
                restore_generic "$target_kernel" \
                    || fail "cannot finish the interrupted Generic restoration"
                write_state recovered-generic "$root_class" "$target_kernel" "$prepared_boot_id"
                log "interrupted Generic restoration completed from the booted standard image"
                exit 0
            fi
            validate_image "$STANDARD_IMAGE" "$target_kernel" "$root_class" \
                || fail "booted candidate failed post-boot content validation"
            resolve_source_bls "$target_kernel" \
                || fail "cannot resolve the confirmed normal BLS entry"
            set_saved_entry "$SOURCE_BLS_ID" \
                || fail "cannot restore the confirmed host-only entry as GRUB default"
            rm -f -- "$FALLBACK_BLS" "$FALLBACK_IMAGE"
            sync -- /boot/loader/entries
            sync -- /boot
            write_state complete "$root_class" "$target_kernel" "$prepared_boot_id"
            log "host-only candidate boot confirmed; generic fallback retired"
            exit 0
            ;;
        *) fail "unknown state phase: $phase" ;;
    esac
fi

kernel=$(uname -r)
case "$kernel" in *[!A-Za-z0-9._+-]*|'') fail "invalid running kernel identity" ;; esac
fallback_paths "$kernel"
resolve_source_bls "$kernel" || fail "cannot resolve the running-kernel BLS entry"
detect_root_class
root_class=$ROOT_CLASS
log "detected root class: $root_class"

# Reconcile a power loss between publication and the durable pending state.
# Presence of the durable Generic copy is the recovery authority.
if [ -f "$FALLBACK_IMAGE" ]; then
    if grep -Fqw -- "$FALLBACK_ARG" /proc/cmdline; then
        log "generic recovery boot detected after interrupted publication"
    else
        log "interrupted publication detected; restoring generic image"
    fi
    restore_generic "$kernel" || fail "cannot restore Generic after interrupted publication"
    current_boot_id=$(cat /proc/sys/kernel/random/boot_id)
    write_state recovered-generic "$root_class" "$kernel" "$current_boot_id"
    log "generic image restored; inspect the interruption, then use --retry"
    exit 0
elif [ ! -f "$STANDARD_IMAGE" ]; then
    fail "running-kernel initramfs is missing and no generic fallback exists"
else
    rm -f -- "$FALLBACK_BLS" "$PUBLISH_TMP" "$FALLBACK_TMP"
    sync -- /boot/loader/entries
    sync -- /boot
fi
if ! awk -v expected="/initramfs-$kernel.img" '
    $1 == "title" { titles++ }
    $1 == "version" { versions++ }
    $1 == "initrd" && $2 == expected { initrds++ }
    $1 == "options" { options++ }
    END { exit !(titles == 1 && versions == 1 && initrds == 1 && options == 1) }
' "$SOURCE_BLS"; then
    fail "running-kernel BLS entry has an ambiguous or nonstandard structure"
fi

# /boot is outside the Snapper root. If a deliberate root rollback removes the
# state file after a confirmed candidate boot, reconstruct completion from the
# actually booted running-kernel image instead of treating it as Generic.
if image_has_hostonly_marker "$STANDARD_IMAGE"; then
    validate_image "$STANDARD_IMAGE" "$kernel" "$root_class" \
        || fail "booted host-only image failed state-reconstruction validation"
    publish_hostonly_inputs
    current_boot_id=$(cat /proc/sys/kernel/random/boot_id)
    write_state complete "$root_class" "$kernel" "$current_boot_id"
    log "reconstructed confirmed host-only config, marker and state after root rollback"
    exit 0
fi

grep -qx 'GRUB_DEFAULT=saved' /etc/default/grub \
    || fail "GRUB_DEFAULT=saved is required for the recovery transaction"
[ -f /boot/grub2/grubenv ] && [ ! -L /boot/grub2/grubenv ] \
    || fail "GRUB environment block is missing or unsafe"
[ "$(grub_env_value saved_entry)" = "$SOURCE_BLS_ID" ] \
    || fail "running-kernel BLS entry is not the current saved GRUB default"
[ -z "$(grub_env_value next_entry)" ] \
    || fail "an unrelated one-shot GRUB entry is already pending"

stage_dir=$(mktemp -d /var/tmp/noid-hostonly-stage.XXXXXX)
candidate=$stage_dir/initramfs-$kernel.img
dracut_log=$stage_dir/dracut.log
fallback_bls_tmp=$stage_dir/fallback.conf
publication_active=0
committed=0
state_published=0
cleanup() {
    local rc=$?
    trap - EXIT
    rm -f -- "${PUBLISH_TMP-}" \
        "${FALLBACK_TMP-}" "${bls_publish_tmp-}"
    rm -rf -- "${stage_dir-}"
    if [ "${publication_active:-0}" -eq 1 ] && [ "${committed:-0}" -eq 0 ]; then
        rm -f -- "$BOOT_SUCCESS_REQUEST"
        log "publication did not commit; restoring generic image"
        if restore_generic "$kernel"; then
            if [ "${state_published:-0}" -eq 1 ]; then
                write_state recovered-generic "$root_class" "$kernel" "$prepared_boot_id" \
                    || true
            fi
        fi
    fi
    exit "$rc"
}
trap cleanup EXIT

# From this point the durable host-only inputs exist. Arm rollback before the
# first publication so a dracut failure cannot strand CONFIG/MARKER while the
# cleanup path still believes no transaction started.
publication_active=1
publish_hostonly_inputs

if ! dracut --force --hostonly --hostonly-mode sloppy --no-hostonly-cmdline \
        "$candidate" "$kernel" >"$dracut_log" 2>&1; then
    tail -n 40 "$dracut_log" >&2 || true
    fail "staged host-only initramfs generation failed"
fi
validate_image "$candidate" "$kernel" "$root_class" \
    || fail "staged host-only candidate failed validation"
validate_generic_image "$STANDARD_IMAGE" "$kernel" \
    || fail "currently booted standard image is not a valid Generic fallback"

# Build the recovery entry before touching /boot. It retains the signed kernel
# and exact command line, changes only the initramfs, title/version and marker.
if ! awk -v kernel="$kernel" \
        -v fallback="/initramfs-$kernel.noid-generic-fallback.img" \
        -v marker="$FALLBACK_ARG" '
    $1 == "title" && !title_done {
        print $0 " — Generic Initramfs Recovery"
        title_done = 1
        next
    }
    $1 == "version" {
        print "version " kernel ".noid-generic-fallback"
        version_done = 1
        next
    }
    $1 == "initrd" {
        $2 = fallback
        print
        initrd_done = 1
        next
    }
    $1 == "options" {
        print $0 " " marker
        options_done = 1
        next
    }
    { print }
    END { exit !(title_done && version_done && initrd_done && options_done) }
' "$SOURCE_BLS" > "$fallback_bls_tmp"; then
    fail "cannot construct the generic recovery BLS entry"
fi
grep -qx "version $kernel.noid-generic-fallback" "$fallback_bls_tmp" \
    || fail "generic recovery BLS version postcondition failed"
grep -qF "initrd /initramfs-$kernel.noid-generic-fallback.img" "$fallback_bls_tmp" \
    || fail "generic recovery BLS initrd postcondition failed"
grep -qF " $FALLBACK_ARG" "$fallback_bls_tmp" \
    || fail "generic recovery BLS marker postcondition failed"

candidate_bytes=$(stat -c %s "$candidate")
generic_bytes=$(stat -c %s "$STANDARD_IMAGE")
boot_available=$(df -PB1 /boot | awk 'NR == 2 { print $4 }')
minimum_headroom=$((64 * 1024 * 1024))
if [ "$boot_available" -lt $((candidate_bytes + generic_bytes + minimum_headroom)) ]; then
    fail "/boot lacks candidate + Generic-copy size plus 64 MiB publication headroom"
fi

rm -f -- "$PUBLISH_TMP" "$FALLBACK_TMP"
install -m 0600 -o root -g root "$candidate" "$PUBLISH_TMP"
restorecon -F "$PUBLISH_TMP" >/dev/null
sync -- "$PUBLISH_TMP"

install -m 0600 -o root -g root "$STANDARD_IMAGE" "$FALLBACK_TMP"
restorecon -F "$FALLBACK_TMP" >/dev/null
sync -- "$FALLBACK_TMP"
mv -fT -- "$FALLBACK_TMP" "$FALLBACK_IMAGE"
sync -- "$FALLBACK_IMAGE"
sync -- /boot

bls_publish_tmp=$(mktemp /boot/loader/entries/.noid-generic-fallback.XXXXXX)
install -m 0644 -o root -g root "$fallback_bls_tmp" "$bls_publish_tmp"
restorecon -F "$bls_publish_tmp" >/dev/null
mv -fT -- "$bls_publish_tmp" "$FALLBACK_BLS"
sync -- "$FALLBACK_BLS"
sync -- /boot/loader/entries
sync -- /boot

set_saved_entry "$FALLBACK_BLS_ID" \
    || fail "cannot arm the Generic recovery entry as the persistent GRUB default"
mv -fT -- "$PUBLISH_TMP" "$STANDARD_IMAGE"
restorecon -F "$STANDARD_IMAGE" "$FALLBACK_IMAGE" >/dev/null
sync -- "$STANDARD_IMAGE"
sync -- /boot

prepared_boot_id=$(cat /proc/sys/kernel/random/boot_id)
state_published=1
write_state pending-reboot "$root_class" "$kernel" "$prepared_boot_id"
set_next_entry "$SOURCE_BLS_ID" \
    || fail "cannot arm the host-only candidate as the one-shot GRUB entry"

# The normal next-entry trial must not manufacture a visible recovery menu.
# Publish an ephemeral, root-owned request instead. A separate graphical-user
# unit consumes it only after noid-user-firstrun.service succeeds, then invokes
# Fedora's deliberately SUID grub2-set-bootflag helper with the single allowed
# boot_success argument. This marks the publishing boot successful so the
# planned one-shot restart remains silent. GRUB resets that flag when the trial
# starts; the saved Generic default remains the recovery path until the target
# kernel reaches the real-root M21 service and passes its image checks.
boot_success_tmp=$(mktemp /run/noid-privacy/.hostonly-boot-success-needed.XXXXXX)
printf 'policy_version=%s\nprepared_boot_id=%s\n' \
    "$POLICY_VERSION" "$prepared_boot_id" > "$boot_success_tmp"
chown root:root "$boot_success_tmp"
chmod 0444 "$boot_success_tmp"
mv -fT -- "$boot_success_tmp" "$BOOT_SUCCESS_REQUEST"
restorecon -F "$BOOT_SUCCESS_REQUEST" >/dev/null
sync -- "$BOOT_SUCCESS_REQUEST"
committed=1
log "host-only candidate published with silent one-shot trial and bootable Generic fallback; reboot required"
HOSTONLY_SCRIPT_EOF
chmod 0755 /usr/libexec/noid-dracut-hostonly-configure
chown root:root /usr/libexec/noid-dracut-hostonly-configure

cat > /etc/systemd/system/noid-dracut-hostonly-firstboot.service <<'HOSTONLY_SERVICE_EOF'
[Unit]
Description=NoID Privacy transactional host-only initramfs convergence
Documentation=file:///usr/share/doc/noid-privacy/21-kernel-module-blacklist.md
Requires=noid-snapper-init.service systemd-tmpfiles-setup.service
After=local-fs.target noid-snapper-init.service systemd-tmpfiles-setup.service
RequiresMountsFor=/boot
ConditionKernelCommandLine=!rd.live.image

[Service]
Type=oneshot
ExecStart=/usr/libexec/noid-dracut-hostonly-configure
RemainAfterExit=yes
TimeoutStartSec=20min
# Building and byte-validating two initramfs paths is intentionally thorough,
# but it must not hold the graphical login target or contend with first-session
# UX. The native scheduler/cgroup controls retain progress while yielding both
# CPU and storage whenever interactive work exists.
Nice=19
CPUWeight=10
IOWeight=10
IOSchedulingClass=idle
# /run/noid-privacy has a cross-service lifetime owned by Module 05's tmpfiles
# rule. This consumer requires that boot setup instead of deleting the shared
# directory when its own oneshot is stopped.
ProtectSystem=strict
ReadWritePaths=/boot /etc/dracut.conf.d /etc/noid-privacy /var/lib/noid-privacy /var/tmp /run/lock /run/noid-privacy
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
# Dracut must be able to read the installed module tree. Deny module loading
# without hiding /usr/lib/modules from the service's mount namespace.
CapabilityBoundingSet=~CAP_SYS_MODULE
SystemCallFilter=~@module
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
IPAddressDeny=any
HOSTONLY_SERVICE_EOF
chmod 0644 /etc/systemd/system/noid-dracut-hostonly-firstboot.service
chown root:root /etc/systemd/system/noid-dracut-hostonly-firstboot.service

cat > /etc/systemd/system/noid-dracut-hostonly-firstboot.timer <<'HOSTONLY_TIMER_EOF'
[Unit]
Description=Schedule NoID Privacy host-only initramfs convergence off the login path
Documentation=file:///usr/share/doc/noid-privacy/21-kernel-module-blacklist.md
ConditionKernelCommandLine=!rd.live.image

[Timer]
# A timer becomes active immediately and starts the long oneshot separately;
# multi-user.target therefore waits only for timer activation, not for Dracut.
OnActiveSec=1s
AccuracySec=1s
Unit=noid-dracut-hostonly-firstboot.service

[Install]
WantedBy=multi-user.target
HOSTONLY_TIMER_EOF
chmod 0644 /etc/systemd/system/noid-dracut-hostonly-firstboot.timer
chown root:root /etc/systemd/system/noid-dracut-hostonly-firstboot.timer
systemctl disable noid-dracut-hostonly-firstboot.service >/dev/null 2>&1 || true
systemctl enable noid-dracut-hostonly-firstboot.timer >/dev/null
log "  [OK] target-topology host-only convergence installed off the login path"

# Mark only the planned first installed boot successful after the real user's
# transactional first-login work succeeds. This retains Fedora's normal
# two-minute success timer for every later boot and does not broaden privilege:
# grub2-set-bootflag is Fedora's existing tightly-scoped SUID helper, accepts
# only boot_success/menu_show_once, and is already retained by Module 10 for the
# vendor grub-boot-success.timer.
cat > /usr/libexec/noid-mark-hostonly-boot-success <<'HOSTONLY_BOOT_SUCCESS_EOF'
#!/usr/bin/bash
set -euo pipefail

REQUEST=/run/noid-privacy/hostonly-boot-success-needed
BOOTFLAG=/usr/sbin/grub2-set-bootflag

fail() {
    printf 'noid-mark-hostonly-boot-success: %s\n' "$*" >&2
    exit 1
}

[ "$EUID" -ne 0 ] || fail "must run in the normal graphical user manager"
! grep -qw 'rd.live.image' /proc/cmdline || fail "refusing the Live environment"
[ -f "$REQUEST" ] && [ ! -L "$REQUEST" ] \
    || fail "ephemeral host-only success request is missing or unsafe"
[ "$(stat -c '%U:%G:%a' "$REQUEST")" = root:root:444 ] \
    || fail "ephemeral host-only success request metadata differs"
[ -f "$BOOTFLAG" ] && [ ! -L "$BOOTFLAG" ] \
    || fail "Fedora boot-flag helper is missing or unsafe"
[ "$(stat -c '%U:%G:%a' "$BOOTFLAG")" = root:root:4755 ] \
    || fail "Fedora boot-flag helper metadata differs"

expected=$(printf 'policy_version=2\nprepared_boot_id=%s' \
    "$(cat /proc/sys/kernel/random/boot_id)")
[ "$(<"$REQUEST")" = "$expected" ] \
    || fail "ephemeral request is not bound to this installed boot"

"$BOOTFLAG" boot_success \
    || fail "Fedora helper did not mark the installed boot successful"
printf 'NoID Privacy: marked the current installed boot successful after first-login transaction\n'
HOSTONLY_BOOT_SUCCESS_EOF
chmod 0755 /usr/libexec/noid-mark-hostonly-boot-success
chown root:root /usr/libexec/noid-mark-hostonly-boot-success

mkdir -p /usr/lib/systemd/user /usr/lib/systemd/user/noid-user-firstrun.service.wants
cat > /usr/lib/systemd/user/noid-hostonly-boot-success.service <<'HOSTONLY_BOOT_SUCCESS_SERVICE_EOF'
[Unit]
Description=NoID Privacy mark planned host-only trial ready after successful first login
Documentation=file:///usr/share/doc/noid-privacy/21-kernel-module-blacklist.md
Requires=noid-user-firstrun.service
After=noid-user-firstrun.service
# Pulled by noid-user-firstrun.service (the .wants symlink below), NOT by
# graphical-session.target: a target-wanted unit that is also ordered After
# that target — here transitively, since noid-user-firstrun.service is itself
# After=graphical-session.target — forms an ordering cycle that systemd breaks
# by deleting this unit's job, leaving the trial unable to terminalize.
ConditionKernelCommandLine=!rd.live.image
ConditionEnvironment=XDG_SESSION_CLASS=user
ConditionPathExists=/run/noid-privacy/hostonly-boot-success-needed

[Service]
Type=oneshot
ExecStart=/usr/libexec/noid-mark-hostonly-boot-success
RemainAfterExit=yes
TimeoutStartSec=30s
UMask=0077
RestrictAddressFamilies=AF_UNIX
LockPersonality=yes
SystemCallArchitectures=native
# In a per-user manager, filesystem namespace settings such as
# ProtectSystem, ProtectHome and PrivateTmp implicitly enable PrivateUsers.
# That maps the root-owned request to nobody and prevents Fedora's deliberately
# SUID boot-flag helper from entering the host user namespace. Match Fedora's
# grub-boot-success.service boundary: no filesystem/user namespace here, while
# retaining the non-namespace restrictions above and the fixed ExecStart.
PrivateUsers=no
# The sole ExecStart intentionally uses Fedora's reviewed SUID boot-flag helper.
NoNewPrivileges=no

[Install]
WantedBy=noid-user-firstrun.service
HOSTONLY_BOOT_SUCCESS_SERVICE_EOF
chmod 0644 /usr/lib/systemd/user/noid-hostonly-boot-success.service
chown root:root /usr/lib/systemd/user/noid-hostonly-boot-success.service

cat > /usr/lib/systemd/user/noid-hostonly-boot-success.path <<'HOSTONLY_BOOT_SUCCESS_PATH_EOF'
[Unit]
Description=Watch for the NoID Privacy host-only trial readiness request
Documentation=file:///usr/share/doc/noid-privacy/21-kernel-module-blacklist.md
ConditionKernelCommandLine=!rd.live.image
ConditionEnvironment=XDG_SESSION_CLASS=user

[Path]
# Covers both orderings: a request already present at first login and one
# published later by the low-priority system service.
PathExists=/run/noid-privacy/hostonly-boot-success-needed
Unit=noid-hostonly-boot-success.service

[Install]
WantedBy=noid-user-firstrun.service
HOSTONLY_BOOT_SUCCESS_PATH_EOF
chmod 0644 /usr/lib/systemd/user/noid-hostonly-boot-success.path
chown root:root /usr/lib/systemd/user/noid-hostonly-boot-success.path

ln -sf /usr/lib/systemd/user/noid-hostonly-boot-success.service \
    /usr/lib/systemd/user/noid-user-firstrun.service.wants/noid-hostonly-boot-success.service
ln -sf /usr/lib/systemd/user/noid-hostonly-boot-success.path \
    /usr/lib/systemd/user/noid-user-firstrun.service.wants/noid-hostonly-boot-success.path
log "  [OK] race-free first-login boot-success bridge deployed without forced GRUB menu"

# ====================================================================
# STEP 2e: Force initramfs rebuild AFTER the dracut-conf writes
# ====================================================================
# LOAD-BEARING: the kernel-core %posttrans trigger (kernel-install ->
# dracut) fires BEFORE this %post runs, so the initramfs is already built
# WITHOUT the drop-ins above — and Anaconda does not regenerate it at
# end-of-install. Compose-time output is explicitly generic for Live/installer
# portability. The enabled firstboot service changes only the installed target
# to host-only before multi-user.target, then verifies the result.

log "STEP 2e: regenerating and verifying generic Live/installer initramfs"
if ! command -v dracut >/dev/null 2>&1; then
    log "  [FAIL] dracut binary not found — load-bearing initramfs policy cannot be applied"
    exit 1
fi
if ! command -v lsinitrd >/dev/null 2>&1; then
    log "  [FAIL] lsinitrd binary not found — rebuilt initramfs cannot be verified"
    exit 1
fi
DRACUT_LOG=$(mktemp /var/tmp/noid-m21-dracut.XXXXXX)
if ! dracut --force --regenerate-all --no-hostonly >"$DRACUT_LOG" 2>&1; then
    tail -n 20 "$DRACUT_LOG" || true
    rm -f "$DRACUT_LOG"
    log "  [FAIL] dracut --force --regenerate-all failed"
    exit 1
fi
tail -n 3 "$DRACUT_LOG" || true
rm -f "$DRACUT_LOG"

checked_initramfs=0
for initramfs in /boot/initramfs-*.img; do
    [ -f "$initramfs" ] || continue
    case "${initramfs##*/}" in initramfs-0-rescue-*) continue ;; esac
    kernel=${initramfs##*/initramfs-}
    kernel=${kernel%.img}
    case "$kernel" in
        ''|*[!A-Za-z0-9._+-]*)
            log "  [FAIL] invalid kernel identity derived from $initramfs"
            exit 1
            ;;
    esac
    checked_initramfs=$((checked_initramfs + 1))
    manifest=$(mktemp /var/tmp/noid-m21-lsinitrd.XXXXXX)
    modules=$(mktemp /var/tmp/noid-m21-modules.XXXXXX)
    if ! lsinitrd "$initramfs" >"$manifest" 2>&1 || \
       ! lsinitrd -m "$initramfs" >"$modules" 2>&1; then
        tail -n 20 "$manifest" || true
        rm -f -- "$manifest" "$modules"
        log "  [FAIL] lsinitrd could not inspect $initramfs"
        exit 1
    fi
    if ! grep -q 'etc/modprobe.d/noid-security-blacklist.conf' "$manifest" || \
       ! cmp -s "$BLACKLIST_CONFIG" \
            <(lsinitrd -f etc/modprobe.d/noid-security-blacklist.conf \
                "$initramfs" 2>/dev/null); then
        rm -f -- "$manifest" "$modules"
        log "  [FAIL] exact blacklist policy bytes missing from $initramfs"
        exit 1
    fi
    if grep -q 'etc/noid-privacy/initramfs-hostonly' "$manifest"; then
        rm -f -- "$manifest" "$modules"
        log "  [FAIL] installed-system host-only marker leaked into Live/installer image"
        exit 1
    fi
    if grep -Eq '/firewire-(core|net|ohci|sbp2)\.ko(\.(xz|zst|gz))?$' "$manifest"; then
        rm -f -- "$manifest" "$modules"
        log "  [FAIL] omitted FireWire kernel object remains in $initramfs"
        exit 1
    fi
    for required in mei_me mei_gsc_proxy; do
        module_path=$(modinfo -k "$kernel" -n "$required" 2>/dev/null || true)
        if [ -z "$module_path" ] || [ "$module_path" = '(builtin)' ]; then
            rm -f -- "$manifest" "$modules"
            log "  [FAIL] cannot resolve Intel GSC dependency for $kernel: $required"
            exit 1
        fi
        module_path=$(readlink -f "$module_path")
        module_rel=${module_path#/}
        if [ ! -f "$module_path" ] || ! cmp -s "$module_path" \
                <(lsinitrd -f "$module_rel" "$initramfs" 2>/dev/null); then
            rm -f -- "$manifest" "$modules"
            log "  [FAIL] exact Intel GSC dependency bytes missing from $initramfs: $required"
            exit 1
        fi
    done
    rm -f -- "$manifest" "$modules"
done
if [ "$checked_initramfs" -eq 0 ]; then
    log "  [FAIL] no rebuilt initramfs image was available for verification"
    exit 1
fi
log "  [OK] generic rebuild + ${checked_initramfs} Live/installer image postcondition(s) verified"

# ====================================================================
# STEP 3: User documentation with opt-in hardening
# ====================================================================
log "STEP 3: writing /usr/share/doc/noid-privacy/21-kernel-module-blacklist.md"

mkdir -p /usr/share/doc/noid-privacy

cat > /usr/share/doc/noid-privacy/21-kernel-module-blacklist.md <<'DOC_EOF'
# Kernel Module Blacklist — NoID Privacy

## What This Does

The canonical policy inventory contains 134 normalized module identities:

- 53 `deny-loadable`: currently shipped as canonical loadable modules and
  enforced with both `blacklist` and `install /bin/false`
- 8 `unaffected-builtin`: present in the kernel, but outside modprobe policy
- 43 `unaffected-absent`: not shipped by the target kernel
- 2 `alias-denied-via-target`: historical names resolving to denied targets
- 28 `supported`: deliberately retained hardware or filesystem support

The inventory is `/usr/share/noid-privacy/kernel-module-policy.tsv`; the
generated effective policy is
`/etc/modprobe.d/noid-security-blacklist.conf`. The build validates every
installed kernel tree with `modinfo`, then checks each deny through effective
`modprobe --dry-run --verbose` resolution. It fails if a loadable, built-in,
absent or alias classification has drifted, the exact `/bin/false` deny is not
selected, or the target module would still be inserted. This avoids treating
duplicate spellings, absent modules, built-ins or inert text as successful
hardening.

The two modprobe directives cover ordinary automatic and explicit modprobe
resolution. They are not a security boundary against privileged root: root can
replace the local policy or invoke lower-level kernel interfaces. The policy is
embedded in every initramfs, and the four canonical FireWire drivers are also
omitted from early boot.

Every Generic and installed image also includes the signed in-tree `mei_me`
transport and `mei_gsc_proxy` object with exact target-kernel bytes. Modern
Intel i915 hardware can request that proxy while still inside the initramfs;
without the dependency closure it can wait for the real-root module tree and
hit the GSC proxy bind timeout before continuing. Dracut `add_drivers` includes
the objects but does not force-load them, so AMD, older Intel and systems that
do not expose matching devices retain normal kernel autoload behavior.

## Effective Deny Set

The 53 canonical loadable modules are:

`9p`, `affs`, `appletalk`, `atm`, `batman_adv`, `befs`, `ceph`, `cifs`,
`coda`, `ecryptfs`, `esp4`, `esp4_offload`, `esp6`, `esp6_offload`,
`firewire_core`, `firewire_net`, `firewire_ohci`, `firewire_sbp2`, `floppy`,
`gfs2`, `gnss`, `gnss_mtk`, `gnss_serial`, `gnss_sirf`, `gnss_ubx`,
`gnss_usb`, `hfs`, `hfsplus`, `jffs2`, `jfs`, `kafs`, `l2tp_eth`,
`l2tp_netlink`, `l2tp_ppp`, `minix`, `n_hdlc`, `nfs`, `nfsv3`, `nfsv4`,
`nilfs2`, `ocfs2`, `orangefs`, `psnap`, `rds`, `rndis_host`, `romfs`,
`rxrpc`, `sctp`, `tipc`, `ubifs`, `udf`, `ufs`, `vivid`.

The primary rationale is attack-surface reduction for legacy filesystems,
unused network protocols/filesystems, GNSS, FireWire DMA, USB RNDIS and test
drivers that have no default NoID Privacy Workstation workflow. The exact state
and canonical identity are machine-readable in the TSV inventory; prose group
counts are not used as release evidence.

`ohci1394` and `sbp2` resolve to the denied canonical targets
`firewire_ohci` and `firewire_sbp2`. They do not create extra effective blocks.

`can`, `msr` and `vesafb` are built into the target Fedora kernel. They are
recorded as unaffected built-ins rather than fake modprobe successes. The
workstation does not deploy version-fragile `initcall_blacklist=` guesses. The 43
absent identities are likewise inventory, not enforcement.

AF_ALG entries are not counted or emitted: the target kernel builds that API
in, so modprobe declarations would not disable it. Kernel security updates,
not inert configuration lines, own fixes for built-in kernel code.

## NOT Blacklisted (by design)

| Module(s) | Reason |
|-----------|--------|
| bluetooth, btusb, btrtl, btbcm, btintel, btmtk | Laptops need Bluetooth — `bluetooth.service` ships OFF by default (rfkill soft-block + flag, M08 — not masked) but modules stay loadable for users who need BT. See opt-in below for full module-level block. |
| usb_storage | USBGuard (Module 14) manages USB devices per-device with allowlist policy. Module-level block is opt-in below. |
| thunderbolt | USB4 docks and eGPU enclosures need this module. NoID Privacy enables strict IOMMU/early-DMA protection; the domain authorization level is firmware/kernel-owned and must be verified as `user` or `secure` on the actual device because the image cannot force it. NoID Privacy does not install `boltd`: with an active IOMMU, upstream boltd can auto-enroll/authorize unknown devices under its IOMMU policy. USB/DisplayPort functions are separate from tunneled PCIe functions. Module-level block is opt-in below. |
| xe | Intel Arc discrete GPU driver (generic image supports Intel Arc hardware). |
| uvcvideo | USB webcam access — generic image accommodates webcam users. |
| nouveau | Default in-tree NVIDIA GPU driver (see `19-nvidia-drivers.md`). |
| mei, mei_me, mei_hdcp, mei_pxp, mei_wdt | Intel Management Engine modules owned by **Module 15** (supported fwupd platform-security attributes depend on compatible hardware and firmware; the achieved HSI result is platform- and runtime-dependent — see Modules 15/24). `mei` + `mei_me` stay loadable for that inspection. `mei_hdcp` + `mei_pxp` + `mei_wdt` also remain loadable by default: blocking can disrupt hardware-dependent protected-media, graphics, or watchdog paths, while closing only narrow host-client surfaces. Opt-in block: `noid-mei-restore-submodules --block hdcp\|pxp\|wdt`. Cross-reference Module 15 for the exact trade-offs. |
| binfmt_misc | The module is not misrepresented as blacklisted. Automatic filesystem activation and handler registration are disabled by exact `/dev/null` masks for `proc-sys-fs-binfmt_misc.automount` and `systemd-binfmt.service`. This intentionally disables Wine/foreign-binary auto-dispatch and cross-architecture container handlers until the user opts in. |
| sr_mod, cdrom | USB-connected optical drives remain supported for installers and ISO9660 media. The UDF filesystem module is denied by default, so UDF-only DVD/Blu-ray data media do not mount unless that policy is reviewed and changed. Module-level drive block is opt-in below. |
| joydev | USB joystick / gamepad support. Gaming users need this — generic image keeps support. Module-level block is opt-in below. |
| ntfs, ntfs3, f2fs, erofs | Modern, actively-maintained filesystems commonly found on USB sticks, SD cards, and cross-OS media. Generic image keeps read support to avoid breaking removable media. |

## Initramfs and Storage Topology

The Live/installer initramfs is explicitly generated with `--no-hostonly` so
it remains portable. NoID Privacy Workstation does **not** ship a global
`omit_dracutmodules` rule for `mdraid`, `iscsi`, `fcoe` or `nbd`.

On the first installed boot,
`noid-dracut-hostonly-firstboot.timer` schedules
`noid-dracut-hostonly-firstboot.service` one second after timer activation.
The timer, rather than the long oneshot, is enabled in `multi-user.target`;
therefore Dracut generation and validation do not hold the graphical login
target. The oneshot runs at low CPU, I/O and process priority so interactive
first-session work wins resource contention. It is ordered after and requires
successful `noid-snapper-init.service`. On a Btrfs root, that means the default-
subvolume, fstab and rootflags-free normal BLS contract are final before
candidate generation or Generic recovery publication. On an ext4, XFS or other
non-Btrfs root, Module 20 exits successfully as explicitly not applicable and
M21 continues with its `other-hostonly` topology class. Module 20 in turn
requires successful completion of Module 01's hardware-specific cmdline
reconciliation, closing the ordered M01 cmdline → M20 applicability/Btrfs-BLS
→ M21 initramfs chain.
It writes `/etc/dracut.conf.d/99-noid-hostonly.conf` and builds the running
kernel's candidate under a private `/var/tmp` staging directory. Internally,
the service invokes Dracut with `--force --hostonly --hostonly-mode sloppy
--no-hostonly-cmdline` against that staged candidate. This describes the
implementation; it is not an operator command. Use the first-boot service for
initial convergence and `/usr/libexec/noid-dracut-regenerate-all` for every
supported later rebuild.

Before publishing, it verifies the embedded policy marker, module deny file,
root-critical Dracut modules, the Fedora systemd-cryptsetup path plus loadable
dm-crypt/DRBG objects on an encrypted root, M32's Plymouth configuration, bgrt
theme and watermark, every loadable driver found along each root-disk device
path, the FireWire omit, and enough `/boot` space for both new images
plus 64 MiB headroom. On the expected single-device LUKS2+Btrfs layout it also
requires `mdraid`, `iscsi`, `fcoe` and `nbd` to be absent. On a topology that
actually needs one of those stacks, host-only Dracut may include it.

A live root-path owner that has no target-kernel `modinfo` object is accepted
without an initramfs object only when its kernel-owned `/sys/module` directory
lacks the dynamic-module `initstate` attribute. This covers integrated PCIe
port drivers such as `pcieportdrv` without weakening the object check for NVMe,
AHCI, virtio or any other loadable controller.

The existing Generic image is not discarded. Publication first copies it to a
separate fallback image, fsynchronizes the image and its
`Generic Initramfs Recovery` BLS entry, and makes that entry GRUB's persistent
saved default. Only then does it atomically publish the validated candidate at
the standard path, record durable `pending-reboot` state and select the normal
entry through GRUB `next_entry` for exactly one trial boot. Every file,
GRUB-environment and `/boot` transition is explicitly synchronized. An
interruption is reconciled to Generic and recorded as `recovered-generic`.
Recovery first retires any armed one-shot entry while the saved Generic image
is still intact, atomically copies Generic back to the standard image path,
switches the saved default only after both paths are bootable, and removes the
temporary fallback last. State, policy and boot renames synchronize both their
files and parent-directory metadata. If power fails after that copy but before
the terminal state rename, the next boot accepts only the booted standard image
that passes the complete Generic byte checks, then finishes `recovered-generic`.

The normal trial does not force a visible boot menu. During the same installed
boot, M21 publishes a root-owned ephemeral request under `/run`.
`noid-hostonly-boot-success.path` watches for that request in the real
graphical user's manager, covering both request-before-login and
request-after-login orderings. Only after the transactional
`noid-user-firstrun.service` succeeds does the triggered
`noid-hostonly-boot-success.service` call Fedora's narrowly scoped
`grub2-set-bootflag boot_success`. The planned `next_entry` therefore boots
silently. Fedora resets `boot_success` as that trial starts, so this does not
claim the candidate itself healthy.

The user bridge deliberately follows Fedora's own boot-success unit boundary:
it does not enable `ProtectSystem`, `ProtectHome`, `PrivateTmp` or another
filesystem namespace setting. In a per-user systemd manager those settings
implicitly enable `PrivateUsers`, map the root-owned request to `nobody`, and
prevent the reviewed SUID helper from reaching host root. The bridge retains
address-family, personality, architecture and umask restrictions, with one
fixed executable and argument.

Bootability is **not** claimed from `lsinitrd`. On the next reboot, the gate is
the target kernel reaching the real-root M21 service and passing the complete
image validation; only then does the service restore the normal saved default,
set `phase=complete` and retire the Generic fallback. This proves the
initramfs, root-storage and unlock path, not the later graphical session. If
the candidate cannot reach that service, the boot loader cannot reset a hung
kernel itself; after the user or hypervisor restarts the machine, the consumed
one-shot selection leaves `Generic Initramfs Recovery` as the automatic
default. That entry adds `noid.initramfs=generic-fallback`; its boot causes the
service to restore Generic as the standard image and record
`phase=recovered-generic`. A failure after M21 has completed belongs to the
ordinary real-root/userspace recovery boundary (including Snapper), not to
initramfs fallback. The user can also press Esc during firmware startup to
request the boot menu manually.

Every supported NoID Privacy writer of initramfs, BLS or GRUB one-shot state
uses `/run/lock/noid-boot-mutation.lock` and then executes
`noid-boot-mutation-guard`. The guard permits exactly two stable bases:
`phase=complete` with the confirmed host-only marker in the running image, or
`phase=recovered-generic` after Generic has been restored to the normal image
path and every temporary recovery/publication artifact has been retired. It
refuses pending/retry states, a live Generic fallback entry, a GRUB
`next_entry`, malformed state, or policy-byte drift. Thus recovery does not
permanently lock out later maintenance, but no writer can reinterpret an active
M21 transaction as complete.

Module 20's checked Snapper rollback takes that same lock before selecting a
different Btrfs default. Because `/boot` is outside the root snapshot, a
persistent pending record or a published default that has not booted blocks
all later boot writers. Only `noid-snap-rollback --resume` may request the
guard's narrow resume mode while it owns the shared lock; after the selected
root is active, the ordinary no-argument guard becomes available again.

`noid-dracut-regenerate-all` is the supported later rebuild path. It takes the
same lock, evaluates that guard, builds each installed image at a same-filesystem
candidate path, and explicitly forces `--no-hostonly` for a recovered Generic
basis or sloppy host-only without embedded host cmdline for the confirmed
host-only basis. It then applies the same boot-critical checks to that basis:
Root/Btrfs/LUKS modules and objects, every live
root-controller driver, Plymouth payload, FireWire omission, the security and
MEI artifacts, exact Intel GSC transport/proxy objects, topology-specific
storage exclusions and any managed NVIDIA
module/certificate set. Ownership, mode and SELinux context are finalized on
the candidate before its atomic publication. When such an NVIDIA image has an
M19 `ready` or `prepared` pre-reboot record, M21 then invokes M19's exact
root-owned evidence bridge; it re-verifies the current driver identity and
atomically binds that record to the new published initramfs hash. Historical
`active` evidence remains an immutable account of the image that actually
booted. A later invocation safely retires
an unreferenced candidate left by power loss; every BLS image path itself still
points to either its old complete image or its new inspected image.

Root-run writers pass an inherited locked descriptor. The two maintained
interactive user orchestrators (the NVIDIA helper and Update All) hold the
shared lock on descriptor 7 and invoke the privileged regenerator through
`sudo -C 8 --lock-held=7`. An exact command-scoped sudoers default permits only
that canonical helper to preserve descriptors below 8. Because parent and
child retain the same open file description, the kernel lease remains held if
the interactive parent dies during the privileged rebuild; there is no
unlock/relock window or stale process-claim record.

This lock is a coordination contract for maintained NoID Privacy tooling, not a
kernel-enforced global lease on `/boot`. An arbitrary root command, foreign RPM
script or third-party kernel hook can bypass it. M21's transition runs before
normal login, minimizing that external window; do not claim serialization for
unmanaged root/package-manager activity.

This transition also preserves the shutdown-hang fix on the first installed
boot: Fedora's `dracut-shutdown.service` restores `/run/initramfs` from the
current on-disk standard image at shutdown, after the service has published the
host-only candidate. Therefore the simple-root shutdown image has no mdraid
cleanup hook and does not enter the `waiting for mdraid devices to be clean`
path.

Inspect the evidence:

```bash
sudo systemctl status noid-dracut-hostonly-firstboot.service
sudo cat /var/lib/noid-privacy/dracut-hostonly.state
sudo ls /boot/loader/entries/noid-generic-fallback-*.conf
sudo lsinitrd -m "/boot/initramfs-$(uname -r).img"
sudo lsinitrd "/boot/initramfs-$(uname -r).img" \
  etc/noid-privacy/initramfs-hostonly
```

`phase=pending-reboot` is expected until the candidate has actually booted.
After a fallback recovery and root-cause review, retry the guarded transition:

```bash
sudo /usr/libexec/noid-dracut-hostonly-configure --retry
```

For a later intentional root-storage migration, make the new storage available
first and follow the storage vendor's migration procedure before regenerating
host-only images. Keep the NoID Privacy Live ISO available as the
hardware-generic external recovery path.

## Enabling binfmt_misc (Opt-In)

Wine automatic executable dispatch and foreign-architecture container
handlers require binfmt registration. Enable the native Fedora path explicitly:

```bash
sudo systemctl unmask proc-sys-fs-binfmt_misc.automount systemd-binfmt.service
sudo systemctl start proc-sys-fs-binfmt_misc.automount systemd-binfmt.service
```

Return to the default-disabled state:

```bash
sudo systemctl stop systemd-binfmt.service proc-sys-fs-binfmt_misc.automount
sudo systemctl mask proc-sys-fs-binfmt_misc.automount systemd-binfmt.service
```

## Enabling Bluetooth (OFF by default)

Bluetooth ships **OFF by default** via an rfkill soft-block + a flag-file
+ a udev enforcer (Module 08) — the service is **not masked**, but the
radio is blocked so no device can pair or connect. The kernel modules
stay loadable.

If you need Bluetooth (wireless headphones, keyboard, mouse), turn it on
with the toggle (clears the rfkill block + flag and starts the service):

```bash
sudo noid-toggle-bluetooth on
```

Verify the stack is up:

```bash
sudo noid-toggle-bluetooth status        # expected: ENABLED
systemctl is-active bluetooth.service    # expected: active
```

The toggle removes NoID Privacy's default rfkill and WirePlumber blocks.
GNOME Settings can then power a present controller and pair devices. No reboot
is needed.

Return to the complete default-disabled state:

```bash
sudo noid-toggle-bluetooth off
sudo noid-toggle-bluetooth status        # expected: FULLY DISABLED
```

## Re-enabling a Module

To re-enable a specific module (e.g., `cifs` for NAS access):

```bash
# 1. Comment out both lines in the blacklist config
sudo sed -i '/^blacklist cifs$/s/^/#/' /etc/modprobe.d/noid-security-blacklist.conf
sudo sed -i '/^install cifs \/bin\/false$/s/^/#/' /etc/modprobe.d/noid-security-blacklist.conf

# 2. Rebuild and verify every host-only initramfs
sudo /usr/libexec/noid-dracut-regenerate-all

# 3. Load the module immediately (or reboot)
sudo modprobe cifs
```

To re-enable the NFS and SMB/CIFS client modules:

```bash
for mod in cifs nfs nfsv3 nfsv4; do
    sudo sed -i "/^blacklist ${mod}$/s/^/#/" /etc/modprobe.d/noid-security-blacklist.conf
    sudo sed -i "/^install ${mod} \/bin\/false$/s/^/#/" /etc/modprobe.d/noid-security-blacklist.conf
done
sudo /usr/libexec/noid-dracut-regenerate-all
```

## Optional: Extra Hardening (Opt-In)

These modules are NOT blacklisted by default because they break common
hardware. Apply only if you know your hardware does not need them. Append each
named block at most once; if its start marker already exists, do not append it
again.

### Bluetooth (Desktop without BT hardware)

```bash
sudo tee -a /etc/modprobe.d/noid-security-blacklist.conf >/dev/null <<'EOF'

# --- Optional: Bluetooth (added manually) ---
blacklist bluetooth
install bluetooth /bin/false
blacklist btusb
install btusb /bin/false
blacklist btrtl
install btrtl /bin/false
blacklist btbcm
install btbcm /bin/false
blacklist btintel
install btintel /bin/false
blacklist btmtk
install btmtk /bin/false
# --- End optional: Bluetooth ---
EOF
sudo /usr/libexec/noid-dracut-regenerate-all
```

### USB Mass Storage (if USBGuard alone is insufficient)

```bash
sudo tee -a /etc/modprobe.d/noid-security-blacklist.conf >/dev/null <<'EOF'

# --- Optional: USB Storage (added manually) ---
blacklist usb_storage
install usb_storage /bin/false
# --- End optional: USB Storage ---
EOF
sudo /usr/libexec/noid-dracut-regenerate-all
```

### Thunderbolt / USB4 (Desktop without TB hardware)

```bash
sudo tee -a /etc/modprobe.d/noid-security-blacklist.conf >/dev/null <<'EOF'

# --- Optional: Thunderbolt DMA (added manually) ---
blacklist thunderbolt
install thunderbolt /bin/false
# --- End optional: Thunderbolt DMA ---
EOF
sudo /usr/libexec/noid-dracut-regenerate-all
```

### Optical Media (Desktop without CD/DVD/Blu-ray drive)

```bash
sudo tee -a /etc/modprobe.d/noid-security-blacklist.conf >/dev/null <<'EOF'

# --- Optional: Optical media (added manually) ---
blacklist sr_mod
install sr_mod /bin/false
blacklist cdrom
install cdrom /bin/false
# --- End optional: Optical media ---
EOF
sudo /usr/libexec/noid-dracut-regenerate-all
```

Note: This also disables USB-connected DVD drives. Do not apply if you still
install OS images from physical optical media.

### Gamepad / Joystick — optional block (for setups that never use controllers)

```bash
sudo tee -a /etc/modprobe.d/noid-security-blacklist.conf >/dev/null <<'EOF'

# --- Optional: Joydev (added manually) ---
blacklist joydev
install joydev /bin/false
# --- End optional: Joydev ---
EOF
sudo /usr/libexec/noid-dracut-regenerate-all
```

Note: Only affects joystick-class input via `/dev/input/jsX`. Controllers
that also register as a generic HID/gamepad still work via the normal
evdev path used by Steam Input, SDL2, and modern games.

To undo an optional block, use
`sudoedit /etc/modprobe.d/noid-security-blacklist.conf` to remove the complete
start-to-end marker block, then run the guarded regenerator again and reboot or
load the required module explicitly. After removing the Bluetooth block, use
`sudo noid-toggle-bluetooth on` when Bluetooth is wanted.

## Advanced: Disable Module Loading After Boot (ANSSI R10 Opt-In)

ANSSI-BP-028 v2.0 recommendation R10 covers locking dynamic module changes
after all required modules have loaded:

```bash
# WARNING: module loading and unloading are locked until reboot.
sudo sysctl -w kernel.modules_disabled=1
```

This is irreversible until reboot: no further module can be loaded and an
already loaded module cannot be unloaded. Hot-plugged hardware still works
when its driver is built in or already loaded; hardware needing another module
does not. Use this only after inspecting the required module set and accepting
the resulting hot-plug and maintenance limits.

## References

- Linux kernel: [module-signing facility](https://docs.kernel.org/admin-guide/module-signing.html)
- Linux kernel: [USB4 and Thunderbolt security/IOMMU model](https://docs.kernel.org/admin-guide/thunderbolt.html)
- Linux kernel: [binfmt_misc interface](https://docs.kernel.org/admin-guide/binfmt-misc.html)
- kmod upstream: [modprobe.d policy semantics](https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git/tree/man/modprobe.d.5.scd)
- Dracut upstream: [dracut.conf driver and host-only semantics](https://dracut-ng.github.io/dracut/man/dracut.conf.5.html)
- Dracut upstream: [shutdown-initramfs lifecycle](https://dracut-ng.github.io/dracut.html)
- GNU Coreutils: [`sync` persistence semantics](https://www.gnu.org/software/coreutils/manual/html_node/sync-invocation.html)
- ANSSI: [GNU/Linux configuration recommendations](https://messervices.cyber.gouv.fr/guides/recommandations-de-securite-relatives-un-systeme-gnulinux)
DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/21-kernel-module-blacklist.md
log "  [OK] documentation written"

# ====================================================================
# STEP 4: SELinux context restore
# ====================================================================
log "STEP 4: SELinux context restore"
command -v restorecon >/dev/null 2>&1 \
    || { log "  [FAIL] restorecon is unavailable"; exit 1; }
restorecon -F "$POLICY_MANIFEST" "$BLACKLIST_CONFIG" \
    /etc/dracut.conf.d/noid-security-blacklist.conf \
    /etc/dracut.conf.d/98-noid-intel-gsc.conf \
    /etc/dracut.conf.d/99-omit-firewire.conf \
    /usr/libexec/noid-boot-mutation-guard \
    /usr/libexec/noid-dracut-regenerate-all \
    /usr/libexec/noid-dracut-hostonly-configure \
    /usr/libexec/noid-mark-hostonly-boot-success \
    /usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf \
    /etc/sudoers.d/90-noid-boot-mutation-fd \
    /etc/systemd/system/noid-dracut-hostonly-firstboot.service \
    /etc/systemd/system/noid-dracut-hostonly-firstboot.timer \
    /usr/lib/systemd/user/noid-hostonly-boot-success.service \
    /usr/lib/systemd/user/noid-hostonly-boot-success.path \
    /usr/lib/systemd/user/noid-user-firstrun.service.wants/noid-hostonly-boot-success.service \
    /usr/lib/systemd/user/noid-user-firstrun.service.wants/noid-hostonly-boot-success.path \
    /usr/share/doc/noid-privacy/21-kernel-module-blacklist.md \
    || { log "  [FAIL] final policy SELinux reconciliation failed"; exit 1; }
log "  [OK] restorecon complete"

# ====================================================================
# STEP 5: Verification
# ====================================================================
log "STEP 5: verification"

verify_ok=0
verify_fail=0

# 5.1 — Exact manifest and generated-config equivalence
if [ -f "$POLICY_MANIFEST" ] && [ -f "$BLACKLIST_CONFIG" ] && \
   [ "$policy_rows" -eq "$EXPECTED_POLICY_ROWS" ] && \
   [ "$actual_bl" -eq "$EXPECTED_DENY_COUNT" ] && \
   [ "$actual_inst" -eq "$EXPECTED_DENY_COUNT" ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] exact normalized policy and ${EXPECTED_DENY_COUNT}+${EXPECTED_DENY_COUNT} effective directives"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] normalized policy/config cardinality mismatch"
fi

# Check every row, not a hand-selected spot list. Only deny-loadable rows may
# appear in the generated config; aliases, built-ins, absent and supported rows
# must not masquerade as effective blocks.
while IFS=$'\t' read -r module state target; do
    case "$module" in ''|'#'*) continue ;; esac
    if [ "$state" = deny-loadable ]; then
        if grep -qx "blacklist $module" "$BLACKLIST_CONFIG" && \
           grep -qx "install $module /bin/false" "$BLACKLIST_CONFIG"; then
            verify_ok=$((verify_ok + 1))
        else
            verify_fail=$((verify_fail + 1))
            log "  [FAIL] deny-loadable row incomplete: $module"
        fi
    elif grep -qE "^(blacklist|install)[[:space:]]+$module([[:space:]]|$)" \
            "$BLACKLIST_CONFIG"; then
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] non-loadable/non-denied row emitted as enforcement: $module ($state)"
    else
        verify_ok=$((verify_ok + 1))
    fi
done < "$POLICY_MANIFEST"

# 5.4 — Dracut config exists
if [ -f /etc/dracut.conf.d/noid-security-blacklist.conf ]; then
    if grep -q 'install_items' /etc/dracut.conf.d/noid-security-blacklist.conf; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] dracut config present with install_items"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] dracut config missing install_items"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] /etc/dracut.conf.d/noid-security-blacklist.conf missing"
fi

# 5.4b — Dracut omit firewire
if [ -f /etc/dracut.conf.d/99-omit-firewire.conf ]; then
    if grep -qx 'omit_drivers+=" firewire_core firewire_net firewire_ohci firewire_sbp2 "' \
            /etc/dracut.conf.d/99-omit-firewire.conf; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] canonical FireWire initramfs omit is exact"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] dracut omit-firewire missing firewire drivers"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] /etc/dracut.conf.d/99-omit-firewire.conf missing"
fi

# 5.4b1 — Intel GSC dependencies are included but never force-loaded.
if [ -f /etc/dracut.conf.d/98-noid-intel-gsc.conf ] && \
   [ ! -L /etc/dracut.conf.d/98-noid-intel-gsc.conf ] && \
   [ "$(stat -c '%U:%G:%a' /etc/dracut.conf.d/98-noid-intel-gsc.conf 2>/dev/null)" = root:root:644 ] && \
   grep -qxF 'add_drivers+=" mei_me mei_gsc_proxy "' \
       /etc/dracut.conf.d/98-noid-intel-gsc.conf && \
   ! grep -q 'force_drivers' /etc/dracut.conf.d/98-noid-intel-gsc.conf; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] Intel GSC dependencies are included without forced loading"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Intel GSC Dracut dependency policy is missing or unsafe"
fi

# 5.4b2 — Live generic now; installed target converges to explicit host-only.
if [ ! -e /etc/dracut.conf.d/99-noid-omit-storage.conf ] && \
   [ ! -e /etc/dracut.conf.d/99-noid-compress.conf ] && \
   [ -x /usr/libexec/noid-boot-mutation-guard ] && \
   [ -x /usr/libexec/noid-dracut-regenerate-all ] && \
   [ -x /usr/libexec/noid-dracut-hostonly-configure ] && \
   [ -x /usr/libexec/noid-mark-hostonly-boot-success ] && \
   [ "$(stat -c '%U:%G:%a' /run/lock/noid-boot-mutation.lock 2>/dev/null)" = root:wheel:660 ] && \
   grep -qF 'f /run/lock/noid-boot-mutation.lock 0660 root wheel -' \
       /usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf && \
   [ "$(stat -c '%U:%G:%a' /etc/sudoers.d/90-noid-boot-mutation-fd 2>/dev/null)" = root:root:440 ] && \
   grep -qxF 'Defaults!/usr/libexec/noid-dracut-regenerate-all closefrom_override' \
       /etc/sudoers.d/90-noid-boot-mutation-fd && \
   visudo -cf /etc/sudoers.d/90-noid-boot-mutation-fd >/dev/null && \
   grep -qF 'recovered-generic) basis=generic' \
       /usr/libexec/noid-boot-mutation-guard && \
   grep -qF 'mv -fT -- "$candidate" "$final"' \
       /usr/libexec/noid-dracut-regenerate-all && \
   [ -f /etc/systemd/system/noid-dracut-hostonly-firstboot.service ] && \
   [ -f /etc/systemd/system/noid-dracut-hostonly-firstboot.timer ] && \
   [ -L /etc/systemd/system/multi-user.target.wants/noid-dracut-hostonly-firstboot.timer ] && \
   [ ! -e /etc/systemd/system/multi-user.target.wants/noid-dracut-hostonly-firstboot.service ] && \
   [ -f /usr/lib/systemd/user/noid-hostonly-boot-success.service ] && \
   [ -f /usr/lib/systemd/user/noid-hostonly-boot-success.path ] && \
   [ -L /usr/lib/systemd/user/noid-user-firstrun.service.wants/noid-hostonly-boot-success.service ] && \
   [ "$(readlink /usr/lib/systemd/user/noid-user-firstrun.service.wants/noid-hostonly-boot-success.service)" = /usr/lib/systemd/user/noid-hostonly-boot-success.service ] && \
   [ -L /usr/lib/systemd/user/noid-user-firstrun.service.wants/noid-hostonly-boot-success.path ] && \
   [ "$(readlink /usr/lib/systemd/user/noid-user-firstrun.service.wants/noid-hostonly-boot-success.path)" = /usr/lib/systemd/user/noid-hostonly-boot-success.path ] && \
   grep -q -- '--hostonly-mode sloppy' /usr/libexec/noid-dracut-hostonly-configure && \
   grep -qF 'FALLBACK_BLS=/boot/loader/entries/noid-generic-fallback-$kernel.conf' \
       /usr/libexec/noid-dracut-hostonly-configure && \
   grep -qF 'write_state pending-reboot' /usr/libexec/noid-dracut-hostonly-configure && \
   grep -qF 'set_saved_entry "$FALLBACK_BLS_ID"' \
       /usr/libexec/noid-dracut-hostonly-configure && \
   grep -qF 'set_next_entry "$SOURCE_BLS_ID"' \
       /usr/libexec/noid-dracut-hostonly-configure && \
   grep -qF 'BOOT_SUCCESS_REQUEST=/run/noid-privacy/hostonly-boot-success-needed' \
       /usr/libexec/noid-dracut-hostonly-configure && \
   ! grep -qF 'grub2-set-bootflag menu_show_once' \
       /usr/libexec/noid-dracut-hostonly-configure && \
   grep -qxF 'ExecStart=/usr/libexec/noid-mark-hostonly-boot-success' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service && \
   grep -qxF 'ConditionPathExists=/run/noid-privacy/hostonly-boot-success-needed' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service && \
   grep -qxF 'PathExists=/run/noid-privacy/hostonly-boot-success-needed' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.path && \
   grep -qxF 'Unit=noid-hostonly-boot-success.service' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.path && \
   grep -qxF 'RemainAfterExit=yes' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service && \
   grep -qxF 'PrivateUsers=no' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service && \
   ! grep -Eq '^(ProtectSystem|ProtectHome|PrivateTmp)=' \
       /usr/lib/systemd/user/noid-hostonly-boot-success.service && \
   grep -qF 'restore_generic "$kernel"' /usr/libexec/noid-dracut-hostonly-configure && \
   grep -qF 'usr/share/plymouth/themes/spinner/watermark.png' \
       /usr/libexec/noid-dracut-hostonly-configure && \
   ! grep -qF 'ConditionPathExists=!/var/lib/noid-privacy/dracut-hostonly.state' \
       /etc/systemd/system/noid-dracut-hostonly-firstboot.service && \
   [ "$checked_initramfs" -gt 0 ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] generic/host-only recovery plus the shared atomic boot-mutation contract is deployed"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] generic-Live/host-only-installed Dracut artifacts are incomplete"
fi

# 5.4c — Exact native binfmt_misc activation masks; retired udev race absent.
binfmt_masks_ok=1
for unit in proc-sys-fs-binfmt_misc.automount systemd-binfmt.service; do
    [ "$(readlink "/etc/systemd/system/$unit" 2>/dev/null || true)" = /dev/null ] \
        || binfmt_masks_ok=0
done
if [ "$binfmt_masks_ok" -eq 1 ] && \
   [ ! -e /usr/lib/udev/rules.d/99-noid-binfmt-disable.rules ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] binfmt_misc automatic activation is natively masked"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] binfmt_misc masks missing or retired udev rule remains"
fi

# 5.5 — Documentation exists with non-trivial size
if [ -f /usr/share/doc/noid-privacy/21-kernel-module-blacklist.md ]; then
    doc_size=$(stat -c %s /usr/share/doc/noid-privacy/21-kernel-module-blacklist.md 2>/dev/null || echo 0)
    doc_size=${doc_size:-0}
    if [ "$doc_size" -gt 1024 ]; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] documentation ${doc_size} bytes"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] documentation too small (${doc_size} bytes)"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] documentation missing"
fi

# 5.6 — No conflict with Module 15 MEI (separate file, no overlap)
# M15 default-blacklists NONE of the MEI sub-modules —
# mei_hdcp/mei_pxp/mei_wdt all LOAD by default, with opt-in blocks owned by
# /etc/modprobe.d/noid-mei-submodules.conf. This check intentionally scans only
# M21's generated file so a valid M15 opt-in is not misreported as overlap.
if grep -q '^blacklist mei_hdcp$\|^blacklist mei_pxp$\|^blacklist mei_wdt$' \
        /etc/modprobe.d/noid-security-blacklist.conf 2>/dev/null; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] MEI sub-modules in noid-security-blacklist.conf (Module 15 owns these)"
else
    verify_ok=$((verify_ok + 1))
    log "  [OK] no MEI overlap with Module 15"
fi

# 5.7 — Cross-Module M01 prerequisite at the compose lifecycle phase.
# The current BLS belongs to the live-image build topology and intentionally is
# not treated as an end-user target. M01 proves the two real target-install
# writers here; the M01 -> M20 -> M21 service chain and pre-ship runtime parser
# make missing installed BLS enforcement fatal after installation.
if [ -f /usr/libexec/noid-verify-target-karg-payload ] && \
        [ ! -L /usr/libexec/noid-verify-target-karg-payload ] && \
        [ "$(stat -c '%U:%G:%a' /usr/libexec/noid-verify-target-karg-payload 2>/dev/null)" = root:root:755 ] && \
        /usr/libexec/noid-verify-target-karg-payload >/dev/null; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] target-install module.sig_enforce=1 payload contract verified"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] target-install module.sig_enforce=1 payload contract invalid"
fi

log "  Verification: ${verify_ok} OK, ${verify_fail} FAIL"
if [ "$verify_fail" -gt 0 ]; then
    log "=== Module 21 FAILED (${verify_fail} verification failures) ==="
    exit 1
fi

log "=== Module 21 complete ==="
%end

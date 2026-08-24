# ============================================================================
# Module 13 — AIDE File Integrity Monitoring + Welcome / Setup hub
# Status: LOCKED 2026-08-24 (v180) — refresh Codex VSIX seed.
#
# Covers:
#   - /etc/aide.conf append-block (idempotent; %config(noreplace) survives
#     rpm upgrades): SECURE rule (NORMAL + sha256 + b — derived from Fedora's
#     NORMAL so it stays a strict superset) on the canonical
#     hardening config paths · false-positive excludes (pam.d/root/grub2 dir-entries,
#     audit + journal logs, boot.log + rotations and /.snapshots subtree) ·
#     package-native root-only System.map files remain content-tracked ·
#     mutable security controls remain content-tracked even when legitimate
#     user actions produce expected drift · retention-path excludes
#     (/var/log/{aide,anaconda,ks-*.log,libvirt,tuned}) · gpg-agent lockfile
#     excludes (/root/.gnupg) · database_attrs=sha256+sha3_256 override (replaces
#     the Fedora 7-hash `H` default; NORMAL still adds sha512 → 3 unique
#     hashes per file)
#   - aide-check.service (see deviations) + aide-check.timer 07:00 ±1h,
#     installed but disabled until the user accepts an initial baseline;
#     Layer-2 GNOME popup stays opt-in. Daily scans are gated off on live media
#     and when no active baseline exists.
#   - drop-ins: exitcode.conf (SuccessExitStatus=1-7 — AIDE bitmask),
#     boot-priority.conf (Nice/IO/OOM caps +
#     TimeoutStartSec=infinity), 30-noid-wrapper.conf (ExecStart →
#     noid-aide-check.sh: external flock shared with explicit candidate review
#     + TS-named reports)
#   - aide-notify.sh (systemd-logind-verified active local graphical sessions)
#   - notifications.md + aide-schedule-override.conf user docs
#   - wait-fedora-welcome.sh shared helper (sourced by M34 before its
#     user-visible notification)
#   - noid-welcome.sh — GTK4/libadwaita setup hub (deployed python heredoc;
#     build rationale lives inline there): Critical / Updates / Hardware
#     Privacy (mic+cam+BT+location switches with live external-change
#     watches incl. pw-mon + /dev/rfkill) / Network app / App Autostart
#     picker / Optional (codecs, NVIDIA, Claude/Codex agent CLIs) / Gaming Mode /
#     Notifications / Reference / reboot row. Autostart + app-grid .desktop
#     entries launch it with GTK's maintained renderer selection.
#   - noid-{claude,codex}-install (opt-in, refuses root, downloads exact
#     versioned native artefacts, verifies release pins, never runs a remote
#     installer and never uses npm)
#   - noid-status diagnostic CLI (STATUS_EOF heredoc; safe for non-root —
#     kernel check via /lib/modules, rpmdb-WAL-immune) + noid-toggle-aide-
#     popup + noid-toggle-aide (on/off = both layers; popup-on/popup-off =
#     Layer 2 only — the Welcome switch uses the popup modes)
#   - noid-aide-baseline-review — explicit prepare/review/hash-confirmed commit
#     workflow; no compose, first-boot, timer or updater path replaces aide.db
#   - NO automatic `aide --init` or `aide --update`
#
# Deliberate deviations (do NOT re-litigate):
#   - aide-check.service omits NoNewPrivileges: it blocks the init_t→aide_t
#     SELinux domain transition (nnp_transition AVC) — aide would run in
#     init_t and fail writing /var/log/aide.
#   - aide-check.service uses CapabilityBoundingSet=~CAP_SYS_MODULE +
#     SystemCallFilter=~@module + SystemCallErrorNumber=EPERM INSTEAD of
#     ProtectKernelModules: the directive would also mask /usr/lib/modules
#     in the unit's mount namespace, hiding the kernel-module tree the
#     check must hash (the DB carries it — baselines run unsandboxed).
#     The pair preserves the load/unload block; do not "consolidate" back.
#   - Timer at 07:00, not midnight: avoids the nighttime timer cluster and
#     the logrotate race on boot.log; results land at first morning login.
#   - Both layers start OFF because no trusted baseline is shipped. After the
#     user reviews and commits a baseline, `noid-toggle-aide on` enables the
#     daily timer and optional popup.
#   - AIDE --workers=1 everywhere: 0.19.x hangs indefinitely with workers>1
#     (pure-userspace PCRE2 spin). Do not raise without upstream fix+retest.
#   - /boot/efi uses an ESP-specific rule without inode/ACL/xattr attributes;
#     excluding it would leave boot files/config outside AIDE. /.snapshots is
#     pruned because recursively indexing root snapshots is unbounded/noisy.
#   - Drop-in perms 644 so `systemctl cat` works for non-root users.
#   - No password-expiry policy; the Welcome password row is a GIS-bypass
#     safety-net pointing to the PAM-enforced Settings path.
#
# Constraint notes (keep when editing):
#   - aide.conf regex anchors are load-bearing: `$` = directory-entry-only
#     exclusion (children stay tracked), `(/.*)?$` = subtree prune. Dropping
#     an anchor silently widens or narrows coverage.
#   - The Step-1 echo count-line enumerates the append-block content
#     classes; keep it in sync with any aide.conf add in the same commit.
#   - Several earlier modules also create /usr/share/doc/noid-privacy. Keep
#     the defensive mkdir here so this module remains independently robust.
#   - M13 runs BEFORE M25: the update-all.sh cross-check is [info]-only
#     here; the authoritative check lives in 99-finalize.
#   - The notify drop-in MUST use ExecStopPost ($EXIT_STATUS is undefined
#     in ExecStartPost per systemd.exec(5)) — verify-block guards this.
#   - Module 15's MEI status contract is consumed by noid-status. The Welcome
#     UI does not carry dead status-file anchors.
#   - /var/lock is tmpfs: every flock consumer recreates the lock file.
#   - tests/13-welcome-script.sh + tests/13b-noid-status-structural.sh
#     assert against the extracted heredocs and this header's Status line.
#
# Cross-reference:
#   - M25 runs check-only AIDE evidence after updates and never replaces the
#     database. M99 verifies the uninitialized/user-owned trust boundary.
#     M20: the exact argument-free root status helper feeds the non-mutating
#     noid-status snapshot summary. M13 AIDE SECURE-tracks /etc/audit (M12).
#   - M08: exact polkit program list for privileged Bluetooth/gaming actions and the
#     noid-toggle-location gsettings helper. M17: mic/cam/location dconf keys
#     are deliberately NOT locked (gsettings toggles persist per-user).
#   - M14/M15: status files consumed read-only. M34 sources
#     wait-fedora-welcome.sh. M36: noid-network app. M29: the autostart doc
#     marks the Welcome picker as the canonical GUI path.
#   - M25 publishes ~/.local/state/noid-privacy/extension-checks after every
#     authenticated add-on marketplace check; noid-status only reads it. Since
#     M16/M35 disable every browser-owned background extension update, that
#     age IS the add-on patch latency, so the reader must stay request-free.
#     M99 verifies that both sides name the identical path.
# ============================================================================

# F44 @workstation-product-environment no longer hard-deps
# aide (demoted to weak-dep, killed by master.ks --exclude-weakdeps). Without
# explicit add here, /etc/aide.conf is missing at install time → Module 13
# Step 1 fails. Same pattern as the M08 fix for ffmpeg-free.
%packages --exclude-weakdeps
aide
%end

%post --erroronfail --log=/var/log/ks-13-aide-welcome.log

set -euo pipefail
echo "=============================================================="
echo "[Module 13] AIDE File Integrity Monitoring"
echo "=============================================================="

# ----------------------------------------------------------------------------
# Step 1: Append NoID Privacy exclusions to /etc/aide.conf
# ----------------------------------------------------------------------------
# Appends to the Fedora-default aide.conf (base rules + tracked paths + 3
# stock exclusions for grubenv/lastlog/dnf5.log). All NoID Privacy additions are
# in the AIDE_EOF block below; per-exclusion rationale lives inline there.
#
# Regex `$` anchor is CRITICAL — it matches only the exact directory entry,
# so children are still tracked by existing NORMAL/LSPP rules. Without `$`,
# the exclusion would recursively prune the subtree — SECURITY REGRESSION.
#
echo ""
echo "[Step 1] Appending NoID Privacy exclusions to /etc/aide.conf"

# Verify base file exists (should be from aide package)
if [ ! -f /etc/aide.conf ]; then
    echo "  [FAIL] /etc/aide.conf missing — aide package not installed?"
    exit 1
fi

# The large annotated block is written once. The later atomic candidate pass
# independently reconciles newly added canonical SECURE paths on an older
# installed block, so idempotence does not freeze the manifest at its first
# image version.
SECURE_PATHS=(
    /etc/modprobe.d/
    /etc/udev/rules.d
    /etc/dracut.conf.d/
    /etc/firewalld/
    /etc/NetworkManager/conf.d
    /etc/NetworkManager/dispatcher.d
    /etc/nftables
    /etc/sysctl.d/
    /etc/dconf
    /etc/dbus-1/session.d
    /etc/systemd/resolved.conf.d
    /etc/systemd/coredump.conf.d
    /etc/systemd/logind.conf.d
    /etc/systemd/system/
    /etc/systemd/system.control
    /etc/systemd/user
    =/etc/chrony.conf
    /etc/ssh/ssh_config.d
    /etc/ssh/sshd_config.d
    =/etc/security/pam_env-sudo.conf
    /etc/sudoers.d/48-noid-gnome-software-quit
    /etc/sudoers.d/90-noid-boot-mutation-fd
    =/etc/sudoers.d/91-noid-aide-status
    /etc/audit/
    /etc/usbguard/
    /etc/tmpfiles.d/
    /etc/dnf/libdnf5-plugins/actions.d
    /etc/codex
    /etc/environment.d
    /etc/wireplumber/wireplumber.conf.d
    /usr/libexec/noid-mei-kt-enforce
    /usr/libexec/noid-platform-policy-sha256
    /usr/libexec/noid-update-lock-guardian
    /usr/libexec/noid-update-window-active
    /usr/libexec/noid-boot-mutation-guard
    /usr/libexec/noid-dracut-regenerate-all
    /usr/libexec/noid-dracut-hostonly-configure
    /usr/libexec/noid-mark-hostonly-boot-success
    /usr/libexec/noid-gsk-hybrid-match
    /usr/libexec/noid-gsk-session-environment
    /usr/libexec/noid-codium-launch
    /usr/libexec/noid-vscodium-repo-key-seed
    =/usr/libexec/noid-aide-status
    /usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer
    /usr/lib/systemd/user/noid-hostonly-boot-success.path
    /usr/lib/systemd/user/noid-hostonly-boot-success.service
    /usr/lib/systemd/user/noid-gsk-session-environment.service
    /usr/lib/tmpfiles.d/noid-boot-mutation-lock.conf
    /usr/lib/tmpfiles.d/noid-identity-bls-refresh.conf
    =/usr/lib/tmpfiles.d/noid-aide-lock.conf
    /usr/local/sbin/noid-restore-identity
    /usr/local/sbin/noid-gnome-software-backend-stop
    /usr/local/sbin/noid-gnome-software-launcher-sync
    /usr/local/sbin/noid-codium-launcher-sync
    /usr/local/sbin/noid-verify-gnome-privacy-contract
    /usr/local/sbin/noid-lan-xdp
    /usr/local/sbin/noid-wireguard-mtu-reconcile
    /usr/local/bin/gnome-software
    /usr/local/bin/noid-gnome-software-quit
    /usr/local/bin/noid-gnome-software-rpm
    /usr/local/bin/noid-lan-xdp-notify
    /usr/local/bin/noid-toggle-gsk-gl
    /usr/local/bin/noid-toggle-microphone
    /usr/local/bin/noid-host-identity
    /usr/local/libexec/noid-gnome-privacy-cleanup
    /usr/local/libexec/noid-wan-strict-endpoints
    /usr/local/share/dbus-1/services
    /usr/local/share/applications
    /usr/local/share/wireplumber/scripts
    /usr/lib/noid-privacy/noid-lan-xdp.bpf.o
    =/usr/lib/noid-privacy/noid_ui.py
    /etc/xdg/autostart/noid-lan-xdp-health.desktop
    =/usr/lib/noid-privacy/aide-secure-paths.tsv
)

# These former exclusions hide integrity-relevant mutable files or security
# controls. Keep one forbidden manifest so re-running M13 removes legacy lines
# and verification fails if a broad blind spot returns.
FORBIDDEN_CONTROL_EXCLUDES=(
    '!/etc/nftables/arp-hardening\.nft$'
    '!/etc/NetworkManager/dispatcher\.d/90-arp-hardening$'
    '!/etc/systemd/system/firewalld\.service\.d/arp-hardening-firewalld-reload\.conf$'
    '!/etc/sysctl\.d/99-wan-ipv6-off\.conf$'
    '!/etc/usbguard/rules\.conf$'
    '!/etc/usbguard/IPCAccessControl\.d(/.*)?$'
    '!/etc/systemd/system\.control(/.*)?$'
    '!/usr/share/plymouth/themes/bgrt/bgrt\.plymouth$'
    '!/boot/System\.map-[^/]*$'
    '!/usr/lib/modules/[^/]+/System\.map$'
)

# The appended SECURE rule is defined as `NORMAL+sha256+b`, so Fedora's NORMAL
# group must already be defined above our block — AIDE resolves group names at
# parse time and rejects a forward reference. Fedora ships it at aide.conf:120;
# assert it rather than trusting a %config(noreplace) file that an earlier
# build step or a rebased base image could have reshaped. Failing here is a
# loud compose abort instead of an image whose daily integrity check cannot
# parse its own config.
if ! grep -qE '^[[:space:]]*NORMAL[[:space:]]*=' /etc/aide.conf; then
    echo "  [FAIL] /etc/aide.conf defines no NORMAL group — SECURE cannot derive from it" >&2
    exit 1
fi

if grep -q "^# NoID Privacy — hardening config dirs (content tracking)" /etc/aide.conf; then
    echo "  [SKIP] NoID Privacy section already present in /etc/aide.conf"
else
    cat >> /etc/aide.conf <<'AIDE_PREAMBLE_EOF'

# ============================================================================
# NoID Privacy — hardening config dirs (content tracking)
# ============================================================================
#
# Fedora default aide.conf tracks /etc with PERMS only (mode/uid/gid, no
# content hash). These subdirectories contain critical hardening config
# files from ALL Modules that MUST be content-tracked — an attacker
# modifying the file content without changing permissions would otherwise
# go undetected.
#
# Fedora's NORMAL rule is `R+sha512-m-c`, which resolves to
# l+p+u+g+s+i+n+acl+sha512+selinux+xattrs+ftype+e2fsattrs+sha3_256 — content
# hashes included, plus symlink target (l) and file type (ftype). A
# more-specific path wins over the general /etc PERMS rule.
#
# SECURE = NORMAL + sha256 + b, i.e. a strict superset of whatever NORMAL
# resolves to on the installed aide. That relationship is load-bearing, not
# cosmetic: these paths would otherwise be covered by a Fedora NORMAL rule,
# so any attribute SECURE fails to carry is an attribute the image stops
# watching. The added sha256 gives dual-hash defense-in-depth against a
# single-algorithm break; SHA-512 is currently collision-resistant, so the
# second digest is independent comparison evidence, not a claim about a
# hypothetical future break. The extra digest adds candidate/check CPU work
# and database bytes; no universal percentage is claimed without retained
# measurements.
#
# Coverage map:
#   /etc/modprobe.d              — MEI sub-module blacklist (Module 15)
#                                  + future kernel module blacklists (Module 21)
#   /etc/udev/rules.d            — KT/SOL PCI driver_override block (Module 15)
#                                  + UDisks USB/SD noexec/NTFS policy (Module 27)
#   /etc/dracut.conf.d           — initramfs blacklist enforcement (Module 15)
#                                  + NVIDIA dracut config (Module 19 conditional)
#   /etc/firewalld               — firewalld.conf + policies/block-lan-out.xml
#                                  (Module 03 — CRITICAL drop-all policy)
#   /etc/NetworkManager/conf.d   — VPN zone enforce + ignore-auto-dns
#                                  (Module 03/05 — VPN + DNS integrity)
#   /etc/sysctl.d                — 99-hardening.conf (Module 02)
#                                  + 99-audit-fixes + 99-userns (Module 02)
#                                  + 98-privacy-network (Module 07, 1 param:
#                                  ip_forward; TCP timestamps retain the
#                                  randomized maintained kernel default)
#                                  + 99-wan-ipv6-off.conf (runtime writer;
#                                  later changes remain visible evidence)
#   /etc/dconf                   — gnome-software lockdown (Module 08)
#                                  + native GVfs discovery policy (Module 05)
#                                  + gnome-privacy 31 keys (Module 17)
#                                  + locks/ (Modules 05+08+17)
#   /etc/systemd/resolved.conf.d — Quad9 + DoT + DNSSEC (Module 05)
#   /etc/systemd/coredump.conf.d — coredump block layer 2 (Module 08)
#   /etc/systemd/logind.conf.d   — session lock + IPC cleanup (Module 10)
#   /etc/systemd/system          — unit hardening drop-ins (Module 08, 7 files)
#                                  + custom noid-* services (all Modules)
#                                  + runtime ARP reload drop-in
#   /etc/chrony.conf             — NTS-only config (Module 11)
#   /etc/ssh/ssh_config.d        — SSH client crypto whitelist (Module 09)
#   /etc/ssh/sshd_config.d       — dormant secure-default server policy (M09)
#   /etc/audit                   — auditd.conf + 99-hardening.rules (Module 12)
#   /etc/usbguard              — daemon config, device policy and per-user IPC
#                                grants (runtime changes remain visible evidence)
#   /etc/nftables              — generated ARP policy
#   /etc/NetworkManager/dispatcher.d — generated ARP dispatcher
#   /etc/systemd/system.control — persistent systemd enable/disable state
#   /etc/dnf/libdnf5-plugins/actions.d — package-scoped local reconciliation
#                                  hooks (permissions, identity and app overlays)
#   /etc/codex                   — Codex CLI/IDE system defaults (Module 08)
#   /etc/wireplumber/wireplumber.conf.d — persistent audio privacy policy
#   /usr/local/share/dbus-1/services — native session-bus activation denials
#                                  (Module 17; RPM-owned /usr/share stays pristine)
#   /usr/local/share/applications — admin launcher overlays that preserve
#                                  deliberate launch without bus autoactivation
#   /usr/local/share/wireplumber/scripts + noid-toggle-microphone
#                                  — actual capture-source enforcement + control

# SECURE rule definition. Derived from Fedora's own NORMAL group so the
# superset property holds by construction and cannot drift: every path
# carrying a SECURE rule below would otherwise fall back to a Fedora NORMAL
# rule, so SECURE must never resolve to fewer attributes than NORMAL does.
#
# Spelling the attribute list out by hand is what broke this before: the
# hand-written set omitted l, i, ftype, selinux, e2fsattrs and sha3_256, so
# the "upgrade" was a net attribute REDUCTION on every SECURE path. Losing l
# is exploitable — symlinks carry no hashsum, so repointing e.g.
# /etc/systemd/system/multi-user.target.wants/*.service at an attacker unit
# of equal length changes no mode, uid, gid, size, nlink or xattr and was
# reported by nothing. Verified with aide-0.19.2 (`--path-check`):
#   NORMAL      -> l+p+u+g+s+i+n+acl+sha512+selinux+xattrs+ftype+e2fsattrs+sha3_256
#   old SECURE  -> p+u+g+s+b+n+acl+sha256+sha512+xattrs
#   this SECURE -> NORMAL + b + sha256 (strict superset of both)
# `b` is carried over from the previous definition so the change is purely
# additive; sha256 keeps the dual-hash intent, and NORMAL's sha3_256 makes it
# three independent digests on the critical hardening paths.
#
# Fedora aide.conf does NOT ship a SECURE rule by default, so defining it in
# our append-block is conflict-free. It DOES ship NORMAL (aide.conf:120,
# `NORMAL = R+sha512-m-c`), and AIDE requires a group to be defined before
# use — our block is appended after it. Step 1 asserts NORMAL is present
# before appending, so a hand-edited %config(noreplace) aide.conf fails the
# compose loudly instead of shipping an unparsable config.
SECURE = NORMAL+sha256+b

# VFAT does not provide stable/useful Unix inode, ACL or xattr semantics. Track
# ownership/mode/size and content hashes without excluding the ESP. This more
# specific rule overrides Fedora's general `/boot NORMAL` rule for the subtree.
ESP = p+u+g+s+sha256+sha512
/boot/efi ESP
AIDE_PREAMBLE_EOF
    # AIDE selects the deepest tree node and then the first rule in that node.
    # A trailing slash therefore gives child files a deeper node than Fedora's
    # earlier directory-wide NORMAL rules. The equals rule gives chrony.conf an
    # exact-rule node ahead of Fedora's earlier regular expression. Removing
    # either form silently downgrades these paths back to NORMAL.
    for secure_path in "${SECURE_PATHS[@]}"; do
        printf '%s SECURE\n' "$secure_path" >> /etc/aide.conf
    done
    cat >> /etc/aide.conf <<'AIDE_EOF'

# ============================================================================
# NoID Privacy — post-reboot false-positive exclusions
# ============================================================================
#
# All 10 exclusions below are for legitimate, reproducible high-churn or
# directory-entry-only changes
# that would otherwise generate false positive alerts on every boot/day:
#
# 1. /etc/pam.d$       — systemd-tmpfiles verifies dir on boot → Ctime bump
#                        Children (system-auth, password-auth, etc.) still
#                        fully tracked via /etc/pam.d LSPP rule above.
# 2. /root$            — systemd-tmpfiles verifies home dir 0700 mode → Ctime
#                        Children still tracked via /root NORMAL rule above.
# 3. /boot/grub2$      — grubenv BLS counter write bumps parent dir mtime
#                        grubenv itself already excluded (line above).
# 4. /var/log/audit/   — auditd logs its own AIDE scan → perpetual motion
#                        (Fedora default comment at line 159 says so.)
# 5. /var/log/journal/ — journald rotates files per boot and normalizes ACLs;
#                        this exclusion avoids a self-changing log corpus. It
#                        is not replaced by a universal FSS guarantee.
# 6. /var/log/boot.log$          — plymouth/systemd truncates + rewrites boot.log
# 7. /var/log/boot.log-YYYYMMDD$   at every boot → size shrinks → violates
#                        Fedora aide.conf `LOG = >` growing-file rule.
#                        PLUS logrotate rotates daily with 7-day retention —
#                        new boot.log-YYYYMMDD appears + oldest deleted = all 3
#                        change types triggered simultaneously.
#                        Double-fire via systemd-timer Persistent=true
#                        race condition.
#                        Fedora default aide.conf excludes dnf5.log, audit,
#                        journal, sa, lastlog — but NOT boot.log. Our fix.
# 8. /.snapshots         — Module 20 Snapper integration.
#                        snapper creates /.snapshots/N/snapshot/** subtrees that
#                        contain entire root filesystem copies via btrfs CoW. AIDE
#                        tracking them would: (1) produce massive false-positive
#                        "added entries" reports at every check after pre/post
#                        snapshot pair and (2) multiply database size by every
#                        retained root copy. Btrfs CoW is not an authenticated
#                        integrity substitute; this is a bounded monitoring scope.
# 9. /var/lib/libvirt/images — default VM disk-image store. Tracking multi-GiB
#                        mutable qcow2/raw guests makes every guest write look
#                        like a host-integrity event. Libvirt policy/configuration
#                        under /etc/libvirt remains tracked.
# 10. /var/lib/libvirt/qemu — generated runtime/domain state, monitor sockets,
#                        NVRAM and save-state data. These are operational guest
#                        state, not the host's authoritative libvirt policy.
#
# Regex `$` anchor = directory-entry-only exclusion (children still tracked).
# Regex `(/.*)?$` = entire subtree prune (use for explicitly named high-churn
# stores; never for all of /var/lib/libvirt).
# See the !/path$ anchor regex pattern for the mental model.

!/etc/pam.d$
!/root$
!/boot/grub2$
!/var/log/audit(/.*)?$
!/var/log/journal(/.*)?$
!/var/log/boot\.log$
!/var/log/boot\.log-[0-9]{8}$
!/\.snapshots(/.*)?$
!/var/lib/libvirt/images(/.*)?$
!/var/lib/libvirt/qemu(/.*)?$
# ============================================================================
# 30-day forensic-retention report exclusions
# ============================================================================
# The retention bundle (M42 forensic-retention + M20 snapper-prune + M25
# check-only update evidence + M13 AIDE workflows) writes and
# deletes files inside /var/log every day. The Fedora-default `/var/log LOG`
# rule would otherwise generate ADDED + REMOVED alerts on every aide-check.
# These paths are excluded to avoid scanner self-reference and high-churn log
# noise. That is an explicit visibility trade-off; the log contents can still
# carry security-relevant evidence and are governed by permissions/retention,
# not by AIDE content monitoring.
#
# Coverage:
#
#   /var/log/aide/                      — per-mode TS-named report files
#       aide-check-YYYYMMDD-HHMMSS.log          (M13 wrapper)
#       aide-baseline-review-YYYYMMDD-HHMMSS.log (M13 explicit prepare)
#       aide.log                               (legacy static; Fedora-default
#                                               `!/var/log/aide.log` rule
#                                               targets the wrong path)
#     Subtree prune `(/.*)?$` covers any future log-naming variant without
#     needing per-pattern rules.
#
#   /var/log/anaconda/                  — noid-install-logs-prune: install-
#       anaconda.log + dbus.log + journal.log + packaging.log + storage.log +
#       lorax-packages.log — pruned at >30d. Files exist at baseline (created
#       by Anaconda install). REMOVED alert at day 31 without this exclusion.
#
#   /var/log/ks-*.log + exact one-shot logs — per-module kickstart %post,
#       authselect stderr, target-karg, firstboot and crypto-policy failure
#       evidence. M42 prunes these exact names after 30 days.
#
#   /var/log/libvirt/qemu/*.log         — noid-misc-logs-prune: per-VM
#       libvirt qemu logs. M42 replaces Fedora's stanza with a strict daily
#       30-day cap.
#
#   /var/log/swtpm/libvirt/qemu/*.log   — separate per-VM vTPM logs. M42
#       rotates/prunes them under the same VM trace boundary.
#
#   /var/log/tuned/*.log*               — noid-misc-logs-prune: tuned
#       daemon profile-change log + rotated variants.

!/var/log/aide(/.*)?$
!/var/log/anaconda(/.*)?$
!/var/log/ks-[^/]*\.log$
!/var/log/ks-10-authselect\.err$
!/var/log/noid-anaconda-kernel-cmdline\.log$
!/var/log/noid-firstboot-setup\.log$
!/var/log/noid-crypto-policy\.err$
!/var/log/libvirt(/.*)?$
!/var/log/swtpm/libvirt/qemu(/.*)?$
!/var/log/tuned(/.*)?$

# ============================================================================
# gpg-agent transient mutex/lockfiles in /root/.gnupg/
# ============================================================================
# gpg-agent creates transient lockfiles during dirmngr/keyring access:
#   - sqlite mutex: /root/.gnupg/<subdir>/<keyring>.lock
#   - process-lock: /root/.gnupg/<subdir>/.#lk0x<HASH>.<HOST>.<PID>
#
# These can appear/disappear on millisecond timescales during RPM/GPG or AIDE
# activity. Their transient timing can cause
# recurring false drift in observed check cycles:
#   Cycle 1: Added 0, Removed 2 (lockfiles freed)
#   Cycle 2: Added 2, Removed 0 (lockfiles re-acquired)
#   Cycle N: ... infinite ping-pong WARN
#
# Trigger paths in NoID Privacy image:
#   - dnf upgrade → rpmkeys --checksig → gpg → /root/.gnupg/ lockfiles
#   - explicit AIDE candidate preparation → libgpgme lookup → lockfiles
#   - dirmngr keyserver fetch (manual gpg --refresh-keys) → same
#
# Pattern parallel to the boot.log fix (line 248-249): Fedora default aide.conf
# excludes dnf5.log / audit / journal / sa / lastlog — but NOT gpg lockfiles.
# Same class of bug, same fix-pattern.
#
# Scope rationale: the excluded files are transient lock state, not key data
#   - excluded: *.lock (sqlite mutex), .#lk* (gpg-agent process lock)
#   - still tracked: pubring.kbx, tofu.db, gpg-agent.conf (real keyring content)
#
# Generic .gnupg/ pattern (covers all subdirs: public-keys.d, private-keys-v1.d,
# openpgp-revocs.d, crls.d, plus future GPG2.5+ keyring layouts).
!/root/\.gnupg/.*\.lock$
!/root/\.gnupg/.*/\.#lk.*$

# ============================================================================
# Performance fix
# ============================================================================
# `database_attrs` controls attributes reported for the uncompressed database
# file itself; it does not add hashes to each tracked filesystem entry. Per-file
# work is selected only by the matching NORMAL/SECURE/path rule. Keep two
# database-file digests explicitly for metadata integrity without claiming a
# per-entry scan-performance effect.
# Last `database_attrs=` line wins (this overrides Fedora default).
database_attrs=sha256+sha3_256
AIDE_EOF
    echo "  [OK] ${#SECURE_PATHS[@]} SECURE rules + ESP content rule + 10 exclusions + 2 gpg-lock excludes + 10 retention-path excludes + 1 database_attrs override appended"
fi

# Remove legacy integrity blind spots, including the two former System.map
# exclusions, if this module is re-applied to an older image. Preserve metadata
# and replace aide.conf atomically in /etc.
forbidden_file=$(mktemp)
aide_candidate=$(mktemp /etc/aide.conf.noid.XXXXXX)
trap 'rm -f -- "$forbidden_file" "$aide_candidate"' EXIT HUP INT TERM
printf '%s\n' "${FORBIDDEN_CONTROL_EXCLUDES[@]}" > "$forbidden_file"
awk 'NR==FNR {deny[$0]=1; next} !($0 in deny)' \
    "$forbidden_file" /etc/aide.conf > "$aide_candidate"
# BEGIN M13_SECURE_RECONCILE
secure_rules_reconciled=0
for secure_path in "${SECURE_PATHS[@]}"; do
    if ! grep -qxF "$secure_path SECURE" "$aide_candidate"; then
        printf '%s SECURE\n' "$secure_path" >> "$aide_candidate"
        secure_rules_reconciled=$((secure_rules_reconciled + 1))
    fi
done
# END M13_SECURE_RECONCILE
chmod --reference=/etc/aide.conf "$aide_candidate"
chown --reference=/etc/aide.conf "$aide_candidate"
if command -v chcon >/dev/null 2>&1 && [ -f /sys/fs/selinux/enforce ]; then
    chcon --reference=/etc/aide.conf "$aide_candidate"
fi
mv -fT -- "$aide_candidate" /etc/aide.conf
aide_candidate=""
rm -f -- "$forbidden_file"
forbidden_file=""
trap - EXIT HUP INT TERM
if [ "$secure_rules_reconciled" -gt 0 ]; then
    echo "  [OK] $secure_rules_reconciled AIDE SECURE rules reconciled from canonical manifest"
fi
unset secure_rules_reconciled

# ----------------------------------------------------------------------------
# Step 2: Install aide-check.service (main unit)
# ----------------------------------------------------------------------------
echo ""
echo "[Step 2] Installing aide-check.service"

cat > /etc/systemd/system/aide-check.service <<'SERVICE_EOF'
[Unit]
Description=AIDE File Integrity Check
Documentation=man:aide(1)
After=network.target
# Never scan the transient live overlay or claim a result without an active,
# user-accepted database.
ConditionKernelCommandLine=!rd.live.image
ConditionPathExists=/var/lib/aide/aide.db.gz

[Service]
Type=oneshot
ExecStart=/usr/sbin/aide --workers=1 --check
StandardOutput=journal
StandardError=journal

# baseline sandbox + 2026 baseline raise.
# NoNewPrivileges=yes is OMITTED for aide-check: it would block the
# init_t→aide_t SELinux domain transition (verified via AVC
# "denied { nnp_transition } scontext=init_t tcontext=aide_t" on
# force-run). Without the transition, AIDE runs in init_t
# which can't write /var/log/aide/ (Permission denied on aide.log).
# The other directives below are universally safe — none affect
# SELinux transitions or aide's read-everything/write-aide.log access.
#
# Original 7 directives (baseline):
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelLogs=yes
ProtectHostname=yes
ProtectClock=yes
SystemCallArchitectures=native
#
# 2026 baseline expansion:
# ProtectSystem=strict makes /usr /etc /boot read-only. The check wrapper writes
# reports under /var/log/aide and creates/holds its flock mutex at
# /var/lock/noid-aide.lock; /var/lock is a symlink to /run/lock (tmpfs), so the
# real writable target the mount namespace needs is the pre-created exact lock
# at /run/lock/noid-aide.lock — without it the
# flock() under `set -euo pipefail` fails on the read-only namespace and the
# daily check silently never runs. /var/lib/aide is readable for the active
# database but no automated service writes or replaces it.
ProtectSystem=strict
ReadWritePaths=/var/log/aide /run/lock/noid-aide.lock
UMask=0077
# Fedora's shipped policy tracks /root but carries no /home selection. A tmpfs
# cover hides /home and /run/user from routine checks while the explicit
# read-only bind makes only the required /root tree visible again (the
# supported ProtectHome=tmpfs exception described by systemd.exec(5)).
ProtectHome=tmpfs
BindReadOnlyPaths=/root
PrivateTmp=yes
ProtectKernelTunables=yes
# Module-load lockdown WITHOUT ProtectKernelModules=: that directive
# additionally makes /usr/lib/modules inaccessible in the unit's mount
# namespace (systemd namespace.c MOUNT_INACCESSIBLE; BindReadOnlyPaths
# cannot restore it) — aide must READ that tree to hash the kernel
# modules tracked in its database (the baseline writers run unsandboxed).
# The pair below keeps the equivalent load/unload block: capability drop
# + @module syscall filter returning EPERM (the directive's own behavior).
CapabilityBoundingSet=~CAP_SYS_MODULE
SystemCallFilter=~@module
SystemCallErrorNumber=EPERM
ProtectControlGroups=yes
# MemoryDenyWriteExecute: aide is C, no JIT — safe to deny W^X regions.
MemoryDenyWriteExecute=yes
# IPAddressDeny=any — aide --check has zero network needs (file-system
# integrity only). Network sockets get denied entirely.
IPAddressDeny=any
SERVICE_EOF

chmod 644 /etc/systemd/system/aide-check.service
chown root:root /etc/systemd/system/aide-check.service
echo "  [OK] /etc/systemd/system/aide-check.service installed (644)"

# ----------------------------------------------------------------------------
# Step 3: Install aide-check.timer
# ----------------------------------------------------------------------------
echo ""
echo "[Step 3] Installing aide-check.timer"

cat > /etc/systemd/system/aide-check.timer <<'TIMER_EOF'
[Unit]
Description=Daily morning AIDE integrity check (07:00-08:00)
Documentation=man:aide(1) man:systemd.timer(5)

[Timer]
# Moved from OnCalendar=daily (Fedora default 00:00-01:00)
# to OnCalendar=07:00:00 to avoid nighttime timer congestion:
#   00:00 snapper-timeline, 00:42 logrotate + systemd-tmpfiles-clean,
#   01:00 unbound-anchor, 01:03 dnf-makecache, 01:23 plocate-updatedb,
#   01:37 snapper-cleanup. With the old schedule, aide-check had random
#   chance to race against logrotate (same 00:00-01:00 window) causing
#   false positives when AIDE tracked /var/log/boot.log. After moving to
#   07:00, AIDE runs after all nighttime cron is done + user sees
#   notifications at first morning login (instead of mid-night disrupt).
OnCalendar=07:00:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
TIMER_EOF

chmod 644 /etc/systemd/system/aide-check.timer
chown root:root /etc/systemd/system/aide-check.timer
echo "  [OK] /etc/systemd/system/aide-check.timer installed (644)"

# ----------------------------------------------------------------------------
# Step 4: Install service drop-ins (exitcode + notify)
# ----------------------------------------------------------------------------
#
# TWO drop-ins:
#
# exitcode.conf:
#   AIDE exit codes 1-7 are SUCCESS (bitmask: 1=added, 2=removed, 4=changed).
#   Exit 0 = no changes. Exit >=14 = real error.
#   systemd default treats all non-zero as failure — drop-in tells systemd
#   that 1-7 are valid success states so the service doesn't get logged as
#   "failed" in every run that finds legitimate changes.
#
# notify.conf:
#   ExecStopPost= (NOT ExecStartPost=) runs after ExecStart= exits.
#   $EXIT_STATUS is only set in ExecStopPost= per systemd.exec(5) man page —
#   if we used ExecStartPost=, bash would expand $EXIT_STATUS to empty string
#   and aide-notify.sh would see exit code 0 and silent-exit → no notifications.
#   `-` prefix = fault-tolerant (don't fail the unit if notify script errors).
#
echo ""
echo "[Step 4] Installing aide-check.service.d drop-ins"

mkdir -p /etc/systemd/system/aide-check.service.d
chmod 755 /etc/systemd/system/aide-check.service.d
chown root:root /etc/systemd/system/aide-check.service.d

cat > /etc/systemd/system/aide-check.service.d/exitcode.conf <<'EXITCODE_EOF'
[Service]
# AIDE bitmask exit codes 1-7 are legitimate success (changes detected):
#   bit 0 (1) = files added
#   bit 1 (2) = files removed
#   bit 2 (4) = files changed
#   bit 3 (8) = reserved
# Exit 0 = no changes. Exit >=14 = configuration or runtime error.
SuccessExitStatus=1 2 3 4 5 6 7
EXITCODE_EOF
chmod 644 /etc/systemd/system/aide-check.service.d/exitcode.conf
chown root:root /etc/systemd/system/aide-check.service.d/exitcode.conf

# Resource-control drop-in. Firstboot/live catch-ups are blocked by the unit
# conditions; therefore no artificial 10-minute sleep is needed in a normal
# scheduled check.
cat > /etc/systemd/system/aide-check.service.d/boot-priority.conf <<'BOOTPRIO_EOF'
# /etc/systemd/system/aide-check.service.d/boot-priority.conf
# Bound the daily scan without delaying it after its intended schedule.
[Service]
TimeoutStartSec=infinity
Nice=19
IOSchedulingClass=2
IOSchedulingPriority=7
OOMScoreAdjust=500
MemoryHigh=3G
MemoryMax=4G
MemorySwapMax=0
TasksMax=16
BOOTPRIO_EOF
chmod 644 /etc/systemd/system/aide-check.service.d/boot-priority.conf
chown root:root /etc/systemd/system/aide-check.service.d/boot-priority.conf

# Ensure /usr/share/doc/noid-privacy/ exists before we write any docs there.
# Earlier modules create this path too, but this module does not rely on that
# ordering: without mkdir here, a standalone/snippet build would fail before
# writing aide-notify-dropin.conf. Later modules likewise create it defensively.
mkdir -p /usr/share/doc/noid-privacy
chmod 755 /usr/share/doc/noid-privacy
chown root:root /usr/share/doc/noid-privacy

# notify.conf is shipped as TEMPLATE in docs, NOT active by default.
# Rationale: on a generic image, AIDE false positives (kernel updates,
# NM connection inode rotation, etc.) cause notification fatigue for
# users who don't understand AIDE. The image creates no trusted baseline and
# enables neither the timer nor popups automatically. After explicit baseline
# acceptance, users can enable the timer and popup independently (see Step 5).
cat > /usr/share/doc/noid-privacy/aide-notify-dropin.conf <<'NOTIFY_EOF'
[Service]
# ExecStopPost (NOT ExecStartPost): $EXIT_STATUS is only defined in
# ExecStop*/ExecStopPost/ExecCondition per systemd.exec(5). Using
# ExecStartPost would expand $EXIT_STATUS to empty string.
# `-` prefix = fault-tolerant if notify script errors.
ExecStopPost=-/bin/bash -c '/usr/local/bin/aide-notify.sh $EXIT_STATUS'
NOTIFY_EOF
chmod 644 /usr/share/doc/noid-privacy/aide-notify-dropin.conf

# Sanctioned AIDE schedule override template.
# Shipped in docs/ — users copy it to /etc/systemd/system/aide-check.timer.d/
# if the default 07:00-08:00 window doesn't fit their schedule (e.g. night
# workers, shift workers, users who run the machine only on weekends).
# Using a drop-in (instead of editing the packaged timer unit directly)
# follows the standard systemd override pattern and survives image updates.
cat > /usr/share/doc/noid-privacy/aide-schedule-override.conf <<'SCHEDULE_EOF'
# AIDE check schedule override — TEMPLATE
#
# Copy this file to:
#     /etc/systemd/system/aide-check.timer.d/override.conf
#
# Edit the OnCalendar line(s) to your preferred schedule, then:
#     sudo systemctl daemon-reload
#     sudo systemctl restart aide-check.timer
#
# Verify the new schedule:
#     systemctl list-timers aide-check.timer
#
# Schedule syntax: see `man systemd.time` and `systemd-analyze calendar`.
#
# Examples:
#   OnCalendar=Fri *-*-* 21:00:00       # Fridays at 21:00
#   OnCalendar=*-*-* 12:30:00           # Daily at 12:30
#   OnCalendar=Mon,Thu *-*-* 09:00:00   # Mondays + Thursdays at 09:00
#   OnCalendar=weekly                   # Monday 00:00 (stock systemd alias)

[Timer]
# Clear default OnCalendar (required to replace, not append)
OnCalendar=
# Replace with your preferred schedule:
OnCalendar=*-*-* 07:00:00
# Optional: widen/narrow the random delay window (default 1 hour)
RandomizedDelaySec=1h
SCHEDULE_EOF
chmod 644 /usr/share/doc/noid-privacy/aide-schedule-override.conf

# User-facing documentation: how to enable/disable desktop notifications
# for AIDE, auditd, and the weekly update reminder.
cat > /usr/share/doc/noid-privacy/notifications.md <<'NOTIFY_DOC_EOF'
# NoID Privacy — Desktop Notifications

The image ships notification mechanisms for explicitly enabled checks. All
notifications are user-facing popups via `notify-send` and appear as GNOME
desktop notifications.

## 1. AIDE integrity check (baseline, timer and popup require user action)

**What it does**: after you accept an initial baseline, AIDE can run daily
between 07:00-08:00 and report new/removed/modified files. The image does not
create a baseline or enable the timer automatically.

**Why the popup is opt-in**: a generic image produces too many false-
positive changes (kernel updates, NetworkManager connection inode rotation,
timezone updates, logrotate). Most users experience this as notification
fatigue. Power users who understand AIDE output can opt in.

**Enable**:

    sudo noid-toggle-aide-popup on

**Disable** (after enabling):

    sudo noid-toggle-aide-popup off

The helper verifies the active baseline, template, destination metadata and
SELinux labels, deploys atomically, reloads systemd and rolls back a failed
transaction. It refuses to overwrite or delete a locally drifted drop-in.

**Prepare and accept a baseline (explicit trust decision)**:

    sudo noid-aide-baseline-review prepare
    sudo noid-aide-baseline-review status
    # Review the complete report, then commit its exact SHA-256:
    sudo noid-aide-baseline-review commit SHA256

Candidate generation does not replace the active database. Commit requires
the exact hash and an interactive typed confirmation. Never commit merely to
silence an alert, and do not delegate this trust decision to an agent.

**Check AIDE results without popup** (after baseline setup):

    sudo journalctl -u aide-check.service -n 50

**Disable scheduled checks**:

    sudo systemctl disable --now aide-check.timer

**Enable scheduled checks (requires an active reviewed baseline)**:

    sudo systemctl enable --now aide-check.timer

**Change the schedule** (default: daily 07:00-08:00):

Use the sanctioned systemd drop-in pattern — this survives image updates
and does not modify the packaged unit file:

    sudo mkdir -p /etc/systemd/system/aide-check.timer.d
    sudo cp /usr/share/doc/noid-privacy/aide-schedule-override.conf \
            /etc/systemd/system/aide-check.timer.d/override.conf
    sudo $EDITOR /etc/systemd/system/aide-check.timer.d/override.conf
    # edit the OnCalendar line to your preferred schedule
    sudo systemctl daemon-reload
    sudo systemctl restart aide-check.timer

Verify with: `systemctl list-timers aide-check.timer`.
Schedule syntax: see `man systemd.time` or `systemd-analyze calendar "Fri *-*-* 21:00:00"`.

## 2. auditd security-event popups (OPT-IN; disabled by default)

**What it does**: receives complete events from auditd through auparse for 16
critical security event keys
(identity, sudoers, audit_config, aide_integrity, bootloader, sysctl, systemd, firewall,
pam_changes, network_config, user_mgmt, su_usage, luks, login_config,
security_config, cron). Shows the affected file path in the notification
body. Rate-limited to 1 popup per key per 5 minutes. Suppressed during
`noid-update-all.sh` runs (expected sysctl/systemd/bootloader noise).

**Why opt-in**: audit evidence is always recorded, while desktop popups can be
noisy. Enable them only if immediate visual alerts are useful for your workflow.

**Disable** (stops popups, but auditd still logs everything):

    sudo noid-toggle-audit-notify off

**Enable**:

    sudo noid-toggle-audit-notify on

**Query audit events without popup** (always available, even if notify off):

    sudo ausearch -k sudoers -ts today
    sudo ausearch -k identity -ts today
    # (replace key name as needed — see list above)

**Full audit report**:

    sudo aureport --summary
    sudo aureport -k --summary

## 3. Weekly update reminder (ACTIVE by default)

**What it does**: every Monday between 10:00-11:00, shows a desktop
notification reminding you to run `noid-update-all.sh`. User-session
timer (runs as your user, not root). Persistent — if the machine is
off on Monday, fires on next login.

**Disable**:

    systemctl --user disable --now noid-update-reminder.timer

**Re-enable**:

    systemctl --user enable --now noid-update-reminder.timer

**Change the schedule** (example: Friday 09:00):

    systemctl --user edit noid-update-reminder.timer
    # Add/modify:
    # [Timer]
    # OnCalendar=
    # OnCalendar=Fri *-*-* 09:00:00

## 4. Updates — manual-only (Silent-Machine philosophy)

**What it does**: NoID Privacy does NOT run any background auto-update timer. All
package updates (Fedora RPMs, Flatpaks, firmware, AIDE check-only evidence,
Firefox user.js re-apply) happen via the user-invoked `noid-update-all.sh`
script. The image makes zero autonomous network fetches for updates.

**Why no auto-update timer**: NoID Privacy's Silent-Machine philosophy — the
machine should make NO autonomous network requests except those that are
unavoidable for operation (chrony NTS time-sync, WireGuard VPN keepalive,
DNS queries triggered by active applications). Background `dnf upgrade` cron jobs leak update
patterns to Fedora mirrors and create traffic-correlation signals even
behind a VPN.

**Trade-off**: the user must run `noid-update-all.sh` regularly to
receive security patches. This is intentional — privacy + user control
over UX-comfort. The weekly Monday 10:00 reminder ensures the user does
not forget.

**How to update**:

    /usr/local/bin/noid-update-all.sh

The script handles 9 steps: Snapper pre-snapshot, DNF upgrade,
NVIDIA akmod + dracut rebuild on kernel-change, Flatpak update, firmware
(interactive prompt), Firefox NoID Privacy user.js re-apply, repo gpgcheck audit,
AIDE check-only evidence against the user-owned baseline, reboot check. Total runtime
5-15 minutes depending on updates available.

**Kernel-update reboot flow** (when noid-update-all.sh installs a new kernel):
1. dnf installs kernel-X.Y.Z
2. akmods rebuilds NVIDIA / evdi / other third-party modules for X.Y.Z
3. dracut regenerates `/boot/initramfs-X.Y.Z.img`
4. On every subsequent GNOME login, `noid-pending-reboot-check.sh`
   compares `uname -r` against the highest version in `/lib/modules/`;
   if they differ, an urgency=critical reminder is shown until reboot
5. After reboot: `uname -r` matches the latest installed kernel → silent
   (no marker file involved — pure version-diff, marker-less)

**Check reboot status anytime**:

    noid-status                   # full overview including reboot line
    noid-status --brief           # one-liner summary

**Rollback a bad update**: `sudo snapper -c root list` to find the
pre-update snapshot, then `sudo noid-snap-rollback <N>` and reboot. See
`/usr/share/doc/noid-privacy/20-rollback-recovery.md`.

## 5. Hardware Privacy Toggles (4 SwitchRows in Welcome dialog)

**What it does**: NoID Privacy default has Microphone, Camera, Bluetooth, and
Location services all blocked. Welcome dialog "Hardware Privacy" group ships
4 SwitchRows so you can opt out per-device whenever you need them. Re-enable
is one-click; re-disable is one-click to restore the strict default.

**Welcome dialog path**: NoID Privacy Setup → **Hardware Privacy** group.

**Microphone** (per-user, no password; changes both independent layers):

    noid-toggle-microphone status
    noid-toggle-microphone on       # allow apps + stop persistent source mute
    noid-toggle-microphone off      # restore strict privacy default

**Camera** (per-user gsettings, no password — key unlocked per M17 design):

    gsettings set org.gnome.desktop.privacy disable-camera false
    # set 'true' to re-block

**Bluetooth** (system-level multi-layer toggle; Setup honors an exact
owner-authorized noninteractive sudo rule when present, otherwise installed
sessions authenticate each privileged action through polkit; the passwordless
Live session uses its transient `sudo -n` grant):

    # Bluetooth (4-layer state: service stop + wireplumber bluez plugin +
    # rfkill + flag-file)
    noid-toggle-bluetooth status     # read-only state, any user
    sudo noid-toggle-bluetooth on    # enable BT stack
    sudo noid-toggle-bluetooth off   # disable (restore privacy default)

**Location** (per-user GNOME setting; no root or flag-file):

    noid-toggle-location status
    noid-toggle-location on          # enable location services
    noid-toggle-location off         # restore privacy default

The microphone CLI atomically coordinates GNOME's application-permission key
with WirePlumber's persistent `noid.microphone.disabled` capture-source policy.
The authoritative location choice is
`org.gnome.system.location enabled`; the M08 user watcher mirrors that choice
to GeoClue's network-source override. Bluetooth alone uses
`/var/lib/noid-privacy/bluetooth-disabled.flag` plus rfkill and WirePlumber.

**Why exact sudo first, then pkexec + AUTH_ADMIN**: Setup asks sudo policy
about the exact backend argv with noninteractive `sudo -n -l -l` and uses
`sudo -n` only when the matching entry is tagged `!authenticate`, i.e. when a
passwordless owner-authorized route really exists. A bare "permitted by the
security policy" answer is not that evidence — `%wheel ALL=(ALL) ALL` satisfies
it for every wheel member — so relying on the exit status alone selected sudo
for backends that then failed with "a password is required". Setup does
not add a sudo rule. Otherwise polkit ≥0.127 enforces a minimum auth requirement
for `org.freedesktop.policykit.exec` (the pkexec action) and silently downgrades
`polkit.Result.YES` to `AUTH_ADMIN`. Rule
`/etc/polkit-1/rules.d/60-noid-toggle-privacy-services.rules` pins that uncached
result for the exact helper paths. Polkit explicitly warns that a retained
result is unsafe when authorization depends on the variable `program`: every
pkexec request shares one action identifier, so one approved helper must never
authorize a different program during a cache window. The Live account
deliberately has no password, so Setup always selects its existing, ephemeral
NOPASSWD sudo route only when `liveuser`, `rd.live.image`, and the initramfs
Live-media marker all agree. Installation removes that account and sudoers
entry before first boot.

## Summary

| Notification / Service        | Default    | Enable/Disable                                                        |
|-------------------------------|------------|-----------------------------------------------------------------------|
| AIDE timer + log              | DISABLED pending baseline review | `sudo noid-toggle-aide on\|off`                 |
| AIDE desktop popup            | DISABLED   | `sudo noid-toggle-aide-popup on\|off`                                 |
| AIDE schedule                 | 07:00-08:00 daily | drop-in: `/etc/systemd/system/aide-check.timer.d/override.conf` |
| auditd log (132 ABI-complete rules) | ACTIVE | always on (immutable, cannot be disabled at runtime)              |
| audit desktop popup           | DISABLED   | `sudo noid-toggle-audit-notify on\|off`                              |
| Weekly update reminder        | ACTIVE     | `systemctl --user {enable,disable} --now noid-update-reminder.timer`  |
| Background auto-update timer  | NOT INSTALLED | Silent-Machine philosophy — run `noid-update-all.sh` manually      |
| Pending-reboot login notifier | ACTIVE     | compares `uname -r` vs `/lib/modules/` — silent when reboot completed |
| Microphone (app block + persistent source mute) | DISABLED | Welcome dialog OR `noid-toggle-microphone on\|off` |
| Camera (per-app block)        | DISABLED   | Welcome dialog OR `gsettings set org.gnome.desktop.privacy disable-camera false` |
| Bluetooth stack               | DISABLED   | Welcome dialog OR `sudo noid-toggle-bluetooth on\|off`                |
| Location services             | DISABLED   | Welcome dialog OR `noid-toggle-location on\|off`                      |

NOTIFY_DOC_EOF
chmod 644 /usr/share/doc/noid-privacy/notifications.md

echo "  [OK] exitcode.conf installed (644), notify.conf shipped as template (inactive)"
echo "  [OK] notifications.md (user-facing doc) installed (644)"

# ----------------------------------------------------------------------------
# Step 5: Install aide-notify.sh (verified local-session detection)
# ----------------------------------------------------------------------------
#
# Runs as root (inherited from aide-check.service ExecStopPost context).
# For each active, unlocked, local graphical seat (uid >= 1000), validates
# systemd-logind's session/seat relationship and the user-owned D-Bus socket,
# then drops privileges with setpriv before invoking notify-send.
#
# Replaces an earlier version that hardcoded a static display-user value.
# Do not regress to /run/systemd/users presence as a login/lock/seat signal:
# lingering user managers and non-graphical sessions can keep those files alive.
#
echo ""
echo "[Step 5] Installing /usr/local/bin/aide-notify.sh"

cat > /usr/local/bin/aide-notify.sh <<'NOTIFY_SH_EOF'
#!/bin/bash
# NoID Privacy — AIDE Result Desktop Notification
# Ships as part of image Module 13.
# Triggered by aide-check.service.d/notify.conf via ExecStopPost=.
# $EXIT_STATUS is passed as $1 (AIDE bitmask exit code).

# Was `set -u` only. `-u` catches undefined
# variable usage; `-o pipefail` propagates failures inside pipelines (the
# journalctl|grep pipes downstream depended on this). `-e` deliberately NOT
# set — script is fault-tolerant by design (`|| true`/`2>/dev/null` patterns
# at every networked/optional step). Adding `-e` would require auditing every
# such fallback to suppress correctly; the current behavior is intentional.
set -uo pipefail
umask 077

AIDE_EXIT=${1:-invalid}
export LANG=C.UTF-8 LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

if ! [[ "$AIDE_EXIT" =~ ^[0-9]+$ ]] || [ "$AIDE_EXIT" -gt 255 ]; then
    AIDE_EXIT=255
fi

property_value() {
    local property=$1 data=$2 values
    values=$(printf '%s\n' "$data" | sed -n "s/^${property}=//p")
    [ "$(printf '%s\n' "$values" | grep -c . || true)" -eq 1 ] || return 1
    printf '%s\n' "$values"
}

# ----------------------------------------------------------------------------
# Dynamic user session detection
# ----------------------------------------------------------------------------
# Notify only non-system users whose session is local, graphical, active,
# foreground on its seat and explicitly unlocked. A user manager or D-Bus
# socket alone is not evidence that any of those properties hold.
send_to_all_active_users() {
    local urgency="$1"
    local title="$2"
    local body="$3"

    local sessions_json session_rows
    local session uid extra properties session_user seat remote session_class
    local session_type session_state session_active locked active_session
    local passwd_record user account_uid gid home shell runtime dbus_sock
    declare -A notified_uids=()

    sessions_json=$(
        /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
            /usr/bin/loginctl list-sessions --json=short 2>/dev/null
    ) || return 0
    session_rows=$(
        /usr/bin/python3 -c '
import json
import sys

rows = json.load(sys.stdin)
if not isinstance(rows, list):
    raise SystemExit("loginctl JSON is not a list")
for row in rows:
    if not isinstance(row, dict):
        continue
    session = row.get("session")
    uid = row.get("uid")
    if isinstance(session, (str, int)) and isinstance(uid, int):
        print(f"{session}\t{uid}")
' <<<"$sessions_json"
    ) || return 0

    while IFS=$'\t' read -r session uid extra; do
        [ -z "${extra:-}" ] || continue
        [[ "$session" =~ ^[[:alnum:]_.-]{1,128}$ ]] || continue
        [[ "$uid" =~ ^[0-9]+$ ]] \
            && [ "$uid" -ge 1000 ] \
            && [ "$uid" -le 4294967294 ] || continue
        [ -z "${notified_uids[$uid]:-}" ] || continue

        properties=$(
            /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
                /usr/bin/loginctl show-session "$session" \
                --property=User \
                --property=Seat \
                --property=Remote \
                --property=Class \
                --property=Type \
                --property=State \
                --property=Active \
                --property=LockedHint 2>/dev/null
        ) || continue

        session_user=$(property_value User "$properties") || continue
        seat=$(property_value Seat "$properties") || continue
        remote=$(property_value Remote "$properties") || continue
        session_class=$(property_value Class "$properties") || continue
        session_type=$(property_value Type "$properties") || continue
        session_state=$(property_value State "$properties") || continue
        session_active=$(property_value Active "$properties") || continue
        locked=$(property_value LockedHint "$properties") || continue
        [ "$session_user" = "$uid" ] \
            && [[ "$seat" =~ ^[[:alnum:]_.-]{1,128}$ ]] \
            && [ "$remote" = no ] \
            && [ "$session_class" = user ] \
            && [[ "$session_type" =~ ^(wayland|x11)$ ]] \
            && [ "$session_state" = active ] \
            && [ "$session_active" = yes ] \
            && [ "$locked" = no ] || continue

        active_session=$(
            /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
                /usr/bin/loginctl show-seat "$seat" \
                --property=ActiveSession --value 2>/dev/null
        ) || continue
        [ "$active_session" = "$session" ] || continue

        passwd_record=$(
            /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
                /usr/bin/getent passwd "$uid" 2>/dev/null
        ) || continue
        [ "$(printf '%s\n' "$passwd_record" | grep -c . || true)" -eq 1 ] \
            || continue
        IFS=: read -r user _ account_uid gid _ home shell extra \
            <<<"$passwd_record"
        [ -z "${extra:-}" ] \
            && [ "$user" != root ] \
            && [ "$account_uid" = "$uid" ] \
            && [[ "$gid" =~ ^[0-9]+$ ]] \
            && [[ "$home" == /* ]] \
            && [ -n "$shell" ] || continue

        runtime="/run/user/${uid}"
        dbus_sock="/run/user/${uid}/bus"
        bus_status=$(
            /usr/bin/setpriv --reuid="$uid" --regid="$gid" --init-groups \
                --reset-env /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
                /usr/bin/stat -c '%F:%u' "$dbus_sock" 2>/dev/null
        ) || continue
        [ "$bus_status" = "socket:$uid" ] || continue

        # No PAM, inherited root environment or password-capable sudo path.
        # A failed delivery is isolated to this session.
        /usr/bin/setpriv \
            --reuid="$uid" \
            --regid="$gid" \
            --init-groups \
            --reset-env \
            /usr/bin/timeout --signal=TERM --kill-after=1s 5s \
            /usr/bin/env \
                HOME="$home" \
                XDG_RUNTIME_DIR="$runtime" \
                DBUS_SESSION_BUS_ADDRESS="unix:path=${dbus_sock}" \
            /usr/bin/notify-send \
                --urgency="$urgency" \
                --icon="dialog-warning" \
                --app-name="NoID Privacy" \
                -- "$title" "$body" \
                </dev/null >/dev/null 2>&1 \
            && notified_uids["$uid"]=1 || true
    done <<<"$session_rows"

    return 0
}

# ----------------------------------------------------------------------------
# Exit code handling
# ----------------------------------------------------------------------------
case "$AIDE_EXIT" in
    0)
        # No changes — silent success, no notification
        exit 0
        ;;
    [1-7])
        # Changes detected (bitmask: bit0=added, bit1=removed, bit2=changed)
        DETAILS=""
        [ $((AIDE_EXIT & 1)) -ne 0 ] && DETAILS="${DETAILS}New files. "
        [ $((AIDE_EXIT & 2)) -ne 0 ] && DETAILS="${DETAILS}Files removed. "
        [ $((AIDE_EXIT & 4)) -ne 0 ] && DETAILS="${DETAILS}Files modified. "

        # Read only this service invocation. A unit-wide tail could surface
        # stale paths from a previous run in the current notification.
        CHANGED_FILES=""
        TOTAL=0
        if [[ "${INVOCATION_ID:-}" =~ ^[a-f0-9]{32}$ ]]; then
            INVOCATION_LOG=$(
                /usr/bin/timeout --signal=TERM --kill-after=1s 5s \
                    /usr/bin/journalctl --no-pager --output=cat \
                    --lines=5000 \
                    "_SYSTEMD_INVOCATION_ID=${INVOCATION_ID}" 2>/dev/null
            ) || INVOCATION_LOG=""
            mapfile -t AIDE_PATHS < <(
                printf '%s\n' "$INVOCATION_LOG" |
                    /usr/bin/sed -n 's/.*File: \(\/.*\)$/\1/p'
            )
            TOTAL=${#AIDE_PATHS[@]}
            if [ "$TOTAL" -gt 0 ]; then
                CHANGED_FILES=$(printf '%s\n' "${AIDE_PATHS[@]:0:3}")
            fi
        fi

        BODY="${DETAILS}"
        if [ -n "$CHANGED_FILES" ]; then
            BODY="${BODY}"$'\n'"${CHANGED_FILES}"
            if [ "$TOTAL" -gt 3 ]; then
                MORE=$((TOTAL - 3))
                BODY="${BODY}"$'\n'"(+${MORE} more)"
            fi
        fi
        BODY="${BODY}"$'\n'"Details: sudo journalctl -u aide-check.service"

        send_to_all_active_users "critical" \
            "AIDE: Integrity changes detected" \
            "$BODY"
        ;;
    *)
        # Exit >= 14 = real error (config, DB, runtime)
        send_to_all_active_users "critical" \
            "AIDE: Integrity check ERROR" \
            "AIDE exit code ${AIDE_EXIT}. Details: sudo journalctl -u aide-check.service"
        ;;
esac

exit 0
NOTIFY_SH_EOF

chmod 755 /usr/local/bin/aide-notify.sh
chown root:root /usr/local/bin/aide-notify.sh
echo "  [OK] /usr/local/bin/aide-notify.sh installed (755)"

# ----------------------------------------------------------------------------
# Step 5a: Install the fixed, read-only AIDE state boundary
# ----------------------------------------------------------------------------
# /var/lib/aide is deliberately root:root 0700. A desktop process therefore
# cannot distinguish "database absent" from "database present but unreadable"
# with a direct pathname test. Expose only a closed, argument-free state schema;
# never grant access to database bytes or any baseline mutation.
echo ""
echo "[Step 5a] Installing the read-only AIDE state helper"

mkdir -p /usr/libexec /etc/sudoers.d /usr/lib/tmpfiles.d
cat > /usr/libexec/noid-aide-status <<'AIDE_STATUS_HELPER_EOF'
#!/bin/bash
# Fixed-schema, read-only AIDE trust-database state. No arguments, no mutation.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin
export LANG=C.UTF-8 LC_ALL=C.UTF-8

[ "$#" -eq 0 ] || {
    echo "Usage: noid-aide-status" >&2
    exit 2
}

# BEGIN AIDE_STATE_READER
read_aide_state() {
    local database_dir=$1 database=$2 expected_dir=$3 expected_file=$4
    local state=unsafe
    if [ -d "$database_dir" ] && [ ! -L "$database_dir" ] \
       && [ "$(stat -Lc '%u:%g:%a' "$database_dir" \
                2>/dev/null || true)" = "$expected_dir" ]; then
        if [ ! -e "$database" ] && [ ! -L "$database" ]; then
            state=absent
        elif [ -f "$database" ] && [ ! -L "$database" ] \
             && [ -s "$database" ] \
             && [ "$(stat -Lc '%u:%g:%a:%h' "$database" \
                    2>/dev/null || true)" = "$expected_file" ]; then
            state=active
        fi
    fi
    printf '%s\n' "$state"
}
# END AIDE_STATE_READER

state=$(read_aide_state \
    /var/lib/aide /var/lib/aide/aide.db.gz 0:0:700 0:0:600:1)
printf 'NOID_AIDE_STATE_V1\nSTATE=%s\n' "$state"
AIDE_STATUS_HELPER_EOF
chmod 0755 /usr/libexec/noid-aide-status
chown root:root /usr/libexec/noid-aide-status

cat > /etc/sudoers.d/91-noid-aide-status <<'AIDE_STATUS_SUDOERS_EOF'
# NoID Privacy: expose only the fixed, argument-free AIDE state summary.
Cmnd_Alias NOID_AIDE_STATUS = /usr/libexec/noid-aide-status ""
%wheel ALL=(root) NOPASSWD: NOID_AIDE_STATUS
AIDE_STATUS_SUDOERS_EOF
chmod 0440 /etc/sudoers.d/91-noid-aide-status
chown root:root /etc/sudoers.d/91-noid-aide-status
visudo -cf /etc/sudoers.d/91-noid-aide-status >/dev/null \
    || { echo "[Module 13] FAIL: invalid noid-aide-status sudoers rule"; exit 1; }

cat > /usr/lib/tmpfiles.d/noid-aide-lock.conf <<'AIDE_LOCK_TMPFILES_EOF'
# Shared daily-check / explicit-review mutex. /var/lock -> /run/lock.
f /run/lock/noid-aide.lock 0600 root root -
AIDE_LOCK_TMPFILES_EOF
chmod 0644 /usr/lib/tmpfiles.d/noid-aide-lock.conf
chown root:root /usr/lib/tmpfiles.d/noid-aide-lock.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/noid-aide-lock.conf
[ -f /run/lock/noid-aide.lock ] && [ ! -L /run/lock/noid-aide.lock ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' /run/lock/noid-aide.lock \
            2>/dev/null || true)" = 0:0:600:1 ] \
    || { echo "[Module 13] FAIL: AIDE lock tmpfiles contract invalid"; exit 1; }
echo "  [OK] fixed AIDE state helper + exact sudo boundary installed"
echo "  [OK] /run/lock/noid-aide.lock is tmpfiles-managed (0600 root:root)"

# ----------------------------------------------------------------------------
# Step 5b: Install /usr/local/lib/noid-privacy/wait-fedora-welcome.sh
# ----------------------------------------------------------------------------
# Shared bash helper sourced by Module 34
# (noid-firefox-playground-init.sh) to defer its notify-send call until the
# Anaconda fedora-welcome dialog has been closed.
#
# Important: HARDENING work is NOT blocked by this helper — callers do their
# work first and call noid_wait_fedora_welcome() only right before the
# visible notify-send.
echo ""
echo "[Step 5b] Installing /usr/local/lib/noid-privacy/wait-fedora-welcome.sh"

mkdir -p /usr/local/lib/noid-privacy
chmod 755 /usr/local/lib/noid-privacy

cat > /usr/local/lib/noid-privacy/wait-fedora-welcome.sh <<'WAIT_HELPER_EOF'
#!/bin/bash
# /usr/local/lib/noid-privacy/wait-fedora-welcome.sh
# Shared "block until fedora-welcome closes" helper.
#
# Usage:
#   . /usr/local/lib/noid-privacy/wait-fedora-welcome.sh
#   noid_wait_fedora_welcome [max_wait_seconds] [min_wait_seconds]
#
# Defaults: max_wait=600 (10 min), min_wait=20.
#
# Returns 0 in all cases (timeout OR closure detected). Callers should
# treat return as "may now display notify-send" — does NOT signal failure.
#
# Polling loop:
#   - pgrep -f fedora-welcome → if found, set seen_running=1, sleep 2, retry
#   - if NOT running and seen_running=1: closure detected → return after
#     1s settle delay
#   - if NOT running and seen_running=0 and elapsed < min_wait: keep waiting
#     (autostart timing race — fedora-welcome may lag 10-20s behind login)
#   - if NOT running and seen_running=0 and elapsed >= min_wait: never
#     appeared (e.g. inst.text mode) → return immediately
#   - if elapsed >= max_wait: timeout → return (caller fires notify anyway)

noid_wait_fedora_welcome() {
    local max_wait="${1:-600}"
    local min_wait="${2:-20}"
    local start now elapsed
    local seen_running=0

    start=$(date +%s)

    while :; do
        now=$(date +%s)
        elapsed=$((now - start))
        if [ "$elapsed" -ge "$max_wait" ]; then
            return 0
        fi

        if pgrep -f fedora-welcome >/dev/null 2>&1; then
            seen_running=1
            sleep 2
            continue
        fi

        # Not running.
        if [ "$seen_running" -eq 0 ] && [ "$elapsed" -lt "$min_wait" ]; then
            sleep 2
            continue
        fi

        if [ "$seen_running" -eq 1 ]; then
            sleep 1  # short settle delay after closure
        fi
        return 0
    done
}
WAIT_HELPER_EOF

chmod 644 /usr/local/lib/noid-privacy/wait-fedora-welcome.sh
chown root:root /usr/local/lib/noid-privacy/wait-fedora-welcome.sh

# Syntax check the embedded helper
if ! bash -n /usr/local/lib/noid-privacy/wait-fedora-welcome.sh; then
    echo "[Module 13] FAIL: wait-fedora-welcome.sh has syntax errors"
    exit 1
fi

echo "  [OK] /usr/local/lib/noid-privacy/wait-fedora-welcome.sh installed"

# ----------------------------------------------------------------------------
# Step 5f: Install the shared NoID Privacy application design contract
# ----------------------------------------------------------------------------
# Presentation-only GTK4/libadwaita helpers shared by all four first-party apps.
# Product/security state remains in each owning app; this module standardizes
# window identity, spacing, action rows, toasts and accessibility labels.
echo ""
echo "[Step 5f] Installing /usr/lib/noid-privacy/noid_ui.py"
install -d -m0755 -o root -g root /usr/lib/noid-privacy
cat > /usr/lib/noid-privacy/noid_ui.py <<'NOID_UI_PY_EOF'
"""Shared visual and interaction contract for NoID Privacy GTK applications.

This module owns presentation primitives only. It performs no network,
privileged, persistence or policy operation; each application retains its own
auditable product logic and passes user actions in as callbacks.
"""

import sys

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, GLib, Gdk

DEFAULT_WIDTH = 960
DEFAULT_HEIGHT = 800

COMMON_CSS = b"""
.noid-app-icon { margin-left: 6px; margin-right: 2px; }
.noid-emoji { font-size: 1.25rem; }
.noid-count { font-feature-settings: "tnum"; font-weight: 700; }
"""


def install_css(extra_css=b'', context='noid-ui'):
    """Install the common stylesheet plus an optional app-local extension."""
    try:
        provider = Gtk.CssProvider()
        payload = COMMON_CSS + (extra_css or b'')
        try:
            provider.load_from_data(payload)
        except TypeError:
            provider.load_from_string(payload.decode())
        display = Gdk.Display.get_default()
        if display is not None:
            Gtk.StyleContext.add_provider_for_display(
                display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    except (TypeError, UnicodeError, GLib.Error) as exc:
        print('%s: CSS setup failed: %s' % (context, exc), file=sys.stderr)


class NoIDApplication(Adw.Application):
    """One-instance application base with shared styling and window icon."""

    def __init__(self, application_id, icon_name, extra_css=b''):
        super().__init__(application_id=application_id,
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self._noid_icon_name = icon_name
        self._noid_extra_css = extra_css

    def do_startup(self):
        Adw.Application.do_startup(self)
        install_css(self._noid_extra_css, self.props.application_id)
        Gtk.Window.set_default_icon_name(self._noid_icon_name)


def _app_icon(icon_name):
    icon = Gtk.Image.new_from_icon_name(icon_name)
    icon.set_pixel_size(28)
    icon.add_css_class('noid-app-icon')
    icon.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
    return icon


def app_header(title, subtitle, icon_name):
    """Return the standard NoID Privacy identity header."""
    header = Adw.HeaderBar()
    header.set_title_widget(Adw.WindowTitle.new(title, subtitle))
    header.pack_start(_app_icon(icon_name))
    return header


def sectioned_app_bars(window, title, subtitle, icon_name, stack):
    """Return persistent identity, wide section, and narrow section bars.

    The identity uses the exact same app_header() contract as Setup, Update
    and Tools. A second native HeaderBar places the wide ViewSwitcher on its
    own row directly below that identity; a native AdwBreakpoint hides this
    row and reveals the bottom ViewSwitcherBar on narrow windows. This
    replaces deprecated Adw.ViewSwitcherTitle, which made Network's visible
    app identity disappear whenever its tabs fitted.
    """
    header = app_header(title, subtitle, icon_name)
    switcher = Adw.ViewSwitcher()
    switcher.set_stack(stack)
    switcher.set_policy(Adw.ViewSwitcherPolicy.WIDE)
    section_bar = Adw.HeaderBar()
    section_bar.set_show_start_title_buttons(False)
    section_bar.set_show_end_title_buttons(False)
    section_bar.set_title_widget(switcher)

    switcher_bar = Adw.ViewSwitcherBar()
    switcher_bar.set_stack(stack)
    bind_view_switcher_accessibility(switcher, stack)
    bind_view_switcher_accessibility(switcher_bar, stack)

    condition = Adw.BreakpointCondition.parse('max-width: 760sp')
    breakpoint = Adw.Breakpoint.new(condition)
    breakpoint.add_setter(section_bar, 'visible', False)
    breakpoint.add_setter(switcher_bar, 'reveal', True)
    window.add_breakpoint(breakpoint)
    return header, section_bar, switcher_bar


def toast(overlay, message, timeout=4):
    notification = Adw.Toast.new(message)
    notification.set_timeout(timeout)
    overlay.add_toast(notification)


def _find_text_label(widget, text):
    text = ' '.join(str(text or '').split())
    if not text:
        return None
    for child in _widget_descendants(widget):
        if isinstance(child, Gtk.Label) and \
                ' '.join((child.get_text() or '').split()) == text:
            return child
    return None


def _accessible_list(widget):
    # GTK 4.22's language-binding API takes its reference list through this
    # boxed type. `new_from_list` is required: the array constructor's GI
    # length annotation is not usable by PyGObject 3.56.
    return Gtk.AccessibleList.new_from_list([widget])


def _apply_accessible_text(widget, label, description,
                           label_widget=None, description_widget=None):
    if label_widget is not None:
        label_widget.set_accessible_role(Gtk.AccessibleRole.LABEL)
        widget.reset_property(Gtk.AccessibleProperty.LABEL)
        widget.update_relation(
            [Gtk.AccessibleRelation.LABELLED_BY],
            [_accessible_list(label_widget)])
    elif label:
        # Correct native fallback for icon-only controls, which have no text
        # widget to reference.
        widget.update_property([Gtk.AccessibleProperty.LABEL], [label])
    if description_widget is not None:
        description_widget.set_accessible_role(Gtk.AccessibleRole.LABEL)
        widget.reset_property(Gtk.AccessibleProperty.DESCRIPTION)
        widget.update_relation(
            [Gtk.AccessibleRelation.DESCRIBED_BY],
            [_accessible_list(description_widget)])
    elif description:
        widget.update_property(
            [Gtk.AccessibleProperty.DESCRIPTION], [description])


def accessible(widget, label, description=''):
    """Publish native GTK accessible text/relations for one control."""
    label = ' '.join(str(label or '').split())
    description = ' '.join(str(description or '').split())
    _apply_accessible_text(
        widget, label, description,
        _find_text_label(widget, label),
        _find_text_label(widget, description))
    return widget


def _prepare_row_text_labels(row):
    # Adw.ActionRow creates its private title/subtitle labels with the
    # presentation role.  Promote them before the first title assignment so
    # later dynamic updates are exposed through the row's native relations.
    # Prefix emoji and Update's ordinal step numbers are deliberately
    # decorative and keep that role.
    for child in _widget_descendants(row):
        if isinstance(child, Gtk.Label) and \
                not child.has_css_class('noid-emoji') and \
                not child.has_css_class('noid-step-num'):
            child.set_accessible_role(Gtk.AccessibleRole.LABEL)


def _sync_row_accessibility(row, description_override=None):
    label = row.get_title() if hasattr(row, 'get_title') else ''
    description = (description_override if description_override is not None
                   else (row.get_subtitle()
                         if hasattr(row, 'get_subtitle') else ''))
    label = ' '.join(str(label or '').split())
    description = ' '.join(str(description or '').split())
    label_widget = _find_text_label(row, label)
    description_widget = _find_text_label(row, description)
    # Libadwaita already publishes the correct native labelled-by relation
    # from a row/control to its private title widget. Preserve that relation
    # instead of overriding the composite accessible name; make its target an
    # explicit label and add only the missing subtitle-description relation.
    if label_widget is not None:
        label_widget.set_accessible_role(Gtk.AccessibleRole.LABEL)
    # Adw.SwitchRow and input rows expose a separate internal actionable
    # widget. Label that public activatable-widget surface as well, otherwise
    # AT-SPI sees a named row beside an anonymous switch/entry.
    control = (row.get_activatable_widget()
               if hasattr(row, 'get_activatable_widget') else None)
    targets = [row]
    if control is not None and control is not row:
        targets.append(control)
    for target in targets:
        if description_widget is not None:
            description_widget.set_accessible_role(Gtk.AccessibleRole.LABEL)
            target.reset_property(Gtk.AccessibleProperty.DESCRIPTION)
            target.update_relation(
                [Gtk.AccessibleRelation.DESCRIBED_BY],
                [_accessible_list(description_widget)])
        elif description:
            target.update_property(
                [Gtk.AccessibleProperty.DESCRIPTION], [description])


def accessible_row(row, description=None):
    """Keep row and internal control names synchronized with dynamic state."""
    _prepare_row_text_labels(row)
    _sync_row_accessibility(row, description)
    if hasattr(row, 'get_title'):
        row.connect('notify::title', lambda current, _pspec:
                    GLib.idle_add(
                        _sync_row_accessibility, current, description))
    if description is None and hasattr(row, 'get_subtitle'):
        row.connect('notify::subtitle', lambda current, _pspec:
                    GLib.idle_add(_sync_row_accessibility, current))
    row.connect('map', lambda current: GLib.idle_add(
        _sync_row_accessibility, current, description))
    return row


def _widget_descendants(widget):
    child = widget.get_first_child()
    while child is not None:
        yield child
        yield from _widget_descendants(child)
        child = child.get_next_sibling()


def _sync_view_switcher_accessibility(switcher, stack, attempt=0):
    pages = stack.get_pages()
    page_items = [pages.get_item(i) for i in range(pages.get_n_items())]
    buttons = [child for child in _widget_descendants(switcher)
               if isinstance(child, Gtk.ToggleButton)]
    if len(buttons) < len(page_items) and attempt < 20:
        GLib.timeout_add(
            100, _sync_view_switcher_accessibility,
            switcher, stack, attempt + 1)
        return GLib.SOURCE_REMOVE
    for button, page in zip(buttons, page_items):
        title = page.get_title() or page.get_name() or 'Application page'
        accessible(button, title, f'Show the {title} page')
    return GLib.SOURCE_REMOVE


def bind_view_switcher_accessibility(switcher, stack):
    """Name libadwaita's private page-tab buttons after they are realized."""
    accessible(switcher, 'Application sections',
               'Choose which application section is visible')
    switcher.connect(
        'map', lambda current: GLib.idle_add(
            _sync_view_switcher_accessibility, current, stack, 0))
    GLib.idle_add(_sync_view_switcher_accessibility, switcher, stack, 0)


def add_emoji_prefix(row, emoji):
    icon = Gtk.Label(label=emoji)
    icon.add_css_class('noid-emoji')
    icon.set_size_request(32, 32)
    icon.set_margin_start(4)
    icon.set_margin_end(8)
    icon.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
    row.add_prefix(icon)
    accessible_row(row)
    return icon


def add_icon_prefix(row, icon_name):
    """Add one native themed application icon using the emoji-row geometry."""
    icon = Gtk.Image.new_from_icon_name(icon_name)
    icon.set_pixel_size(32)
    icon.set_size_request(32, 32)
    icon.set_margin_start(4)
    icon.set_margin_end(8)
    icon.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
    row.add_prefix(icon)
    accessible_row(row)
    return icon


def action_row(emoji, title, subtitle, callback):
    row = Adw.ActionRow()
    row.set_title(title)
    row.set_subtitle(subtitle)
    row.set_activatable(True)
    add_emoji_prefix(row, emoji)
    action = Gtk.Button.new_from_icon_name('go-next-symbolic')
    action.add_css_class('flat')
    action.set_valign(Gtk.Align.CENTER)
    action.set_tooltip_text(title)
    accessible(action, title, subtitle)
    action.connect('clicked', lambda _button: callback(row))
    row.add_suffix(action)
    # Native Adw row activation forwards mouse/keyboard activation to the
    # button, while AT-SPI gets one real actionable control instead of a
    # visually clickable list item with no published action.
    row.set_activatable_widget(action)
    return row


def icon_action_row(icon_name, title, subtitle, callback):
    """Build an action row for a known application or system icon."""
    row = Adw.ActionRow()
    row.set_title(title)
    row.set_subtitle(subtitle)
    row.set_activatable(True)
    add_icon_prefix(row, icon_name)
    action = Gtk.Button.new_from_icon_name('go-next-symbolic')
    action.add_css_class('flat')
    action.set_valign(Gtk.Align.CENTER)
    action.set_tooltip_text(title)
    accessible(action, title, subtitle)
    action.connect('clicked', lambda _button: callback(row))
    row.add_suffix(action)
    row.set_activatable_widget(action)
    return row


def status_row(emoji):
    row = Adw.ActionRow()
    add_emoji_prefix(row, emoji)
    return row


def icon_button(icon_name, accessible_label, callback):
    button = Gtk.Button.new_from_icon_name(icon_name)
    button.add_css_class('flat')
    button.set_valign(Gtk.Align.CENTER)
    button.set_tooltip_text(accessible_label)
    accessible(button, accessible_label, accessible_label)
    button.connect('clicked', callback)
    return button
NOID_UI_PY_EOF
chmod 0644 /usr/lib/noid-privacy/noid_ui.py
chown root:root /usr/lib/noid-privacy/noid_ui.py
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/lib/noid-privacy/noid_ui.py 2>/dev/null || true
fi
echo "  [OK] shared NoID Privacy GTK design contract installed (644)"

# ----------------------------------------------------------------------------
# Step 6: Install noid-welcome.sh (first-boot notification)
# ----------------------------------------------------------------------------
#
# Runs as user via xdg autostart (not as root).
# Idempotent via state file in $XDG_STATE_HOME/noid-privacy/welcome-shown.
# Shows once per user account, then never again.
#
echo ""
echo "[Step 6] Installing /usr/local/bin/noid-welcome.sh"

cat > /usr/local/bin/noid-welcome.sh <<'NOID_WELCOME_PY_EOF'
#!/usr/bin/python3
"""NoID Privacy — Setup welcome dialog (GTK4 + libadwaita).

Replaces the zenity-based bash welcome.
Triggered by /etc/xdg/autostart/noid-welcome.desktop on first GNOME login
after gnome-initial-setup completes. Idempotent via state file.

Module 13 is the canonical welcome script. System-level USBGuard and platform
firmware state is exposed by noid-status instead of dead UI constants.
"""

import os
import stat
import sys
import time
import shutil
import shlex
import subprocess
import tempfile
import re
import pwd
from pathlib import Path

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, GLib
sys.path.insert(0, '/usr/lib/noid-privacy')
import noid_ui

# --- Constants ---------------------------------------------------------------
APP_ID = 'com.noidprivacy.Welcome'
LOGO_PATH = '/usr/share/pixmaps/noid-privacy-logo.png'
DOC_DIR = '/usr/share/doc/noid-privacy'
DNS_MODE_CLI = '/usr/local/sbin/noid-dns-mode'

STATE_DIR = Path(GLib.get_user_state_dir()) / 'noid-privacy'
STATE_FILE = STATE_DIR / 'welcome-shown'
FIRSTBOOT_REBOOT_MARKER = Path(
    '/var/lib/noid-privacy/.firstboot-cmdline-reboot-required')

PROCESS_ERRORS = (OSError, subprocess.SubprocessError, UnicodeError)
WP_MIC_SETTING_RE = re.compile(
    r'^Value: (true|false)(?: \(Saved: (true|false)\))?$')
ACTIVE_TOAST_OVERLAY = None


def _warn(context, exc):
    """Make best-effort UI fallbacks visible without exposing command output."""
    print('noid-welcome: %s: %s' % (context, exc), file=sys.stderr)


def _toast(message, timeout=4):
    if ACTIVE_TOAST_OVERLAY is not None:
        noid_ui.toast(ACTIVE_TOAST_OVERLAY, message, timeout)


def firstboot_reboot_pending():
    """Return true while an M01 boot-policy change still needs its restart.

    The root-owned marker adds a durable signal when M01 changed boot bytes. A
    symlink is never trusted as state, but still requires operator review and
    therefore keeps the warning visible.
    """
    if is_live_mode():
        return False
    if (not STATE_FILE.exists()
            or FIRSTBOOT_REBOOT_MARKER.exists()
            or FIRSTBOOT_REBOOT_MARKER.is_symlink()):
        return True
    try:
        snapper_state = subprocess.check_output(
            ['sudo', '-n', '/usr/libexec/noid-snapper-status'],
            text=True, timeout=3)
        return ' boot=reboot-required ' in ' {} '.format(
            snapper_state.strip())
    except PROCESS_ERRORS as exc:
        _warn('firstboot reboot-state detection failed', exc)
        return False

# --- Hardware/system detection -----------------------------------------------

def has_luks():
    try:
        out = subprocess.check_output(['lsblk', '-no', 'FSTYPE'], text=True, timeout=3)
        return 'crypto_LUKS' in out
    except PROCESS_ERRORS as exc:
        _warn('LUKS detection failed', exc)
        return False

def has_nvidia():
    try:
        out = subprocess.check_output(['lspci'], text=True, timeout=3)
        return 'NVIDIA' in out
    except PROCESS_ERRORS as exc:
        _warn('NVIDIA detection failed', exc)
        return False

def has_nvidia_proprietary():
    # libcuda, not nvidia_drv.so: this is a Wayland-only image, so the X11
    # session driver is never installed and its absence proves nothing. The
    # NVIDIA opt-in ships xorg-x11-drv-nvidia-cuda, which provides this file.
    return Path('/usr/lib64/libcuda.so.1').exists()

def read_status(path):
    try:
        return Path(path).read_text(errors='replace').strip()
    except OSError as exc:
        _warn('status file read failed', exc)
        return ''

def is_unit_enabled(unit_name):
    """Return True if a systemd unit is currently enabled."""
    try:
        result = subprocess.run(['systemctl', 'is-enabled', unit_name],
                                capture_output=True, text=True, timeout=3)
        return result.stdout.strip() == 'enabled'
    except PROCESS_ERRORS as exc:
        _warn('systemd unit-state query failed', exc)
        return False

def is_live_mode():
    """Return True if running from Live ISO (rootfs is overlay, /usr is RO)."""
    try:
        cmdline = Path('/proc/cmdline').read_text(errors='replace').split()
        return any(token == 'rd.live.image'
                   or token.startswith('rd.live.image=')
                   for token in cmdline)
    except OSError as exc:
        _warn('live-mode detection failed', exc)
        return False


def _is_passwordless_live_session():
    """Recognize only NoID Privacy's transient passwordless Live account."""
    try:
        return (is_live_mode()
                and pwd.getpwuid(os.getuid()).pw_name == 'liveuser'
                and Path('/run/initramfs/livedev').exists())
    except (KeyError, OSError) as exc:
        _warn('Live privilege-route detection failed', exc)
        return False


def _noninteractive_sudo_authorizes(argv):
    """True only when sudo policy runs this exact argv without a password.

    A plain `sudo -l <cmd>` exit status only proves the command is "permitted
    by the security policy" (sudo(8)), which the image's own
    `%wheel ALL=(ALL) ALL` rule satisfies for every wheel member. Whether `-l`
    may itself run unprompted is governed by sudoers(5) `listpw`, default
    `any`, which the unrelated NOPASSWD drop-ins this image ships already
    satisfy. The probe therefore succeeded for backends that have no sudoers
    rule at all, the sudo route was chosen, and `sudo -n --` then failed with
    "a password is required" while the provisioned polkit AUTH_ADMIN route went
    unused. The verbose listing prints the matching entry only and tags a
    passwordless rule as `Options: !authenticate`; that output is translated,
    so the C locale is forced here as everywhere else.
    """
    environment = dict(os.environ, LC_ALL='C.UTF-8', LANG='C.UTF-8')
    try:
        result = subprocess.run(
            ['/usr/bin/sudo', '-n', '-l', '-l', '--'] + argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            text=True,
            timeout=3,
            check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _warn('noninteractive sudo-route query failed', exc)
        return False
    if result.returncode != 0:
        return False
    listing = result.stdout or ''
    return ('!authenticate' in listing
            and listing.count('Matched:') == 1)


def _privileged_argv(argv):
    """Return a shell-free privilege route for one exact backend argv."""
    if (_is_passwordless_live_session()
            or _noninteractive_sudo_authorizes(argv)):
        # The Live account has no password but already has a transient
        # NOPASSWD grant. Installed systems may also carry an explicit
        # owner-authorized rule. sudo -n always fails closed without one.
        return ['/usr/bin/sudo', '-n', '--'] + argv
    return ['/usr/bin/pkexec'] + argv

# --- Process helpers ---------------------------------------------------------

def spawn_terminal(shell_cmd):
    """Open a graphical terminal running the given shell command."""
    candidates = [
        ('ptyxis', ['ptyxis', '--', 'bash', '-c']),
        ('gnome-terminal', ['gnome-terminal', '--', 'bash', '-c']),
        ('xterm', ['xterm', '-e', 'bash', '-c']),
    ]
    for binary, argv in candidates:
        if shutil.which(binary):
            try:
                subprocess.Popen(argv + [shell_cmd],
                                 stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 start_new_session=True)
                return True
            except OSError as exc:
                _warn('terminal launch failed', exc)
                continue
    _toast('Could not open a terminal. Run the command from Ptyxis instead.', 5)
    return False

def run_in_terminal(command_path):
    """Run one setup action in a transient terminal with ONE close prompt.

    Contract shared by every terminal-backed action row:
      - NOID_WELCOME_SPAWN=1 tells companion scripts the wrapper owns the
        hold, so their standalone return_to_menu_prompt() becomes a no-op
        (otherwise the user pressed ENTER twice on success).
      - The wrapper always holds once so the summary stays readable on
        every terminal (gnome-terminal/xterm close instantly on exit).
      - The trailing `exit 0` keeps the wrapper shell's status clean:
        Ptyxis keeps the window open with its own process-failed hold on
        any non-zero exit, which would add a second close interaction.
        Failure detail is already printed above the prompt."""
    spawn_terminal(
        'NOID_WELCOME_SPAWN=1 ' + command_path + '; rc=$?; echo; '
        '[ $rc -ne 0 ] && echo "Script exited with error (rc=$rc)"; '
        'read -r -p "Press ENTER to close..." || :; exit 0')

def spawn_app(argv_list):
    """Run a non-blocking GUI command (no terminal)."""
    try:
        subprocess.Popen(argv_list,
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         start_new_session=True)
        return True
    except OSError as exc:
        _warn('application launch failed', exc)
        _toast('Could not open the requested application.', 5)
        return False

def open_doc(filename):
    p = Path(DOC_DIR) / filename
    if p.exists():
        spawn_app(['xdg-open', str(p)])
    else:
        _toast('Documentation file is missing: %s' % filename, 5)

# --- Action handlers ---------------------------------------------------------

def act_change_password(_row):
    """GIS-bypass safety net.
    gnome-initial-setup creates the user account via accountsservice
    SetPassword() — admin-level D-Bus operation that BYPASSES
    pam_pwquality + Anaconda password_policies (verified upstream GNOME
    wiki PinAuthentication design — pam_chauthtok stack 'is not used by
    accountsservice's SetPassword'). Result: GIS accepts a weak password
    even though /etc/security/pwquality.conf requires minlen=15.

    NoID Privacy does NOT force pw-expiry (NIST 800-63B style — no scheduled
    password expiration). The user is reminded here to verify their
    password strength manually. Opening gnome-control-center user-
    accounts triggers the regular PAM stack (pam_chauthtok →
    pam_pwquality) which DOES enforce minlen=15 without a character-class
    composition rule."""
    spawn_app(['gnome-control-center', 'user-accounts'])


def act_run_updates(_row):
    """Launch system updates as the topmost welcome action.
    Threat-model alignment with Mythos/Glasswing 2026: <1% patch rate is the
    real bottleneck — at minimum NoID Privacy surfaces the update path as the first
    thing the user sees. Launches the same noid-update-all-launcher.sh that
    resolves the App-grid action to the NoID Privacy Update GUI and its owned
    live terminal."""
    spawn_app(['/usr/local/bin/noid-update-all-launcher.sh'])

def act_open_software_with_rpms(_row):
    """Open one GNOME Software session with appstream + dnf5 added.

    The helper refuses an already running Software process so it cannot change
    the plugin scope under a real install. It owns the user-facing diagnostic;
    this non-blocking Setup action therefore remains a normal GUI launch.
    """
    spawn_app(['/usr/local/bin/noid-gnome-software-rpm'])

def act_open_network_app(_row):
    """Launch the NoID Privacy Network app —
    standalone GTK4+libadwaita GUI for WAN-egress-strict toggle + LAN per-IP
    exceptions + network state overview. One of the four first-party apps
    beside Setup (this dialog), Update and Tools. Module 36."""
    spawn_app(['/usr/local/bin/noid-network'])

def act_open_network_lan(_row):
    """Open the Network app directly on its LAN Exceptions tab.

    The network-printer step is only actionable there. Landing on WAN Privacy
    would turn this row into an instruction to go looking for the right tab,
    which is the kind of hand-off the Setup dialog exists to remove.
    """
    spawn_app(['/usr/local/bin/noid-network', '--section', 'lan'])

def act_open_tools_app(_row):
    """Launch NoID Privacy Tools — the curated helper-command launcher
    (Module 37). Every user-facing noid-* CLI as a described, runnable
    row; the discoverability companion to this Setup dialog."""
    spawn_app(['/usr/local/bin/noid-tools'])

def act_luks_backup(_row):
    # run_in_terminal() owns the single close prompt; see its contract.
    run_in_terminal('/usr/local/bin/noid-luks-backup.sh')

def act_vpn_setup(_row):
    open_doc('06-vpn-setup.md')


def _vpn_dns_compatibility_state():
    """Return True=opportunistic, False=strict, None=unsafe/mismatched."""
    try:
        result = subprocess.run(
            [DNS_MODE_CLI, '--status-machine'],
            capture_output=True, text=True, timeout=5, check=False)
    except PROCESS_ERRORS as exc:
        _warn('DNS compatibility state query failed', exc)
        return None
    lines = result.stdout.splitlines()
    if (result.returncode != 0 or len(lines) != 8
            or lines[0] != 'NOID-DNS-MODE-V2'):
        return None
    state = {}
    for line in lines[1:]:
        if line.count('=') != 1:
            return None
        key, value = line.split('=', 1)
        if not key or not value or key in state:
            return None
        state[key] = value
    if set(state) != {
            'selection', 'configured', 'runtime_global',
            'physical_configured', 'physical_runtime', 'scope', 'link_mode'}:
        return None
    if (state['configured'] == 'opportunistic'
            and state['runtime_global'] == 'opportunistic'
            and state['physical_runtime'] in {'none', 'opportunistic'}):
        return True
    if (state['configured'] == 'yes'
            and state['runtime_global'] == 'yes'
            and state['physical_runtime'] in {'none', 'yes'}):
        return False
    return None


def _start_vpn_dns_mode(switch, mode):
    try:
        proc = subprocess.Popen(
            _privileged_argv([DNS_MODE_CLI, mode]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True)
    except OSError as exc:
        _warn('DNS compatibility change failed to launch', exc)
        proc = None
    switch.set_sensitive(False)
    GLib.timeout_add(
        500, _resync_vpn_dns_when_done, switch, proc, [0])


def _resync_vpn_dns_when_done(switch, proc, attempts):
    attempts[0] += 1
    if proc is not None and proc.poll() is None and attempts[0] < 120:
        return True
    state = _vpn_dns_compatibility_state()
    if state is not None and switch.get_active() != state:
        switch.handler_block_by_func(on_vpn_dns_compatibility_toggle)
        switch.set_active(state)
        switch.handler_unblock_by_func(on_vpn_dns_compatibility_toggle)
    switch.set_sensitive(state is not None)
    if proc is None or proc.returncode not in {0, None}:
        _toast('DNS transport was not changed; previous state restored.', 5)
    return False


def on_vpn_dns_compatibility_toggle(switch, _pspec):
    if not switch.get_active():
        _start_vpn_dns_mode(switch, 'strict')
        return
    dialog = Adw.AlertDialog.new(
        'Enable pre-VPN DNS compatibility?',
        'Use this before VPN setup only when strict DNS-over-TLS on the '
        'physical uplink prevents resolving the VPN endpoint. Quad9 and '
        'managed physical profiles still try DoT, but an interfered or '
        'incompatible network can downgrade them to unauthenticated plaintext '
        'DNS on port 53. This mode persists until Strict is selected again. '
        'It does not control DNS inside the tunnel: an unset tunnel transport '
        'separately inherits NoID Privacy\'s best-effort opportunistic default, '
        'which can also fall back to DNS/53. An explicit VPN profile value wins.')
    dialog.add_response('cancel', 'Cancel')
    dialog.add_response('enable', 'Enable compatibility')
    dialog.set_default_response('cancel')
    dialog.set_close_response('cancel')

    def on_response(_dialog, response):
        if response == 'enable':
            _start_vpn_dns_mode(switch, 'opportunistic')
        else:
            switch.handler_block_by_func(
                on_vpn_dns_compatibility_toggle)
            switch.set_active(False)
            switch.handler_unblock_by_func(
                on_vpn_dns_compatibility_toggle)

    dialog.connect('response', on_response)
    dialog.present(switch.get_root())

def act_codecs(_row):
    run_in_terminal('/usr/local/bin/noid-complete-setup.sh')

def act_firefox_drm(_row):
    """Explicit profile-local Widevine consent for streaming services.
    Keep this beside the codec action: Prime Video and Netflix need both the
    ordinary media stack and Firefox's separately downloaded proprietary CDM.
    The row names that privacy cost; the helper asks independently for both
    supported profiles, refuses to mutate an in-use profile and records each
    durable consent before Firefox is restarted."""
    run_in_terminal('/usr/local/bin/noid-firefox-drm enable')

def act_nvidia_install(_row):
    run_in_terminal('/usr/local/bin/noid-nvidia-install.sh')

def act_install_claude_code(_row):
    """Opt-in Anthropic Claude Code CLI + optional VSCodium extension.
    Helper /usr/local/bin/noid-claude-install runs in user-context (no sudo);
    each component sits behind its own [y/N] prompt and installs one exact
    SHA256-pinned artefact (native CLI from Anthropic's versioned release
    CDN, VSIX from Open VSX). No remote shell script and no npm. System-wide
    directives are at /etc/claude-code/CLAUDE.md; noid-update-all.sh
    refreshes only opted-in components once installed."""
    run_in_terminal('/usr/local/bin/noid-claude-install')

def act_install_codex(_row):
    """Opt-in OpenAI Codex CLI + optional VSCodium extension install.
    The helper downloads exact SHA256-pinned native release artefacts; it
    neither executes a remote installer nor uses npm. Each component sits
    behind its own [y/N] prompt; the extension prompt is telemetry-aware
    because its telemetry cannot be disabled like Claude's. Shared CLI/IDE
    security defaults live in /etc/codex/config.toml; noid-update-all.sh
    refreshes only opted-in components once installed."""
    run_in_terminal('/usr/local/bin/noid-codex-install')

def act_install_protonvpn(_row):
    """Opt-in Proton VPN GUI via the official Proton Fedora repository.
    Helper /usr/local/bin/noid-protonvpn-install pins the published Proton
    repo signing-key fingerprint and verifies it BEFORE any key import or
    package install (no blind key-accept); later updates arrive through
    the repo via the normal dnf/noid-update-all path."""
    run_in_terminal('/usr/local/bin/noid-protonvpn-install')

def act_install_mullvad(_row):
    """Opt-in Mullvad VPN app via the official Mullvad RPM repository.
    Helper /usr/local/bin/noid-mullvad-install fetches the vendor repo
    definition, pins Mullvad's published code-signing key fingerprint and
    verifies it BEFORE import; later updates arrive through the repo via
    the normal dnf/noid-update-all path."""
    run_in_terminal('/usr/local/bin/noid-mullvad-install')

# Welcome AIDE switch controls popup delivery and remains insensitive until a
# user-reviewed active database exists. Timer control stays in the explicit
# noid-toggle-aide CLI.
AIDE_TIMER_UNIT = 'aide-check.timer'
AIDE_STATUS_HELPER = '/usr/libexec/noid-aide-status'
AIDE_NOTIFY_DROPIN = '/etc/systemd/system/aide-check.service.d/notify.conf'
AIDE_NOTIFY_TEMPLATE = '/usr/share/doc/noid-privacy/aide-notify-dropin.conf'

def _aide_database_state():
    """Read only the fixed root-published AIDE state schema."""
    argv = [AIDE_STATUS_HELPER]
    if os.geteuid() != 0:
        argv = ['/usr/bin/sudo', '-n', AIDE_STATUS_HELPER]
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=3, check=True)
    except PROCESS_ERRORS:
        return 'unavailable'
    lines = result.stdout.splitlines()
    if (len(lines) != 2 or lines[0] != 'NOID_AIDE_STATE_V1'
            or not lines[1].startswith('STATE=')):
        return 'unavailable'
    state = lines[1].removeprefix('STATE=')
    return state if state in {'active', 'absent', 'unsafe'} else 'unavailable'

def _is_aide_popup_enabled():
    # Layer 2 (GNOME popup) state — represented by presence of the
    # aide-check.service.d/notify.conf drop-in. Layer 1 (aide-check.timer)
    # state is independent and requires an active reviewed baseline.
    try:
        status = os.lstat(AIDE_NOTIFY_DROPIN)
        template_status = os.lstat(AIDE_NOTIFY_TEMPLATE)
        if not (stat.S_ISREG(status.st_mode)
                and stat.S_ISREG(template_status.st_mode)
                and status.st_uid == status.st_gid == 0
                and template_status.st_uid == template_status.st_gid == 0
                and stat.S_IMODE(status.st_mode) == 0o644
                and stat.S_IMODE(template_status.st_mode) == 0o644
                and status.st_nlink == template_status.st_nlink == 1):
            return False
        return Path(AIDE_NOTIFY_DROPIN).read_bytes() == \
            Path(AIDE_NOTIFY_TEMPLATE).read_bytes()
    except (OSError, ValueError):
        return False

def _privileged_action_async(argv):
    """Start one exact privileged helper and return its process handle."""
    try:
        return subprocess.Popen(
            _privileged_argv(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True)
    except OSError as exc:
        _warn('privileged action launch failed', exc)
        return None

def _resync_switch_when_done(switch, proc, on_handler, state_reader,
                             attempts):
    """Poll a privilege action for at most 60s, then show actual state."""
    attempts[0] += 1
    if proc is not None and proc.poll() is None and attempts[0] < 120:
        return True
    if proc is not None and proc.poll() is None:
        _warn('privileged action exceeded the UI resync deadline',
              TimeoutError('60-second privilege-action deadline'))
        _toast('The privileged action is still running; showing current state.',
               5)
    actual = state_reader()
    if switch.get_active() != actual:
        switch.handler_block_by_func(on_handler)
        switch.set_active(actual)
        switch.handler_unblock_by_func(on_handler)
    return False

def on_aide_toggle(switch, _pspec):
    # Routes to noid-toggle-aide popup-on/popup-off — Layer 2 only.
    # Installed sessions prefer an exact already-authorized sudo route, then
    # fall back to M08's uncached AUTH_ADMIN exact-program pin. The exact
    # passwordless Live session always uses its transient sudo -n route.
    target = 'popup-on' if switch.get_active() else 'popup-off'
    proc = _privileged_action_async(
        ['/usr/local/sbin/noid-toggle-aide', target])
    GLib.timeout_add(500, _resync_switch_when_done, switch, proc,
                     on_aide_toggle, _is_aide_popup_enabled, [0])

def on_audit_toggle(switch, _pspec):
    # Use dedicated argument-validating wrapper
    # /usr/local/sbin/noid-toggle-audit-notify (M12 Step 9b), whose exact
    # path is pinned to uncached AUTH_ADMIN by M08. Earlier design called
    # broad `pkexec systemctl enable --now audit-notify.service` directly.
    target = 'on' if switch.get_active() else 'off'
    proc = _privileged_action_async(
        ['/usr/local/sbin/noid-toggle-audit-notify', target])
    GLib.timeout_add(500, _resync_switch_when_done, switch, proc,
                     on_audit_toggle,
                     lambda: is_unit_enabled('audit-notify.service'), [0])

# Hardware-privacy toggle helpers — moved from
# the deprecated noid-setup-wizard into the welcome dialog. Module 17
# ships the dconf defaults at disable-microphone=true / disable-camera=true
# but explicitly does NOT lock mic, camera, or location. The locks file covers
# autorun, thumbnailers, remote desktop and other image-owned defaults;
# these user-facing switches therefore persist through gsettings.

def _gsetting_is_true(schema, key, fallback):
    try:
        out = subprocess.check_output(['gsettings', 'get', schema, key],
                                      text=True, timeout=3)
        return out.strip() == 'true'
    except PROCESS_ERRORS as exc:
        _warn('gsettings query failed; using conservative UI fallback', exc)
        return fallback

def _gsetting_set_bool(schema, key, value):
    spawn_app(['gsettings', 'set', schema, key,
               'true' if value else 'false'])

# The microphone toggle controls both persistent policy layers.
# Background: the dconf key `org.gnome.desktop.privacy.disable-microphone`
# is the GNOME "App-permission" layer — it stops sandboxed apps from
# requesting microphone access. It does NOT mute the PipeWire source.
# M17's required WirePlumber component owns actual capture-source mute and
# persists `noid.microphone.disabled`. The hardware mic-mute key and GNOME
# Settings → Audio remain an orthogonal manual-mute layer. The Welcome switch
# invokes the transactional CLI and OR-combines all three on read.

def _pipewire_source_ids():
    """All PipeWire capture-source node IDs, enumerated from `wpctl status` —
    NOT @DEFAULT_AUDIO_SOURCE@, which resolves to -1 when no default source is
    configured (then set-mute is a no-op) and would only cover one of several
    mics (e.g. analog + digital DMIC). Parses the audio Sources block only."""
    try:
        out = subprocess.check_output(['wpctl', 'status'],
                                      text=True, timeout=4,
                                      stderr=subprocess.DEVNULL)
    except PROCESS_ERRORS as exc:
        _warn('PipeWire source enumeration failed', exc)
        return []
    ids = []
    in_sources = False
    for line in out.splitlines():
        if 'Sources:' in line:
            in_sources = True
            continue
        if in_sources:
            if 'Filters:' in line:
                break  # stay inside the audio Sources block (skip Video/Streams)
            s = line.strip()
            i = 0
            while i < len(s) and not s[i].isdigit():
                i += 1
            j = i
            while j < len(s) and s[j].isdigit():
                j += 1
            if i < j and j < len(s) and s[j] == '.':
                ids.append(s[i:j])
    return ids

def _pipewire_get_mic_muted():
    """True only if EVERY capture source is muted, False if any is still live,
    None if unknown (no sources / wpctl missing)."""
    ids = _pipewire_source_ids()
    if not ids:
        return None
    for sid in ids:
        try:
            out = subprocess.check_output(['wpctl', 'get-volume', sid],
                                          text=True, timeout=2,
                                          stderr=subprocess.DEVNULL)
            if '[MUTED]' not in out:
                return False
        except PROCESS_ERRORS as exc:
            _warn('PipeWire mute-state query failed', exc)
            return None
    return True

def _wireplumber_mic_policy_disabled():
    """Read M17's dynamic WirePlumber policy. Return None if unavailable or
    malformed; callers treat unknown as privacy-disabled (fail closed)."""
    try:
        out = subprocess.check_output(
            ['wpctl', 'settings', 'noid.microphone.disabled'],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
    except PROCESS_ERRORS as exc:
        _warn('WirePlumber microphone-policy query failed', exc)
        return None
    match = WP_MIC_SETTING_RE.fullmatch(out.strip())
    if match is None:
        _warn('WirePlumber microphone-policy output malformed',
              ValueError('unexpected wpctl settings output'))
        return None
    return match.group(1) == 'true'

def _mic_is_disabled_any_layer():
    """OR-combine app block, persistent source policy and manual source mute."""
    dconf_off = _gsetting_is_true('org.gnome.desktop.privacy',
                                  'disable-microphone', False)
    wp_policy_off = _wireplumber_mic_policy_disabled()
    pw_muted = _pipewire_get_mic_muted()
    return dconf_off or (wp_policy_off is not False) or (pw_muted is True)

def on_mic_toggle(switch, _pspec):
    target = switch.get_active()
    command = 'off' if target else 'on'
    if not spawn_app(['/usr/local/bin/noid-toggle-microphone', command]):
        _resync_mic(switch)
        return
    # The helper waits for dconf and WirePlumber state-file durability. Resync
    # after its bounded transaction and snap back on any fail-closed result.
    GLib.timeout_add_seconds(8, _resync_mic, switch)

def _resync_mic(switch):
    actual = _mic_is_disabled_any_layer()
    if switch.get_active() != actual:
        switch.handler_block_by_func(on_mic_toggle)
        switch.set_active(actual)
        switch.handler_unblock_by_func(on_mic_toggle)
    return False

def on_cam_toggle(switch, _pspec):
    _gsetting_set_bool('org.gnome.desktop.privacy', 'disable-camera',
                       switch.get_active())
    GLib.timeout_add_seconds(2, _resync_cam, switch)

def _resync_cam(switch):
    actual = _gsetting_is_true(
        'org.gnome.desktop.privacy', 'disable-camera', False)
    if switch.get_active() != actual:
        switch.handler_block_by_func(on_cam_toggle)
        switch.set_active(actual)
        switch.handler_unblock_by_func(on_cam_toggle)
    return False

# Bluetooth + Location toggles. Bluetooth's privileged state machine
# lives in /usr/local/sbin/noid-toggle-bluetooth. Location directly uses its
# per-user GNOME setting; M08's helper exposes the same setting to the CLI.
# Installed sessions prefer an exact already-authorized sudo route, then use
# polkit rule 60-noid-toggle-privacy-services.rules and uncached AUTH_ADMIN for
# wheel-local-active subjects. The exact Live session always uses its transient
# NOPASSWD sudo route because liveuser has no password.
# Switch ACTIVE = privacy-default (disabled). Bluetooth's state source is its
# flag plus live rfkill; Location's source is its Gio.Settings key.

BT_FLAG = '/var/lib/noid-privacy/bluetooth-disabled.flag'

def _flag_file_present(path):
    try:
        Path(path).lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        _warn('privacy flag query failed; assuming disabled', exc)
        return True  # privacy-safe fallback
    return True

def _privileged_toggle_async(svc, target_disabled):
    """Spawn noid-toggle-<svc> through the session's privilege route.

    Returns a Popen handle so
    the resync can wait for actual exit (polkit prompt + CLI run can take
    5-15s; a fixed 2s timeout would race-flip the switch back)."""
    mode = 'off' if target_disabled else 'on'
    return _privileged_action_async(
        ['/usr/local/sbin/noid-toggle-' + svc, mode])

def _resync_when_done(switch, proc, on_handler, flag_path, post_action,
                      attempts):
    """Poll the privileged subprocess every 500ms until exit or timeout,
    optionally run a post-action (e.g. user-level gsetting sync), then
    sync the switch state to the flag-file truth. post_action runs in
    user-context (welcome.sh's own UID) so it can write per-user dconf."""
    attempts[0] += 1
    if proc is not None and proc.poll() is None and attempts[0] < 120:
        return True  # keep polling (60s max)
    if post_action is not None:
        try:
            post_action()
        except (OSError, subprocess.SubprocessError, GLib.Error) as exc:
            _warn('privacy-toggle post-action failed', exc)
    actual = _flag_file_present(flag_path)
    if switch.get_active() != actual:
        switch.handler_block_by_func(on_handler)
        switch.set_active(actual)
        switch.handler_unblock_by_func(on_handler)
    return False

def on_bluetooth_toggle(switch, _pspec):
    # No user-gsetting analog for BT — system-level mask + wireplumber
    # config + rfkill cover the full stack.
    proc = _privileged_toggle_async('bluetooth', switch.get_active())
    GLib.timeout_add(500, _resync_when_done, switch, proc,
                     on_bluetooth_toggle, BT_FLAG, None, [0])

def on_location_toggle(switch, _pspec):
    # location is now the camera/microphone model — no dconf-lock, geoclue
    # unmasked (M08 / M17). Drive the per-user gsetting
    # directly (no pkexec / flag), exactly like the mic/cam rows.
    # Switch ACTIVE = privacy-default (disabled) = location enabled=false.
    _gsetting_set_bool('org.gnome.system.location', 'enabled',
                       not switch.get_active())
    GLib.timeout_add_seconds(2, _resync_location, switch)

def _resync_location(switch):
    disabled = not _gsetting_is_true(
        'org.gnome.system.location', 'enabled', True)
    if switch.get_active() != disabled:
        switch.handler_block_by_func(on_location_toggle)
        switch.set_active(disabled)
        switch.handler_unblock_by_func(on_location_toggle)
    return False


# --- Live external-change listeners -------------------------------
# The hardware-privacy switches must mirror the single source of truth in both
# directions, not only when the user clicks them here: GNOME Settings and the
# noid-toggle-* CLIs write the same state. cam/mic/location bind
# Gio.Settings 'changed::' on the keys GNOME Settings writes; Bluetooth has no
# gsetting and watches its flag file instead. Everything routes through the
# _resync_* helpers, which block notify::active while writing, so there is no
# feedback loop.

def _bt_is_disabled_any_layer():
    """BT counts as disabled if the NoID Privacy flag is present OR rfkill reports it
    blocked (mirrors the mic OR-combine)."""
    if _flag_file_present(BT_FLAG):
        return True
    try:
        out = subprocess.check_output(['rfkill', 'list', 'bluetooth'],
                                      text=True, timeout=2,
                                      stderr=subprocess.DEVNULL)
        return 'blocked: yes' in out.lower()
    except PROCESS_ERRORS as exc:
        _warn('Bluetooth rfkill query failed', exc)
        return _flag_file_present(BT_FLAG)

def _resync_bt(switch):
    actual = _bt_is_disabled_any_layer()
    if switch.get_active() != actual:
        switch.handler_block_by_func(on_bluetooth_toggle)
        switch.set_active(actual)
        switch.handler_unblock_by_func(on_bluetooth_toggle)
    return False

def _watch_flag_file(path, on_event):
    """Gio.FileMonitor on a flag-file; calls on_event() on any change. Returns
    the monitor (caller must keep a ref) or None. Best-effort."""
    try:
        gfile = Gio.File.new_for_path(path)
        mon = gfile.monitor_file(Gio.FileMonitorFlags.NONE, None)
        mon.connect('changed', lambda *_a: on_event())
        return mon
    except (OSError, TypeError, GLib.Error) as exc:
        _warn('privacy flag monitor setup failed', exc)
        return None

# --- Pure hardware-event watches ---------------------------------
# Two layers carry no gsetting and no flag file, so the watches above cannot
# see them: F4 mic-mute and the GNOME audio panel act on the PipeWire source
# mute, and the GNOME Bluetooth toggle and the hardware key act on rfkill.
# Both feed _resync_mic / _resync_bt, which OR-combine every layer and block
# the notify::active handler while writing, so there is no feedback loop.

def _fd_add_watch(fd, cond, cb):
    """Register an fd watch via the non-deprecated API, fallback to the old one."""
    try:
        from gi.repository import GLibUnix
        return GLibUnix.fd_add_full(GLib.PRIORITY_DEFAULT, fd, cond, cb)
    except (ImportError, AttributeError):
        return GLib.unix_fd_add_full(GLib.PRIORITY_DEFAULT, fd, cond, cb)

def _classify_fd_event(condition, in_mask, terminal_mask, read_call):
    """Return (keep_source, data_seen, error) for one readiness callback.

    The injected read_call keeps the state machine unit-testable without a
    live GLib loop or hardware descriptor.
    """
    terminal = bool(condition & terminal_mask)
    if not condition & in_mask:
        return (not terminal, False, None)
    try:
        data = read_call()
    except BlockingIOError:
        return (not terminal, False, None)
    except OSError as exc:
        return (False, False, exc)
    if not data:
        return (False, False, None)
    return (not terminal, True, None)

def _retire_pipewire_monitor(proc):
    """Close and reap a pw-mon whose fd watch reached a terminal state."""
    try:
        proc.stdout.close()
    except (OSError, AttributeError) as exc:
        _warn('PipeWire monitor stdout cleanup failed', exc)
    try:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=0.2)
        except (OSError, subprocess.TimeoutExpired) as exc:
            _warn('PipeWire monitor reap failed', exc)
    except OSError as exc:
        _warn('PipeWire monitor cleanup failed', exc)

def _watch_pipewire(on_event):
    """Watch `pw-mon` for PipeWire graph changes (F4 mic-mute + GNOME audio
    panel). Debounced. Best-effort; None if pw-mon missing. Keep the returned
    Popen ref alive on self."""
    try:
        proc = subprocess.Popen(['pw-mon'], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True,
                                start_new_session=True)
    except OSError as exc:
        _warn('PipeWire monitor launch failed', exc)
        return None
    pending = [False]
    def _drain(fd, cond):
        keep, data_seen, read_error = _classify_fd_event(
            int(cond), int(GLib.IOCondition.IN),
            int(GLib.IOCondition.HUP | GLib.IOCondition.ERR |
                GLib.IOCondition.NVAL),
            lambda: os.read(fd, 65536))
        if read_error is not None:
            exc = read_error
            _warn('PipeWire monitor read failed', exc)
        if data_seen and not pending[0]:
            pending[0] = True
            def _fire():
                pending[0] = False
                on_event()
                return False
            GLib.timeout_add(400, _fire)   # debounce: many events per mute
        if not keep:
            _retire_pipewire_monitor(proc)
            return False
        return True
    try:
        os.set_blocking(proc.stdout.fileno(), False)
        _fd_add_watch(proc.stdout.fileno(),
                      GLib.IOCondition.IN | GLib.IOCondition.HUP |
                      GLib.IOCondition.ERR | GLib.IOCondition.NVAL, _drain)
    except (OSError, AttributeError, TypeError, GLib.Error) as exc:
        _warn('PipeWire monitor watch setup failed', exc)
        _retire_pipewire_monitor(proc)
        return None
    return proc

def _watch_rfkill(on_event):
    """Watch /dev/rfkill for radio block/unblock (BT from GNOME Settings, the
    hardware key, rfkill CLI). Best-effort; None if it can't open. Keep the
    returned fd alive on self."""
    try:
        fd = os.open('/dev/rfkill', os.O_RDONLY | os.O_NONBLOCK)
    except OSError as exc:
        _warn('rfkill monitor open failed', exc)
        return None
    def _cb(fdesc, cond):
        keep, data_seen, read_error = _classify_fd_event(
            int(cond), int(GLib.IOCondition.IN),
            int(GLib.IOCondition.HUP | GLib.IOCondition.ERR |
                GLib.IOCondition.NVAL),
            lambda: os.read(fdesc, 64))
        if read_error is not None:
            exc = read_error
            _warn('rfkill monitor read failed', exc)
        if data_seen:
            on_event()
        if not keep:
            try:
                os.close(fdesc)
            except OSError as exc:
                _warn('rfkill monitor cleanup failed', exc)
            return False
        return True
    try:
        _fd_add_watch(fd, GLib.IOCondition.IN | GLib.IOCondition.HUP |
                      GLib.IOCondition.ERR | GLib.IOCondition.NVAL, _cb)
    except (OSError, TypeError, GLib.Error) as exc:
        _warn('rfkill monitor watch setup failed', exc)
        try:
            os.close(fd)
        except OSError as close_exc:
            _warn('rfkill monitor cleanup failed', close_exc)
        return None
    return fd

# Gaming-Mode toggle (opt-in Steam/Proton) — backend = M08 Step 1g
# /usr/local/sbin/noid-toggle-gaming (M01 ia32 policy + setsebool, then a
# separate post-reboot dnf steam stage). Polkit 60-noid-toggle-privacy-services
# pins uncached AUTH_ADMIN. UNLIKE the bluetooth/location toggles (privacy-
# default = switch-ON), gaming-mode is an opt-in hardening RELAXATION:
# switch ON = gaming ENABLED = flag PRESENT (default OFF = no flag = full
# hardening). A flag-query error is shown conservatively as enabled: the UI
# must not claim the relaxation is absent when it cannot verify that state.
GAMING_FLAG = '/var/lib/noid-privacy/gaming-mode.enabled'
GAMING_TOGGLE_CLI = '/usr/local/sbin/noid-toggle-gaming'
GAMING_COMPLETION_ROWS = {}

def _gaming_enabled():
    try:
        Path(GAMING_FLAG).lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        _warn('gaming-mode flag query failed; assuming enabled', exc)
        return True  # do not falsely claim full hardening on a stat error
    return True

def _gaming_steam_installed():
    try:
        result = subprocess.run(
            ['rpm', '-q', 'steam'], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except PROCESS_ERRORS as exc:
        _warn('Steam package-state query failed', exc)
        return False
    return result.returncode == 0

def _gaming_ia32_live():
    try:
        tokens = Path('/proc/cmdline').read_text(encoding='ascii').split()
    except (OSError, UnicodeError) as exc:
        _warn('Gaming live IA32 query failed', exc)
        return False
    return ('ia32_emulation=1' in tokens and 'vdso32=1' in tokens
            and 'ia32_emulation=0' not in tokens
            and 'vdso32=0' not in tokens)

def _sync_gaming_completion_row(row):
    """Render the explicit second stage without conflating it with policy."""
    if row is None:
        return
    if _gaming_steam_installed():
        row.set_title('Steam installation complete')
        row.set_subtitle('Steam is installed; Gaming Mode controls compatibility policy')
        row.set_sensitive(False)
    elif not _gaming_enabled():
        row.set_title('Complete Steam installation')
        row.set_subtitle('Enable Gaming Mode first')
        row.set_sensitive(False)
    elif not _gaming_ia32_live():
        row.set_title('Complete Steam installation')
        row.set_subtitle('Restart first so 32-bit package scriptlets can execute')
        row.set_sensitive(False)
    else:
        row.set_title('Complete Steam installation')
        row.set_subtitle('32-bit execution is active · opens the reviewed DNF transaction')
        row.set_sensitive(True)

def _set_gaming_switch_truth(switch, enabled):
    switch.handler_block_by_func(on_gaming_toggle)
    switch.set_active(enabled)
    switch.handler_unblock_by_func(on_gaming_toggle)

def _poll_gaming_enable_result(switch, result_path, completion_row, attempts):
    """Wait up to one hour for DNF/helper completion, then restore the UI."""
    attempts[0] += 1
    try:
        result_status = result_path.lstat()
    except FileNotFoundError:
        if attempts[0] < 7200:
            return True
        _warn('gaming-mode result timed out',
              TimeoutError('one-hour gaming-result deadline'))
        _toast('Gaming Mode timed out; showing the committed system state.', 5)
        result_text = ''
    except OSError as exc:
        _warn('gaming-mode result read failed', exc)
        result_text = ''
    else:
        if stat.S_ISREG(result_status.st_mode):
            try:
                result_text = result_path.read_text(encoding='ascii').strip()
            except (OSError, UnicodeError) as exc:
                _warn('gaming-mode result read failed', exc)
                result_text = ''
        else:
            _warn('gaming-mode result has an unsafe file type',
                  ValueError(str(result_path)))
            result_text = ''
    if result_text and not result_text.isdigit():
        _warn('gaming-mode result was malformed', ValueError(result_text))
    try:
        result_path.unlink(missing_ok=True)
    except OSError as exc:
        _warn('gaming-mode result cleanup failed', exc)
    _set_gaming_switch_truth(switch, _gaming_enabled())
    switch.set_sensitive(True)
    _sync_gaming_completion_row(completion_row)
    return False

def _start_gaming_enable_terminal(switch, completion_row):
    """Run either preparation or post-reboot install in the visible terminal."""
    runtime_dir = Path(GLib.get_user_runtime_dir())
    result_path = runtime_dir / (
        'noid-gaming-result-{}-{}'.format(os.getpid(), time.time_ns()))
    result_q = shlex.quote(str(result_path))
    shell_cmd = (
        'gaming_rc=125; result=' + result_q + '; '
        'publish_result() { umask 077; tmp="${result}.tmp.$$"; '
        'printf "%s\\n" "$gaming_rc" > "$tmp" && '
        'mv -f -- "$tmp" "$result"; }; '
        "trap 'publish_result' EXIT; "
        "trap 'publish_result; exit 129' HUP INT TERM; "
        + shlex.join(_privileged_argv([GAMING_TOGGLE_CLI, 'on']))
        + '; gaming_rc=$?; publish_result; '
        'trap - EXIT HUP INT TERM; echo; '
        '[ "$gaming_rc" -ne 0 ] && '
        'echo "Gaming-mode enable exited rc=$gaming_rc"; '
        # The result file above carries the real rc for the switch resync;
        # exit 0 keeps Ptyxis from adding a second process-failed hold.
        'read -r -p "Press ENTER to close..." || :; '
        'exit 0')
    _set_gaming_switch_truth(switch, _gaming_enabled())
    switch.set_sensitive(False)
    if completion_row is not None:
        completion_row.set_sensitive(False)
    if spawn_terminal(shell_cmd):
        GLib.timeout_add(500, _poll_gaming_enable_result,
                         switch, result_path, completion_row, [0])
    else:
        switch.set_sensitive(True)
        _set_gaming_switch_truth(switch, _gaming_enabled())
        _sync_gaming_completion_row(completion_row)

def _poll_gaming_disable_result(switch, proc, completion_row, attempts):
    keep_polling = _resync_when_done(
        switch, proc, on_gaming_toggle, GAMING_FLAG, None, attempts)
    if not keep_polling:
        _sync_gaming_completion_row(completion_row)
    return keep_polling

def on_gaming_toggle(switch, _pspec):
    # Switch ON = enable gaming; OFF = restore hardening. Both confirm first;
    # both need a reboot for the ia32_emulation cmdline flip. Module-level
    # (like on_bluetooth_toggle) so handler_block_by_func matches reliably;
    # dialog parent = switch.get_root() (the WelcomeWindow).
    if switch.get_active():
        _gaming_enable_confirm(switch)
    else:
        _gaming_disable_confirm(switch)

def _gaming_enable_confirm(switch):
    dialog = Adw.AlertDialog.new(
        'Enable Gaming Mode?',
        'This re-opens two hardening surfaces so Steam and Proton can run:\n'
        '• 32-bit execution (ia32_emulation) — needs a REBOOT\n'
        '• W^X memory for Wine (selinuxuser_execmod)\n\n'
        'Steam is installed in the terminal only after you restart and run '
        'the visible completion step; this keeps 32-bit RPM scriptlets out of '
        'the hardened boot. There you can review the current DNF transaction and watch progress. '
        'SELinux stays '
        'Enforcing; all other hardening is '
        'unchanged. The helper verifies the transition and reports failures.')
    dialog.add_response('cancel', 'Cancel')
    dialog.add_response('enable', 'Enable Gaming Mode')
    dialog.set_response_appearance('enable', Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response('cancel')
    dialog.set_close_response('cancel')

    def on_response(_d, response):
        if response == 'enable':
            _start_gaming_enable_terminal(
                switch, GAMING_COMPLETION_ROWS.get(id(switch)))
        else:
            switch.handler_block_by_func(on_gaming_toggle)
            switch.set_active(False)
            switch.handler_unblock_by_func(on_gaming_toggle)

    dialog.connect('response', on_response)
    dialog.present(switch.get_root())

def _gaming_disable_confirm(switch):
    dialog = Adw.AlertDialog.new(
        'Disable Gaming Mode?',
        'Restores full NoID Privacy hardening: 32-bit execution off again '
        '(needs a REBOOT) and the Wine W^X boolean back off. Steam stays '
        'installed (remove it later with "sudo dnf remove steam").')
    dialog.add_response('cancel', 'Cancel')
    dialog.add_response('disable', 'Disable')
    dialog.set_response_appearance('disable',
                                   Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.set_default_response('cancel')
    dialog.set_close_response('cancel')

    def on_response(_d, response):
        if response == 'disable':
            # 'off' is fast (grubby + setsebool + rm flag, no download) — reuse
            # the silent privilege route + proc-poll resync shared with
            # Bluetooth. _privileged_toggle_async('gaming', True) -> 'off';
            # _resync_when_done reads the flag (absent after 'off') and settles
            # the switch OFF.
            proc = _privileged_toggle_async('gaming', True)
            GLib.timeout_add(
                500, _poll_gaming_disable_result, switch, proc,
                GAMING_COMPLETION_ROWS.get(id(switch)), [0])
        else:
            switch.handler_block_by_func(on_gaming_toggle)
            switch.set_active(True)
            switch.handler_unblock_by_func(on_gaming_toggle)

    dialog.connect('response', on_response)
    dialog.present(switch.get_root())

# Printing + USB device policy. Both are capability opt-ins rather than privacy
# defaults, so ON means the capability is AVAILABLE — the inverse of the
# Hardware Privacy switches, and the same direction as Gaming Mode above.
#
# M05 Step 4 masks cups.path/.service/.socket because LAN isolation is a
# product decision. Step 4b ships noid-toggle-printing so taking that decision
# back is a reviewed action instead of four hand-typed systemctl invocations.
# The backend never unmasks cups-browsed, avahi or wsdd and never touches the
# firewall, so enabling printing re-opens no discovery surface.
#
# USBGuard is whitelist-only: an unknown device is blocked on insertion and the
# desktop prompt authorizes it for the current session only, writing nothing to
# the policy. Nothing in the shipped UI said so, so a device allowed once came
# back blocked after a replug with no discoverable way to keep it.
PRINTING_TOGGLE_CLI = '/usr/local/sbin/noid-toggle-printing'
USBGUARD_DEVICES_CLI = '/usr/local/bin/noid-usbguard-devices'


def _is_unit_masked(unit_name):
    """True when systemd reports the unit as masked."""
    try:
        result = subprocess.run(['systemctl', 'is-enabled', unit_name],
                                capture_output=True, text=True, timeout=3)
        return result.stdout.strip() == 'masked'
    except PROCESS_ERRORS as exc:
        _warn('systemd mask-state query failed', exc)
        # Fail towards "printing unavailable": never claim a capability the
        # switch could not verify.
        return True


def _printing_enabled():
    """True when the print stack is opted in.

    noid-toggle-printing unmasks all three CUPS units and enables the two
    activation entry points, so an enabled cups.socket is the exact state it
    writes. cups.service is checked as well because a socket enabled beside a
    hand-masked service still prints nothing — one unit must not be trusted to
    represent the set.
    """
    return (is_unit_enabled('cups.socket')
            and not _is_unit_masked('cups.service'))


def on_printing_toggle(switch, _pspec):
    # Backend is M05 Step 4b, pinned to uncached AUTH_ADMIN by M08's polkit
    # rule; installed sessions prefer an exact already-authorized sudo route.
    # There is no flag file: the unit state the CLI writes is the truth, so
    # this resync reads that instead of _resync_when_done's flag probe.
    proc = _privileged_toggle_async('printing', not switch.get_active())
    GLib.timeout_add(500, _resync_printing_when_done, switch, proc, [0])


def _resync_printing_when_done(switch, proc, attempts):
    attempts[0] += 1
    if proc is not None and proc.poll() is None and attempts[0] < 120:
        return True
    actual = _printing_enabled()
    if switch.get_active() != actual:
        switch.handler_block_by_func(on_printing_toggle)
        switch.set_active(actual)
        switch.handler_unblock_by_func(on_printing_toggle)
    return False


# Laptop lid. Three states, not two, so a switch would have to misrepresent
# one of them: an explicit `lock`, an explicit `suspend`, and no pinned choice
# at all. The helper refuses to run as root and escalates itself through its
# own closed sudoers bridge (M17 / 49-noid-lid-action), so this must be invoked
# as the desktop user — the same call shape as the microphone row, never
# _privileged_argv.
LID_ACTION_CLI = '/usr/local/bin/noid-toggle-lid-action'
# Index order of the ComboRow model below; the two must stay in lockstep.
LID_ACTION_CHOICES = ('lock', 'suspend', 'reset')
LID_CHOICE_INDEX = {'lock': 0, 'suspend': 1, 'none': 2}


# systemd-logind's documented lid-handler values, each rendered as the sentence
# fragment it produces. Anything unmapped is never guessed — see below.
LID_EFFECT_PHRASES = {
    'lock': 'locks the screen',
    'suspend': 'suspends',
    'hibernate': 'hibernates',
    'suspend-then-hibernate': 'suspends, then hibernates',
    'hybrid-sleep': 'hybrid-sleeps',
    'poweroff': 'powers off',
    'halt': 'halts',
    'ignore': 'does nothing',
}


def _lid_effective_prose(effective):
    """Render the helper's `lid=… external-power=… docked=…` line as prose.

    Every other subtitle in this dialog is written for a reader; pasting the
    machine line in verbatim made this the only row that spoke in key=value.
    Returns the raw line unchanged when the field set or any value is
    unrecognised: an unreadable truth beats a readable guess.
    """
    fields = {}
    for token in effective.split():
        key, separator, value = token.partition('=')
        if separator:
            fields[key] = value
    wanted = ('lid', 'external-power', 'docked')
    if set(fields) != set(wanted):
        return effective
    try:
        battery, external, docked = (
            LID_EFFECT_PHRASES[fields[key]] for key in wanted)
    except KeyError:
        return effective
    if battery == external:
        head = '%s on battery and on external power' % battery
    else:
        head = '%s on battery, %s on external power' % (battery, external)
    return '%s; %s while docked' % (head, docked)


def _lid_action_state():
    """Return (hardware_present, choice, effective) from the helper's status.

    choice is 'lock', 'suspend', 'none', or None when the helper reports that
    its managed file was changed independently. None keeps the row from
    inventing a state it cannot verify.
    """
    try:
        out = subprocess.check_output(
            [LID_ACTION_CLI, 'status'], text=True, timeout=5,
            stderr=subprocess.DEVNULL)
    except PROCESS_ERRORS as exc:
        _warn('lid-action state query failed', exc)
        return (False, None, '')
    present = False
    choice = None
    effective = ''
    for line in out.splitlines():
        if line.startswith('Hardware: PRESENT'):
            present = True
        elif line.startswith('Explicit choice: none'):
            choice = 'none'
        elif line == 'Explicit choice: suspend':
            choice = 'suspend'
        elif line == 'Explicit choice: lock':
            choice = 'lock'
        elif line.startswith('Effective: '):
            effective = line[len('Effective: '):]
    return (present, choice, effective)


def on_lid_action_changed(combo, _pspec):
    index = combo.get_selected()
    if index >= len(LID_ACTION_CHOICES):
        return
    spawn_app([LID_ACTION_CLI, LID_ACTION_CHOICES[index]])
    GLib.timeout_add_seconds(4, _resync_lid_action, combo)


def _resync_lid_action(combo):
    _, choice, effective = _lid_action_state()
    target = LID_CHOICE_INDEX.get(choice)
    if target is not None and combo.get_selected() != target:
        combo.handler_block_by_func(on_lid_action_changed)
        combo.set_selected(target)
        combo.handler_unblock_by_func(on_lid_action_changed)
    if effective:
        combo.set_subtitle('Currently ' + _lid_effective_prose(effective))
    combo.set_sensitive(choice is not None)
    return False


def act_usbguard_devices(_row):
    """Open the reviewed USBGuard device manager in a terminal.

    The insertion prompt authorizes a device for the current session only.
    The manager shows runtime versus persistent authorization, delegates new
    admissions to the specialized helper and can revoke one exact durable
    rule. It is offered both under USB Devices and beside the USB-printer step
    where a user first meets a blocked device.

    Runs through sudo because the helper writes the durable USBGuard rules
    file and refuses a non-root caller outright: without it the terminal
    opened, printed "This helper must be run as root (use sudo)." and closed
    with rc=1, which reads as a broken row rather than a missing privilege.
    Module 37 already lists this exact command in its SUDO_ACTIONS; this row
    follows the same convention. It stays a terminal action rather than a
    pkexec one because the helper is an interactive numbered menu that needs
    a real stdin, and sudo prompts in that same terminal.
    """
    run_in_terminal('sudo ' + USBGUARD_DEVICES_CLI)


# App Autostart picker — NoID Privacy's included GNOME 50 autostart GUI.
# GNOME Settings does not expose this control on the shipped image; upstream
# GNOME Help documents the optional Tweaks Startup Applications page. Tweaks
# is omitted as redundant package/UI surface, not because it can bypass dconf:
# system locks take precedence over user-db writes. File-copy /usr/share/applications/
# <id>.desktop → $XDG_CONFIG_HOME/autostart/ is the canonical user-level
# XDG-spec pattern. This section automates it.
# Privacy nudge in group set_description() — apps with telemetry send data
# from login. User picks deliberately.
# All ops user-context (no sudo, no pkexec) — autostart dir is user-owned.
AUTOSTART_DIR = Path(GLib.get_user_config_dir()) / 'autostart'


def _xdg_app_dirs():
    """XDG-spec application directories per $XDG_DATA_DIRS + user/flatpak."""
    paths = []
    paths.append(Path.home() / '.local' / 'share' / 'applications')
    xdg_dirs = os.environ.get('XDG_DATA_DIRS', '/usr/local/share:/usr/share')
    for d in xdg_dirs.split(':'):
        if d:
            paths.append(Path(d.rstrip('/')) / 'applications')
    # Flatpak exports (user + system)
    paths.append(Path.home() / '.local' / 'share' / 'flatpak'
                 / 'exports' / 'share' / 'applications')
    paths.append(Path('/var/lib/flatpak/exports/share/applications'))
    # Dedupe + filter existing
    seen = set()
    result = []
    for p in paths:
        rp = p.resolve() if p.exists() else p
        key = str(rp)
        if key in seen:
            continue
        seen.add(key)
        if p.exists():
            result.append(p)
    return result


def _parse_desktop_file(path, include_masked=False):
    """Parse .desktop file with standard XDG filter. Returns dict or None.

    Normal app-picker entries exclude Hidden/NoDisplay. The current-autostart
    view includes those local entries so disabled masks and menu-hidden startup
    programs remain visible and removable."""
    try:
        content = Path(path).read_text(errors='replace')
    except OSError as exc:
        _warn('desktop-file read failed', exc)
        return None
    parser = {}
    in_entry = False
    for line in content.splitlines():
        s = line.strip()
        if s == '[Desktop Entry]':
            in_entry = True
            continue
        if s.startswith('[') and s.endswith(']'):
            in_entry = False
            continue
        if not in_entry or '=' not in s or s.startswith('#'):
            continue
        key, _, value = s.partition('=')
        key = key.strip()
        if key in parser:
            continue  # first wins (English baseline ignores Name[de]= etc)
        parser[key] = value.strip()
    if parser.get('Type', 'Application') != 'Application':
        return None
    hidden = parser.get('Hidden', 'false').lower() == 'true'
    no_display = parser.get('NoDisplay', 'false').lower() == 'true'
    if not include_masked and (hidden or no_display):
        return None
    only = parser.get('OnlyShowIn', '').strip()
    if not hidden and only \
       and 'GNOME' not in [x for x in only.split(';') if x]:
        return None
    not_show = parser.get('NotShowIn', '').strip()
    if not hidden and not_show \
       and 'GNOME' in [x for x in not_show.split(';') if x]:
        return None
    if not hidden and (not parser.get('Name') or not parser.get('Exec')):
        return None
    return {
        'path': str(path),
        'filename': Path(path).name,
        'name': parser.get('Name') or Path(path).stem,
        'comment': parser.get('Comment', ''),
        'icon': parser.get('Icon', 'application-x-executable'),
        'exec': parser.get('Exec', ''),
        'hidden': hidden,
        'no_display': no_display,
    }


def _scan_autostart_dir():
    """List current local autostart entries and masks, sorted by name."""
    if not AUTOSTART_DIR.exists():
        return []
    entries = []
    for f in AUTOSTART_DIR.glob('*.desktop'):
        info = _parse_desktop_file(f, include_masked=True)
        if info is not None:
            entries.append(info)
    entries.sort(key=lambda x: x['name'].lower())
    return entries


def _scan_available_apps():
    """List launchable apps from all XDG app dirs, dedup by filename,
    exclude apps already in autostart, sorted by name."""
    autostart_files = set()
    if AUTOSTART_DIR.exists():
        autostart_files = {f.name for f in AUTOSTART_DIR.glob('*.desktop')}
    seen_ids = set()
    apps = []
    for app_dir in _xdg_app_dirs():
        for f in app_dir.glob('*.desktop'):
            if f.name in autostart_files or f.name in seen_ids:
                continue
            info = _parse_desktop_file(f)
            if info is not None:
                seen_ids.add(f.name)
                apps.append(info)
    apps.sort(key=lambda x: x['name'].lower())
    return apps


def _autostart_recommends_netwait(entry):
    """Recommend the fail-open network gate only for recognizable VPN apps.

    This is a narrow initial value, not a lock: the row switch remains fully
    user-controlled.  Match semantic desktop metadata rather than one vendor
    filename so Proton, Mullvad and generic WireGuard/OpenVPN frontends
    follow the same provider-neutral path without delaying unrelated apps.
    """
    fields = (
        entry.get('filename', ''), entry.get('name', ''),
        entry.get('comment', ''), entry.get('exec', ''))
    text = ' '.join(fields).lower()
    return re.search(
        r'(?<![a-z0-9])(vpn|protonvpn|mullvad|wireguard|openvpn)'
        r'(?![a-z0-9])', text) is not None


def _autostart_add(source_desktop_path, target_filename,
                   enable_netwait=False):
    """Copy one XDG entry and optionally apply the fail-open network gate."""
    try:
        AUTOSTART_DIR.mkdir(parents=True, exist_ok=True)
        target = AUTOSTART_DIR / target_filename
        shutil.copy2(source_desktop_path, target)
        if enable_netwait:
            helper = Path(NETWAIT_CMD)
            if (not helper.is_file() or helper.is_symlink()
                    or not os.access(helper, os.X_OK)
                    or not _autostart_set_netwait(target_filename, True)):
                target.unlink(missing_ok=True)
                _warn('network-gated autostart creation failed', None)
                return False
        return True
    except OSError as exc:
        _warn('autostart entry creation failed', exc)
        return False


def _autostart_remove(filename):
    """Delete a file from the XDG autostart directory. User-context op."""
    try:
        target = AUTOSTART_DIR / filename
        if target.exists():
            target.unlink()
        return True
    except OSError as exc:
        _warn('autostart entry removal failed', exc)
        return False


# Per-entry network gate — see /usr/local/bin/noid-autostart-netwait.
# XDG autostart has no ordering contract with NetworkManager: gnome-session
# launches every entry as soon as the session is ready, regularly seconds before
# wifi association completes. A client that probes the network once at startup
# and does not retry then fails permanently, and the symptom looks like a
# firewall fault although nothing was dropped. Enabling the gate rewrites only
# the Exec= line of the *local* copy under ~/.config/autostart; the packaged
# launcher in /usr/share/applications is never touched. The wrapper fails open,
# so the worst case is a delayed start, never a missing app.
NETWAIT_CMD = '/usr/local/bin/noid-autostart-netwait'


def _netwait_enabled(exec_line):
    """True when this Exec= value already routes through the autostart gate."""
    return (exec_line or '').strip().startswith(NETWAIT_CMD + ' ')


def _netwait_strip(exec_line):
    """Return the application command without a leading gate invocation."""
    value = (exec_line or '').strip()
    if not _netwait_enabled(value):
        return value
    rest = value[len(NETWAIT_CMD):].lstrip()
    if rest.startswith('-- '):
        return rest[3:].lstrip()
    # A hand-edited entry may carry options between the command and '--'.
    sep = rest.find(' -- ')
    if sep >= 0:
        return rest[sep + 4:].lstrip()
    return rest


def _autostart_set_netwait(filename, enabled):
    """Rewrite the first Exec= of a local autostart entry, atomically.

    Only the [Desktop Entry] group's Exec= key changes. Every other line —
    comments, localized keys, other groups — is preserved byte-for-byte, so an
    entry stays exactly the vendor's file plus this one documented edit."""
    target = AUTOSTART_DIR / filename
    try:
        original = target.read_text(errors='replace')
    except OSError as exc:
        _warn('autostart entry read failed', exc)
        return False

    lines = original.splitlines(keepends=True)
    in_entry = False
    rewritten = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == '[Desktop Entry]':
            in_entry = True
            continue
        if stripped.startswith('[') and stripped.endswith(']'):
            in_entry = False
            continue
        if not in_entry or rewritten or not stripped.startswith('Exec='):
            continue
        bare = _netwait_strip(stripped[len('Exec='):])
        if not bare:
            _warn('autostart entry has an empty Exec', None)
            return False
        newline = '\n' if line.endswith('\n') else ''
        if enabled:
            lines[index] = 'Exec={} -- {}{}'.format(NETWAIT_CMD, bare, newline)
        else:
            lines[index] = 'Exec={}{}'.format(bare, newline)
        rewritten = True

    if not rewritten:
        _warn('autostart entry has no Exec= to gate', None)
        return False

    tmp = None
    try:
        mode = target.stat().st_mode & 0o7777
        fd, tmp = tempfile.mkstemp(
            dir=str(AUTOSTART_DIR), prefix='.' + filename + '.')
        with os.fdopen(fd, 'w') as handle:
            handle.write(''.join(lines))
        os.chmod(tmp, mode)
        os.replace(tmp, str(target))
        return True
    except OSError as exc:
        if tmp is not None and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        _warn('autostart network-gate update failed', exc)
        return False


def act_doc_getting_started(_row):
    open_doc('01-getting-started.md')

def act_open_doc_folder(_row):
    """Open the canonical installed documentation directory in Files."""
    p = Path(DOC_DIR)
    if p.is_dir():
        spawn_app(['xdg-open', str(p)])
    else:
        _toast('Documentation directory is missing.', 5)

def act_doc_hardware(_row):
    open_doc('08-masked-services.md')

def act_open_website(_row):
    """Open the project website from the Project & Ecosystem group
    in the default browser via xdg-open (same helper pattern as
    open_doc). User-initiated only — the OS itself never contacts these
    hosts (Silent-Machine posture, see 00-architecture.md)."""
    spawn_app(['xdg-open', 'https://noid-privacy.com/'])

def act_open_github(_row):
    """Open the GitHub account that gathers the open-source NoID Privacy
    projects — the Windows engine, the Linux audit tool, and this
    distro — in one place. Opens the account overview so every repo is one
    click away (same xdg-open pattern; user-initiated only)."""
    spawn_app(['xdg-open', 'https://github.com/NexusOne23'])

def act_open_donate(_row):
    """Open the donation page from the one-shot welcome
    dialog — deliberately NO timer/popup/nag (the same noise class M17
    locks off for the GNOME Foundation reminder and M35 disables for
    Thunderbird's appeal)."""
    spawn_app(['xdg-open', 'https://buymeacoffee.com/noidprivacy'])

def act_reboot(row):
    """User-controlled completion reboot from Welcome.

    M01 never surprises the user with a pre-GDM restart. When boot-policy bytes
    changed, its Root-owned marker remains pending and its equality seal remains
    absent until this deliberate, confirmed action activates the prepared state.
    The confirmed path calls `systemctl reboot` directly, NOT pkexec.
    org.freedesktop.login1.reboot is allow_active=yes for the local active
    session (no password), and logind still does the clean Wayland shutdown.
    pkexec was wrong: it routes through org.freedesktop.policykit.exec
    (auth_admin) which forced a password prompt for a plain reboot."""
    dialog = Adw.AlertDialog.new(
        'Restart NoID Privacy?',
        'The system will restart now. Save your work and close other apps '
        'before continuing.')
    dialog.add_response('cancel', 'Cancel')
    dialog.add_response('restart', 'Restart')
    dialog.set_response_appearance(
        'restart', Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.set_default_response('cancel')
    dialog.set_close_response('cancel')

    def on_response(_dialog, response):
        if response == 'restart':
            spawn_app(['systemctl', 'reboot'])

    dialog.connect('response', on_response)
    dialog.present(row.get_root())

# --- UI ----------------------------------------------------------------------

class WelcomeWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app,
                         default_width=noid_ui.DEFAULT_WIDTH,
                         default_height=noid_ui.DEFAULT_HEIGHT)
        self.set_title('NoID Privacy Setup')

        toolbar = Adw.ToolbarView()
        self.set_content(toolbar)

        # ---- Shared NoID Privacy identity header ----
        header = noid_ui.app_header(
            'NoID Privacy Setup', 'Guided system setup',
            'noid-privacy-setup')
        toolbar.add_top_bar(header)

        # ---- Body: common ToastOverlay + grouped PreferencesPage ----
        global ACTIVE_TOAST_OVERLAY
        self.toast_overlay = Adw.ToastOverlay()
        ACTIVE_TOAST_OVERLAY = self.toast_overlay
        page = Adw.PreferencesPage()
        self.toast_overlay.set_child(page)
        toolbar.set_content(self.toast_overlay)

        # RECOVERY FIRST — highest-stakes actions stay at the top.
        # Surface user-controlled update and recovery actions prominently.
        # LUKS Backup stays before VPN per the user-approved order.
        # feedback. LUKS header backup is irreversible-data-loss prevention
        # (highest stakes), VPN is network-privacy hardening (recoverable).
        # Account-password verification last because it's a safety-net
        # (user already chose a password; this row points them to settings
        # if they suspect it was weak).
        critical = Adw.PreferencesGroup()
        critical.set_title('Critical — Do These First')
        critical.set_description(
            'Prepare recovery for any encrypted volume and verify your '
            'account password.')
        if has_luks():
            critical.add(self._row('🔐', 'Back Up LUKS Header',
                                   'Adds a recovery path if LUKS metadata or '
                                   'required keyslots are damaged',
                                   act_luks_backup))
        # GIS-bypass safety-net row.
        # gnome-initial-setup created the account via accountsservice
        # SetPassword() — bypassing pam_pwquality and Anaconda password
        # policies. NoID Privacy does NOT force pw-expiry (NIST 800-63B style:
        # no scheduled password expiration). This row is the user-facing
        # reminder: open Settings → Users to change the password through
        # the PAM stack which DOES enforce minlen=15 without composition rules.
        critical.add(self._row('🔑', 'Verify Account Password Strength',
                               'GNOME setup wizard accepts weak '
                               'passwords. If you used a short password, '
                               'open Settings to change it — NoID Privacy '
                               'enforces 15+ characters there.',
                               act_change_password))
        page.add(critical)

        # VPN — own group directly after recovery, BEFORE updates/apps.
        # The image preaches VPN-first, so it also OFFERS the two main
        # privacy providers as direct pinned installs (official vendor
        # repos; the vendor signing-key fingerprint is verified before any
        # key import or package install). The provider-agnostic walkthrough
        # stays for every other provider.
        vpn = Adw.PreferencesGroup()
        vpn.set_title('VPN — Install Before Updates &amp; Apps')
        vpn.set_description(
            'Route traffic through your VPN from the very first update. '
            'Direct installs verify the official vendor signing key before '
            'any package is accepted.')
        dns_compat_state = _vpn_dns_compatibility_state()
        dns_compat_switch = Adw.SwitchRow()
        dns_compat_switch.set_title('Pre-VPN DNS compatibility')
        dns_compat_switch.set_subtitle(
            'Off keeps strict authenticated DoT on the physical uplink. '
            'Enable only if that prevents resolving the VPN endpoint; DNS/53 '
            'fallback then remains possible until Strict is restored. DNS '
            'inside the tunnel is a separate per-link setting.')
        noid_ui.add_emoji_prefix(dns_compat_switch, '🛜')
        dns_compat_switch.set_active(dns_compat_state is True)
        dns_compat_switch.set_sensitive(dns_compat_state is not None)
        dns_compat_switch.connect(
            'notify::active', on_vpn_dns_compatibility_toggle)
        noid_ui.accessible_row(dns_compat_switch)
        vpn.add(dns_compat_switch)
        if not is_live_mode():
            vpn.add(self._row('🛡️', 'Install Proton VPN',
                              'Official Proton Fedora repo — signing-key '
                              'fingerprint verified before install',
                              act_install_protonvpn))
            vpn.add(self._row('🔏', 'Install Mullvad VPN',
                              'Official Mullvad repo — code-signing key '
                              'fingerprint verified before install',
                              act_install_mullvad))
        vpn.add(self._row('🧭', 'Other Providers / Manual Setup',
                          'Provider-agnostic walkthrough (WireGuard, '
                          'OpenVPN profiles)', act_vpn_setup))
        page.add(vpn)

        # SYSTEM UPDATES — second step (after VPN tunnel is up)
        # Runs noid-update-all-launcher.sh — same chain as App-grid icon.
        updates = Adw.PreferencesGroup()
        updates.set_title('System Updates')
        updates.set_description(
            'Patch security vulnerabilities. Run AFTER your VPN is up so '
            'package downloads go through the tunnel.')
        updates.add(self._row('🔄', 'Update System Now',
                              'DNF + Flatpak + fwupd + AIDE check-only evidence + '
                              'kernel — runs in a terminal',
                              act_run_updates))
        page.add(updates)

        # SOFTWARE SOURCES — explicit per-launch RPM visibility. The ordinary
        # GNOME Software launcher remains Flatpak-only and fast; this action
        # writes no preference, enables no service and changes no repository.
        software_sources = Adw.PreferencesGroup()
        software_sources.set_title('GNOME Software Sources')
        software_sources.set_description(
            'Normal Software launches stay Flatpak-only. This one-time view '
            'adds the native RPM catalog without changing repositories, '
            'automatic updates, or the next launch.')
        software_sources.add(noid_ui.icon_action_row(
            'org.gnome.Software', 'Open GNOME Software with Fedora RPMs',
            'Shows RPMs from all enabled DNF repositories for this launch; '
            'use “Quit completely” afterward to release the DNF5 backend',
            act_open_software_with_rpms))
        page.add(software_sources)

        # HARDWARE PRIVACY — toggleable (defaults: ON for privacy)
        # Moved here from the deprecated noid-setup-wizard.
        # mic + cam are NOT in Module 17's dconf locks file (only location,
        # autorun, thumbnailers, remote-desktop are locked) — so user toggles
        # via gsettings persist correctly. Same toggle pattern as the AIDE +
        # audit-notify rows below.
        hw = Adw.PreferencesGroup()
        hw.set_title('Hardware Privacy')
        hw.set_description(
            'Block all apps from accessing your microphone, camera, '
            'Bluetooth, and location services. Re-enable per-feature '
            'here when you need them.')

        mic_switch = Adw.SwitchRow()
        mic_switch.set_title('Disable Microphone')
        mic_switch.set_subtitle('Block all apps from microphone access')
        self._add_emoji_prefix(mic_switch, '🎤')
        # OR-combine GNOME app block + persistent WirePlumber policy + current
        # source mute so the switch never claims that a disabled layer is on.
        mic_switch.set_active(_mic_is_disabled_any_layer())
        mic_switch.connect('notify::active', on_mic_toggle)
        # Live-mirror the GNOME Settings app-permission layer.
        # _resync_mic re-reads every layer so a gsettings change also refreshes
        # policy/hardware state.
        self._mic_settings = Gio.Settings.new('org.gnome.desktop.privacy')
        self._mic_settings.connect('changed::disable-microphone',
                                   lambda *_a: _resync_mic(mic_switch))
        # Pure hardware-event layer — F4 mic-mute + the GNOME audio
        # panel go through PipeWire source-mute (no gsetting); watch pw-mon so
        # the switch mirrors those live too. _resync_mic OR-combines all layers.
        self._mic_pwmon = _watch_pipewire(lambda: _resync_mic(mic_switch))
        hw.add(mic_switch)

        cam_switch = Adw.SwitchRow()
        cam_switch.set_title('Disable Camera')
        cam_switch.set_subtitle('Block all apps from camera access')
        self._add_emoji_prefix(cam_switch, '📷')
        cam_switch.set_active(_gsetting_is_true(
            'org.gnome.desktop.privacy', 'disable-camera', False))
        cam_switch.connect('notify::active', on_cam_toggle)
        # Live-mirror external changes (GNOME Settings writes the
        # same key). Keep the Settings object on self so the signal keeps firing.
        self._cam_settings = Gio.Settings.new('org.gnome.desktop.privacy')
        self._cam_settings.connect('changed::disable-camera',
                                   lambda *_a: _resync_cam(cam_switch))
        hw.add(cam_switch)

        # Privileged Bluetooth CLI plus native Location gsetting.
        bt_switch = Adw.SwitchRow()
        bt_switch.set_title('Disable Bluetooth')
        bt_switch.set_subtitle(
            'rfkill-block Bluetooth + silence wireplumber bluez probe')
        self._add_emoji_prefix(bt_switch, '📡')
        bt_switch.set_active(_flag_file_present(BT_FLAG))
        bt_switch.connect('notify::active', on_bluetooth_toggle)
        # Bluetooth has no gsetting — live-mirror via the flag file and the
        # noid-toggle-bluetooth CLI writes/removes.
        self._bt_flag_mon = _watch_flag_file(BT_FLAG,
                                             lambda: _resync_bt(bt_switch))
        # Pure hardware-event layer — the GNOME Settings Bluetooth
        # toggle + the hardware key go through rfkill (not the flag-file); watch
        # /dev/rfkill so the switch mirrors those live too. _resync_bt OR-combines.
        self._bt_rfkill = _watch_rfkill(lambda: _resync_bt(bt_switch))
        hw.add(bt_switch)

        loc_switch = Adw.SwitchRow()
        loc_switch.set_title('Disable Location Services')
        loc_switch.set_subtitle(
            'Turn off GNOME location services (GeoClue)')
        self._add_emoji_prefix(loc_switch, '📍')
        loc_switch.set_active(
            not _gsetting_is_true(
                'org.gnome.system.location', 'enabled', True))
        loc_switch.connect('notify::active', on_location_toggle)
        # Live-mirror external changes — GNOME Settings and the
        # noid-location-sync watcher both flip this key.
        self._loc_settings = Gio.Settings.new('org.gnome.system.location')
        self._loc_settings.connect('changed::enabled',
                                   lambda *_a: _resync_location(loc_switch))
        hw.add(loc_switch)

        page.add(hw)

        # DEVICES — one group for the two decisions that share a subject: what
        # this machine does with its own hardware, and what it accepts from
        # hardware you attach. Kept together rather than as two single-row
        # groups, where the heading and description cost more vertical space
        # than the controls themselves. Built-in first, attached second, which
        # is also the order the description reads in.
        #
        # The lid control is a ComboRow, not a switch: its helper has three
        # states — an explicit lock, an explicit suspend, and no pinned choice
        # at all — and a two-state widget would have to misrepresent one. The
        # USB control is an action rather than a toggle because the decision is
        # per device and only meaningful while that device is plugged in; the
        # policy stays owner-written and is never widened from this dialog.
        lid_present, lid_choice, lid_effective = _lid_action_state()
        devices = Adw.PreferencesGroup()
        devices.set_title('Devices')
        devices.set_description(
            'What this machine does with its own hardware, and what it '
            'accepts from hardware you attach. New USB devices stay blocked '
            'until you allow them, and the prompt shown when you plug one in '
            'lasts only for the current session.')
        lid_row = Adw.ComboRow()
        lid_row.set_title('Laptop Lid Action')
        lid_row.set_model(Gtk.StringList.new(
            ['Lock the screen', 'Suspend', 'System default']))
        self._add_emoji_prefix(lid_row, '🔋')
        if not lid_present:
            # Same treatment as the NVIDIA row: stay visible with the reason
            # inline so the option is discoverable on the machines that have it.
            lid_row.set_sensitive(False)
            lid_row.set_subtitle('No lid switch detected on this system')
        elif lid_choice is None:
            lid_row.set_sensitive(False)
            lid_row.set_subtitle(
                'The managed policy file was changed independently — inspect '
                'it with noid-toggle-lid-action status before changing it here')
        else:
            lid_row.set_subtitle(
                'Currently ' + _lid_effective_prose(lid_effective))
            lid_row.set_selected(LID_CHOICE_INDEX[lid_choice])
        # Connect after the initial selection so building the row does not
        # fire a policy change.
        lid_row.connect('notify::selected', on_lid_action_changed)
        noid_ui.accessible_row(lid_row)
        devices.add(lid_row)
        devices.add(self._row('🔌', 'Manage USB Devices',
                              'See temporary and permanent authorization, '
                              'allow blocked devices or revoke exact rules',
                              act_usbguard_devices))
        page.add(devices)

        # PRINTING — constructed beside Devices because its USB-printer row
        # reaches that group's helper, but added to the page later beside the
        # optional Media/Gaming capability groups. This keeps a seldom-used
        # service opt-in out of the high-priority hardware-privacy area.
        #
        # An explicit capability opt-in with its cost named, so ON means
        # AVAILABLE — the inverse of the privacy switches above.
        #
        # The two follow-up rows are not decoration: enabling CUPS alone
        # prints nothing on this image. A USB printer still needs a USBGuard
        # decision, and a network printer still needs an outbound LAN
        # exception because block-lan-out drops LAN egress by default.
        printing = Adw.PreferencesGroup()
        printing.set_title('Printing')
        printing.set_description(
            'Printing is off by default — no print service runs and no '
            'printer is discovered on the network. Turn it on if you use a '
            'printer, then follow the step for how yours is connected. '
            'Saving as PDF works either way and needs none of this.')
        printing_switch = Adw.SwitchRow()
        printing_switch.set_title('Enable Printing (CUPS)')
        printing_switch.set_subtitle(
            'Starts the local print service on demand. Automatic network '
            'discovery stays off — printers are added by address.')
        self._add_emoji_prefix(printing_switch, '🖨️')
        printing_switch.set_active(_printing_enabled())
        printing_switch.connect('notify::active', on_printing_toggle)
        printing.add(printing_switch)
        # Distinct prefixes from the USB Devices and Companion Apps rows above:
        # the suite contract requires every decorative prefix in this dialog to
        # be unique, and these two rows reach the same helpers from a different
        # starting point.
        printing.add(self._row('🔗', 'USB Printer — Manage the Device',
                               'Inspect its USBGuard state, allow it '
                               'permanently or revoke the exact rule',
                               act_usbguard_devices))
        printing.add(self._row('📠', 'Network Printer — Allow its Address',
                               'Opens NoID Privacy Network on LAN Exceptions '
                               "— add an outbound rule for the printer's IPv4 "
                               'address',
                               act_open_network_lan))
        # OPTIONAL — codecs / nvidia
        # Installed-system-only: the codec transaction runs through
        # noid-firstboot-setup.service, whose
        # ConditionKernelCommandLine=!rd.live.image makes a Live start a
        # no-op the wrapper can only report as a generic failure. Hide the
        # row there instead of offering a dead end. VP8/VP9 software decode
        # ships with the base image; this task adds the H.264/H.265 family
        # and the full-featured GPU decode drivers.
        # AI DEVELOPMENT TOOLS — own group: coding agents are a first-class
        # scenario on this image, not an afterthought buried in Optional.
        # Installs stay explicit opt-ins: both products require a vendor
        # account/network connection and process code/prompt context on
        # vendor infrastructure. Helpers refuse root and install only exact,
        # versioned, SHA256-pinned native artefacts (no npm, no remote shell).
        ai = Adw.PreferencesGroup()
        ai.set_title('AI Development Tools')
        ai.set_description(
            'Pinned, reviewable installs for the two supported coding '
            'agents. Opt-in: while in use both send prompts and selected '
            'code context to their vendor.')
        ai.add(self._row('🧠', 'Install Claude Code CLI / VSCodium Extension',
                         "Anthropic's pinned native CLI and/or pinned "
                         'extension, each behind its own prompt (no npm)',
                         act_install_claude_code))
        ai.add(self._row('🤖', 'Install Codex CLI / VSCodium Extension',
                         "Pinned native CLI and/or VSIX behind a separate "
                         'extension telemetry prompt (no npm)',
                         act_install_codex))
        page.add(ai)

        opt = Adw.PreferencesGroup()
        opt.set_title('Media &amp; Graphics')
        opt.set_description(
            'Optional additions for media playback and graphics. Install '
            'only what you need — none of these are required for core '
            'privacy.')
        opt.add(self._row('🎞️', 'Enable Firefox DRM / Widevine',
                          'Required for Prime Video, Netflix and similar '
                          'services; permits the proprietary Google CDM '
                          'download after a separate opt-in for each Firefox '
                          'profile',
                          act_firefox_drm))
        if not is_live_mode():
            opt.add(self._row('🎬', 'Install Multimedia Codecs + GPU HW-Decode',
                              'H.264 + H.265 video codecs and full GPU '
                              'hardware decode (~70 MB)',
                              act_codecs))
        # Greyed-out instead of hidden when not applicable: the row stays
        # visible so users learn the option exists, with the reason inline.
        nvidia_row = self._row('🖥️', 'Install NVIDIA Driver',
                               'Proprietary GPU driver (~15-20 min, '
                               'requires 2 reboots)',
                               act_nvidia_install)
        if not has_nvidia():
            nvidia_row.set_sensitive(False)
            nvidia_row.set_subtitle('No NVIDIA GPU detected on this system')
        elif has_nvidia_proprietary():
            nvidia_row.set_sensitive(False)
            nvidia_row.set_subtitle(
                'Already installed — the proprietary NVIDIA driver is active')
        opt.add(nvidia_row)
        page.add(opt)

        # Printing is an optional local capability like the adjacent media and
        # gaming groups, not an early privacy prerequisite.
        page.add(printing)

        # GAMING MODE — opt-in Steam/Proton hardening relaxation (M08 Step 1g
        # noid-toggle-gaming). Distinct from Hardware Privacy above: those
        # DISABLE hardware for privacy, whereas this RE-OPENS two hardening
        # surfaces for gaming — 32-bit execution (ia32_emulation, reboot-
        # required) + W^X for unconfined home (selinuxuser_execmod). Steam is
        # a second explicit action after that reboot so its i686 RPM scriptlets
        # never run while the hardened kernel still rejects 32-bit execution.
        # SELinux stays Enforcing;
        # everything else stays hardened. Default OFF (no flag = full
        # hardening). Own group, NOT inside Hardware Privacy, so a relaxation
        # is never mistaken for a privacy-protection toggle.
        # A Live overlay has no durable BLS policy and must not run the Steam
        # RPM transaction. The backend independently rejects Live mutations;
        # omit the installed-system control here instead of offering a dead end.
        if not is_live_mode():
            gaming = Adw.PreferencesGroup()
            gaming.set_title('Gaming Mode (Steam / Proton)')
            gaming.set_description(
                'Opt-in. Re-opens the two blockers Steam/Proton need — 32-bit '
                'support (reboot) and the W^X boolean for Wine. After that '
                'restart, the completion row installs Steam from RPM Fusion and '
                'shows the current DNF transaction. SELinux stays Enforcing, '
                'everything else stays hardened, and it is reversible. It does '
                'not guarantee every game runs (Proton per-title support + '
                'anti-cheat are upstream).')
            gaming_switch = Adw.SwitchRow()
            gaming_switch.set_title('Enable Gaming Mode')
            gaming_switch.set_subtitle(
                'Off = full hardening (NoID Privacy default) · '
                'On = compatibility policy selected')
            self._add_emoji_prefix(gaming_switch, '🎮')
            gaming_switch.set_active(_gaming_enabled())
            steam_completion_row = self._row(
                '📦', 'Complete Steam installation',
                'Enable Gaming Mode first',
                lambda row: _start_gaming_enable_terminal(
                    gaming_switch, row))
            GAMING_COMPLETION_ROWS[id(gaming_switch)] = steam_completion_row
            gaming_switch.connect('notify::active', on_gaming_toggle)
            gaming.add(gaming_switch)
            _sync_gaming_completion_row(steam_completion_row)
            gaming.add(steam_completion_row)
            page.add(gaming)

        # APP AUTOSTART — placed after the install groups above, because the
        # picker can only offer what is already installed: deciding what starts
        # at login before choosing what exists is the wrong way round.
        # GNOME Settings has no app-autostart control on the shipped image and
        # Tweaks is omitted as redundant UI, so this implements the canonical
        # XDG pattern instead — copy a .desktop file into ~/.config/autostart.
        # All ops user-context; System dconf locks remain effective in either
        # UI.
        autostart_group = Adw.PreferencesGroup()
        autostart_group.set_title('App Autostart')
        autostart_group.set_description(
            'Apps automatically launch at login — e.g. VPN client, '
            'password manager, mail bridge. GNOME Settings has no app-'
            'autostart control on this image; this section is included. Apps with '
            'telemetry start phoning home from login — choose deliberately. '
            'The switch on each row holds that app back until a physical '
            'network device is up — turn it on for VPN clients, which '
            'otherwise probe their server before wifi exists and give up.')
        self._autostart_group = autostart_group
        self._autostart_rows = []  # tracked for refresh
        self._refresh_autostart_rows()
        page.add(autostart_group)

        # NOTIFICATIONS — popup toggles (Layer 2 opt-in)
        # Auditd is always on. AIDE Layer 1 remains disabled until the user
        # accepts a reviewed baseline and separately enables its timer; this
        # switch controls only the Layer 2 desktop popup.
        notif = Adw.PreferencesGroup()
        notif.set_title('Security Notifications')
        notif.set_description(
            'AIDE checks require a user-reviewed baseline. After setup, this '
            'switch controls desktop notifications only. Audit surfaces '
            'critical events in real time.')

        aide_switch = Adw.SwitchRow()
        aide_switch.set_title('AIDE Desktop Notifications')
        aide_switch.set_subtitle(
            'First run: sudo noid-aide-baseline-review prepare; review and '
            'commit the exact candidate hash')
        self._add_emoji_prefix(aide_switch, '🧾')
        # Switch scoped to Layer 2 popup state only. The Layer 1 timer remains
        # separately controlled by `sudo noid-toggle-aide on|off`.
        aide_switch.set_active(_is_aide_popup_enabled())
        aide_switch.set_sensitive(_aide_database_state() == 'active')
        aide_switch.connect('notify::active', on_aide_toggle)
        notif.add(aide_switch)

        audit_switch = Adw.SwitchRow()
        audit_switch.set_title('Audit Event Notifications')
        audit_switch.set_subtitle(
            'Real-time desktop alerts for critical security events')
        self._add_emoji_prefix(audit_switch, '🔔')
        audit_switch.set_active(is_unit_enabled('audit-notify.service'))
        audit_switch.connect('notify::active', on_audit_toggle)
        notif.add(audit_switch)

        page.add(notif)

        # COMPANION APPS — the first of the three "where do I go next" groups,
        # ahead of Reference and Project & Ecosystem. It is the only group on
        # this page that changes nothing on the system, so it belongs with the
        # other signposts rather than between two settings groups. It stays
        # because a first-boot user has no reason to know the Network (M36) and
        # Tools (M37) apps exist; the app grid lists them but does not guide.
        netmgmt = Adw.PreferencesGroup()
        netmgmt.set_title('Companion Apps')
        netmgmt.set_description(
            'The dedicated NoID Privacy apps beyond this Setup dialog: '
            'network policy management and the curated helper-command '
            'launcher. Both are also in the app grid.')
        netmgmt.add(self._row('🌐', 'Open NoID Privacy Network',
                              'WAN strict-mode toggle, per-IP LAN '
                              'exceptions, network status overview',
                              act_open_network_app))
        # Tools app cross-link (Module 37): curated launcher for every
        # user-facing noid-* helper CLI — the discoverability companion.
        netmgmt.add(self._row('🧰', 'Open NoID Privacy Tools',
                              'All helper commands, grouped and described '
                              '— run them without memorizing CLI names',
                              act_open_tools_app))
        page.add(netmgmt)

        # REFERENCE — docs
        ref = Adw.PreferencesGroup()
        ref.set_title('Reference')
        ref.set_description(
            'Documentation and tips. Start with the Getting Started Guide '
            '— it covers the core concepts and the first-day checklist.')
        ref.add(self._row('📖', 'Getting Started Guide',
                          'Read first — core concepts and first-day '
                          'checklist (~15 min)',
                          act_doc_getting_started))
        ref.add(self._row('📚', 'All Documentation',
                          'Open the folder containing every installed '
                          'NoID Privacy guide',
                          act_open_doc_folder))
        ref.add(self._row('🔧', 'Optional Hardware Setup',
                          'Background details on masked services (Bluetooth '
                          'one-click in Hardware Privacy above), printing, '
                          'and modem support',
                          act_doc_hardware))
        page.add(ref)

        # PROJECT & ECOSYSTEM — website + siblings + support.
        # One static group in a one-shot dialog: deliberately no timer, no
        # popup, no nag. A recurring donation reminder would be the same noise
        # class M17 locks off for the GNOME Foundation and M35 disables for
        # Thunderbird. Every row is a user-initiated browser launch; the OS
        # never contacts these hosts on its own. Companion doc:
        # ecosystem-and-support.md
        # (M32 STEP 7c).
        eco = Adw.PreferencesGroup()
        eco.set_title('Project &amp; Ecosystem')
        eco.set_description(
            'NoID Privacy is an independent one-developer project. '
            'Everything below is optional and opens in your browser — '
            'the system never contacts these sites by itself.')
        eco.add(self._row('🏠', 'Project Website',
                          'noid-privacy.com — guides, downloads, and news '
                          'for all NoID Privacy platforms',
                          act_open_website))
        eco.add(self._row('💻', 'Projects on GitHub',
                          'Windows engine, Linux audit tool + this distro '
                          '— all open source',
                          act_open_github))
        eco.add(self._row('☕', 'Support the Project',
                          'If this distro is useful to you, a coffee keeps '
                          'development going — buymeacoffee.com/noidprivacy',
                          act_open_donate))
        page.add(eco)

        # FINAL STEP — installed-system-only, user-controlled firstboot
        # completion. Live media has no durable install state and must never
        # offer an action that merely reboots back into the same Live image.
        if not is_live_mode():
            final = Adw.PreferencesGroup()
            if firstboot_reboot_pending():
                final.set_title('Required — Finish Installation')
                final.set_description(
                    'The security kernel arguments are already active. After '
                    'completing the setup steps above, save your work and '
                    'restart once to finalize the first-install boot policy '
                    'and Btrfs root-selector handoff.')
                restart_title = 'Restart and Finish Installation'
                restart_subtitle = (
                    'Required once after first login — opens a confirmation '
                    'before restarting')
            else:
                final.set_title('Restart System')
                final.set_description(
                    'No first-install boot-policy activation is pending. You '
                    'can still restart cleanly here after updates or '
                    'configuration changes.')
                restart_title = 'Restart System'
                restart_subtitle = 'Opens a confirmation before restarting'
            final.add(self._row('🏁', restart_title,
                                restart_subtitle,
                                act_reboot))
            page.add(final)

    def retire_pipewire_monitor(self):
        """Stop the window-owned pw-mon exactly once before application exit."""
        proc = getattr(self, '_mic_pwmon', None)
        self._mic_pwmon = None
        if proc is not None:
            _retire_pipewire_monitor(proc)

    @staticmethod
    def _add_emoji_prefix(row, emoji):
        """Use the suite-wide decorative prefix contract."""
        noid_ui.add_emoji_prefix(row, emoji)

    def _row(self, emoji, title, subtitle, callback):
        return noid_ui.action_row(emoji, title, subtitle, callback)

    # ---- App Autostart methods -----------------

    def _refresh_autostart_rows(self):
        """Clear rows and repopulate from the XDG autostart directory.
        Always ends with '+ Add app' action row. Idempotent — safe to call
        on init + after every add/remove action."""
        # Remove previously-tracked rows from group
        for row in self._autostart_rows:
            try:
                self._autostart_group.remove(row)
            except (TypeError, GLib.Error) as exc:
                _warn('stale autostart row removal failed', exc)
        self._autostart_rows = []

        current = _scan_autostart_dir()
        if not current:
            placeholder = Adw.ActionRow()
            placeholder.set_title('(No apps in autostart)')
            placeholder.set_subtitle(
                'Click "Add app to autostart" below to pick one')
            self._add_emoji_prefix(placeholder, '🕊️')
            self._autostart_group.add(placeholder)
            self._autostart_rows.append(placeholder)
        else:
            for entry in current:
                row = Adw.ActionRow()
                row.set_use_markup(False)
                row.set_title(entry['name'])
                if entry['hidden']:
                    subtitle = (
                        'Disabled local mask — removing it may restore an '
                        'inherited autostart entry')
                elif entry['no_display']:
                    detail = entry['comment'] or entry['exec']
                    subtitle = 'Autostarts but is hidden from app menus'
                    if detail:
                        subtitle += ' — ' + detail
                else:
                    subtitle = entry['comment'] or _netwait_strip(entry['exec'])
                if _netwait_enabled(entry['exec']):
                    subtitle = 'Waits for the network — ' + subtitle
                # Truncate long subtitles to fit one line
                if len(subtitle) > 80:
                    subtitle = subtitle[:77] + '...'
                row.set_subtitle(subtitle)
                icon_widget = Gtk.Image.new_from_icon_name(entry['icon'])
                icon_widget.set_pixel_size(28)
                icon_widget.set_margin_start(4)
                icon_widget.set_margin_end(8)
                icon_widget.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
                row.add_prefix(icon_widget)
                fname = entry['filename']
                # Network gate switch. Off by default: delaying an app the user
                # did not ask to delay would be a silent behavior change, and
                # only network-probing clients benefit. A mask entry has no
                # Exec= to rewrite, so it gets no switch.
                if not entry['hidden'] and entry['exec']:
                    gate = Gtk.Switch()
                    gate.set_valign(Gtk.Align.CENTER)
                    gate.set_active(_netwait_enabled(entry['exec']))
                    gate_label = 'Wait for network before starting: '
                    gate_help = (
                        'Hold this app back until a physical network device is '
                        'up (30s limit, then it starts anyway). Fixes VPN '
                        'clients that give up when launched before wifi.')
                    if not Path(NETWAIT_CMD).is_file():
                        gate.set_sensitive(False)
                        gate_help = ('Unavailable: ' + NETWAIT_CMD
                                     + ' is not installed.')
                    gate.set_tooltip_text(gate_help)
                    noid_ui.accessible(
                        gate, gate_label + entry['name'], gate_help)
                    gate.connect(
                        'state-set',
                        lambda _s, state, f=fname, r=row:
                            self._on_netwait_toggled(f, state, r))
                    row.add_suffix(gate)
                # Remove button (trash icon, flat style)
                remove_btn = Gtk.Button.new_from_icon_name(
                    'user-trash-symbolic')
                remove_btn.add_css_class('flat')
                remove_btn.set_valign(Gtk.Align.CENTER)
                remove_action = (
                    'Remove local mask (may restore inherited autostart): '
                    if entry['hidden'] else 'Remove from autostart: ')
                remove_btn.set_tooltip_text(remove_action + entry['name'])
                noid_ui.accessible(
                    remove_btn, remove_action + entry['name'],
                    'Remove this local XDG autostart entry')
                remove_btn.connect(
                    'clicked',
                    lambda _b, f=fname: self._on_autostart_remove(f))
                row.add_suffix(remove_btn)
                noid_ui.accessible_row(row)
                self._autostart_group.add(row)
                self._autostart_rows.append(row)

        # Always show "+ Add app" at bottom
        count = len(current)
        add_row = self._row(
            '➕', 'Add app to autostart',
            'Currently {} app(s) in autostart'.format(count),
            self._on_autostart_add_clicked)
        self._autostart_group.add(add_row)
        self._autostart_rows.append(add_row)

    def _on_autostart_remove(self, filename):
        """Remove the named local XDG autostart entry and refresh."""
        if _autostart_remove(filename):
            self._refresh_autostart_rows()

    def _on_netwait_toggled(self, filename, state, row):
        """Enable or disable the network gate for one autostart entry.

        The row is updated in place rather than rebuilt: this handler runs from
        the switch's own 'state-set' signal, and destroying that switch here
        would tear the widget down mid-emission. Returning False lets GTK apply
        the visual state; on failure the switch is reset to the real state so
        the UI never claims a change that did not reach disk."""
        if not _autostart_set_netwait(filename, bool(state)):
            _toast('Could not update the autostart entry.', 5)
            for entry in _scan_autostart_dir():
                if entry['filename'] == filename:
                    GLib.idle_add(self._refresh_autostart_rows)
                    break
            return True
        for entry in _scan_autostart_dir():
            if entry['filename'] != filename:
                continue
            subtitle = entry['comment'] or _netwait_strip(entry['exec'])
            if _netwait_enabled(entry['exec']):
                subtitle = 'Waits for the network — ' + subtitle
            if len(subtitle) > 80:
                subtitle = subtitle[:77] + '...'
            row.set_subtitle(subtitle)
            break
        return False

    def _on_autostart_add_clicked(self, _row):
        """+ Add button handler: open modal picker."""
        self._show_autostart_picker()

    def _show_autostart_picker(self):
        """Modal Adw.Dialog with Gtk.SearchEntry + Gtk.ListBox of available
        apps (XDG-filtered, dedup, excludes already-autostarting)."""
        apps = _scan_available_apps()

        dialog = Adw.Dialog()
        dialog.set_title('Select app')
        dialog.set_content_width(560)
        dialog.set_content_height(640)

        toolbar = Adw.ToolbarView()
        dialog.set_child(toolbar)

        header = Adw.HeaderBar()
        title_widget = Adw.WindowTitle.new(
            'Select app', '{} apps available'.format(len(apps)))
        header.set_title_widget(title_widget)
        toolbar.add_top_bar(header)

        # Body: vbox(search, scrolled(listbox))
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        vbox.set_margin_top(8)
        vbox.set_margin_bottom(8)
        vbox.set_margin_start(12)
        vbox.set_margin_end(12)
        vbox.set_spacing(8)

        search = Gtk.SearchEntry()
        search.set_placeholder_text('Search apps...')
        vbox.append(search)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        listbox.add_css_class('boxed-list')

        # Populate ListBox + track (row, info) pairs for filter + activate
        picker_pairs = []
        for entry in apps:
            row = Adw.ActionRow()
            row.set_use_markup(False)
            row.set_title(entry['name'])
            subtitle = entry['comment']
            if len(subtitle) > 80:
                subtitle = subtitle[:77] + '...'
            row.set_subtitle(subtitle)
            row.set_activatable(True)
            icon_widget = Gtk.Image.new_from_icon_name(entry['icon'])
            icon_widget.set_pixel_size(32)
            icon_widget.set_margin_start(4)
            icon_widget.set_margin_end(8)
            icon_widget.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
            row.add_prefix(icon_widget)
            noid_ui.accessible_row(row)
            listbox.append(row)
            picker_pairs.append((row, entry))

        scrolled.set_child(listbox)
        vbox.append(scrolled)
        toolbar.set_content(vbox)

        # Search filter
        def on_search_changed(entry):
            query = entry.get_text().lower().strip()
            for row, info in picker_pairs:
                if query == '':
                    row.set_visible(True)
                else:
                    visible = (query in info['name'].lower()
                               or query in info.get('comment', '').lower())
                    row.set_visible(visible)
        search.connect('search-changed', on_search_changed)

        # On row activate: add to autostart, close, refresh
        def on_row_activated(_lb, activated_row):
            for row, info in picker_pairs:
                if row is activated_row:
                    prefer_netwait = _autostart_recommends_netwait(info)
                    if _autostart_add(
                            info['path'], info['filename'], prefer_netwait):
                        dialog.close()
                        self._refresh_autostart_rows()
                    break
        listbox.connect('row-activated', on_row_activated)

        dialog.present(self)


class NoIDWelcomeApp(noid_ui.NoIDApplication):
    def __init__(self):
        super().__init__(APP_ID, 'noid-privacy-setup')
        self._welcome_window = None

    def _on_window_close_request(self, win):
        win.retire_pipewire_monitor()
        self.quit()
        return False

    def do_activate(self):
        win = self.props.active_window
        if win is None:
            win = WelcomeWindow(self)
            self._welcome_window = win
            # Terminate the application when its sole window
            # closes instead of leaving schedule polling alive in the
            # background. The state file is still written below regardless.
            win.connect('close-request', self._on_window_close_request)
        win.present()
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            STATE_FILE.touch()
        except OSError as exc:
            _warn('welcome state-file creation failed', exc)

    def do_shutdown(self):
        # Also cover application-driven exits. The method is idempotent because
        # close-request normally retires the monitor first.
        if self._welcome_window is not None:
            self._welcome_window.retire_pipewire_monitor()
            self._welcome_window = None
        Adw.Application.do_shutdown(self)


def main():
    # Never set SIGCHLD to SIG_IGN here. The kernel then reaps children before
    # subprocess can read their status, so subprocess.run() may report rc=0
    # with empty stdout and corrupt process-backed state queries throughout the
    # UI. Defunct spawn_terminal/spawn_app children until session end are the
    # accepted cost of not doing it.
    if '--help' in sys.argv or '-h' in sys.argv:
        print(__doc__ or '')
        print('\nUsage:')
        print('  noid-welcome.sh             Run once (skips if already shown)')
        print('  noid-welcome.sh --again     Force re-open')
        print('  noid-welcome.sh --autostart Wait for GNOME initial setup, then run')
        return 0

    again = '--again' in sys.argv
    autostart = '--autostart' in sys.argv

    # Live-ISO guard: suppress the AUTO entry points (--autostart at login +
    # plain run-once) in live mode. Setup content (LUKS status, snapper
    # rollback, USBGuard, AIDE, Welcome-Setup state) is meaningful only on the
    # installed btrfs system, so the live autostart path returns immediately.
    # Exception: a manual launch (--again, i.e.
    # the user clicking the "NoID Privacy Setup" app-grid icon) opens the hub
    # on demand even in live — LUKS/snapper rows just show n/a, and the
    # is_live_mode() defined above checks /proc/cmdline for `rd.live.image`.
    if is_live_mode() and not again:
        return 0

    if not again and STATE_FILE.exists():
        return 0

    # Fedora 44's systemd XDG-autostart generator translates GNOME's
    # AutostartCondition= extension into an ExecCondition helper. GNOME 50 no
    # longer ships that helper, so putting the condition in the desktop file
    # silently drops this app from the generated target. Keep the real
    # gnome-initial-setup ordering in-process instead. A timeout leaves
    # STATE_FILE untouched so the next login can retry.
    if autostart:
        config_home = os.environ.get('XDG_CONFIG_HOME', '')
        if not config_home or not os.path.isabs(config_home):
            config_home = str(Path.home() / '.config')
        initial_setup_done = Path(config_home) / 'gnome-initial-setup-done'
        deadline = time.monotonic() + 1800
        while not initial_setup_done.is_file():
            if STATE_FILE.exists() or time.monotonic() >= deadline:
                return 0
            time.sleep(2)

    if not again and shutil.which('notify-send'):
        # f-string for clarity (was '+'-concat).
        spawn_app(['notify-send',
                   f'--icon={LOGO_PATH}',
                   '--app-name=NoID Privacy',
                   'Welcome to NoID Privacy',
                   'Opening setup…'])

    app = NoIDWelcomeApp()
    return app.run([sys.argv[0]])


if __name__ == '__main__':
    sys.exit(main())
NOID_WELCOME_PY_EOF

chmod 755 /usr/local/bin/noid-welcome.sh
chown root:root /usr/local/bin/noid-welcome.sh
echo "  [OK] /usr/local/bin/noid-welcome.sh installed (755)"

# Step 6b (removed): noid-setup-wizard
# Wizard's Hardware-Privacy + VPN-link + App-installs were either
# integrated into the welcome dialog (mic/cam toggles) or removed
# (Flatpak app-installs out of NoID Privacy scope; KeePassXC stays as RPM).

# ----------------------------------------------------------------------------
# Step 6b2: Shared CLI presentation library (single source of truth)
# ----------------------------------------------------------------------------
# One tiny, root-owned formatting library sourced by user-facing NoID Privacy
# CLIs, including every opt-in installer, so they share one consistent,
# legible look instead of drifting per-script. Colour is emitted ONLY to an
# interactive terminal and is suppressed under NO_COLOR / dumb TERM, so piped
# or logged output stays plain text. Pure presentation — no side effects.
echo ""
echo "[Step 6b2] Installing /usr/local/lib/noid-privacy/agent-install-format.sh"
install -d -m 0755 -o root -g root /usr/local/lib/noid-privacy
cat > /usr/local/lib/noid-privacy/agent-install-format.sh <<'FMT_EOF'
# NoID Privacy — shared CLI presentation helpers. Source, don't execute.
# shellcheck shell=bash
# Colours activate only for an interactive TTY and honour NO_COLOR + TERM=dumb.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
    _F_RST=$'\033[0m'; _F_B=$'\033[1m'; _F_DIM=$'\033[2m'
    _F_BLUE=$'\033[38;5;39m'; _F_GREEN=$'\033[38;5;42m'
    _F_YEL=$'\033[38;5;214m'; _F_RED=$'\033[38;5;203m'; _F_GREY=$'\033[38;5;245m'
else
    _F_RST=; _F_B=; _F_DIM=; _F_BLUE=; _F_GREEN=; _F_YEL=; _F_RED=; _F_GREY=
fi

fmt_banner() { # TITLE [SUBTITLE]
    # ${#s} counts characters (not bytes) under a UTF-8 locale, so padding
    # stays aligned even with em-dashes or middle dots in the text.
    local title=$1 sub=${2:-} bar pad
    bar=$(printf '%0.s─' $(seq 1 52))
    printf '%s╭%s╮%s\n' "$_F_BLUE" "$bar" "$_F_RST"
    pad=$((50 - ${#title})); [ "$pad" -lt 0 ] && pad=0
    printf '%s│%s %s%s%s%*s %s│%s\n' \
        "$_F_BLUE" "$_F_RST" "$_F_B" "$title" "$_F_RST" "$pad" '' "$_F_BLUE" "$_F_RST"
    if [ -n "$sub" ]; then
        pad=$((50 - ${#sub})); [ "$pad" -lt 0 ] && pad=0
        printf '%s│%s %s%s%s%*s %s│%s\n' \
            "$_F_BLUE" "$_F_RST" "$_F_GREY" "$sub" "$_F_RST" "$pad" '' "$_F_BLUE" "$_F_RST"
    fi
    printf '%s╰%s╯%s\n' "$_F_BLUE" "$bar" "$_F_RST"
}
fmt_step() { printf '\n%s[%s/%s]%s %s%s%s\n' \
    "$_F_BLUE$_F_B" "$1" "$2" "$_F_RST" "$_F_B" "$3" "$_F_RST"; }
fmt_section() { printf '\n%s%s── %s%s\n' \
    "$_F_BLUE" "$_F_B" "$1" "$_F_RST"; }
fmt_kv() { printf '  %-22s %s\n' "$1" "$2"; }
fmt_kv_warn() { printf '  %-22s %s!%s %s\n' \
    "$1" "$_F_YEL" "$_F_RST" "$2"; }
fmt_ok()   { printf '  %s✓%s %s\n' "$_F_GREEN" "$_F_RST" "$1"; }
fmt_info() { printf '  %s•%s %s\n' "$_F_GREY" "$_F_RST" "$1"; }
fmt_warn() { printf '  %s!%s %s\n' "$_F_YEL" "$_F_RST" "$1" >&2; }
fmt_err()  { printf '  %s✗ %s%s\n' "$_F_RED" "$1" "$_F_RST" >&2; }
fmt_note() { printf '%s%s%s\n' "$_F_DIM" "$1" "$_F_RST"; }
fmt_done() { printf '\n%s%s✓ %s%s\n' "$_F_GREEN" "$_F_B" "$1" "$_F_RST"; }
fmt_tty_banner() { # TITLE [SUBTITLE]
    [ -t 1 ] || return 0
    fmt_banner "$1" "${2:-}"
}
if [ -n "${NOID_FMT_AUTO_TITLE:-}" ]; then
    fmt_tty_banner "$NOID_FMT_AUTO_TITLE" "${NOID_FMT_AUTO_SUBTITLE:-}"
fi
FMT_EOF
chmod 0644 /usr/local/lib/noid-privacy/agent-install-format.sh
chown root:root /usr/local/lib/noid-privacy/agent-install-format.sh
echo "  [OK] /usr/local/lib/noid-privacy/agent-install-format.sh installed (644)"

# ----------------------------------------------------------------------------
# Step 6c: Install /usr/local/bin/noid-claude-install (opt-in CLI + IDE)
# ----------------------------------------------------------------------------
# Direct, versioned native-binary install plus an optional pinned VSIX, each
# behind its own prompt. No mutable install.sh is executed, no package manager
# is introduced, and the exact reviewed bytes are pinned. --update refreshes
# only opted-in components over the vendor channel with recorded evidence.
echo ""
echo "[Step 6c] Installing /usr/local/bin/noid-claude-install (opt-in)"

cat > /usr/local/bin/noid-claude-install <<'CLAUDE_INSTALL_EOF'
#!/bin/bash
# Per-user Claude Code installer/updater: pinned native CLI plus an optional
# pinned VSCodium extension, each behind its own prompt. No npm, no remote
# shell installer and no sudo. --update refreshes only components already
# installed here — that consent was given at install time — and appends
# version + SHA-256 evidence to the agent-update ledger.
set -euo pipefail
umask 077

CLAUDE_VERSION="2.1.241"
CLAUDE_SHA256="0771bd866cff82b76581fc0499f6529e1a36845078f144f8c81dccb3bc7037b8"
CLAUDE_SIZE="342636848"
CLAUDE_URL="https://downloads.claude.ai/claude-code-releases/2.1.241/linux-x64/claude"
EXT_VERSION="2.1.241"
EXT_SHA256="1af9fd16fe55873073685a6e562afa54f142d237b4500ca1dcb02b63c3328e90"
EXT_SIZE="107201776"
EXT_ID="anthropic.claude-code"
EXT_API_BASE="https://open-vsx.org/api/Anthropic/claude-code/linux-x64"

FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
# shellcheck source=/dev/null
if [ -r "$FMT_LIB" ]; then . "$FMT_LIB"; else
    fmt_banner(){ echo "== $1 =="; [ -n "${2:-}" ] && echo "   $2"; }
    fmt_step(){ echo "[$1/$2] $3"; }; fmt_ok(){ echo "  OK: $1"; }
    fmt_info(){ echo "  - $1"; }; fmt_warn(){ echo "  ! $1" >&2; }
    fmt_err(){ echo "  ERROR: $1" >&2; }; fmt_note(){ echo "$1"; }
    fmt_done(){ echo "$1"; }
fi
fail() { fmt_err "$*"; exit 1; }

usage() {
    printf '%s\n' \
        'Usage: noid-claude-install [--update|--help]' \
        '' \
        "Interactively install the repository-pinned Claude Code $CLAUDE_VERSION" \
        "native x86_64 CLI and/or the pinned VSCodium extension $EXT_VERSION. Each" \
        'component has its own [y/N] prompt; no network access or filesystem' \
        'mutation happens before that component is confirmed.' \
        '' \
        '--update refreshes, without prompting, exactly the components that are' \
        "already installed here: the NoID Privacy-managed CLI through Anthropic's" \
        "'claude update' channel and the installed extension through the newest" \
        'Open VSX linux-x64 release. Missing components are skipped untouched; exit' \
        'code 3 means no component is opted in. Every applied update appends' \
        'version + SHA-256 evidence to the agent-update ledger.'
}

MODE=install
case "$#:${1:-}" in
    0:) ;;
    1:--update) MODE=update ;;
    1:-h|1:--help) usage; exit 0 ;;
    *) fail "Usage: noid-claude-install [--update|--help]" ;;
esac

[ "$EUID" -ne 0 ] || fail "Run this per-user installer without sudo."
[ "$(uname -m)" = "x86_64" ] || fail "This reviewed pin is for x86_64 only."
for name in curl sha256sum stat install mktemp mv ln readlink awk grep date \
            flock sort sync; do
    command -v "$name" >/dev/null 2>&1 || fail "Required command missing: $name"
done
exec 9</usr/local/bin/noid-claude-install
flock -n 9 || fail "Another Claude installer/update run is already active."

DEST_DIR="$HOME/.local/share/claude/versions"
DEST="$DEST_DIR/$CLAUDE_VERSION"
LINK_DIR="$HOME/.local/bin"
LINK="$LINK_DIR/claude"
STATE_HOME=${XDG_STATE_HOME:-"$HOME/.local/state"}
case "$STATE_HOME" in /*) ;; *) STATE_HOME="$HOME/.local/state" ;; esac
LEDGER_DIR="$STATE_HOME/noid-privacy"
LEDGER="$LEDGER_DIR/agent-updates.log"
if { [ -e "$LINK" ] || [ -L "$LINK" ]; } && [ ! -L "$LINK" ]; then
    fail "$LINK is not a symlink; refusing to overwrite it."
fi

DOWNLOAD=""
VSIX=""
ZIP_LIST=""
TMP_DEST=""
TMP_LINK=""
cleanup() {
    # The guard lists may end false; never let that status leak out of the
    # EXIT trap, where errexit would replace the script's real exit code.
    [ -n "$DOWNLOAD" ] && rm -f "$DOWNLOAD"
    [ -n "$VSIX" ] && rm -f "$VSIX"
    [ -n "$ZIP_LIST" ] && rm -f "$ZIP_LIST"
    [ -n "$TMP_DEST" ] && rm -f "$TMP_DEST"
    [ -n "$TMP_LINK" ] && rm -f "$TMP_LINK"
    return 0
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ledger_append() {
    if [ -e "$LEDGER_DIR" ] || [ -L "$LEDGER_DIR" ]; then
        [ -d "$LEDGER_DIR" ] && [ ! -L "$LEDGER_DIR" ] \
            && [ "$(stat -Lc '%u:%g:%a' "$LEDGER_DIR" \
                    2>/dev/null || true)" = "$(id -u):$(id -g):700" ] \
            || fail "Unsafe agent-update ledger directory."
    else
        install -d -m 0700 "$LEDGER_DIR"
    fi
    if [ -e "$LEDGER" ] || [ -L "$LEDGER" ]; then
        [ -f "$LEDGER" ] && [ ! -L "$LEDGER" ] \
            && [ "$(stat -Lc '%u:%g:%a:%h' "$LEDGER" \
                    2>/dev/null || true)" = "$(id -u):$(id -g):600:1" ] \
            || fail "Unsafe agent-update ledger."
    else
        install -m 0600 /dev/null "$LEDGER"
    fi
    exec 8>>"$LEDGER"
    flock -x 8
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LEDGER"
    sync -- "$LEDGER"
    exec 8>&-
}

fetch_https() { # URL DEST MAX_TIME_SECONDS
    curl -fL --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --max-redirs 3 --connect-timeout 20 --max-time "$3" "$1" -o "$2"
}

claude_reported_version() {
    "$1" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
}

version_is_newer() {
    local candidate=$1 current=$2 newest
    [[ "$candidate" =~ ^[0-9]+(\.[0-9]+)+$ ]] \
        && [[ "$current" =~ ^[0-9]+(\.[0-9]+)+$ ]] || return 1
    [ "$candidate" != "$current" ] || return 1
    newest=$(printf '%s\n%s\n' "$current" "$candidate" | sort -V | tail -1)
    [ "$newest" = "$candidate" ]
}

restore_managed_cli_link() {
    local previous_path=$1 expected_sha=$2 temporary
    [ -f "$previous_path" ] && [ ! -L "$previous_path" ] \
        && [ "$(sha256sum "$previous_path" | awk '{print $1}')" = "$expected_sha" ] \
        || fail "Claude updater changed state and the previous binary cannot be safely restored."
    temporary="$LINK_DIR/.claude.rollback.$$"
    ln -s "$previous_path" "$temporary"
    mv -fT "$temporary" "$LINK"
    [ "$(readlink -f "$LINK")" = "$previous_path" ] \
        || fail "Claude CLI rollback link verification failed."
}

cli_install_pinned() {
    local existing_path existing_version
    if [ -L "$LINK" ]; then
        existing_path=$(readlink -f "$LINK" 2>/dev/null || true)
        case "$existing_path" in
            "$DEST_DIR"/*) ;;
            *) fail "Existing Claude symlink is not NoID Privacy-managed; refusing takeover." ;;
        esac
        existing_version=$(claude_reported_version "$LINK")
        [[ "$existing_version" =~ ^[0-9]+(\.[0-9]+)+$ ]] \
            || fail "Existing managed Claude CLI reports an invalid version."
        if version_is_newer "$existing_version" "$CLAUDE_VERSION"; then
            fail "Installed Claude CLI $existing_version is newer than pin $CLAUDE_VERSION; refusing downgrade."
        fi
    fi
    DOWNLOAD=$(mktemp /var/tmp/noid-claude.XXXXXX)
    fmt_step 1 3 "Download + verification"
    fetch_https "$CLAUDE_URL" "$DOWNLOAD" 600 || \
        fail "Download failed; nothing installed."
    actual_size=$(stat -c '%s' "$DOWNLOAD")
    [ "$actual_size" = "$CLAUDE_SIZE" ] ||
        fail "Size mismatch (expected $CLAUDE_SIZE, got $actual_size)."
    actual_sha=$(sha256sum "$DOWNLOAD" | awk '{print $1}')
    [ "$actual_sha" = "$CLAUDE_SHA256" ] || fail "SHA-256 mismatch."
    fmt_ok "exact reviewed bytes"

    fmt_step 2 3 "Atomic user install"
    install -d -m 0755 "$DEST_DIR" "$LINK_DIR"
    TMP_DEST=$(mktemp "$DEST_DIR/.claude-$CLAUDE_VERSION.XXXXXX")
    install -m 0755 "$DOWNLOAD" "$TMP_DEST"
    reported=$(claude_reported_version "$TMP_DEST")
    [ "$reported" = "$CLAUDE_VERSION" ] || fail "Binary reports version: $reported"
    mv -fT "$TMP_DEST" "$DEST"
    TMP_DEST=""
    TMP_LINK="$LINK_DIR/.claude.noid.$$"
    ln -s "$DEST" "$TMP_LINK"
    mv -fT "$TMP_LINK" "$LINK"
    TMP_LINK=""

    fmt_step 3 3 "Final verification"
    reported=$(claude_reported_version "$LINK")
    [ "$reported" = "$CLAUDE_VERSION" ] || fail "Post-install verification failed."
    fmt_ok "Claude Code $reported"
}

require_ext_tools() {
    for name in codium unzip zipinfo python3; do
        command -v "$name" >/dev/null 2>&1 || fail "Required command missing: $name"
    done
}

vsix_validate() { # EXPECTED_VERSION — validates $VSIX via $ZIP_LIST
    unzip -Z1 "$VSIX" > "$ZIP_LIST" || fail "Unreadable VSIX."
    local entry
    while IFS= read -r entry; do
        case "$entry" in
            ""|/*|../*|*/../*|*/..) fail "Unsafe VSIX path: $entry" ;;
            "[Content_Types].xml"|extension.vsixmanifest|extension/*) ;;
            *) fail "Unexpected VSIX path: $entry" ;;
        esac
    done < "$ZIP_LIST"
    zipinfo -l "$VSIX" | awk '
      NR>2 && substr($1,1,1)=="l" {bad=1}
      END {exit bad}
    ' || fail "VSIX contains a symlink."
    python3 - "$VSIX" "$1" <<'PY' || fail "VSIX structure or identity is unsafe."
import json
from pathlib import PurePosixPath
import stat
import sys
import zipfile

archive, version = sys.argv[1:]
with zipfile.ZipFile(archive) as zf:
    infos = zf.infolist()
    if not infos or len(infos) > 100000:
        raise SystemExit("invalid VSIX member count")
    names = [entry.filename for entry in infos]
    if len(names) != len(set(names)):
        raise SystemExit("duplicate VSIX member")
    total = 0
    for entry in infos:
        name = entry.filename
        path = PurePosixPath(name)
        if (not name or "\\" in name or name.startswith("/")
                or ".." in path.parts or "." in path.parts):
            raise SystemExit("unsafe VSIX member path")
        if not (name in {"[Content_Types].xml", "extension.vsixmanifest"}
                or name.startswith("extension/")):
            raise SystemExit("unexpected VSIX member path")
        mode = entry.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind and kind not in {stat.S_IFREG, stat.S_IFDIR}:
            raise SystemExit("special VSIX member")
        total += entry.file_size
        if total > 4 * 1024**3:
            raise SystemExit("VSIX expands beyond safety cap")
    package = json.loads(zf.read("extension/package.json"))
expected = {"name": "claude-code", "publisher": "Anthropic", "version": version}
if any(package.get(key) != value for key, value in expected.items()):
    raise SystemExit("VSIX identity mismatch")
PY
}

ext_install_file() { # VSIX_FILE VERSION
    codium --install-extension "$1" --force
    codium --list-extensions --show-versions 2>/dev/null |
        grep -Fiqx "$EXT_ID@$2" || fail "Extension verify failed."
    if command -v pgrep >/dev/null 2>&1 \
       && pgrep -x codium >/dev/null 2>&1; then
        fmt_info "VSCodium is running; reload or restart it to activate the installed extension bytes."
    fi
}

ext_installed_version() {
    codium --list-extensions --show-versions 2>/dev/null | awk -v id="$EXT_ID@" '
        BEGIN { IGNORECASE=1 }
        index(tolower($0), id) == 1 { split($0, part, "@"); print part[2]; exit }
    '
}

if [ "$MODE" = install ]; then
    fmt_banner "NoID Privacy — Claude Code $CLAUDE_VERSION" \
        "pinned native CLI + optional VSCodium extension"
    fmt_note "Two separate opt-ins, each behind its own prompt:"
    fmt_note "  1. Anthropic's exact native x86_64 CLI binary (user context)"
    fmt_note "  2. The pinned Claude Code VSCodium extension from Open VSX"
    fmt_note "Security: pinned HTTPS URLs + byte counts + SHA-256; no curl|bash,"
    fmt_note "npm or sudo. Privacy: login/use sends prompts, selected code/context"
    fmt_note "and responses to Anthropic. The system-wide instructions are"
    fmt_note "/etc/claude-code/CLAUDE.md. Later updates of installed components"
    fmt_note "are an explicit noid-update-all.sh action over the vendor release"
    fmt_note "channel, recorded in the agent-update ledger."
    echo ""
    installed_any=0
    cli_installed=0
    extension_installed=0
    read -r -p "Install the reviewed native CLI? [y/N] " answer
    case "$answer" in
        [yY]|[yY][eE][sS])
            cli_install_pinned
            installed_any=1
            cli_installed=1
            ;;
        *) fmt_info "CLI not installed." ;;
    esac

    echo ""
    cat <<NOTE
Optional VSCodium extension:
  The pinned Anthropic Claude Code extension activates at editor startup;
  documented nonessential telemetry and error reporting are disabled by the
  Claude runtime defaults. The normal first-use sign-in screen remains
  available. It bundles its own Claude runtime, so it also works without the
  native CLI above.
NOTE
    read -r -p "Install the pinned Claude Code VSCodium extension? [y/N] " ext
    case "$ext" in
        [yY]|[yY][eE][sS])
            require_ext_tools
            current_ext=$(ext_installed_version)
            if [ -n "$current_ext" ] \
               && { ! [[ "$current_ext" =~ ^[0-9]+(\.[0-9]+)+$ ]] \
                    || version_is_newer "$current_ext" "$EXT_VERSION"; }; then
                fail "Installed Claude extension ${current_ext:-unknown} is newer than or incompatible with pin $EXT_VERSION; refusing downgrade."
            fi
            VSIX=$(mktemp /var/tmp/noid-claude-ext.XXXXXX.vsix)
            ZIP_LIST=$(mktemp /var/tmp/noid-claude-ext.XXXXXX.list)
            fetch_https \
                "$EXT_API_BASE/$EXT_VERSION/file/Anthropic.claude-code-$EXT_VERSION@linux-x64.vsix" \
                "$VSIX" 900 || fail "VSIX download failed."
            ext_size=$(stat -c '%s' "$VSIX")
            [ "$ext_size" = "$EXT_SIZE" ] || fail "VSIX size mismatch."
            ext_sha=$(sha256sum "$VSIX" | awk '{print $1}')
            [ "$ext_sha" = "$EXT_SHA256" ] || fail "VSIX SHA-256 mismatch."
            vsix_validate "$EXT_VERSION"
            ext_install_file "$VSIX" "$EXT_VERSION"
            fmt_ok "$EXT_ID@$EXT_VERSION installed as explicit opt-in"
            installed_any=1
            extension_installed=1
            ;;
        *) fmt_info "Extension not installed." ;;
    esac

    if [ "$installed_any" = 1 ]; then
        fmt_done "Claude Code setup complete."
    fi
    if [ "$cli_installed" = 1 ]; then
        fmt_note "Next (CLI): claude auth login"
    fi
    if [ "$extension_installed" = 1 ]; then
        fmt_note "Next (VSCodium): open the Claude Code panel and use its first-use sign-in screen."
    fi
    if [ "$installed_any" = 0 ]; then
        fmt_info "Nothing installed."
    fi
    exit 0
fi

# --update: non-interactive refresh of already-opted-in components only.
present=0
failures=0

if ! command -v claude >/dev/null 2>&1; then
    fmt_info "Claude CLI not installed."
else
    cli_path=$(readlink -f "$(command -v claude)" 2>/dev/null || true)
    case "$cli_path" in
        "$DEST_DIR"/*)
            present=1
            prev=$(claude_reported_version claude)
            if ! [[ "$prev" =~ ^[0-9]+(\.[0-9]+)+$ ]] \
               || [ ! -f "$cli_path" ] || [ -L "$cli_path" ]; then
                fmt_warn "managed Claude CLI has an invalid pre-update state"
                failures=$((failures + 1))
            else
                prev_sha=$(sha256sum "$cli_path" | awk '{print $1}')
                fmt_info "refreshing via Anthropic's 'claude update' channel"
                if claude update; then
                    new=$(claude_reported_version claude)
                    new_path=$(readlink -f "$(command -v claude)" 2>/dev/null || true)
                    if [ "$new" = "$prev" ] && [ -f "$new_path" ]; then
                        fmt_ok "Claude CLI already current ($new)"
                    elif version_is_newer "$new" "$prev" && [ -f "$new_path" ]; then
                        new_sha=$(sha256sum "$new_path" | awk '{print $1}')
                        ledger_append "component=claude-cli previous=${prev:-unknown} installed=$new sha256=$new_sha path=$new_path"
                        fmt_ok "Claude CLI ${prev:-unknown} -> $new (evidence recorded)"
                    else
                        restore_managed_cli_link "$cli_path" "$prev_sha"
                        fmt_warn "Claude update produced an invalid or older version; restored $prev"
                        failures=$((failures + 1))
                    fi
                else
                    current_path=$(readlink -f "$LINK" 2>/dev/null || true)
                    if [ "$current_path" != "$cli_path" ]; then
                        restore_managed_cli_link "$cli_path" "$prev_sha"
                    fi
                    fmt_warn "'claude update' failed; previous managed CLI restored"
                    failures=$((failures + 1))
                fi
            fi
            ;;
        *)
            fmt_info "Claude CLI is not NoID Privacy-managed; left untouched: ${cli_path:-unknown}"
            ;;
    esac
fi

if ! command -v codium >/dev/null 2>&1; then
    fmt_info "VSCodium not installed."
else
    ext_current=$(ext_installed_version)
    if [ -z "$ext_current" ]; then
        fmt_info "Claude Code extension not installed."
    else
        present=1
        ext_latest=$(curl -fsS --proto '=https' --tlsv1.2 --connect-timeout 20 \
            --max-time 60 "$EXT_API_BASE" 2>/dev/null |
            python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])' \
            2>/dev/null || true)
        if ! printf '%s' "$ext_latest" | grep -qE '^[0-9]+(\.[0-9]+)+$'; then
            fmt_warn "could not resolve the newest Open VSX release"
            failures=$((failures + 1))
        elif ! [[ "$ext_current" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
            fmt_warn "installed Claude extension reports an invalid version"
            failures=$((failures + 1))
        elif [ "$ext_latest" = "$ext_current" ]; then
            fmt_ok "Claude Code extension already current ($ext_current)"
        elif version_is_newer "$ext_latest" "$ext_current"; then
            require_ext_tools
            VSIX=$(mktemp /var/tmp/noid-claude-ext.XXXXXX.vsix)
            ZIP_LIST=$(mktemp /var/tmp/noid-claude-ext.XXXXXX.list)
            # A moving release cannot carry a repository byte pin; identity,
            # version, path safety and link freedom are still enforced before
            # activation and the exact SHA-256 is recorded as evidence.
            fetch_https \
                "$EXT_API_BASE/$ext_latest/file/Anthropic.claude-code-$ext_latest@linux-x64.vsix" \
                "$VSIX" 900 || fail "VSIX download failed."
            vsix_validate "$ext_latest"
            ext_install_file "$VSIX" "$ext_latest"
            vsix_sha=$(sha256sum "$VSIX" | awk '{print $1}')
            ledger_append "component=claude-ext previous=$ext_current installed=$ext_latest sha256=$vsix_sha source=open-vsx"
            fmt_ok "Claude Code extension $ext_current -> $ext_latest (evidence recorded)"
        else
            fmt_warn "Open VSX returned an older Claude extension ($ext_latest < $ext_current); refusing downgrade"
            failures=$((failures + 1))
        fi
    fi
fi

[ "$failures" -eq 0 ] || exit 1
[ "$present" -eq 1 ] || exit 3
exit 0
CLAUDE_INSTALL_EOF

chmod 755 /usr/local/bin/noid-claude-install
chown root:root /usr/local/bin/noid-claude-install
bash -n /usr/local/bin/noid-claude-install || {
    echo "[Module 13] FAIL: noid-claude-install syntax"; exit 1;
}
echo "  [OK] /usr/local/bin/noid-claude-install installed (755)"

# ----------------------------------------------------------------------------
# Step 6d: Install /usr/local/bin/noid-codex-install (opt-in CLI + IDE)
# ----------------------------------------------------------------------------
# Same reviewed-native-artifact model as Claude. The VSIX is a second opt-in
# because Codex has no equivalent to Claude's telemetry-off environment keys.
echo ""
echo "[Step 6d] Installing /usr/local/bin/noid-codex-install (opt-in)"

cat > /usr/local/bin/noid-codex-install <<'CODEX_INSTALL_EOF'
#!/bin/bash
# Per-user OpenAI Codex installer/updater: pinned standalone native package
# plus an optional pinned local VSIX, each behind its own prompt. No npm, no
# remote shell installer and no sudo. --update refreshes only components
# already installed here — that consent was given at install time — and
# appends version + SHA-256 evidence to the agent-update ledger.
set -euo pipefail
umask 077

CODEX_VERSION="0.149.1"
CODEX_TARGET="x86_64-unknown-linux-musl"
CODEX_SHA256="1e8531ae5f6dea3c6e11e53e74cc5ac81bf1ba597f9b296fb112d6ea30fdaf5d"
CODEX_SIZE="122578702"
CODEX_URL="https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-package-x86_64-unknown-linux-musl.tar.gz"
CODEX_DOWNLOAD_BASE="https://github.com/openai/codex/releases/download"
CODEX_LATEST_URL="https://github.com/openai/codex/releases/latest"
EXT_VERSION="26.5818.61809"
EXT_SHA256="8ac93a0682eda97ff79d0ef6e4b7d8344615f8dc1ebd816b7863f5a0629ea33e"
EXT_SIZE="228819497"
EXT_ID="openai.chatgpt"
EXT_API_BASE="https://open-vsx.org/api/openai/chatgpt/linux-x64"

FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
# shellcheck source=/dev/null
if [ -r "$FMT_LIB" ]; then . "$FMT_LIB"; else
    fmt_banner(){ echo "== $1 =="; [ -n "${2:-}" ] && echo "   $2"; }
    fmt_step(){ echo "[$1/$2] $3"; }; fmt_ok(){ echo "  OK: $1"; }
    fmt_info(){ echo "  - $1"; }; fmt_warn(){ echo "  ! $1" >&2; }
    fmt_err(){ echo "  ERROR: $1" >&2; }; fmt_note(){ echo "$1"; }
    fmt_done(){ echo "$1"; }
fi
fail() { fmt_err "$*"; exit 1; }

usage() {
    printf '%s\n' \
        'Usage: noid-codex-install [--update|--help]' \
        '' \
        "Interactively install the repository-pinned OpenAI Codex $CODEX_VERSION" \
        "standalone CLI and/or the pinned VSCodium extension $EXT_VERSION. Each" \
        'component has its own [y/N] prompt; no network access or filesystem' \
        'mutation happens before that component is confirmed.' \
        '' \
        '--update refreshes, without prompting, exactly the components that are' \
        'already installed here: the NoID Privacy-managed CLI from the newest official' \
        'GitHub release tarball (same archive validation as the pinned install,' \
        'never a remote shell installer) and the installed extension through the' \
        'newest Open VSX linux-x64 release. Missing components are skipped' \
        'untouched; exit code 3 means no component is opted in. Every applied' \
        'update appends version + SHA-256 evidence to the agent-update ledger.'
}

MODE=install
case "$#:${1:-}" in
    0:) ;;
    1:--update) MODE=update ;;
    1:-h|1:--help) usage; exit 0 ;;
    *) fail "Usage: noid-codex-install [--update|--help]" ;;
esac

[ "$EUID" -ne 0 ] || fail "Run this per-user installer without sudo."
[ "$(uname -m)" = "x86_64" ] || fail "This reviewed pin is for x86_64 only."
for name in curl sha256sum stat tar awk grep install mktemp mv ln readlink \
            date python3 flock sort sync; do
    command -v "$name" >/dev/null 2>&1 || fail "Required command missing: $name"
done
exec 9</usr/local/bin/noid-codex-install
flock -n 9 || fail "Another Codex installer/update run is already active."

CODEX_HOME=${CODEX_HOME:-"$HOME/.codex"}
case "$CODEX_HOME" in /*) ;; *) fail "CODEX_HOME must be absolute." ;; esac
BASE="$CODEX_HOME/packages/standalone"
RELEASES="$BASE/releases"
CURRENT="$BASE/current"
BIN_DIR="$HOME/.local/bin"
USER_LINK="$BIN_DIR/codex"
STATE_HOME=${XDG_STATE_HOME:-"$HOME/.local/state"}
case "$STATE_HOME" in /*) ;; *) STATE_HOME="$HOME/.local/state" ;; esac
LEDGER_DIR="$STATE_HOME/noid-privacy"
LEDGER="$LEDGER_DIR/agent-updates.log"
for link in "$CURRENT" "$USER_LINK"; do
    if { [ -e "$link" ] || [ -L "$link" ]; } && [ ! -L "$link" ]; then
        fail "$link is not a symlink; refusing to overwrite it."
    fi
done

ARCHIVE=""
LIST=""
VSIX=""
ZIP_LIST=""
STAGE=""
TMP_CURRENT=""
TMP_LINK=""
cleanup() {
    # The guard lists may end false; never let that status leak out of the
    # EXIT trap, where errexit would replace the script's real exit code.
    [ -n "$ARCHIVE" ] && rm -f "$ARCHIVE"
    [ -n "$LIST" ] && rm -f "$LIST"
    [ -n "$VSIX" ] && rm -f "$VSIX"
    [ -n "$ZIP_LIST" ] && rm -f "$ZIP_LIST"
    [ -n "$STAGE" ] && rm -rf "$STAGE"
    [ -n "$TMP_CURRENT" ] && rm -f "$TMP_CURRENT"
    [ -n "$TMP_LINK" ] && rm -f "$TMP_LINK"
    return 0
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ledger_append() {
    if [ -e "$LEDGER_DIR" ] || [ -L "$LEDGER_DIR" ]; then
        [ -d "$LEDGER_DIR" ] && [ ! -L "$LEDGER_DIR" ] \
            && [ "$(stat -Lc '%u:%g:%a' "$LEDGER_DIR" \
                    2>/dev/null || true)" = "$(id -u):$(id -g):700" ] \
            || fail "Unsafe agent-update ledger directory."
    else
        install -d -m 0700 "$LEDGER_DIR"
    fi
    if [ -e "$LEDGER" ] || [ -L "$LEDGER" ]; then
        [ -f "$LEDGER" ] && [ ! -L "$LEDGER" ] \
            && [ "$(stat -Lc '%u:%g:%a:%h' "$LEDGER" \
                    2>/dev/null || true)" = "$(id -u):$(id -g):600:1" ] \
            || fail "Unsafe agent-update ledger."
    else
        install -m 0600 /dev/null "$LEDGER"
    fi
    exec 8>>"$LEDGER"
    flock -x 8
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LEDGER"
    sync -- "$LEDGER"
    exec 8>&-
}

fetch_https() { # URL DEST MAX_TIME_SECONDS
    curl -fL --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --max-redirs 3 --connect-timeout 20 --max-time "$3" "$1" -o "$2"
}

resolve_latest_codex_version() {
    local effective prefix latest
    prefix=https://github.com/openai/codex/releases/tag/rust-v
    effective=$(curl -fsSIL --proto '=https' --proto-redir '=https' \
        --tlsv1.2 --connect-timeout 20 --max-time 60 --max-redirs 5 \
        -o /dev/null -w '%{url_effective}' "$CODEX_LATEST_URL") || return 1
    case "$effective" in
        "$prefix"*) latest=${effective#"$prefix"} ;;
        *) return 1 ;;
    esac
    [[ "$latest" =~ ^[0-9]+(\.[0-9]+)+$ ]] || return 1
    printf '%s\n' "$latest"
}

version_is_newer() {
    local candidate=$1 current=$2 newest
    [[ "$candidate" =~ ^[0-9]+(\.[0-9]+)+$ ]] \
        && [[ "$current" =~ ^[0-9]+(\.[0-9]+)+$ ]] || return 1
    [ "$candidate" != "$current" ] || return 1
    newest=$(printf '%s\n%s\n' "$current" "$candidate" | sort -V | tail -1)
    [ "$newest" = "$candidate" ]
}

cli_validate_archive() { # validates $ARCHIVE via $LIST
    tar -tzf "$ARCHIVE" > "$LIST" || fail "Unreadable CLI archive."
    local entry
    while IFS= read -r entry; do
        case "$entry" in
            ""|/*|../*|*/../*|*/..) fail "Unsafe archive path: $entry" ;;
            bin|bin/*|codex-package.json|codex-path|codex-path/*|codex-resources|codex-resources/*) ;;
            *) fail "Unexpected archive path: $entry" ;;
        esac
    done < "$LIST"
    for entry in bin/codex bin/codex-code-mode-host codex-package.json \
                 codex-path/rg codex-resources/bwrap; do
        grep -Fxq "$entry" "$LIST" || fail "Required entry missing: $entry"
    done
    tar -tvzf "$ARCHIVE" | awk '
      substr($1,1,1)!="-" && substr($1,1,1)!="d" {bad=1}
      END {exit bad}
    ' || fail "Archive contains a link or special file."
    python3 - "$ARCHIVE" <<'PY' || fail "Archive structure exceeds the closed safety contract."
from pathlib import PurePosixPath
import sys
import tarfile

archive = sys.argv[1]
required = {
    "bin/codex",
    "bin/codex-code-mode-host",
    "codex-package.json",
    "codex-path/rg",
    "codex-resources/bwrap",
}
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    if not members or len(members) > 10000:
        raise SystemExit("invalid archive member count")
    names = []
    total = 0
    for member in members:
        name = member.name.rstrip("/")
        path = PurePosixPath(name)
        if (not name or "\\" in name or name.startswith("/")
                or ".." in path.parts or "." in path.parts):
            raise SystemExit("unsafe archive path")
        if not (name == "bin" or name.startswith("bin/")
                or name == "codex-package.json"
                or name == "codex-path" or name.startswith("codex-path/")
                or name == "codex-resources"
                or name.startswith("codex-resources/")):
            raise SystemExit("unexpected archive path")
        if not (member.isfile() or member.isdir()):
            raise SystemExit("link or special archive member")
        names.append(name)
        total += member.size
        if total > 2 * 1024**3:
            raise SystemExit("archive expands beyond safety cap")
if len(names) != len(set(names)):
    raise SystemExit("duplicate archive member")
if not required.issubset(names):
    raise SystemExit("required archive member missing")
PY
}

cli_activate() { # VERSION — extracts $ARCHIVE and atomically activates it
    local version=$1 release_name final OLD reported
    release_name="$version-$CODEX_TARGET"
    final="$RELEASES/$release_name"
    install -d -m 0700 "$RELEASES"
    install -d -m 0755 "$BIN_DIR"
    STAGE=$(mktemp -d "$RELEASES/.noid-$release_name.XXXXXX")
    tar -xzf "$ARCHIVE" -C "$STAGE" --no-same-owner --no-same-permissions
    chmod 0755 "$STAGE/bin/codex" "$STAGE/bin/codex-code-mode-host" \
      "$STAGE/codex-path/rg" "$STAGE/codex-resources/bwrap"
    python3 - "$STAGE/codex-package.json" "$version" "$CODEX_TARGET" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    package = json.load(handle)
if package.get("layoutVersion") != 1:
    raise SystemExit("unexpected package layout")
if package.get("version") != sys.argv[2] or package.get("target") != sys.argv[3]:
    raise SystemExit("package metadata does not match the expected release")
if package.get("entrypoint") != "bin/codex":
    raise SystemExit("unexpected package entrypoint")
PY
    reported=$("$STAGE/bin/codex" --version 2>/dev/null || true)
    [ "$reported" = "codex-cli $version" ] || fail "Package reports: $reported"

    if [ -e "$final" ] || [ -L "$final" ]; then
        OLD="$RELEASES/.old-$release_name.$$"
        mv -T "$final" "$OLD"
    else
        OLD=""
    fi
    if ! mv -T "$STAGE" "$final"; then
        [ -n "$OLD" ] && mv -T "$OLD" "$final"
        fail "Could not activate release directory."
    fi
    STAGE=""
    [ -n "$OLD" ] && rm -rf "$OLD"
    TMP_CURRENT="$BASE/.current.noid.$$"
    ln -s "releases/$release_name" "$TMP_CURRENT"
    mv -fT "$TMP_CURRENT" "$CURRENT"
    TMP_CURRENT=""
    TMP_LINK="$BIN_DIR/.codex.noid.$$"
    ln -s "$CURRENT/bin/codex" "$TMP_LINK"
    mv -fT "$TMP_LINK" "$USER_LINK"
    TMP_LINK=""
    reported=$("$USER_LINK" --version 2>/dev/null || true)
    [ "$reported" = "codex-cli $version" ] || fail "Post-install check failed."
    fmt_ok "$reported"
}

require_ext_tools() {
    for name in codium unzip zipinfo; do
        command -v "$name" >/dev/null 2>&1 || fail "Required command missing: $name"
    done
}

vsix_validate_paths() { # validates $VSIX structure via $ZIP_LIST
    unzip -Z1 "$VSIX" > "$ZIP_LIST" || fail "Unreadable VSIX."
    local entry
    while IFS= read -r entry; do
        case "$entry" in
            ""|/*|../*|*/../*|*/..) fail "Unsafe VSIX path: $entry" ;;
            "[Content_Types].xml"|extension.vsixmanifest|extension/*) ;;
            *) fail "Unexpected VSIX path: $entry" ;;
        esac
    done < "$ZIP_LIST"
    zipinfo -l "$VSIX" | awk '
      NR>2 && substr($1,1,1)=="l" {bad=1}
      END {exit bad}
    ' || fail "VSIX contains a symlink."
    python3 - "$VSIX" <<'PY' || fail "VSIX structure exceeds the closed safety contract."
from pathlib import PurePosixPath
import stat
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as zf:
    infos = zf.infolist()
    if not infos or len(infos) > 100000:
        raise SystemExit("invalid VSIX member count")
    names = [entry.filename for entry in infos]
    if len(names) != len(set(names)):
        raise SystemExit("duplicate VSIX member")
    total = 0
    for entry in infos:
        name = entry.filename
        path = PurePosixPath(name)
        if (not name or "\\" in name or name.startswith("/")
                or ".." in path.parts or "." in path.parts):
            raise SystemExit("unsafe VSIX member path")
        if not (name in {"[Content_Types].xml", "extension.vsixmanifest"}
                or name.startswith("extension/")):
            raise SystemExit("unexpected VSIX member path")
        mode = entry.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind and kind not in {stat.S_IFREG, stat.S_IFDIR}:
            raise SystemExit("special VSIX member")
        total += entry.file_size
        if total > 4 * 1024**3:
            raise SystemExit("VSIX expands beyond safety cap")
PY
}

ext_install_file() { # VSIX_FILE VERSION
    codium --install-extension "$1" --pre-release --force
    codium --list-extensions --show-versions 2>/dev/null |
        grep -Fqx "$EXT_ID@$2" || fail "Extension verify failed."
    if command -v pgrep >/dev/null 2>&1 \
       && pgrep -x codium >/dev/null 2>&1; then
        fmt_info "VSCodium is running; reload or restart it to activate the installed extension bytes."
    fi
}

ext_installed_version() {
    codium --list-extensions --show-versions 2>/dev/null | awk -v id="$EXT_ID@" '
        BEGIN { IGNORECASE=1 }
        index(tolower($0), id) == 1 { split($0, part, "@"); print part[2]; exit }
    '
}

if [ "$MODE" = install ]; then
    fmt_banner "NoID Privacy — OpenAI Codex $CODEX_VERSION" \
        "pinned native CLI + optional VSCodium extension"
    fmt_note "Two separate opt-ins, each behind its own prompt:"
    fmt_note "  1. Native standalone CLI, exact size/SHA-256 and safe paths"
    fmt_note "  2. The pinned Codex VSCodium extension from Open VSX (telemetry-aware)"
    fmt_note "No curl|bash, npm or sudo. Shared CLI/IDE defaults:"
    fmt_note "/etc/codex/config.toml (workspace-write, untrusted-command approvals,"
    fmt_note "child-command network off, index-gated web search, OS keyring"
    fmt_note "credentials, update checks/OTel exporters off). Web search is"
    fmt_note "model-controlled without a per-call approval; the shared policy"
    fmt_note "restricts it to material verification with minimized queries. Those"
    fmt_note "are user-overridable defaults. Login/use still sends prompts, selected"
    fmt_note "files/context, tool results and responses to OpenAI. Later updates of"
    fmt_note "installed components are an explicit noid-update-all.sh action over the"
    fmt_note "vendor release channel, recorded in the agent-update ledger."
    echo ""
    installed_cli=0
    installed_any=0
    read -r -p "Install the reviewed native Codex CLI? [y/N] " answer
    case "$answer" in
        [yY]|[yY][eE][sS])
            if [ -L "$USER_LINK" ]; then
                current_cli_path=$(readlink -f "$USER_LINK" 2>/dev/null || true)
                case "$current_cli_path" in
                    "$RELEASES"/*) ;;
                    *) fail "Existing Codex symlink is not NoID Privacy-managed; refusing takeover." ;;
                esac
                current_reported=$("$USER_LINK" --version 2>/dev/null || true)
                current_version=${current_reported#codex-cli }
                [[ "$current_version" =~ ^[0-9]+(\.[0-9]+)+$ ]] \
                    || fail "Existing managed Codex CLI reports an invalid version."
                if version_is_newer "$current_version" "$CODEX_VERSION"; then
                    fail "Installed Codex CLI $current_version is newer than pin $CODEX_VERSION; refusing downgrade."
                fi
            fi
            ARCHIVE=$(mktemp /var/tmp/noid-codex.XXXXXX.tar.gz)
            LIST=$(mktemp /var/tmp/noid-codex.XXXXXX.list)
            fmt_step 1 3 "Download + verification"
            fetch_https "$CODEX_URL" "$ARCHIVE" 600 || \
                fail "CLI download failed; nothing installed."
            actual_size=$(stat -c '%s' "$ARCHIVE")
            [ "$actual_size" = "$CODEX_SIZE" ] ||
                fail "CLI size mismatch (expected $CODEX_SIZE, got $actual_size)."
            actual_sha=$(sha256sum "$ARCHIVE" | awk '{print $1}')
            [ "$actual_sha" = "$CODEX_SHA256" ] || fail "CLI SHA-256 mismatch."
            fmt_ok "exact reviewed bytes"
            fmt_step 2 3 "Archive validation"
            cli_validate_archive
            fmt_step 3 3 "Atomic user install"
            cli_activate "$CODEX_VERSION"
            installed_cli=1
            installed_any=1
            ;;
        *) fmt_info "CLI not installed." ;;
    esac

    echo ""
    fmt_note "Optional VSCodium extension:"
    fmt_note "  Open VSX marks the verified openai.chatgpt Linux build PRE-RELEASE."
    fmt_note "  It activates on editor startup and contains OpenAI product telemetry"
    fmt_note "  plus a Sentry endpoint. VSCodium's core telemetry-off switch does not"
    fmt_note "  govern it, and the extension exposes no supported telemetry-off"
    fmt_note "  setting. NoID Privacy disables startup focus and automatic TODO"
    fmt_note "  CodeLens, but does not call those UI keys telemetry controls. It also"
    fmt_note "  works without the native CLI above."
    read -r -p "Install the pinned Codex VSCodium extension? [y/N] " ext
    case "$ext" in
        [yY]|[yY][eE][sS])
            require_ext_tools
            current_ext=$(ext_installed_version)
            if [ -n "$current_ext" ] \
               && { ! [[ "$current_ext" =~ ^[0-9]+(\.[0-9]+)+$ ]] \
                    || version_is_newer "$current_ext" "$EXT_VERSION"; }; then
                fail "Installed Codex extension ${current_ext:-unknown} is newer than or incompatible with pin $EXT_VERSION; refusing downgrade."
            fi
            VSIX=$(mktemp /var/tmp/noid-codex-ext.XXXXXX.vsix)
            ZIP_LIST=$(mktemp /var/tmp/noid-codex-ext.XXXXXX.list)
            fetch_https \
                "$EXT_API_BASE/$EXT_VERSION/file/$EXT_ID-$EXT_VERSION@linux-x64.vsix" \
                "$VSIX" 900 || fail "VSIX download failed."
            ext_size=$(stat -c '%s' "$VSIX")
            [ "$ext_size" = "$EXT_SIZE" ] || fail "VSIX size mismatch."
            ext_sha=$(sha256sum "$VSIX" | awk '{print $1}')
            [ "$ext_sha" = "$EXT_SHA256" ] || fail "VSIX SHA-256 mismatch."
            vsix_validate_paths
            unzip -p "$VSIX" extension/package.json |
            python3 -c 'import json,sys
p=json.load(sys.stdin)
expected={"name":"chatgpt","publisher":"openai","version":sys.argv[1]}
assert all(p.get(k)==v for k,v in expected.items())
assert p.get("engines",{}).get("vscode")=="^1.96.2"
assert "onStartupFinished" in p.get("activationEvents",[])' "$EXT_VERSION" ||
                fail "VSIX manifest does not match the reviewed package."
            ext_install_file "$VSIX" "$EXT_VERSION"
            fmt_ok "$EXT_ID@$EXT_VERSION installed as explicit opt-in"
            installed_any=1
            ;;
        *) fmt_info "Extension not installed." ;;
    esac

    if [ "$installed_any" = 1 ]; then
        fmt_done "Codex setup complete."
    fi
    if [ "$installed_cli" = 1 ]; then
        fmt_note "Next: codex login"
    elif [ "$installed_any" = 0 ]; then
        fmt_info "Nothing installed."
    fi
    exit 0
fi

# --update: non-interactive refresh of already-opted-in components only.
present=0
failures=0

if ! command -v codex >/dev/null 2>&1; then
    fmt_info "Codex CLI not installed."
else
    cli_path=$(readlink -f "$(command -v codex)" 2>/dev/null || true)
    case "$cli_path" in
        "$RELEASES"/*)
            present=1
            prev_reported=$(codex --version 2>/dev/null || true)
            prev=${prev_reported#codex-cli }
            latest=$(resolve_latest_codex_version 2>/dev/null || true)
            if ! printf '%s' "$latest" | grep -qE '^[0-9]+(\.[0-9]+)+$'; then
                fmt_warn "could not resolve the newest official release"
                failures=$((failures + 1))
            elif ! [[ "$prev" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
                fmt_warn "managed Codex CLI reports an invalid current version"
                failures=$((failures + 1))
            elif [ "$latest" = "$prev" ]; then
                fmt_ok "Codex CLI already current ($prev)"
            elif version_is_newer "$latest" "$prev"; then
                ARCHIVE=$(mktemp /var/tmp/noid-codex.XXXXXX.tar.gz)
                LIST=$(mktemp /var/tmp/noid-codex.XXXXXX.list)
                # A moving release cannot carry a repository byte pin; the
                # archive keeps the full structural validation plus exact
                # metadata match, and the applied SHA-256 is recorded.
                fmt_info "refreshing to official release rust-v$latest"
                fetch_https \
                    "$CODEX_DOWNLOAD_BASE/rust-v$latest/codex-package-$CODEX_TARGET.tar.gz" \
                    "$ARCHIVE" 600 || fail "CLI download failed; installed CLI left as-is."
                cli_validate_archive
                cli_activate "$latest"
                arch_sha=$(sha256sum "$ARCHIVE" | awk '{print $1}')
                ledger_append "component=codex-cli previous=${prev:-unknown} installed=$latest sha256=$arch_sha source=github-releases"
                fmt_ok "Codex CLI ${prev:-unknown} -> $latest (evidence recorded)"
            else
                fmt_warn "official Codex release channel returned an older release ($latest < $prev); refusing downgrade"
                failures=$((failures + 1))
            fi
            ;;
        *)
            fmt_info "Codex CLI is not NoID Privacy-managed; left untouched: ${cli_path:-unknown}"
            ;;
    esac
fi

if ! command -v codium >/dev/null 2>&1; then
    fmt_info "VSCodium not installed."
else
    ext_current=$(ext_installed_version)
    if [ -z "$ext_current" ]; then
        fmt_info "Codex extension not installed."
    else
        present=1
        ext_latest=$(curl -fsS --proto '=https' --tlsv1.2 --connect-timeout 20 \
            --max-time 60 "$EXT_API_BASE" 2>/dev/null |
            python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])' \
            2>/dev/null || true)
        if ! printf '%s' "$ext_latest" | grep -qE '^[0-9]+(\.[0-9]+)+$'; then
            fmt_warn "could not resolve the newest Open VSX release"
            failures=$((failures + 1))
        elif ! [[ "$ext_current" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
            fmt_warn "installed Codex extension reports an invalid version"
            failures=$((failures + 1))
        elif [ "$ext_latest" = "$ext_current" ]; then
            fmt_ok "Codex extension already current ($ext_current)"
        elif version_is_newer "$ext_latest" "$ext_current"; then
            require_ext_tools
            VSIX=$(mktemp /var/tmp/noid-codex-ext.XXXXXX.vsix)
            ZIP_LIST=$(mktemp /var/tmp/noid-codex-ext.XXXXXX.list)
            # Same moving-release rule as the CLI path above: structural and
            # identity validation stay mandatory, evidence is recorded.
            fetch_https \
                "$EXT_API_BASE/$ext_latest/file/$EXT_ID-$ext_latest@linux-x64.vsix" \
                "$VSIX" 900 || fail "VSIX download failed."
            vsix_validate_paths
            unzip -p "$VSIX" extension/package.json |
            python3 -c 'import json,sys
p=json.load(sys.stdin)
expected={"name":"chatgpt","publisher":"openai","version":sys.argv[1]}
assert all(p.get(k)==v for k,v in expected.items())' "$ext_latest" ||
                fail "VSIX manifest does not match the expected identity."
            ext_install_file "$VSIX" "$ext_latest"
            vsix_sha=$(sha256sum "$VSIX" | awk '{print $1}')
            ledger_append "component=codex-ext previous=$ext_current installed=$ext_latest sha256=$vsix_sha source=open-vsx"
            fmt_ok "Codex extension $ext_current -> $ext_latest (evidence recorded)"
        else
            fmt_warn "Open VSX returned an older Codex extension ($ext_latest < $ext_current); refusing downgrade"
            failures=$((failures + 1))
        fi
    fi
fi

[ "$failures" -eq 0 ] || exit 1
[ "$present" -eq 1 ] || exit 3
exit 0
CODEX_INSTALL_EOF

chmod 755 /usr/local/bin/noid-codex-install
chown root:root /usr/local/bin/noid-codex-install
bash -n /usr/local/bin/noid-codex-install || {
    echo "[Module 13] FAIL: noid-codex-install syntax"; exit 1;
}
if grep -qF 'api.github.com/repos/openai/codex/releases/latest' \
        /usr/local/bin/noid-codex-install \
   || ! grep -qF 'https://github.com/openai/codex/releases/latest' \
        /usr/local/bin/noid-codex-install \
   || ! grep -qF 'resolve_latest_codex_version()' \
        /usr/local/bin/noid-codex-install; then
    echo "[Module 13] FAIL: noid-codex-install release resolver"; exit 1
fi
echo "  [OK] /usr/local/bin/noid-codex-install installed (755)"

# ----------------------------------------------------------------------------
# Step 6e: Install /usr/local/bin/noid-protonvpn-install (opt-in VPN)
# ----------------------------------------------------------------------------
# Native install of the official Proton VPN GUI via Proton's own Fedora repo.
# The Proton signing key is fetched, its primary fingerprint is pinned and
# verified BEFORE import (no blind dnf key-accept), then the canonical .repo
# file is written and proton-vpn-gnome-desktop is installed. Updates then
# arrive through the repo via the normal dnf / noid-update-all path. Uses
# sudo for the system-level steps and prompts before doing anything.
echo ""
echo "[Step 6e] Installing /usr/local/bin/noid-protonvpn-install (opt-in)"
cat > /usr/local/bin/noid-protonvpn-install <<'PROTONVPN_INSTALL_EOF'
#!/bin/bash
# Opt-in Proton VPN GUI installer via the official Proton Fedora repository.
# Fingerprint-pinned key verification before import; canonical repo baseurl;
# no blind key-accept, no remote install script. Idempotent and reversible
# (--uninstall). Verified against Proton's Fedora support page 2026-07.
set -euo pipefail
umask 022

FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
# shellcheck source=/dev/null
if [ -r "$FMT_LIB" ]; then . "$FMT_LIB"; else
    fmt_banner(){ echo "== $1 =="; [ -n "${2:-}" ] && echo "   $2"; }
    fmt_step(){ echo "[$1/$2] $3"; }; fmt_ok(){ echo "  OK: $1"; }
    fmt_info(){ echo "  - $1"; }; fmt_warn(){ echo "  ! $1" >&2; }
    fmt_err(){ echo "  ERROR: $1" >&2; }; fmt_note(){ echo "$1"; }
    fmt_done(){ echo "$1"; }
fi
fail() { fmt_err "$*"; exit 1; }

case "$#:${1:-}" in
    0:) ACTION=install ;;
    1:install|1:--install) ACTION=install ;;
    1:--uninstall|1:uninstall) ACTION=uninstall ;;
    1:-h|1:--help) echo "Usage: noid-protonvpn-install [--uninstall]"; exit 0 ;;
    *) fail "Usage: noid-protonvpn-install [--uninstall]" ;;
esac

PKG=proton-vpn-gnome-desktop
PROTON_CORE_PKGS=(proton-vpn-gnome-desktop proton-vpn-gtk-app proton-vpn-daemon)
DAEMON_UNIT=me.proton.vpn.split_tunneling.service
REPO_FILE=/etc/yum.repos.d/protonvpn-fedora-stable.repo
KEY_URL_LIVE="https://repo.protonvpn.com/fedora-$(rpm -E %fedora)-stable/public_key.asc"
KEY_LOCAL=/etc/pki/rpm-gpg/RPM-GPG-KEY-protonvpn
FPR_EXPECTED="6929133BDE1CE1CFA9EDB286D84176F6844830D4"

is_known_proton_posttrans_failure() {
    local transcript=$1
    # RPM reports a non-zero transaction result even though %posttrans runs
    # after all transaction files are installed. Recover only Proton's exact
    # daemon-scriptlet signature; unrelated DNF failures remain fatal.
    LC_ALL=C grep -Ei \
        '(%?posttrans[^[:cntrl:]]*proton-vpn-daemon|proton-vpn-daemon[^[:cntrl:]]*%?posttrans)' \
        "$transcript" |
        LC_ALL=C grep -Eqi \
            '(fail(ed|ure)?|error|fehlgeschlagen|fehler|status[[:space:],:=_-]*1|code[[:space:],:=_-]*1)'
}

[ "$EUID" -ne 0 ] || fail "Run this installer without sudo; it elevates only where required."
[ "$(uname -m)" = "x86_64" ] || fail "Proton VPN's Fedora repo targets x86_64."
for c in curl gpg rpm rpmkeys sudo dnf awk grep tee systemctl flock cmp \
         restorecon matchpathcon stat; do
    command -v "$c" >/dev/null 2>&1 || fail "Required command missing: $c"
done
exec 9<"$0"
flock -n 9 || fail "Another Proton VPN installer run is already active."

if [ "$ACTION" = uninstall ]; then
    fmt_banner "Proton VPN — Uninstall"
    sudo rpm -q "$PKG" >/dev/null 2>&1 && { fmt_step 1 2 "Removing $PKG"; sudo dnf -y remove "$PKG" || fail "Package removal failed."; fmt_ok "removed"; } || fmt_info "$PKG not installed"
    fmt_step 2 2 "Removing repo file (key left in the trust store)"
    [ -e "$REPO_FILE" ] && sudo rm -f -- "$REPO_FILE" && fmt_ok "repo removed" || fmt_info "no repo file"
    fmt_done "Proton VPN removed."
    exit 0
fi

fmt_banner "Proton VPN — Official GUI" "Proton's Fedora repo · signing key fingerprint-verified"
fmt_note "Installs proton-vpn-gnome-desktop from Proton's official repository."
fmt_note "The vendor signing key is verified against a pinned fingerprint"
fmt_note "before it is trusted — no blind key-accept."
echo ""
read -r -p "Install Proton VPN now? [y/N] " a
case "$a" in [yY]|[yY][eE][sS]) ;; *) echo "Nothing installed."; exit 0 ;; esac

TMPKEY=$(mktemp /tmp/noid-protonvpn-key.XXXXXX.asc)
DNF_TRANSCRIPT=
cleanup() {
    [ -z "${TMPKEY:-}" ] || rm -f -- "$TMPKEY"
    [ -z "${DNF_TRANSCRIPT:-}" ] || rm -f -- "$DNF_TRANSCRIPT"
    return 0
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fmt_step 1 4 "Fetch + verify Proton signing key"
curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --max-redirs 3 --connect-timeout 20 --max-time 60 \
    -o "$TMPKEY" "$KEY_URL_LIVE" || fail "Could not download the Proton signing key."
mapfile -t PRIMARY_FPRS < <(
    gpg --batch --show-keys --with-colons "$TMPKEY" 2>/dev/null |
        awk -F: '
            /^pub:/ { primaries++; want_fpr=1; next }
            want_fpr && /^fpr:/ { print toupper($10); want_fpr=0 }
            END { if (primaries == 0 || want_fpr) exit 1 }
        '
)
[ "${#PRIMARY_FPRS[@]}" -eq 1 ] \
    && [ "${PRIMARY_FPRS[0]}" = "$FPR_EXPECTED" ] \
    || fail "Proton keyring primary-key set is not exactly the pinned fingerprint $FPR_EXPECTED. Aborting."
fmt_ok "sole primary fingerprint verified: $FPR_EXPECTED"

fmt_step 2 4 "Import key into the RPM trust store"
sudo install -Dm0644 -o root -g root "$TMPKEY" "$KEY_LOCAL"
sudo cmp -s -- "$TMPKEY" "$KEY_LOCAL" \
    || fail "Installed Proton key differs from the verified download."
sudo restorecon -F "$KEY_LOCAL"
[ "$(sudo stat -Lc '%u:%g:%a:%h' "$KEY_LOCAL" \
        2>/dev/null || true)" = 0:0:644:1 ] \
    && sudo matchpathcon -V "$KEY_LOCAL" >/dev/null \
    || fail "Installed Proton key metadata or SELinux label is unsafe."
if sudo rpmkeys --list "$FPR_EXPECTED" >/dev/null 2>&1; then
    fmt_info "the exact Proton signing key is already trusted"
else
    sudo rpmkeys --import "$KEY_LOCAL" || fail "Key import failed."
    fmt_ok "key imported"
fi
sudo rpmkeys --list "$FPR_EXPECTED" >/dev/null 2>&1 ||
    fail "The exact Proton signing key is absent after import."

fmt_step 3 4 "Write Proton's canonical repository definition"
sudo tee "$REPO_FILE" >/dev/null <<REPO
#
# ProtonVPN stable release — managed by noid-protonvpn-install
#
[protonvpn-fedora-stable]
name = ProtonVPN Fedora Stable repository
baseurl = https://repo.protonvpn.com/fedora-\$releasever-stable
enabled = 1
gpgcheck = 1
repo_gpgcheck = 0
skip_if_unavailable = true
gpgkey = file://$KEY_LOCAL
REPO
sudo chmod 0644 "$REPO_FILE"
sudo chown root:root "$REPO_FILE"
sudo restorecon -F "$REPO_FILE"
[ "$(sudo stat -Lc '%u:%g:%a:%h' "$REPO_FILE" \
        2>/dev/null || true)" = 0:0:644:1 ] \
    && sudo matchpathcon -V "$REPO_FILE" >/dev/null \
    || fail "Proton repository metadata or SELinux label is unsafe."
fmt_ok "repo written: $REPO_FILE"

fmt_step 4 4 "Install $PKG (gpg-checked against the pinned key)"
DNF_TRANSCRIPT=$(mktemp /tmp/noid-protonvpn-dnf.XXXXXX.log)
set +e
sudo dnf -y --refresh install "$PKG" 2>&1 | tee "$DNF_TRANSCRIPT"
dnf_status=("${PIPESTATUS[@]}")
set -e
[ "${dnf_status[1]}" -eq 0 ] || fail "Could not capture DNF's transaction result."
dnf_rc=${dnf_status[0]}

if [ "$dnf_rc" -ne 0 ]; then
    if is_known_proton_posttrans_failure "$DNF_TRANSCRIPT"; then
        fmt_warn "Proton's daemon failed during its package %posttrans; verifying the completed transaction before retrying it."
    else
        fail "dnf install failed with an unrecognized error (exit $dnf_rc)."
    fi
fi

for installed_pkg in "${PROTON_CORE_PKGS[@]}"; do
    sudo rpm -q -- "$installed_pkg" >/dev/null 2>&1 ||
        fail "Post-install verification failed: $installed_pkg is not installed."
done

if ! sudo systemctl is-active --quiet "$DAEMON_UNIT"; then
    fmt_info "retrying Proton's split-tunneling daemon after package completion"
    sudo systemctl restart "$DAEMON_UNIT" ||
        fail "Installed packages are present, but $DAEMON_UNIT could not be started."
fi
sudo systemctl is-active --quiet "$DAEMON_UNIT" ||
    fail "Installed packages are present, but $DAEMON_UNIT is not active."

if [ "$dnf_rc" -ne 0 ]; then
    fmt_ok "packages verified and Proton daemon recovered after the known %posttrans failure"
else
    fmt_ok "packages verified and Proton daemon active"
fi
fmt_done "Proton VPN installed. Launch it from the app grid and sign in."
fmt_note "Set it to auto-connect, then run your first system update through the tunnel."
exit 0
PROTONVPN_INSTALL_EOF
chmod 755 /usr/local/bin/noid-protonvpn-install
chown root:root /usr/local/bin/noid-protonvpn-install
bash -n /usr/local/bin/noid-protonvpn-install || {
    echo "[Module 13] FAIL: noid-protonvpn-install syntax"; exit 1;
}
echo "  [OK] /usr/local/bin/noid-protonvpn-install installed (755)"

# ----------------------------------------------------------------------------
# Step 6f: Install /usr/local/bin/noid-mullvad-install (opt-in VPN)
# ----------------------------------------------------------------------------
# Native install of the official Mullvad VPN app via Mullvad's own RPM repo.
# The bundled Mullvad keyring is fetched, its published code-signing key
# fingerprint is required to be present BEFORE import, then the canonical
# .repo file is written and mullvad-vpn is installed. Updates arrive through
# the repo via the normal dnf / noid-update-all path.
echo ""
echo "[Step 6f] Installing /usr/local/bin/noid-mullvad-install (opt-in)"
cat > /usr/local/bin/noid-mullvad-install <<'MULLVAD_INSTALL_EOF'
#!/bin/bash
# Opt-in Mullvad VPN app installer via the official Mullvad RPM repository.
# The fetched keyring must contain exactly one primary key and that primary must
# be Mullvad's published code-signing fingerprint. No blind key-accept, no remote
# install script. Idempotent and reversible (--uninstall). Verified against
# Mullvad's Fedora + signature-verification pages 2026-07.
set -euo pipefail
umask 022

FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
# shellcheck source=/dev/null
if [ -r "$FMT_LIB" ]; then . "$FMT_LIB"; else
    fmt_banner(){ echo "== $1 =="; [ -n "${2:-}" ] && echo "   $2"; }
    fmt_step(){ echo "[$1/$2] $3"; }; fmt_ok(){ echo "  OK: $1"; }
    fmt_info(){ echo "  - $1"; }; fmt_warn(){ echo "  ! $1" >&2; }
    fmt_err(){ echo "  ERROR: $1" >&2; }; fmt_note(){ echo "$1"; }
    fmt_done(){ echo "$1"; }
fi
fail() { fmt_err "$*"; exit 1; }

case "$#:${1:-}" in
    0:) ACTION=install ;;
    1:install|1:--install) ACTION=install ;;
    1:--uninstall|1:uninstall) ACTION=uninstall ;;
    1:-h|1:--help) echo "Usage: noid-mullvad-install [--uninstall]"; exit 0 ;;
    *) fail "Usage: noid-mullvad-install [--uninstall]" ;;
esac

PKG=mullvad-vpn
REPO_FILE=/etc/yum.repos.d/mullvad-stable.repo
KEY_URL="https://repository.mullvad.net/rpm/mullvad-keyring.asc"
KEY_LOCAL=/etc/pki/rpm-gpg/RPM-GPG-KEY-mullvad
FPR_EXPECTED="A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF"

[ "$EUID" -ne 0 ] || fail "Run this installer without sudo; it elevates only where required."
[ "$(uname -m)" = "x86_64" ] || fail "Mullvad's Fedora repo targets x86_64."
for c in curl gpg rpm rpmkeys sudo dnf awk cmp flock restorecon matchpathcon \
         stat; do
    command -v "$c" >/dev/null 2>&1 || fail "Required command missing: $c"
done
exec 9</usr/local/bin/noid-mullvad-install
flock -n 9 || fail "Another Mullvad installer run is already active."

pkg_installed() {
    local query_output query_rc
    if query_output=$(
        sudo /usr/bin/env LC_ALL=C /usr/bin/rpm \
            -q --qf '%{NAME}\n' -- "$PKG" 2>&1
    ); then
        [ "$query_output" = "$PKG" ] \
            || fail "RPM returned an unexpected installed-package record."
        return 0
    else
        query_rc=$?
    fi
    if [ "$query_rc" -eq 1 ] \
       && [ "$query_output" = "package $PKG is not installed" ]; then
        return 1
    fi
    if [ -n "$query_output" ]; then
        fail "RPM package-state query failed: $query_output"
    fi
    fail "RPM package-state query failed without a diagnostic."
}

if [ "$ACTION" = uninstall ]; then
    fmt_banner "Mullvad VPN — Uninstall"
    if pkg_installed; then
        fmt_step 1 2 "Removing $PKG"
        sudo dnf -y remove "$PKG" || fail "Package removal failed."
        if pkg_installed; then
            fail "$PKG remains installed after the removal transaction."
        fi
        fmt_ok "removed"
    else
        fmt_info "$PKG not installed"
    fi
    fmt_step 2 2 "Removing repo file (key left in the trust store)"
    [ -e "$REPO_FILE" ] && sudo rm -f -- "$REPO_FILE" && fmt_ok "repo removed" || fmt_info "no repo file"
    fmt_done "Mullvad VPN removed."
    exit 0
fi

fmt_banner "Mullvad VPN — Official App" "Mullvad's RPM repo · code-signing key fingerprint-verified"
fmt_note "Installs mullvad-vpn from Mullvad's official repository. The vendor"
fmt_note "code-signing key fingerprint is verified against a pinned value"
fmt_note "before the keyring is trusted — no blind key-accept."
echo ""
read -r -p "Install Mullvad VPN now? [y/N] " a
case "$a" in [yY]|[yY][eE][sS]) ;; *) echo "Nothing installed."; exit 0 ;; esac

TMPKEY=$(mktemp /tmp/noid-mullvad-key.XXXXXX.asc)
cleanup() { [ -n "${TMPKEY:-}" ] && rm -f "$TMPKEY"; return 0; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fmt_step 1 4 "Fetch + verify Mullvad keyring"
curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --max-redirs 3 --connect-timeout 20 --max-time 60 \
    -o "$TMPKEY" "$KEY_URL" || fail "Could not download the Mullvad keyring."
mapfile -t PRIMARY_FPRS < <(
    gpg --batch --show-keys --with-colons "$TMPKEY" 2>/dev/null |
        awk -F: '
            /^pub:/ { primaries++; want_fpr=1; next }
            want_fpr && /^fpr:/ { print toupper($10); want_fpr=0 }
            END { if (primaries == 0 || want_fpr) exit 1 }
        '
)
[ "${#PRIMARY_FPRS[@]}" -eq 1 ] \
    && [ "${PRIMARY_FPRS[0]}" = "$FPR_EXPECTED" ] \
    || fail "Mullvad keyring primary-key set is not exactly the pinned fingerprint $FPR_EXPECTED. Aborting."
fmt_ok "sole primary fingerprint verified: $FPR_EXPECTED"

fmt_step 2 4 "Import keyring into the RPM trust store"
sudo install -Dm0644 -o root -g root "$TMPKEY" "$KEY_LOCAL"
sudo cmp -s -- "$TMPKEY" "$KEY_LOCAL" \
    || fail "Installed Mullvad keyring differs from the verified download."
sudo restorecon -F "$KEY_LOCAL"
[ "$(sudo stat -Lc '%u:%g:%a:%h' "$KEY_LOCAL" \
        2>/dev/null || true)" = 0:0:644:1 ] \
    && sudo matchpathcon -V "$KEY_LOCAL" >/dev/null \
    || fail "Installed Mullvad key metadata or SELinux label is unsafe."
if sudo rpmkeys --list "$FPR_EXPECTED" >/dev/null 2>&1; then
    fmt_info "the exact Mullvad signing key is already trusted"
else
    sudo rpmkeys --import "$KEY_LOCAL" || fail "Key import failed."
    fmt_ok "keyring imported"
fi
sudo rpmkeys --list "$FPR_EXPECTED" >/dev/null 2>&1 \
    || fail "The exact Mullvad signing key is absent after import."

fmt_step 3 4 "Write Mullvad's canonical repository definition"
sudo tee "$REPO_FILE" >/dev/null <<REPO
# Mullvad VPN — managed by noid-mullvad-install
[mullvad-stable]
name=Mullvad VPN
baseurl=https://repository.mullvad.net/rpm/stable/\$basearch
type=rpm
enabled=1
gpgcheck=1
gpgkey=file://$KEY_LOCAL
REPO
sudo chmod 0644 "$REPO_FILE"
sudo chown root:root "$REPO_FILE"
sudo restorecon -F "$REPO_FILE"
[ "$(sudo stat -Lc '%u:%g:%a:%h' "$REPO_FILE" \
        2>/dev/null || true)" = 0:0:644:1 ] \
    && sudo matchpathcon -V "$REPO_FILE" >/dev/null \
    || fail "Mullvad repository metadata or SELinux label is unsafe."
fmt_ok "repo written: $REPO_FILE"

fmt_step 4 4 "Install $PKG (gpg-checked against the pinned keyring)"
sudo dnf -y --refresh install "$PKG" || fail "dnf install failed."
pkg_installed || fail "Post-install verification failed."

# WAN-egress-strict pins Mullvad's kernel tunnel by reading `wg show`, and its
# daemon drives the kernel through netlink without ever needing wireguard-tools.
# Module 26 therefore ships that package, so this normally only confirms it.
# The recovery branch exists because a host can reach this installer without
# it: an image predating the M26 include, or an administrator who removed it.
# Without the package the endpoint is never pinned and an armed boundary drops
# every handshake -- measured, with the peer's handshake timestamp frozen until
# the package was present and resuming immediately once it was.
if ! rpm -q wireguard-tools >/dev/null 2>&1; then
    if sudo dnf -y install wireguard-tools >/dev/null 2>&1 \
       && rpm -q wireguard-tools >/dev/null 2>&1; then
        fmt_ok "wireguard-tools installed (WAN-egress-strict can pin this tunnel)"
    else
        fmt_warn "wireguard-tools could not be installed."
        fmt_warn "With WAN-egress-strict armed, Mullvad's tunnel cannot be pinned"
        fmt_warn "and its handshake will be blocked. Install it, then reconnect:"
        fmt_warn "  sudo dnf install wireguard-tools"
    fi
else
    fmt_ok "wireguard-tools present (WAN-egress-strict can pin this tunnel)"
fi

fmt_done "Mullvad VPN installed. Launch it from the app grid and log in with your account number."
fmt_note "Enable auto-connect, then run your first system update through the tunnel."
exit 0
MULLVAD_INSTALL_EOF
chmod 755 /usr/local/bin/noid-mullvad-install
chown root:root /usr/local/bin/noid-mullvad-install
bash -n /usr/local/bin/noid-mullvad-install || {
    echo "[Module 13] FAIL: noid-mullvad-install syntax"; exit 1;
}
echo "  [OK] /usr/local/bin/noid-mullvad-install installed (755)"

# ----------------------------------------------------------------------------
# Step 6g: Install /usr/local/bin/noid-autostart-netwait
# ----------------------------------------------------------------------------
# Provider-neutral autostart gate. XDG autostart has no ordering contract with
# NetworkManager, so gnome-session starts every entry seconds before wifi
# association completes. A VPN client that probes its server once at startup
# then fails permanently, and the visible symptom looks like a firewall problem
# although no packet was ever dropped. This wrapper delays such an entry until a
# physical carrier exists, and fails open on every error path so it can never be
# the reason an application does not start. The App Autostart picker selects it
# initially only for semantically recognizable VPN/WireGuard/OpenVPN clients;
# the per-app switch remains the user's authoritative, reversible choice.
echo ""
echo "[Step 6g] Installing /usr/local/bin/noid-autostart-netwait"
cat > /usr/local/bin/noid-autostart-netwait <<'NETWAIT_EOF'
#!/bin/bash
# noid-autostart-netwait — hold an autostarted application back until the
# physical network is actually up, then exec it. Provider-neutral.
#
# Why this exists
# ---------------
# XDG autostart has no ordering contract with NetworkManager. gnome-session
# launches every entry as soon as the session is ready, which on a fast machine
# is several seconds before wifi association completes. A client that probes the
# network once at startup and does not retry therefore fails permanently through
# no fault of the firewall, the tunnel or the provider.
#
# `nm-online` cannot express the condition we need. It waits for "a connection",
# and a VPN client's own kill-switch placeholder is a fully activated
# NetworkManager connection that owns the default route while no packet can
# leave the host. Waiting for it is waiting for nothing.
#
# This helper waits for a *physical carrier* instead: a NetworkManager device in
# state 100 (activated) that is backed by real hardware in the kernel, proven by
# /sys/class/net/<dev>/device, or whose device type cannot be a tunnel at all
# (ADSL/PPP/mobile broadband have no such symlink but are never virtual).
# Device-type strings are only ever used to *reject*; acceptance rests on the
# kernel, so unusual or future NetworkManager type names cannot smuggle a dummy
# or tunnel device past the gate.
#
# Fail-open by contract
# ---------------------
# Every error path, an unreachable NetworkManager and the timeout all end in
# exec'ing the requested command. This helper may delay an application. It must
# never be the reason one does not start.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Deliberately no `set -e`: an aborted probe must fall through to the exec,
# never terminate the wrapper and swallow the user's application.
set -uo pipefail
umask 022

# Human --check/help invocations share the same terminal frame as every other
# public NoID Privacy CLI. XDG autostart runs without a TTY, so the wrapper's
# fail-open execution and journal contract remain byte-for-byte quiet there.
# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Network Gate" \
    NOID_FMT_AUTO_SUBTITLE="Physical-link readiness" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

PROG=noid-autostart-netwait
LOG_TAG=$PROG

DEFAULT_TIMEOUT=30
# No settle by default. NetworkManager reaches state 100 only after the
# activation-blocking pre-up dispatcher chain has run, so a further pause buys
# nothing; measured on the reference host that chain completes in ~250 ms. The
# knob stays available for hosts with slow non-blocking 'up' work.
DEFAULT_SETTLE=0

# Overridable for the offline test harness only. On a real session this is the
# kernel's own view and must not be redirected.
SYS_CLASS_NET=${NOID_AUTOSTART_NETWAIT_SYSFS:-/sys/class/net}

timeout_s=${NOID_AUTOSTART_NETWAIT_TIMEOUT:-$DEFAULT_TIMEOUT}
settle_s=${NOID_AUTOSTART_NETWAIT_SETTLE:-$DEFAULT_SETTLE}
quiet=0
check_only=0

usage() {
    cat <<'USAGE_EOF'
Usage: noid-autostart-netwait [OPTIONS] [--] COMMAND [ARGS...]
       noid-autostart-netwait --check

Wait until a physical network device is activated, then run COMMAND.

Options:
  -t, --timeout SECONDS   give up waiting after SECONDS and start anyway
                          (default 30, 0 disables the wait entirely)
  -s, --settle SECONDS    additional pause after the link appears, for hosts
                          with slow non-blocking 'up' dispatcher work
                          (default 0)
  -q, --quiet             do not write a journal line
      --check             report link state and exit; 0 = physical link up,
                          1 = none. Runs no command.
  -h, --help              show this help

Environment:
  NOID_AUTOSTART_NETWAIT_TIMEOUT, NOID_AUTOSTART_NETWAIT_SETTLE
      same meaning as the options; the options win.

Exit status:
  the status of COMMAND, or 2 when the invocation itself was wrong.
USAGE_EOF
}

note() {
    [ "$quiet" -eq 1 ] && return 0
    logger -t "$LOG_TAG" -- "$1" 2>/dev/null || true
}

# Monotonic centiseconds. /proc/uptime is immune to the clock step that chrony
# performs shortly after boot, which is exactly the window this helper runs in.
now_cs() {
    local up _rest
    if read -r up _rest < /proc/uptime 2>/dev/null && [ -n "$up" ]; then
        printf '%s' "${up/./}"
        return 0
    fi
    printf '0'
}

# nmcli -t escapes ':' and '\' inside values; undo that for the device name.
unescape_field() {
    local v=$1
    v=${v//\\:/:}
    v=${v//\\\\/\\}
    printf '%s' "$v"
}

# 0 = at least one physical device is activated, 1 = none (yet).
# On success the accepting device is left in GATE_DEVICE so --check can name it;
# the wait path never reports it, because a journal line does not need to carry
# an interface name to be useful.
GATE_DEVICE=
physical_link_up() {
    local dev typ state found=1
    GATE_DEVICE=

    while IFS=: read -r dev typ; do
        [ -n "$dev" ] || continue
        dev=$(unescape_field "$dev")
        typ=$(unescape_field "$typ")

        # Reject everything that can exist without a carrier. A kill-switch
        # placeholder is a 'dummy'; the tunnel itself is 'wireguard'/'tun'/'vpn'.
        # Aggregates are listed for the reader's benefit: they carry no bus
        # device either, and their enslaved port reports activated in its own
        # right, so the gate still opens on a bond or bridge uplink.
        case $typ in
            loopback|dummy|wireguard|tun|tap|vpn|wifi-p2p) continue ;;
            ip-tunnel|ipip|veth|vxlan|macvlan|macvtap|vrf) continue ;;
            6lowpan|wpan|ovs-*|bridge|bond|team) continue ;;
        esac

        # Acceptance is kernel-backed: a real NIC has a bus device behind it.
        # PPPoE/ADSL and mobile broadband legitimately have none, and none of
        # those types can be a software tunnel, so they are allowed by type.
        if [ ! -e "$SYS_CLASS_NET/$dev/device" ]; then
            case $typ in
                adsl|ppp|pppoe|bt|wwan|gsm|cdma|modem) : ;;
                *) continue ;;
            esac
        fi

        # Numeric device state, so the check does not depend on the locale of
        # nmcli's human-readable strings. 100 = NM_DEVICE_STATE_ACTIVATED.
        state=$(nmcli -g GENERAL.STATE device show "$dev" 2>/dev/null)
        state=${state%% *}
        if [ "$state" = "100" ]; then
            GATE_DEVICE=$dev
            found=0
            break
        fi
    done < <(nmcli -t -f DEVICE,TYPE device status 2>/dev/null)

    return "$found"
}

while [ $# -gt 0 ]; do
    case $1 in
        -t|--timeout)
            [ $# -ge 2 ] || { echo "$PROG: --timeout needs a value" >&2; exit 2; }
            timeout_s=$2; shift 2 ;;
        -s|--settle)
            [ $# -ge 2 ] || { echo "$PROG: --settle needs a value" >&2; exit 2; }
            settle_s=$2; shift 2 ;;
        -q|--quiet)  quiet=1; shift ;;
        --check)     check_only=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        --)          shift; break ;;
        -*)          echo "$PROG: unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)           break ;;
    esac
done

[[ $timeout_s =~ ^[0-9]+$ ]] || timeout_s=$DEFAULT_TIMEOUT
[[ $settle_s  =~ ^[0-9]+$ ]] || settle_s=$DEFAULT_SETTLE

if [ "$check_only" -eq 1 ]; then
    if ! command -v nmcli >/dev/null 2>&1; then
        echo "no NetworkManager client available"
        exit 1
    fi
    if physical_link_up; then
        echo "physical network device activated: $GATE_DEVICE"
        exit 0
    fi
    echo "no activated physical network device"
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "$PROG: no command given" >&2
    usage >&2
    exit 2
fi

# From here on every path must reach the exec below.
if [ "$timeout_s" -gt 0 ] && command -v nmcli >/dev/null 2>&1; then
    started_cs=$(now_cs)
    deadline_cs=$(( started_cs + timeout_s * 100 ))
    waited=0

    while :; do
        if physical_link_up; then
            elapsed_ms=$(( ( $(now_cs) - started_cs ) * 10 ))
            if [ "$waited" -eq 1 ]; then
                note "physical link up after ${elapsed_ms} ms; settling ${settle_s}s"
                [ "$settle_s" -gt 0 ] && sleep "$settle_s"
            fi
            break
        fi
        if [ "$(now_cs)" -ge "$deadline_cs" ]; then
            note "no physical link after ${timeout_s}s; starting anyway (fail-open)"
            break
        fi
        waited=1
        sleep 0.5
    done
fi

exec "$@"
NETWAIT_EOF
chmod 755 /usr/local/bin/noid-autostart-netwait
chown root:root /usr/local/bin/noid-autostart-netwait
bash -n /usr/local/bin/noid-autostart-netwait || {
    echo "[Module 13] FAIL: noid-autostart-netwait syntax"; exit 1;
}
echo "  [OK] /usr/local/bin/noid-autostart-netwait installed (755)"

# ----------------------------------------------------------------------------
# Step 7: Install xdg autostart .desktop entry for welcome notification
# ----------------------------------------------------------------------------
echo ""
echo "[Step 7] Installing /etc/xdg/autostart/noid-welcome.desktop"

mkdir -p /etc/xdg/autostart

cat > /etc/xdg/autostart/noid-welcome.desktop <<'DESKTOP_EOF'
[Desktop Entry]
Type=Application
Name=NoID Privacy Setup
GenericName=System Setup
Comment=Open guided NoID Privacy setup after first sign-in
# --autostart is required for the one-shot GNOME-initial-setup sentinel wait.
# The live-media auto path is suppressed; a user may still open Setup manually
# there with the app-grid launcher's --again mode.
Exec=/usr/local/bin/noid-welcome.sh --autostart
Icon=noid-privacy-setup
# StartupWMClass — matches our GTK4 libadwaita window class so GNOME Shell
# maps the running window to this .desktop entry (custom icon in dock instead
# of generic). Set via welcome.py APP_ID = 'com.noidprivacy.Welcome'.
StartupWMClass=com.noidprivacy.Welcome
StartupNotify=true
NoDisplay=true
X-GNOME-Autostart-enabled=true
# The --autostart Python path waits for GNOME's
# ~/.config/gnome-initial-setup-done sentinel before opening. Do not use
# AutostartCondition= here: systemd-xdg-autostart-generator would require the
# no-longer-shipped gnome-systemd-autostart-condition helper and silently omit
# this application.
# NOTE: X-GNOME-Autostart-Phase was intentionally REMOVED.
# GNOME 49+ (Fedora 44 ships GNOME 50) rejects .desktop files with
# X-GNOME-Autostart-Phase as errors in journalctl. gnome-session no
# longer manages session services via this key — only user-level app
# autostart via XDG. Removing the key reverts to default "Application"
# phase which is handled by the generic XDG autostart mechanism.
# See: https://discourse.gnome.org/t/autostart-files-with-x-gnome-autostart-phase-entry-in-gnome-49/31620
# NOTE: OnlyShowIn=GNOME; REMOVED.
# Welcome dialog is GTK4 + libadwaita Python (rewrite —
# replaced legacy zenity bash welcome). DE-agnostic, runs in any modern
# desktop. Per XDG spec OnlyShowIn should only restrict where DE-specific
# behavior exists.
DESKTOP_EOF

chmod 644 /etc/xdg/autostart/noid-welcome.desktop
chown root:root /etc/xdg/autostart/noid-welcome.desktop
echo "  [OK] noid-welcome.desktop installed (644)"

# Step 7a: Install /usr/share/applications/noid-welcome.desktop
# Companion to autostart entry — this one IS visible in app-grid so users can
# re-launch the welcome dialog from Activities. Uses --again flag so the dialog
# re-opens even after first-boot completion sentinel exists.
cat > /usr/share/applications/noid-welcome.desktop <<'APPDESKTOP_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=NoID Privacy Setup
GenericName=System Setup
Comment=Review NoID Privacy setup, recovery and optional features
# Match the autostart entry and inherit the maintained session renderer.
Exec=/usr/local/bin/noid-welcome.sh --again
Icon=noid-privacy-setup
# GTK4 libadwaita match (was Zenity leftover)
StartupWMClass=com.noidprivacy.Welcome
StartupNotify=true
# "System;Settings;" had 2 main categories
# (desktop-file-validate hint). Settings; alone matches GNOME Preferences
# submenu — appropriate for a setup wizard. Mirrors the M36 fix.
Categories=Settings;
Terminal=false
Keywords=NoID Privacy;Privacy;Setup;Recovery;Hardening;
APPDESKTOP_EOF
chmod 644 /usr/share/applications/noid-welcome.desktop
chown root:root /usr/share/applications/noid-welcome.desktop
echo "  [OK] /usr/share/applications/noid-welcome.desktop installed (app-grid launcher)"

# ----------------------------------------------------------------------------
# Step 7b: Install /usr/local/bin/noid-status (cross-Module diagnostic CLI)
# ----------------------------------------------------------------------------
#
# Self-discovery tool for users. Shows state of all hardening components in
# one screen: AIDE, audit-notify, SELinux, firewall, VPN, USBGuard, LUKS,
# kernel lockdown, Secure Boot, HSI score, etc. Read-only, no config changes.
#
# Thematic fit: M13 already ships user-facing tooling (noid-welcome,
# aide-notify, notifications.md). noid-status extends that pattern into a
# cross-Module status view.
#
echo ""
echo "[Step 7b] Installing /usr/local/bin/noid-status"

cat > /usr/local/bin/noid-status <<'STATUS_EOF'
#!/bin/bash
# noid-status — NoID Privacy hardening state diagnostic
#
# Read-only one-screen overview of all hardening components installed by
# the image. Safe to run as any user (skips root-only checks gracefully).
# Runs multiple system queries in parallel where possible.
#
# Usage: noid-status            (full overview)
#        noid-status --brief    (single-line summary)
#        noid-status --json     (machine-readable RFC 8259 JSON object)

set -euo pipefail
# This diagnostic parses `stat -c %F` and other tool output against English
# literals, and it runs interactively under the user's own locale. Pin the parse
# locale so a localized desktop cannot turn a healthy component into a reported
# defect. All strings this script prints are English regardless.
LC_ALL=C.UTF-8
export LC_ALL

MODE="full"
case "$#:${1:-}" in
    0:) ;;
    1:--brief) MODE="brief" ;;
    1:--json)  MODE="json" ;;
    1:--help|1:-h)
        cat <<HELP
noid-status — NoID Privacy hardening state diagnostic

Usage: noid-status [--brief|--json|--help]

Sections:
  Kernel         : lockdown mode, Secure Boot, module signature enforcement
  SELinux        : enforcing/permissive state
  Firewall       : firewalld state, default zone, physical XDP/TC boundary
  VPN            : WireGuard/VPN interface presence
  DNS            : persistent global/physical policy and active routing scope
  Authentication : faillock state for current user + config (deny/unlock/dir)
  Integrity      : AIDE timer, audit-notify, auditd + boot-scoped storage marker
  Hardware       : USBGuard state, Intel ME (HSI score)
  Storage        : LUKS volume count, LUKS-Backup status (run noid-luks-backup.sh), snapper snapshot count
  Updates        : update-reminder timer, add-on marketplace check age (read
                   from local state only; no network request) and
                   reboot-required state

For full rollback/update workflow see:
  /usr/share/doc/noid-privacy/notifications.md
  /usr/share/doc/noid-privacy/20-rollback-recovery.md
HELP
        exit 0
        ;;
    *)
        echo "Usage: noid-status [--brief|--json|--help]" >&2
        exit 2
        ;;
esac

FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
# shellcheck source=/dev/null
if [ -r "$FMT_LIB" ]; then
    . "$FMT_LIB"
else
    fmt_banner(){ echo "== $1 =="; [ -n "${2:-}" ] && echo "   $2"; }
    fmt_section(){ printf '\n-- %s --\n' "$1"; }
    fmt_kv(){ printf '  %-22s %s\n' "$1" "$2"; }
    fmt_kv_warn(){ printf '  %-22s ! %s\n' "$1" "$2"; }
    fmt_note(){ printf '%s\n' "$1"; }
fi

# ------------------------------------------------------------
# Collect state (best-effort, tolerant of missing commands)
# ------------------------------------------------------------

# Kernel lockdown. Missing securityfs/LSM support is a reportable unknown, not
# a reason for this best-effort diagnostic to abort under errexit.
LOCKDOWN="unknown"
if [ -r /sys/kernel/security/lockdown ]; then
    lockdown_probe=""
    lockdown_probe=$(awk -F'[][]' '/\[/ {print $2}' /sys/kernel/security/lockdown 2>/dev/null || true)
    LOCKDOWN="${lockdown_probe:-unknown}"
fi

# Secure Boot
if command -v mokutil >/dev/null 2>&1; then
    SB_RAW=""
    if SB_RAW=$(mokutil --sb-state 2>/dev/null); then
        SB=${SB_RAW%%$'\n'*}
        case "$SB" in
            *enabled*) SB="enabled" ;;
            *disabled*) SB="disabled" ;;
            *) SB="unknown" ;;
        esac
    else
        SB="unknown"
    fi
else
    SB="unknown (mokutil missing)"
fi

# Module signature enforcement
SIG_ENF="unknown"
if grep -qw "module.sig_enforce=1" /proc/cmdline 2>/dev/null; then
    SIG_ENF="enforced"
fi

# SELinux
if command -v getenforce >/dev/null 2>&1; then
    SEL=$(getenforce 2>/dev/null)
else
    SEL="unknown"
fi

# Firewall
if systemctl is-active firewalld >/dev/null 2>&1; then
    FW="active"
    DZ=$(firewall-cmd --get-default-zone 2>/dev/null || echo "?")
    FW_ZONES="default=${DZ}"
else
    FW="inactive"
    FW_ZONES=""
fi

# Pre-AF_PACKET physical-link boundary. A world-readable root-published health
# state makes an XDP-only fallback visible without granting BPF/TC inspection;
# ACTIVE still receives an exact privileged attachment verification when
# possible.
# BEGIN LAN_XDP_HEALTH_READER
read_lan_xdp_degraded_detail() {
    local file="${1:-/run/noid-privacy/lan-xdp-health}"
    local expected_file_meta="${2:-root:root:644:1}"
    local expected_dir_meta="${3:-root:root:755}"
    local directory metadata detail
    local -a lines=()
    directory=${file%/*}
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] \
        || return 1
    metadata=$(stat -c '%U:%G:%a' "$directory" 2>/dev/null) || return 1
    [ "$metadata" = "$expected_dir_meta" ] || return 1
    metadata=$(stat -c '%U:%G:%a:%h' "$file" 2>/dev/null) || return 1
    [ "$metadata" = "$expected_file_meta" ] || return 1
    mapfile -t lines < "$file" || return 1
    [ "${#lines[@]}" -eq 2 ] && [ "${lines[0]}" = STATE=DEGRADED ] \
        || return 1
    detail=${lines[1]#DETAIL=}
    [ "${lines[1]}" = "DETAIL=$detail" ] || return 1
    case "$detail" in
        controller-missing|sync-or-postcheck-failed|unsupported-link-type|\
        no-ethernet-link|physical-ipv6-unsupported) ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$detail"
}
# END LAN_XDP_HEALTH_READER

XDP_STATE="inactive"
if [ -x /usr/local/sbin/noid-lan-xdp ]; then
    XDP_DETAIL=""
    if XDP_DETAIL=$(read_lan_xdp_degraded_detail); then
        XDP_STATE="DEGRADED (reason=$XDP_DETAIL; WAN repair available through nft/firewall fallback)"
    elif [ "$(id -u)" -eq 0 ]; then
        if /usr/local/sbin/noid-lan-xdp status >/dev/null 2>&1; then
            XDP_STATE="active"
        else
            XDP_STATE="FAILED"
        fi
    elif sudo -n true 2>/dev/null; then
        if sudo -n /usr/local/sbin/noid-lan-xdp status >/dev/null 2>&1; then
            XDP_STATE="active"
        else
            XDP_STATE="FAILED"
        fi
    elif [ -e /run/noid-privacy/lan-xdp.state ]; then
        XDP_STATE="loaded (root verification required)"
    fi
fi

# BEGIN WAN_IPV6_STATUS_READER
read_live_wan_ipv6_status() {
    local cmdline="${1:-/proc/cmdline}"
    local sys_class_net="${2:-/sys/class/net}"
    local proc_ipv6_root="${3:-/proc/sys/net/ipv6/conf}"
    local path iface value
    local -a physical=() degraded=()

    grep -Eq '(^|[[:space:]])rd\.live\.image(=[^[:space:]]*)?([[:space:]]|$)' \
        "$cmdline" 2>/dev/null || return 1

    for path in "$sys_class_net"/*; do
        [ -e "$path" ] || continue
        iface=${path##*/}
        [[ "$iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || continue
        [ -d "$path/device" ] || continue
        physical+=("$iface")
        value=$(cat "$proc_ipv6_root/$iface/disable_ipv6" 2>/dev/null || true)
        [ "$value" = 1 ] || degraded+=("$iface")
    done

    if [ "${#degraded[@]}" -gt 0 ]; then
        printf 'ERROR (%s; Live physical IPv6 not disabled)\n' \
            "$(IFS=,; echo "${degraded[*]}")"
    elif [ "${#physical[@]}" -eq 0 ]; then
        printf '%s\n' "LIVE-DEFERRED (no physical NIC; default-disable remains)"
    else
        printf 'LIVE-OFF (%s; runtime verified, non-persistent Live media)\n' \
            "$(IFS=,; echo "${physical[*]}")"
    fi
}

read_wan_ipv6_status() {
    local file="${1:-/run/noid-privacy/wan-ipv6-status}"
    local expected_file_meta="${2:-root:root:644:1}"
    local expected_dir_meta="${3:-root:root:755}"
    local dir meta mode iface
    local -a lines=()
    dir=${file%/*}
    if [ ! -d "$dir" ] || [ -L "$dir" ] || [ ! -f "$file" ] || \
       [ -L "$file" ] || [ ! -r "$file" ]; then
        printf '%s\n' "unknown (missing or unsafe status file)"
        return 0
    fi
    meta=$(stat -c '%U:%G:%a' "$dir" 2>/dev/null || true)
    [ "$meta" = "$expected_dir_meta" ] || {
        printf '%s\n' "unknown (invalid status-directory metadata)"
        return 0
    }
    meta=$(stat -c '%U:%G:%a:%h' "$file" 2>/dev/null || true)
    [ "$meta" = "$expected_file_meta" ] || {
        printf '%s\n' "unknown (invalid status-file metadata)"
        return 0
    }
    mapfile -t lines < "$file"
    if [ "${#lines[@]}" -ne 3 ] || \
       [ "${lines[0]}" != NOID_WAN_IPV6_STATUS_V1 ] || \
       [[ "${lines[1]}" != MODE=* ]] || [[ "${lines[2]}" != IFACE=* ]]; then
        printf '%s\n' "unknown (invalid status-file schema)"
        return 0
    fi
    mode=${lines[1]#MODE=}
    iface=${lines[2]#IFACE=}
    case "$mode:$iface" in
        ENFORCED:*)
            [[ "$iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || mode=INVALID
            ;;
        DEFERRED:-) ;;
        ERROR:-) ;;
        ERROR:*)
            [[ "$iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || mode=INVALID
            ;;
        *) mode=INVALID ;;
    esac
    case "$mode" in
        ENFORCED) printf 'ENFORCED (%s)\n' "$iface" ;;
        DEFERRED) printf '%s\n' "DEFERRED (no physical NIC; default-disable remains)" ;;
        ERROR) printf 'ERROR (%s; physical IPv6 enforcement degraded)\n' "$iface" ;;
        *) printf '%s\n' "unknown (invalid status-file schema)" ;;
    esac
}
# END WAN_IPV6_STATUS_READER

if WAN_IPV6_STATUS=$(read_live_wan_ipv6_status); then
    :
else
    WAN_IPV6_STATUS=$(read_wan_ipv6_status)
fi

# VPN interface detection (wireguard, tun, tap, vpn)
#
# Existence is not activity. A WireGuard interface survives `wg-quick down`
# only as a removed device, but a provider client that exits badly, a tunnel
# torn down by hand, or a leftover tun device from a crashed OpenVPN all leave
# an administratively DOWN interface behind. Reporting that as "active" claims
# protection the user does not have, which is the one direction this row must
# never fail in. `ip -br link` puts the state in the second field: a live
# tunnel reads UNKNOWN, because a point-to-point device has no carrier to
# report, while a dead one reads DOWN. Measured on the installed image against
# both states.
VPN_IF=""
WG_LINKS=""
if command -v ip >/dev/null 2>&1; then
    WG_LINKS=$(ip -br link show type wireguard 2>/dev/null \
        | awk '$2 != "DOWN" {print $1}')
    VPN_IF=$(printf '%s\n' "$WG_LINKS" | awk 'NF{print; exit}')
    [ -z "$VPN_IF" ] && VPN_IF=$(ip -br link show 2>/dev/null \
        | awk '/^(tun|tap|proton|wg)/ && $2 != "DOWN" {print $1; exit}')
fi
if [ -n "$VPN_IF" ]; then
    VPN="active (${VPN_IF})"
else
    VPN="not connected"
fi
# WAN-egress-strict pins a kernel WireGuard tunnel by reading `wg show`.
# Module 26 ships wireguard-tools, so this row normally stays silent. On a host
# where it was removed -- or an image predating that include -- a provider
# daemon that drives the kernel through netlink (Mullvad and similar) brings up
# a tunnel this host cannot enumerate: the endpoint is never pinned, and an
# armed boundary drops its handshake. The condition is invisible everywhere
# else -- the mode file still reads STRICT_EMPTY, which looks healthy -- so
# name it where the user looks.
if [ -n "$WG_LINKS" ] && ! command -v wg >/dev/null 2>&1; then
    VPN="$VPN; kernel tunnel unreadable (install wireguard-tools to pin it)"
fi

# WAN-egress-strict runtime mode. Reported because an armed boundary is the
# usual reason a tunnel NoID Privacy cannot pin fails to connect at all: a
# client started outside NetworkManager sees only "Operation not permitted"
# from its own socket, and no layer it can see explains why. STRICT_EMPTY in
# particular reads as healthy everywhere else -- it is the correct fail-closed
# state, and also the state in which an unpinned tunnel is going nowhere.
WAN_STRICT="unknown"
if [ -r /run/noid-privacy/wan-strict-status ]; then
    case "$(cat /run/noid-privacy/wan-strict-status 2>/dev/null || true)" in
        MODE=DISABLED)        WAN_STRICT="off (user-disabled)" ;;
        MODE=GRACE_BOOTSTRAP) WAN_STRICT="bootstrap grace (direct IPv4 WAN)" ;;
        MODE=GRACE_PAUSED)    WAN_STRICT="paused (explicit, bounded)" ;;
        MODE=STRICT)          WAN_STRICT="armed (VPN endpoints pinned)" ;;
        MODE=STRICT_EMPTY)    WAN_STRICT="armed, nothing pinned (unpinned tunnels cannot connect)" ;;
        MODE=ERROR)           WAN_STRICT="error (do not infer protection)" ;;
    esac
fi

# DNS policy and routing scope. Consume the same closed, privacy-minimized
# machine schema used by Setup and NoID Privacy Network: it contains only mode
# enums and never profile names, interface names, resolver addresses or query
# targets. This is a local status read and generates no DNS query.
# BEGIN DNS_TRANSPORT_STATUS_READER
DNS_MODE_CLI=/usr/local/sbin/noid-dns-mode
DNS_SELECTION=unknown
DNS_CONFIGURED=unknown
DNS_RUNTIME_GLOBAL=unknown
DNS_PHYSICAL_CONFIGURED=unknown
DNS_PHYSICAL_RUNTIME=unknown
DNS_SCOPE=unknown
DNS_LINK_MODE=unknown
DNS_STATE_VALID=no
DNS_POLICY="unknown (noid-dns-mode unavailable or invalid schema)"
DNS_ACTIVE_PATH="unknown (no routing-scope claim)"
DNS_BRIEF=check
DNS_POLICY_WARN=1

read_dns_transport_state() {
    local cli="${1:-$DNS_MODE_CLI}" output line key value
    local -a lines=()
    local -A fields=()
    DNS_SELECTION=unknown
    DNS_CONFIGURED=unknown
    DNS_RUNTIME_GLOBAL=unknown
    DNS_PHYSICAL_CONFIGURED=unknown
    DNS_PHYSICAL_RUNTIME=unknown
    DNS_SCOPE=unknown
    DNS_LINK_MODE=unknown
    DNS_STATE_VALID=no
    [ -x "$cli" ] || return 0
    if ! output=$(
        /usr/bin/timeout --signal=TERM --kill-after=1s 8s \
            "$cli" --status-machine 2>/dev/null
    ); then
        return 0
    fi
    mapfile -t lines <<<"$output"
    [ "${#lines[@]}" -eq 8 ] \
        && [ "${lines[0]}" = NOID-DNS-MODE-V2 ] || return 0
    for line in "${lines[@]:1}"; do
        [[ "$line" == *=* ]] || return 0
        key=${line%%=*}
        value=${line#*=}
        [ -n "$key" ] && [ -n "$value" ] \
            && [ -z "${fields[$key]+x}" ] || return 0
        fields[$key]=$value
    done
    [ "${#fields[@]}" -eq 7 ] \
        && [ -n "${fields[selection]+x}" ] \
        && [ -n "${fields[configured]+x}" ] \
        && [ -n "${fields[runtime_global]+x}" ] \
        && [ -n "${fields[physical_configured]+x}" ] \
        && [ -n "${fields[physical_runtime]+x}" ] \
        && [ -n "${fields[scope]+x}" ] \
        && [ -n "${fields[link_mode]+x}" ] || return 0
    case "${fields[selection]}" in
        default|off|opportunistic|strict|invalid) ;;
        *) return 0 ;;
    esac
    case "${fields[configured]}:${fields[runtime_global]}" in
        no:no|no:opportunistic|no:yes|no:unknown|\
        opportunistic:no|opportunistic:opportunistic|opportunistic:yes|opportunistic:unknown|\
        yes:no|yes:opportunistic|yes:yes|yes:unknown|\
        unknown:no|unknown:opportunistic|unknown:yes|unknown:unknown) ;;
        *) return 0 ;;
    esac
    case "${fields[physical_configured]}" in
        none|default|no|opportunistic|yes|mixed|unknown) ;;
        *) return 0 ;;
    esac
    case "${fields[physical_runtime]}" in
        none|no|opportunistic|yes|mixed|unknown) ;;
        *) return 0 ;;
    esac
    case "${fields[scope]}" in
        global|physical|link|mixed|unknown) ;;
        *) return 0 ;;
    esac
    case "${fields[link_mode]}" in
        none|no|opportunistic|yes|mixed|unknown) ;;
        *) return 0 ;;
    esac
    DNS_SELECTION=${fields[selection]}
    DNS_CONFIGURED=${fields[configured]}
    DNS_RUNTIME_GLOBAL=${fields[runtime_global]}
    DNS_PHYSICAL_CONFIGURED=${fields[physical_configured]}
    DNS_PHYSICAL_RUNTIME=${fields[physical_runtime]}
    DNS_SCOPE=${fields[scope]}
    DNS_LINK_MODE=${fields[link_mode]}
    DNS_STATE_VALID=yes
}

format_dns_transport_state() {
    local expected=unknown drift=0
    DNS_POLICY_WARN=1
    if [ "$DNS_STATE_VALID" != yes ]; then
        DNS_POLICY="unknown (noid-dns-mode unavailable or invalid schema)"
        DNS_ACTIVE_PATH="unknown (no routing-scope claim)"
        DNS_BRIEF=check
        return 0
    fi
    case "$DNS_SELECTION" in
        default)
            expected=yes
            DNS_POLICY="strict (image default)"
            DNS_BRIEF=strict
            ;;
        strict)
            expected=yes
            DNS_POLICY="strict (explicit, authenticated and fail-closed)"
            DNS_BRIEF=strict
            ;;
        opportunistic)
            expected=opportunistic
            DNS_POLICY="opportunistic (persistent; DNS/53 fallback allowed)"
            DNS_BRIEF=opportunistic
            ;;
        off)
            expected=no
            DNS_POLICY="off (persistent plaintext DNS)"
            DNS_BRIEF=off
            ;;
        invalid)
            DNS_POLICY="ERROR (unsafe or malformed selector file)"
            DNS_BRIEF=invalid
            ;;
        *)
            DNS_POLICY="unknown (noid-dns-mode unavailable or invalid schema)"
            DNS_BRIEF=check
            ;;
    esac
    if [ "$expected" != unknown ]; then
        [ "$DNS_CONFIGURED" = "$expected" ] || drift=1
        [ "$DNS_RUNTIME_GLOBAL" = "$expected" ] || drift=1
        case "$expected:$DNS_PHYSICAL_CONFIGURED" in
            yes:none|yes:default|yes:yes|\
            opportunistic:none|opportunistic:opportunistic|\
            no:none|no:no) ;;
            *) drift=1 ;;
        esac
        case "$expected:$DNS_PHYSICAL_RUNTIME" in
            yes:none|yes:yes|\
            opportunistic:none|opportunistic:opportunistic|\
            no:none|no:no) ;;
            *) drift=1 ;;
        esac
        if [ "$drift" -ne 0 ]; then
            DNS_POLICY="${DNS_POLICY}; DRIFT (global=${DNS_CONFIGURED}/${DNS_RUNTIME_GLOBAL}, physical=${DNS_PHYSICAL_CONFIGURED}/${DNS_PHYSICAL_RUNTIME})"
            DNS_BRIEF="${DNS_BRIEF}/check"
        elif [ "$DNS_SELECTION" = default ] || [ "$DNS_SELECTION" = strict ]; then
            DNS_POLICY_WARN=0
        fi
    fi
    case "$DNS_SCOPE" in
        global)
            DNS_ACTIVE_PATH="global resolver (DoT=${DNS_RUNTIME_GLOBAL})"
            ;;
        physical)
            DNS_ACTIVE_PATH="managed physical ~. link (DoT=${DNS_LINK_MODE})"
            ;;
        link)
            DNS_ACTIVE_PATH="VPN/private ~. link (DoT=${DNS_LINK_MODE}); selected global policy dormant"
            ;;
        mixed)
            DNS_ACTIVE_PATH="mixed physical and VPN/private ~. links (DoT=${DNS_LINK_MODE}); inspect before claiming one path"
            ;;
        *)
            DNS_ACTIVE_PATH="unknown (no routing-scope claim)"
            ;;
    esac
}
# END DNS_TRANSPORT_STATUS_READER

read_dns_transport_state
format_dns_transport_state

# Faillock state for current user (read-only query). `awk` returns success and
# prints zero when there are no records; unlike `grep -c`, that healthy state
# cannot abort this strict-mode script through pipefail. A failed faillock
# query remains distinguishable from a clean tally.
count_faillock_records() {
    local output
    if ! output=$("$@" 2>/dev/null); then
        return 1
    fi
    printf '%s\n' "$output" | awk '/^[0-9]{4}-/{n++} END{print n+0}'
}

STATUS_USER="${SUDO_USER:-${USER:-}}"
[ -n "$STATUS_USER" ] || STATUS_USER=$(id -un)
FAIL_STATE="unknown (root required)"
if command -v faillock >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
        if fail_lines=$(count_faillock_records faillock --user "$STATUS_USER"); then
            if [ "$fail_lines" -eq 0 ]; then
                FAIL_STATE="clean (0 failed attempts)"
            else
                FAIL_STATE="${fail_lines} failed attempts on record"
            fi
        else
            FAIL_STATE="unknown (faillock query failed)"
        fi
    elif sudo -n true 2>/dev/null; then
        if fail_lines=$(count_faillock_records sudo -n faillock --user "$STATUS_USER"); then
            if [ "$fail_lines" -eq 0 ]; then
                FAIL_STATE="clean (0 failed attempts)"
            else
                FAIL_STATE="${fail_lines} failed attempts on record"
            fi
        else
            FAIL_STATE="unknown (faillock query failed)"
        fi
    fi
fi

# Faillock config (mode 644 world-readable)
FAIL_CONFIG="unknown"
if [ -r /etc/security/faillock.conf ]; then
    fail_deny=$(awk -F'=' '/^deny[[:space:]]*=/ {gsub(/[ \t]/,"",$2); print $2; exit}' /etc/security/faillock.conf 2>/dev/null)
    fail_unlock=$(awk -F'=' '/^unlock_time[[:space:]]*=/ {gsub(/[ \t]/,"",$2); print $2; exit}' /etc/security/faillock.conf 2>/dev/null)
    fail_dir=$(awk -F'=' '/^dir[[:space:]]*=/ {gsub(/[ \t]/,"",$2); print $2; exit}' /etc/security/faillock.conf 2>/dev/null)
    case "$fail_dir" in
        /var/lib/faillock) fail_dir_state="persistent" ;;
        "")                fail_dir_state="tmpfs default (reboot-clears)" ;;
        *)                 fail_dir_state="custom ($fail_dir)" ;;
    esac
    FAIL_CONFIG="deny=${fail_deny:-?} unlock=${fail_unlock:-?}s ${fail_dir_state}"
fi

# AIDE trust/timer state. /var/lib/aide is intentionally 0700, so a direct
# non-root pathname probe always looks absent after activation. Consume only the
# exact argument-free helper schema.
read_aide_database_state() {
    local output command_path=/usr/libexec/noid-aide-status
    local -a lines=()
    if [ "$(id -u)" -eq 0 ]; then
        output=$("$command_path" 2>/dev/null) || {
            printf '%s\n' unavailable
            return 0
        }
    else
        output=$(sudo -n "$command_path" 2>/dev/null) || {
            printf '%s\n' unavailable
            return 0
        }
    fi
    mapfile -t lines <<<"$output"
    if [ "${#lines[@]}" -ne 2 ] \
       || [ "${lines[0]}" != NOID_AIDE_STATE_V1 ] \
       || [[ "${lines[1]}" != STATE=* ]]; then
        printf '%s\n' unavailable
        return 0
    fi
    case "${lines[1]#STATE=}" in
        active|absent|unsafe) printf '%s\n' "${lines[1]#STATE=}" ;;
        *) printf '%s\n' unavailable ;;
    esac
}

AIDE_DATABASE_STATE=$(read_aide_database_state)
if [ "$AIDE_DATABASE_STATE" = absent ]; then
    AIDE_STATE="uninitialized (user baseline review required)"
elif [ "$AIDE_DATABASE_STATE" = unsafe ]; then
    AIDE_STATE="unsafe database metadata (root review required)"
elif [ "$AIDE_DATABASE_STATE" != active ]; then
    AIDE_STATE="unavailable (read-only status boundary)"
elif systemctl is-enabled aide-check.timer >/dev/null 2>&1; then
    AIDE_STATE="enabled"
else
    AIDE_STATE="disabled"
fi

# AIDE popup drop-in (opt-in feature). Presence alone is not activation: only
# the exact root-owned template copy is a recognized enabled state.
AIDE_POPUP_DROPIN=/etc/systemd/system/aide-check.service.d/notify.conf
AIDE_POPUP_TEMPLATE=/usr/share/doc/noid-privacy/aide-notify-dropin.conf
if [ -f "$AIDE_POPUP_DROPIN" ] && [ ! -L "$AIDE_POPUP_DROPIN" ] \
   && [ "$(stat -Lc '%u:%g:%a:%h' "$AIDE_POPUP_DROPIN" \
           2>/dev/null || true)" = 0:0:644:1 ] \
   && cmp -s -- "$AIDE_POPUP_TEMPLATE" "$AIDE_POPUP_DROPIN"; then
    AIDE_POPUP="ENABLED (drop-in active)"
elif [ -e "$AIDE_POPUP_DROPIN" ] || [ -L "$AIDE_POPUP_DROPIN" ]; then
    AIDE_POPUP="unsafe or locally drifted (root review required)"
else
    AIDE_POPUP="disabled (template available after baseline setup)"
fi

# audit-notify
if systemctl is-active audit-notify.service >/dev/null 2>&1; then
    AUD_NOTIFY="active"
else
    AUD_NOTIFY="inactive"
fi

# auditd immutable mode
# Non-root users cannot query auditctl (CAP_AUDIT_CONTROL/CAP_AUDIT_READ required,
# no /proc/sys fallback on Fedora 44). Show clear "n/a (root only)" instead of
# silent-fail "unknown" which previously masked a working auditd daemon.
AUDITD_IMMUT="unknown"
if [ "$(id -u)" -ne 0 ]; then
    AUDITD_IMMUT="n/a (root only)"
elif command -v auditctl >/dev/null 2>&1; then
    if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
        AUDITD_IMMUT="immutable (enabled=2)"
    elif auditctl -s 2>/dev/null | grep -q "enabled 1"; then
        AUDITD_IMMUT="active (enabled=1)"
    fi
fi

# A low-space event remains operator evidence for the rest of the current boot,
# even after free space is restored. The /run marker is root-readable only, but
# its existence and metadata are safe for an unprivileged status command.
# BEGIN AUDIT_STORAGE_STATUS_READER
read_audit_storage_state() {
    local file="${1:-/run/noid-privacy/audit-storage-degraded}"
    local expected_file_meta="${2:-root:root:600:1}"
    local expected_dir_meta="${3:-root:root:755}"
    local dir meta
    dir=${file%/*}
    if [ ! -e "$file" ] && [ ! -L "$file" ]; then
        printf '%s\n' ok
        return 0
    fi
    if [ ! -d "$dir" ] || [ -L "$dir" ] || [ ! -f "$file" ] || [ -L "$file" ]; then
        printf '%s\n' "unknown (unsafe audit-storage marker type)"
        return 0
    fi
    meta=$(stat -c '%U:%G:%a' "$dir" 2>/dev/null || true)
    if [ "$meta" != "$expected_dir_meta" ]; then
        printf '%s\n' "unknown (invalid audit-storage directory metadata)"
        return 0
    fi
    meta=$(stat -c '%U:%G:%a:%h' "$file" 2>/dev/null || true)
    if [ "$meta" != "$expected_file_meta" ]; then
        printf '%s\n' "unknown (invalid audit-storage marker metadata)"
        return 0
    fi
    printf '%s\n' "DEGRADED (boot-scoped low-space marker; review required)"
}
# END AUDIT_STORAGE_STATUS_READER

AUDIT_STORAGE=$(read_audit_storage_state)

# USBGuard
read_usbguard_state() {
    local file="$1"
    local expected_file_meta="${2:-root:root:644}"
    local expected_dir_meta="${3:-root:root:755}"
    local dir meta line key value state="" count="" fallback="" last_run=""
    local seen_state=0 seen_count=0 seen_fallback=0 seen_last=0 invalid=0
    dir=${file%/*}

    if [ ! -d "$dir" ] || [ -L "$dir" ] || [ ! -f "$file" ] || \
       [ -L "$file" ] || [ ! -r "$file" ]; then
        printf '%s\n' "unknown (missing or unsafe status file)"
        return 0
    fi
    meta=$(stat -c '%U:%G:%a' "$dir" 2>/dev/null || true)
    if [ "$meta" != "$expected_dir_meta" ]; then
        printf '%s\n' "unknown (invalid status-directory metadata)"
        return 0
    fi
    meta=$(stat -c '%U:%G:%a' "$file" 2>/dev/null || true)
    if [ "$meta" != "$expected_file_meta" ]; then
        printf '%s\n' "unknown (invalid status-file metadata)"
        return 0
    fi

    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            *=*) key=${line%%=*}; value=${line#*=} ;;
            *) invalid=1; continue ;;
        esac
        case "$key" in
            STATE)
                seen_state=$((seen_state + 1)); state=$value ;;
            DEVICE_COUNT)
                seen_count=$((seen_count + 1)); count=$value ;;
            FALLBACK_ACTIVE)
                seen_fallback=$((seen_fallback + 1)); fallback=$value ;;
            LAST_RUN)
                seen_last=$((seen_last + 1)); last_run=$value ;;
            *) invalid=1 ;;
        esac
    done < "$file"

    [ "$seen_state" -eq 1 ] && [ "$seen_count" -eq 1 ] && \
    [ "$seen_fallback" -eq 1 ] && [ "$seen_last" -eq 1 ] || invalid=1
    case "$state" in real|emergency|initializing) ;; *) invalid=1 ;; esac
    case "$count" in ''|*[!0-9]*) invalid=1 ;; esac
    case "$fallback" in yes|no) ;; *) invalid=1 ;; esac
    if [[ ! $last_run =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:[0-9]{2}|Z)$ ]]; then
        invalid=1
    fi
    if [ "$invalid" -ne 0 ]; then
        printf '%s\n' "unknown (invalid status-file content)"
    else
        printf '%s\n' "$state"
    fi
}

if systemctl is-active usbguard >/dev/null 2>&1; then
    UG="active"
    UG_STATE_FILE="/var/lib/noid-privacy/usbguard-status.txt"
    UG_STATE=$(read_usbguard_state "$UG_STATE_FILE")
    UG="active (first-boot state: ${UG_STATE})"
    UG_WILDCARD_STATUS=/var/lib/noid-privacy/usbguard-gnome-wildcard.status
    if [ -f "$UG_WILDCARD_STATUS" ] && [ ! -L "$UG_WILDCARD_STATUS" ] && \
       grep -qxF 'STATE=DEGRADED' "$UG_WILDCARD_STATUS" 2>/dev/null; then
        UG="$UG; GNOME wildcard cleanup DEGRADED"
    fi
else
    UG="inactive"
fi

# Intel ME / HSI. noid-status is diagnostic and must not wake the otherwise
# boot-dormant fwupd D-Bus service. Read HSI only while an explicit firmware
# operation already has fwupd active; otherwise disclose the deferred check.
# fwupdmgr legitimately returns non-zero when the platform exposes no supported
# host-security device. Keep that absence as an explicit unknown value instead
# of letting strict mode abort the entire status report.
read_hsi() {
    local raw parsed
    if ! systemctl --quiet is-active fwupd.service; then
        printf '%s\n' 'unknown (fwupd dormant; explicit check required)'
        return 0
    fi
    if ! raw=$(LC_ALL=C fwupdmgr security --no-authenticate 2>/dev/null); then
        printf '%s\n' unknown
        return 0
    fi
    # fwupdmgr emits ANSI color codes even with NO_COLOR=1 (upstream issue
    # #4959). Strip them before extracting the HSI value. sub() preserves the
    # "HSI:N!" colon that an awk -F: parser would truncate.
    if ! parsed=$(printf '%s\n' "$raw" \
        | sed -e 's/\x1b\[[0-9;]*m//g' \
        | awk '/^Host Security ID:/ && !seen {
                   sub(/^Host Security ID:[[:space:]]*/, "")
                   value=$0
                   seen=1
               }
               END {if (seen) print value}'); then
        printf '%s\n' unknown
        return 0
    fi
    printf '%s\n' "${parsed:-unknown}"
}

HSI=""
if command -v fwupdmgr >/dev/null 2>&1; then
    HSI=$(read_hsi)
fi

# Module 15's root-owned schema is deliberately consumed here rather than
# retained as a self-referential Welcome constant. Parse only known fields;
# never source the data file as shell code. Kernel/policy binding prevents an
# old successful probe from being presented as current after a refresh fails.
# BEGIN PLATFORM_STATUS_READER
read_platform_status() {
    local file="${1:-/var/lib/noid-privacy/mei-status.txt}"
    local expected_file_meta="${2:-root:root:644}"
    local expected_dir_meta="${3:-root:root:755}"
    local current_kernel="${4:-$(uname -r)}" current_policy="${5:-}"
    local dir meta line key value invalid=0 cpu_vendor="unknown" mei_state="unknown"
    local lifecycle="" mei_regression="" mei_core_policy="" mei_submodules=""
    local ccp_policy=""
    local kt_state="unknown" fwupd_state="unknown" psp_state="unknown"
    local ccp_state="unknown" psp_fwupd="" psb_state="unknown" hardware_doc=""
    local note="" checked_kernel="" checked_at="" checked_policy=""
    local -A seen=()
    [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || {
        printf '%s\n' unknown
        return 0
    }
    dir=${file%/*}
    [ -d "$dir" ] && [ ! -L "$dir" ] || {
        printf '%s\n' "unknown (invalid status-directory type)"
        return 0
    }
    meta=$(stat -c '%U:%G:%a' "$file" 2>/dev/null || true)
    [ "$meta" = "$expected_file_meta" ] || {
        printf '%s\n' "unknown (invalid status-file metadata)"
        return 0
    }
    meta=$(stat -c '%U:%G:%a' "$dir" 2>/dev/null || true)
    [ "$meta" = "$expected_dir_meta" ] || {
        printf '%s\n' "unknown (invalid status-directory metadata)"
        return 0
    }
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*) continue ;;
            *=*) key=${line%%=*}; value=${line#*=} ;;
            *) invalid=1; continue ;;
        esac
        if ! [[ "$key" =~ ^[A-Z0-9_]+$ ]]; then
            invalid=1
            continue
        fi
        if [ -n "${seen[$key]+x}" ]; then
            invalid=1
            continue
        fi
        seen[$key]=1
        case "$value" in
            *[!A-Za-z0-9._:/+,\;\(\)\ -]*) invalid=1; continue ;;
        esac
        case "$key" in
            CPU_VENDOR) cpu_vendor=$value ;;
            STATUS_LIFECYCLE) lifecycle=$value ;;
            MEI_STATE) mei_state=$value ;;
            MEI_CORE_POLICY) mei_core_policy=$value ;;
            MEI_KERNEL_REGRESSION) mei_regression=$value ;;
            MEI_SUBMODULES_BLOCKED) mei_submodules=$value ;;
            MEI_KT_SOL_HOST_BINDING) kt_state=$value ;;
            MEI_FWUPD_VISIBILITY) fwupd_state=$value ;;
            PSP_STATE) psp_state=$value ;;
            CCP_STATE) ccp_state=$value ;;
            CCP_POLICY) ccp_policy=$value ;;
            PSP_FWUPD_VISIBILITY) psp_fwupd=$value ;;
            PSB_STATE) psb_state=$value ;;
            HARDWARE_LAYER_DOC) hardware_doc=$value ;;
            NOTE) note=$value ;;
            CHECKED_AT_KERNEL) checked_kernel=$value ;;
            CHECKED_AT) checked_at=$value ;;
            CHECKED_POLICY_SHA256) checked_policy=$value ;;
            *) invalid=1 ;;
        esac
    done < "$file"

    # The raw Live image deliberately carries one producer-marked staged
    # record until M15 probes the installed target. Accept only those exact
    # closed producer schemas; an arbitrary partial runtime record remains a
    # hard parse failure rather than being relabelled "pending".
    if [ "$lifecycle" = build-time-placeholder ]; then
        case "$cpu_vendor" in
            intel)
                [ "${#seen[@]}" -eq 6 ] \
                    && [ "$mei_state" = build-time-unknown ] \
                    && [ "$mei_submodules" = none ] \
                    && [ "$kt_state" = configured-not-runtime-verified ] \
                    && [ "$fwupd_state" = runtime-check-required ] \
                    || invalid=1
                ;;
            amd)
                [ "${#seen[@]}" -eq 8 ] \
                    && [ "$mei_state" = n/a-on-amd ] \
                    && [ "$psp_state" = runtime-check-required ] \
                    && [ "$ccp_policy" = not-blacklisted ] \
                    && [ "$psp_fwupd" = runtime-check-required ] \
                    && [ "$psb_state" = see-fwupdmgr-security ] \
                    && [ "$hardware_doc" = /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md ] \
                    || invalid=1
                ;;
            unknown)
                [ "${#seen[@]}" -eq 5 ] \
                    && [ "$mei_state" = n/a ] \
                    && [ "$psp_state" = n/a ] \
                    && [ "$note" = 'vendor-specific firmware status unavailable; generic hardening still applies' ] \
                    || invalid=1
                ;;
            *) invalid=1 ;;
        esac
        if [ "$invalid" -eq 0 ]; then
            printf '%s\n' 'pending (Live/build-time placeholder; target-boot refresh not run)'
        else
            printf '%s\n' "unknown (invalid platform-status schema)"
        fi
        return 0
    fi

    # Runtime records never carry the staged lifecycle marker and must match
    # one complete vendor-specific producer schema, including every field.
    [ -z "$lifecycle" ] || invalid=1
    case "$cpu_vendor:$mei_core_policy:$mei_state" in
        intel:loadable:mei-me-bound|intel:loadable:available-not-loaded|intel:loadable:absent)
            [ "${#seen[@]}" -eq 10 ] \
                && [[ "$mei_regression" =~ ^(yes|no)$ ]] \
                && [[ "$mei_submodules" =~ ^(none|hdcp(,pxp)?(,wdt)?|pxp(,wdt)?|wdt)$ ]] \
                && [[ "$kt_state" =~ ^(enforced|no-device-present|failed)$ ]] \
                && [[ "$fwupd_state" =~ ^(available-platform-results-vary|conditional|unavailable)$ ]] \
                || invalid=1
            ;;
        intel:blacklisted:blocked-by-policy)
            [ "${#seen[@]}" -eq 10 ] \
                && [ "$mei_regression" = no ] \
                && [[ "$mei_submodules" =~ ^(none|hdcp(,pxp)?(,wdt)?|pxp(,wdt)?|wdt)$ ]] \
                && [[ "$kt_state" =~ ^(enforced|no-device-present|failed)$ ]] \
                && [ "$fwupd_state" = unavailable-by-policy ] \
                || invalid=1
            ;;
        amd::n/a-on-amd)
            [ "${#seen[@]}" -eq 11 ] \
                && [ "$psp_state" = firmware-managed ] \
                && [[ "$ccp_state" =~ ^(loaded|available-not-loaded|unavailable)$ ]] \
                && [ "$ccp_policy" = not-blacklisted ] \
                && [[ "$psp_fwupd" =~ ^(available-platform-results-vary|unavailable)$ ]] \
                && [ "$psb_state" = see-fwupdmgr-security ] \
                && [ "$hardware_doc" = /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md ] \
                || invalid=1
            ;;
        unknown::n/a)
            [ "${#seen[@]}" -eq 7 ] \
                && [ "$psp_state" = n/a ] \
                && [ "$note" = 'vendor-specific firmware status unavailable; generic hardening still applies' ] \
                || invalid=1
            ;;
        *) invalid=1 ;;
    esac
    [[ "$checked_kernel" =~ ^[A-Za-z0-9._+-]+$ ]] || invalid=1
    [[ "$checked_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
        invalid=1
    [[ "$checked_policy" =~ ^[a-f0-9]{64}$ ]] || invalid=1
    if [ "$invalid" -ne 0 ]; then
        printf '%s\n' "unknown (invalid platform-status schema)"
        return 0
    fi
    if [ -z "$current_policy" ]; then
        if [ ! -x /usr/libexec/noid-platform-policy-sha256 ] || \
           ! current_policy=$(/usr/libexec/noid-platform-policy-sha256 2>/dev/null); then
            printf '%s\n' "unknown (current platform policy unavailable)"
            return 0
        fi
    fi
    if [ "$checked_kernel" != "$current_kernel" ]; then
        printf 'stale (checked kernel %s; running %s)\n' \
            "$checked_kernel" "$current_kernel"
        return 0
    fi
    if [ "$checked_policy" != "$current_policy" ]; then
        printf '%s\n' "stale (MEI platform policy changed since check)"
        return 0
    fi
    case "$cpu_vendor" in
        intel) printf 'Intel MEI=%s; core-policy=%s; submodules=%s; KT/SOL=%s; fwupd=%s\n' \
            "$mei_state" "$mei_core_policy" "$mei_submodules" "$kt_state" \
            "$fwupd_state" ;;
        amd) printf 'AMD PSP=%s; CCP=%s; PSB=%s\n' "$psp_state" "$ccp_state" "$psb_state" ;;
        *) printf 'platform=%s; MEI=%s\n' "$cpu_vendor" "$mei_state" ;;
    esac
}
# END PLATFORM_STATUS_READER

PLATFORM_STATUS=$(read_platform_status)

# LUKS
# Avoid the "grep -c | echo 0 multi-line" trap: same pattern as SNAP_COUNT below.
LUKS_COUNT=$(lsblk -o TYPE 2>/dev/null | grep -c '^crypt$' 2>/dev/null || true)
LUKS_COUNT=${LUKS_COUNT:-0}
LUKS_COUNT=$(echo "$LUKS_COUNT" | tr -d '[:space:]')
LUKS_COUNT=${LUKS_COUNT:-0}
if [ "$LUKS_COUNT" -gt 0 ]; then
    LUKS_STATE="${LUKS_COUNT} LUKS volume(s)"
else
    LUKS_STATE="no LUKS detected"
fi

# Snapper — never grant the desktop user arbitrary Snapper D-Bus operations
# merely to show a count. M20's exact sudo rule permits only this fixed-schema,
# argument-free, root-owned read-only helper.
if [ -x /usr/libexec/noid-snapper-status ] \
        && SNAP_RAW=$(sudo -n /usr/libexec/noid-snapper-status 2>/dev/null) \
        && [[ "$SNAP_RAW" =~ ^count=([0-9]+)[[:space:]]boot=(ready|reboot-required|degraded)[[:space:]]default=(none|[0-9]+)[[:space:]]active=(none|[0-9]+)[[:space:]]retention=(unknown|ok|protected|clock-guard|degraded)$ ]]; then
    SNAP_COUNT=${BASH_REMATCH[1]}
    SNAP_BOOT=${BASH_REMATCH[2]}
    SNAP_RETENTION=${BASH_REMATCH[5]}
    SNAP_STATE="${SNAP_COUNT} snapshots; boot=${SNAP_BOOT}; retention=${SNAP_RETENTION}"
else
    SNAP_STATE="unavailable (read-only status boundary)"
fi

# LUKS-Backup state:
# noid-luks-backup.sh writes /var/lib/noid-privacy/luks-backup.log on
# successful backup (TAB-separated: timestamp \t sha256; no device/media label).
# CRITICAL data-loss-prevention — LUKS header corruption without backup =
# volume forever unreadable. One-time-action; user-init only.
# Show present + last-date if log exists, escalate days-since-install if not.
LUKS_BACKUP_LOG="/var/lib/noid-privacy/luks-backup.log"
if [ "$LUKS_COUNT" -gt 0 ]; then
    # BEGIN LUKS_BACKUP_STATUS_READER
    read_luks_backup_log() {
        local file=$1 expected_file_meta="${2:-root:wheel:640:1}"
        local expected_dir_meta="${3:-root:root:755}"
        local line timestamp sha last_timestamp="" last_sha="" directory
        local size meta entry_count=0
        [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || return 1
        directory=${file%/*}
        [ -d "$directory" ] && [ ! -L "$directory" ] \
            && [ "$(stat -Lc '%U:%G:%a' "$directory" \
                    2>/dev/null || true)" = "$expected_dir_meta" ] || return 1
        meta=$(stat -Lc '%U:%G:%a:%h' "$file" 2>/dev/null || true)
        [ "$meta" = "$expected_file_meta" ] || return 1
        size=$(stat -Lc '%s' "$file" 2>/dev/null || true)
        [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -gt 0 ] \
            && [ "$size" -le 1048576 ] || return 1
        while IFS= read -r line || [ -n "$line" ]; do
            [[ "$line" == *$'\t'* ]] || return 1
            timestamp=${line%%$'\t'*}
            sha=${line#*$'\t'}
            [[ "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:[0-9]{2}|Z)$ ]] \
                && [[ "$sha" =~ ^[a-f0-9]{64}$ ]] || return 1
            last_timestamp=$timestamp
            last_sha=$sha
            entry_count=$((entry_count + 1))
        done < "$file"
        [ "$entry_count" -gt 0 ] || return 1
        printf 'present (last %s, sha256:%s…)\n' \
            "$last_timestamp" "${last_sha:0:12}"
    }
    # END LUKS_BACKUP_STATUS_READER
    if LUKS_BACKUP_STATE=$(read_luks_backup_log "$LUKS_BACKUP_LOG"); then
        :
    elif [ -e "$LUKS_BACKUP_LOG" ] || [ -L "$LUKS_BACKUP_LOG" ]; then
        LUKS_BACKUP_STATE="unknown (unsafe or malformed backup evidence)"
    else
        # No backup yet — compute days-since-install for escalation severity.
        # Install anchor: /etc/noid-privacy-release (cleanest single-file
        # marker written by M99 and refreshed by M41). Fallback to
        # /var/lib/noid-privacy/anaconda-cleanup.done on older builds.
        INSTALL_TS=$(stat -c %Y /etc/noid-privacy-release 2>/dev/null \
                     || stat -c %Y /var/lib/noid-privacy/anaconda-cleanup.done 2>/dev/null \
                     || echo 0)
        if [ "$INSTALL_TS" -gt 0 ]; then
            DAYS_SINCE=$(( ($(date +%s) - INSTALL_TS) / 86400 ))
            LUKS_BACKUP_STATE="NOT YET DONE — run noid-luks-backup.sh (${DAYS_SINCE}d since install)"
        else
            LUKS_BACKUP_STATE="NOT YET DONE — run noid-luks-backup.sh"
        fi
    fi
else
    LUKS_BACKUP_STATE="n/a (no LUKS volume)"
fi

# Update reminder timer (user-session). A diagnostic launched from an agent,
# cron-like shell or TTY does not necessarily inherit the GNOME session's
# XDG_RUNTIME_DIR/DBUS_SESSION_BUS_ADDRESS. The canonical systemd user runtime
# path remains available, but consume it only after binding it to the current
# non-root UID/GID and an actual same-owner D-Bus socket.
# BEGIN UPDATE_REMINDER_STATUS_READER
classify_update_reminder_state() {
    local exit_status=$1 output=$2
    case "${exit_status}:${output}" in
        0:enabled) printf '%s\n' enabled ;;
        1:disabled) printf '%s\n' disabled ;;
        *) printf '%s\n' "unknown (user-session timer)" ;;
    esac
}

read_update_reminder_state() {
    local uid gid runtime bus runtime_meta bus_meta output exit_status
    uid=$(id -u)
    gid=$(id -g)
    [ "$uid" -ne 0 ] || {
        printf '%s\n' "unknown (user-session timer)"
        return 0
    }
    runtime="/run/user/${uid}"
    bus="${runtime}/bus"
    [ -d "$runtime" ] && [ ! -L "$runtime" ] \
        && [ -S "$bus" ] && [ ! -L "$bus" ] || {
        printf '%s\n' "unknown (user-session timer)"
        return 0
    }
    runtime_meta=$(stat -Lc '%u:%g:%a:%F' "$runtime" 2>/dev/null || true)
    bus_meta=$(stat -Lc '%u:%g:%F' "$bus" 2>/dev/null || true)
    [ "$runtime_meta" = "${uid}:${gid}:700:directory" ] \
        && [ "$bus_meta" = "${uid}:${gid}:socket" ] || {
        printf '%s\n' "unknown (user-session timer)"
        return 0
    }
    if output=$(
        /usr/bin/timeout --signal=TERM --kill-after=1s 3s \
            /usr/bin/env \
                XDG_RUNTIME_DIR="$runtime" \
                DBUS_SESSION_BUS_ADDRESS="unix:path=${bus}" \
            /usr/bin/systemctl --user is-enabled \
                noid-update-reminder.timer 2>/dev/null
    ); then
        exit_status=0
    else
        exit_status=$?
    fi
    classify_update_reminder_state "$exit_status" "$output"
}
# END UPDATE_REMINDER_STATUS_READER

UR_STATE=$(read_update_reminder_state)

# BEGIN EXTENSION_CHECK_STATUS_READER
# Add-on patch age. Firefox and Thunderbird background extension updates are
# deliberately disabled (M16/M35) and the managed XPIs advance only inside an
# explicitly started noid-update-all.sh, so the age of the newest authenticated
# marketplace check IS this machine's add-on patch latency. M25's update-all
# publishes one bounded line per managed component; this reader only reads that
# file and issues no request of its own, so "never checked" always means
# "update-all has not run", never "a check failed quietly".
# M25's append-only extension-updates.log cannot answer this: it records only
# actual version changes, so a component current for a year looks identical to
# one never checked. GNOME Shell extensions are a separate consent-gated step
# and are deliberately not folded into this line.
EXTENSION_CHECK_STATE_FILE="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy/extension-checks"
# The update reminder fires weekly, so 30 days is four ignored reminders — the
# point at which add-on patch latency stops being routine.
EXTENSION_CHECK_STALE_DAYS=30

# Assigns EXT_CHECK_STATE and EXT_CHECK_WARN directly instead of printing one
# of them: this reader has two results, and a command substitution would run it
# in a subshell where the severity flag could never reach the caller. The
# caller must not have to recover severity by re-matching prose it also renders.
read_extension_check_state() {
    local line newest='' failed=0 total=0 newest_epoch now age age_phrase
    EXT_CHECK_WARN=1
    [ -f "$EXTENSION_CHECK_STATE_FILE" ] && [ ! -L "$EXTENSION_CHECK_STATE_FILE" ] || {
        EXT_CHECK_STATE="never checked (run noid-update-all.sh)"
        return 0
    }
    while IFS= read -r line; do
        [[ $line =~ ^component=[A-Za-z0-9._+@{}-]+\ checked=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)\ result=(current|updated|failed)$ ]] || continue
        total=$((total + 1))
        [ "${BASH_REMATCH[2]}" != failed ] || failed=$((failed + 1))
        if [ -z "$newest" ] || [[ ${BASH_REMATCH[1]} > $newest ]]; then
            newest=${BASH_REMATCH[1]}
        fi
    done < "$EXTENSION_CHECK_STATE_FILE"
    if [ "$total" -eq 0 ] \
            || ! newest_epoch=$(date -u -d "$newest" +%s 2>/dev/null); then
        EXT_CHECK_STATE="unreadable (no valid check record)"
        return 0
    fi
    now=$(date -u +%s)
    age=$(( (now - newest_epoch) / 86400 ))
    # A clock stepped backwards since the check must not render a negative age.
    [ "$age" -ge 0 ] || age=0
    if [ "$age" -eq 0 ]; then
        age_phrase=today
    else
        age_phrase="${age}d ago"
    fi
    if [ "$failed" -gt 0 ]; then
        EXT_CHECK_STATE="checked ${age_phrase}; ${failed} of ${total} component(s) failed"
        return 0
    fi
    [ "$age" -lt "$EXTENSION_CHECK_STALE_DAYS" ] && EXT_CHECK_WARN=0
    EXT_CHECK_STATE="checked ${age_phrase} (${total} component(s))"
}
# END EXTENSION_CHECK_STATUS_READER

EXT_CHECK_STATE=''
EXT_CHECK_WARN=1
read_extension_check_state

# The M25 helper is the single authority for activation need and boot safety.
# Consume only its closed eight-line schema; helper failure or malformed output
# stays visibly unknown instead of falling back to a second kernel heuristic.
# BEGIN REBOOT_STATUS_READER
read_reboot_state() {
    local helper=${1:-/usr/libexec/noid-reboot-readiness}
    local output activation safety blockers running latest nv_run nv_disk reason
    local -a lines=() reasons=()
    [ -x "$helper" ] || {
        printf '%s\n' 'unknown (canonical reboot reader unavailable)'
        return 0
    }
    if ! output=$(/usr/bin/timeout --signal=TERM --kill-after=1s 5s \
            "$helper" 2>/dev/null); then
        printf '%s\n' 'unknown (canonical reboot reader failed)'
        return 0
    fi
    mapfile -t lines <<< "$output"
    if [ "${#lines[@]}" -ne 8 ] || [ "${lines[0]}" != schema=1 ] \
            || [[ ! "${lines[1]}" =~ ^activation=(required|recommended|none)$ ]] \
            || [[ ! "${lines[2]}" =~ ^safety=(safe|blocked)$ ]] \
            || [[ ! "${lines[3]}" =~ ^blockers=[a-z-]+(,[a-z-]+)*$ ]] \
            || [[ ! "${lines[4]}" =~ ^running_kernel=[A-Za-z0-9._+-]+$ ]] \
            || [[ ! "${lines[5]}" =~ ^latest_kernel=[A-Za-z0-9._+-]+$ ]] \
            || [[ ! "${lines[6]}" =~ ^nvidia_running=[A-Za-z0-9._+-]+$ ]] \
            || [[ ! "${lines[7]}" =~ ^nvidia_installed=[A-Za-z0-9._+-]+$ ]]; then
        printf '%s\n' 'unknown (canonical reboot state malformed)'
        return 0
    fi
    activation=${lines[1]#activation=}
    safety=${lines[2]#safety=}
    blockers=${lines[3]#blockers=}
    running=${lines[4]#running_kernel=}
    latest=${lines[5]#latest_kernel=}
    nv_run=${lines[6]#nvidia_running=}
    nv_disk=${lines[7]#nvidia_installed=}
    case "$safety:$blockers" in
        safe:none) ;;
        blocked:none|safe:*)
            printf '%s\n' 'unknown (canonical reboot state inconsistent)'
            return 0
            ;;
        blocked:*)
            IFS=, read -r -a reasons <<< "$blockers"
            for reason in "${reasons[@]}"; do
                case "$reason" in
                    kernel-cmdline|initramfs|bls-identity|nvidia|boot-inventory|state-unsafe|nvidia-state) ;;
                    *)
                        printf '%s\n' 'unknown (canonical reboot blocker malformed)'
                        return 0
                        ;;
                esac
            done
            ;;
        *)
            printf '%s\n' 'unknown (canonical reboot state inconsistent)'
            return 0
            ;;
    esac
    if [ "$safety" = blocked ]; then
        printf 'BLOCKED (activation=%s; repair before restart: %s)\n' \
            "$activation" "$blockers"
    elif [ "$activation" = required ]; then
        printf 'REQUIRED + SAFE (kernel %s → %s; NVIDIA %s → %s)\n' \
            "$running" "$latest" "$nv_run" "$nv_disk"
    elif [ "$activation" = recommended ]; then
        printf '%s\n' 'RECOMMENDED + SAFE (updated core packages)'
    else
        printf '%s\n' 'not required'
    fi
}
# END REBOOT_STATUS_READER

REBOOT_STATE=$(read_reboot_state)

# ------------------------------------------------------------
# Summary status (for --brief)
# ------------------------------------------------------------
BRIEF_PARTS=()
[ "$LOCKDOWN" = "integrity" ] && BRIEF_PARTS+=("lockdown:ok") || BRIEF_PARTS+=("lockdown:${LOCKDOWN}")
[ "$SB" = "enabled" ] && BRIEF_PARTS+=("secureboot:ok") || BRIEF_PARTS+=("secureboot:${SB}")
[ "$SEL" = "Enforcing" ] && BRIEF_PARTS+=("selinux:ok") || BRIEF_PARTS+=("selinux:${SEL,,}")
[ "$FW" = "active" ] && BRIEF_PARTS+=("firewall:ok") || BRIEF_PARTS+=("firewall:${FW}")
[ "$XDP_STATE" = "active" ] && BRIEF_PARTS+=("lan-xdp:ok") || BRIEF_PARTS+=("lan-xdp:check")
case "$WAN_IPV6_STATUS" in
    ENFORCED*) BRIEF_PARTS+=("wan-ipv6:off-enforced") ;;
    LIVE-OFF*) BRIEF_PARTS+=("wan-ipv6:live-off") ;;
    DEFERRED*|LIVE-DEFERRED*) BRIEF_PARTS+=("wan-ipv6:deferred") ;;
    *) BRIEF_PARTS+=("wan-ipv6:check") ;;
esac
BRIEF_PARTS+=("dns:${DNS_BRIEF}")
case "$FAIL_STATE" in clean*) BRIEF_PARTS+=("faillock:ok") ;; *) BRIEF_PARTS+=("faillock:check") ;; esac
[ "$AUD_NOTIFY" = "active" ] && BRIEF_PARTS+=("audit-notify:ok") || BRIEF_PARTS+=("audit-notify:${AUD_NOTIFY}")
case "$AUDIT_STORAGE" in
    ok) BRIEF_PARTS+=("audit-storage:ok") ;;
    DEGRADED*) BRIEF_PARTS+=("audit-storage:DEGRADED") ;;
    *) BRIEF_PARTS+=("audit-storage:check") ;;
esac
classify_usbguard_brief() {
    case "$1" in
        "active (first-boot state: real)") printf '%s\n' ok ;;
        inactive) printf '%s\n' inactive ;;
        *) printf '%s\n' check ;;
    esac
}
BRIEF_PARTS+=("usbguard:$(classify_usbguard_brief "$UG")")
case "$LUKS_BACKUP_STATE" in
    present*) BRIEF_PARTS+=("luks-backup:ok") ;;
    n/a*)     BRIEF_PARTS+=("luks-backup:n/a") ;;
    *)        BRIEF_PARTS+=("luks-backup:missing") ;;
esac
# Brief mode reuses the severity the reader already computed rather than
# re-deriving it from the rendered prose.
if [ "$EXT_CHECK_WARN" -eq 0 ]; then
    BRIEF_PARTS+=("addon-updates:ok")
else
    BRIEF_PARTS+=("addon-updates:check")
fi
case "$REBOOT_STATE" in
    "not required") BRIEF_PARTS+=("reboot:not-required") ;;
    BLOCKED*) BRIEF_PARTS+=("reboot:BLOCKED") ;;
    REQUIRED*) BRIEF_PARTS+=("reboot:REQUIRED") ;;
    RECOMMENDED*) BRIEF_PARTS+=("reboot:RECOMMENDED") ;;
    *) BRIEF_PARTS+=("reboot:check") ;;
esac

# ------------------------------------------------------------
# Output
# ------------------------------------------------------------
if [ "$MODE" = "brief" ]; then
    (IFS=" "; echo "${BRIEF_PARTS[*]}")
    exit 0
fi

if [ "$MODE" = "json" ]; then
    # One serializer owns quoting of quotes, backslashes and every control
    # character. Hand-built sed escaping is not sufficient for RFC 8259.
    command -v python3 >/dev/null 2>&1 || {
        echo "noid-status --json requires python3" >&2
        exit 1
    }
    python3 - \
        "$(date -Iseconds)" "$LOCKDOWN" "$SB" "$SIG_ENF" "$SEL" \
        "$FW" "$FW_ZONES" "$XDP_STATE" "$WAN_IPV6_STATUS" "$VPN" \
        "$DNS_SELECTION" "$DNS_CONFIGURED" "$DNS_RUNTIME_GLOBAL" \
        "$DNS_PHYSICAL_CONFIGURED" "$DNS_PHYSICAL_RUNTIME" "$DNS_SCOPE" \
        "$DNS_LINK_MODE" "$FAIL_STATE" \
        "$FAIL_CONFIG" "$AIDE_STATE" "$AIDE_POPUP" "$AUD_NOTIFY" \
        "$AUDITD_IMMUT" "$AUDIT_STORAGE" "$UG" "$HSI" "$PLATFORM_STATUS" "$LUKS_STATE" \
        "$LUKS_BACKUP_STATE" "$SNAP_STATE" "$UR_STATE" "$EXT_CHECK_STATE" \
        "$REBOOT_STATE" <<'JSON_PY'
import json
import sys

v = iter(sys.argv[1:])
document = {
    "timestamp": next(v),
    "kernel": {
        "lockdown": next(v),
        "secure_boot": next(v),
        "module_sig_enforce": next(v),
    },
    "lsm": {"selinux": next(v)},
    "network": {
        "firewall_state": next(v),
        "firewall_zones": next(v),
        "lan_xdp": next(v),
        "wan_ipv6": next(v),
        "vpn": next(v),
        "dns": {
            "selection": next(v),
            "configured": next(v),
            "runtime_global": next(v),
            "physical_configured": next(v),
            "physical_runtime": next(v),
            "active_scope": next(v),
            "active_link_mode": next(v),
        },
    },
    "auth": {"faillock_state": next(v), "faillock_config": next(v)},
    "integrity": {
        "aide_timer": next(v),
        "aide_popup": next(v),
        "audit_notify": next(v),
        "auditd": next(v),
        "audit_storage": next(v),
    },
    "hardware": {
        "usbguard": next(v),
        "hsi": next(v),
        "platform_security": next(v),
    },
    "storage": {
        "luks": next(v),
        "luks_backup": next(v),
        "snapper": next(v),
    },
    "updates": {
        "reminder_timer": next(v),
        "addon_check": next(v),
        "reboot_required": next(v),
    },
}
try:
    next(v)
except StopIteration:
    pass
else:
    raise SystemExit("internal noid-status JSON field mismatch")
json.dump(document, sys.stdout, ensure_ascii=False, indent=2)
sys.stdout.write("\n")
JSON_PY
    exit 0
fi

# Full mode
fmt_banner "NoID Privacy — System Status" \
    "$(hostname) · $(uname -r)"
fmt_note "$(date -Iseconds)"

fmt_section "Kernel"
fmt_kv "Lockdown" "$LOCKDOWN"
fmt_kv "Secure Boot" "$SB"
fmt_kv "Module signatures" "$SIG_ENF"

fmt_section "LSM"
fmt_kv "SELinux" "$SEL"

fmt_section "Network"
fmt_kv "Firewalld" "$FW $FW_ZONES"
fmt_kv "Physical XDP/TC" "$XDP_STATE"
fmt_kv "Physical WAN IPv6" "$WAN_IPV6_STATUS"
fmt_kv "WAN-egress-strict" "$WAN_STRICT"
fmt_kv "VPN" "$VPN"
if [ "$DNS_POLICY_WARN" -eq 0 ]; then
    fmt_kv "DNS policy" "$DNS_POLICY"
else
    fmt_kv_warn "DNS policy" "$DNS_POLICY"
fi
fmt_kv "DNS active path" "$DNS_ACTIVE_PATH"

fmt_section "Authentication"
fmt_kv "Faillock state" "$FAIL_STATE"
fmt_kv "Faillock config" "$FAIL_CONFIG"

fmt_section "Integrity monitoring"
fmt_kv "AIDE timer" "$AIDE_STATE"
fmt_kv "AIDE popup" "$AIDE_POPUP"
fmt_kv "Audit alerts" "$AUD_NOTIFY"
fmt_kv "Auditd" "$AUDITD_IMMUT"
fmt_kv "Audit storage" "$AUDIT_STORAGE"

fmt_section "Hardware"
fmt_kv "USBGuard" "$UG"
fmt_kv "Host Security ID" "$HSI"
fmt_kv "Platform security" "$PLATFORM_STATUS"

fmt_section "Storage"
fmt_kv "LUKS" "$LUKS_STATE"
case "$LUKS_BACKUP_STATE" in
    present*|n/a*) fmt_kv "LUKS backup" "$LUKS_BACKUP_STATE" ;;
    *) fmt_kv_warn "LUKS backup" "$LUKS_BACKUP_STATE" ;;
esac
fmt_kv "Snapper" "$SNAP_STATE"

fmt_section "Updates"
fmt_kv "Update reminder" "$UR_STATE"
if [ "$EXT_CHECK_WARN" -eq 0 ]; then
    fmt_kv "Add-on updates" "$EXT_CHECK_STATE"
else
    fmt_kv_warn "Add-on updates" "$EXT_CHECK_STATE"
fi
if [ "$REBOOT_STATE" = "not required" ]; then
    fmt_kv "Reboot" "$REBOOT_STATE"
else
    fmt_kv_warn "Reboot" "$REBOOT_STATE"
fi
fmt_note ""
fmt_note "Docs: /usr/share/doc/noid-privacy/ · Commands: noid-status --help"
STATUS_EOF

chmod 755 /usr/local/bin/noid-status
chown root:root /usr/local/bin/noid-status
echo "  [OK] /usr/local/bin/noid-status installed (755)"

# ----------------------------------------------------------------------------
# Step 7c: Install /usr/local/bin/noid-toggle-aide-popup (escape-hatch)
# ----------------------------------------------------------------------------
# Convenience wrapper for enabling/disabling the AIDE desktop popup via the
# documented drop-in. Avoids users having to remember the cp + daemon-reload
# two-liner from notifications.md.

cat > /usr/local/bin/noid-toggle-aide-popup <<'TOGGLE_POPUP_EOF'
#!/bin/bash
# noid-toggle-aide-popup — enable or disable the AIDE desktop notification.
#
# This helper does not change the timer. It only installs/removes
# /etc/systemd/system/aide-check.service.d/notify.conf.
#
# Usage:
#   sudo noid-toggle-aide-popup on     # enable popup
#   sudo noid-toggle-aide-popup off    # disable popup (default image state)
#   sudo noid-toggle-aide-popup        # show current state

set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin
export LANG=C.UTF-8 LC_ALL=C.UTF-8
# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — AIDE Popup" \
    NOID_FMT_AUTO_SUBTITLE="Desktop notification layer" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

TEMPLATE=/usr/share/doc/noid-privacy/aide-notify-dropin.conf
TEMPLATE_DIR=/usr/share/doc/noid-privacy
DROPIN_DIR=/etc/systemd/system/aide-check.service.d
DROPIN=${DROPIN_DIR}/notify.conf
DATABASE=/var/lib/aide/aide.db.gz
TEMPORARY=""
ROLLBACK=""
DEPLOYED_NEW=0
COMMITTED=0

cleanup_popup_transaction() {
    local cleanup_needed=0 cleanup_failed=0
    if [ -n "$TEMPORARY" ] && ! rm -f -- "$TEMPORARY"; then
        cleanup_failed=1
    fi
    if [ -n "$ROLLBACK" ] && [ -f "$ROLLBACK" ] \
       && [ ! -e "$DROPIN" ] && [ ! -L "$DROPIN" ]; then
        if mv -T -- "$ROLLBACK" "$DROPIN"; then
            cleanup_needed=1
        else
            cleanup_failed=1
        fi
    fi
    if [ "$DEPLOYED_NEW" -eq 1 ] && [ "$COMMITTED" -eq 0 ]; then
        if rm -f -- "$DROPIN"; then
            cleanup_needed=1
        else
            cleanup_failed=1
        fi
    fi
    if [ "$cleanup_needed" -ne 0 ]; then
        sync -- "$DROPIN_DIR" || cleanup_failed=1
        systemctl daemon-reload >/dev/null 2>&1 || cleanup_failed=1
    fi
    if [ "$cleanup_failed" -ne 0 ]; then
        echo "CRITICAL: AIDE popup transaction rollback was incomplete." >&2
        return 1
    fi
}
trap cleanup_popup_transaction EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ACTION="${1:-status}"
[ "$#" -le 1 ] || {
    echo "Usage: noid-toggle-aide-popup [on|off|status]" >&2
    exit 2
}
exec 9</usr/local/bin/noid-toggle-aide-popup
flock -n 9 || {
    echo "Another AIDE popup toggle is already active." >&2
    exit 1
}

if [ "$ACTION" != "status" ] && [ "$(id -u)" -ne 0 ]; then
    echo "Mutating action requires root (use sudo)." >&2
    exit 1
fi

valid_active_database() {
    [ -d /var/lib/aide ] && [ ! -L /var/lib/aide ] \
        && [ "$(stat -Lc '%u:%g:%a' /var/lib/aide 2>/dev/null || true)" = 0:0:700 ] \
        && matchpathcon -V /var/lib/aide >/dev/null \
        && [ -f "$DATABASE" ] && [ ! -L "$DATABASE" ] && [ -s "$DATABASE" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$DATABASE" 2>/dev/null || true)" = 0:0:600:1 ] \
        && matchpathcon -V "$DATABASE" >/dev/null \
        && timeout --signal=TERM --kill-after=2s 30s gzip -t -- "$DATABASE"
}

valid_template() {
    [ -d "$TEMPLATE_DIR" ] && [ ! -L "$TEMPLATE_DIR" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$TEMPLATE_DIR" \
                2>/dev/null || true)" = 0:0:755 ] \
        && matchpathcon -V "$TEMPLATE_DIR" >/dev/null \
        && [ -f "$TEMPLATE" ] && [ ! -L "$TEMPLATE" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$TEMPLATE" \
                2>/dev/null || true)" = 0:0:644:1 ] \
        && matchpathcon -V "$TEMPLATE" >/dev/null
}

dropin_state() {
    if [ ! -e "$DROPIN_DIR" ] && [ ! -L "$DROPIN_DIR" ] \
       && [ ! -e "$DROPIN" ] && [ ! -L "$DROPIN" ]; then
        printf '%s\n' absent
    elif [ ! -d "$DROPIN_DIR" ] || [ -L "$DROPIN_DIR" ] \
         || [ "$(stat -Lc '%u:%g:%a' "$DROPIN_DIR" \
                    2>/dev/null || true)" != 0:0:755 ] \
         || ! matchpathcon -V "$DROPIN_DIR" >/dev/null; then
        printf '%s\n' unsafe
    elif [ ! -e "$DROPIN" ] && [ ! -L "$DROPIN" ]; then
        printf '%s\n' absent
    elif [ -f "$DROPIN" ] && [ ! -L "$DROPIN" ] \
         && [ "$(stat -Lc '%u:%g:%a:%h' "$DROPIN" \
                 2>/dev/null || true)" = 0:0:644:1 ] \
         && matchpathcon -V "$DROPIN" >/dev/null \
         && valid_template && cmp -s -- "$TEMPLATE" "$DROPIN"; then
        printf '%s\n' enabled
    else
        printf '%s\n' unsafe
    fi
}

require_dropin_dir() {
    if [ -e "$DROPIN_DIR" ] || [ -L "$DROPIN_DIR" ]; then
        [ -d "$DROPIN_DIR" ] && [ ! -L "$DROPIN_DIR" ] \
            && [ "$(stat -Lc '%u:%g:%a' "$DROPIN_DIR" \
                    2>/dev/null || true)" = 0:0:755 ] || return 1
    else
        install -d -m 0755 -o root -g root "$DROPIN_DIR"
        restorecon -F "$DROPIN_DIR"
    fi
    [ -d "$DROPIN_DIR" ] && [ ! -L "$DROPIN_DIR" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$DROPIN_DIR" \
                2>/dev/null || true)" = 0:0:755 ] \
        && matchpathcon -V "$DROPIN_DIR" >/dev/null
}

enable_popup() {
    local state
    valid_active_database || {
        echo "No safe active AIDE baseline exists; review and commit one first." >&2
        return 1
    }
    valid_template || {
        echo "Unsafe or missing notification template: $TEMPLATE" >&2
        return 1
    }
    state=$(dropin_state)
    case "$state" in
        enabled)
            echo "AIDE popup is already enabled (exact drop-in active)."
            return 0
            ;;
        unsafe)
            echo "Refusing unsafe or locally drifted drop-in: $DROPIN" >&2
            return 1
            ;;
    esac
    require_dropin_dir || {
        echo "Unsafe AIDE drop-in directory: $DROPIN_DIR" >&2
        return 1
    }
    TEMPORARY=$(mktemp "$DROPIN_DIR/.notify.conf.XXXXXX")
    install -m 0644 -o root -g root "$TEMPLATE" "$TEMPORARY"
    restorecon -F "$TEMPORARY"
    matchpathcon -V "$TEMPORARY" >/dev/null
    sync -- "$TEMPORARY"
    mv -fT -- "$TEMPORARY" "$DROPIN"
    TEMPORARY=""
    DEPLOYED_NEW=1
    sync -- "$DROPIN" "$DROPIN_DIR"
    if ! systemctl daemon-reload; then
        rm -f -- "$DROPIN"
        sync -- "$DROPIN_DIR"
        systemctl daemon-reload >/dev/null 2>&1 || true
        DEPLOYED_NEW=0
        echo "daemon-reload failed; popup deployment rolled back." >&2
        return 1
    fi
    [ "$(dropin_state)" = enabled ] || {
        echo "AIDE popup postcondition failed." >&2
        return 1
    }
    COMMITTED=1
}

disable_popup() {
    local state
    state=$(dropin_state)
    case "$state" in
        absent)
            echo "AIDE popup is already disabled (no drop-in present)."
            return 0
            ;;
        unsafe)
            echo "Refusing to remove unsafe or locally drifted drop-in: $DROPIN" >&2
            return 1
            ;;
    esac
    ROLLBACK=$(mktemp "$DROPIN_DIR/.notify.conf.rollback.XXXXXX")
    rm -f -- "$ROLLBACK"
    mv -T -- "$DROPIN" "$ROLLBACK"
    sync -- "$DROPIN_DIR"
    if ! systemctl daemon-reload; then
        mv -T -- "$ROLLBACK" "$DROPIN"
        ROLLBACK=""
        sync -- "$DROPIN" "$DROPIN_DIR"
        systemctl daemon-reload >/dev/null 2>&1 || true
        echo "daemon-reload failed; popup removal rolled back." >&2
        return 1
    fi
    rm -f -- "$ROLLBACK"
    ROLLBACK=""
    COMMITTED=1
}

case "$ACTION" in
    on|enable)
        enable_popup
        echo "AIDE popup enabled. Disable again: sudo noid-toggle-aide-popup off"
        ;;
    off|disable)
        disable_popup
        echo "AIDE popup disabled. Enable again: sudo noid-toggle-aide-popup on"
        ;;
    status|"")
        case "$(dropin_state)" in
        enabled)
            echo "AIDE popup: ENABLED (${DROPIN})"
            ;;
        absent)
            echo "AIDE popup: disabled (default image state)"
            echo "Enable: sudo noid-toggle-aide-popup on"
            ;;
        *)
            echo "AIDE popup: UNSAFE OR DRIFTED (${DROPIN})" >&2
            exit 1
            ;;
        esac
        ;;
    *)
        echo "Usage: noid-toggle-aide-popup [on|off|status]" >&2
        exit 2
        ;;
esac
TOGGLE_POPUP_EOF

chmod 755 /usr/local/bin/noid-toggle-aide-popup
chown root:root /usr/local/bin/noid-toggle-aide-popup
echo "  [OK] /usr/local/bin/noid-toggle-aide-popup installed (755)"

# ----------------------------------------------------------------------------
# Step 7d: Install /usr/local/sbin/noid-toggle-aide wrapper
# ----------------------------------------------------------------------------
# The Welcome AIDE switch invokes this wrapper directly through its privilege
# router. Installed sessions prefer exact already-authorized noninteractive
# sudo, then use M08's exact-path, uncached AUTH_ADMIN pin. The passwordless
# Live session always uses its transient NOPASSWD sudo route. on/off drive both
# layers; the Welcome switch uses popup-on/popup-off (Layer 2 only — see the
# heredoc usage text).
cat > /usr/local/sbin/noid-toggle-aide <<'TOGGLE_AIDE_EOF'
#!/bin/bash
# noid-toggle-aide — combined toggle for AIDE daily check + GNOME popup.
#
# Two-layer architecture:
#   Layer 1: aide-check.timer — daily integrity scan, available only after a
#            user-reviewed baseline exists.
#   Layer 2: aide-check.service.d/notify.conf drop-in — GNOME popup
#            (opt-in, default OFF; user adds via Welcome dialog or
#            `noid-toggle-aide-popup on`).
#
# Status states (all 4 are valid, none are "wrong"):
#   timer=enabled popup=disabled → silent daily checks
#   timer=enabled popup=enabled  → max-visibility (user-opted-into popup)
#   timer=disabled popup=disabled → default before baseline acceptance or opt-out
#   timer=disabled popup=enabled → unusual (popup hooks service that
#                                  doesn't auto-fire; effectively off)
#
# Usage:
#   sudo noid-toggle-aide on         # enable BOTH layers (timer + popup)
#   sudo noid-toggle-aide off        # disable BOTH layers
#   sudo noid-toggle-aide popup-on   # enable Layer 2 ONLY (timer unchanged)
#   sudo noid-toggle-aide popup-off  # disable Layer 2 ONLY (timer unchanged)
#   sudo noid-toggle-aide            # show current state
#
# popup-on / popup-off are used by the Welcome dialog
# AIDE switch so toggling the GNOME popup does NOT destroy the Layer 1
# silent baseline as side-effect. The M08 polkit program pin keys on the
# binary path; the helper validates ARGS, and uncached AUTH_ADMIN applies to
# every privileged invocation.

set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin
export LANG=C.UTF-8 LC_ALL=C.UTF-8
# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — AIDE" \
    NOID_FMT_AUTO_SUBTITLE="Daily integrity check and notification state" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

TIMER=aide-check.timer
POPUP_CLI=/usr/local/bin/noid-toggle-aide-popup
DROPIN=/etc/systemd/system/aide-check.service.d/notify.conf
DATABASE=/var/lib/aide/aide.db.gz
ACTION="${1:-status}"
TX_ACTIVE=0
TX_TIMER_WAS_ENABLED=0
TX_TIMER_WAS_ACTIVE=0
TX_POPUP_WAS_ENABLED=0
[ "$#" -le 1 ] || {
    echo "Usage: noid-toggle-aide [on|off|popup-on|popup-off|status]" >&2
    exit 2
}
exec 9</usr/local/sbin/noid-toggle-aide
flock -n 9 || {
    echo "Another combined AIDE toggle is already active." >&2
    exit 1
}

if [ "$ACTION" != "status" ] && [ "$(id -u)" -ne 0 ]; then
    echo "Mutating action requires root (use sudo or pkexec)." >&2
    exit 1
fi

timer_enabled() {
    systemctl is-enabled --quiet "$TIMER"
}

timer_active() {
    systemctl is-active --quiet "$TIMER"
}

popup_state() {
    local output
    if ! output=$("$POPUP_CLI" status 2>/dev/null); then
        printf '%s\n' unsafe
        return 0
    fi
    case "$output" in
        "AIDE popup: ENABLED (${DROPIN})")
            printf '%s\n' enabled
            ;;
        "AIDE popup: disabled (default image state)"$'\n'"Enable: sudo noid-toggle-aide-popup on")
            printf '%s\n' disabled
            ;;
        *)
            printf '%s\n' unsafe
            ;;
    esac
}

popup_enabled() {
    [ "$(popup_state)" = enabled ]
}

database_active() {
    local output
    local -a command=(/usr/libexec/noid-aide-status)
    local -a lines=()
    if [ "$(id -u)" -ne 0 ]; then
        command=(sudo -n /usr/libexec/noid-aide-status)
    fi
    output=$("${command[@]}" 2>/dev/null) || return 1
    mapfile -t lines <<<"$output"
    [ "${#lines[@]}" -eq 2 ] \
        && [ "${lines[0]}" = NOID_AIDE_STATE_V1 ] \
        && [ "${lines[1]}" = STATE=active ]
}

restore_timer_state() {
    local was_enabled=$1 was_active=$2
    local failed=0
    if [ "$was_enabled" -eq 1 ]; then
        systemctl enable "$TIMER" >/dev/null 2>&1 || failed=1
    else
        systemctl disable "$TIMER" >/dev/null 2>&1 || failed=1
    fi
    if [ "$was_active" -eq 1 ]; then
        systemctl start "$TIMER" >/dev/null 2>&1 || failed=1
    else
        systemctl stop "$TIMER" >/dev/null 2>&1 || failed=1
    fi
    if [ "$was_enabled" -eq 1 ]; then
        timer_enabled || failed=1
    else
        ! timer_enabled || failed=1
    fi
    if [ "$was_active" -eq 1 ]; then
        timer_active || failed=1
    else
        ! timer_active || failed=1
    fi
    return "$failed"
}

restore_layer_transaction() {
    local failed=0
    [ "$TX_ACTIVE" -eq 1 ] || return 0
    restore_timer_state "$TX_TIMER_WAS_ENABLED" "$TX_TIMER_WAS_ACTIVE" \
        || failed=1
    if [ "$TX_POPUP_WAS_ENABLED" -eq 1 ]; then
        "$POPUP_CLI" on >/dev/null 2>&1 || failed=1
        [ "$(popup_state)" = enabled ] || failed=1
    else
        "$POPUP_CLI" off >/dev/null 2>&1 || failed=1
        [ "$(popup_state)" = disabled ] || failed=1
    fi
    TX_ACTIVE=0
    if [ "$failed" -ne 0 ]; then
        echo "CRITICAL: original AIDE timer/popup state could not be restored completely." >&2
        return 1
    fi
}
trap restore_layer_transaction EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

transactional_both() {
    local target=$1 timer_was_enabled=0 timer_was_active=0
    local popup_was_enabled=0 original_popup_state
    timer_enabled && timer_was_enabled=1
    timer_active && timer_was_active=1
    original_popup_state=$(popup_state)
    case "$original_popup_state" in
        enabled) popup_was_enabled=1 ;;
        disabled) ;;
        *)
            echo "Unsafe or drifted popup state; refusing combined mutation." >&2
            return 1
            ;;
    esac
    TX_TIMER_WAS_ENABLED=$timer_was_enabled
    TX_TIMER_WAS_ACTIVE=$timer_was_active
    TX_POPUP_WAS_ENABLED=$popup_was_enabled
    TX_ACTIVE=1

    if [ "$target" = on ]; then
        "$POPUP_CLI" on
        if ! systemctl enable --now "$TIMER"; then
            restore_layer_transaction || true
            echo "Timer enable failed; rollback was attempted." >&2
            return 1
        fi
        if ! timer_enabled || ! timer_active || ! popup_enabled; then
            restore_layer_transaction || true
            echo "AIDE enable postcondition failed; rollback was attempted." >&2
            return 1
        fi
    else
        "$POPUP_CLI" off
        if ! systemctl disable --now "$TIMER"; then
            restore_layer_transaction || true
            echo "Timer disable failed; rollback was attempted." >&2
            return 1
        fi
        if timer_enabled || timer_active \
           || [ "$(popup_state)" != disabled ]; then
            restore_layer_transaction || true
            echo "AIDE disable postcondition failed; rollback was attempted." >&2
            return 1
        fi
    fi
    TX_ACTIVE=0
}

case "$ACTION" in
    on|enable)
        if ! database_active; then
            echo "No active AIDE baseline exists." >&2
            echo "Run the user-owned review workflow first: sudo noid-aide-baseline-review prepare" >&2
            exit 1
        fi
        transactional_both on
        echo "AIDE Daily Check: ENABLED (timer + popup)."
        echo "Disable again: sudo noid-toggle-aide off"
        ;;
    off|disable)
        transactional_both off
        echo "AIDE Daily Check: disabled (timer + popup)."
        echo "Re-enable both layers after baseline review: sudo noid-toggle-aide on"
        echo "Enable the timer without popups: sudo systemctl enable --now aide-check.timer"
        ;;
    popup-on)
        # Layer 2 ONLY — deploys notify.conf drop-in. Layer 1 timer state
        # is left untouched (stays as silent baseline).
        "$POPUP_CLI" on
        echo "AIDE popup: ENABLED (Layer 2 only; Layer 1 timer unchanged)."
        ;;
    popup-off)
        # Layer 2 ONLY — removes notify.conf drop-in. Layer 1 timer state
        # is left untouched (stays as silent baseline).
        "$POPUP_CLI" off
        echo "AIDE popup: disabled (Layer 2 only; Layer 1 timer unchanged)."
        ;;
    status|"")
        # systemctl is-enabled returns rc=1 for "disabled" while still
        # printing "disabled" to stdout — `|| echo` would append "unknown"
        # to the real state. Use plain capture + post-check instead.
        timer_state=$(systemctl is-enabled "$TIMER" 2>/dev/null || true)
        [ -z "$timer_state" ] && timer_state="unknown"
        timer_runtime=$(systemctl is-active "$TIMER" 2>/dev/null || true)
        [ -z "$timer_runtime" ] && timer_runtime="unknown"
        popup_state=$(popup_state)
        echo "AIDE Daily Check:"
        echo "  timer ($TIMER):  $timer_state / $timer_runtime"
        echo "  popup drop-in:   $popup_state"
        if [ "$popup_state" = unsafe ]; then
            echo "-> UNSAFE OR DRIFTED POPUP STATE (refusing mutation)" >&2
            exit 1
        elif ! database_active; then
            if [ "$timer_state" = enabled ] || [ "$timer_runtime" = active ]; then
                echo "-> INVALID: AIDE timer runs without a valid reviewed baseline" >&2
                exit 1
            fi
            echo "-> UNINITIALIZED (review and accept a baseline before enabling checks)"
        elif [ "$timer_state" = "enabled" ] && [ "$timer_runtime" = "active" ] \
             && [ "$popup_state" = "enabled" ]; then
            echo "-> BOTH LAYERS ON (timer + popup)"
        elif [ "$timer_state" = "enabled" ] && [ "$timer_runtime" = "active" ] \
             && [ "$popup_state" = "disabled" ]; then
            echo "-> SILENT DAILY CHECK (popup off)"
        elif [ "$timer_state" = "disabled" ] && [ "$timer_runtime" = "inactive" ] \
             && [ "$popup_state" = "disabled" ]; then
            echo "-> FULLY OFF (user-opted-out)"
        elif [ "$timer_state" = "disabled" ] && [ "$timer_runtime" = "inactive" ] \
             && [ "$popup_state" = "enabled" ]; then
            echo "-> POPUP ONLY (timer off, popup armed — popup will not fire)"
        else
            echo "-> NON-CANONICAL TIMER STATE: $timer_state / $timer_runtime" >&2
            exit 1
        fi
        ;;
    *)
        echo "Usage: noid-toggle-aide [on|off|popup-on|popup-off|status]" >&2
        exit 2
        ;;
esac
TOGGLE_AIDE_EOF
chmod 0755 /usr/local/sbin/noid-toggle-aide
chown root:root /usr/local/sbin/noid-toggle-aide
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/sbin/noid-toggle-aide 2>/dev/null || true
fi
echo "  [OK] /usr/local/sbin/noid-toggle-aide installed (755)"

# ----------------------------------------------------------------------------
# Step 8: keep aide-check.timer disabled until baseline acceptance
# ----------------------------------------------------------------------------
# A scan without an accepted baseline cannot produce meaningful integrity
# evidence. Installing or first-booting the image must not create that trust
# decision on the user's behalf.
echo ""
echo "[Step 8] aide-check.timer disabled pending user-owned baseline review"
systemctl disable aide-check.timer >/dev/null 2>&1 || true
echo "  [OK] aide-check.timer installed but disabled"
echo "  [INFO] Prepare/review: sudo noid-aide-baseline-review prepare"

# ----------------------------------------------------------------------------
# Step 9: Create /var/log/aide directory for AIDE's log output
# ----------------------------------------------------------------------------
# aide.conf has `report_url=file:@@{LOGDIR}/aide.log` where LOGDIR=/var/log/aide
# Package aide creates the dir, but ensure it exists (defensive).
echo ""
echo "[Step 9] Ensuring /var/log/aide directory exists"

if [ -L /var/log/aide ]; then
    echo "  [FAIL] /var/log/aide must not be a symlink"
    exit 1
fi
install -d -m 0700 -o root -g root /var/log/aide
if [ ! -d /var/log/aide ] || [ -L /var/log/aide ] \
   || [ "$(stat -c '%U:%G:%a' /var/log/aide 2>/dev/null || true)" != \
        root:root:700 ]; then
    echo "  [FAIL] /var/log/aide metadata contract is not a real root:root 0700 directory"
    exit 1
fi
echo "  [OK] /var/log/aide ready (real 700 root:root directory)"

# ----------------------------------------------------------------------------
# Step 9b: aide-check wrapper (per-run TS report + flock mutex + coverage probe)
# ----------------------------------------------------------------------------
# Wrapper adds per-run TS-named reports (--before is ADDITIVE to aide.conf)
# + an external flock vs aide-update (their shared internal aide.log lock
# otherwise fails the daily check with status=21 during candidate preparation) —
# detail in the deployed AIDE_CHECK_WRAPPER_EOF comment. /var/lock is tmpfs,
# so every lock consumer recreates the lock file. Shipped in /usr/local/sbin
# (root-only convention); wired via drop-in so the aide-RPM unit survives
# package upgrades untouched.
#
# The deployed coverage manifest below mirrors manifests/aide-secure-paths.tsv
# byte-for-byte (tests and the M99 finalize view hold every copy identical).
# The wrapper re-resolves each contract with `aide --path-check` before every
# daily check, so the SECURE coverage stays proven against the aide binary
# that actually runs on the installed system, not only against the compose
# chroot's aide.
echo ""
echo "[Step 9b] Installing aide-check wrapper + drop-in + coverage manifest"

install -d -m 0755 -o root -g root /usr/lib/noid-privacy
cat > /usr/lib/noid-privacy/aide-secure-paths.tsv <<'AIDE_COVERAGE_TSV_EOF'
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
AIDE_COVERAGE_TSV_EOF
chmod 0644 /usr/lib/noid-privacy/aide-secure-paths.tsv
chown root:root /usr/lib/noid-privacy/aide-secure-paths.tsv
echo "  [OK] /usr/lib/noid-privacy/aide-secure-paths.tsv installed (644)"

mkdir -p /usr/local/sbin
cat > /usr/local/sbin/noid-aide-check.sh <<'AIDE_CHECK_WRAPPER_EOF'
#!/bin/bash
# NoID Privacy — daily AIDE integrity check wrapper
#
# Provides three things on top of plain `aide --check`:
#   (report) Per-run timestamped report file. AIDE's default report_url
#         (aide.log) is shared across all aide invocations, so daily
#         results were overwritten + lost. This wrapper sets a TS-named
#         report file via --before='report_url=file:…'.
#   (mutex) External flock mutex with aide-update. AIDE's internal flock on
#         aide.log caused aide-check.service to fail with status=21
#         (file-lock timeout) whenever an aide-update was concurrent. The
#         external mutex /var/lock/noid-aide.lock makes the two serialize
#         cleanly — daily check waits up to 1h for candidate review activity.
#   (coverage) Effective-rule probe. AIDE selects the deepest tree node and
#         then the first rule in that node; Fedora's aide.conf carries
#         earlier, broader rules on several of the same nodes. Every
#         canonical coverage contract is re-resolved with `aide --path-check`
#         against the aide binary and config that run on THIS system, so a
#         rule-resolution change after a package update surfaces as a failed
#         unit instead of a quietly downgraded ruleset.

# -E (errtrace) makes the exit-code remapping below hold everywhere. Without
# it bash does not propagate an ERR trap into function bodies, so a `set -e`
# abort inside a helper would exit with the failing command's own status --
# usually 1, which lands right back inside AIDE's 1-7 difference bitmask that
# SuccessExitStatus turns into unit SUCCESS. Today every guard happens to sit
# at top level or behind `||`, so this closes the gap before a future helper
# reopens it rather than after.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin
export LANG=C.UTF-8 LC_ALL=C.UTF-8

AIDE_INTERACTIVE_FORMAT=0
if [ -r /usr/local/lib/noid-privacy/agent-install-format.sh ]; then
    # shellcheck source=/dev/null
    NOID_FMT_AUTO_TITLE="NoID Privacy — AIDE Check" \
    NOID_FMT_AUTO_SUBTITLE="Integrity evidence · baseline preserved" \
        . /usr/local/lib/noid-privacy/agent-install-format.sh
    if [ -t 1 ]; then
        AIDE_INTERACTIVE_FORMAT=1
        fmt_step 1 2 "Validate policy, baseline and coverage"
    fi
fi

# Every guard below exits 14, not 1. aide-check.service.d/exitcode.conf sets
# SuccessExitStatus=1 2 3 4 5 6 7 so that AIDE's own difference bitmask is not
# treated as a unit failure -- which means a wrapper that refuses to run and
# exits 1 is recorded by systemd as a completed, successful check. The unit
# would report "Deactivated successfully", noid-status would still show the
# timer as healthy, and aide-notify.sh would render the refusal as "Integrity
# changes detected. New files." for a scan that never compared anything. The
# drop-in already documents >=14 as the configuration/runtime error range, and
# M25 classifies anything above 7 as an error, so 14 is the correct namespace.
# An unexpected `set -e` abort carries the failing command's own status, which
# is usually 1 and would land back inside the bitmask, so remap that too. The
# script ends in `exec aide --check`, so AIDE's real exit code still reaches
# systemd unchanged -- this trap is gone by then.
noid_aide_abort() {
    local rc=$?
    [ "$rc" -ge 14 ] || rc=14
    echo "noid-aide-check: aborted before the check ran" >&2
    exit "$rc"
}
trap noid_aide_abort ERR

COVERAGE_MANIFEST=/usr/lib/noid-privacy/aide-secure-paths.tsv
CONFIG=/etc/aide.conf
DATABASE_DIR=/var/lib/aide
DATABASE=$DATABASE_DIR/aide.db.gz
LOG_DIR=/var/log/aide
LOCK_FILE=/run/lock/noid-aide.lock

require_selinux_type() {
    local path=$1 expected_type=$2 context
    context=$(stat -Lc '%C' "$path" 2>/dev/null || true)
    [[ "$context" == *":object_r:${expected_type}:"* ]]
}

# These are execution prerequisites, not optional cosmetics. Failure must make
# the systemd unit fail visibly instead of invoking AIDE with an unusable log
# destination or mutex.
[ -d "$LOG_DIR" ] && [ ! -L "$LOG_DIR" ] \
    && [ "$(stat -Lc '%u:%g:%a' "$LOG_DIR" 2>/dev/null || true)" = 0:0:700 ] \
    || { echo "noid-aide-check: unsafe AIDE log directory" >&2; exit 14; }
[ -d "$DATABASE_DIR" ] && [ ! -L "$DATABASE_DIR" ] \
    && [ "$(stat -Lc '%u:%g:%a' "$DATABASE_DIR" \
            2>/dev/null || true)" = 0:0:700 ] \
    || { echo "noid-aide-check: unsafe AIDE database directory" >&2; exit 14; }
if ! { [ -f "$DATABASE" ] && [ ! -L "$DATABASE" ] && [ -s "$DATABASE" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$DATABASE" \
                2>/dev/null || true)" = 0:0:600:1 ] \
        && gzip -t -- "$DATABASE"; }; then
    echo "noid-aide-check: unsafe or unreadable active database" >&2
    exit 14
fi
[ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] && [ -s "$CONFIG" ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' "$CONFIG" \
            2>/dev/null || true)" = 0:0:600:1 ] \
    || { echo "noid-aide-check: unsafe AIDE configuration" >&2; exit 14; }
[ -f "$LOCK_FILE" ] && [ ! -L "$LOCK_FILE" ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' "$LOCK_FILE" \
            2>/dev/null || true)" = 0:0:600:1 ] \
    || { echo "noid-aide-check: unsafe tmpfiles-managed mutex" >&2; exit 14; }
for labeled_path in "$LOG_DIR" "$DATABASE_DIR" "$DATABASE" "$CONFIG"; do
    matchpathcon -V "$labeled_path" >/dev/null || {
        echo "noid-aide-check: non-canonical SELinux label: $labeled_path" >&2
        exit 14
    }
done
require_selinux_type "$LOCK_FILE" var_lock_t || {
    echo "noid-aide-check: invalid SELinux type on AIDE mutex" >&2
    exit 14
}

# Hold the mutex on an inherited descriptor for the whole run — the coverage
# probes and the check serialize against aide-update as one unit, and the
# final exec still hands aide's exit code to systemd unchanged.
exec 9<>"$LOCK_FILE"
/usr/bin/flock -w 3600 9 || {
    echo "noid-aide-check: AIDE mutex not acquired within 1h" >&2
    exit 14
}

# Coverage contracts fail closed before AIDE compares a single file: a
# missing rule line, a weak or shadowed resolution, or an unusable manifest
# fails the unit instead of running a check on a downgraded ruleset.
[ -f "$COVERAGE_MANIFEST" ] && [ ! -L "$COVERAGE_MANIFEST" ] \
    && [ -s "$COVERAGE_MANIFEST" ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' "$COVERAGE_MANIFEST" \
            2>/dev/null || true)" = 0:0:644:1 ] || {
    echo "noid-aide-check: coverage manifest missing or symlinked: $COVERAGE_MANIFEST" >&2
    exit 14
}
matchpathcon -V "$COVERAGE_MANIFEST" >/dev/null || {
    echo "noid-aide-check: non-canonical coverage-manifest SELinux label" >&2
    exit 14
}
contracts=0
while IFS='|' read -r rule_path file_type probe_path extra; do
    if [ -z "$rule_path" ] || [ "$file_type" != f ] \
       || [[ "$probe_path" != /* ]] || [ -n "${extra:-}" ]; then
        echo "noid-aide-check: malformed coverage contract line" >&2
        exit 14
    fi
    if ! grep -qxF "$rule_path SECURE" /etc/aide.conf; then
        echo "noid-aide-check: canonical AIDE SECURE rule missing: $rule_path" >&2
        exit 14
    fi
    if ! aide_match=$(
            /usr/bin/timeout --signal=TERM --kill-after=2s 30s \
                /usr/sbin/aide --workers=1 --config="$CONFIG" \
                --path-check="$file_type:$probe_path" 2>&1
        ); then
        aide_match=
    fi
    # Compare resolved attributes as '+'-delimited tokens, not as substrings:
    # a plain `grep -qF sha256` also matches the rule name or the config path
    # in the same output line, and `l` would match inside acl/selinux. The
    # rule string is the first single-quoted group; its last field is the
    # attribute list.
    aide_attrs=$(sed -n "s/^[^']*'\([^']*\)'.*/\1/p" <<<"$aide_match" \
        | head -1 | awk '{print $NF}')
    # ftype and l are load-bearing, not decorative: without ftype a tracked
    # file replaced by a directory or device node reads as unchanged, and
    # without l a symlink retarget is invisible because symlinks carry no
    # hashsum. Both were missing from an earlier hand-written SECURE list, so
    # assert them here rather than trusting the definition to stay a superset.
    coverage_missing=""
    for want_attr in l ftype sha256 sha512; do
        case "+${aide_attrs}+" in
            *"+${want_attr}+"*) ;;
            *) coverage_missing="${coverage_missing} ${want_attr}" ;;
        esac
    done
    if [ -n "$coverage_missing" ]; then
        echo "noid-aide-check: canonical AIDE coverage weak or shadowed: $probe_path (missing:${coverage_missing})" >&2
        exit 14
    fi
    contracts=$((contracts + 1))
done < "$COVERAGE_MANIFEST"
if [ "$contracts" -ne 73 ]; then
    echo "noid-aide-check: coverage manifest contract count is $contracts, expected 73" >&2
    exit 14
fi

AIDE_CHECK_LOG=$(mktemp "$LOG_DIR/aide-check-$(date +%Y%m%d-%H%M%S).XXXXXX.log")
chmod 0600 "$AIDE_CHECK_LOG"
chown root:root "$AIDE_CHECK_LOG"
restorecon -F "$AIDE_CHECK_LOG"
matchpathcon -V "$AIDE_CHECK_LOG" >/dev/null
[ "$AIDE_INTERACTIVE_FORMAT" -ne 1 ] || \
    fmt_step 2 2 "Run check and write timestamped evidence"
exec /usr/sbin/aide --workers=1 \
    --before="report_url=file:${AIDE_CHECK_LOG}" --check
AIDE_CHECK_WRAPPER_EOF

chmod 0755 /usr/local/sbin/noid-aide-check.sh
chown root:root /usr/local/sbin/noid-aide-check.sh

mkdir -p /etc/systemd/system/aide-check.service.d
cat > /etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf <<'AIDE_CHECK_DROPIN_EOF'
# Wrap aide --check with per-mode TS-named report
# (--before) + external flock (vs aide-update lock collision).
#
# Why drop-in vs editing the .service file directly:
#   - aide-check.service is written by Step 2 of the same module (the
#     Fedora aide RPM ships no unit file); the wrapper stays a drop-in so
#     the ExecStart override is visible as an override in `systemctl cat`
#     and survives if the unit ever moves to a packaged one.
#   - The empty `ExecStart=` first resets the parent's ExecStart, then the
#     second line sets the wrapper script as the new ExecStart.
[Service]
ExecStart=
ExecStart=/usr/local/sbin/noid-aide-check.sh
AIDE_CHECK_DROPIN_EOF

chmod 0644 /etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf
chown root:root /etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/sbin/noid-aide-check.sh \
                  /etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf \
                  2>/dev/null || true
fi

systemctl daemon-reload

echo "  [OK] /usr/local/sbin/noid-aide-check.sh installed"
echo "  [OK] /etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf installed"

# ----------------------------------------------------------------------------
# Step 9c: explicit user-owned AIDE baseline review workflow
# ----------------------------------------------------------------------------
# The image does not create or replace an active AIDE database automatically.
# This helper separates candidate generation from trust acceptance: `prepare`
# writes only aide.db.new.gz + a report; `commit` requires the exact candidate
# hash and an interactive typed confirmation before the active DB is replaced.
echo ""
echo "[Step 9c] Installing noid-aide-baseline-review"

cat > /usr/local/sbin/noid-aide-baseline-review <<'AIDE_BASELINE_REVIEW_EOF'
#!/bin/bash
# User-owned AIDE trust workflow. Never called by a timer, service, updater or
# compose finalizer. Agents must not run this workflow on the user's behalf.

set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LANG=C.UTF-8 LC_ALL=C.UTF-8
# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — AIDE Baseline" \
    NOID_FMT_AUTO_SUBTITLE="User-reviewed integrity trust workflow" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

ACTIVE=/var/lib/aide/aide.db.gz
CANDIDATE=/var/lib/aide/aide.db.new.gz
META=/var/lib/aide/aide.db.new.review
ARCHIVE=/var/lib/aide/archive
LOG_DIR=/var/log/aide
LOCK=/run/lock/noid-aide.lock
CONFIG=/etc/aide.conf
COVERAGE=/usr/lib/noid-privacy/aide-secure-paths.tsv
CURRENT_BASIS=
declare -A META_VALUES=()

usage() {
    cat <<'USAGE'
Usage: sudo noid-aide-baseline-review COMMAND [SHA256]

  status               Show active/candidate database state
  prepare              Generate a candidate and detailed report; do not commit
  commit SHA256        Interactively accept the exact reviewed candidate
  discard SHA256       Interactively discard the exact candidate

`commit` is a trust decision. Review the complete report and unexpected drift
before accepting it. Do not use this command merely to silence an alert.
Preparation and commit require one of Module 21's two fully reconciled bases:
confirmed host-only or restored Generic. Transient recovery artifacts are never
trusted.
USAGE
}

require_root() {
    [ "$(id -u)" -eq 0 ] || { echo "ERROR: root required" >&2; exit 1; }
}

path_absent() {
    [ ! -e "$1" ] && [ ! -L "$1" ]
}

validate_regular() {
    local path=$1 expected=$2
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$path" 2>/dev/null || true)" = "$expected" ]
}

validate_file() {
    validate_regular "$1" "$2" && [ -s "$1" ]
}

require_selinux_type() {
    local path=$1 expected_type=$2 context
    context=$(stat -Lc '%C' "$path" 2>/dev/null || true)
    [[ "$context" == *":object_r:${expected_type}:"* ]]
}

file_hash() {
    local line
    line=$(sha256sum -- "$1")
    [[ "$line" =~ ^([a-f0-9]{64})[[:space:]] ]] || return 1
    printf '%s\n' "${BASH_REMATCH[1]}"
}

require_directories() {
    local directory
    for directory in /var/lib/aide "$ARCHIVE" "$LOG_DIR"; do
        if [ -e "$directory" ] || [ -L "$directory" ]; then
            [ -d "$directory" ] && [ ! -L "$directory" ] \
                && [ "$(stat -Lc '%u:%g:%a' "$directory" \
                        2>/dev/null || true)" = 0:0:700 ] || {
                echo "ERROR: unsafe directory metadata: $directory" >&2
                exit 1
            }
        else
            install -d -m 0700 -o root -g root "$directory"
            restorecon -F "$directory"
        fi
        [ -d "$directory" ] && [ ! -L "$directory" ] \
            && [ "$(stat -Lc '%u:%g:%a' "$directory" \
                    2>/dev/null || true)" = 0:0:700 ] || {
            echo "ERROR: unsafe directory metadata: $directory" >&2
            exit 1
        }
        matchpathcon -V "$directory" >/dev/null || {
            echo "ERROR: non-canonical SELinux label: $directory" >&2
            exit 1
        }
    done
}

acquire_lock() {
    validate_regular "$LOCK" 0:0:600:1 || {
        echo "ERROR: unsafe or missing tmpfiles-managed AIDE mutex: $LOCK" >&2
        exit 1
    }
    require_selinux_type "$LOCK" var_lock_t || {
        echo "ERROR: invalid SELinux type on AIDE mutex" >&2
        exit 1
    }
    exec 9<>"$LOCK"
    flock -n 9 || {
        echo "ERROR: another AIDE operation holds $LOCK" >&2
        exit 1
    }
}

require_static_inputs() {
    validate_file "$CONFIG" 0:0:600:1 || {
        echo "ERROR: unsafe AIDE configuration metadata: $CONFIG" >&2
        exit 1
    }
    matchpathcon -V "$CONFIG" >/dev/null || {
        echo "ERROR: non-canonical AIDE configuration SELinux label" >&2
        exit 1
    }
    validate_file "$COVERAGE" 0:0:644:1 || {
        echo "ERROR: unsafe AIDE coverage-manifest metadata: $COVERAGE" >&2
        exit 1
    }
    matchpathcon -V "$COVERAGE" >/dev/null || {
        echo "ERROR: non-canonical coverage-manifest SELinux label" >&2
        exit 1
    }
}

active_binding() {
    if path_absent "$ACTIVE"; then
        printf '%s\n' absent
        return 0
    fi
    if ! { validate_file "$ACTIVE" 0:0:600:1 \
            && matchpathcon -V "$ACTIVE" >/dev/null \
            && gzip -t -- "$ACTIVE"; }; then
        echo "ERROR: active AIDE database is unsafe or unreadable" >&2
        return 1
    fi
    file_hash "$ACTIVE"
}

require_stable_boot_state() {
    [ -x /usr/libexec/noid-boot-mutation-guard ] || {
        echo "ERROR: Module 21 boot-state guard is missing" >&2
        exit 1
    }
    if ! basis_record=$(/usr/libexec/noid-boot-mutation-guard); then
        echo "ERROR: first-boot initramfs state is not reconciled; complete the M21 reboot/recovery workflow first" >&2
        exit 1
    fi
    case "$basis_record" in
        basis=hostonly|basis=generic) ;;
        *)
            echo "ERROR: Module 21 returned an invalid stable-basis record" >&2
            exit 1
            ;;
    esac
    CURRENT_BASIS=${basis_record#basis=}
}

load_meta() {
    local line key value invalid=0 meta_size
    local -A seen=()
    META_VALUES=()
    validate_file "$META" 0:0:600:1 || {
        echo "ERROR: review metadata is absent or unsafe" >&2
        return 1
    }
    matchpathcon -V "$META" >/dev/null || {
        echo "ERROR: review metadata has a non-canonical SELinux label" >&2
        return 1
    }
    meta_size=$(stat -Lc '%s' "$META" 2>/dev/null || true)
    if ! [[ "$meta_size" =~ ^[0-9]+$ ]] || [ "$meta_size" -gt 16384 ]; then
        echo "ERROR: review metadata exceeds the bounded schema size" >&2
        return 1
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            *=*) key=${line%%=*}; value=${line#*=} ;;
            *) invalid=1; continue ;;
        esac
        case "$key" in
            version|candidate_sha256|candidate_size|source_active_sha256|\
            aide_config_sha256|coverage_manifest_sha256|boot_basis|\
            kernel_release|mode|aide_rc|created|report|report_sha256) ;;
            *) invalid=1; continue ;;
        esac
        if [ -n "${seen[$key]+x}" ]; then
            invalid=1
            continue
        fi
        seen["$key"]=1
        META_VALUES["$key"]=$value
    done < "$META"
    [ "${#seen[@]}" -eq 13 ] || invalid=1
    [ "${META_VALUES[version]:-}" = NOID_AIDE_REVIEW_V1 ] || invalid=1
    [[ "${META_VALUES[candidate_sha256]:-}" =~ ^[a-f0-9]{64}$ ]] || invalid=1
    [[ "${META_VALUES[candidate_size]:-}" =~ ^[1-9][0-9]*$ ]] || invalid=1
    [[ "${META_VALUES[source_active_sha256]:-}" =~ ^(absent|[a-f0-9]{64})$ ]] || invalid=1
    [[ "${META_VALUES[aide_config_sha256]:-}" =~ ^[a-f0-9]{64}$ ]] || invalid=1
    [[ "${META_VALUES[coverage_manifest_sha256]:-}" =~ ^[a-f0-9]{64}$ ]] || invalid=1
    [[ "${META_VALUES[boot_basis]:-}" =~ ^(hostonly|generic)$ ]] || invalid=1
    [[ "${META_VALUES[kernel_release]:-}" =~ ^[A-Za-z0-9._+-]{1,255}$ ]] || invalid=1
    [[ "${META_VALUES[mode]:-}" =~ ^(init|update)$ ]] || invalid=1
    [[ "${META_VALUES[aide_rc]:-}" =~ ^[0-7]$ ]] || invalid=1
    [[ "${META_VALUES[created]:-}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:[0-9]{2}|Z)$ ]] \
        || invalid=1
    [[ "${META_VALUES[report]:-}" =~ ^/var/log/aide/aide-baseline-review-[0-9]{8}-[0-9]{6}\.[A-Za-z0-9]{6}\.log$ ]] \
        || invalid=1
    [[ "${META_VALUES[report_sha256]:-}" =~ ^[a-f0-9]{64}$ ]] || invalid=1
    [ "$invalid" -eq 0 ] || {
        echo "ERROR: review metadata violates the closed schema" >&2
        return 1
    }
}

verify_bound_candidate() {
    local supplied=$1 actual source config_hash coverage_hash report_hash size
    [[ "$supplied" =~ ^[a-f0-9]{64}$ ]] || {
        echo "ERROR: exact lowercase SHA-256 argument required" >&2
        return 2
    }
    load_meta
    if ! { validate_file "$CANDIDATE" 0:0:600:1 \
            && matchpathcon -V "$CANDIDATE" >/dev/null \
            && gzip -t -- "$CANDIDATE"; }; then
        echo "ERROR: candidate database is absent, unsafe or unreadable" >&2
        return 1
    fi
    validate_file "${META_VALUES[report]}" 0:0:600:1 || {
        echo "ERROR: bound review report is absent or unsafe" >&2
        return 1
    }
    matchpathcon -V "${META_VALUES[report]}" >/dev/null || {
        echo "ERROR: bound review report has a non-canonical SELinux label" >&2
        return 1
    }
    require_static_inputs
    require_stable_boot_state
    actual=$(file_hash "$CANDIDATE")
    size=$(stat -Lc '%s' "$CANDIDATE")
    source=$(active_binding)
    config_hash=$(file_hash "$CONFIG")
    coverage_hash=$(file_hash "$COVERAGE")
    report_hash=$(file_hash "${META_VALUES[report]}")
    [ "$actual" = "$supplied" ] \
        && [ "$actual" = "${META_VALUES[candidate_sha256]}" ] \
        && [ "$size" = "${META_VALUES[candidate_size]}" ] \
        && [ "$source" = "${META_VALUES[source_active_sha256]}" ] \
        && [ "$config_hash" = "${META_VALUES[aide_config_sha256]}" ] \
        && [ "$coverage_hash" = "${META_VALUES[coverage_manifest_sha256]}" ] \
        && [ "$CURRENT_BASIS" = "${META_VALUES[boot_basis]}" ] \
        && [ "$(uname -r)" = "${META_VALUES[kernel_release]}" ] \
        && [ "$report_hash" = "${META_VALUES[report_sha256]}" ] || {
        echo "ERROR: candidate bindings changed after review preparation" >&2
        return 1
    }
    case "${META_VALUES[mode]}" in
        init)
            [ "${META_VALUES[source_active_sha256]}" = absent ] || {
                echo "ERROR: candidate mode/source binding is inconsistent" >&2
                return 1
            }
            ;;
        update)
            [[ "${META_VALUES[source_active_sha256]}" =~ ^[a-f0-9]{64}$ ]] || {
                echo "ERROR: candidate mode/source binding is inconsistent" >&2
                return 1
            }
            ;;
        *)
            echo "ERROR: candidate mode/source binding is inconsistent" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$actual"
}

verify_discard_identity() {
    local supplied=$1 actual size
    [[ "$supplied" =~ ^[a-f0-9]{64}$ ]] || {
        echo "ERROR: exact lowercase SHA-256 argument required" >&2
        return 2
    }
    if ! { validate_file "$CANDIDATE" 0:0:600:1 \
            && matchpathcon -V "$CANDIDATE" >/dev/null; }; then
        echo "ERROR: candidate is absent, unsafe or unlabeled" >&2
        return 1
    fi
    actual=$(file_hash "$CANDIDATE")
    [ "$actual" = "$supplied" ] || {
        echo "ERROR: supplied hash does not identify the current candidate" >&2
        return 1
    }
    if [ -e "$META" ] || [ -L "$META" ]; then
        load_meta
        size=$(stat -Lc '%s' "$CANDIDATE")
        [ "$actual" = "${META_VALUES[candidate_sha256]}" ] \
            && [ "$size" = "${META_VALUES[candidate_size]}" ] || {
            echo "ERROR: candidate does not match its review metadata" >&2
            return 1
        }
    fi
    printf '%s\n' "$actual"
}

show_status() {
    local active_state candidate_hash
    [ -d /var/lib/aide ] && [ ! -L /var/lib/aide ] \
        && [ "$(stat -Lc '%u:%g:%a' /var/lib/aide \
                2>/dev/null || true)" = 0:0:700 ] || {
        echo "ERROR: unsafe AIDE database directory" >&2
        exit 1
    }
    matchpathcon -V /var/lib/aide >/dev/null || {
        echo "ERROR: non-canonical AIDE database-directory SELinux label" >&2
        exit 1
    }
    acquire_lock
    if active_state=$(active_binding) && [ "$active_state" != absent ]; then
        echo "active: present sha256=$active_state size=$(stat -Lc %s "$ACTIVE")"
    elif [ "$active_state" = absent ]; then
        echo "active: absent (daily timer must remain disabled)"
    else
        echo "active: unsafe or unreadable"
    fi
    if path_absent "$CANDIDATE" && path_absent "$META"; then
        echo "candidate: absent"
    elif validate_file "$CANDIDATE" 0:0:600:1 \
         && matchpathcon -V "$CANDIDATE" >/dev/null; then
        candidate_hash=$(file_hash "$CANDIDATE")
        echo "candidate: present sha256=$candidate_hash size=$(stat -Lc %s "$CANDIDATE")"
        if [ -e "$META" ] || [ -L "$META" ]; then
            if load_meta; then
                echo "report: ${META_VALUES[report]}"
            else
                echo "review metadata: INCOMPLETE OR UNSAFE"
            fi
        else
            echo "review metadata: absent (partial generation; discard by the exact SHA-256 above)"
        fi
    else
        echo "candidate: INCOMPLETE OR UNSAFE (manual root review required)"
    fi
}

prepare_candidate() {
    local source config_hash coverage_hash ts report mode rc hash size
    local report_hash meta_tmp="" kernel_release basis
    acquire_lock
    require_directories
    require_stable_boot_state
    basis=$CURRENT_BASIS
    kernel_release=$(uname -r)
    require_static_inputs
    if ! path_absent "$CANDIDATE" || ! path_absent "$META"; then
        echo "ERROR: an uncommitted candidate already exists; review, commit or discard it first" >&2
        exit 1
    fi

    source=$(active_binding)
    config_hash=$(file_hash "$CONFIG")
    coverage_hash=$(file_hash "$COVERAGE")
    ts=$(date +%Y%m%d-%H%M%S)
    report=$(mktemp "$LOG_DIR/aide-baseline-review-${ts}.XXXXXX.log")
    chmod 0600 "$report"
    chown root:root "$report"
    restorecon -F "$report"
    matchpathcon -V "$report" >/dev/null
    if [ "$source" != absent ]; then
        mode=update
    else
        mode=init
    fi

    echo "Generating $mode candidate. This can take several minutes."
    echo "The active database will not be changed."
    set +e
    /usr/sbin/aide --before="report_url=file:${report}" --workers=1 "--${mode}" \
        >/dev/null 2>&1
    rc=$?
    set -e

    if [ -f "$CANDIDATE" ] && [ ! -L "$CANDIDATE" ] \
       && [ "$(stat -Lc '%u:%g:%h' "$CANDIDATE" \
                2>/dev/null || true)" = 0:0:1 ]; then
        chmod 0600 "$CANDIDATE"
        chown root:root "$CANDIDATE"
        restorecon -F "$CANDIDATE"
    fi
    if [ "$rc" -gt 7 ] || ! validate_file "$CANDIDATE" 0:0:600:1 \
       || ! matchpathcon -V "$CANDIDATE" >/dev/null; then
        echo "ERROR: AIDE candidate generation failed (rc=$rc, report=$report)" >&2
        if validate_file "$CANDIDATE" 0:0:600:1 \
           && matchpathcon -V "$CANDIDATE" >/dev/null; then
            echo "A partial candidate remains at SHA-256 $(file_hash "$CANDIDATE"); inspect it and discard that exact hash explicitly." >&2
        elif [ -e "$CANDIDATE" ] || [ -L "$CANDIDATE" ]; then
            echo "An unsafe partial candidate remains; inspect it manually as root." >&2
        fi
        exit 1
    fi

    chmod 0600 "$CANDIDATE" "$report"
    chown root:root "$CANDIDATE" "$report"
    restorecon -F "$CANDIDATE" "$report"
    matchpathcon -V "$CANDIDATE" "$report" >/dev/null
    gzip -t -- "$CANDIDATE" || {
        echo "ERROR: AIDE wrote an unreadable candidate database" >&2
        exit 1
    }
    [ "$(active_binding)" = "$source" ] \
        && [ "$(file_hash "$CONFIG")" = "$config_hash" ] \
        && [ "$(file_hash "$COVERAGE")" = "$coverage_hash" ] \
        && [ "$(uname -r)" = "$kernel_release" ] || {
        echo "ERROR: a candidate input changed during generation; candidate not reviewable" >&2
        exit 1
    }
    require_stable_boot_state
    [ "$CURRENT_BASIS" = "$basis" ] || {
        echo "ERROR: boot basis changed during candidate generation" >&2
        exit 1
    }
    hash=$(file_hash "$CANDIDATE")
    size=$(stat -Lc '%s' "$CANDIDATE")
    report_hash=$(file_hash "$report")
    meta_tmp=$(mktemp /var/lib/aide/.aide-review.XXXXXX)
    trap 'rm -f -- "${meta_tmp:-}"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    {
        printf 'version=NOID_AIDE_REVIEW_V1\n'
        printf 'candidate_sha256=%s\n' "$hash"
        printf 'candidate_size=%s\n' "$size"
        printf 'source_active_sha256=%s\n' "$source"
        printf 'aide_config_sha256=%s\n' "$config_hash"
        printf 'coverage_manifest_sha256=%s\n' "$coverage_hash"
        printf 'boot_basis=%s\n' "$basis"
        printf 'kernel_release=%s\n' "$kernel_release"
        printf 'mode=%s\n' "$mode"
        printf 'aide_rc=%s\n' "$rc"
        printf 'created=%s\n' "$(date -Iseconds)"
        printf 'report=%s\n' "$report"
        printf 'report_sha256=%s\n' "$report_hash"
    } > "$meta_tmp"
    chmod 0600 "$meta_tmp"
    chown root:root "$meta_tmp"
    restorecon -F "$meta_tmp"
    matchpathcon -V "$meta_tmp" >/dev/null
    sync -- "$CANDIDATE" "$report" "$meta_tmp"
    mv -fT -- "$meta_tmp" "$META"
    meta_tmp=""
    sync -- "$META" /var/lib/aide "$LOG_DIR"
    trap - EXIT HUP INT TERM
    verify_bound_candidate "$hash" >/dev/null

    echo "Candidate prepared: $CANDIDATE"
    echo "SHA-256: $hash"
    echo "Report: $report"
    echo "Review every unexpected path before commit."
    echo "Commit only with: sudo noid-aide-baseline-review commit $hash"
}

commit_candidate() {
    local hash report phrase stamp old_hash archive="" archive_pending=""
    local accepted_record
    local accepted_pending meta_hash transaction_active=0 restore_tmp=""
    local meta_restore_tmp="" meta_source=""
    rollback_commit() {
        local rollback_rc=0 current_hash=""
        [ "$transaction_active" -eq 1 ] || return 0
        set +e
        if validate_file "$CANDIDATE" 0:0:600:1; then
            current_hash=$(file_hash "$CANDIDATE" 2>/dev/null)
            [ "$current_hash" = "$hash" ] || rollback_rc=1
        elif validate_file "$ACTIVE" 0:0:600:1 \
             && [ "$(file_hash "$ACTIVE" 2>/dev/null)" = "$hash" ] \
             && path_absent "$CANDIDATE"; then
            mv -fT -- "$ACTIVE" "$CANDIDATE" || rollback_rc=1
        else
            rollback_rc=1
        fi

        if [ "$old_hash" = absent ]; then
            path_absent "$ACTIVE" || rollback_rc=1
        elif validate_file "$ACTIVE" 0:0:600:1 \
             && [ "$(file_hash "$ACTIVE" 2>/dev/null)" = "$old_hash" ]; then
            :
        elif path_absent "$ACTIVE" && validate_file "$archive" 0:0:600:1 \
             && [ "$(file_hash "$archive" 2>/dev/null)" = "$old_hash" ]; then
            restore_tmp=$(mktemp /var/lib/aide/.aide-active-rollback.XXXXXX) \
                || rollback_rc=1
            if [ -n "$restore_tmp" ]; then
                cp --reflink=auto --preserve=mode,ownership,timestamps \
                    -- "$archive" "$restore_tmp" \
                    && chmod 0600 "$restore_tmp" \
                    && chown root:root "$restore_tmp" \
                    && restorecon -F "$restore_tmp" \
                    && matchpathcon -V "$restore_tmp" >/dev/null \
                    && mv -fT -- "$restore_tmp" "$ACTIVE" \
                    || rollback_rc=1
                restore_tmp=""
            fi
        else
            rollback_rc=1
        fi

        if path_absent "$META"; then
            meta_source=
            if validate_file "$accepted_record" 0:0:600:1 \
               && [ "$(file_hash "$accepted_record" 2>/dev/null)" = "$meta_hash" ]; then
                meta_source=$accepted_record
            elif validate_file "$accepted_pending" 0:0:600:1 \
                 && [ "$(file_hash "$accepted_pending" 2>/dev/null)" = "$meta_hash" ]; then
                meta_source=$accepted_pending
            else
                rollback_rc=1
            fi
            if [ -n "$meta_source" ]; then
                meta_restore_tmp=$(mktemp /var/lib/aide/.aide-meta-rollback.XXXXXX) \
                    || rollback_rc=1
                if [ -n "$meta_restore_tmp" ]; then
                    cp --reflink=auto --preserve=mode,ownership,timestamps \
                        -- "$meta_source" "$meta_restore_tmp" \
                        && chmod 0600 "$meta_restore_tmp" \
                        && chown root:root "$meta_restore_tmp" \
                        && restorecon -F "$meta_restore_tmp" \
                        && matchpathcon -V "$meta_restore_tmp" >/dev/null \
                        && mv -fT -- "$meta_restore_tmp" "$META" \
                        || rollback_rc=1
                    meta_restore_tmp=""
                fi
            fi
        elif ! validate_file "$META" 0:0:600:1 \
             || [ "$(file_hash "$META" 2>/dev/null)" != "$meta_hash" ]; then
            rollback_rc=1
        fi
        rm -f -- "$accepted_pending" "$accepted_record" "$restore_tmp" \
            "$meta_restore_tmp" || rollback_rc=1
        sync -- /var/lib/aide "$ARCHIVE" || rollback_rc=1
        transaction_active=0
        if [ "$rollback_rc" -eq 0 ]; then
            echo "ERROR: baseline commit failed; original active state and candidate were restored." >&2
        else
            echo "CRITICAL: baseline commit failed and automatic rollback was incomplete; keep checks disabled and inspect /var/lib/aide plus $ARCHIVE." >&2
        fi
        set -e
        return "$rollback_rc"
    }

    acquire_lock
    require_directories
    require_stable_boot_state
    verify_bound_candidate "$1" >/dev/null
    hash=${META_VALUES[candidate_sha256]}
    [ -r /dev/tty ] && [ -w /dev/tty ] || { echo "ERROR: interactive TTY required" >&2; exit 1; }

    report=${META_VALUES[report]}
    echo "Report: $report" >/dev/tty
    echo "This will replace the active AIDE trust database with SHA-256 $hash" >/dev/tty
    printf 'Type exactly: ACCEPT AIDE BASELINE %s\n> ' "$hash" >/dev/tty
    IFS= read -r phrase </dev/tty
    [ "$phrase" = "ACCEPT AIDE BASELINE $hash" ] || { echo "Cancelled; active database unchanged." >&2; exit 1; }
    verify_bound_candidate "$hash" >/dev/null

    stamp=$(date +%Y%m%d-%H%M%S.%N)
    accepted_record="$ARCHIVE/aide.review.accepted.${stamp}.${hash}"
    accepted_pending="${accepted_record}.pending"
    path_absent "$accepted_record" && path_absent "$accepted_pending" || {
        echo "ERROR: accepted-review archive collision" >&2
        exit 1
    }
    trap 'rm -f -- "$accepted_pending" "$archive_pending"' EXIT
    old_hash=${META_VALUES[source_active_sha256]}
    if [ "$old_hash" != absent ]; then
        archive="$ARCHIVE/aide.db.${stamp}.${old_hash}.gz"
        archive_pending="${archive}.pending"
        path_absent "$archive" && path_absent "$archive_pending" || {
            echo "ERROR: active-database archive collision" >&2
            exit 1
        }
        cp --reflink=auto --preserve=mode,ownership,timestamps \
            -- "$ACTIVE" "$archive_pending"
        chmod 0600 "$archive_pending"
        chown root:root "$archive_pending"
        restorecon -F "$archive_pending"
        matchpathcon -V "$archive_pending" >/dev/null
        [ "$(file_hash "$archive_pending")" = "$old_hash" ] || {
            echo "ERROR: archived active database hash mismatch" >&2
            exit 1
        }
        sync -- "$archive_pending"
        mv -T -- "$archive_pending" "$archive"
        archive_pending=""
        sync -- "$archive"
    fi

    meta_hash=$(file_hash "$META")
    cp --reflink=auto --preserve=mode,ownership,timestamps \
        -- "$META" "$accepted_pending"
    chmod 0600 "$accepted_pending"
    chown root:root "$accepted_pending"
    restorecon -F "$accepted_pending"
    matchpathcon -V "$accepted_pending" >/dev/null
    [ "$(file_hash "$accepted_pending")" = "$meta_hash" ] || {
        echo "ERROR: pending accepted-review record hash mismatch" >&2
        exit 1
    }
    sync -- "$accepted_pending" "$ARCHIVE"

    transaction_active=1
    trap 'rollback_commit || true' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mv -fT -- "$CANDIDATE" "$ACTIVE"
    matchpathcon -V "$ACTIVE" >/dev/null
    if ! { validate_file "$ACTIVE" 0:0:600:1 \
            && [ "$(file_hash "$ACTIVE")" = "$hash" ] \
            && gzip -t -- "$ACTIVE"; }; then
        echo "ERROR: activated database failed post-commit verification" >&2
        exit 1
    fi
    sync -- "$ACTIVE" /var/lib/aide
    mv -T -- "$accepted_pending" "$accepted_record"
    matchpathcon -V "$accepted_record" >/dev/null
    [ "$(file_hash "$accepted_record")" = "$meta_hash" ] || {
        echo "ERROR: accepted-review record failed post-commit verification" >&2
        exit 1
    }
    rm -f -- "$META"
    sync -- "$accepted_record" "$ARCHIVE" /var/lib/aide
    transaction_active=0
    trap - EXIT HUP INT TERM
    echo "Accepted active baseline SHA-256: $hash"
    echo "Daily checks remain disabled until you run: sudo noid-toggle-aide on"
}

discard_candidate() {
    local hash phrase
    acquire_lock
    require_directories
    verify_discard_identity "$1" >/dev/null
    hash=$1
    [ -r /dev/tty ] && [ -w /dev/tty ] || { echo "ERROR: interactive TTY required" >&2; exit 1; }
    printf 'Type exactly: DISCARD AIDE CANDIDATE %s\n> ' "$hash" >/dev/tty
    IFS= read -r phrase </dev/tty
    [ "$phrase" = "DISCARD AIDE CANDIDATE $hash" ] || { echo "Cancelled; candidate retained." >&2; exit 1; }
    verify_discard_identity "$hash" >/dev/null
    rm -f -- "$CANDIDATE" "$META"
    sync -- /var/lib/aide
    echo "Candidate discarded; reports were preserved."
}

require_root
case "${1:-status}" in
    status)  { [ "$#" -eq 0 ] || [ "$#" -eq 1 ]; } || { usage >&2; exit 2; }; show_status ;;
    prepare) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; prepare_candidate ;;
    commit)  [ "$#" -eq 2 ] || { usage >&2; exit 2; }; commit_candidate "$2" ;;
    discard) [ "$#" -eq 2 ] || { usage >&2; exit 2; }; discard_candidate "$2" ;;
    help|-h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac
AIDE_BASELINE_REVIEW_EOF

chmod 0750 /usr/local/sbin/noid-aide-baseline-review
chown root:root /usr/local/sbin/noid-aide-baseline-review
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/sbin/noid-aide-baseline-review 2>/dev/null || true
fi

# Remove every superseded automatic trust-replacement artifact.
systemctl disable noid-aide-firstboot-rebaseline.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/timers.target.wants/noid-aide-firstboot-rebaseline.timer
rm -f /etc/systemd/system/noid-aide-firstboot-rebaseline.timer
rm -f /etc/systemd/system/noid-aide-firstboot-rebaseline.service
rm -f /usr/local/sbin/noid-aide-firstboot-rebaseline.sh
rm -f /var/lib/noid-privacy/aide-firstboot-rebaselined.flag

echo "  [OK] /usr/local/sbin/noid-aide-baseline-review installed (0750)"
echo "  [OK] no automatic first-boot AIDE rebaseline is installed"

# Every generated policy/helper is a security-relevant installed artifact.
# Labeling failures are fatal: swallowing restorecon errors can leave an image
# that passes syntax checks but fails only after SELinux reaches enforcing mode.
command -v restorecon >/dev/null 2>&1 \
    && command -v matchpathcon >/dev/null 2>&1 || {
    echo "[Module 13] FAIL: SELinux labeling tools are unavailable"
    exit 1
}
while IFS='|' read -r artifact expected_mode; do
    [ -f "$artifact" ] && [ ! -L "$artifact" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$artifact" \
                2>/dev/null || true)" = "0:0:${expected_mode}:1" ] || {
        echo "[Module 13] FAIL: unsafe generated artifact metadata: $artifact"
        exit 1
    }
    restorecon -F "$artifact"
    matchpathcon -V "$artifact" >/dev/null
done <<'M13_GENERATED_ARTIFACTS_EOF'
/etc/aide.conf|600
/etc/systemd/system/aide-check.service|644
/etc/systemd/system/aide-check.timer|644
/etc/systemd/system/aide-check.service.d/exitcode.conf|644
/etc/systemd/system/aide-check.service.d/boot-priority.conf|644
/etc/systemd/system/aide-check.service.d/30-noid-wrapper.conf|644
/usr/share/doc/noid-privacy/aide-notify-dropin.conf|644
/usr/share/doc/noid-privacy/aide-schedule-override.conf|644
/usr/share/doc/noid-privacy/notifications.md|644
/usr/local/bin/aide-notify.sh|755
/usr/libexec/noid-aide-status|755
/etc/sudoers.d/91-noid-aide-status|440
/usr/lib/tmpfiles.d/noid-aide-lock.conf|644
/usr/local/lib/noid-privacy/wait-fedora-welcome.sh|644
/usr/lib/noid-privacy/noid_ui.py|644
/usr/local/bin/noid-welcome.sh|755
/usr/local/lib/noid-privacy/agent-install-format.sh|644
/usr/local/bin/noid-claude-install|755
/usr/local/bin/noid-codex-install|755
/usr/local/bin/noid-protonvpn-install|755
/usr/local/bin/noid-mullvad-install|755
/usr/local/bin/noid-autostart-netwait|755
/etc/xdg/autostart/noid-welcome.desktop|644
/usr/share/applications/noid-welcome.desktop|644
/usr/local/bin/noid-status|755
/usr/local/bin/noid-toggle-aide-popup|755
/usr/local/sbin/noid-toggle-aide|755
/usr/lib/noid-privacy/aide-secure-paths.tsv|644
/usr/local/sbin/noid-aide-check.sh|755
/usr/local/sbin/noid-aide-baseline-review|750
M13_GENERATED_ARTIFACTS_EOF
for artifact_dir in \
    /var/lib/aide \
    /var/log/aide \
    /etc/systemd/system/aide-check.service.d; do
    [ -d "$artifact_dir" ] && [ ! -L "$artifact_dir" ] || {
        echo "[Module 13] FAIL: unsafe generated artifact directory: $artifact_dir"
        exit 1
    }
    restorecon -F "$artifact_dir"
    matchpathcon -V "$artifact_dir" >/dev/null
done
echo "  [OK] generated artifact metadata and SELinux labels are canonical"

# ----------------------------------------------------------------------------
# Step 10: Verification
# ----------------------------------------------------------------------------
#
# No active database is created here. Candidate generation and activation are
# separate, explicit commands in noid-aide-baseline-review.
#
echo ""
echo "[Step 10] Verification"

fail=0

# 10.0 — aide.conf has all authoritative SECURE content-tracking rules. All
# paths come from SECURE_PATHS, the same manifest used to write the config.
# below are added by NoID Privacy (Step 1 append-block); they upgrade Fedora's default
# `/etc PERMS` rule (mode/uid/gid only) to SECURE content tracking. The SECURE
# rule definition itself must precede the path entries.
if grep -qxF 'SECURE = NORMAL+sha256+b' /etc/aide.conf; then
    echo "  [OK] SECURE rule defined (NORMAL + sha256 + b)"
else
    echo "  [FAIL] SECURE rule definition missing or altered — append-block did not run?"
    fail=$((fail + 1))
fi

# 10.0a — prove the superset invariant against the aide binary this image
# ships, not against the spelling of the rule. Every SECURE path would fall
# back to a Fedora NORMAL rule if our rule were absent, so a SECURE that
# resolves to fewer attributes than NORMAL is a coverage REGRESSION, not the
# advertised upgrade. A hand-written attribute list had exactly that defect:
# it silently dropped l (symlink target) and ftype, and symlinks carry no
# hashsum — retargeting a unit symlink was reported by nothing.
# `--path-check` matches against the rule tree only, so the probe paths need
# not exist. /usr resolves through Fedora's own `/usr NORMAL` rule and is not
# shadowed by any SECURE_PATHS entry (those live under /usr/local/share).
aide_rule_attrs() {
    /usr/sbin/aide --config=/etc/aide.conf --path-check="$1" 2>/dev/null \
        | sed -n "s/^[^']*'\([^']*\)'.*/\1/p" | head -1 | awk '{print $NF}'
}
secure_attrs=$(aide_rule_attrs 'f:/etc/audit/.noid-aide-attr-probe' || true)
normal_attrs=$(aide_rule_attrs 'f:/usr/bin/.noid-aide-attr-probe' || true)
if [ -z "$secure_attrs" ] || [ -z "$normal_attrs" ]; then
    echo "  [FAIL] could not resolve SECURE/NORMAL attributes with aide --path-check"
    fail=$((fail + 1))
else
    dropped_attrs=""
    # shellcheck disable=SC2001  # attribute separator is '+', not whitespace
    for attr in $(echo "$normal_attrs" | sed 's/+/ /g'); do
        case "+${secure_attrs}+" in
            *"+${attr}+"*) ;;
            *) dropped_attrs="${dropped_attrs} ${attr}" ;;
        esac
    done
    if [ -n "$dropped_attrs" ]; then
        echo "  [FAIL] SECURE drops NORMAL attribute(s):${dropped_attrs}"
        echo "         NORMAL=$normal_attrs"
        echo "         SECURE=$secure_attrs"
        fail=$((fail + 1))
    else
        echo "  [OK] SECURE resolves to a superset of NORMAL ($secure_attrs)"
    fi
fi
unset -f aide_rule_attrs

# 10.0b — AIDE 0.19.x worker safety. Product-owned CLI pins protect every
# automated/review path; the config assertion also keeps direct admin checks
# on the qualified single-worker setting.
if [ "$(grep -Ec '^[[:space:]]*num_workers[[:space:]]*=' \
        /etc/aide.conf 2>/dev/null || true)" -eq 1 ] && \
   grep -Eq '^[[:space:]]*num_workers[[:space:]]*=[[:space:]]*1([[:space:]]|$)' \
        /etc/aide.conf; then
    echo "  [OK] AIDE num_workers=1 is the single active config assignment"
else
    echo "  [FAIL] AIDE num_workers must have exactly one active assignment set to 1"
    fail=$((fail + 1))
fi
for secure_path in "${SECURE_PATHS[@]}"; do
    if grep -qxF "$secure_path SECURE" /etc/aide.conf; then
        echo "  [OK] SECURE rule present: $secure_path"
    else
        echo "  [FAIL] SECURE rule missing: $secure_path"
        fail=$((fail + 1))
    fi
done

# 10.0b — mutable security controls must never be hidden as runtime noise.
for forbidden_exclude in "${FORBIDDEN_CONTROL_EXCLUDES[@]}"; do
    if grep -qxF "$forbidden_exclude" /etc/aide.conf; then
        echo "  [FAIL] forbidden security-control exclusion present: $forbidden_exclude"
        fail=$((fail + 1))
    else
        echo "  [OK] security-control exclusion absent: $forbidden_exclude"
    fi
done

# 10.1 — AIDE exclusions plus explicit ESP coverage
# Use grep -qF (fixed-string) throughout — avoids bash dq `\$` → `$` → BRE anchor bug.
if grep -qF '!/etc/pam.d$' /etc/aide.conf; then
    echo "  [OK] !/etc/pam.d exclusion present"
else
    echo "  [FAIL] !/etc/pam.d exclusion missing"
    fail=$((fail + 1))
fi

if grep -qF '!/root$' /etc/aide.conf; then
    echo "  [OK] !/root exclusion present"
else
    echo "  [FAIL] !/root exclusion missing"
    fail=$((fail + 1))
fi

if grep -qF '!/boot/grub2$' /etc/aide.conf; then
    echo "  [OK] !/boot/grub2 exclusion present"
else
    echo "  [FAIL] !/boot/grub2 exclusion missing"
    fail=$((fail + 1))
fi

if grep -qF '!/var/log/audit(/.*)?$' /etc/aide.conf; then
    echo "  [OK] !/var/log/audit recursive exclusion present"
else
    echo "  [FAIL] !/var/log/audit recursive exclusion missing"
    fail=$((fail + 1))
fi

if grep -qF '!/var/log/journal(/.*)?$' /etc/aide.conf; then
    echo "  [OK] !/var/log/journal recursive exclusion present"
else
    echo "  [FAIL] !/var/log/journal recursive exclusion missing"
    fail=$((fail + 1))
fi

if grep -qF '/boot/efi ESP' /etc/aide.conf && \
   grep -qF 'ESP = p+u+g+s+sha256+sha512' /etc/aide.conf && \
   ! grep -qF '!/boot/efi' /etc/aide.conf && \
   ! grep -qF '=/boot/efi E' /etc/aide.conf; then
    echo "  [OK] /boot/efi content tracked with VFAT-safe ESP attributes"
else
    echo "  [FAIL] /boot/efi is excluded or lacks the ESP content rule"
    fail=$((fail + 1))
fi

# boot.log exclusions (fixed double-fire)
if grep -qF '!/var/log/boot\.log$' /etc/aide.conf; then
    echo "  [OK] !/var/log/boot.log exclusion present (v2)"
else
    echo "  [FAIL] !/var/log/boot.log exclusion missing (v2)"
    fail=$((fail + 1))
fi

if grep -qF '!/var/log/boot\.log-[0-9]{8}$' /etc/aide.conf; then
    echo "  [OK] !/var/log/boot.log-YYYYMMDD exclusion present (v2)"
else
    echo "  [FAIL] !/var/log/boot.log-YYYYMMDD exclusion missing (v2)"
    fail=$((fail + 1))
fi

# /.snapshots subtree exclusion (Module 20 Snapper integration).
# Explicit verification (silent-regression guard).
# Without this check, an accidental drop of the !/\.snapshots(/.*)?$ line in
# Step 1 would cause exponential AIDE DB growth (N snapshots × 170k files)
# the next time a user prepares a candidate or a check traverses the tree. This
# test catches the regression at image-build %post stage.
if grep -qF '!/\.snapshots(/.*)?$' /etc/aide.conf; then
    echo "  [OK] !/.snapshots subtree exclusion present (v3)"
else
    echo "  [FAIL] !/.snapshots subtree exclusion missing (v3) — exponential DB growth risk"
    fail=$((fail + 1))
fi

# VM disks and generated QEMU runtime state are high-churn, but excluding all
# of /var/lib/libvirt would hide unrelated host state. Verify the narrow pair.
for libvirt_aide_path in \
    '!/var/lib/libvirt/images(/.*)?$' \
    '!/var/lib/libvirt/qemu(/.*)?$'; do
    if grep -qF "$libvirt_aide_path" /etc/aide.conf; then
        echo "  [OK] targeted libvirt exclusion present: $libvirt_aide_path"
    else
        echo "  [FAIL] targeted libvirt exclusion missing: $libvirt_aide_path"
        fail=$((fail + 1))
    fi
done

# 10.2 — systemd units present
for unit in aide-check.service aide-check.timer; do
    if [ -f /etc/systemd/system/$unit ]; then
        mode=$(stat -c "%a" /etc/systemd/system/$unit)
        if [ "$mode" = "644" ]; then
            echo "  [OK] $unit installed (mode $mode)"
        else
            echo "  [FAIL] $unit has wrong mode $mode (expected 644)"
            fail=$((fail + 1))
        fi
    else
        echo "  [FAIL] $unit not installed"
        fail=$((fail + 1))
    fi
done

# 10.3 — exitcode.conf drop-in present and 644 (only active drop-in)
# notify.conf is shipped as TEMPLATE at /usr/share/doc/noid-privacy/aide-notify-dropin.conf
# (opt-in by design per Step 4 rationale), NOT installed at /etc/ path.
exitcode_dropin=/etc/systemd/system/aide-check.service.d/exitcode.conf
if [ -f "$exitcode_dropin" ]; then
    mode=$(stat -c "%a" "$exitcode_dropin")
    if [ "$mode" = "644" ]; then
        echo "  [OK] aide-check.service.d/exitcode.conf installed (mode $mode)"
    else
        echo "  [FAIL] aide-check.service.d/exitcode.conf has wrong mode $mode"
        fail=$((fail + 1))
    fi
else
    echo "  [FAIL] aide-check.service.d/exitcode.conf missing"
    fail=$((fail + 1))
fi

# 10.4 — notify.conf TEMPLATE uses ExecStopPost (NOT ExecStartPost)
# Shipped at /usr/share/doc/noid-privacy/aide-notify-dropin.conf for opt-in users.
# ExecStartPost would be a silent-break bug: $EXIT_STATUS is only defined in
# ExecStop*/ExecCondition per systemd.exec(5).
notify_template=/usr/share/doc/noid-privacy/aide-notify-dropin.conf
if [ ! -f "$notify_template" ]; then
    echo "  [FAIL] notify.conf template missing at $notify_template"
    fail=$((fail + 1))
elif ! grep -q "^ExecStopPost=" "$notify_template"; then
    echo "  [FAIL] notify.conf template missing ExecStopPost directive"
    fail=$((fail + 1))
elif grep -q "^ExecStartPost=" "$notify_template"; then
    echo "  [FAIL] notify.conf template uses ExecStartPost (\$EXIT_STATUS NOT defined — BUG)"
    fail=$((fail + 1))
else
    echo "  [OK] notify.conf template uses ExecStopPost (\$EXIT_STATUS available, opt-in safe)"
fi

# 10.5 — notifier is immutable-owned and accepts only an active, unlocked,
# local graphical foreground session before dropping privileges without PAM.
if [ -f /usr/local/bin/aide-notify.sh ] \
   && [ ! -L /usr/local/bin/aide-notify.sh ] \
   && [ "$(stat -Lc '%U:%G:%a:%h' /usr/local/bin/aide-notify.sh \
            2>/dev/null || true)" = root:root:755:1 ] \
   && bash -n /usr/local/bin/aide-notify.sh \
   && grep -qF 'list-sessions --json=short' /usr/local/bin/aide-notify.sh \
   && grep -qF '/usr/bin/timeout --signal=TERM --kill-after=1s 3s' /usr/local/bin/aide-notify.sh \
   && grep -qF -- '--property=LockedHint' /usr/local/bin/aide-notify.sh \
   && grep -qF 'show-seat "$seat"' /usr/local/bin/aide-notify.sh \
   && grep -qF '[ "$uid" -le 4294967294 ]' /usr/local/bin/aide-notify.sh \
   && grep -qF 'notified_uids["$uid"]=1' /usr/local/bin/aide-notify.sh \
   && grep -qF '"_SYSTEMD_INVOCATION_ID=${INVOCATION_ID}"' /usr/local/bin/aide-notify.sh \
   && grep -qF '/usr/bin/stat -c '\''%F:%u'\'' "$dbus_sock"' /usr/local/bin/aide-notify.sh \
   && grep -qF '/usr/bin/setpriv' /usr/local/bin/aide-notify.sh \
   && ! grep -qF '/run/systemd/users/' /usr/local/bin/aide-notify.sh \
   && ! grep -qF 'sudo -u' /usr/local/bin/aide-notify.sh; then
    echo "  [OK] aide-notify.sh local-session and privilege-drop contract is exact"
else
    echo "  [FAIL] aide-notify.sh local-session or privilege-drop contract invalid"
    fail=$((fail + 1))
fi

if [ -x /usr/libexec/noid-aide-status ] \
   && [ ! -L /usr/libexec/noid-aide-status ] \
   && [ "$(stat -Lc '%U:%G:%a:%h' /usr/libexec/noid-aide-status \
            2>/dev/null || true)" = root:root:755:1 ] \
   && grep -qF 'NOID_AIDE_STATE_V1' /usr/libexec/noid-aide-status \
   && grep -qF 'state=unsafe' /usr/libexec/noid-aide-status \
   && visudo -cf /etc/sudoers.d/91-noid-aide-status >/dev/null \
   && grep -qxF 'Cmnd_Alias NOID_AIDE_STATUS = /usr/libexec/noid-aide-status ""' \
        /etc/sudoers.d/91-noid-aide-status \
   && grep -qxF 'f /run/lock/noid-aide.lock 0600 root root -' \
        /usr/lib/tmpfiles.d/noid-aide-lock.conf; then
    echo "  [OK] read-only AIDE state and exact mutex boundaries are installed"
else
    echo "  [FAIL] read-only AIDE state or mutex boundary invalid"
    fail=$((fail + 1))
fi

# 10.6 — aide-notify.sh does NOT contain a hardcoded user (regression guard)
if grep -qE '^DISPLAY_USER="[^"$]' /usr/local/bin/aide-notify.sh; then
    echo "  [FAIL] aide-notify.sh contains a hardcoded DISPLAY_USER (should be dynamic)"
    fail=$((fail + 1))
else
    echo "  [OK] aide-notify.sh uses dynamic user detection"
fi

# 10.7 — welcome script + desktop file
if [ -f /usr/lib/noid-privacy/noid_ui.py ] \
        && [ ! -L /usr/lib/noid-privacy/noid_ui.py ] \
        && [ "$(stat -c '%U:%G:%a' /usr/lib/noid-privacy/noid_ui.py)" = 'root:root:644' ] \
        && python3 -c 'import pathlib,sys; p=sys.argv[1]; compile(pathlib.Path(p).read_text(), p, "exec")' \
            /usr/lib/noid-privacy/noid_ui.py 2>/dev/null; then
    echo "  [OK] shared NoID Privacy GTK design contract is valid + immutable-owned"
else
    echo "  [FAIL] shared NoID Privacy GTK design contract missing/invalid"
    fail=$((fail + 1))
fi

if [ -x /usr/local/bin/noid-welcome.sh ]; then
    echo "  [OK] /usr/local/bin/noid-welcome.sh executable"
else
    echo "  [FAIL] /usr/local/bin/noid-welcome.sh missing"
    fail=$((fail + 1))
fi

if [ -f /etc/xdg/autostart/noid-welcome.desktop ]; then
    echo "  [OK] /etc/xdg/autostart/noid-welcome.desktop installed"
else
    echo "  [FAIL] /etc/xdg/autostart/noid-welcome.desktop missing"
    fail=$((fail + 1))
fi

if [ -f /usr/share/applications/noid-welcome.desktop ] \
        && grep -q '^Icon=noid-privacy-setup$' \
            /usr/share/applications/noid-welcome.desktop \
        && grep -q '^StartupWMClass=com.noidprivacy.Welcome$' \
            /usr/share/applications/noid-welcome.desktop; then
    echo "  [OK] NoID Privacy Setup app-grid identity is complete"
else
    echo "  [FAIL] NoID Privacy Setup app-grid identity missing/incomplete"
    fail=$((fail + 1))
fi

# 10.7c — noid-claude-install opt-in helper present + executable
if [ -x /usr/local/bin/noid-claude-install ]; then
    echo "  [OK] /usr/local/bin/noid-claude-install executable (Claude Code opt-in installer)"
else
    echo "  [FAIL] /usr/local/bin/noid-claude-install missing or not executable"
    fail=$((fail + 1))
fi

# 10.7b — setup-wizard removed. The wizard was a
# zenity-replacement Python/GTK4 dialog that duplicated the welcome's
# VPN-link and exposed a location toggle that did not match its then-current
# backend assumptions. M17 now deliberately leaves the location key unlocked,
# and curated 4 Flatpak apps (Signal/Flatseal/Tor/KeePassXC) — out of
# NoID Privacy scope. mic + cam toggles were promoted to the welcome dialog
# (Step 6 Hardware Privacy group) using the same SwitchRow/gsettings
# pattern as the AIDE + audit-notify rows. KeePassXC remains as an RPM
# in Module 26 (privacy-essential, GPL-licensed, Fedora-vetted).

# 10.8 — timer installed but disabled pending baseline acceptance.
if [ -L /etc/systemd/system/timers.target.wants/aide-check.timer ]; then
    echo "  [FAIL] aide-check.timer enabled before a user-owned baseline exists"
    fail=$((fail + 1))
elif [ -f /etc/systemd/system/aide-check.timer ]; then
    echo "  [OK] aide-check.timer installed and disabled pending review"
else
    echo "  [FAIL] aide-check.timer not installed"
    fail=$((fail + 1))
fi

# 10.8b — Layer 2 popup drop-in must NOT be deployed at install-time
# (Layer 2 is opt-in via Welcome dialog AIDE switch). Default-install
# state: notify.conf drop-in absent at /etc/systemd/system/aide-check.
# service.d/. Template lives at /usr/share/doc/noid-privacy/aide-notify-
# dropin.conf and is copied into place only when user opts in.
if [ -f /etc/systemd/system/aide-check.service.d/notify.conf ]; then
    echo "  [FAIL] Layer 2 notify.conf drop-in present at install — should be opt-in only"
    fail=$((fail + 1))
else
    echo "  [OK] Layer 2 notify.conf NOT deployed at install (opt-in design)"
fi

# 10.9 — aide package installed (sanity check)
if command -v aide >/dev/null 2>&1; then
    aide_version=$(aide --version 2>&1 | head -1)
    echo "  [OK] aide binary present ($aide_version)"
else
    echo "  [FAIL] aide binary not found"
    fail=$((fail + 1))
fi

# 10.10 — Cross-reference check: Module 25 update-all.sh installed
# M13 runs before M25 in master.ks
# include order, so noid-update-all.sh is NOT yet written when M13's
# verification runs. The WARN was expected timing artifact, not an actual bug.
# Replaced with [info] message acknowledging order. 99-finalize.ks does the
# authoritative end-of-build cross-check (after ALL modules complete).
if [ -x /usr/local/bin/noid-update-all.sh ]; then
    echo "  [OK] Module 25 update-all.sh present (check-only AIDE consumer)"
else
    echo "  [info] Module 25 update-all.sh not yet written at this point in build"
    echo "         (M13 runs before M25 — final verify is in 99-finalize.ks)"
fi

if [ $fail -gt 0 ]; then
    echo ""
    echo "[Module 13] FAILED ($fail checks)"
    exit 1
fi

echo ""
echo "=============================================================="
echo "[Module 13] Done — all checks passed"
echo ""
echo "AIDE baseline: uninitialized by design; user review is required"
echo "  sudo noid-aide-baseline-review prepare"
echo "=============================================================="

%end

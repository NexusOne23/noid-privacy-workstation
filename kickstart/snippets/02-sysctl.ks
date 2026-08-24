# ============================================================================
# Module 02 — Sysctl Hardening
# Status: LOCKED 2026-08-01 (v37) — classify boot-integrity and deliberate Fedora deviations accurately.
#
# Covers:
#   - Hardening parameters across 3 files (hardening / audit-fixes / userns);
#     per-key rationale lives inline in the deployed heredocs below.
#   - Triple-coverage pattern for selected interface-scoped keys: `.all`
#     supplies each key's documented global/aggregate policy, `.default`
#     templates interfaces created later, and `.*` writes every matching
#     interface node. Aggregation is key-specific; only keys whose kernel
#     contract says so (notably rp_filter) use max(all, interface). The
#     wildcard is load-bearing because vendor sysctl.d files also ship
#     wildcards and existing interfaces do not retroactively inherit `.default`.
#   - rp_filter strict (=1) paired with src_valid_mark=1: firewall marks
#     participate in the reverse-path route lookup, so mark-based policy
#     routing and strict validation evaluate the same route context.
#     src_valid_mark needs no wildcard because its documented effective value
#     is max(all, interface); `.default=1` preserves the future-interface
#     template while `.all=1` supplies the global policy.
#   - Coredump Layer 3 of 6: core_pattern=|/bin/false (Layers 1+2 = M08
#     socket mask + coredump.conf, Layer 4 = suid_dumpable=0, Layers 5+6 =
#     M10 limits.conf hard core 0 + system.conf DefaultLimitCORE=0).
#   - Performance/network tuning stays at Fedora/kernel vendor policy unless
#     a separate workload matrix justifies an explicit opt-in profile.
#
# Deliberate deviations (decided + verified; do not re-litigate without
# new evidence):
#   1. kernel.yama.ptrace_scope = 2, not KSPP's 3 — =3 breaks gdb attach /
#      strace -p / ltrace -p, wrong for a Dev/Admin/Creator/AI workstation.
#      Kicksecure-parallel decision. Only scope 3 becomes immutable after it is
#      selected; users can deliberately choose that one-boot ratchet.
#   2. user.max_user_namespaces = 256, not KSPP's 0 — =0 breaks Flatpak,
#      rootless podman and bubblewrap (Firefox sandbox). 256 is the middle
#      ground below the kernel's high, dynamically derived default.
#   3. kernel.modules_disabled stays 0 — =1 would break USB hot-plug,
#      noid-toggle-bluetooth and on-demand module loads.
#      module.sig_enforce=1 + lockdown=integrity + kexec_load_disabled=1 +
#      M21's explicit module policy constrain that attack surface while
#      preserving the workstation's reviewed hardware lifecycle.
#   Madaidan-guide deviations: umask 027 not 0077 (dnf5 issue #1908);
#   mce=0 not applied: it forces a panic for every uncorrected machine-check
#   report, trading recoverability for fail-stop behavior, and does not add
#   ECC detection to non-ECC memory. A system-wide hidepid=2 mount is not
#   applied because it conflicts with the reviewed GNOME/logind/polkit desktop
#   contract; systemd's per-service process-visibility controls remain usable.
#
# Decisions:
#   [1] Wildcard * instead of hardcoded interface names
#   [2] 3 separate files (hardening / audit-fixes / userns)
#   [3] Mode 640 root:root on all three
#   [4] Do NOT set .all.disable_ipv6: tunnel interfaces may carry IPv6
#       (including the killswitch control link); only .default.disable_ipv6=1
#   [5] oops_limit/warn_limit = 100 + panic = -1 (middle ground between
#       KSPP 1/1 and permissive kernel defaults — see the STEP 1 comment)
#   [6] binfmt_misc automatic activation is disabled by Module 21's native
#       systemd masks, NOT in sysctl.d — fs.binfmt_misc.status is a special
#       file that exists only while the filesystem is mounted.
#
# File apply-order (systemd-sysctl lexical):
#   1. /usr/lib/sysctl.d/*                   → vendor defaults
#   2. /etc/sysctl.d/98-privacy-network.conf → M07 forwarding policy; must
#                                                precede reset-sensitive M02
#                                                IPv4 interface hardening
#   3. /etc/sysctl.d/99-audit-fixes.conf     → M02 panic control
#   4. /etc/sysctl.d/99-hardening.conf       → M02 main hardening
#   5. /etc/sysctl.d/99-sysctl.conf          → Fedora compatibility symlink
#                                                to admin-owned /etc/sysctl.conf
#   6. /etc/sysctl.d/99-userns.conf          → M02 userns limit
#   7. /etc/sysctl.d/99-wan-ipv6-off.conf    → M07 firstboot-generated
#                                                physical-link IPv6 policy
#   Last wins per param.
# ============================================================================

%post --erroronfail --log=/var/log/ks-02-sysctl.log
set -euo pipefail

log() { echo "[noid-02-sysctl] $*"; }
log "=== Module 02 post-install: sysctl hardening ==="

# systemd-udev owns this directory on a full Fedora workstation, but create it
# defensively so the module remains valid in minimal/custom package sets.
install -d -m 0755 /etc/sysctl.d

# ====================================================================
# /etc/sysctl.d/99-audit-fixes.conf — Kernel panic control
# ====================================================================
# Bounds the repeatable kernel-oops/warn exploitation window. 100/100/-1 is
# the project-selected middle ground between KSPP 1/1 and the kernel defaults
# (oops_limit=10000, warn_limit=0/unlimited): it avoids a panic on the first
# diagnostic while forcing a panic after the configured count reaches 100.
# panic=-1 requests an immediate reboot once that panic is entered.
cat > /etc/sysctl.d/99-audit-fixes.conf << 'AUDIT_EOF'
# NoID Privacy — Kernel panic control (secureblue/kernel-hardening-checker aligned)
kernel.oops_limit = 100
kernel.warn_limit = 100
kernel.panic = -1
AUDIT_EOF

chmod 640 /etc/sysctl.d/99-audit-fixes.conf
chown root:root /etc/sysctl.d/99-audit-fixes.conf
log "STEP 1: /etc/sysctl.d/99-audit-fixes.conf written (panic control)"

# ====================================================================
# /etc/sysctl.d/99-hardening.conf — Main hardening
# ====================================================================
cat > /etc/sysctl.d/99-hardening.conf << 'HARDENING_EOF'
# ============================================================================
# NoID Privacy — Kernel Hardening Sysctl
# ============================================================================

# === Kernel Security ===
kernel.kptr_restrict = 2              # kernel pointer hidden from all
# KSPP-deviation: ptrace_scope=2 (admin only) instead of KSPP-recommended =3
# (no ptrace at all). =3 would break gdb/strace/ltrace attach-to-running-pid
# workflows — incompatible with NoID Privacy "Dev/Admin/Creator/AI workflows"
# positioning (README). Kicksecure-parallel decision (Kicksecure also uses =2
# for the same reason). Only ptrace_scope=3 is immutable after selection;
# users can deliberately ratchet to 3 manually (`sudo sysctl -w
# kernel.yama.ptrace_scope=3`) until reboot if temporarily needed.
kernel.yama.ptrace_scope = 2          # ptrace: admin only (CAP_SYS_PTRACE) — KSPP-deviation (module header)
kernel.sysrq = 0                      # SysRq disabled (Fedora default is 16)
net.core.bpf_jit_harden = 2           # BPF JIT constant blinding (anti JIT-spray)
dev.tty.ldisc_autoload = 0            # no auto-load of TTY line disciplines
fs.suid_dumpable = 0                  # no core dumps for SUID (Fedora default 2)
# Discard all coredumps — Layer 3 of 6-layer coredump
# block. Without this, kernel pipes to systemd-coredump even when its socket
# is masked → crashing process blocks waiting. |/bin/false closes the pipe
# immediately, process freed. Value MUST stay on its own line: systemd-sysctl
# passes trailing inline text to the kernel. Numeric handlers accept the
# project's inline rationale, but core_pattern would retain such text as
# arguments to /bin/false and silently change the handler contract.
# The `-` prefix → silent failure logged at debug-level
# instead of failing systemd-sysctl. If kernel/SELinux blocks this specific
# write, Layers 1+2+4+5 (systemd-coredump.socket masked + coredump.conf
# Storage=none + fs.suid_dumpable=0 + limits.conf hard core 0) still cover.
-kernel.core_pattern = |/bin/false
fs.protected_regular = 2              # block unsafe O_CREAT opens of others' regular files in sticky dirs
fs.protected_fifos = 2                # block unsafe O_CREAT opens of others' FIFOs in sticky dirs

# === binfmt_misc disable — authoritative handling in Module 21 ===
# fs.binfmt_misc.status is a SPECIAL control file, NOT a
# regular sysctl. Path /proc/sys/fs/binfmt_misc/status only exists when the
# binfmt_misc filesystem is mounted (module loaded + fs mount). On a fresh
# install without cross-arch emulation the path is absent, producing avoidable
# apply-time diagnostics.
#
# Authoritative mechanism: Module 21 masks Fedora's
# proc-sys-fs-binfmt_misc.automount and systemd-binfmt.service activation
# units. That prevents the automatic mount and handler-registration path
# without racing a udev event against filesystem availability. Users who need
# Wine auto-dispatch or cross-architecture handlers have a documented opt-in.
#
# Rationale for sysctl.d removal: writing status=0 at sysctl-apply time is a
# no-op when binfmt_misc is not mounted and cannot replace control of the
# native activation units.

# === Network: ICMP Redirects (reject all) ===
# Triple coverage writes the global policy, future-interface template and
# every matching interface node. Live verification previously found loopback
# nodes still at kernel defaults when only `.all`/`.default` were relied on.
# Aggregation differs by key, so explicit interface writes make source intent
# equal runtime state without assuming a generic `.all` rule.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.*.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.*.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.*.accept_redirects = 0

# === Source Routing (reject all) ===
# Wildcards for pattern-consistency. Vendor 50-default.conf already
# ships `*.accept_source_route=0` for IPv4 (matches NoID Privacy intent, no actual drift),
# but explicit NoID Privacy wildcard makes the M02 source contract drift-proof against
# any future vendor change + matches the triple-coverage convention.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.*.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.*.accept_source_route = 0

# === Send Redirects (off) ===
# Wildcard covers lo (kernel-created before sysctl.d loads).
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.*.send_redirects = 0

# === Shared-Media Flag off — ICMP-redirect hardening ===
# Disable RFC 1620 shared-media redirect behavior. This prevents shared_media
# from broadening secure_redirects to every on-link gateway and keeps the
# redirect policy explicit alongside accept_redirects=0/send_redirects=0.
# It is not a substitute for send_redirects=0: re-enabling that independent
# knob can still permit outbound redirects. Wildcard (*) covers matching
# current interfaces and systemd's per-interface replay path.
net.ipv4.conf.all.shared_media = 0
net.ipv4.conf.default.shared_media = 0
net.ipv4.conf.*.shared_media = 0

# === Martian Logging (on) ===
# Wildcard covers lo (kernel-created before sysctl.d loads).
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.*.log_martians = 1

# === Reverse Path Filtering (mode 1 = strict, with src_valid_mark) ===
# Strict mode + src_valid_mark=1, paired with the M06
# WAN-egress-strict nft-table. For mark-based routing, src_valid_mark=1
# includes the packet mark in the reverse-path route lookup instead of
# exempting the packet from validation. This lets strict rp_filter evaluate
# the same policy-routing context used by marked traffic while unmarked
# traffic remains strictly checked.
# The *.rp_filter=1 wildcard overrides the Fedora vendor
# /usr/lib/sysctl.d/50-default.conf wildcard *.rp_filter=2.
# Per kernel ip-sysctl docs, effective = max(.all, .<iface>); without our
# wildcard, vendor `*=2` applied at boot → existing interfaces stayed LOOSE
# despite NoID Privacy .all=1 (one-way ratchet semantics). Triple-coverage pattern
# matches arp_*/shared_media/IPv6 RA family wildcards already in M02.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.*.rp_filter = 1

# === Mark-aware rp_filter route lookup ===
# Required when rp_filter=1 is combined with any firewall-mark-based policy
# routing. Without it, the reverse-path lookup omits the mark and can consult a
# different routing policy from the packet's marked path. This is
# provider-agnostic and does not bypass validation.
net.ipv4.conf.all.src_valid_mark = 1
net.ipv4.conf.default.src_valid_mark = 1

# === ICMP Protection ===
# Ignore ordinary IPv4 echo requests as an intentional reachability reduction;
# this also removes ping-based diagnostics. Broadcast echo and bogus-error
# controls separately suppress amplification and malformed error handling.
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IPv6 parity (Kicksecure security-misc cross-audit): ignore all unicast and
# multicast ICMPv6 echo requests on IPv6-capable paths. This reduces remote
# echo-reply reachability and multicast amplification surface; the explicit
# compatibility cost is loss of ping6 diagnostics. ICMPv6 defines no timestamp
# request/reply messages, so this is not represented as timestamp protection.
net.ipv6.icmp.echo_ignore_all = 1

# === TCP Hardening ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# === Boot integrity: disable kexec image loading for this running boot ===
kernel.kexec_load_disabled = 1

# === IPv6 default disable (new interfaces start IPv6-off) ===
# NOT .all.disable_ipv6=1: that global switch would also disable IPv6 on
# tunnel/control interfaces that intentionally carry it.
# M07 and M23 own the physical-WAN disable paths.
# VPN providers remain free to configure their own tunnel interfaces.
net.ipv6.conf.default.disable_ipv6 = 1

# === ARP Hardening (.all + .default + wildcard covers all interfaces) ===
# arp_ignore=1 answers only when the requested target address belongs to the
# incoming interface. This is the control X41 recommended for
# MLLVD-CR-24-03 in its 2024 Mullvad VPN audit.
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.conf.*.arp_ignore = 1

# arp_announce=2 selects the best local address for the target from the
# outgoing interface's subnets, reducing cross-interface source disclosure;
# if no suitable address exists, the kernel retains its documented fallback.
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.*.arp_announce = 2

# drop_gratuitous_arp=1 drops all gratuitous ARP frames. The deliberate
# compatibility cost is loss of gratuitous-ARP-based gateway/peer failover;
# M04's permanent gateway identity already chooses the same fail-closed model.
net.ipv4.conf.all.drop_gratuitous_arp = 1
net.ipv4.conf.default.drop_gratuitous_arp = 1
net.ipv4.conf.*.drop_gratuitous_arp = 1

net.ipv4.conf.all.drop_unicast_in_l2_multicast = 1
net.ipv4.conf.default.drop_unicast_in_l2_multicast = 1
net.ipv4.conf.*.drop_unicast_in_l2_multicast = 1

# IPv6 parity: reject unicast IPv6 delivered in an L2 multicast frame. The
# kernel exposes the same per-interface control for IPv6; leaving it at zero
# defeats the spoofing defense on VPN-capable dual-stack paths.
net.ipv6.conf.all.drop_unicast_in_l2_multicast = 1
net.ipv6.conf.default.drop_unicast_in_l2_multicast = 1
net.ipv6.conf.*.drop_unicast_in_l2_multicast = 1

# arp_filter=1 is a separate anti-ARP-flux control for hosts with multiple
# interfaces on one subnet: the kernel answers only if its route decision for
# traffic sourced from the requested address would use the incoming interface.
# Correct behavior therefore depends on matching source-based routing.
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.default.arp_filter = 1
net.ipv4.conf.*.arp_filter = 1

# === IGMP/Multicast: suppress link-local multicast membership reports ===
# Ethernet already exposes the interface MAC to the local link; this setting
# reduces needless IGMP report traffic rather than hiding that MAC.
net.ipv4.igmp_link_local_mcast_reports = 0

# === IPv6 per-interface RA hardening (wildcard + default) ===
# Disable SLAAC/RA/DAD/RS on every matching IPv6 interface. This is inert for
# ordinary WireGuard and routed OpenVPN TUN profiles, but a TAP/RA-dependent
# tunnel must explicitly restore its required per-interface settings after
# activation. Applies at boot and to future interfaces through `.default` plus
# systemd's per-interface replay.
#
# accept_ra = 0 (KSPP via CIS): block ALL router advertisements. Combined
# with accept_ra_defrtr/pinfo/rtr_pref = 0 this is triple-deep coverage.
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.*.accept_ra = 0

net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.*.autoconf = 0

net.ipv6.conf.all.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.*.accept_ra_defrtr = 0

net.ipv6.conf.all.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.*.accept_ra_pinfo = 0

net.ipv6.conf.all.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.*.accept_ra_rtr_pref = 0

net.ipv6.conf.all.dad_transmits = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.*.dad_transmits = 0

net.ipv6.conf.all.router_solicitations = 0
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.*.router_solicitations = 0

# === Fedora/kernel defaults explicit (portability, drift prevention) ===
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# === Intentional NoID Privacy surface reduction (not a Fedora vendor default) ===
# Kernel-doc semantics (Documentation/admin-guide/sysctl/kernel.rst):
#   =0 — unprivileged BPF allowed (pre-5.16 default)
#   =1 — unprivileged bpf() disabled without recovery in this running kernel
#   =2 — unprivileged bpf() disabled, but an administrator may later write
#        0 or 1
# NoID Privacy applies =1 because irreversible disablement for the running boot is the
# intended security boundary. Re-enabling requires an explicit configuration
# change followed by reboot; value 2 would be the administrator-reversible
# alternative, not a stricter state.
kernel.unprivileged_bpf_disabled = 1
# Fedora's mainline-derived perf implementation currently treats 3 like 2:
# unprivileged kernel-wide and kernel-inclusive events are denied, but eligible
# per-process userspace events are not all denied. Keep 3 as a drift-resistant
# KSPP/checker pin, not as a claim of an additional Fedora restriction.
kernel.perf_event_paranoid = 3
# =2 disables io_uring for every process, including privileged callers. This
# removes a large asynchronous syscall interface with a recurring kernel-bug
# history; the explicit compatibility cost is that applications requiring
# io_uring must use their synchronous/epoll fallback or will not run.
kernel.io_uring_disabled = 2

# === Console Kernel Log Verbosity ===
# 4 integers: current_console / default_message / minimum_allowed / boot_default
# Messages print only when their numeric priority is LESS than
# current_console. Therefore current=4 retains KERN_ERR(3) and more severe
# diagnostics while excluding KERN_WARNING(4) and lower-priority chatter.
# default_message=4 labels unprefixed messages as warnings; minimum=1 keeps the
# kernel's standard valid floor; boot_default=4 restores the intended console
# threshold when the kernel resets it. Console writes require administrative
# privilege; dmesg_restrict/kptr_restrict provide the separate disclosure
# controls. This deliberately differs from the KSPP 3/3/3/3 profile because
# M01 uses rd.emergency=halt + rd.shell=0 and must retain actionable early
# KERN_ERR output. Source: kernel printk documentation.
kernel.printk = 4 4 1 4

# === Defense-in-Depth (Memory + Keyboard) ===
dev.tty.legacy_tiocsti = 0
vm.unprivileged_userfaultfd = 0
vm.mmap_min_addr = 65536
vm.mmap_rnd_bits = 32
# KSPP-tightening: mmap_rnd_compat_bits = 16 (max x86_64-
# compat ASLR entropy). Kernel default is 8; a13xp0p0v + KSPP recommend 16.
# This affects 32-bit-compat processes and is retained as a security choice,
# not represented as a measured performance-neutral change. Closes 1 of 8
# KSPP cmdline+sysctl gaps identified by
# `kernel-hardening-checker` during the live hardening audit.
vm.mmap_rnd_compat_bits = 16

# === Generic-image performance policy ===
# NoID Privacy does not override congestion control/qdisc, global socket ceilings,
# NAPI queues, TCP idle/MTU behavior, VFS/writeback policy, max_map_count,
# swappiness or swap readahead in this security file. Their effects depend on
# RAM, storage, RTT/loss, VPN transport, application and kernel version. Fedora
# 44 already supplies its own max_map_count vendor policy. A future NoID Privacy
# performance profile requires a separate opt-in surface plus retained
# low/high-RAM, slow/fast-storage, no-VPN, WireGuard and OpenVPN measurements;
# a universal throughput or no-cost claim is not evidence.

# === KS-consensus additions (Kicksecure cross-audit) ===
# Live-deployed and verified before source-port.
# kernel.core_uses_pid: PID-suffix in core-dump filename — defense-in-depth
#   layer; even though -kernel.core_pattern=|/bin/false discards core dumps,
#   ensures a future filename pattern without its own PID token gains a suffix.
# dev.cdrom.debug: keep the kernel default of no CD-ROM debug output explicit
#   for drift prevention.
kernel.core_uses_pid = 1
dev.cdrom.debug = 0
HARDENING_EOF

chmod 640 /etc/sysctl.d/99-hardening.conf
chown root:root /etc/sysctl.d/99-hardening.conf
log "STEP 2: /etc/sysctl.d/99-hardening.conf written (101 params)"

# ====================================================================
# /etc/sysctl.d/99-userns.conf — User namespace limit
# ====================================================================
cat > /etc/sysctl.d/99-userns.conf << 'USERNS_EOF'
# NoID Privacy — User namespace limit
# KSPP recommends 0 (disable userns), but flatpak/podman/toolbox require
# userns to function. 256 is a middle ground: enough for realistic
# container/sandbox use, far below the kernel's high dynamically derived
# default on Fedora.
user.max_user_namespaces = 256
USERNS_EOF

chmod 640 /etc/sysctl.d/99-userns.conf
chown root:root /etc/sysctl.d/99-userns.conf
log "STEP 3: /etc/sysctl.d/99-userns.conf written"

# ====================================================================
# STEP 4: closed installation postconditions
# ====================================================================
M02_SYSCTL_FILES=(
    /etc/sysctl.d/99-audit-fixes.conf
    /etc/sysctl.d/99-hardening.conf
    /etc/sysctl.d/99-userns.conf
)

command -v restorecon >/dev/null 2>&1 \
    || { log "FAIL: restorecon missing"; exit 1; }
command -v matchpathcon >/dev/null 2>&1 \
    || { log "FAIL: matchpathcon missing"; exit 1; }
command -v sysctl >/dev/null 2>&1 \
    || { log "FAIL: sysctl parser missing"; exit 1; }
restorecon -F "${M02_SYSCTL_FILES[@]}"

verify_owned_regular() {
    local path="$1"
    [ -f "$path" ] && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$path" 2>/dev/null)" = "0:0:640:1" ]
}

for path in "${M02_SYSCTL_FILES[@]}"; do
    verify_owned_regular "$path" \
        || { log "FAIL: invalid M02 file metadata: $path"; exit 1; }
    sysctl --dry-run -p "$path" >/dev/null \
        || { log "FAIL: procps rejected M02 syntax: $path"; exit 1; }
    matchpathcon -V "$path" >/dev/null \
        || { log "FAIL: invalid M02 SELinux label: $path"; exit 1; }
done

[ "$(grep -cE '^-?[a-z]+\.' /etc/sysctl.d/99-audit-fixes.conf)" -eq 3 ] \
    && [ "$(grep -cE '^-?[a-z]+\.' /etc/sysctl.d/99-hardening.conf)" -eq 101 ] \
    && [ "$(grep -cE '^-?[a-z]+\.' /etc/sysctl.d/99-userns.conf)" -eq 1 ] \
    || { log "FAIL: M02 directive cardinality drift"; exit 1; }
grep -qxF 'kernel.printk = 4 4 1 4' /etc/sysctl.d/99-hardening.conf \
    || { log "FAIL: M02 console diagnostic threshold drift"; exit 1; }
grep -qxF -- '-kernel.core_pattern = |/bin/false' \
    /etc/sysctl.d/99-hardening.conf \
    || { log "FAIL: M02 coredump handler drift"; exit 1; }
log "STEP 4: all 3 M02 files passed metadata, parser and content checks"

# ====================================================================
# Note: systemd-sysctl.service runs during early boot before sysinit.target and
# applies sysctl.d/*.conf files in lexical order. No explicit
# `sysctl --system` needed here in the kickstart chroot.
# ====================================================================

log "=== Module 02 complete ==="
%end

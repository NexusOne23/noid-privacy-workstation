#!/bin/bash
# 08-mask-list-structural — verify Module 08 MASK_LIST + dconf + firstboot
#
# Checks:
#   - MASK_LIST has critical units (atd, bluetooth, systemd-coredump.socket, etc.)
#   - MASK_LIST has dnf/dnf5 makecache timer mask (privacy fix)
#   - Coredump layer 2 config written
#   - dconf gnome-software hardening + locks
#   - RPM Fusion release packages installed via dnf
#   - VSCodium repo file + codium install + offline per-user metadata trust
#   - canonical AI doctrine + byte-identical Codex/Gemini adapters
#   - unified firstboot-setup script orchestrates 3 tasks
#   - M3: repo check uses rpm -q (not dnf repolist parsing)

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"
FORMAT_KS="$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks"
ADAPTER_RUNTIME="$PROJECT_ROOT/tests/pre-ship/08-agent-policy-adapters-runtime.sh"
CODEC_RUNTIME="$PROJECT_ROOT/tests/pre-ship/08-codec-runtime.sh"
TEST_LEDGER="$PROJECT_ROOT/tests/README.md"
TEST_STRATEGY="$PROJECT_ROOT/docs/test-strategy.md"
RELEASE_PROCESS="$PROJECT_ROOT/docs/release-process.md"
GAMING_DOC="$PROJECT_ROOT/docs/gaming.md"
KNOWN_FAILURES="$PROJECT_ROOT/docs/known-failures.md"
AUTOMATIC_EXECUTION_DOC="$PROJECT_ROOT/docs/automatic-execution.md"
GPG_TRUST_DOC="$PROJECT_ROOT/docs/gpg-trust-chain.md"
CODIUM_LAUNCH_SOURCE="$PROJECT_ROOT/scripts/noid-codium-launch.sh"
CODIUM_SYNC_SOURCE="$PROJECT_ROOT/scripts/noid-codium-launcher-sync.sh"
CODIUM_LAUNCHER_REGEN="$PROJECT_ROOT/scripts/regen-codium-launcher-embed.sh"

test_start "08-mask-list-structural"

assert_file_exists "$KS_FILE"
assert_file_exists "$AUTOMATIC_EXECUTION_DOC"
assert_grep_fixed 'continuously running project-owned service in an ordinary eligible' \
    "$AUTOMATIC_EXECUTION_DOC" \
    "automatic-execution inventory distinguishes a resident service from enabled metadata"
assert_grep_fixed '`noid-location-sync.service`' "$AUTOMATIC_EXECUTION_DOC" \
    "automatic-execution inventory names the sole resident NoID Privacy service"
assert_grep_fixed 'event-triggered resolution of hostname-based VPN' \
    "$AUTOMATIC_EXECUTION_DOC" \
    "automatic network-traffic disclosure includes WAN-strict endpoint DNS"
assert_grep_fixed 'No project-owned `pam_exec`, cron/anacron or' \
    "$AUTOMATIC_EXECUTION_DOC" \
    "automatic-execution inventory records absent legacy schedulers"

for automatic_surface in \
    aide-check.timer aide-check.service btrfs-scrub.timer btrfs-scrub.service \
    noid-audit-prune.timer noid-auditd-rotate.timer \
    noid-dracut-hostonly-firstboot.timer \
    noid-install-logs-prune.timer noid-lan-expiry-reconcile.timer \
    noid-misc-logs-prune.timer noid-nm-privacy-prune.timer \
    noid-nm-scope-physical-profiles.timer noid-snapper-prune.timer \
    noid-wan-strict-endpoint-expiry.timer \
    noid-audit-event-notify.path noid-audit-storage-notify.path \
    noid-identity-bls-refresh.path noid-liveinst-webui-lifecycle.path \
    noid-usbguard-add-user.path noid-user-avatar-backfill.path \
    noid-wan-strict-scan-profiles.path \
    noid-agent-policy-adapters.service noid-gnome-shell-privacy-cleanup.service \
    noid-gsk-session-environment.service noid-hostonly-boot-success.path \
    noid-location-sync.service noid-update-reminder.timer \
    noid-user-firstrun.service noid-vscodium-repo-key-seed.service \
    noid-firefox-playground-init.desktop noid-firefox-setup.desktop \
    noid-lan-xdp-health.desktop noid-pending-reboot.desktop noid-welcome.desktop \
    25-noid-arp-initial-learn 30-noid-lan-topology-guard \
    40-noid-connection-defaults 50-vpn-zone-enforce \
    55-wan-ipv6-refresh 55-wan-strict-scan-on-network-up \
    58-wan-strict-tunnel-down 60-vpn-endpoint-pin 90-arp-hardening \
    99-noid-sysctl-reapply 20-noid-wan-strict-boot-guard \
    62-noid-mutter-headless-offload.rules \
    70-noid-lan-topology-hotplug.rules \
    71-noid-wan-strict-tunnel-hotplug.rules \
    99-noid-mei-kt-block.rules 99-noid-external-storage-mount.rules \
    99-zz-noid-bluetooth-default.rules \
    noid-lan-expiry-generator audit-notify.service snapper-cleanup.service \
    usbguard-notifier.service 99-noid-xdg-cleanup \
    90-noid-microphone-privacy.conf noid-microphone-privacy.lua \
    50-noid-disable-bluez.conf \
    localsearch-3.desktop org.gnome.Evolution-alarm-notify.desktop \
    geoclue-demo-agent.desktop org.gnome.Tour.desktop \
    org.gnome.OnlineAccounts org.gnome.Identity org.gnome.Software.service \
    49-noid-location-apply 60-noid-toggle-privacy-services.rules \
    50-noid-usbguard.rules \
    25-noid-arp-bootstrap-learn 58-wan-strict-clean-disconnect \
    70-pvpn-killswitch-dns-fix 80-vpn-keepalive \
    60-noid-iosched.rules 99-noid-usb-sync-mount.rules \
    99-noid-usb-write-through.rules \
    noid-dbus-suppress.actions 55-noid-gsk-renderer \
    noid-aide-firstboot-rebaseline.service \
    noid-aide-firstboot-rebaseline.timer noid-aide-rebaseline-on-boot.service \
    noid-dns-health.service noid-dns-health.timer \
    noid-suid-harden.service noid-suid-harden.timer \
    noid-flatseal-install.service noid-firstboot-codec-swap.service \
    noid-mic-privacy-enforce.service noid-plymouth-firstboot.service \
    noid-plymouth-firstboot-cleanup.service \
    noid-arp-bootstrap.service noid-chrony-network-online.path \
    noid-grub-menu-show.service 99-noid-binfmt-disable.rules; do
    assert_grep_fixed "$automatic_surface" "$AUTOMATIC_EXECUTION_DOC" \
        "automatic-execution inventory covers: $automatic_surface"
done
assert_grep_fixed '[`docs/automatic-execution.md`](docs/automatic-execution.md)' \
    "$PROJECT_ROOT/README.md" \
    "README Silent Machine claim links its complete execution inventory"
assert_grep_fixed '[`automatic-execution.md`](automatic-execution.md)' \
    "$PROJECT_ROOT/docs/faq.md" \
    "FAQ background-traffic disclosure links its complete execution inventory"
assert_grep_fixed 'RPM installed by Module 08 `%post`' \
    "$PROJECT_ROOT/docs/ai-workspace.md" \
    "AI workspace states VSCodium's actual installation path"
assert_not_grep 'RPM, in `%packages`' "$PROJECT_ROOT/docs/ai-workspace.md" \
    "AI workspace does not misattribute VSCodium to the package section"
assert_not_grep '](known-failures.md)' "$PROJECT_ROOT/docs/ai-workspace.md" \
    "installed AI-workspace source has no repository-only relative link"
assert_grep_fixed 'exact 27-top-level-key contract' "$KS_FILE" \
    "module header matches the enforced VSCodium settings count"
assert_not_grep_extended 'the %post umask yields|default umask=077|Anaconda %post umask' \
    "$KS_FILE" \
    "module carries no contradictory inherited-umask claim"
assert_grep_fixed 'supported build wrapper pins the compose umask to 022' \
    "$KS_FILE" \
    "explicit metadata rationale names the supported compose boundary"
assert_grep_fixed 'Step 1 MASK_LIST below' "$KS_FILE" \
    "iSCSI package rationale points to its real enforcement step"
assert_not_grep 'Q14 comment line' "$KS_FILE" \
    "iSCSI rationale has no drifting numeric cross-reference"
assert_grep_fixed 'Module 01 sets `countme=False` in /etc/dnf/dnf.conf' \
    "$KS_FILE" \
    "countme rationale names the actual global-policy owner"
assert_not_grep 'verify at lines 1290-1299' "$KS_FILE" \
    "RPM Fusion fallback verification has no stale numeric citation"
assert_not_grep 'codium-install-status' "$KS_FILE" \
    "VSCodium installation leaves no unread dead-state marker"

TMPDIR="$(mktemp -d)"
CODIUM_LAUNCH_FIXTURE=
cleanup_test_fixtures() {
    rm -rf -- "$TMPDIR"
    if [[ -n $CODIUM_LAUNCH_FIXTURE ]]; then
        rm -rf -- "$CODIUM_LAUNCH_FIXTURE"
    fi
}
trap cleanup_test_fixtures EXIT

extract_heredoc "$KS_FILE" "MASK_LIST_EOF"        "$TMPDIR/mask-list.txt" || _fail "MASK_LIST extraction"
extract_heredoc "$KS_FILE" "COREDUMP_EOF"         "$TMPDIR/coredump.conf" || _fail "coredump heredoc"
extract_heredoc "$KS_FILE" "PSTORE_EOF"           "$TMPDIR/pstore.conf" || _fail "pstore heredoc"
extract_heredoc "$KS_FILE" "JOURNALD_EOF"         "$TMPDIR/journald.conf" || _fail "journald heredoc"
extract_heredoc "$KS_FILE" "FSS_SCRIPT_EOF"       "$TMPDIR/fss-init.sh" || _fail "FSS helper heredoc"
extract_heredoc "$KS_FILE" "FSS_UNIT_EOF"         "$TMPDIR/noid-fss-keys-firstboot.service" || _fail "FSS unit heredoc"
extract_heredoc "$KS_FILE" "FSS_DOC_EOF"          "$TMPDIR/fss-verify.md" || _fail "FSS documentation heredoc"
extract_heredoc "$KS_FILE" "NMDISP_EOF"           "$TMPDIR/04-iscsi" || _fail "iSCSI dispatcher override"
# dbus-broker + NM drop-ins re-enabled. Live-test
# bisected NoNewPrivileges=yes as F44 SELinux domain-transition blocker.
extract_heredoc "$KS_FILE" "DBUS_EOF"             "$TMPDIR/dbus-broker.conf" || _fail "dbus-broker heredoc"
# other 5 hardened service drop-ins (for ProtectProc audit)
extract_heredoc "$KS_FILE" "FW_EOF"               "$TMPDIR/firewalld.conf" || _fail "firewalld heredoc"
extract_heredoc "$KS_FILE" "NM_EOF"               "$TMPDIR/nm.conf" || _fail "NetworkManager heredoc"
extract_heredoc "$KS_FILE" "FWUPD_EOF"            "$TMPDIR/fwupd.conf" || _fail "fwupd heredoc"
extract_heredoc "$KS_FILE" "RS_EOF"               "$TMPDIR/rsyslog.conf" || _fail "rsyslog heredoc"
extract_heredoc "$KS_FILE" "ACCOUNTSD_HARDEN_EOF" "$TMPDIR/accountsd.conf" || _fail "accounts-daemon heredoc"
extract_heredoc "$KS_FILE" "USBGUARD_DBUS_HARDEN_EOF" "$TMPDIR/usbguard-dbus.conf" || _fail "usbguard-dbus heredoc"
extract_heredoc "$KS_FILE" "RTKIT_HARDEN_EOF"     "$TMPDIR/rtkit.conf" || _fail "rtkit-daemon heredoc"
extract_heredoc "$KS_FILE" "FIRSTBOOT_SCRIPT_EOF" "$TMPDIR/firstboot.sh" || _fail "firstboot script"
extract_heredoc "$KS_FILE" "FIRSTBOOT_UNIT_EOF"   "$TMPDIR/firstboot.service" || _fail "firstboot unit"
extract_heredoc "$KS_FILE" "NOID_TOGGLE_GAMING_EOF" "$TMPDIR/toggle-gaming" || _fail "gaming toggle"
extract_heredoc "$KS_FILE" "TOGGLE_REPOS_EOF" "$TMPDIR/toggle-thirdparty-repos" \
    || _fail "third-party repo toggle"
extract_heredoc "$KS_FILE" "CLAUDEMD_EOF" "$TMPDIR/agent-policy.md" \
    || _fail "canonical AI policy heredoc"
extract_heredoc "$KS_FILE" "AI_WORKSPACE_DOC_EOF" "$TMPDIR/ai-workspace.md" \
    || _fail "installed AI-workspace documentation heredoc"
extract_heredoc "$KS_FILE" "ELIGIBLE_USER_EOF" "$TMPDIR/noid-eligible-user" \
    || _fail "persistent-user/logind eligibility helper heredoc"
extract_heredoc "$KS_FILE" "VSCODIUM_USER_KEY_HELPER_EOF" \
    "$TMPDIR/vscodium-user-key-seed" || _fail "VSCodium user-key helper heredoc"
extract_heredoc "$KS_FILE" "VSCODIUM_USER_KEY_UNIT_EOF" \
    "$TMPDIR/vscodium-user-key-seed.service" || _fail "VSCodium user-key unit heredoc"
extract_heredoc "$KS_FILE" "VSCODIUM_DNF_ACTION_EOF" \
    "$TMPDIR/vscodium-repo-key.actions" || _fail "VSCodium DNF action heredoc"
extract_heredoc "$KS_FILE" "NOID_CODIUM_LAUNCH_EOF" \
    "$TMPDIR/noid-codium-launch" || _fail "VSCodium default-GPU launcher heredoc"
extract_heredoc "$KS_FILE" "NOID_CODIUM_SYNC_EOF" \
    "$TMPDIR/noid-codium-launcher-sync" || \
    _fail "VSCodium desktop synchronizer heredoc"
extract_heredoc "$KS_FILE" "NOID_CODIUM_ACTION_EOF" \
    "$TMPDIR/noid-codium-launcher.actions" || \
    _fail "VSCodium desktop DNF action heredoc"

# --- MASK_LIST critical entries ---------------------------------------------
# bluetooth.service REMOVED from critical-entries assert
# (design pivot — BT-stack now uses disable+rfkill-block instead of
# mask so GNOME-Settings BT-toggle works natively). bluetooth.service is no
# longer in MASK_LIST.
for unit in atd.service fprintd.service \
            ModemManager.service pcscd.service systemd-homed.service \
            systemd-oomd.service systemd-coredump.socket sshd-unix-local.socket; do
    assert_grep_fixed "$unit" "$TMPDIR/mask-list.txt" "MASK: $unit"
done

# explicit NEGATIVE-assertion that bluetooth.service is NOT
# in MASK_LIST anymore (regression check — re-adding it would break the
# design + GNOME-Settings BT-toggle path).
if grep -qFx "bluetooth.service" "$TMPDIR/mask-list.txt" 2>/dev/null; then
    _fail "bluetooth.service must NOT be in MASK_LIST (regression — service-disable+rfkill-block design)"
else
    _pass "bluetooth.service correctly absent from MASK_LIST (design)"
fi

if grep -qFx "thermald.service" "$TMPDIR/mask-list.txt" 2>/dev/null; then
    _fail "thermald.service must follow Fedora hardware detection, not the privacy mask list"
else
    _pass "thermald.service correctly remains Fedora-owned and unmasked"
fi
assert_grep_fixed "intel_lpmd.service" "$TMPDIR/mask-list.txt" \
    "MASK: intel_lpmd.service (single-EPP-writer policy — tuned is the one backend)"
assert_grep_fixed 'platform/workload configuration can change EPP' "$KS_FILE" \
    "intel_lpmd rationale names its actual overlap with TuneD"
assert_grep_fixed 'at the cost of LPMD'\''s' "$KS_FILE" \
    "intel_lpmd mask documents the active-idle optimization trade-off"
assert_not_grep 'SoC-die LP E-cores (no L3' "$KS_FILE" \
    "intel_lpmd rationale does not universalize one platform topology"

# --- MASK_LIST dnf-makecache (privacy fix) -------------------------------
for unit in dnf-makecache.timer dnf-makecache.service \
            dnf5-makecache.timer dnf5-makecache.service; do
    assert_grep_fixed "$unit" "$TMPDIR/mask-list.txt" "MASK: $unit"
done

# --- MASK_LIST legacy monolithic libvirtd (modular switch) ---
# Reverse polarity: we now mask libvirtd (legacy) and let modular daemons
# stay socket-activated. NoID Privacy matches Fedora F35+ default architecture.
for unit in libvirtd.service libvirtd.socket libvirtd-ro.socket \
            libvirtd-admin.socket libvirtd-tcp.socket libvirtd-tls.socket; do
    assert_grep_fixed "$unit" "$TMPDIR/mask-list.txt" "MASK libvirtd: $unit"
done

# Modular libvirt OPTIONAL daemons masked:
# REVERTED the earlier modular CORE-daemon mask (was over-aggressive — broke VM-hosting
# workflow on systems using libvirt). CORE daemons (virtqemud, virtnetworkd,
# virtstoraged) stay socket-activated per Fedora 35+ design. OPTIONAL daemons that
# are unused on a single-user, local-only privacy workstation ARE masked here:
#   virtproxyd     — remote TCP/TLS libvirt access (local-only design)
#   virtinterfaced — host-NIC management (NetworkManager owns NICs)
#   virtnwfilterd  — per-VM firewall rules (firewalld + nftables cover this)
#   virtsecretd    — libvirt secret storage (unused)
for unit in virtproxyd.service virtproxyd.socket virtproxyd-admin.socket virtproxyd-ro.socket virtproxyd-tcp.socket \
            virtinterfaced.service virtinterfaced.socket virtinterfaced-admin.socket virtinterfaced-ro.socket \
            virtnwfilterd.service virtnwfilterd.socket virtnwfilterd-admin.socket virtnwfilterd-ro.socket \
            virtsecretd.service virtsecretd.socket virtsecretd-admin.socket virtsecretd-ro.socket; do
    assert_grep_fixed "$unit" "$TMPDIR/mask-list.txt" "MASK optional-libvirt: $unit"
done

# CORE modular daemons MUST NOT be masked (regression check — would break VM-hosting):
for unit in virtqemud.service virtqemud.socket virtnetworkd.service virtnetworkd.socket virtstoraged.service virtstoraged.socket; do
    if grep -qFx "$unit" "$TMPDIR/mask-list.txt" 2>/dev/null; then
        _fail "CORE modular-libvirt $unit must NOT be masked (regression — breaks VM-hosting)"
    else
        _pass "CORE modular-libvirt $unit correctly unmasked (socket-active)"
    fi
done

# Local hardware safety/recovery units follow Fedora's maintained conditional
# service/preset policy. Masking any of them silently drops failure detection
# or reshape recovery without reducing network egress.
for unit in mcelog.service smartd.service mdmonitor.service \
            mdmonitor-oneshot.service mdadm-grow-continue@.service; do
    if grep -qFx "$unit" "$TMPDIR/mask-list.txt" 2>/dev/null; then
        _fail "local hardware safety unit must remain unmasked: $unit"
    else
        _pass "local hardware safety unit remains Fedora-owned: $unit"
    fi
done
assert_not_grep 'mdmonitor-grow-continue@\.service' "$TMPDIR/mask-list.txt" \
    "nonexistent mdmonitor grow template spelling is absent"

# --- MASK_LIST defense-in-depth for removed packages ------------------------
for unit in abrtd.service sssd.service passim.service plocate-updatedb.timer; do
    assert_grep_fixed "$unit" "$TMPDIR/mask-list.txt" "MASK (removed-pkg): $unit"
done

# --- iSCSI dispatcher: native admin precedence, no RPM mutation --------------
assert_cmd_success "iSCSI dispatcher no-op parses" bash -n "$TMPDIR/04-iscsi"
assert_eq 1 "$(grep -c '^exit 0$' "$TMPDIR/04-iscsi")" \
    "iSCSI dispatcher override has one explicit no-op exit"
assert_grep_fixed 'documented dispatcher precedence makes an identically named root-owned' \
    "$KS_FILE" "source records NetworkManager admin dispatcher precedence"
assert_not_grep 'chmod 0644 /usr/lib/NetworkManager/dispatcher.d/04-iscsi' "$KS_FILE" \
    "NoID Privacy does not mutate the signed iSCSI dispatcher payload"
assert_not_grep 'cat > /etc/tmpfiles.d/noid-disable-iscsi-dispatcher.conf' "$KS_FILE" \
    "obsolete iSCSI tmpfiles mode repair is not created"
assert_not_grep 'm /usr/lib/NetworkManager/dispatcher.d/04-iscsi' "$KS_FILE" \
    "no tmpfiles mode mutation targets the signed iSCSI dispatcher"
for relabel_target in \
    /etc/systemd/system/switcheroo-control.service.d/99-noid-hardening.conf \
    /etc/systemd/system/dnf5daemon-server.service.d/10-noid-shutdown-timeout.conf \
    /etc/systemd/system/systemd-resolved.service.d/10-noid-shutdown-timeout.conf \
    /etc/NetworkManager/dispatcher.d/04-iscsi \
    /etc/tmpfiles.d/tmp.conf; do
    assert_cmd_success "non-load-bearing relabel cannot abort M08: $relabel_target" \
        awk -v target="$relabel_target" '
            index($0, target) && index($0, "restorecon") {
                record=$0
                getline
                record=record "\n" $0
                if (index(record, "|| true")) ok=1
            }
            END { exit !ok }
        ' "$KS_FILE"
done

# --- MASK_LIST malcontent parental-controls --------------------------------
# Single-user adult workstation has no parental-controls semantic; upstream
# 0.14.0 has buggy time-span handling causing GDBus errors + auto-logout.
assert_grep_fixed "malcontent-timerd.service" "$TMPDIR/mask-list.txt" "MASK malcontent: malcontent-timerd.service"

# --- MASK_LIST total count --------------------------------------------------
# The reviewed 82-entry inventory spans unused discovery/remote-access
# services, legacy networking, parental controls, optional virtualization,
# hardware-specific daemons and their sockets/timers/targets/mount helpers.
# Count the closed heredoc vocabulary directly: systemd also permits dotted
# aliases plus path/slice/scope/device unit types, so a suffix allowlist would
# let a newly reviewed unit escape the cardinality gate.
mask_count=$(grep -cEv '^[[:space:]]*(#|$)' "$TMPDIR/mask-list.txt" 2>/dev/null || true)
mask_count=${mask_count:-0}
if [ "$mask_count" -eq 82 ]; then
    _pass "MASK_LIST exact reviewed count: $mask_count"
else
    _fail "MASK_LIST count drifted (actual: $mask_count, expected: 82)"
fi

# --- coredump.conf Storage=none (Layer 2) -----------------------------------
assert_grep_extended '^Storage=none$' "$TMPDIR/coredump.conf"
assert_grep_extended '^ProcessSizeMax=0$' "$TMPDIR/coredump.conf"
assert_grep_fixed 'layer 2 of the 6-layer coredump block' "$TMPDIR/coredump.conf" \
    "deployed coredump policy documents all six layers"
assert_grep_fixed 'DefaultLimitCORE=0 (Module 10, systemd services)' \
    "$TMPDIR/coredump.conf" \
    "deployed coredump policy names the systemd-service limit"
assert_not_grep '^KeepFree=' "$TMPDIR/coredump.conf" \
    "coredump policy contains no invalid percentage-valued size directive"

# Storage=none exits without processing /sys/fs/pstore. It prevents the
# userspace copy but cannot drain firmware-backed records; M01 owns that
# separate kernel boundary.
assert_grep_extended '^Storage=none$' "$TMPDIR/pstore.conf"
assert_not_grep '^Unlink=' "$TMPDIR/pstore.conf" \
    "pstore policy does not advertise an unreachable unlink operation"
assert_grep_fixed 'does not unlink firmware-backed' "$TMPDIR/pstore.conf" \
    "deployed pstore rationale scopes the userspace control accurately"

# --- journald hardening drop-in -----------------------------
# Caps journal growth, enables FSS sealing, blocks log forwarding leaks
assert_grep_extended '^Storage=persistent$'          "$TMPDIR/journald.conf"
assert_grep_extended '^Compress=yes$'                "$TMPDIR/journald.conf"
assert_grep_extended '^Seal=yes$'                    "$TMPDIR/journald.conf"
assert_grep_extended '^SystemMaxUse=500M$'           "$TMPDIR/journald.conf"
assert_grep_extended '^SystemKeepFree=1G$'           "$TMPDIR/journald.conf"
assert_grep_extended '^SystemMaxFileSize=50M$'       "$TMPDIR/journald.conf"
assert_grep_extended '^MaxRetentionSec=30day$'       "$TMPDIR/journald.conf"
assert_grep_extended '^MaxFileSec=1week$'            "$TMPDIR/journald.conf"
assert_grep_extended '^ForwardToSyslog=no$'          "$TMPDIR/journald.conf"
assert_grep_extended '^ForwardToKMsg=no$'            "$TMPDIR/journald.conf"
assert_grep_extended '^ForwardToConsole=no$'         "$TMPDIR/journald.conf"
assert_grep_extended '^ForwardToWall=no$'            "$TMPDIR/journald.conf"

# FSS output classification and key extraction must remain diagnostic under
# set -e: zero, one and multiple keys are distinct outcomes, as are an
# unsupported feature and a real command failure.
FSS_HARNESS="$TMPDIR/fss-pure-functions.sh"
sed -n '/^# BEGIN FSS_PURE_FUNCTIONS$/,/^# END FSS_PURE_FUNCTIONS$/p' \
    "$TMPDIR/fss-init.sh" > "$FSS_HARNESS"
cat >> "$FSS_HARNESS" <<'FSS_HARNESS_EOF'
case "$1" in
    classify) classify_fss_setup "$2" "$3" ;;
    parse) extract_fss_verify_key "$2" ;;
    *) exit 64 ;;
esac
FSS_HARNESS_EOF
assert_cmd_success "FSS pure-function harness is valid bash" \
    bash -n "$FSS_HARNESS"
assert_cmd_failure "FSS parser rejects output with no verification key" \
    bash "$FSS_HARNESS" parse 'setup completed without a printable key'
FSS_KEY_ONE='abcdef-012345-6789ab-cdef01/123456-abcdef'
parsed_key=$(bash "$FSS_HARNESS" parse "generated key $FSS_KEY_ONE")
assert_eq "$FSS_KEY_ONE" "$parsed_key" \
    "FSS parser accepts exactly one verification key"
assert_cmd_failure "FSS parser rejects multiple verification keys" \
    bash "$FSS_HARNESS" parse "$FSS_KEY_ONE second $FSS_KEY_ONE"
fss_state=$(bash "$FSS_HARNESS" classify 1 \
    'Compiled without forward-secure sealing support.')
assert_eq unsupported "$fss_state" \
    "FSS classifier distinguishes unsupported systemd build"
fss_state=$(bash "$FSS_HARNESS" classify 7 'journal transport failed')
assert_eq failed "$fss_state" \
    "FSS classifier preserves a real command failure"
fss_state=$(bash "$FSS_HARNESS" classify 0 "generated key $FSS_KEY_ONE")
assert_eq supported "$fss_state" \
    "FSS classifier accepts successful setup output"
fss_state=$(bash "$FSS_HARNESS" classify 1 \
    'Sealing key file /var/log/journal/fixture/fss exists already. Use --force to recreate.')
assert_eq existing "$fss_state" \
    "FSS classifier distinguishes an existing trust chain"
assert_not_grep 'journalctl --setup-keys --force' "$TMPDIR/fss-init.sh" \
    "FSS helper never replaces an existing sealing-key trust chain"
assert_grep_fixed 'no completion state written; a future supported build may retry' \
    "$TMPDIR/fss-init.sh" \
    "unsupported FSS builds do not permanently suppress later support"
assert_grep_fixed \
    "ExecCondition=/usr/bin/sh -c '/usr/bin/systemd-analyze --version | /usr/bin/grep -qF -- +GCRYPT'" \
    "$TMPDIR/noid-fss-keys-firstboot.service" \
    "known-unsupported FSS builds skip the mutating helper before startup"
assert_grep_fixed 'without a key-setup attempt' "$TMPDIR/fss-verify.md" \
    "FSS guide preserves the silent-machine condition-skip boundary"
assert_not_grep 'bounded journal notice per boot' "$TMPDIR/fss-verify.md" \
    "FSS guide does not normalize a known-no-op per-boot task"
assert_grep_fixed 'state=skipped-no-fss' "$KS_FILE" \
    "the exact v123 unsupported-state schema has a migration path"
assert_grep_fixed 'Never absorb or replace an unknown or' "$KS_FILE" \
    "FSS migration preserves unknown and successful trust state"
assert_grep_fixed 'install -d -m 0700 -o root -g root /etc/noid-privacy' \
    "$KS_FILE" "FSS owns its local verification-key parent as private root state"
assert_grep_fixed 'mv -fT -- "$key_candidate" "$KEY_DEST"' \
    "$TMPDIR/fss-init.sh" "FSS verification key is published atomically"
assert_not_grep_fixed 'chown root:root "$key_candidate"' "$TMPDIR/fss-init.sh" \
    "FSS key publication needs no chown syscall under its seccomp filter"
assert_not_grep_fixed 'chown root:root "$state_candidate"' "$TMPDIR/fss-init.sh" \
    "FSS state publication needs no chown syscall under its seccomp filter"
assert_grep_fixed 'RECOVERY: FSS key publication failed' \
    "$TMPDIR/fss-init.sh" \
    "post-setup publication failure preserves the public recovery key"
assert_grep_fixed "journalctl -u noid-fss-keys-firstboot.service --grep='RECOVERY:'" \
    "$TMPDIR/fss-verify.md" \
    "FSS guide documents non-rotating recovery after a publication failure"
assert_grep_fixed 'VERIFY_KEY_SHA256=' "$TMPDIR/fss-init.sh" \
    "FSS completion evidence binds the exact local verification-key bytes"
assert_grep_fixed 'FSS keys generated but verification key not extractable from output' \
    "$TMPDIR/fss-init.sh" "no-match parser diagnostic remains reachable"
assert_grep_fixed 'multiple verification keys; refusing ambiguity' \
    "$TMPDIR/fss-init.sh" "multiple-key ambiguity has an explicit diagnostic"
assert_grep_fixed 'After the user reviews and accepts a baseline and enables the timer' \
    "$TMPDIR/fss-verify.md" "FSS guide states the conditional AIDE boundary"
assert_not_grep_extended 'AIDE.*baseline \+ daily check|AIDE.*active integrity layer' \
    "$TMPDIR/fss-verify.md" "FSS guide does not claim uninitialized AIDE is active"
assert_grep_fixed 'The verification key is not secret.' "$TMPDIR/fss-verify.md" \
    "FSS guide states the public verification-key boundary accurately"
assert_not_grep 'shred -u' "$TMPDIR/fss-verify.md" \
    "FSS guide makes no false secure-erasure claim on Btrfs/flash"

cp "$TMPDIR/noid-fss-keys-firstboot.service" "$TMPDIR/fss-verify.service"
sed -i 's|^ExecStart=.*|ExecStart=/usr/bin/true|' "$TMPDIR/fss-verify.service"
assert_cmd_success "FSS service passes the native systemd unit verifier" \
    systemd-analyze verify "$TMPDIR/fss-verify.service"

# MALLOC_PERTURB_ is a glibc debugging aid, not a production exploit
# mitigation. It fills every glibc allocation/free, does not guarantee a crash
# or a particular freed value, and must not be imposed on every desktop process.
assert_not_grep 'MALLOC_PERTURB_' "$KS_FILE" \
    "global malloc debug perturbation is absent from the production image"

# --- dbus-broker hardening drop-in (re-enabled, no NNP) ----
# Verify dbus-broker drop-in: 13 directives, NoNewPrivileges EXCLUDED
# (F44 systemd 259.5 + SELinux init_t→system_dbusd_t domain transition).
assert_grep_extended '^PrivateTmp=yes$'         "$TMPDIR/dbus-broker.conf"
assert_grep_extended '^ProtectSystem=full$'     "$TMPDIR/dbus-broker.conf"
assert_grep_extended '^ProtectProc=invisible$'  "$TMPDIR/dbus-broker.conf"
# Negative assertion: NoNewPrivileges MUST NOT be set (would break SELinux)
if grep -qE '^NoNewPrivileges=' "$TMPDIR/dbus-broker.conf" 2>/dev/null; then
    _fail "dbus-broker: NoNewPrivileges= MUST NOT be set (SELinux domain transition)"
else
    _pass "dbus-broker: correctly omits NoNewPrivileges (SELinux compat)"
fi

# --- M3 fix verification: firstboot uses rpm -q, not dnf repolist -----------
# The script header references "dnf repolist --enabled" in the M3 rationale
# comment. Check for ACTUAL command invocation (not grep pattern in comment)
# by requiring the rpm -q call lines + absence of `if ! dnf repolist` control
# flow (the old parsing mechanism).
assert_grep_fixed 'rpm -q rpmfusion-free-release'    "$TMPDIR/firstboot.sh"
assert_grep_fixed 'rpm -q rpmfusion-nonfree-release' "$TMPDIR/firstboot.sh"
assert_grep_fixed 'rpmfusion_free_configured()' "$TMPDIR/firstboot.sh" \
    "RPM Fusion free is evaluated at its dependent tasks"
assert_grep_fixed 'rpmfusion_nonfree_configured()' "$TMPDIR/firstboot.sh" \
    "RPM Fusion nonfree is evaluated only for applicable Intel work"
assert_grep_fixed 'cisco_openh264_configured()' "$TMPDIR/firstboot.sh" \
    "Cisco OpenH264 is evaluated at Task 2"
assert_not_grep 'need_rf_nonfree' "$TMPDIR/firstboot.sh" \
    "an unrelated missing nonfree repository cannot abort all codec tasks"
if grep -qE '^\s*if ! dnf repolist --enabled' "$TMPDIR/firstboot.sh"; then
    _fail "M3 regression: dnf repolist parsing still in use (should be rpm -q)"
else
    _pass "M3 fix verified: no human-formatted dnf repolist parsing"
fi

# --- firstboot orchestrates 3 tasks (system codecs + OpenH264 + GPU driver) ---
# minimalist: dropped old Task 2 (unrar from RPM Fusion nonfree)
# and old Task 3 (p7zip-plugins from RPM Fusion) — replaced by FOSS Fedora-main
# alternatives `unar` + `7zip` shipped at build-time in M26. Renumbered the
# H.264 codec task from Task 4 to Task 2.
# NEW Task 3 = GPU-vendor-conditional codec-driver swap
# (Intel: intel-media-driver from rpmfusion-nonfree; AMD: mesa-va-drivers-
# freeworld from rpmfusion-free; NVIDIA: log-only, manual via M19 setup).
# (H264/HEVC HW-decode enable).
assert_grep_fixed 'Task 1: FFmpeg + GStreamer codec completion' "$TMPDIR/firstboot.sh"
assert_grep_fixed 'Task 2: H.264 codec install' "$TMPDIR/firstboot.sh"
assert_grep_fixed 'Task 3: GPU multi-vendor codec-driver swap' "$TMPDIR/firstboot.sh"
assert_grep_fixed 'rpm -q ffmpeg gstreamer1-plugins-bad-freeworld' \
    "$TMPDIR/firstboot.sh" \
    "Task 1 completion requires both FFmpeg and GStreamer software codecs"
assert_grep_fixed 'dnf install -y gstreamer1-plugins-bad-freeworld' \
    "$TMPDIR/firstboot.sh" \
    "Task 1 installs the GStreamer H.265 software decoder path"
assert_not_grep 'ZERO patent-encumbered' "$KS_FILE" \
    "codec policy avoids a jurisdiction-independent patent claim"
assert_not_grep_extended 'all open.source|no proprietary blobs|All installed binaries are open.source' \
    "$KS_FILE" "codec policy does not overclaim the Intel full-feature media driver"
assert_not_grep_extended 'EU-enforceable patents|Cross-browser/cross-GPU 2026 reality|Linux only gets Widevine L3|stay CPU-decoded' \
    "$KS_FILE" "codec policy carries no universal legal or protected-media claim"
assert_grep_fixed 'browser/CDM and streaming service' "$KS_FILE" \
    "protected-media limits are scoped to the actual browser/CDM/service boundary"
assert_grep_fixed 'closed-source media-kernel/shader binaries' "$KS_FILE" \
    "Intel full-feature media-driver trust trade-off is named"
assert_grep_fixed 'oh264_pkgs="openh264 mozilla-openh264 gstreamer1-plugin-openh264"' \
    "$TMPDIR/firstboot.sh" \
    "OpenH264 transaction guarantees both Mozilla and GStreamer bridges"
assert_grep_fixed '&& oh264_postcondition' "$TMPDIR/firstboot.sh" \
    "OpenH264 replay rechecks every package in the transaction"
assert_grep_fixed 'rather than relying on' "$KS_FILE" \
    "GStreamer H.264 coverage does not depend on weak-dependency policy"
assert_grep_fixed 'builds and signs the OpenH264 RPMs' "$KS_FILE" \
    "OpenH264 repository boundary names the Fedora build and signature owner"
assert_grep_fixed 'then Cisco distributes those exact' "$KS_FILE" \
    "OpenH264 repository boundary names the required distributor"
assert_not_grep 'Cisco-CDN' "$KS_FILE" \
    "OpenH264 provenance is not collapsed into an ambiguous CDN label"
assert_eq 3 "$(grep -cF 'Repository metadata and package-signature boundary' \
    "$KS_FILE" || true)" \
    "OpenH264 metadata exception points only at the canonical threat-model section"
assert_not_grep 'TM-R6' "$KS_FILE" \
    "OpenH264 metadata exception has no reference to a nonexistent threat ID"
assert_not_grep 'predates Fedora metadata-signing' "$KS_FILE" \
    "OpenH264 metadata exception states the observed endpoint capability"
assert_not_grep 'ffmpeg + unrar + p7zip-plugins' "$KS_FILE" \
    "Step 9 summary matches the current three codec tasks"
# multi-vendor parallel processing flags (Intel/AMD/NVIDIA all checked)
assert_grep_fixed 'intel_gpu=1' "$TMPDIR/firstboot.sh"
assert_grep_fixed 'amd_gpu=1' "$TMPDIR/firstboot.sh"
assert_grep_fixed 'nvidia_gpu=1' "$TMPDIR/firstboot.sh"
# nouveau-vs-proprietary distinction via lsmod
assert_grep_extended '^[[:space:]]*if lsmod 2>/dev/null \| grep -qE "\^nouveau "' "$TMPDIR/firstboot.sh"
assert_grep_extended '^[[:space:]]*elif lsmod 2>/dev/null \| grep -qE "\^nvidia "' "$TMPDIR/firstboot.sh"
# Task 3 Intel branch must use canonical dnf swap pattern
assert_grep_fixed 'dnf swap -y libva-intel-media-driver intel-media-driver --allowerasing' "$TMPDIR/firstboot.sh"
# Freeworld is an AMD-only codec opt-in. A mere NVIDIA PCI identity, Nouveau or
# an unbound device must never add the tightly Mesa-version-coupled package.
assert_grep_fixed 'dnf install -y mesa-va-drivers-freeworld' "$TMPDIR/firstboot.sh"
assert_eq "1" "$(grep -cF 'dnf install -y mesa-va-drivers-freeworld' "$TMPDIR/firstboot.sh")" \
    "mesa-va-drivers-freeworld install exists only in the AMD branch"
sed -n '/^# --- NVIDIA vendor branch/,/^# A codec package/p' \
    "$TMPDIR/firstboot.sh" > "$TMPDIR/firstboot-nvidia-codec.block"
assert_not_grep 'dnf install' "$TMPDIR/firstboot-nvidia-codec.block" \
    "NVIDIA codec selection never mutates packages"
assert_not_grep 'mesa-va-drivers-freeworld' "$TMPDIR/firstboot-nvidia-codec.block" \
    "NVIDIA codec selection never claims the AMD Freeworld package"
assert_grep_fixed 'no active driver — no codec package selected from hardware identity alone' \
    "$TMPDIR/firstboot-nvidia-codec.block" \
    "unbound NVIDIA hardware is not treated as a future Nouveau proof"
# NVIDIA proprietary branch is log-only (software video decode, no helper)
assert_grep_fixed 'software video decode (no sandbox-weakening helper)' "$TMPDIR/firstboot.sh"
# Task 3 result accounting (single-task counter, not per-vendor)
assert_grep_fixed 't3_any_attempted=0' "$TMPDIR/firstboot.sh"
assert_grep_fixed 't3_any_failed=0' "$TMPDIR/firstboot.sh"
assert_grep_fixed 'if ! command -v lspci >/dev/null 2>&1; then' \
    "$TMPDIR/firstboot.sh" \
    "GPU task distinguishes an unavailable inventory tool from no hardware"
assert_grep_fixed 'elif ! gpu_inventory=$(lspci -nn 2>/dev/null); then' \
    "$TMPDIR/firstboot.sh" \
    "GPU task treats an lspci execution failure as a failed probe"
assert_grep_fixed 'if [ "$gpu_probe_ok" != "1" ]; then' \
    "$TMPDIR/firstboot.sh" \
    "GPU task cannot seal a failed hardware inventory as headless success"
# Summary line bumped to 3 tasks
assert_grep_fixed 'all 3 tasks OK' "$TMPDIR/firstboot.sh"
assert_grep_fixed 'Task 3: FAIL dynamic-linker cache refresh' "$TMPDIR/firstboot.sh" \
    "ldconfig failure participates in codec task result"
assert_not_grep 'ldconfig.*[|][|][[:space:]]*true' "$TMPDIR/firstboot.sh" \
    "ldconfig failure is not swallowed"
assert_cmd_success "firstboot codec helper is valid bash" bash -n "$TMPDIR/firstboot.sh"
assert_grep_fixed 'noid-firstboot-setup: must run as root' "$TMPDIR/firstboot.sh" \
    "codec transaction has an explicit root boundary"
if [ "$(id -u)" -ne 0 ]; then
    assert_cmd_failure "unprivileged codec helper exits before touching system state" \
        bash "$TMPDIR/firstboot.sh"
else
    _pass "root test run never executes the unredirected codec transaction"
fi
assert_grep_extended '^NoNewPrivileges=no$' "$TMPDIR/firstboot.service" \
    "RPM scriptlets retain their SELinux domain-transition capability"
assert_not_grep '^NoNewPrivileges=yes$' "$TMPDIR/firstboot.service" \
    "codec transaction does not block rpm_script_t with no_new_privs"
cp "$TMPDIR/firstboot.service" "$TMPDIR/codec-verify.service"
sed -i 's|^ExecStart=.*|ExecStart=/usr/bin/true|' "$TMPDIR/codec-verify.service"
assert_cmd_success "codec service passes the native systemd unit verifier" \
    systemd-analyze verify "$TMPDIR/codec-verify.service"
assert_grep_fixed 'UMask=0077' "$TMPDIR/firstboot.service" \
    "codec transaction creates private scratch and log files by default"
assert_grep_fixed 'DNF=/usr/bin/dnf' "$TMPDIR/firstboot.sh" \
    "codec transaction binds package mutations to Fedora's native DNF path"
assert_grep_fixed '( umask 022; "$DNF" "$@" )' "$TMPDIR/firstboot.sh" \
    "codec DNF wrapper scopes public metadata permissions to package work"
assert_grep_fixed 'TASK1_UNNEEDED_BASELINE="$STATE_DIR/task1-unneeded-before.list"' \
    "$TMPDIR/firstboot.sh" \
    "codec swap persists its pre-existing unneeded-package boundary"
assert_grep_fixed 'TASK1_REPLACED_CLOSURE="$STATE_DIR/task1-replaced-closure.list"' \
    "$TMPDIR/firstboot.sh" \
    "codec swap persists the replaced package dependency closure"
assert_grep_fixed 'LC_ALL=C comm -13 "$TASK1_UNNEEDED_BASELINE" "$post_set" > "$new_set"' \
    "$TMPDIR/firstboot.sh" \
    "codec cleanup derives only packages newly classified unneeded"
assert_grep_fixed 'LC_ALL=C comm -12 "$new_set" "$TASK1_REPLACED_CLOSURE" > "$owned_set"' \
    "$TMPDIR/firstboot.sh" \
    "codec cleanup intersects new orphans with the replaced stack"
assert_grep_fixed 'run_system_dnf --cacheonly --assumeyes remove --no-autoremove' \
    "$TMPDIR/firstboot.sh" \
    "codec cleanup removes only its exact owned set without recursive autoremove"
assert_not_grep 'run_system_dnf.*[[:space:]]autoremove' "$TMPDIR/firstboot.sh" \
    "codec opt-in never launches a global autoremove transaction"
assert_eq 11 \
    "$(grep -cE '^[[:space:]]*run_system_dnf[[:space:]]+(install|reinstall|swap)[[:space:]]' \
        "$TMPDIR/firstboot.sh")" \
    "all eleven codec package transactions use the scoped DNF wrapper"
assert_eq 0 \
    "$(grep -cE '^[[:space:]]*dnf[[:space:]]+(install|reinstall|swap)[[:space:]]' \
        "$TMPDIR/firstboot.sh" || true)" \
    "codec helper has no package transaction outside the scoped DNF wrapper"
assert_grep_fixed 'UnsetEnvironment=BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME' \
    "$TMPDIR/firstboot.service" \
    "codec transaction removes interpreter injection variables before exec"
# This invariant is deliberately helper-specific. The privileged codec
# transaction has no test seam; the VSCodium user service strips every
# NOID_TEST_* variable, while the adapter helper is user-scoped and its seam
# can redirect only that user's own files.
assert_not_grep 'NOID_TEST_MODE' "$TMPDIR/firstboot.sh" \
    "installed codec transaction has no caller-controlled test bypass"
assert_grep_fixed \
    'UnsetEnvironment=NOID_TEST_MODE NOID_TEST_KEY_FILE NOID_TEST_FINGERPRINT NOID_TEST_KEY_ID NOID_TEST_REPO_DIR NOID_TEST_STATE_DIR' \
    "$TMPDIR/vscodium-user-key-seed.service" \
    "VSCodium user service strips every fixture override"
assert_grep_fixed 'STATE_DIR="/var/lib/noid-privacy/firstboot-setup"' "$TMPDIR/firstboot.sh" \
    "partial codec transactions retain task-scoped clean receipts"
assert_grep_fixed 'valid_empty_receipt "$receipt"' "$TMPDIR/firstboot.sh" \
    "clean transaction receipts require exact owner, mode, link count and size"
assert_grep_fixed 'mv -fT -- "$candidate" "$receipt"' "$TMPDIR/firstboot.sh" \
    "task receipts are published atomically without following a symlink"
assert_not_grep 'touch "$FLAG_FILE"' "$TMPDIR/firstboot.sh" \
    "global codec completion never follows a pre-created symlink"
assert_grep_fixed 'mv -fT -- "$candidate" "$FLAG_FILE"' "$TMPDIR/firstboot.sh" \
    "global codec completion receipt is published atomically"
for rc_guard in task1_scope_rc task1_ffmpeg_rc task1_gstreamer_rc \
        task1_cleanup_rc install_rc \
        intel_swap_rc intel_install_rc amd_install_rc; do
    assert_grep_fixed "[ \"\$$rc_guard\" -eq 0 ]" "$TMPDIR/firstboot.sh" \
        "successful package postcondition also requires $rc_guard=0"
done
assert_grep_fixed 'run_system_dnf reinstall -y ffmpeg gstreamer1-plugins-bad-freeworld' \
    "$TMPDIR/firstboot.sh" \
    "receipt-less system codec state replays both Task 1 packages"
for repair_pkg in '$oh264_pkgs' intel-media-driver mesa-va-drivers-freeworld; do
    assert_grep_fixed "run_system_dnf reinstall -y $repair_pkg" \
        "$TMPDIR/firstboot.sh" \
        "receipt-less desired state replays $repair_pkg scriptlets"
done
assert_not_grep 'Trust rpm -q post-condition over dnf exit code' "$TMPDIR/firstboot.sh" \
    "DNF transaction errors are never relabeled as success"
assert_grep_fixed 'run_system_dnf install -y intel-media-driver' \
    "$TMPDIR/firstboot.sh" \
    "missing Intel baseline is repaired with the full desired driver"
assert_not_grep 'libva-intel-media-driver not installed, nothing to swap' \
    "$TMPDIR/firstboot.sh" \
    "missing Intel drivers cannot be sealed as a successful codec task"

# Runtime regression: RPM can expose the requested package after a scriptlet
# failure because it cannot roll the transaction back. The first run must stay
# failed and leave no clean receipt; the next explicit run must replay only
# that incomplete task while retaining receipts for clean sibling tasks.
RUNTIME_ROOT="$TMPDIR/firstboot-runtime"
mkdir -p "$RUNTIME_ROOT"
chmod 0755 "$RUNTIME_ROOT"
cp "$TMPDIR/firstboot.sh" "$RUNTIME_ROOT/firstboot.sh"
runtime_uid=$(id -u)
runtime_gid=$(id -g)
sed -i \
    -e "s|^FLAG_FILE=.*|FLAG_FILE=\"$RUNTIME_ROOT/done.flag\"|" \
    -e "s|^LOG_FILE=.*|LOG_FILE=\"$RUNTIME_ROOT/firstboot.log\"|" \
    -e "s|^STATE_DIR=.*|STATE_DIR=\"$RUNTIME_ROOT/state\"|" \
    -e 's|^if \[ "$(id -u)" -ne 0 \]; then$|if false; then|' \
    -e "s|^EXPECTED_UID=0$|EXPECTED_UID=$runtime_uid|" \
    -e "s|^EXPECTED_GID=0$|EXPECTED_GID=$runtime_gid|" \
    -e 's|^DNF=/usr/bin/dnf$|DNF=dnf|' \
    "$RUNTIME_ROOT/firstboot.sh"
export DNF_CALL_LOG="$RUNTIME_ROOT/dnf.calls"
export DNF_UMASK_LOG="$RUNTIME_ROOT/dnf.umasks"
export DNF_FAIL_ONCE_MARKER="$RUNTIME_ROOT/ffmpeg.failed-once"
# shellcheck disable=SC2317,SC2329
rpm() {
    [ "${1:-}" = "-q" ] || return 2
    shift
    for pkg in "$@"; do
        case "$pkg" in
            ffmpeg-free|libva-intel-media-driver) return 1 ;;
            rpmfusion-free-release|rpmfusion-nonfree-release|ffmpeg|gstreamer1-plugins-bad-freeworld|openh264|mozilla-openh264|gstreamer1-plugin-openh264|intel-media-driver) ;;
            *) return 1 ;;
        esac
    done
}
# shellcheck disable=SC2317,SC2329
dnf() {
    printf '%s\n' "$*" >> "$DNF_CALL_LOG"
    umask >> "$DNF_UMASK_LOG"
    if [ "$*" = "reinstall -y ffmpeg gstreamer1-plugins-bad-freeworld" ] \
            && [ ! -e "$DNF_FAIL_ONCE_MARKER" ]; then
        : > "$DNF_FAIL_ONCE_MARKER"
        return 1
    fi
    return 0
}
# shellcheck disable=SC2317,SC2329
lspci() {
    printf '%s\n' '00:02.0 VGA compatible controller: Intel Corporation fixture GPU'
}
# shellcheck disable=SC2317,SC2329
lsmod() { return 0; }
# shellcheck disable=SC2317,SC2329
ldconfig() { return 0; }
export -f rpm dnf lspci lsmod ldconfig
assert_cmd_failure "scriptlet-error fixture stays failed despite desired RPM state" \
    bash "$RUNTIME_ROOT/firstboot.sh"
assert_cmd_failure "failed transaction cannot seal global codec completion" \
    test -e "$RUNTIME_ROOT/done.flag"
assert_cmd_failure "failed ffmpeg transaction has no clean receipt" \
    test -e "$RUNTIME_ROOT/state/task1-ffmpeg.ok"
assert_file_exists "$RUNTIME_ROOT/state/task2-openh264.ok" \
    "clean OpenH264 sibling transaction retains its receipt"
assert_file_exists "$RUNTIME_ROOT/state/task3-intel-media.ok" \
    "clean Intel sibling transaction retains its receipt"
assert_cmd_success "explicit retry replays and seals the incomplete transaction" \
    bash "$RUNTIME_ROOT/firstboot.sh"
assert_file_exists "$RUNTIME_ROOT/done.flag" \
    "clean retry seals global codec completion"
assert_eq 600 "$(stat -c %a "$RUNTIME_ROOT/done.flag")" \
    "global codec completion receipt is private"
assert_file_exists "$RUNTIME_ROOT/state/task1-ffmpeg.ok" \
    "clean retry creates the ffmpeg receipt"
assert_eq 2 "$(grep -cFx 'reinstall -y ffmpeg gstreamer1-plugins-bad-freeworld' "$DNF_CALL_LOG")" \
    "failed system-codec transaction is replayed exactly once"
assert_eq 1 "$(grep -cFx 'reinstall -y openh264 mozilla-openh264 gstreamer1-plugin-openh264' "$DNF_CALL_LOG")" \
    "clean OpenH264 transaction is not replayed"
assert_eq 1 "$(grep -cFx 'reinstall -y intel-media-driver' "$DNF_CALL_LOG")" \
    "clean Intel transaction is not replayed"
assert_eq 0022 "$(sort -u "$DNF_UMASK_LOG")" \
    "every codec DNF transaction receives only the public metadata umask"

# A failed PCI inventory is not a headless-machine result and must never
# publish the durable all-tasks receipt, even when earlier task receipts are
# already clean.
rm -f "$RUNTIME_ROOT/done.flag"
# This exported fixture override is invoked by the child firstboot script.
# shellcheck disable=SC2317,SC2329
lspci() { return 1; }
export -f lspci
assert_cmd_failure "failed lspci probe cannot seal codec completion" \
    bash "$RUNTIME_ROOT/firstboot.sh"
assert_cmd_failure "failed lspci probe leaves no global codec receipt" \
    test -e "$RUNTIME_ROOT/done.flag"
assert_grep_fixed 'Task 3: FAIL lspci inventory query failed' \
    "$RUNTIME_ROOT/firstboot.log" \
    "failed GPU inventory is diagnosed distinctly from a headless host"
# This replacement is likewise exported for subsequent child invocations.
# shellcheck disable=SC2317,SC2329
lspci() {
    printf '%s\n' '00:02.0 VGA compatible controller: Intel Corporation fixture GPU'
}
export -f lspci

outside_flag="$RUNTIME_ROOT/outside.flag"
printf '%s\n' 'must remain untouched' > "$outside_flag"
rm -f "$RUNTIME_ROOT/done.flag"
ln -s "$outside_flag" "$RUNTIME_ROOT/done.flag"
calls_before=$(wc -l < "$DNF_CALL_LOG")
assert_cmd_failure "unsafe global codec receipt is rejected before package work" \
    bash "$RUNTIME_ROOT/firstboot.sh"
assert_eq "$calls_before" "$(wc -l < "$DNF_CALL_LOG")" \
    "unsafe global receipt causes no DNF transaction"
assert_eq 'must remain untouched' "$(cat "$outside_flag")" \
    "unsafe global receipt target is never modified"

rm -f "$RUNTIME_ROOT/done.flag"
rm -rf "$RUNTIME_ROOT/state"
outside_state="$RUNTIME_ROOT/outside-state"
mkdir "$outside_state"
ln -s "$outside_state" "$RUNTIME_ROOT/state"
calls_before=$(wc -l < "$DNF_CALL_LOG")
assert_cmd_failure "symlinked codec task-state directory is rejected" \
    bash "$RUNTIME_ROOT/firstboot.sh"
assert_eq "$calls_before" "$(wc -l < "$DNF_CALL_LOG")" \
    "unsafe task-state directory causes no DNF transaction"
assert_eq 0 "$(find "$outside_state" -mindepth 1 -maxdepth 1 | wc -l)" \
    "codec helper never traverses a symlinked task-state directory"
unset -f rpm dnf lspci lsmod ldconfig
unset DNF_CALL_LOG DNF_UMASK_LOG DNF_FAIL_ONCE_MARKER

# Runtime regression: a successful ffmpeg-free replacement can make packages
# from the old dependency closure newly eligible for autoremove. The helper
# must preserve an unrelated pre-existing orphan, remove only its own delta,
# and retain enough private state to retry a failed scoped removal.
ORPHAN_ROOT="$TMPDIR/firstboot-orphan-runtime"
mkdir -p "$ORPHAN_ROOT"
chmod 0755 "$ORPHAN_ROOT"
cp "$TMPDIR/firstboot.sh" "$ORPHAN_ROOT/firstboot.sh"
sed -i \
    -e "s|^FLAG_FILE=.*|FLAG_FILE=\"$ORPHAN_ROOT/done.flag\"|" \
    -e "s|^LOG_FILE=.*|LOG_FILE=\"$ORPHAN_ROOT/firstboot.log\"|" \
    -e "s|^STATE_DIR=.*|STATE_DIR=\"$ORPHAN_ROOT/state\"|" \
    -e 's|^if \[ "$(id -u)" -ne 0 \]; then$|if false; then|' \
    -e "s|^EXPECTED_UID=0$|EXPECTED_UID=$runtime_uid|" \
    -e "s|^EXPECTED_GID=0$|EXPECTED_GID=$runtime_gid|" \
    -e 's|^DNF=/usr/bin/dnf$|DNF=dnf|' \
    -e "s|\[ -f /etc/yum.repos.d/fedora-cisco-openh264.repo \]|[ -f $ORPHAN_ROOT/fedora-cisco-openh264.repo ]|" \
    "$ORPHAN_ROOT/firstboot.sh"
: > "$ORPHAN_ROOT/fedora-cisco-openh264.repo"
export ORPHAN_DNF_CALL_LOG="$ORPHAN_ROOT/dnf.calls"
export ORPHAN_DNF_UMASK_LOG="$ORPHAN_ROOT/dnf.umasks"
export ORPHAN_SWAPPED="$ORPHAN_ROOT/ffmpeg-swapped"
export ORPHAN_GSTREAMER="$ORPHAN_ROOT/gstreamer-installed"
export ORPHAN_REMOVE_FAILED="$ORPHAN_ROOT/remove-failed-once"
export ORPHAN_OLD_REMOVED="$ORPHAN_ROOT/old-codec-dep-removed"
# shellcheck disable=SC2317,SC2329
rpm() {
    [ "${1:-}" = "-q" ] || return 2
    shift
    for pkg in "$@"; do
        case "$pkg" in
            ffmpeg-free)
                [ ! -e "$ORPHAN_SWAPPED" ] || return 1
                ;;
            ffmpeg)
                [ -e "$ORPHAN_SWAPPED" ] || return 1
                ;;
            gstreamer1-plugins-bad-freeworld)
                [ -e "$ORPHAN_GSTREAMER" ] || return 1
                ;;
            old-codec-dep)
                [ ! -e "$ORPHAN_OLD_REMOVED" ] || return 1
                ;;
            libva-intel-media-driver)
                return 1
                ;;
            rpmfusion-free-release|rpmfusion-nonfree-release|openh264|\
            mozilla-openh264|gstreamer1-plugin-openh264|intel-media-driver)
                ;;
            *)
                return 1
                ;;
        esac
    done
}
# shellcheck disable=SC2317,SC2329
dnf() {
    printf '%s\n' "$*" >> "$ORPHAN_DNF_CALL_LOG"
    umask >> "$ORPHAN_DNF_UMASK_LOG"
    if [ "${1:-}" = "-q" ] && [ "${2:-}" = "--cacheonly" ] \
            && [ "${3:-}" = "repoquery" ] \
            && [ "${4:-}" = "--unneeded" ]; then
        printf '%s\n' unrelated-orphan
        if [ -e "$ORPHAN_SWAPPED" ] && [ ! -e "$ORPHAN_OLD_REMOVED" ]; then
            printf '%s\n' old-codec-dep
        fi
        return 0
    fi
    if [ "${1:-}" = "-q" ] && [ "${2:-}" = "--cacheonly" ] \
            && [ "${3:-}" = "repoquery" ] \
            && [ "${4:-}" = "--installed" ] \
            && [ "${5:-}" = "--providers-of=requires" ] \
            && [ "${6:-}" = "--recursive" ] \
            && [ "${7:-}" = "ffmpeg-free" ]; then
        printf '%s\n' old-codec-dep
        return 0
    fi
    case "$*" in
        'swap -y ffmpeg-free ffmpeg --allowerasing')
            : > "$ORPHAN_SWAPPED"
            ;;
        'install -y gstreamer1-plugins-bad-freeworld')
            : > "$ORPHAN_GSTREAMER"
            ;;
        '--cacheonly --assumeyes remove --no-autoremove old-codec-dep')
            if [ ! -e "$ORPHAN_REMOVE_FAILED" ]; then
                : > "$ORPHAN_REMOVE_FAILED"
                return 1
            fi
            : > "$ORPHAN_OLD_REMOVED"
            ;;
    esac
    return 0
}
# shellcheck disable=SC2317,SC2329
lspci() {
    printf '%s\n' '00:02.0 VGA compatible controller: Intel Corporation fixture GPU'
}
# shellcheck disable=SC2317,SC2329
lsmod() { return 0; }
# shellcheck disable=SC2317,SC2329
ldconfig() { return 0; }
export -f rpm dnf lspci lsmod ldconfig

assert_cmd_failure "failed scoped codec-orphan removal stays retryable" \
    bash "$ORPHAN_ROOT/firstboot.sh"
assert_cmd_failure "failed scoped cleanup cannot seal Task 1" \
    test -e "$ORPHAN_ROOT/state/task1-ffmpeg.ok"
assert_file_exists "$ORPHAN_ROOT/state/task1-unneeded-before.list" \
    "failed cleanup retains the pre-swap unneeded boundary"
assert_file_exists "$ORPHAN_ROOT/state/task1-replaced-closure.list" \
    "failed cleanup retains the replaced dependency closure"
assert_eq unrelated-orphan \
    "$(cat "$ORPHAN_ROOT/state/task1-unneeded-before.list")" \
    "pre-existing unrelated orphan remains outside the owned delta"
assert_eq old-codec-dep \
    "$(cat "$ORPHAN_ROOT/state/task1-replaced-closure.list")" \
    "replacement scope is bound to the old dependency closure"
assert_cmd_success "explicit retry completes the exact codec-orphan cleanup" \
    bash "$ORPHAN_ROOT/firstboot.sh"
assert_file_exists "$ORPHAN_ROOT/state/task1-ffmpeg.ok" \
    "successful scoped cleanup permits the Task 1 receipt"
assert_file_exists "$ORPHAN_ROOT/done.flag" \
    "successful retry permits global codec completion"
assert_file_exists "$ORPHAN_OLD_REMOVED" \
    "retry removes the old codec dependency"
assert_cmd_failure "successful cleanup retires the pre-swap baseline" \
    test -e "$ORPHAN_ROOT/state/task1-unneeded-before.list"
assert_cmd_failure "successful cleanup retires the old dependency closure" \
    test -e "$ORPHAN_ROOT/state/task1-replaced-closure.list"
assert_eq 2 \
    "$(grep -cFx -- '--cacheonly --assumeyes remove --no-autoremove old-codec-dep' \
        "$ORPHAN_DNF_CALL_LOG")" \
    "scoped removal is retried exactly once"
assert_not_grep 'remove.*unrelated-orphan' "$ORPHAN_DNF_CALL_LOG" \
    "pre-existing unrelated orphan is never passed to package removal"
assert_eq 0022 "$(sort -u "$ORPHAN_DNF_UMASK_LOG")" \
    "codec queries and scoped removal preserve public DNF metadata modes"
unset -f rpm dnf lspci lsmod ldconfig
unset ORPHAN_DNF_CALL_LOG ORPHAN_DNF_UMASK_LOG ORPHAN_SWAPPED \
    ORPHAN_GSTREAMER ORPHAN_REMOVE_FAILED ORPHAN_OLD_REMOVED

# --- dconf + Flathub + RPM Fusion in source ---------------------------------
assert_grep_fixed 'dnf5daemon-server'                   "$KS_FILE"
assert_grep_fixed '/etc/dconf/db/distro.d/00-noid-gnome-software' "$KS_FILE"
assert_not_grep_extended 'flatpak[[:space:]]+remote-add' "$KS_FILE" \
    "M08 never provisions a Flatpak remote by name; M18 owns trust reconciliation"
assert_grep_fixed 'Flatpak remote provisioning delegated exclusively to Module 18' "$KS_FILE"
assert_grep_fixed 'rpmfusion-free-release-44.noarch.rpm'    "$KS_FILE"
assert_grep_fixed 'rpmfusion-nonfree-release-44.noarch.rpm' "$KS_FILE"
assert_grep_fixed 'E9A491A3DE247814E7E067EAE06F8ECDD651FF2E' "$KS_FILE" \
    "RPM Fusion free full signing-key fingerprint is pinned"
assert_grep_fixed '79BDB88F9BBF73910FD4095B6A2AF96194843C65' "$KS_FILE" \
    "RPM Fusion nonfree full signing-key fingerprint is pinned"
assert_grep_fixed 'gpg --batch --show-keys --with-colons' "$KS_FILE" \
    "embedded RPM key is independently fingerprint-checked"
assert_grep_fixed 'primary_count=$(awk -F:' "$KS_FILE" \
    "key validation requires exactly one primary OpenPGP key"
assert_grep_fixed 'rpmkeys -Kv "$rpm_path"' "$KS_FILE" \
    "release RPM signature is checked before installation"
assert_grep_fixed "--proto '=https' --proto-redir '=https' --tlsv1.2" "$KS_FILE" \
    "external repository bootstrap redirects remain HTTPS-only"
assert_grep_fixed 'extract_dir=$(mktemp -d "/var/tmp/rpmfusion-${repo}-extract.XXXXXX")' \
    "$KS_FILE" "RPM Fusion extraction uses unique disk-backed private scratch"
# The RPM is still unauthenticated when it is opened -- both the fingerprint
# gate and the rpmkeys check need the key this extraction produces. GNU cpio
# honours absolute member names in copy-in mode, so a hostile payload could
# write outside the scratch tree as root before any verification ran. GNU tar
# strips leading slashes and refuses ".." members, rpm2archive verifies the
# per-file checksums cpio ignores, and only the key path is extracted at all.
assert_grep_fixed 'rpm2archive -n "${rpm_path}"' "$KS_FILE" \
    "unverified release RPM is opened with the maintained extractor"
assert_not_grep 'rpm2cpio "\${rpm_path}"' "$KS_FILE" \
    "the obsolete cpio extractor no longer opens an unverified payload"
assert_grep_fixed "--wildcards './etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-*'" "$KS_FILE" \
    "extraction is narrowed to the signing-key path"
assert_grep_fixed '--no-same-owner --no-same-permissions' "$KS_FILE" \
    "an unverified archive cannot choose ownership or modes"
assert_grep_fixed 'RPM-GPG-KEY-rpmfusion-${repo}-fedora-2020' "$KS_FILE" \
    "RPM Fusion verifies the regular key payload behind releasever symlinks"
assert_grep_fixed 'base=${path#/var/tmp/}' "$KS_FILE" \
    "RPM Fusion cleanup validates every scratch path against /var/tmp"
assert_grep_fixed 'base##*/' "$KS_FILE" \
    "RPM Fusion cleanup rejects nested or escaped scratch paths"
assert_not_grep 'release packages will install at first-boot' "$KS_FILE" \
    "fallback repository files are not misdescribed as release-package auto-installers"
assert_grep_fixed 'rpm --import "$key_src"' "$KS_FILE" \
    "verified RPM Fusion keys are imported from the extraction tree"
assert_not_grep 'rpm --import "$key_dst"' "$KS_FILE" \
    "trust bootstrap does not pre-create an RPM-owned key path"
assert_grep_fixed 'install_rf_fallback_key free "$RPMFUSION_FREE_FPR"' "$KS_FILE" \
    "manual key publication is confined to the repository fallback path"
assert_grep_fixed 'install_rf_fallback_key nonfree "$RPMFUSION_NONFREE_FPR"' "$KS_FILE" \
    "both fallback repositories receive their independently pinned key"
assert_not_grep 'rpm --import.*[|][|][[:space:]]*true' "$KS_FILE" \
    "RPM key-import failure is never swallowed"
assert_not_grep 'fetch_rf_keys.*[|][|][[:space:]]*true' "$KS_FILE" \
    "RPM Fusion trust bootstrap cannot fall through on failure"
assert_not_grep '="/tmp/rpmfusion-' "$KS_FILE" \
    "RPM Fusion package work does not use the target noexec tmpfs"
assert_not_grep 'dconf update.*[|][|][[:space:]]*true' "$KS_FILE" \
    "dconf compilation failure is not swallowed"
assert_not_grep 'mandatory Flathub remote could not be added' "$KS_FILE" \
    "M08 has no stale name-only Flathub failure path"
assert_grep_fixed 'COUNTME_REMAINING countme=1 lines remain (privacy invariant violated)' "$KS_FILE" \
    "surviving Fedora countme telemetry aborts the build"
assert_grep_fixed 'maintained HTTPS metalinks' "$KS_FILE" \
    "RPM Fusion stays on its package-maintained mirror selection"
assert_not_grep 'ftp-stud.hs-esslingen.de' "$KS_FILE" \
    "NoID Privacy carries no aging hardcoded RPM Fusion mirror inventory"

# --- VSCodium trust bootstrap + mandatory package invariant ---------------
assert_grep_fixed '1302DE60231889FE1EBACADC54678CF75A278D9C' "$KS_FILE" \
    "VSCodium full signing-key fingerprint is pinned"
assert_grep_fixed 'install -Dm0644 -o root -g root "$KEY_TMP" "$VSCODIUM_KEY_LOCAL"' "$KS_FILE" \
    "verified VSCodium key is persisted locally"
assert_grep_fixed 'gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-vscodium' "$KS_FILE" \
    "VSCodium repo never follows a mutable remote key URL"
assert_grep_fixed 'VSCODIUM_RPM_SIG=$(rpmkeys -Kv "$TMP_RPM" 2>&1)' "$KS_FILE" \
    "pre-staged VSCodium RPM signature is explicitly verified"
assert_grep_fixed 'TMP_RPM=$(mktemp /var/tmp/vscodium-pre-staged.XXXXXX.rpm)' \
    "$KS_FILE" "large VSCodium payload uses unique disk-backed scratch"
assert_grep_fixed "--proto '=http' --proto-redir '=http'" "$KS_FILE" \
    "local VSCodium staging is confined to the builder HTTP protocol"
assert_grep_fixed '--max-redirs 0 --connect-timeout 5 --max-time 60' "$KS_FILE" \
    "local VSCodium RPM fetch rejects redirects and is time-bounded"
assert_grep_fixed 'codium is mandatory but was not installed' "$KS_FILE" \
    "missing codium aborts the image build"
assert_grep_fixed 'python3-libdnf5' "$KS_FILE" \
    "native DNF5 repository-cache API is an explicit image dependency"
assert_not_grep 'build-time-skipped' "$KS_FILE" \
    "mandatory codium cannot be silently deferred"
assert_cmd_success "VSCodium per-user key helper parses" \
    bash -n "$TMPDIR/vscodium-user-key-seed"
assert_grep_fixed 'EXPECTED_FINGERPRINT=1302DE60231889FE1EBACADC54678CF75A278D9C' \
    "$TMPDIR/vscodium-user-key-seed" \
    "per-user metadata trust is pinned to the reviewed full fingerprint"
assert_grep_fixed 'base.get_repo_sack().create_repos_from_system_configuration()' \
    "$TMPDIR/vscodium-user-key-seed" \
    "per-user seed resolves the opaque cache path through native libdnf5"
assert_grep_fixed 'if len(repos) == 0 or not repos[0].is_enabled():' \
    "$TMPDIR/vscodium-user-key-seed" \
    "disabled or absent VSCodium repo is a supported no-op"
assert_grep_fixed 'if [[ $repo_dir == NOID_VSCODIUM_REPO_DISABLED ]]; then' \
    "$TMPDIR/vscodium-user-key-seed" \
    "disabled repo never blocks unrelated DNF operations"
assert_grep_fixed 'home=${HOME:-}' "$TMPDIR/vscodium-user-key-seed" \
    "DNF action helper treats HOME as optional input"
assert_grep_fixed 'home=$(getent passwd "$uid"' "$TMPDIR/vscodium-user-key-seed" \
    "DNF action helper resolves an environment-free account home through NSS"
assert_grep_fixed 'export HOME=$home' "$TMPDIR/vscodium-user-key-seed" \
    "DNF action dependencies receive the validated account home"
assert_grep_fixed 'state_dir=/var/lib/noid-privacy/vscodium-repo-key-seed' \
    "$TMPDIR/vscodium-user-key-seed" \
    "root DNF actions keep durable evidence outside protected /root"
assert_grep_fixed '*/dnf5daemon-server)' \
    "$TMPDIR/vscodium-user-key-seed" \
    "GNOME Software's native DNF daemon cache is accepted explicitly"
assert_grep_fixed 'state_dir=${STATE_DIRECTORY:-${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy}' \
    "$TMPDIR/vscodium-user-key-seed" \
    "unprivileged DNF actions retain per-user state"
assert_grep_fixed 'fail "state directory must be an absolute normalized path"' \
    "$TMPDIR/vscodium-user-key-seed" \
    "DNF action helper rejects unsafe state paths"
assert_not_grep_extended '^[[:space:]]*base.*load_repos|/usr/bin/dnf|([[:space:]]-y|--assumeyes)' \
    "$TMPDIR/vscodium-user-key-seed" \
    "per-user seed neither loads metadata nor invokes the DNF CLI"
assert_grep_fixed 'repos_configured:::enabled=host-only raise_error=1:/usr/libexec/noid-vscodium-repo-key-seed --cache-root ${conf.cachedir}' \
    "$TMPDIR/vscodium-repo-key.actions" \
    "host DNF reconciles the exact configured cache before metadata load"
assert_not_grep '/usr/bin/sh' "$TMPDIR/vscodium-repo-key.actions" \
    "VSCodium cache-path substitution is passed as argv without a shell"
assert_eq 1 "$(grep -cF "printf 'noid-vscodium-repo-key-seed: %s\\n' \"\$*\" >&2" \
    "$TMPDIR/vscodium-user-key-seed")" \
    "plain-mode DNF action helper writes only failure diagnostics to stderr"
assert_not_grep_extended '^[[:space:]]*echo[[:space:]]' "$TMPDIR/vscodium-user-key-seed" \
    "plain-mode DNF action helper has no success output"
for boundary in \
    'ExecCondition=/usr/libexec/noid-eligible-user account' \
    'RestrictAddressFamilies=AF_UNIX' \
    'ProtectSystem=strict' \
    'ProtectHome=read-only' \
    'CacheDirectory=libdnf5' \
    'CacheDirectoryMode=0700' \
    'StateDirectory=noid-privacy'; do
    assert_grep_fixed "$boundary" "$TMPDIR/vscodium-user-key-seed.service" \
        "VSCodium user-key unit boundary: $boundary"
done
assert_not_grep_extended '^IPAddressDeny=' "$TMPDIR/vscodium-user-key-seed.service" \
    "user unit avoids an unenforceable user-manager IP firewall directive"
assert_not_grep_extended '^PrivateNetwork=' "$TMPDIR/vscodium-user-key-seed.service" \
    "user unit avoids an unenforceable user-manager network-namespace claim"

# The normal VSCodium desktop path uses switcheroo-control's platform-declared
# default GPU so Electron's Vulkan loader does not enumerate and wake an
# unrelated dGPU. Explicit owner/session offload selectors bypass this default.
assert_file_executable "$CODIUM_LAUNCH_SOURCE" \
    "canonical VSCodium default-GPU launcher is executable"
assert_file_executable "$CODIUM_SYNC_SOURCE" \
    "canonical VSCodium desktop synchronizer is executable"
assert_file_executable "$CODIUM_LAUNCHER_REGEN" \
    "VSCodium launcher embed generator is executable"
assert_cmd_success "VSCodium launcher embed generator is in sync" \
    "$CODIUM_LAUNCHER_REGEN" --check
assert_cmd_success "embedded VSCodium launcher matches canonical source" \
    cmp -s "$CODIUM_LAUNCH_SOURCE" "$TMPDIR/noid-codium-launch"
assert_cmd_success "embedded VSCodium synchronizer matches canonical source" \
    cmp -s "$CODIUM_SYNC_SOURCE" "$TMPDIR/noid-codium-launcher-sync"
assert_cmd_success "VSCodium default-GPU launcher parses" \
    bash -n "$TMPDIR/noid-codium-launch"
assert_cmd_success "VSCodium desktop synchronizer parses" \
    bash -n "$TMPDIR/noid-codium-launcher-sync"
assert_cmd_success "VSCodium default-GPU launcher passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-codium-launch"
assert_cmd_success "VSCodium desktop synchronizer passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-codium-launcher-sync"
assert_grep_fixed 'exec "$SWITCHEROOCTL" launch --gpu=0 "$VENDOR_EXECUTABLE" "$@"' \
    "$TMPDIR/noid-codium-launch" \
    "normal VSCodium launch uses the native platform-default GPU"
for gpu_selector in DRI_PRIME __NV_PRIME_RENDER_OFFLOAD \
        __NV_PRIME_RENDER_OFFLOAD_PROVIDER __GLX_VENDOR_LIBRARY_NAME \
        __EGL_VENDOR_LIBRARY_FILENAMES __VK_LAYER_NV_optimus VK_DRIVER_FILES \
        VK_ICD_FILENAMES VK_LOADER_DRIVERS_SELECT VK_LOADER_DRIVERS_DISABLE \
        VK_LOADER_DEVICE_SELECT MESA_VK_DEVICE_SELECT \
        MESA_VK_DEVICE_SELECT_FORCE_DEFAULT_DEVICE; do
    assert_grep_fixed "    $gpu_selector" "$TMPDIR/noid-codium-launch" \
        "explicit GPU selector remains owner-controlled: $gpu_selector"
done
assert_not_grep 'VK_LOADER_DRIVERS_SELECT=\*intel\*' \
    "$TMPDIR/noid-codium-launch" \
    "launcher never hardcodes Intel as the platform default"
assert_grep_fixed 'rpm -q --dump "$EXPECTED_PACKAGE"' \
    "$TMPDIR/noid-codium-launcher-sync" \
    "desktop synchronizer authenticates current VSCodium RPM bytes"
assert_grep_fixed 'vendor launcher bytes differ from the RPM record' \
    "$TMPDIR/noid-codium-launcher-sync" \
    "desktop synchronizer fails closed on vendor payload drift"
assert_grep_fixed 'generated launcher changed bytes outside Exec routing' \
    "$TMPDIR/noid-codium-launcher-sync" \
    "desktop overlay changes only VSCodium Exec routing"
assert_grep_fixed \
    'sed -E "s#^Exec=${VENDOR_EXECUTABLE}([[:space:]]|$)#Exec=${LAUNCH_WRAPPER}\\1#"' \
    "$TMPDIR/noid-codium-launcher-sync" \
    "desktop overlay translates the real whitespace-delimited RPM Exec form"
assert_grep_fixed \
    'sed -E "s#^Exec=${LAUNCH_WRAPPER}([[:space:]]|$)#Exec=${VENDOR_EXECUTABLE}\\1#"' \
    "$TMPDIR/noid-codium-launcher-sync" \
    "desktop overlay reverse-check uses the same exact Exec boundary"
assert_cmd_success "desktop candidate cleanup registration precedes file creation" \
    awk '
        index($0, "candidates+=(\"$candidate\")") { registered = NR }
        index($0, "\"$vendor_file\" > \"$candidate\"") { created = NR }
        END { exit !(registered && created && registered < created) }
    ' "$TMPDIR/noid-codium-launcher-sync"
assert_grep_fixed 'mv -fT -- "$candidate" "$admin_file"' \
    "$TMPDIR/noid-codium-launcher-sync" \
    "desktop synchronizer publishes each validated overlay atomically"
assert_grep_fixed 'matchpathcon -V "$admin_file"' \
    "$TMPDIR/noid-codium-launcher-sync" \
    "desktop synchronizer makes the SELinux label a hard postcondition"
assert_grep_fixed 'update-desktop-database "$ADMIN_DIR"' \
    "$TMPDIR/noid-codium-launcher-sync" \
    "desktop synchronizer refreshes the native MIME association cache"
assert_grep_fixed \
    'post_transaction:codium:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-codium-launcher-sync\ >/dev/null' \
    "$TMPDIR/noid-codium-launcher.actions" \
    "codium transactions regenerate only admin-owned launchers"
assert_grep_fixed 'VSCodium default-GPU launcher contract is incomplete' \
    "$KS_FILE" "M08 verifies the complete desktop-routing postcondition"

# Exercise argv and environment preservation against fakes without importing a
# test-mode escape hatch into the installed helper.
CODIUM_LAUNCH_FIXTURE="$(mktemp -d /var/tmp/noid-codium-launch.XXXXXX)"
sed \
    -e "s|^VENDOR_EXECUTABLE=/usr/share/codium/codium$|VENDOR_EXECUTABLE=$CODIUM_LAUNCH_FIXTURE/vendor|" \
    -e "s|^SWITCHEROOCTL=/usr/bin/switcherooctl$|SWITCHEROOCTL=$CODIUM_LAUNCH_FIXTURE/switcherooctl|" \
    "$TMPDIR/noid-codium-launch" > "$CODIUM_LAUNCH_FIXTURE/launcher"
cat > "$CODIUM_LAUNCH_FIXTURE/vendor" <<'CODIUM_VENDOR_FIXTURE_EOF'
#!/usr/bin/env bash
printf 'vendor-argv:' >> "$FAKE_CODIUM_TRACE"
printf ' <%s>' "$@" >> "$FAKE_CODIUM_TRACE"
printf '\nDRI_PRIME=%s\n' "${DRI_PRIME-}" >> "$FAKE_CODIUM_TRACE"
exit "${FAKE_CODIUM_EXIT:-0}"
CODIUM_VENDOR_FIXTURE_EOF
cat > "$CODIUM_LAUNCH_FIXTURE/switcherooctl" <<'CODIUM_SWITCHEROO_FIXTURE_EOF'
#!/usr/bin/env bash
printf 'switcheroo-argv:' >> "$FAKE_CODIUM_TRACE"
printf ' <%s>' "$@" >> "$FAKE_CODIUM_TRACE"
printf '\n' >> "$FAKE_CODIUM_TRACE"
[[ ${1:-} == launch && ${2:-} == --gpu=0 ]] || exit 64
shift 2
export DRI_PRIME=fixture-platform-default
exec "$@"
CODIUM_SWITCHEROO_FIXTURE_EOF
chmod 0755 "$CODIUM_LAUNCH_FIXTURE/launcher" \
    "$CODIUM_LAUNCH_FIXTURE/vendor" "$CODIUM_LAUNCH_FIXTURE/switcherooctl"
: > "$CODIUM_LAUNCH_FIXTURE/trace"
assert_cmd_success "normal launcher preserves argv through switcherooctl" \
    env -i PATH=/usr/bin:/bin \
        FAKE_CODIUM_TRACE="$CODIUM_LAUNCH_FIXTURE/trace" \
        "$CODIUM_LAUNCH_FIXTURE/launcher" --new-window "/tmp/path with space"
assert_grep_fixed \
    "switcheroo-argv: <launch> <--gpu=0> <$CODIUM_LAUNCH_FIXTURE/vendor> <--new-window> </tmp/path with space>" \
    "$CODIUM_LAUNCH_FIXTURE/trace" \
    "normal launcher requests exact default-GPU argv"
assert_grep_fixed \
    'vendor-argv: <--new-window> </tmp/path with space>' \
    "$CODIUM_LAUNCH_FIXTURE/trace" \
    "switcherooctl exec preserves VSCodium arguments"
assert_grep_fixed 'DRI_PRIME=fixture-platform-default' \
    "$CODIUM_LAUNCH_FIXTURE/trace" \
    "native helper environment reaches the vendor process"

for gpu_selector in DRI_PRIME __NV_PRIME_RENDER_OFFLOAD \
        __NV_PRIME_RENDER_OFFLOAD_PROVIDER __GLX_VENDOR_LIBRARY_NAME \
        __EGL_VENDOR_LIBRARY_FILENAMES __VK_LAYER_NV_optimus VK_DRIVER_FILES \
        VK_ICD_FILENAMES VK_LOADER_DRIVERS_SELECT VK_LOADER_DRIVERS_DISABLE \
        VK_LOADER_DEVICE_SELECT MESA_VK_DEVICE_SELECT \
        MESA_VK_DEVICE_SELECT_FORCE_DEFAULT_DEVICE; do
    : > "$CODIUM_LAUNCH_FIXTURE/trace"
    assert_cmd_success "explicit selector bypasses default GPU: $gpu_selector" \
        env -i PATH=/usr/bin:/bin \
            FAKE_CODIUM_TRACE="$CODIUM_LAUNCH_FIXTURE/trace" \
            "$gpu_selector=owner-choice" \
            "$CODIUM_LAUNCH_FIXTURE/launcher" --reuse-window
    assert_not_grep 'switcheroo-argv:' "$CODIUM_LAUNCH_FIXTURE/trace" \
        "default selector is not nested over $gpu_selector"
    assert_grep_fixed 'vendor-argv: <--reuse-window>' \
        "$CODIUM_LAUNCH_FIXTURE/trace" \
        "explicit $gpu_selector reaches VSCodium directly"
done
set +e
env -i PATH=/usr/bin:/bin \
    FAKE_CODIUM_TRACE="$CODIUM_LAUNCH_FIXTURE/trace" FAKE_CODIUM_EXIT=37 \
    DRI_PRIME=owner-choice \
    "$CODIUM_LAUNCH_FIXTURE/launcher" >/dev/null 2>&1
codium_launch_rc=$?
set -e
assert_eq 37 "$codium_launch_rc" \
    "launcher preserves the vendor process exit status"

assert_grep_fixed 'DNF5 stores `repo_gpgcheck` keys separately' "$GPG_TRUST_DOC" \
    "trust documentation distinguishes metadata keys from RPM package keys"
assert_grep_fixed '`noid-vscodium-repo-key-seed`' "$GPG_TRUST_DOC" \
    "trust documentation names the offline metadata-key reconciliation path"
assert_grep_fixed '`/var/cache/dnf5daemon-server`' "$GPG_TRUST_DOC" \
    "trust documentation covers GNOME Software's distinct DNF cache"
assert_grep_fixed 'accepts trust on first use.' \
    "$GPG_TRUST_DOC" \
    "trust documentation preserves the no-TOFU boundary"

# A durable evidence marker must never suppress reconciliation of the mutable
# DNF metadata cache. Exercise first seed, cache-only removal, repair with the
# same state record, and fail-closed handling of an unexpected existing key.
VSC_FIXTURE="$TMPDIR/vscodium-key-runtime"
mkdir -m 0700 "$VSC_FIXTURE" "$VSC_FIXTURE/gnupg" "$VSC_FIXTURE/cache" \
    "$VSC_FIXTURE/state"
assert_cmd_success "generate offline VSCodium helper fixture key" \
    env GNUPGHOME="$VSC_FIXTURE/gnupg" gpg --batch --passphrase '' \
        --quick-generate-key 'NoID Privacy VSCodium cache fixture' ed25519 sign 0
env GNUPGHOME="$VSC_FIXTURE/gnupg" gpg --batch --armor \
    --export 'NoID Privacy VSCodium cache fixture' > "$VSC_FIXTURE/key.asc"
chmod 0644 "$VSC_FIXTURE/key.asc"
VSC_FIXTURE_FPR=$(env GNUPGHOME="$VSC_FIXTURE/gnupg" gpg --batch --with-colons \
    --show-keys "$VSC_FIXTURE/key.asc" | awk -F: '$1 == "fpr" {print toupper($10); exit}')
VSC_FIXTURE_KEY_ID=${VSC_FIXTURE_FPR: -16}

# Exercise the shared source-pinned-key parser with real OpenPGP packets.
# A concatenated bundle with two primary keys must never be reduced to the
# first fingerprint silently.
sed -n '/^read_single_primary_fingerprint()/,/^}/p' "$KS_FILE" \
    > "$VSC_FIXTURE/read-single-primary.sh"
# shellcheck source=/dev/null
. "$VSC_FIXTURE/read-single-primary.sh"
assert_eq "$VSC_FIXTURE_FPR" \
    "$(read_single_primary_fingerprint "$VSC_FIXTURE/key.asc")" \
    "single-primary OpenPGP fixture returns its exact fingerprint"
assert_cmd_success "generate second OpenPGP primary-key fixture" \
    env GNUPGHOME="$VSC_FIXTURE/gnupg" gpg --batch --passphrase '' \
        --quick-generate-key 'NoID Privacy second primary fixture' ed25519 sign 0
env GNUPGHOME="$VSC_FIXTURE/gnupg" gpg --batch --armor \
    --export 'NoID Privacy second primary fixture' > "$VSC_FIXTURE/key2.asc"
cp "$VSC_FIXTURE/key.asc" "$VSC_FIXTURE/multi-primary.asc"
printf '\n' >> "$VSC_FIXTURE/multi-primary.asc"
cat "$VSC_FIXTURE/key2.asc" >> "$VSC_FIXTURE/multi-primary.asc"
assert_cmd_failure "multiple OpenPGP primary keys fail closed" \
    read_single_primary_fingerprint "$VSC_FIXTURE/multi-primary.asc"

VSC_CACHE="$VSC_FIXTURE/cache/libdnf5"
VSC_REPO="$VSC_CACHE/gitlab.com_paulcarroty_vscodium_repo-0123456789abcdef"
mkdir -m 0750 "$VSC_CACHE"
VSC_HELPER_ENV=(
    NOID_TEST_MODE=1
    NOID_TEST_KEY_FILE="$VSC_FIXTURE/key.asc"
    NOID_TEST_FINGERPRINT="$VSC_FIXTURE_FPR"
    NOID_TEST_KEY_ID="$VSC_FIXTURE_KEY_ID"
    NOID_TEST_REPO_DIR="$VSC_REPO"
    NOID_TEST_STATE_DIR="$VSC_FIXTURE/state/noid-privacy"
    XDG_STATE_HOME="$VSC_FIXTURE/state"
)
assert_cmd_success "first VSCodium metadata-key reconciliation succeeds" \
    env -i PATH=/usr/sbin:/usr/bin "${VSC_HELPER_ENV[@]}" \
        bash "$TMPDIR/vscodium-user-key-seed" \
        --cache-root "$VSC_CACHE"
VSC_TARGET="$VSC_REPO/pubring/$VSC_FIXTURE_KEY_ID.pub"
VSC_STATE="$VSC_FIXTURE/state/noid-privacy/vscodium-repo-key-seed-v1.done"
assert_file_exists "$VSC_TARGET" "first reconciliation installs the pinned cache key"
assert_file_exists "$VSC_STATE" "first reconciliation seals validation evidence"
VSC_STATE_SHA=$(sha256sum "$VSC_STATE" | awk '{print $1}')
unlink "$VSC_TARGET"
assert_cmd_success "valid state does not suppress cache-key repair" \
    env "${VSC_HELPER_ENV[@]}" bash "$TMPDIR/vscodium-user-key-seed" \
        --cache-root "$VSC_CACHE"
assert_file_exists "$VSC_TARGET" "cache-only removal is repaired offline"
assert_eq "$VSC_STATE_SHA" "$(sha256sum "$VSC_STATE" | awk '{print $1}')" \
    "repair preserves the sealed evidence record"
chmod 0644 "$VSC_TARGET"
assert_cmd_success "DNF5-native public-key mode remains accepted" \
    env "${VSC_HELPER_ENV[@]}" bash "$TMPDIR/vscodium-user-key-seed" \
        --cache-root "$VSC_CACHE"
VSC_DAEMON_CACHE="$VSC_FIXTURE/cache/dnf5daemon-server"
VSC_DAEMON_REPO="$VSC_DAEMON_CACHE/gitlab.com_paulcarroty_vscodium_repo-0123456789abcdef"
mkdir -m 0750 "$VSC_DAEMON_CACHE"
assert_cmd_success "GNOME Software DNF daemon cache reconciles offline" \
    env "${VSC_HELPER_ENV[@]}" NOID_TEST_REPO_DIR="$VSC_DAEMON_REPO" \
        bash "$TMPDIR/vscodium-user-key-seed" \
        --cache-root "$VSC_DAEMON_CACHE"
assert_file_exists "$VSC_DAEMON_REPO/pubring/$VSC_FIXTURE_KEY_ID.pub" \
    "DNF daemon cache receives the same pinned metadata key"
VSC_UNEXPECTED_CACHE="$VSC_FIXTURE/cache/unexpected"
mkdir -m 0750 "$VSC_UNEXPECTED_CACHE"
assert_cmd_failure "unrecognized absolute cache basename fails closed" \
    env "${VSC_HELPER_ENV[@]}" \
        NOID_TEST_REPO_DIR="$VSC_UNEXPECTED_CACHE/gitlab.com_paulcarroty_vscodium_repo-0123456789abcdef" \
        bash "$TMPDIR/vscodium-user-key-seed" \
        --cache-root "$VSC_UNEXPECTED_CACHE"
printf 'unexpected-key-bytes\n' > "$VSC_TARGET"
chmod 0640 "$VSC_TARGET"
assert_cmd_failure "unexpected existing cache key fails closed" \
    env "${VSC_HELPER_ENV[@]}" bash "$TMPDIR/vscodium-user-key-seed" \
        --cache-root "$VSC_CACHE"
assert_cmd_failure "relative cache path is rejected" \
    env "${VSC_HELPER_ENV[@]}" bash "$TMPDIR/vscodium-user-key-seed" \
        --cache-root relative/libdnf5

# --- Step 1d native service mask; M17 verifies the durable route ------------
assert_grep_fixed 'ln -sf /dev/null /etc/systemd/user/gnome-software.service' "$KS_FILE"
assert_grep_fixed 'rm -f /usr/local/share/dbus-1/services/org.gnome.Software.service' "$KS_FILE" \
    "redundant or legacy D-Bus service override is removed"
assert_grep_fixed "Fedora D-Bus descriptor's SystemdService=gnome-software.service route" \
    "$KS_FILE" "M08 documents the native masked activation chain"
assert_not_grep 'Exec=/usr/bin/gnome-software --gapplication-service' "$KS_FILE" \
    "M08 does not recreate the direct-exec activation bypass"

# --- ProtectProc/ProcSubset (Kicksecure hidepid parity) ------
# Systemd's per-service hidepid equivalent. ProtectProc=invisible hides
# other processes' /proc/<pid>/ from this service. ProcSubset=pid (rsyslog +
# dbus-broker only) additionally hides /proc/sys/*, /proc/net/* etc.
#
# All 5 M08-owned hardened services get ProtectProc=invisible (re-enabled
# dbus-broker + NM after live-test bisect):
for conf in firewalld NetworkManager fwupd rsyslog dbus-broker; do
    # NetworkManager file is "nm.conf" in tmpdir
    file_name="${conf}"
    [ "$conf" = "NetworkManager" ] && file_name="nm"
    assert_grep_extended '^ProtectProc=invisible$' "$TMPDIR/${file_name}.conf" \
        "ProtectProc=invisible in ${conf} drop-in (Kicksecure parity)"
done

# ProcSubset=pid ONLY on services that don't read /proc/net or /proc/sys
# (rsyslog only — dbus-broker uses default since busctl needs /proc/<pid>/cmdline):
assert_grep_extended '^ProcSubset=pid$' "$TMPDIR/rsyslog.conf" \
    "ProcSubset=pid in rsyslog (pure IPC/log forwarder, no /proc/net)"

# ProcSubset=pid MUST NOT appear in firewalld/NM/fwupd/dbus-broker
# — they need /proc/net or /proc/sys access. Regression check.
for conf in firewalld nm fwupd dbus-broker; do
    if grep -qE '^ProcSubset=pid$' "$TMPDIR/${conf}.conf" 2>/dev/null; then
        _fail "${conf}: ProcSubset=pid MUST NOT be set — would break /proc/net access"
    else
        _pass "${conf}: correctly uses default ProcSubset=all (needs /proc/net)"
    fi
done

# --- Step 3b D-Bus daemon drop-ins (accounts-daemon / usbguard-dbus /
# rtkit-daemon) — load-bearing directives + the documented exclusions ------
assert_grep_extended '^RestrictSUIDSGID=yes$' "$TMPDIR/accountsd.conf" \
    "RestrictSUIDSGID in accounts-daemon drop-in"
if grep -qE '^PrivateTmp=' "$TMPDIR/accountsd.conf" 2>/dev/null; then
    _fail "accounts-daemon: PrivateTmp MUST NOT be overridden — GIS SetIconFile passes a caller-created /tmp path"
else
    _pass "accounts-daemon: correctly preserves Fedora PrivateTmp=false (GIS temporary-avatar handoff)"
fi
if grep -qE '^ProtectHome=' "$TMPDIR/accountsd.conf" 2>/dev/null; then
    _fail "accounts-daemon: ProtectHome MUST NOT be set — CreateUser()/useradd needs /home"
else
    _pass "accounts-daemon: correctly leaves ProtectHome at vendor default (useradd /home access)"
fi
assert_grep_extended '^NoNewPrivileges=yes$' "$TMPDIR/usbguard-dbus.conf" \
    "NoNewPrivileges in usbguard-dbus drop-in"
assert_grep_extended '^SystemCallFilter=@system-service$' "$TMPDIR/usbguard-dbus.conf" \
    "SystemCallFilter in usbguard-dbus drop-in"
assert_grep_fixed 'ReadWritePaths=-/dev/shm' "$TMPDIR/usbguard-dbus.conf" \
    "usbguard-dbus keeps the libqb /dev/shm IPC channel writable"
assert_grep_extended '^ProtectSystem=strict$' "$TMPDIR/rtkit.conf" \
    "ProtectSystem=strict in rtkit-daemon drop-in"
if grep -qE '^RestrictRealtime=' "$TMPDIR/rtkit.conf" 2>/dev/null; then
    _fail "rtkit-daemon: RestrictRealtime MUST NOT be set — RT-grant is the core function"
else
    _pass "rtkit-daemon: correctly omits RestrictRealtime (RT-grant core function)"
fi
if grep -qE '^NoNewPrivileges=' "$TMPDIR/rtkit.conf" 2>/dev/null; then
    _fail "rtkit-daemon: NoNewPrivileges= MUST NOT be set (SELinux domain transition)"
else
    _pass "rtkit-daemon: correctly omits NoNewPrivileges (SELinux compat)"
fi

# M11 owns chronyd through Fedora's native restricted client unit. M08 must not
# recreate either retired custom drop-in or a second sandbox owner.
assert_not_grep_extended "(^|[[:space:]<'])CH_EOF([[:space:]']|$)|/etc/systemd/system/chronyd\\.service\\.d|/etc/systemd/system/chronyd-restricted\\.service\\.d" \
    "$KS_FILE" "M08 has no competing chronyd sandbox drop-in"
assert_grep_fixed 'chronyd sandbox delegated to Fedora restricted client (M11)' \
    "$KS_FILE" "M08 documents the single native chronyd owner"
assert_grep_fixed 'starts directly as chrony in chronyd_restricted_t with NNP=yes' \
    "$KS_FILE" "M08 does not apply its SELinux NNP exception to restricted chronyd"
assert_grep_fixed 'for svc in firewalld NetworkManager fwupd rsyslog dbus-broker' \
    "$KS_FILE" "M08 runtime verification enumerates the core drop-in owners"
assert_grep_fixed 'switcheroo-control accounts-daemon usbguard-dbus udisks2 rtkit-daemon; do' \
    "$KS_FILE" "M08 runtime verification covers the complete per-unit drop-in set"
assert_not_grep 'for svc in .*chronyd.*; do' "$KS_FILE" \
    "M08 runtime verification does not require M11 artifacts before M11 runs"

# NM drop-in re-enabled (without NNP for SELinux). Verify.
assert_grep_extended '^ProtectSystem=full$'     "$TMPDIR/nm.conf"
assert_grep_extended '^ProtectProc=invisible$'  "$TMPDIR/nm.conf"
if grep -qE '^NoNewPrivileges=' "$TMPDIR/nm.conf" 2>/dev/null; then
    _fail "NetworkManager: NoNewPrivileges= MUST NOT be set (SELinux domain transition)"
else
    _pass "NetworkManager: correctly omits NoNewPrivileges (SELinux compat)"
fi
# NM design exclusions (per discovery 08-service-minimization.md):
for excluded in MemoryDenyWriteExecute PrivateDevices ProtectKernelModules; do
    if grep -qE "^${excluded}=" "$TMPDIR/nm.conf" 2>/dev/null; then
        _fail "NetworkManager: $excluded MUST NOT be set (plugin/rfkill/WG-driver compat)"
    else
        _pass "NetworkManager: correctly omits $excluded (per discovery doc design)"
    fi
done

# --- Step 8b VSCodium /etc/skel privacy defaults ----------
extract_heredoc "$KS_FILE" "CODIUM_SETTINGS_EOF" "$TMPDIR/codium-settings.json" \
    || _fail "VSCodium settings.json heredoc extraction"
assert_grep_fixed '/etc/skel/.config/VSCodium/User/settings.json' "$KS_FILE"
for key in '"telemetry.telemetryLevel": "off"' \
           '"telemetry.feedback.enabled": false' \
           '"update.mode": "none"' \
           '"update.showReleaseNotes": false' \
           '"extensions.autoCheckUpdates": false' \
           '"extensions.autoUpdate": "off"' \
           '"workbench.enableExperiments": false' \
           '"workbench.settings.enableNaturalLanguageSearch": false' \
           '"workbench.settings.showAISearchToggle": false' \
           '"workbench.cloudChanges.continueOn": "off"' \
           '"workbench.cloudChanges.autoResume": "off"' \
           '"search.searchView.semanticSearchBehavior": "manual"' \
           '"json.schemaDownload.enable": false' \
           '"npm.fetchOnlinePackageInfo": false' \
           '"js/ts.tsserver.automaticTypeAcquisition.enabled": false' \
           '"task.allowAutomaticTasks": "off"' \
           '"security.workspace.trust.enabled": false' \
           '"git.autofetch": false' \
           '"git.openRepositoryInParentFolders": "prompt"' \
           '"github.copilot.enable": { "*": false }' \
           '"redhat.telemetry.enabled": false' \
           '"aws.telemetry": false' \
           '"gitlens.telemetry.enabled": false' \
           '"claudeCode.allowDangerouslySkipPermissions": true' \
           '"claudeCode.initialPermissionMode": "bypassPermissions"' \
           '"claudeCode.respectGitIgnore": true' \
           '"claudeCode.claudeProcessWrapper": "/usr/local/bin/claude-thinking-wrapper"'; do
    assert_grep_fixed "$key" "$TMPDIR/codium-settings.json"
done
sed -n '/^count_codium_settings() {$/,/^}$/p' "$KS_FILE" \
    > "$TMPDIR/count-codium-settings.sh"
assert_cmd_success "VSCodium settings JSON counter parses" \
    bash -n "$TMPDIR/count-codium-settings.sh"
# shellcheck source=/dev/null
. "$TMPDIR/count-codium-settings.sh"
codium_key_count=$(count_codium_settings "$TMPDIR/codium-settings.json")
assert_eq 27 "$codium_key_count" \
    "VSCodium settings are valid JSON with the reviewed top-level key count"
assert_grep_fixed '`security.workspace.trust.enabled=false`' \
    "$TMPDIR/ai-workspace.md" \
    "AI-workspace documentation names the prompt-free trust default"
assert_grep_fixed 'Manage Workspace Trust' "$TMPDIR/ai-workspace.md" \
    "AI-workspace documentation preserves the native selective-trust path"
assert_grep_fixed 'opening an untrusted repository immediately' \
    "$TMPDIR/ai-workspace.md" \
    "AI-workspace documentation names the untrusted-repository authority trade-off"
# Phantom or stale key names silently no-op and give false assurance. Only
# names verified against the shipped VSCodium build or the owning
# extension's current manifest may appear. GitLens uses
# gitlens.telemetry.enabled; the old GitLens advanced.* spelling is gone,
# and the GitHub PR extension exposes no telemetry key.
assert_grep_fixed '"gitlens.telemetry.enabled": false' \
    "$TMPDIR/codium-settings.json" \
    "GitLens telemetry uses the current manifest key name"
assert_not_grep '"continue.telemetryEnabled"' \
    "$TMPDIR/codium-settings.json" \
    "retired Continue integration key is absent"
for phantom in 'telemetry.enableErrorTelemetry' 'git.enableTelemetry' \
               'github.telemetry.enabled' 'azure.telemetry.enabled' \
               'docker.telemetry.enabled' 'chat.commandCenter.enabled' \
               'githubPullRequests.telemetry.enabled' \
               'gitlens.advanced.telemetry.enabled'; do
    assert_not_grep "\"$phantom\"" "$TMPDIR/codium-settings.json" \
        "unverified vendor key name is absent: $phantom"
done
for excluded_setting in 'telemetry.enableTelemetry' \
                        'telemetry.enableCrashReporter' \
                        'extensions.verifySignature' \
                        'git.autoRepositoryDetection' \
                        'claudeCode.disableLoginPrompt' \
                        'claudeCode.preferredLocation' \
                        'chatgpt.openOnStartup' \
                        'chatgpt.commentCodeLensEnabled'; do
    assert_not_grep "\"$excluded_setting\"" "$TMPDIR/codium-settings.json" \
        "deprecated, ineffective, overreaching or UI-only setting is absent: $excluded_setting"
done
printf '%s\n' '{"broken":' > "$TMPDIR/codium-settings.invalid.json"
assert_cmd_failure "VSCodium counter rejects malformed JSON" \
    count_codium_settings "$TMPDIR/codium-settings.invalid.json"
printf '%s\n' '[]' > "$TMPDIR/codium-settings.array.json"
assert_cmd_failure "VSCodium counter rejects a non-object JSON root" \
    count_codium_settings "$TMPDIR/codium-settings.array.json"
sed -n '/^# Verification: parse the exact JSON object/,/^# Step 8b\.1:/p' \
    "$KS_FILE" > "$TMPDIR/codium-settings-verifier.sh"
assert_grep_fixed 'if ! codium_settings_count=$(count_codium_settings "$codium_settings_file"); then' \
    "$TMPDIR/codium-settings-verifier.sh" \
    "M08 rejects invalid VSCodium JSON before evaluating the exact count"
assert_grep_fixed 'if [ "$codium_settings_count" -eq 27 ]; then' \
    "$TMPDIR/codium-settings-verifier.sh" \
    "M08 enforces the reviewed exact 27-key VSCodium set"
assert_eq 2 "$(grep -cE '^[[:space:]]+exit 1$' \
    "$TMPDIR/codium-settings-verifier.sh" || true)" \
    "invalid JSON and a non-exact object both abort M08"

# --- Step 8d Claude Code /etc/skel privacy defaults --------
extract_heredoc "$KS_FILE" "CLAUDE_SETTINGS_EOF" "$TMPDIR/claude-settings.json" \
    || _fail "Claude Code settings.json heredoc extraction"
assert_grep_fixed '/etc/skel/.claude/settings.json' "$KS_FILE"
for key in '"cleanupPeriodDays": 7' \
           '"skipWebFetchPreflight": true' \
           '"defaultMode": "bypassPermissions"' \
           '"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"' \
           '"CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1"' \
           '"CLAUDE_CODE_HIDE_CWD": "1"' \
           '"DISABLE_AUTOUPDATER": "1"' \
           '"DISABLE_ERROR_REPORTING": "1"' \
           '"DISABLE_FEEDBACK_COMMAND": "1"' \
           '"DISABLE_GROWTHBOOK": "1"' \
           '"DISABLE_TELEMETRY": "1"' \
           '"DO_NOT_TRACK": "1"'; do
    assert_grep_fixed "$key" "$TMPDIR/claude-settings.json"
done
# The schema's permission-mode switches are string enums whose only valid
# value is "disable". They would conflict with the selected bypass default;
# Boolean `false` was also a schema violation and must never return.
for invalid_key in 'disableAutoMode' 'disableBypassPermissionsMode'; do
    assert_not_grep "$invalid_key" "$TMPDIR/claude-settings.json" \
        "schema-invalid permission-mode key is absent: $invalid_key"
done
# JSON must be parseable (defense vs. heredoc typo regression)
python3 -c "import json; json.load(open('$TMPDIR/claude-settings.json'))" 2>/dev/null \
    && _pass "Claude Code settings.json valid JSON" \
    || _fail "Claude Code settings.json invalid JSON"
assert_not_grep_fixed 'Claude Code web search fails at reasoning effort' \
    "$KNOWN_FAILURES" \
    "vendor-fixed Claude WebSearch failure is absent from current known failures"
assert_not_grep_fixed 'The supported workaround is the first one' \
    "$KNOWN_FAILURES" \
    "obsolete lower-effort Claude WebSearch workaround cannot return"
assert_not_grep_fixed 'one such gate makes Claude Code web search fail' \
    "$PROJECT_ROOT/docs/ai-workspace.md" \
    "GrowthBook privacy trade-off no longer claims the vendor-fixed regression"

# --- Step 8c/8c.1 canonical cross-agent policy -----------------------------
# The repo-root AGENTS.md (Cursor/project clients) and every installed global
# adapter must resolve to the exact CLAUDE.md policy bytes. No independently
# maintained copies are allowed: they would silently drift.
assert_file_exists "$PROJECT_ROOT/AGENTS.md" "repo-root AGENTS.md exists"
assert_file_executable "$PROJECT_ROOT/scripts/regen-agent-policy-embed.sh" \
    "cross-agent policy embed generator is executable"
assert_cmd_success "cross-agent policy generator reports no drift" \
    "$PROJECT_ROOT/scripts/regen-agent-policy-embed.sh" --check
if cmp -s "$TMPDIR/agent-policy.md" "$PROJECT_ROOT/AGENTS.md"; then
    _pass "repo-root AGENTS.md is byte-identical to canonical CLAUDE.md"
else
    _fail "repo-root AGENTS.md drifted from canonical CLAUDE.md"
fi
policy_lines=$(wc -l < "$TMPDIR/agent-policy.md")
if [ "$policy_lines" -ge 100 ] && [ "$policy_lines" -le 200 ]; then
    _pass "canonical agent policy stays within 100-200 lines ($policy_lines)"
else
    _fail "canonical agent policy outside 100-200 lines ($policy_lines)"
fi
assert_grep_fixed '100-200 policy range' "$KS_FILE" \
    "canonical agent policy is capped at the adherence-friendly size"
assert_not_grep '100-240 policy range' "$KS_FILE" \
    "relaxed agent-policy line bracket cannot return"
assert_not_grep 'unexpected line count: $claudemd_lines"$' "$KS_FILE" \
    "agent-policy size failure is not a log-only false success"
assert_grep_fixed 'the open report does not' "$KNOWN_FAILURES" \
    "Codex blank-panel guide distinguishes observation from root cause"
assert_grep_fixed 'not confirmation of the blank-panel root cause' "$KNOWN_FAILURES" \
    "separate Codex renderer crash is not misclassified as causal evidence"
assert_not_grep 'This is an upstream extension-host activation-timing bug' \
    "$KNOWN_FAILURES" \
    "Codex blank-panel guide does not promote an unconfirmed timing hypothesis"
assert_grep_fixed 'applied proactively. Current NoID Privacy validation' "$KNOWN_FAILURES" \
    "Codex timing workaround is conditional rather than a default"
assert_grep_fixed 'not persist the dummy flag: retain the normal launcher' "$KNOWN_FAILURES" \
    "Codex timing workaround never becomes a launcher mutation"
assert_not_grep 'sed -i.*codex-timing-workaround-32388' "$KNOWN_FAILURES" \
    "known-failure guide no longer recommends a persistent dummy flag"
assert_not_grep 'timedatectl timesync-status' "$KNOWN_FAILURES" \
    "chrony diagnostics do not invoke systemd-timesyncd tooling"
assert_grep_fixed 'sudo chronyc -N sources -v' "$KNOWN_FAILURES" \
    "chrony failure guide inspects the active source set"
assert_grep_fixed "Activation request for 'org.freedesktop.home1' failed." \
    "$KNOWN_FAILURES" \
    "known-failure guide classifies D-Bus requests for deliberately masked services"
assert_grep_fixed 'gkr-pam: unable to locate daemon control file' \
    "$KNOWN_FAILURES" \
    "known-failure guide requires a post-login keyring owner before accepting startup noise"
assert_grep_fixed 'busctl --user status org.freedesktop.secrets' \
    "$KNOWN_FAILURES" \
    "keyring diagnostic verifies the live session service rather than hiding PAM output"
assert_grep_fixed 'Lost connection to Wayland compositor' \
    "$KNOWN_FAILURES" \
    "known-failure guide limits the GlobalShortcutsProvider case to the observed GDM handoff"
assert_grep_fixed "A provider failure in the active user's manager" \
    "$KNOWN_FAILURES" \
    "greeter shortcut-provider noise is never accepted for the active user session"
assert_grep_fixed 'org.freedesktop.bolt.enroll' \
    "$KNOWN_FAILURES" \
    "known-failure guide classifies the optional absent Bolt PolicyKit action"
assert_grep_fixed 'invent a local PolicyKit action merely to silence GNOME Shell.' \
    "$KNOWN_FAILURES" \
    "absent optional Bolt support is documented without weakening authorization policy"
assert_grep_fixed 'A version label or release tag alone can move' "$GPG_TRUST_DOC" \
    "supply-chain guide never treats a release tag alone as immutable"
# The policy assertions below pin prose, not line breaks. grep matches within a
# line, so against the raw file a pinned phrase had to sit on one source line:
# rewrapping a paragraph split the phrase across a newline and broke the match
# without changing a single word, and lines were being wrapped short purely to
# prevent that. The contract is now evaluated against a copy whose paragraphs
# are joined back into one logical line each, so wrapping is free again.
#
# Joining only ever merges text, so a positive assertion that matched before
# still matches, and the four negative assertions get stricter: a banned phrase
# can no longer hide across a line break. Line count, byte identity against
# repo-root AGENTS.md, and the generator drift check stay on the raw extraction
# above -- those are properties of the file as published, not of its prose.
policy_flatten() {
    awk '
        /^[[:space:]]*$/ { if (buf != "") { print buf; buf = "" } print ""; next }
        /^(#|- |[0-9]+\. )/ { if (buf != "") print buf; buf = $0; next }
        { line = $0; sub(/^[[:space:]]+/, "", line)
          buf = (buf == "" ? line : buf " " line) }
        END { if (buf != "") print buf }
    ' "$1" > "$2"
}
POLICY_FLAT="$TMPDIR/agent-policy-flat.md"
policy_flatten "$TMPDIR/agent-policy.md" "$POLICY_FLAT"
assert_file_exists "$POLICY_FLAT" "policy prose contract has a reflow-tolerant copy"
# Positive control: the join must actually happen, or every assertion below
# would pass for the wrong reason on a file that was never flattened.
if [ "$(wc -l < "$POLICY_FLAT")" -lt "$(wc -l < "$TMPDIR/agent-policy.md")" ]; then
    _pass "reflow-tolerant copy joined wrapped paragraphs"
else
    _fail "reflow-tolerant copy did not join anything -- matcher is inert"
fi
assert_grep_fixed 'These are NoID Privacy defaults, not constraints' "$POLICY_FLAT" \
    "cross-agent user-intent doctrine marker"
assert_grep_fixed 'Independently verify delegated audit or review claims — including the' \
    "$POLICY_FLAT" "delegated findings never replace primary verification"
assert_grep_fixed 'user-governed AIDE evidence (daily checks only after baseline' \
    "$POLICY_FLAT" "AIDE schedule is conditional on the user-owned baseline"
# Pin the substance, not the sentence. These four tokens are what must survive
# any rewording: the configured value, the downgrade property of the
# compatibility mode, its plaintext fallback, and the ban on presenting that
# mode as strict. Anchoring on a long verbatim clause instead made the contract
# break on phrasing changes that did not alter a single claim.
assert_grep_fixed 'strict authenticated DoT (`DNSOverTLS=yes`)' \
    "$POLICY_FLAT" "DNS transport claim names the image default value"
assert_grep_fixed 'downgrade-capable' \
    "$POLICY_FLAT" "DNS compatibility mode is marked downgrade-capable"
assert_grep_fixed 'DNS/53 fallback' \
    "$POLICY_FLAT" "DNS compatibility mode discloses its plaintext fallback"
assert_grep_fixed 'never present it as strict or MITM-resistant' \
    "$POLICY_FLAT" "DNS compatibility mode may not be overclaimed"
assert_grep_fixed 'noid-dns-mode status' \
    "$POLICY_FLAT" "DNS section defers to the live selector, not this text"
assert_grep_fixed 'Normative' "$POLICY_FLAT" \
    "recommendations are not misclassified as factual uncertainty"
assert_grep_fixed 'Before editing, inspect the affected contracts, canonical source, surrounding control flow, and relevant tests.' \
    "$POLICY_FLAT" "review depth follows the affected behavioral surface"
assert_grep_fixed 'security-critical work requires the complete affected trust boundary, not' \
    "$POLICY_FLAT" "security review stays complete without unrelated-file busywork"
assert_not_grep 'Read every affected file before editing' "$POLICY_FLAT" \
    "large generated files are not read wholesale without a behavioral reason"
assert_grep_fixed '**External facts**: use the available retrieval tool' \
    "$POLICY_FLAT" "tool-neutral risk-based external verification"
assert_grep_fixed '**Cloud disclosure**: prompts, and any file content or tool result returned to a cloud model, become model context' \
    "$POLICY_FLAT" "cloud-model context is an explicit egress boundary"
assert_grep_fixed 'Authority for local host or repository work does not authorize outward-facing action.' \
    "$POLICY_FLAT" "local authority never silently expands to external publication"
assert_grep_fixed 'pre-existing user-owned adapter files are preserved and may differ.' \
    "$POLICY_FLAT" "existing user-owned agent policy is never overwritten"
assert_grep_fixed 'not state-level anonymity' "$POLICY_FLAT" \
    "product claims stay inside the declared threat model"
assert_grep_fixed 'Existing stronger controls remain valid defense in depth' \
    "$POLICY_FLAT" \
    "threat-model scope never justifies weakening existing layers"
assert_grep_fixed 'This is a multi-license repo, not repo-wide GPL.' \
    "$POLICY_FLAT" \
    "cross-component work starts from the real license inventory"
assert_grep_fixed 'inspect `LICENSING.md` and affected SPDX IDs.' \
    "$POLICY_FLAT" \
    "license work retains the canonical inventory and per-file gate"
assert_grep_fixed 'may coexist with GPL-3.0-or-later components as a separate work' \
    "$POLICY_FLAT" \
    "GPL-2.0-only BPF aggregation and combination boundaries stay distinct"
assert_grep_fixed '`/home` and `/var/lib/libvirt` are separate top-level' \
    "$POLICY_FLAT" "snapshot doctrine names both excluded subvolumes"
assert_grep_fixed '`.claude`, `.codex`, `.gemini`, `.cursor`, `.vscode`, or' \
    "$POLICY_FLAT" "all supported repository trust surfaces named"
assert_grep_fixed '**Treat AIDE as an evidence boundary and a user-owned trust decision.**' \
    "$POLICY_FLAT" "AIDE baseline ownership is explicit"
assert_grep_fixed 'but never run' "$POLICY_FLAT" \
    "the policy forbids agents from changing the AIDE baseline"
assert_grep_fixed 'do not launch it on the user' "$POLICY_FLAT" \
    "agents cannot launch the full update workflow"
assert_grep_fixed 'the workflow invokes the check-only `noid-aide-check.sh`' \
    "$POLICY_FLAT" "update documentation explicitly retains the AIDE invocation"
assert_grep_fixed 'never creates or replaces the AIDE baseline' \
    "$POLICY_FLAT" "update documentation truthfully limits AIDE to check-only"
for app_helper in \
    'Setup (`noid-welcome.sh --again`)' \
    '(`noid-update`), Tools (`noid-tools`) and Network (`noid-network`)'; do
    assert_grep_fixed "$app_helper" "$POLICY_FLAT" \
        "canonical policy names every stable first-party GUI/CLI pair"
done
assert_grep_fixed 'this is the silent-machine baseline, and nonessential background execution stays off' \
    "$POLICY_FLAT" "silent-machine default and its egress boundary are explicit"
assert_grep_fixed 'do not silently weaken those defaults' \
    "$POLICY_FLAT" "existing silent-machine opt-in boundary remains intact"
assert_grep_fixed 'audited backend over raw firewalld/nft edits' \
    "$POLICY_FLAT" "LAN exceptions use the cross-layer product transaction"
assert_grep_fixed 'sudo noid-lan-allow --add <IPv4> --direction outbound [--temp <MIN>]' \
    "$POLICY_FLAT" "agent has the exact outbound LAN grant entry point"
assert_grep_fixed 'sudo noid-lan-allow --add <IPv4> --direction <inbound|both> --protocol <tcp|udp> --ports <PORT|START-END> [--temp <MIN>]' \
    "$POLICY_FLAT" "agent has the exact inbound LAN grant boundary"
assert_grep_fixed 'sudo noid-lan-allow --revert' \
    "$POLICY_FLAT" "agent has the exact LAN revoke entry point"
assert_grep_fixed 'This is not arbitrary WAN allowlisting, port' \
    "$POLICY_FLAT" "LAN exception scope cannot be mistaken for WAN or forwarding"
assert_not_grep_extended 'WebSearch|single Write|Edit is fine|per-Edit' \
    "$POLICY_FLAT" \
    "canonical policy contains no Claude-specific tool or approval wording"
assert_not_grep_extended 'pnpm/bun do|npm via `ignore-scripts`|≤12-month' \
    "$POLICY_FLAT" \
    "canonical policy contains no stale package-manager or source-age rule"
assert_not_grep 'Shai-Hulud\|TanStack compromise\|axios post-install RAT\|PyPI typosquats\|uv shipped without\|20[0-9][0-9]-[0-9][0-9]' \
    "$POLICY_FLAT" \
    "canonical policy contains no dated incident or product-history inventory"
assert_grep_fixed 'Treat dependency lifecycle scripts and build hooks as code execution.' \
    "$POLICY_FLAT" \
    "canonical policy retains the stable lifecycle-code threat boundary"
assert_grep_fixed 'never infer behavior from the tool name, a calendar date, or a' \
    "$POLICY_FLAT" \
    "canonical policy rejects tool-name/date/default assumptions"
assert_grep_fixed 'approve only reviewed packages pinned to' \
    "$POLICY_FLAT" \
    "canonical policy retains scoped version-pinned approval guidance"
assert_grep_fixed 'and otherwise isolate the build.' \
    "$POLICY_FLAT" \
    "canonical policy requires isolation when granular controls are unavailable"

for adapter in \
    '/etc/skel/.codex/AGENTS.md' \
    '/etc/skel/.gemini/AGENTS.md' \
    '/etc/skel/.gemini/GEMINI.md' \
    '/root/.codex/AGENTS.md' \
    '/root/.gemini/AGENTS.md' \
    '/root/.gemini/GEMINI.md'; do
    assert_grep_fixed "ln -sfn /etc/claude-code/CLAUDE.md $adapter" "$KS_FILE" \
        "managed adapter: $adapter"
done
assert_grep_fixed 'cmp -s /etc/claude-code/CLAUDE.md "$adapter"' "$KS_FILE" \
    "build-time byte-identity verification"
assert_grep_fixed 'readlink "$adapter"' "$KS_FILE" \
    "build-time adapter-target verification"

# Existing accounts are reconciled once in user context. The helper may fill
# only absent paths; it must preserve user files/symlinks and unsafe adapter
# directories, and it must never install vendor-agent code.
extract_heredoc "$KS_FILE" AGENT_ADAPTER_HELPER_EOF \
    "$TMPDIR/noid-agent-policy-adapters" || _fail "existing-user adapter helper extraction"
extract_heredoc "$KS_FILE" AGENT_ADAPTER_UNIT_EOF \
    "$TMPDIR/noid-agent-policy-adapters.service" || _fail "existing-user adapter unit extraction"
chmod 0755 "$TMPDIR/noid-agent-policy-adapters"
chmod 0755 "$TMPDIR/noid-eligible-user"
assert_cmd_success "persistent-user/logind eligibility helper parses" \
    bash -n "$TMPDIR/noid-eligible-user"
assert_cmd_success "existing-user adapter helper parses" \
    bash -n "$TMPDIR/noid-agent-policy-adapters"
assert_grep_fixed 'ConditionUser=!@system' "$TMPDIR/noid-agent-policy-adapters.service" \
    "adapter retains systemd's system-identity defense in depth"
assert_grep_fixed 'ExecCondition=/usr/libexec/noid-eligible-user account' \
    "$TMPDIR/noid-agent-policy-adapters.service" \
    "adapter requires the root-owned persistent-account gate"
assert_grep_fixed 'UID_MIN' "$TMPDIR/noid-eligible-user" \
    "account gate reads the maintained local UID allocation floor"
assert_grep_fixed 'UID_MAX' "$TMPDIR/noid-eligible-user" \
    "account gate reads the maintained local UID allocation ceiling"
assert_grep_fixed '[[ $home == "/home/$name" ]]' "$TMPDIR/noid-eligible-user" \
    "transient non-home identities cannot pass the account gate"
assert_grep_fixed '[[ -d $home && ! -L $home && $(/usr/bin/stat -c %u "$home") == "$uid" ]]' \
    "$TMPDIR/noid-eligible-user" \
    "current-user consumers require a real UID-owned non-symlink home"
assert_grep_fixed 'Class "$properties") && [[ $value == user ]]' \
    "$TMPDIR/noid-eligible-user" \
    "graphical gate accepts only normal logind user sessions"
assert_grep_fixed 'case "$value" in wayland|x11)' "$TMPDIR/noid-eligible-user" \
    "graphical gate accepts only Wayland or X11 session types"
for required_state in \
    'Remote "$properties") && [[ $value == no ]]' \
    'Active "$properties") && [[ $value == yes ]]' \
    'State "$properties") && [[ $value == active ]]'; do
    assert_grep_fixed "$required_state" "$TMPDIR/noid-eligible-user" \
        "graphical gate pins local foreground session state"
done
assert_not_grep 'ConditionPathExists=!%h/.local/state/noid-privacy/agent-policy-adapters.done' \
    "$TMPDIR/noid-agent-policy-adapters.service" \
    "systemd cannot bypass validation of an existing one-shot record"
assert_grep_fixed 'validate_state()' "$TMPDIR/noid-agent-policy-adapters" \
    "adapter helper validates the closed one-shot schema"
assert_grep_fixed '600:$(id -u)' "$TMPDIR/noid-agent-policy-adapters" \
    "adapter helper binds the one-shot record to its user and private mode"
assert_grep_fixed 'ReadWritePaths=-%h' "$TMPDIR/noid-agent-policy-adapters.service" \
    "adapter service can mutate only the user home on a strict system view"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' \
    "$TMPDIR/noid-agent-policy-adapters.service" \
    "adapter retains its enforceable local-socket-only boundary"
assert_not_grep '^IPAddressDeny=' "$TMPDIR/noid-agent-policy-adapters.service" \
    "user unit makes no unenforceable IP firewall claim"
assert_file_executable "$ADAPTER_RUNTIME" \
    "three-pass adapter sandbox runtime gate is executable"
assert_file_executable "$CODEC_RUNTIME" \
    "three-pass codec/runtime gate is executable"
assert_cmd_success "codec/runtime gate is valid bash" bash -n "$CODEC_RUNTIME"
assert_grep_fixed 'relabel_output=$(restorecon -nv "$installed_path" 2>/dev/null)' \
    "$CODEC_RUNTIME" \
    "codec runtime asks restorecon to expose every proposed SELinux relabel"
assert_not_grep_fixed 'relabel_output=$(restorecon -n "$installed_path" 2>/dev/null)' \
    "$CODEC_RUNTIME" \
    "codec runtime does not use restorecon's silent passive-check mode"
for codec_anchor in \
        'dnf --cacheonly check --duplicates --dependencies' \
        '/usr/lib/sysimage/libdnf5' \
        'root:root:644:1' \
        'gstreamer1-plugin-openh264' \
        'VAProfileH264.*VAEntrypointVLD' \
        'VAProfileHEVCMain[[:space:]]*:[[:space:]]*VAEntrypointVLD' \
        'VAProfileVP9Profile0.*VAEntrypointVLD' \
        'VAProfileAV1Profile0.*VAEntrypointVLD'; do
    assert_grep_fixed "$codec_anchor" "$CODEC_RUNTIME" \
        "codec/runtime gate retains anchor: $codec_anchor"
done
for codec_invocation in \
        'live pristine' \
        'fresh-install pristine' \
        'fresh-install complete' \
        'reboot complete'; do
    assert_grep_fixed \
        "sudo bash tests/pre-ship/08-codec-runtime.sh $codec_invocation" \
        "$TEST_LEDGER" "codec runtime ledger retains: $codec_invocation"
done
assert_grep_fixed '`tests/pre-ship/08-codec-runtime.sh`' "$TEST_STRATEGY" \
    "test strategy defines the codec runtime evidence boundary"
assert_grep_fixed 'public read-only DNF5' "$RELEASE_PROCESS" \
    "release checklist requires readable package-system state"
assert_grep_fixed 'H.264/HEVC/VP9/AV1 FFmpeg and GStreamer decode' \
    "$RELEASE_PROCESS" "release checklist requires actual codec decode"
assert_cmd_success "adapter sandbox runtime gate parses" bash -n "$ADAPTER_RUNTIME"
for lifecycle in live fresh-install reboot; do
    assert_grep_fixed "$lifecycle" "$ADAPTER_RUNTIME" \
        "adapter runtime gate recognizes $lifecycle"
done
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' "$ADAPTER_RUNTIME" \
    "runtime gate exercises the retained address-family boundary"
assert_grep_fixed '/etc/systemd/user/default.target.wants/noid-agent-policy-adapters.service' \
    "$KS_FILE" "existing-user reconciliation is globally enabled"
assert_not_grep_extended 'claude-install|codex-install|codium.*install-extension|curl|wget' \
    "$TMPDIR/noid-agent-policy-adapters" \
    "policy backfill contains no vendor-agent installer or network client"

cat > "$TMPDIR/eligible-user-harness" <<'ELIGIBLE_HARNESS_EOF'
#!/bin/bash
set -euo pipefail
helper=$1
shift
# shellcheck source=/dev/null
. "$helper"
operation=$1
shift
case "$operation" in
    bounds) read_uid_bounds "$@" ;;
    account) account_record_is_eligible "$@" ;;
    session) session_record_is_eligible "$@" ;;
    *) exit 64 ;;
esac
ELIGIBLE_HARNESS_EOF
chmod 0755 "$TMPDIR/eligible-user-harness"
assert_cmd_success "eligibility pure-function harness parses" \
    bash -n "$TMPDIR/eligible-user-harness"
cat > "$TMPDIR/login.defs" <<'LOGIN_DEFS_FIXTURE_EOF'
# ignored historical example
# UID_MIN 500
UID_MIN 1000
UID_MAX 60000
LOGIN_DEFS_FIXTURE_EOF
uid_bounds=$(bash "$TMPDIR/eligible-user-harness" "$TMPDIR/noid-eligible-user" \
    bounds "$TMPDIR/login.defs")
assert_eq '1000 60000' "$uid_bounds" \
    "login.defs parser returns the exact active allocation range"
assert_cmd_success "canonical persistent human account is eligible" \
    bash "$TMPDIR/eligible-user-harness" "$TMPDIR/noid-eligible-user" account \
        1000 alice 1000 60000 'alice:x:1000:1000:Alice:/home/alice:/bin/bash'
assert_cmd_failure "gdm-greeter high UID is outside UID_MAX" \
    bash "$TMPDIR/eligible-user-harness" "$TMPDIR/noid-eligible-user" account \
        60579 gdm-greeter 1000 60000 \
        'gdm-greeter:x:60579:60579:GDM greeter:/run/gdm/home/gdm-greeter:/bin/bash'
assert_cmd_failure "GNOME Initial Setup system UID is below UID_MIN" \
    bash "$TMPDIR/eligible-user-harness" "$TMPDIR/noid-eligible-user" account \
        975 gnome-initial-setup 1000 60000 \
        'gnome-initial-setup:x:975:975:Initial Setup:/var/lib/gnome-initial-setup:/bin/bash'
assert_cmd_failure "transient runtime home is ineligible even inside the UID range" \
    bash "$TMPDIR/eligible-user-harness" "$TMPDIR/noid-eligible-user" account \
        1001 transient 1000 60000 \
        'transient:x:1001:1001:Transient:/run/user/1001:/bin/bash'
assert_cmd_failure "nologin account is never classified as human" \
    bash "$TMPDIR/eligible-user-harness" "$TMPDIR/noid-eligible-user" account \
        1001 service 1000 60000 \
        'service:x:1001:1001:Service:/home/service:/usr/sbin/nologin'

valid_session=$'State=active\nUser=1000\nRemote=no\nClass=user\nActive=yes\nType=wayland'
assert_cmd_success "active local Wayland Class=user session is eligible" \
    bash "$TMPDIR/eligible-user-harness" "$TMPDIR/noid-eligible-user" session \
        1000 "$valid_session"
assert_cmd_success "active local X11 Class=user session is eligible" \
    bash "$TMPDIR/eligible-user-harness" "$TMPDIR/noid-eligible-user" session \
        1000 "${valid_session/Type=wayland/Type=x11}"
for rejected_session in \
    "${valid_session/Class=user/Class=greeter}" \
    "${valid_session/Remote=no/Remote=yes}" \
    "${valid_session/Active=yes/Active=no}" \
    "${valid_session/State=active/State=online}" \
    "${valid_session/Type=wayland/Type=tty}" \
    "$valid_session"$'\nClass=user'; do
    assert_cmd_failure "non-exact graphical session record is rejected" \
        bash "$TMPDIR/eligible-user-harness" "$TMPDIR/noid-eligible-user" session \
            1000 "$rejected_session"
done

adapter_fixture="$TMPDIR/adapter-fixture"
adapter_home="$adapter_fixture/home"
adapter_canonical="$adapter_fixture/CLAUDE.md"
mkdir -p "$adapter_home/.gemini"
printf '%s\n' 'fixture canonical policy' > "$adapter_canonical"
printf '%s\n' 'user-owned Gemini context' > "$adapter_home/.gemini/GEMINI.md"
assert_cmd_success "existing user receives only missing safe policy adapters" \
    env NOID_TEST_MODE=1 NOID_TEST_AGENT_HOME="$adapter_home" \
        NOID_TEST_AGENT_CANONICAL="$adapter_canonical" \
        bash "$TMPDIR/noid-agent-policy-adapters"
assert_eq "$adapter_canonical" "$(readlink "$adapter_home/.codex/AGENTS.md")" \
    "missing Codex adapter links to the canonical policy"
assert_eq "$adapter_canonical" "$(readlink "$adapter_home/.gemini/AGENTS.md")" \
    "missing Gemini interoperability adapter links to the canonical policy"
assert_eq 'user-owned Gemini context' "$(cat "$adapter_home/.gemini/GEMINI.md")" \
    "pre-existing Gemini context is preserved byte-for-byte"
adapter_state="$adapter_home/.local/state/noid-privacy/agent-policy-adapters.done"
assert_eq 4 "$(wc -l < "$adapter_state")" \
    "one-time adapter record has a closed four-line schema"
assert_eq 600 "$(stat -c %a "$adapter_state")" \
    "one-time adapter record is private"
rm -f "$adapter_home/.codex/AGENTS.md"
assert_cmd_success "sealed adapter reconciliation is idempotent" \
    env NOID_TEST_MODE=1 NOID_TEST_AGENT_HOME="$adapter_home" \
        NOID_TEST_AGENT_CANONICAL="$adapter_canonical" \
        bash "$TMPDIR/noid-agent-policy-adapters"
if [ ! -e "$adapter_home/.codex/AGENTS.md" ] \
   && [ ! -L "$adapter_home/.codex/AGENTS.md" ]; then
    _pass "user-removed adapter is not recreated after the one-time seal"
else
    _fail "user-removed adapter was recreated after the one-time seal"
fi

cp "$adapter_state" "$adapter_state.good"
sed -i 's/^codex=.*/codex=unknown-open-value/' "$adapter_state"
assert_cmd_failure "invalid adapter state cannot masquerade as a sealed run" \
    env NOID_TEST_MODE=1 NOID_TEST_AGENT_HOME="$adapter_home" \
        NOID_TEST_AGENT_CANONICAL="$adapter_canonical" \
        bash "$TMPDIR/noid-agent-policy-adapters"
mv -fT "$adapter_state.good" "$adapter_state"

unsafe_home="$adapter_fixture/unsafe-home"
outside_dir="$adapter_fixture/outside"
mkdir -p "$unsafe_home" "$outside_dir"
ln -s "$outside_dir" "$unsafe_home/.codex"
assert_cmd_success "unsafe existing adapter directory is preserved and recorded" \
    env NOID_TEST_MODE=1 NOID_TEST_AGENT_HOME="$unsafe_home" \
        NOID_TEST_AGENT_CANONICAL="$adapter_canonical" \
        bash "$TMPDIR/noid-agent-policy-adapters"
assert_grep_fixed 'codex=skipped-unsafe-directory' \
    "$unsafe_home/.local/state/noid-privacy/agent-policy-adapters.done" \
    "unsafe Codex directory decision is explicit"
if [ ! -e "$outside_dir/AGENTS.md" ] && [ ! -L "$outside_dir/AGENTS.md" ]; then
    _pass "adapter helper never traverses a user-controlled directory symlink"
else
    _fail "adapter helper traversed a user-controlled directory symlink"
fi

# --- Step 8c.2 shared Codex CLI/IDE defaults -------------------------------
extract_heredoc "$KS_FILE" "CODEX_CONFIG_EOF" "$TMPDIR/codex-config.toml" \
    || _fail "Codex config.toml heredoc extraction"
assert_grep_fixed '/etc/codex/config.toml' "$KS_FILE"
for setting in \
    'approval_policy = "never"' \
    'sandbox_mode = "danger-full-access"' \
    'allow_login_shell = false' \
    'cli_auth_credentials_store = "keyring"' \
    'check_for_update_on_startup = false' \
    'web_search = "indexed"' \
    'inherit = "core"' \
    '[analytics]' \
    '[feedback]' \
    'enabled = false' \
    'log_user_prompt = false' \
    'exporter = "none"' \
    'trace_exporter = "none"' \
    'metrics_exporter = "none"'; do
    assert_grep_fixed "$setting" "$TMPDIR/codex-config.toml"
done
assert_not_grep '^\[sandbox_workspace_write\]$' "$TMPDIR/codex-config.toml" \
    "unrestricted Codex default carries no stale workspace sandbox table"
assert_not_grep 'network_access' "$TMPDIR/codex-config.toml" \
    "unrestricted Codex default carries no misleading child-network toggle"
assert_grep_fixed 'passwordless-sudo authorization' "$TMPDIR/ai-workspace.md" \
    "AI-workspace documentation names the bypass privilege consequence"
assert_grep_fixed '`approval_policy="never"` prevents both CLI and IDE approval prompts' \
    "$TMPDIR/ai-workspace.md" \
    "AI-workspace documentation names the shared Codex no-prompt default"
assert_grep_fixed 'set `web_search = "live"` in' "$KS_FILE" \
    "Codex documentation exposes the persistent user-owned live-search override"
assert_not_grep 'cat > /etc/codex/requirements.toml' "$KS_FILE" \
    "NoID Privacy does not silently constrain the documented Codex search override"
python3 -c "import tomllib; tomllib.load(open('$TMPDIR/codex-config.toml','rb'))" 2>/dev/null \
    && _pass "Codex config.toml valid TOML" \
    || _fail "Codex config.toml invalid TOML"

# --- Step 8c.3 installed AI-workspace documentation ------------------------
assert_grep_fixed '/usr/share/doc/noid-privacy/ai-workspace.md' "$KS_FILE" \
    "AI-workspace trust-boundary document is installed"
if cmp -s "$TMPDIR/ai-workspace.md" "$PROJECT_ROOT/docs/ai-workspace.md"; then
    _pass "installed AI-workspace doc is byte-identical to repository source"
else
    _fail "installed AI-workspace doc drifted from docs/ai-workspace.md"
fi
assert_cmd_success "regen-ai-workspace-doc.sh --check" \
    "$PROJECT_ROOT/scripts/regen-ai-workspace-doc.sh" --check
assert_grep_fixed 'bash scripts/regen-ai-workspace-doc.sh --check' \
    "$PROJECT_ROOT/.github/workflows/ci.yml" \
    "CI enforces AI-workspace source/heredoc parity"

# Exercise the generator's failure boundaries on isolated copies. Invalid
# options, ambiguous markers, and delimiter injection must never modify M08.
AI_GEN_DIR="$TMPDIR/ai-generator"
mkdir -p "$AI_GEN_DIR"
cp "$PROJECT_ROOT/docs/ai-workspace.md" "$AI_GEN_DIR/source.md"
cp "$KS_FILE" "$AI_GEN_DIR/module.ks"
AI_GEN=(env NOID_AI_WORKSPACE_SRC="$AI_GEN_DIR/source.md" \
    NOID_AI_WORKSPACE_M08="$AI_GEN_DIR/module.ks" \
    "$PROJECT_ROOT/scripts/regen-ai-workspace-doc.sh")
assert_cmd_success "AI-workspace generator fixture starts in sync" \
    "${AI_GEN[@]}" --check

before_hash=$(sha256sum "$AI_GEN_DIR/module.ks" | cut -d' ' -f1)
assert_cmd_failure "AI-workspace generator rejects unknown arguments" \
    "${AI_GEN[@]}" --typo
after_hash=$(sha256sum "$AI_GEN_DIR/module.ks" | cut -d' ' -f1)
[ "$before_hash" = "$after_hash" ] \
    && _pass "unknown generator argument leaves target unchanged" \
    || _fail "unknown generator argument modified target"

printf '%s\n' "# duplicate <<'AI_WORKSPACE_DOC_EOF'" >> "$AI_GEN_DIR/module.ks"
assert_cmd_failure "AI-workspace generator rejects duplicate opening markers" \
    "${AI_GEN[@]}" --check
cp "$KS_FILE" "$AI_GEN_DIR/module.ks"
printf '%s\n' 'AI_WORKSPACE_DOC_EOF' >> "$AI_GEN_DIR/source.md"
before_hash=$(sha256sum "$AI_GEN_DIR/module.ks" | cut -d' ' -f1)
assert_cmd_failure "AI-workspace generator rejects delimiter injection" \
    "${AI_GEN[@]}"
after_hash=$(sha256sum "$AI_GEN_DIR/module.ks" | cut -d' ' -f1)
[ "$before_hash" = "$after_hash" ] \
    && _pass "delimiter injection leaves target unchanged" \
    || _fail "delimiter injection modified target"

cp "$PROJECT_ROOT/docs/ai-workspace.md" "$AI_GEN_DIR/source.md"
printf '%s\n' '' '<!-- generator runtime fixture -->' >> "$AI_GEN_DIR/source.md"
assert_cmd_success "AI-workspace generator atomically repairs fixture drift" \
    "${AI_GEN[@]}"
assert_cmd_success "regenerated AI-workspace fixture is valid bash" \
    bash -n "$AI_GEN_DIR/module.ks"
assert_cmd_success "regenerated AI-workspace fixture passes parity check" \
    "${AI_GEN[@]}" --check

# --- Step 1e: wireplumber dir-perms + template single-source-of-truth ---
assert_grep_fixed 'chmod 0755 /etc/wireplumber/wireplumber.conf.d' "$KS_FILE"
assert_grep_fixed '/usr/share/doc/noid-privacy/wireplumber-disable-bluez.conf' "$KS_FILE"
# Step 1e deploys via `install` from template (not direct heredoc to /etc)
assert_grep_fixed 'install -m 0644 -o root -g root' "$KS_FILE"

# --- Step 1f: Privacy Toggle Infrastructure -----------------------------
# 1f.1 + 1f.2: toggle CLIs deployed via heredoc + executable
extract_heredoc "$KS_FILE" "NOID_TOGGLE_BT_EOF"   "$TMPDIR/toggle-bt"  \
    || _fail "NOID_TOGGLE_BT_EOF extraction"
extract_heredoc "$KS_FILE" "NOID_BT_APPLY_EOF" "$TMPDIR/bt-apply-default" \
    || _fail "NOID_BT_APPLY_EOF extraction"
extract_heredoc "$KS_FILE" "NOID_TOGGLE_LOC_EOF"  "$TMPDIR/toggle-loc" \
    || _fail "NOID_TOGGLE_LOC_EOF extraction"
extract_heredoc "$KS_FILE" "NOID_LOC_APPLY_EOF" "$TMPDIR/location-apply" \
    || _fail "NOID_LOC_APPLY_EOF extraction"
extract_heredoc "$KS_FILE" "NOID_LOC_SUDO_EOF" "$TMPDIR/location-sudoers" \
    || _fail "NOID_LOC_SUDO_EOF extraction"
extract_heredoc "$KS_FILE" "NOID_LOC_WATCHER_EOF" "$TMPDIR/location-watch" \
    || _fail "NOID_LOC_WATCHER_EOF extraction"
extract_heredoc "$KS_FILE" "NOID_LOC_SVC_EOF" "$TMPDIR/location-sync.service" \
    || _fail "NOID_LOC_SVC_EOF extraction"
extract_heredoc "$KS_FILE" "COMPLETE_SETUP_EOF" "$TMPDIR/complete-setup" \
    || _fail "COMPLETE_SETUP_EOF extraction"
extract_heredoc "$FORMAT_KS" "FMT_EOF" "$TMPDIR/installer-format" \
    || _fail "shared installer format extraction"
extract_heredoc "$KS_FILE" "POLKIT_TOGGLE_EOF"    "$TMPDIR/polkit.rules" \
    || _fail "POLKIT_TOGGLE_EOF extraction"
sed -n \
    '/^if ! visudo -cf \/etc\/sudoers.d\/49-noid-location-apply/,/^fi$/p' \
    "$KS_FILE" > "$TMPDIR/location-sudoers-publication.block"
assert_grep_fixed 'rm -f /etc/sudoers.d/49-noid-location-apply' \
    "$TMPDIR/location-sudoers-publication.block" \
    "invalid location sudoers candidate is removed"
assert_grep_fixed 'exit 1' "$TMPDIR/location-sudoers-publication.block" \
    "invalid location sudoers candidate aborts the compose"
assert_grep_fixed 'location-sync sudoers capability missing or invalid' \
    "$KS_FILE" \
    "final verification cannot miss an absent location sudoers rule"
assert_grep_fixed 'visudo -cf "$location_sudoers"' "$KS_FILE" \
    "final verification reparses the installed location sudoers rule"

# CLIs must be syntactically clean bash
bash -n "$TMPDIR/toggle-bt"  || _fail "noid-toggle-bluetooth bash syntax"
bash -n "$TMPDIR/bt-apply-default" || _fail "Bluetooth udev helper bash syntax"
bash -n "$TMPDIR/toggle-loc" || _fail "noid-toggle-location bash syntax"
bash -n "$TMPDIR/location-apply" || _fail "location apply bash syntax"
bash -n "$TMPDIR/location-watch" || _fail "location watcher bash syntax"
bash -n "$TMPDIR/complete-setup" || _fail "complete setup bash syntax"
sed -n '/^return_to_menu_prompt()/,/^}$/p' "$TMPDIR/complete-setup" \
    > "$TMPDIR/return-to-menu-prompt"
assert_grep_fixed 'if [ ! -t 0 ]; then' "$TMPDIR/return-to-menu-prompt" \
    "codec completion prompt detects non-interactive stdin"
assert_grep_fixed \
    'read -rp "Press Enter to close terminal (welcome menu still open) ... " _ans' \
    "$TMPDIR/return-to-menu-prompt" \
    "existing-welcome close prompt keeps terminal EOF non-fatal"
assert_grep_fixed '|| return 0' "$TMPDIR/return-to-menu-prompt" \
    "existing-welcome terminal EOF preserves successful operation status"
assert_grep_fixed 'read -rp "Re-open welcome menu? [Y/n] " ans || ans=n' \
    "$TMPDIR/return-to-menu-prompt" \
    "standalone terminal EOF selects the non-mutating close path"
assert_cmd_success "codec completion prompt treats stdin EOF as presentation-only" \
    bash -c '. "$1"; return_to_menu_prompt' _ \
        "$TMPDIR/return-to-menu-prompt" </dev/null
assert_grep_fixed 'LOCATION_SCHEMA="org.gnome.system.location"' \
    "$TMPDIR/toggle-loc" "location CLI keeps schema as one exact argument"
assert_grep_fixed 'LOCATION_KEY="enabled"' "$TMPDIR/toggle-loc" \
    "location CLI keeps key as one exact argument"
assert_grep_fixed 'gset set "$LOCATION_SCHEMA" "$LOCATION_KEY" true' \
    "$TMPDIR/toggle-loc" "location enable passes quoted schema and key arguments"
assert_grep_fixed 'gset set "$LOCATION_SCHEMA" "$LOCATION_KEY" false' \
    "$TMPDIR/toggle-loc" "location disable passes quoted schema and key arguments"
assert_grep_fixed 'gset get "$LOCATION_SCHEMA" "$LOCATION_KEY"' \
    "$TMPDIR/toggle-loc" "location status passes quoted schema and key arguments"
assert_grep_fixed 'if [ "$(id -u)" -eq 0 ]; then' "$TMPDIR/toggle-loc" \
    "plain-user location actions never re-enter sudo as the same user"
assert_not_grep 'gset \(set\|get\) \$KEY' "$TMPDIR/toggle-loc" \
    "location CLI has no implicit word-splitting argument contract"
assert_eq 2 "$(grep -cF "GPU_CONTROLLER_RE=' (VGA|3D|Display) (compatible )?controller'" \
    "$KS_FILE")" "codec runtime and dry-run share the exact PCI display-class regex"
broad_gpu_pattern='grep -iE " (VGA|3D|Display)"'
assert_not_grep "$broad_gpu_pattern" "$TMPDIR/firstboot.sh" \
    "codec runtime rejects broad non-controller display-class matches"
assert_not_grep "$broad_gpu_pattern" "$TMPDIR/complete-setup" \
    "codec dry-run rejects broad non-controller display-class matches"
gpu_controller_re=' (VGA|3D|Display) (compatible )?controller'
gpu_fixture=$(
    printf '%s\n' \
        '00:02.0 VGA compatible controller: Intel fixture' \
        '01:00.0 3D controller: NVIDIA fixture' \
        '02:00.0 Display controller: AMD fixture' \
        '03:00.0 Display memory controller: Intel false-positive fixture' |
        grep -iE "$gpu_controller_re"
)
assert_eq 3 "$(wc -l <<< "$gpu_fixture")" \
    "exact PCI display-class regex accepts all three real controller spellings"
printf '%s\n' "$gpu_fixture" > "$TMPDIR/gpu-controller-matches"
assert_not_grep 'false-positive fixture' "$TMPDIR/gpu-controller-matches" \
    "exact PCI display-class regex rejects a broad Display substring"
assert_grep_fixed 'NOID_WELCOME_SPAWN' "$TMPDIR/complete-setup" \
    "welcome-spawned runs skip the standalone hold (wrapper owns the prompt)"
assert_grep_fixed 'FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh' \
    "$TMPDIR/complete-setup" \
    "codec wrapper shares the Claude/Codex installer presentation"
assert_grep_fixed 'HTTPS metalinks may select HTTP or HTTPS Fedora/RPM Fusion mirrors' \
    "$TMPDIR/complete-setup" \
    "codec consent text discloses the real mirror-transport boundary"
assert_not_grep 'RPM Fusion + fedora-cisco-openh264 over HTTPS' \
    "$TMPDIR/complete-setup" \
    "codec consent text does not promise HTTPS for a metalink-selected mirror"
assert_grep_fixed '"$SUDO" -v' "$TMPDIR/complete-setup" \
    "codec wrapper authorizes once before starting the transaction"
assert_grep_fixed '"$SUDO" "$SYSTEMCTL" start "$SERVICE" &' \
    "$TMPDIR/complete-setup" \
    "codec wrapper starts the blocking oneshot asynchronously for live display"
assert_grep_fixed '--pid="$service_pid" --sleep-interval=0.2' \
    "$TMPDIR/complete-setup" \
    "codec live log follows the exact systemctl client lifecycle"
assert_grep_fixed '-n "+$first_new_line" -F "$LOG_FILE"' \
    "$TMPDIR/complete-setup" \
    "codec live log starts after prior attempts and survives rotation"
assert_grep_fixed 'while ! valid_live_log && kill -0 "$service_pid"' \
    "$TMPDIR/complete-setup" \
    "codec first-run log follower waits for the service-owned safe log"
assert_grep_fixed 'The service returned success but its private log is missing or unsafe.' \
    "$TMPDIR/complete-setup" \
    "codec wrapper makes the private live log a successful-run postcondition"
assert_grep_fixed 'wait "$service_pid"' "$TMPDIR/complete-setup" \
    "codec wrapper collects the authoritative start exit status"
assert_grep_fixed 'if [ "$start_rc" -ne 0 ]' "$TMPDIR/complete-setup" \
    "codec wrapper keeps service failure distinct from log-follow failure"

# Runtime UI regression: the real GNU tail implementation follows only lines
# from this invocation, visibly streams both task updates, and terminates with
# the exact background systemctl client. A failed start must retain its real
# exit status even though the live-log follower itself completed normally.
# NoID Privacy mounts /tmp noexec by design. These fixture commands are executed
# directly (not through `bash path`), so place only this bounded harness under
# the supported executable scratch tree.
CODEC_UI_ROOT=$(mktemp -d /var/tmp/noid-codec-ui.XXXXXX)
mkdir -p "$CODEC_UI_ROOT/bin"
cp "$TMPDIR/complete-setup" "$CODEC_UI_ROOT/complete-setup"
cp "$TMPDIR/installer-format" "$CODEC_UI_ROOT/installer-format"
sed -i \
    -e "s|^FMT_LIB=.*|FMT_LIB=\"$CODEC_UI_ROOT/installer-format\"|" \
    -e "s|^FLAG_FILE=.*|FLAG_FILE=\"$CODEC_UI_ROOT/done.flag\"|" \
    -e "s|^LOG_FILE=.*|LOG_FILE=\"$CODEC_UI_ROOT/transaction.log\"|" \
    -e "s|^SUDO=.*|SUDO=\"$CODEC_UI_ROOT/bin/sudo\"|" \
    -e "s|^SYSTEMCTL=.*|SYSTEMCTL=\"$CODEC_UI_ROOT/bin/systemctl\"|" \
    -e "s|^EXPECTED_RECEIPT_UID=.*|EXPECTED_RECEIPT_UID=$(id -u)|" \
    -e "s|^EXPECTED_RECEIPT_GID=.*|EXPECTED_RECEIPT_GID=$(id -g)|" \
    -e 's|^if \[ "$(id -u)" -eq 0 \]; then$|if false; then  # fixture: identity neutralised|' \
    "$CODEC_UI_ROOT/complete-setup"
# The shipped helper pins PATH=/usr/sbin:/usr/bin:/sbin:/bin and exports it
# before its root check, so a PATH-injected `id` shim is discarded and the real
# uid decides the branch -- unlike SUDO= and SYSTEMCTL=, which are absolute
# variables the sed above can redirect. The former shim was therefore dead code
# and the whole codec-UI block failed whenever the suite ran as root, which is
# exactly how .github/workflows/ci.yml runs it inside container: fedora:44.
# Neutralise the branch in the fixture copy and prove both sides of the
# substitution, so a reworded production guard cannot turn this into a no-op.
assert_grep_fixed 'if false; then  # fixture: identity neutralised' \
    "$CODEC_UI_ROOT/complete-setup" \
    "codec UI fixture installs its explicit identity neutralisation"
assert_not_grep 'if \[ "$(id -u)" -eq 0 \]; then' \
    "$CODEC_UI_ROOT/complete-setup" \
    "codec UI fixture no longer resolves the production root check"
cat > "$CODEC_UI_ROOT/bin/sudo" <<'CODEC_SUDO_EOF'
#!/bin/bash
if [ "${1:-}" = "-v" ]; then
    exit "${CODEC_AUTH_RC:-0}"
fi
exec "$@"
CODEC_SUDO_EOF
cat > "$CODEC_UI_ROOT/bin/systemctl" <<'CODEC_SYSTEMCTL_EOF'
#!/bin/bash
case "${1:-}" in
    start)
        if [ "${CODEC_FIXTURE_DELAY_LOG:-0}" = 1 ]; then
            sleep 0.1
        fi
        if [ ! -e "$CODEC_FIXTURE_LOG" ]; then
            install -m 0600 /dev/null "$CODEC_FIXTURE_LOG"
        fi
        printf '%s\n' 'fixture: task 1 started' >> "$CODEC_FIXTURE_LOG"
        sleep 0.2
        if [ "${CODEC_FIXTURE_MODE:-success}" = fail ]; then
            printf '%s\n' 'fixture: task 2 failed' >> "$CODEC_FIXTURE_LOG"
            exit 7
        fi
        printf '%s\n' 'fixture: task 2 finished' >> "$CODEC_FIXTURE_LOG"
        install -m 0600 /dev/null "$CODEC_FIXTURE_FLAG"
        ;;
    status)
        printf '%s\n' 'fixture: failed service status'
        exit 3
        ;;
    *)
        exit 2
        ;;
esac
CODEC_SYSTEMCTL_EOF
chmod 0755 "$CODEC_UI_ROOT/complete-setup" "$CODEC_UI_ROOT/bin/"*
export CODEC_FIXTURE_LOG="$CODEC_UI_ROOT/transaction.log"
export CODEC_FIXTURE_FLAG="$CODEC_UI_ROOT/done.flag"
printf '%s\n' 'fixture: old attempt must stay hidden' > "$CODEC_FIXTURE_LOG"
chmod 0600 "$CODEC_FIXTURE_LOG"
if env PATH="$CODEC_UI_ROOT/bin:$PATH" NO_COLOR=1 NOID_WELCOME_SPAWN=1 \
        CODEC_FIXTURE_MODE=success \
        bash "$CODEC_UI_ROOT/complete-setup" > "$CODEC_UI_ROOT/success.out" 2>&1; then
    _pass "codec UI fixture completes a successful live transaction"
else
    sed 's/^/  | /' "$CODEC_UI_ROOT/success.out" >&2
    _fail "codec UI fixture failed its successful live transaction"
fi
for expected in \
        '[1/4] Review' \
        '[2/4] Authorization' \
        '[3/4] Install · live output' \
        'fixture: task 1 started' \
        'fixture: task 2 finished' \
        '[4/4] Verification' \
        'Media codec setup complete'; do
    assert_grep_fixed "$expected" "$CODEC_UI_ROOT/success.out" \
        "successful codec UI shows: $expected"
done
assert_not_grep 'old attempt must stay hidden' "$CODEC_UI_ROOT/success.out" \
    "codec UI never replays output from an earlier attempt"
assert_file_exists "$CODEC_UI_ROOT/done.flag" \
    "successful codec UI fixture receives its completion receipt"

rm -f "$CODEC_UI_ROOT/done.flag" "$CODEC_FIXTURE_LOG"
if env PATH="$CODEC_UI_ROOT/bin:$PATH" NO_COLOR=1 NOID_WELCOME_SPAWN=1 \
        CODEC_FIXTURE_MODE=success CODEC_FIXTURE_DELAY_LOG=1 \
        bash "$CODEC_UI_ROOT/complete-setup" \
        > "$CODEC_UI_ROOT/first-run.out" 2>&1; then
    _pass "codec UI fixture synchronizes a missing first-run log"
else
    sed 's/^/  | /' "$CODEC_UI_ROOT/first-run.out" >&2
    _fail "codec UI fixture failed its missing first-run log transaction"
fi
assert_grep_fixed 'fixture: task 1 started' "$CODEC_UI_ROOT/first-run.out" \
    "codec first-run UI retains the first task line"
assert_grep_fixed 'fixture: task 2 finished' "$CODEC_UI_ROOT/first-run.out" \
    "codec first-run UI retains the final task line"
assert_not_grep 'tail: cannot open' "$CODEC_UI_ROOT/first-run.out" \
    "codec first-run UI has no missing-log race"
assert_not_grep 'Live log display ended with rc=' "$CODEC_UI_ROOT/first-run.out" \
    "codec first-run UI has no false follower warning"

rm -f "$CODEC_UI_ROOT/done.flag"
printf '%s\n' 'fixture: prior failure must stay hidden' > "$CODEC_FIXTURE_LOG"
if env PATH="$CODEC_UI_ROOT/bin:$PATH" NO_COLOR=1 NOID_WELCOME_SPAWN=1 \
        CODEC_FIXTURE_MODE=fail \
        bash "$CODEC_UI_ROOT/complete-setup" > "$CODEC_UI_ROOT/failure.out" 2>&1; then
    _fail "codec UI fixture must propagate a failed service start"
else
    _pass "codec UI fixture propagates a failed service start"
fi
assert_grep_fixed 'fixture: task 2 failed' "$CODEC_UI_ROOT/failure.out" \
    "failed codec task remains visible in the live output"
assert_grep_fixed 'failed (rc=7)' "$CODEC_UI_ROOT/failure.out" \
    "codec UI reports the exact service-start exit status"
assert_grep_fixed 'fixture: failed service status' "$CODEC_UI_ROOT/failure.out" \
    "codec UI adds bounded service status after a failure"
assert_not_grep 'prior failure must stay hidden' "$CODEC_UI_ROOT/failure.out" \
    "failed codec UI also excludes an earlier attempt"
assert_not_grep 'Media codec setup complete' "$CODEC_UI_ROOT/failure.out" \
    "failed codec UI never prints a success summary"
unset CODEC_FIXTURE_LOG CODEC_FIXTURE_FLAG
case "$CODEC_UI_ROOT" in
    /var/tmp/noid-codec-ui.*) rm -rf -- "$CODEC_UI_ROOT" ;;
    *) _fail "codec UI fixture cleanup path escaped /var/tmp" ;;
esac
unset CODEC_UI_ROOT

# CLI install paths + perms
assert_grep_fixed 'chmod 0755 /usr/local/sbin/noid-toggle-bluetooth' "$KS_FILE"
assert_grep_fixed 'chmod 0755 /usr/local/sbin/noid-toggle-location'  "$KS_FILE"

# 1f.3: only privileged toggles belong in the exact pkexec program list;
# Location is a per-user gsetting and must not acquire a redundant root path.
assert_grep_fixed 'return polkit.Result.AUTH_ADMIN;'                     "$TMPDIR/polkit.rules"
assert_not_grep 'return polkit[.]Result[.]AUTH_ADMIN_KEEP;'             "$TMPDIR/polkit.rules" \
    "pkexec program-variable rule never retains cross-program authorization"
assert_grep_fixed 'a retained authorization for the same action identifier' \
    "$TMPDIR/polkit.rules" "polkit variable-cache threat is documented"
assert_grep_fixed 'while `program` is only a variable'                   "$TMPDIR/polkit.rules" \
    "pkexec program lookup is not mistaken for a distinct action identifier"
# Match the array element, not the bare path. Every program is also named in
# the rule file's comment header, so a plain path grep stays green even if the
# `allowed` array is emptied outright — the allowlist is what grants the
# authorization, and it is what has to be asserted.
assert_grep_fixed '"/usr/local/sbin/noid-toggle-bluetooth",'             "$TMPDIR/polkit.rules" \
    "the Bluetooth toggle is in the allowlist itself, not only in its header"
# M05 Step 4b. The Setup switch and the Tools row both reach this CLI through
# _privileged_argv, whose polkit fallback is the only route on a system with no
# passwordless sudoers rule for it — an unpinned program leaves the switch dead.
assert_grep_fixed '"/usr/local/sbin/noid-toggle-printing",'              "$TMPDIR/polkit.rules" \
    "the printing toggle has a polkit fallback route"
assert_grep_fixed '/usr/local/sbin/noid-dns-mode'                       "$TMPDIR/polkit.rules" \
    "global DNS transport helper is an exact uncached pkexec target"
assert_not_grep '/usr/local/sbin/noid-toggle-location'                   "$TMPDIR/polkit.rules"
assert_grep_fixed 'subject.local && subject.active && subject.isInGroup' "$TMPDIR/polkit.rules"
assert_grep_fixed '/etc/polkit-1/rules.d/60-noid-toggle-privacy-services.rules' "$KS_FILE"

# 1f.4: only Bluetooth has a durable flag.
assert_grep_fixed 'mv -fT -- "$BT_DEFAULT_TMP" "$BT_DEFAULT_FLAG"' "$KS_FILE" \
    "Bluetooth default receipt is published atomically"
assert_not_grep 'touch /var/lib/noid-privacy/bluetooth-disabled.flag' "$KS_FILE" \
    "Bluetooth default receipt never follows a pre-created symlink"
assert_grep_fixed 'sync -- "$BT_STATE_DIR"' "$KS_FILE" \
    "Bluetooth default receipt is durably published"
assert_not_grep 'location-disabled.flag' "$KS_FILE" \
    "Location has no stale flag layer"

# Sanity: BT CLI multi-layer state machine has all layers. bluetooth.service
# is Type=dbus and has no [Install] section, so the correct operation is a
# verified direct start, not a silently failing `enable --now`.
for layer in 'systemctl unmask "\$SERVICE"' \
             'systemctl start "\$SERVICE"' \
             'rm -f -- "\$WPCFG"' \
             'rfkill unblock bluetooth' \
             'rm -f -- "\$FLAG"' \
             'restore_bt_disabled_state'; do
    assert_grep_extended "$layer" "$TMPDIR/toggle-bt"
done
assert_grep_fixed 'set -euo pipefail' "$TMPDIR/toggle-bt" \
    "privileged Bluetooth transitions use strict error propagation"
assert_grep_fixed 'mv -fT -- "$candidate" "$FLAG"' "$TMPDIR/toggle-bt" \
    "Bluetooth runtime flag publication is atomic"
assert_grep_fixed 'mv -fT -- "$candidate" "$WPCFG"' "$TMPDIR/toggle-bt" \
    "Bluetooth runtime WirePlumber policy publication is atomic"
assert_grep_fixed 'cmp -s -- "$WPCFG_TEMPLATE" "$WPCFG"' "$TMPDIR/toggle-bt" \
    "Bluetooth status and mutation validate exact WirePlumber policy bytes"
assert_grep_fixed 'matchpathcon -V "$1"' "$TMPDIR/toggle-bt" \
    "Bluetooth status and mutation validate SELinux path policy"
assert_not_grep 'touch "$FLAG"' "$TMPDIR/toggle-bt" \
    "Bluetooth runtime never follows a pre-created flag symlink"
assert_not_grep 'systemctl enable --now "\$SERVICE"' "$TMPDIR/toggle-bt" \
    "Type=dbus Bluetooth service is not falsely enabled"
assert_not_grep 'systemctl start "\$SERVICE".*|| true' "$TMPDIR/toggle-bt" \
    "Bluetooth start failure is not swallowed"
assert_grep_fixed 'user WirePlumber restart failed; restoring disabled state' \
    "$TMPDIR/toggle-bt" \
    "Bluetooth enable never reports success with stale user-session policy"
assert_not_grep 'WARN: user WirePlumber restart failed' "$TMPDIR/toggle-bt" \
    "Bluetooth disable never downgrades a stale user-session policy to success"
assert_grep_fixed 'Bluetooth disable postcondition failed' "$TMPDIR/toggle-bt" \
    "Bluetooth off path verifies final service/radio state"
assert_grep_fixed 'user opt-in via this CLI or noid-welcome GTK4' \
    "$TMPDIR/toggle-bt" \
    "only wired paths are documented as authoritative Bluetooth opt-ins"
assert_not_grep 'via this CLI, noid-welcome GTK4, or GNOME Settings' \
    "$TMPDIR/toggle-bt" \
    "GNOME rfkill toggle is not conflated with the multi-layer state machine"
assert_grep_fixed 'rfkill_all_blocked' "$TMPDIR/toggle-bt" \
    "Bluetooth disabled state checks every controller"
assert_grep_fixed 'rfkill_all_unblocked' "$TMPDIR/toggle-bt" \
    "Bluetooth enabled state checks every controller"
# assert_not_grep uses basic grep syntax: an unescaped `|` is literal there.
# Escaping both pipes creates BRE alternations (including empty branches),
# which makes the assertion match every file and report a false failure.
assert_not_grep '"\$RFKILL" block bluetooth 2>/dev/null || true' "$KS_FILE" \
    "udev Bluetooth enforcer does not hide rfkill failure"
assert_not_grep 'if rfkill list bluetooth >/dev/null 2>&1' "$KS_FILE" \
    "installer VM empty-success rfkill status is not mistaken for target hardware"
assert_grep_fixed '/usr/bin/rfkill block bluetooth' "$KS_FILE" \
    "privileged udev Bluetooth helper uses the package-owned absolute binary"
assert_not_grep 'command -v rfkill' "$KS_FILE" \
    "privileged udev Bluetooth helper does not search a mutable PATH"
assert_grep_fixed 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' \
    "$TMPDIR/bt-apply-default" \
    "privileged udev Bluetooth helper closes its command path"
assert_grep_fixed 'if [ "$#" -ne 0 ]; then' "$TMPDIR/bt-apply-default" \
    "privileged udev Bluetooth helper requires an argumentless invocation"
assert_cmd_success "Bluetooth udev argument gate precedes flag and rfkill state" \
    awk '
        /^if \[ "\$#" -ne 0 \]; then$/ { gate = NR }
        /^FLAG=/ { flag = NR }
        /\/usr\/bin\/rfkill block bluetooth/ { rfkill = NR }
        END { exit !(gate && flag && rfkill && gate < flag && flag < rfkill) }
    ' "$TMPDIR/bt-apply-default"
assert_grep_fixed 'target default is enforced on rfkill add/change events' "$KS_FILE" \
    "build log states the target-relevant Bluetooth enforcement boundary"
assert_grep_fixed 'udevadm control --reload-rules' "$KS_FILE" \
    "Bluetooth persistence reloads udev rules"

# Sanity: Location CLI is the gsettings model (camera/microphone parity)
for layer in 'LOCATION_SCHEMA="org\.gnome\.system\.location"' \
             'gset set "\$LOCATION_SCHEMA" "\$LOCATION_KEY" true' \
             'gset set "\$LOCATION_SCHEMA" "\$LOCATION_KEY" false' \
             'gsettings'; do
    assert_grep_extended "$layer" "$TMPDIR/toggle-loc"
done
assert_not_grep 'sudo -n /usr/local/sbin/noid-location-apply.*|| true' \
    "$TMPDIR/location-watch" \
    "location watcher does not hide reconciliation failure"
assert_grep_fixed 'user service will retry' "$TMPDIR/location-watch" \
    "location watcher makes failed reconciliation visible"
assert_grep_fixed 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' \
    "$TMPDIR/location-apply" \
    "privileged location helper pins its command search path"
assert_grep_fixed 'unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME' \
    "$TMPDIR/location-apply" \
    "privileged location helper removes interpreter injection variables"
assert_grep_fixed '[ "$(id -u)" -eq 0 ]' "$TMPDIR/location-apply" \
    "privileged location helper requires UID 0"
assert_grep_fixed '[ "$#" -eq 1 ]' "$TMPDIR/location-apply" \
    "privileged location helper enforces exactly one argument"
assert_grep_fixed '[ $((8#$mode & 0022)) -eq 0 ]' "$TMPDIR/location-apply" \
    "privileged location helper rejects writable configuration parents"
assert_grep_fixed '/usr/bin/mktemp "$OVERRIDE_DIR/.90-noid-location.conf.XXXXXX"' \
    "$TMPDIR/location-apply" \
    "disabled-location policy is staged inside the trusted destination"
assert_grep_fixed '/usr/bin/mv -fT -- "$tmp" "$OVERRIDE"' \
    "$TMPDIR/location-apply" \
    "disabled-location policy replaces a symlink instead of following it"
assert_grep_fixed '/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin' \
    "$TMPDIR/location-apply" \
    "GeoClue restart receives an empty controlled environment"
assert_cmd_success "location sudoers exception passes the native parser" \
    visudo -cf "$TMPDIR/location-sudoers"
assert_eq 1 "$(grep -cEv '^[[:space:]]*(#|$)' "$TMPDIR/location-sudoers")" \
    "location sudoers contains exactly one effective rule"
assert_grep_fixed '%wheel ALL=(root) NOPASSWD: /usr/local/sbin/noid-location-apply true, /usr/local/sbin/noid-location-apply false' \
    "$TMPDIR/location-sudoers" \
    "location sudoers grants only the two exact boolean invocations"
assert_grep_fixed "ExecCondition=/usr/bin/bash -c '/usr/bin/id -nG | /usr/bin/grep -qw wheel'" \
    "$TMPDIR/location-sync.service" \
    "global location watcher skips GDM/GIS and non-wheel sessions cleanly"
assert_not_grep 'systemctl try-restart geoclue.service.*|| true' \
    "$TMPDIR/location-apply" \
    "active geoclue restart failure is not swallowed"
assert_not_grep 'systemctl start noid-firstboot-setup.service || true' \
    "$TMPDIR/complete-setup" \
    "complete-setup does not hide oneshot failure"
assert_not_grep 'retry at next boot' "$TMPDIR/firstboot.sh" \
    "disabled codec service never promises retry at next boot"
assert_not_grep 'retries next boot' "$TMPDIR/firstboot.sh" \
    "disabled codec service never promises retries next boot"
assert_grep_fixed 'rerun noid-complete-setup.sh' "$TMPDIR/firstboot.sh" \
    "codec failure gives the truthful manual retry path"

# Gaming mode must never claim success after a failed BLS or SELinux update.
# -E is not decoration: without errtrace the rollback trap is not inherited by
# function bodies, so an M01 failure inside set_persistent_mode would abort
# with the SELinux W^X relaxation already made permanent and no rollback.
assert_grep_fixed 'set -Eeuo pipefail' "$TMPDIR/toggle-gaming" \
    "gaming toggle uses strict error propagation with errtrace"
assert_grep_fixed "trap 'rollback_state \$?' ERR" "$TMPDIR/toggle-gaming" \
    "gaming toggle arms the rollback trap it depends on"
assert_grep_fixed 'FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh' \
    "$TMPDIR/toggle-gaming" \
    "Gaming Mode shares the Setup installer presentation"
assert_grep_fixed 'fmt_banner "NoID Privacy Gaming Mode"' \
    "$TMPDIR/toggle-gaming" \
    "Gaming Mode has a consistent terminal identity"
assert_grep_fixed 'fmt_step 1 3 "Apply + verify compatibility policy"' \
    "$TMPDIR/toggle-gaming" \
    "Gaming Mode prepares policy before any package work"
assert_grep_fixed 'fmt_step 2 3 "Install Steam"' "$TMPDIR/toggle-gaming" \
    "Gaming Mode exposes the potentially long post-reboot package phase"
assert_grep_fixed 'fmt_step 2 3 "Defer Steam until 32-bit execution is live"' \
    "$TMPDIR/toggle-gaming" \
    "Gaming Mode names the mandatory pre-install reboot boundary"
assert_grep_fixed 'fmt_done "Gaming mode enabled · Steam verified"' \
    "$TMPDIR/toggle-gaming" \
    "Gaming Mode ends with a concise verified summary"
assert_grep_fixed 'mapfile -t canonical_lines < /etc/kernel/cmdline' \
    "$TMPDIR/toggle-gaming" \
    "unprivileged Gaming status reads kernel-install's canonical source"
assert_grep_fixed 'if [ "$(id -u)" -eq 0 ]; then' "$TMPDIR/toggle-gaming" \
    "privileged Gaming transitions retain exact BLS inspection"
assert_grep_fixed "grep -qw -- 'vdso32=1'" "$TMPDIR/toggle-gaming" \
    "live Gaming state requires the vDSO32 compatibility token"
assert_grep_fixed "grep -qw -- 'ia32_emulation=0'" "$TMPDIR/toggle-gaming" \
    "live Gaming state rejects contradictory ia32 tokens"
assert_grep_fixed 'Gaming Mode changes are unavailable on transient Live media' \
    "$TMPDIR/toggle-gaming" \
    "Gaming mutations reject the transient Live overlay"
assert_grep_fixed "persist='not applicable (Live media)'" \
    "$TMPDIR/toggle-gaming" \
    "Gaming status does not treat Live installer BLS as a next boot"
assert_grep_fixed 'Live media: Gaming Mode unavailable · hardened runtime active' \
    "$TMPDIR/toggle-gaming" \
    "Gaming status reports the exact hardened Live boundary"
assert_eq 2 "$(grep -cFx '        require_installed_system' \
        "$TMPDIR/toggle-gaming" || true)" \
    "both Gaming mutation aliases pass the installed-system gate"
assert_file_exists "$GAMING_DOC"
assert_grep_fixed 'reports the next-boot state as not applicable' "$GAMING_DOC" \
    "Gaming documentation explains the Live-media status contract"

# The installed/Live classification accepts only the real kernel token and its
# valued form. A lookalike argument must not disable installed-system controls.
GAMING_ENV_HARNESS="$TMPDIR/gaming-boot-environment"
GAMING_ENV_CMDLINE="$TMPDIR/gaming-environment-cmdline"
sed -n '/^boot_environment()/,/^}$/p' "$TMPDIR/toggle-gaming" \
    | sed "s|/proc/cmdline|$GAMING_ENV_CMDLINE|g" \
    > "$GAMING_ENV_HARNESS"
assert_cmd_success "Gaming boot-environment reader parses" \
    bash -n "$GAMING_ENV_HARNESS"
for environment_case in \
    'quiet rd.live.image hardened|live' \
    'quiet rd.live.image=1 hardened|live' \
    'quiet source=rd.live.image hardened|installed' \
    'quiet rd.live.imagex hardened|installed' \
    '|unknown'; do
    cmdline=${environment_case%%|*}
    expected_environment=${environment_case##*|}
    printf '%s\n' "$cmdline" > "$GAMING_ENV_CMDLINE"
    observed_environment=$(bash -c ". '$GAMING_ENV_HARNESS'; boot_environment")
    assert_eq "$expected_environment" "$observed_environment" \
        "Gaming boot environment classifies: ${cmdline:-empty input}"
done

# Exercise the fail-closed mutation gate independently of the host boot.
GAMING_INSTALLED_GATE="$TMPDIR/gaming-installed-gate"
cat > "$GAMING_INSTALLED_GATE" <<'GAMING_INSTALLED_GATE_PREFIX'
#!/bin/bash
set -euo pipefail
boot_environment() { printf '%s\n' "${GAMING_ENVIRONMENT:?}"; }
fmt_err() { printf '%s\n' "$*" >&2; }
GAMING_INSTALLED_GATE_PREFIX
sed -n '/^require_installed_system()/,/^}$/p' "$TMPDIR/toggle-gaming" \
    >> "$GAMING_INSTALLED_GATE"
printf '%s\n' 'require_installed_system' >> "$GAMING_INSTALLED_GATE"
assert_cmd_success "Gaming installed-system gate accepts installed state" \
    env GAMING_ENVIRONMENT=installed bash "$GAMING_INSTALLED_GATE"
assert_cmd_failure "Gaming installed-system gate rejects Live state" \
    env GAMING_ENVIRONMENT=live bash "$GAMING_INSTALLED_GATE"
assert_cmd_failure "Gaming installed-system gate rejects unknown state" \
    env GAMING_ENVIRONMENT=unknown bash "$GAMING_INSTALLED_GATE"

# Exercise exact live-state classification without touching the host cmdline.
GAMING_LIVE_HARNESS="$TMPDIR/gaming-ia32-live"
GAMING_LIVE_CMDLINE="$TMPDIR/live-cmdline"
sed -n '/^ia32_live()/,/^}$/p' "$TMPDIR/toggle-gaming" \
    | sed "s|/proc/cmdline|$GAMING_LIVE_CMDLINE|g" \
    > "$GAMING_LIVE_HARNESS"
assert_cmd_success "Gaming live-state reader parses" \
    bash -n "$GAMING_LIVE_HARNESS"
printf '%s\n' 'quiet ia32_emulation=1 vdso32=1' > "$GAMING_LIVE_CMDLINE"
gaming_live=$(bash -c ". '$GAMING_LIVE_HARNESS'; ia32_live")
assert_eq on "$gaming_live" \
    "live Gaming state requires both enabled compatibility tokens"
printf '%s\n' 'quiet ia32_emulation=1 vdso32=0' > "$GAMING_LIVE_CMDLINE"
gaming_live=$(bash -c ". '$GAMING_LIVE_HARNESS'; ia32_live")
assert_eq mixed "$gaming_live" \
    "contradictory live compatibility tokens are never reported enabled"
printf '%s\n' 'quiet ia32_emulation=0 vdso32=0' > "$GAMING_LIVE_CMDLINE"
gaming_live=$(bash -c ". '$GAMING_LIVE_HARNESS'; ia32_live")
assert_eq off "$gaming_live" \
    "live Gaming state requires both hardened tokens before reporting off"

# Steam package work is gated only by the installed state and the exact live
# cmdline classification above. Persisted/BLS IA32 state is deliberately not
# an execution proof for RPM scriptlets in the current boot.
GAMING_STEAM_PHASE_HARNESS="$TMPDIR/gaming-steam-phase"
{
    cat <<'GAMING_STEAM_PHASE_PREFIX'
#!/bin/bash
set -euo pipefail
steam_installed() { printf '%s\n' "${GAMING_STEAM_INSTALLED:?}"; }
ia32_live() { printf '%s\n' "${GAMING_LIVE_STATE:?}"; }
GAMING_STEAM_PHASE_PREFIX
    sed -n '/^steam_install_phase()/,/^}$/p' "$TMPDIR/toggle-gaming"
    printf '%s\n' 'steam_install_phase'
} > "$GAMING_STEAM_PHASE_HARNESS"
assert_cmd_success "Gaming Steam phase harness parses" \
    bash -n "$GAMING_STEAM_PHASE_HARNESS"
for phase_case in \
    'no off reboot' \
    'no mixed reboot' \
    'no unknown reboot' \
    'no on install' \
    'yes off installed' \
    'yes on installed'; do
    read -r installed_state live_state expected_phase <<<"$phase_case"
    observed_phase=$(GAMING_STEAM_INSTALLED="$installed_state" \
        GAMING_LIVE_STATE="$live_state" \
        bash "$GAMING_STEAM_PHASE_HARNESS")
    assert_eq "$expected_phase" "$observed_phase" \
        "Gaming Steam phase installed=$installed_state live=$live_state"
done

# Exercise both branches of the persistent-state reader. The fixture replaces
# only the canonical source path; root and unprivileged identities are mocked
# locally so no host boot state or privilege is involved.
GAMING_IA32_HARNESS="$TMPDIR/gaming-ia32-persistent"
GAMING_CMDLINE_FIXTURE="$TMPDIR/kernel-cmdline"
sed -n '/^ia32_persistent()/,/^}$/p' "$TMPDIR/toggle-gaming" \
    | sed "s|/etc/kernel/cmdline|$GAMING_CMDLINE_FIXTURE|g" \
    > "$GAMING_IA32_HARNESS"
assert_cmd_success "Gaming persistent-state reader parses" \
    bash -n "$GAMING_IA32_HARNESS"
printf '%s\n' 'quiet ia32_emulation=0 vdso32=0' > "$GAMING_CMDLINE_FIXTURE"
gaming_persist=$(env GAMING_IA32_HARNESS="$GAMING_IA32_HARNESS" bash -c '
    id() { [ "${1:-}" = -u ] && printf "1000\n"; }
    grubby() { return 99; }
    . "$GAMING_IA32_HARNESS"
    GRUBBY=grubby
    ia32_persistent
')
assert_eq off "$gaming_persist" \
    "unprivileged Gaming status resolves the canonical hardened state"
gaming_persist=$(env GAMING_IA32_HARNESS="$GAMING_IA32_HARNESS" bash -c '
    id() { [ "${1:-}" = -u ] && printf "0\n"; }
    grubby() { printf "%s\n" "args=quiet ia32_emulation=1 vdso32=1"; }
    . "$GAMING_IA32_HARNESS"
    GRUBBY=grubby
    ia32_persistent
')
assert_eq on "$gaming_persist" \
    "privileged Gaming transitions continue to inspect BLS through grubby"
assert_grep_fixed 'set_persistent_mode' "$TMPDIR/toggle-gaming" \
    "gaming toggle verifies every persisted BLS entry"
assert_grep_fixed 'GRUBBY=/usr/sbin/grubby' "$TMPDIR/toggle-gaming" \
    "gaming BLS verification binds Fedora's native absolute grubby path"
assert_not_grep '"$GRUBBY" --update-kernel' "$TMPDIR/toggle-gaming" \
    "gaming leaves durable boot publication solely to M01"
assert_grep_fixed 'CMDLINE_TRANSITION=/usr/libexec/noid-firstboot-cmdline-transition' \
    "$TMPDIR/toggle-gaming" \
    "gaming transitions use M01's reviewed evidence opener"
assert_grep_fixed '"$CMDLINE_TRANSITION" --invalidate-hardening-profile' \
    "$TMPDIR/toggle-gaming" \
    "gaming opens exact M01 evidence only for a real profile transition"
assert_grep_fixed 'reconcile_firstboot_cmdline_evidence "Gaming Mode' \
    "$TMPDIR/toggle-gaming" \
    "gaming synchronously republishes M01 evidence after boot mutation"
assert_grep_fixed 'if mode_is_canonical off; then' "$TMPDIR/toggle-gaming" \
    "already-hardened Gaming off is a complete transaction no-op"
assert_grep_fixed 'if mode_is_canonical on; then' "$TMPDIR/toggle-gaming" \
    "already-enabled Gaming on is a complete policy no-op"
for mode in on off; do
    case "$mode" in
        on) begin_ordinal=1 ;;
        off) begin_ordinal=2 ;;
    esac
    begin_line=$(grep -nF '        begin_transaction' "$TMPDIR/toggle-gaming" \
        | sed -n "${begin_ordinal}p" \
        | cut -d: -f1 || true)
    canonical_line=$(grep -nF "        if mode_is_canonical $mode; then" \
        "$TMPDIR/toggle-gaming" | head -1 | cut -d: -f1 || true)
    if [ -n "$begin_line" ] && [ -n "$canonical_line" ] \
            && [ "$begin_line" -lt "$canonical_line" ]; then
        _pass "Gaming $mode serializes its canonical no-op decision"
    else
        _fail "Gaming $mode serializes its canonical no-op decision"
    fi
done
assert_grep_fixed 'Persistent 32-bit mode already $mode; boot bytes unchanged' \
    "$TMPDIR/toggle-gaming" \
    "persisted-mode no-op explicitly retains byte identity"
assert_grep_fixed 'verify_execmod_mode' "$TMPDIR/toggle-gaming" \
    "gaming toggle verifies SELinux boolean state"
assert_grep_fixed 'rollback_state' "$TMPDIR/toggle-gaming" \
    "gaming toggle has transactional rollback"
assert_grep_fixed 'PREV_FLAG=$(validate_flag_state)' "$TMPDIR/toggle-gaming" \
    "gaming transaction snapshots its receipt state"
assert_grep_fixed 'restore_flag_state || rollback_failed=1' "$TMPDIR/toggle-gaming" \
    "gaming rollback restores the prior receipt state"
assert_grep_fixed 'mv -fT -- "$candidate" "$FLAG"' "$TMPDIR/toggle-gaming" \
    "gaming receipt publication is atomic and does not follow a symlink"
assert_not_grep 'touch "$FLAG"' "$TMPDIR/toggle-gaming" \
    "gaming receipt creation never follows an attacker-controlled symlink"
assert_grep_fixed 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' "$TMPDIR/toggle-gaming" \
    "privileged gaming helper pins its command search path"
assert_grep_fixed 'DNF=/usr/bin/dnf' "$TMPDIR/toggle-gaming" \
    "Gaming Mode binds package work to Fedora's native DNF path"
assert_grep_fixed '( umask 022; "$DNF" "$@" )' "$TMPDIR/toggle-gaming" \
    "Gaming Mode scopes public metadata permissions to the Steam transaction"
assert_grep_fixed 'run_system_dnf install -y steam' "$TMPDIR/toggle-gaming" \
    "Steam installation uses the scoped DNF wrapper"
assert_not_grep_extended '^[[:space:]]*dnf[[:space:]]+install[[:space:]]+-y[[:space:]]+steam' \
    "$TMPDIR/toggle-gaming" \
    "Gaming Mode has no Steam transaction outside the scoped wrapper"
GAMING_DNF_HARNESS="$TMPDIR/gaming-dnf-umask"
{
    grep -m1 '^DNF=' "$TMPDIR/toggle-gaming"
    sed -n '/^run_system_dnf()/,/^}$/p' "$TMPDIR/toggle-gaming"
} > "$GAMING_DNF_HARNESS"
sed -i 's|^DNF=/usr/bin/dnf$|DNF=dnf|' "$GAMING_DNF_HARNESS"
gaming_dnf_umask=$(umask 077; bash -c '
    dnf() { umask; }
    export -f dnf
    . "$1"
    run_system_dnf install -y steam
' _ "$GAMING_DNF_HARNESS")
assert_eq 0022 "$gaming_dnf_umask" \
    "Gaming Mode gives its Steam transaction only the public metadata umask"
assert_grep_fixed 'phase=$(steam_install_phase)' "$TMPDIR/toggle-gaming" \
    "Gaming Mode resolves the live execution gate after committing policy"
assert_grep_fixed 'Persisted/BLS state is intentionally not accepted as an execution proof.' \
    "$TMPDIR/toggle-gaming" \
    "Gaming Mode rejects durable bytes as current i686 execution evidence"
gaming_policy_commit_line=$(grep -nF '        commit_transaction' \
    "$TMPDIR/toggle-gaming" | sed -n '1p' | cut -d: -f1 || true)
gaming_phase_line=$(grep -nF '        phase=$(steam_install_phase)' \
    "$TMPDIR/toggle-gaming" | head -1 | cut -d: -f1 || true)
gaming_install_branch_line=$(grep -nF '            install)' \
    "$TMPDIR/toggle-gaming" | head -1 | cut -d: -f1 || true)
gaming_dnf_line=$(grep -nF '                if ! run_system_dnf install -y steam; then' \
    "$TMPDIR/toggle-gaming" | head -1 | cut -d: -f1 || true)
if [ -n "$gaming_policy_commit_line" ] && [ -n "$gaming_phase_line" ] \
        && [ -n "$gaming_install_branch_line" ] && [ -n "$gaming_dnf_line" ] \
        && [ "$gaming_policy_commit_line" -lt "$gaming_phase_line" ] \
        && [ "$gaming_phase_line" -lt "$gaming_install_branch_line" ] \
        && [ "$gaming_install_branch_line" -lt "$gaming_dnf_line" ]; then
    _pass "Gaming Steam DNF follows committed policy and the live-only install branch"
else
    _fail "Gaming Steam DNF ordering differs from the two-stage contract"
fi
assert_grep_fixed '[ "$(ia32_live)" = on ] || {' "$TMPDIR/toggle-gaming" \
    "Gaming Mode rechecks live IA32 immediately before DNF"
assert_grep_fixed '/usr/lib/ld-linux.so.2 --help' "$TMPDIR/toggle-gaming" \
    "Gaming Mode executes the installed i686 loader before success"
assert_grep_fixed '/usr/bin/fc-cache-32 --version' "$TMPDIR/toggle-gaming" \
    "Gaming Mode checks the observed failing i686 scriptlet helper"
assert_not_grep_extended 'about 1 GiB|~1 GiB|~184 packages' \
    "$TMPDIR/toggle-gaming" \
    "Gaming Mode delegates moving transaction size to DNF"
assert_grep_fixed 'matchpathcon -V "$1"' "$TMPDIR/toggle-gaming" \
    "gaming receipt validation enforces SELinux path policy"
assert_grep_fixed 'flag_state=$(validate_flag_state)' "$TMPDIR/toggle-gaming" \
    "gaming status never follows or trusts an unsafe receipt"
assert_grep_fixed 'BOOT_MUTATION_LOCK=/run/lock/noid-boot-mutation.lock' \
    "$TMPDIR/toggle-gaming" "gaming BLS writer uses the shared boot lock"
assert_grep_fixed '/usr/libexec/noid-boot-mutation-guard' \
    "$TMPDIR/toggle-gaming" "gaming BLS writer requires a stable M21 basis"
guard_line=$(grep -nF '/usr/libexec/noid-boot-mutation-guard' \
    "$TMPDIR/toggle-gaming" | head -1 | cut -d: -f1 || true)
transition_count=$(grep -cF '"$CMDLINE_TRANSITION" --invalidate-hardening-profile' \
    "$TMPDIR/toggle-gaming" || true)
gaming_order_ok=1
[ -n "$guard_line" ] && [ "$transition_count" -gt 0 ] || gaming_order_ok=0
while IFS=: read -r transition_line _; do
    [ "$transition_line" -gt "${guard_line:-0}" ] || gaming_order_ok=0
done < <(grep -nF '"$CMDLINE_TRANSITION" --invalidate-hardening-profile' \
    "$TMPDIR/toggle-gaming" || true)
if [ "$gaming_order_ok" -eq 1 ]; then
    _pass "gaming guard precedes every M01 evidence transition"
else
    _fail "gaming guard precedes every M01 evidence transition"
fi

# Execute the load-bearing no-op/transition distinction with local fixtures.
# The already-target state must call neither M01 entry point; a real change
# must call evidence opener -> canonical M01 reconciliation exactly.
GAMING_TRANSITION_HARNESS="$TMPDIR/gaming-transition-harness"
GAMING_TRANSITION_STATE="$TMPDIR/gaming-transition-state"
GAMING_TRANSITION_LOG="$TMPDIR/gaming-transition.log"
cat > "$GAMING_TRANSITION_HARNESS" <<GAMING_HARNESS_PREFIX
#!/bin/bash
set -euo pipefail
CMDLINE_TRANSITION=gaming_fixture_transition
CMDLINE_TRANSITION_OPEN=\${GAMING_TRANSITION_OPEN_INITIAL:-0}
fmt_info() { :; }
fmt_err() { printf '%s\n' "\$*" >&2; }
ia32_persistent() { cat "\${GAMING_TRANSITION_STATE:?}"; }
gaming_fixture_transition() {
    [ "\$#" -eq 1 ] && [ "\$1" = --invalidate-hardening-profile ]
    printf '%s\n' transition >> "\${GAMING_TRANSITION_LOG:?}"
}
reconcile_firstboot_cmdline_evidence() {
    [ "\$CMDLINE_TRANSITION_OPEN" -eq 1 ]
    printf '%s\n' reconcile >> "\${GAMING_TRANSITION_LOG:?}"
    if [ -n "\${GAMING_TRANSITION_EXPECTED:-}" ]; then
        printf '%s\n' "\$GAMING_TRANSITION_EXPECTED" \
            > "\${GAMING_TRANSITION_STATE:?}"
    fi
    CMDLINE_TRANSITION_OPEN=0
}
GAMING_HARNESS_PREFIX
sed -n '/^set_persistent_mode()/,/^}$/p' "$TMPDIR/toggle-gaming" \
    >> "$GAMING_TRANSITION_HARNESS"
cat >> "$GAMING_TRANSITION_HARNESS" <<'GAMING_HARNESS_SUFFIX'
set_persistent_mode "$1"
printf 'transition_open=%s\n' "$CMDLINE_TRANSITION_OPEN"
GAMING_HARNESS_SUFFIX
chmod 0755 "$GAMING_TRANSITION_HARNESS"
assert_cmd_success "Gaming transition behavior harness parses" \
    bash -n "$GAMING_TRANSITION_HARNESS"
: > "$GAMING_TRANSITION_LOG"
printf '%s\n' off > "$GAMING_TRANSITION_STATE"
gaming_transition_result=$(GAMING_TRANSITION_LOG="$GAMING_TRANSITION_LOG" \
    GAMING_TRANSITION_STATE="$GAMING_TRANSITION_STATE" \
    GAMING_TRANSITION_EXPECTED=off \
    bash "$GAMING_TRANSITION_HARNESS" off)
assert_eq transition_open=0 "$gaming_transition_result" \
    "already-hardened Gaming off leaves no evidence transition open"
assert_eq 0 "$(wc -l < "$GAMING_TRANSITION_LOG")" \
    "already-hardened Gaming off performs zero boot mutations"
: > "$GAMING_TRANSITION_LOG"
gaming_transition_result=$(GAMING_TRANSITION_LOG="$GAMING_TRANSITION_LOG" \
    GAMING_TRANSITION_STATE="$GAMING_TRANSITION_STATE" \
    GAMING_TRANSITION_OPEN_INITIAL=1 \
    bash "$GAMING_TRANSITION_HARNESS" off)
assert_eq transition_open=0 "$gaming_transition_result" \
    "unchanged rollback target still closes an opened M01 transition"
assert_eq reconcile "$(cat "$GAMING_TRANSITION_LOG")" \
    "unchanged rollback target republishes exact M01 evidence"
: > "$GAMING_TRANSITION_LOG"
printf '%s\n' on > "$GAMING_TRANSITION_STATE"
gaming_transition_result=$(GAMING_TRANSITION_LOG="$GAMING_TRANSITION_LOG" \
    GAMING_TRANSITION_STATE="$GAMING_TRANSITION_STATE" \
    GAMING_TRANSITION_EXPECTED=off \
    bash "$GAMING_TRANSITION_HARNESS" off)
assert_eq transition_open=0 "$gaming_transition_result" \
    "real Gaming transition closes M01 evidence synchronously"
assert_eq $'transition\nreconcile' \
    "$(cat "$GAMING_TRANSITION_LOG")" \
    "real Gaming transition orders evidence opener and canonical M01 reconciliation"

assert_grep_fixed 'Steam install failed; Gaming compatibility remains enabled by your request.' \
    "$TMPDIR/toggle-gaming" \
    "post-reboot Steam failure reports the retained explicit policy truth"
assert_grep_fixed 'This invocation started no Steam DNF transaction' \
    "$TMPDIR/toggle-gaming" \
    "pre-reboot invocation proves that no package transaction was started"
assert_grep_fixed 'Steam installation was intentionally deferred until after that reboot.' \
    "$TMPDIR/toggle-gaming" \
    "pre-reboot invocation states that package work was deliberately deferred"
assert_not_grep '\[WARN\] Steam install failed' "$TMPDIR/toggle-gaming" \
    "Steam install failure is not downgraded to warning"

# DNF5 effective-state contract: an override-disabled repo must not be reported
# from its base .repo `enabled=1`. Mock only the read-only repolist interface.
assert_cmd_success "third-party repo helper is valid bash" \
    bash -n "$TMPDIR/toggle-thirdparty-repos"
assert_grep_fixed 'export PATH=/usr/sbin:/usr/bin' \
    "$TMPDIR/toggle-thirdparty-repos" \
    "privileged repository mutations use only the trusted system path"
assert_grep_fixed 'DNF=/usr/bin/dnf' "$TMPDIR/toggle-thirdparty-repos" \
    "repository toggle binds package work to Fedora's native DNF path"
assert_grep_fixed '( umask 022; "$DNF" "$@" )' \
    "$TMPDIR/toggle-thirdparty-repos" \
    "repository toggle scopes public DNF metadata to umask 0022"
assert_grep_fixed 'run_system_dnf -q --cacheonly repolist --enabled' \
    "$TMPDIR/toggle-thirdparty-repos" \
    "status reads effective DNF5 enabled state without network refresh"
repo_toggle_dnf_calls=$(grep -Ec 'run_system_dnf([[:space:]]|$)' \
    "$TMPDIR/toggle-thirdparty-repos")
[ "$repo_toggle_dnf_calls" -eq 3 ] \
    && _pass "all three repository-toggle DNF paths use the scoped wrapper" \
    || _fail "repository-toggle DNF path count differs (expected 3, got $repo_toggle_dnf_calls)"
assert_not_grep_extended '^[[:space:]]*(if ![[:space:]]+|[!][[:space:]]+)?dnf([[:space:]]|$)' \
    "$TMPDIR/toggle-thirdparty-repos" \
    "repository toggle has no DNF invocation outside the scoped wrapper"
REPO_DNF_HARNESS="$TMPDIR/repo-toggle-dnf-umask.sh"
awk '
    /^DNF=\/usr\/bin\/dnf$/ { print; next }
    /^run_system_dnf\(\) \{$/ { copy=1 }
    copy { print }
    copy && /^}$/ { exit }
' "$TMPDIR/toggle-thirdparty-repos" > "$REPO_DNF_HARNESS"
repo_toggle_dnf_umask=$(env REPO_DNF_HARNESS="$REPO_DNF_HARNESS" bash -c '
    dnf() { umask; }
    export -f dnf
    # shellcheck source=/dev/null
    . "$REPO_DNF_HARNESS"
    DNF=dnf
    umask 027
    run_system_dnf -q --cacheonly repolist --all
')
[ "$repo_toggle_dnf_umask" = 0022 ] \
    && _pass "repository toggle gives every DNF child the public metadata umask" \
    || _fail "repository-toggle DNF wrapper inherited umask $repo_toggle_dnf_umask"
assert_not_grep 'grep -l.*etc/yum.repos.d' "$TMPDIR/toggle-thirdparty-repos" \
    "base repo files cannot override effective DNF5 state"
assert_not_grep 'repolist --setopt=enabled=1' "$TMPDIR/toggle-thirdparty-repos" \
    "status query never mutates enabled semantics"
assert_grep_fixed 'FEDORA_PRIMARY_REPOS=(' "$TMPDIR/toggle-thirdparty-repos" \
    "Fedora-only mode uses one explicit distro-source allowlist"
assert_grep_fixed 'THIRDPARTY_REPOS+=("$repo")' \
    "$TMPDIR/toggle-thirdparty-repos" \
    "managed third-party repos are derived from effective DNF configuration"
assert_grep_fixed 'thirdparty-repos-minimal.state' \
    "$TMPDIR/toggle-thirdparty-repos" \
    "minimal mode records exact reversible pre-transition state"
assert_grep_fixed 'restore evidence retained' "$TMPDIR/toggle-thirdparty-repos" \
    "partial restore cannot discard recovery evidence"
assert_grep_fixed "stat -Lc '%U:%G:%a:%h' /usr/local/bin/noid-toggle-thirdparty-repos" \
    "$KS_FILE" "installed third-party repo helper has an exact metadata gate"
assert_grep_fixed 'bash -n /usr/local/bin/noid-toggle-thirdparty-repos' \
    "$KS_FILE" "installed third-party repo helper has a syntax gate"
assert_grep_fixed 'installed and verified' "$KS_FILE" \
    "Module 08 cannot report final success before helper verification"
assert_grep_fixed 'install verification failed' "$KS_FILE" \
    "third-party helper verification failure is explicit"
assert_cmd_success "third-party repo helper empty invocation shows help" \
    bash "$TMPDIR/toggle-thirdparty-repos"
for help_arg in -h --help help; do
    assert_cmd_success "third-party repo helper $help_arg exits success" \
        bash "$TMPDIR/toggle-thirdparty-repos" "$help_arg"
done
assert_cmd_failure "third-party repo helper rejects unknown command" \
    bash "$TMPDIR/toggle-thirdparty-repos" unknown
assert_cmd_failure "third-party repo helper rejects extra help argument" \
    bash "$TMPDIR/toggle-thirdparty-repos" --help extra
assert_cmd_failure "third-party repo helper rejects extra status argument" \
    bash "$TMPDIR/toggle-thirdparty-repos" status extra

assert_grep_fixed 'expected $COUNTME_EXPECTED Fedora repo files' "$KS_FILE" \
    "countme gate rejects an absent Fedora repo source set"
assert_grep_fixed "packaging-format-preference=['flatpak:flathub-verified']" "$KS_FILE" \
    "M08 verifies only its GNOME Software origin preference"
assert_not_grep 'mandatory system Flathub remote not configured' "$KS_FILE" \
    "M08 does not verify remotes before M18 owns their exact reconciliation"
assert_grep_fixed '[FAIL] package still present (expected removed)' "$KS_FILE" \
    "reintroduced excluded packages are build failures"
assert_grep_fixed 'dconf database binary not found after mandatory dconf update' "$KS_FILE" \
    "missing compiled dconf database is a build failure"

# The udev helper is contractually argumentless. Derive a safe copy whose
# absolute rfkill boundary is replaced by a bash-read fixture: /tmp is noexec
# on the target, and invoking the fixture through /usr/bin/bash preserves that
# mount policy while proving whether execution reached the dependency.
BT_APPLY_FIXTURE="$TMPDIR/bt-apply-default-fixture"
mkdir -p "$BT_APPLY_FIXTURE/state"
cp "$TMPDIR/bt-apply-default" "$BT_APPLY_FIXTURE/apply"
sed -i \
    -e "s|^FLAG=.*|FLAG=$BT_APPLY_FIXTURE/state/bluetooth-disabled.flag|" \
    -e "s|^/usr/bin/rfkill block bluetooth$|/usr/bin/bash \"$BT_APPLY_FIXTURE/rfkill-stub\" block bluetooth|" \
    "$BT_APPLY_FIXTURE/apply"
printf '%s\n' \
    '#!/bin/bash' \
    'printf "%s\\n" reached >> "$BT_APPLY_MARKER"' \
    'exit 97' \
    > "$BT_APPLY_FIXTURE/rfkill-stub"
install -m 0644 /dev/null "$BT_APPLY_FIXTURE/state/bluetooth-disabled.flag"
BT_APPLY_MARKER="$BT_APPLY_FIXTURE/dependency.reached"
export BT_APPLY_MARKER

run_bt_apply_hostile() {
    local label=$1 rc
    shift
    rm -f -- "$BT_APPLY_MARKER"
    set +e
    PATH="$BT_APPLY_FIXTURE/untrusted-path" \
        /usr/bin/bash "$BT_APPLY_FIXTURE/apply" "$@" \
        > "$BT_APPLY_FIXTURE/stdout" 2> "$BT_APPLY_FIXTURE/stderr"
    rc=$?
    set -e
    assert_eq 2 "$rc" "Bluetooth udev helper rejects $label before rfkill"
    assert_eq '' "$(< "$BT_APPLY_FIXTURE/stdout")" \
        "Bluetooth udev helper $label rejection keeps stdout empty"
    assert_eq 'ERROR: noid-bluetooth-apply-default accepts no arguments' \
        "$(< "$BT_APPLY_FIXTURE/stderr")" \
        "Bluetooth udev helper $label rejection is constant"
    if [[ -e $BT_APPLY_MARKER ]]; then
        _fail "Bluetooth udev helper $label reached rfkill"
    else
        _pass "Bluetooth udev helper $label cannot reach rfkill"
    fi
}

run_bt_apply_hostile unknown unknown
run_bt_apply_hostile empty ''
run_bt_apply_hostile surplus one two
run_bt_apply_hostile newline $'line\nbreak'
run_bt_apply_hostile escape $'\033[31m'

rm -f -- "$BT_APPLY_MARKER"
set +e
/usr/bin/bash "$BT_APPLY_FIXTURE/apply" \
    > "$BT_APPLY_FIXTURE/stdout" 2> "$BT_APPLY_FIXTURE/stderr"
bt_apply_rc=$?
set -e
assert_eq 97 "$bt_apply_rc" \
    "argumentless Bluetooth udev fixture reaches the intended rfkill boundary"
if [[ -e $BT_APPLY_MARKER ]]; then
    _pass "argumentless Bluetooth udev fixture records rfkill reachability"
else
    _fail "argumentless Bluetooth udev fixture did not reach rfkill"
fi

rm -f -- "$BT_APPLY_MARKER" "$BT_APPLY_FIXTURE/state/bluetooth-disabled.flag"
assert_cmd_success "argumentless Bluetooth udev helper is a no-op without its flag" \
    /usr/bin/bash "$BT_APPLY_FIXTURE/apply"
if [[ -e $BT_APPLY_MARKER ]]; then
    _fail "flagless Bluetooth udev helper reached rfkill"
else
    _pass "flagless Bluetooth udev helper does not reach rfkill"
fi
unset BT_APPLY_MARKER

# Multi-controller rfkill fixture: every present Bluetooth controller must
# agree. A mixed host is never reported as disabled or enabled.
BT_FIXTURE="$TMPDIR/bt-fixture"
mkdir -p "$BT_FIXTURE/sysfs" "$BT_FIXTURE/state"
cp "$TMPDIR/toggle-bt" "$BT_FIXTURE/toggle-bt"
fixture_uid=$(id -u)
fixture_gid=$(id -g)
sed -i \
    -e "s|^RFKILL_SYSFS_ROOT=.*|RFKILL_SYSFS_ROOT=$BT_FIXTURE/sysfs|" \
    -e "s|^FLAG=.*|FLAG=$BT_FIXTURE/state/bluetooth-disabled.flag|" \
    -e "s|^WPCFG=.*|WPCFG=$BT_FIXTURE/state/bluez.conf|" \
    -e "s|^WPCFG_TEMPLATE=.*|WPCFG_TEMPLATE=$BT_FIXTURE/state/template.conf|" \
    -e "s|0:0:\\\$mode|$fixture_uid:$fixture_gid:\\\$mode|g" \
    "$BT_FIXTURE/toggle-bt"
printf '%s\n' 'monitor.bluez.properties = { bluez5.enable = false }' \
    > "$BT_FIXTURE/state/template.conf"
install -m 0644 /dev/null "$BT_FIXTURE/state/bluetooth-disabled.flag"
install -m 0644 "$BT_FIXTURE/state/template.conf" "$BT_FIXTURE/state/bluez.conf"
# shellcheck disable=SC2317,SC2329
systemctl() {
    case "${1:-}" in
        is-enabled) printf '%s\n' disabled ;;
        is-active) return 1 ;;
        *) return 2 ;;
    esac
}
export -f systemctl
# The fixture lives below mktemp's unmapped pathname, for which SELinux has no
# path policy to validate. Metadata/content invariants are still exercised;
# production label validation is asserted separately against the helper source.
# shellcheck disable=SC2317,SC2329  # invoked by the fixture's child shell via export -f
selinuxenabled() {
    return 1
}
export -f selinuxenabled
bt_status=$(bash "$BT_FIXTURE/toggle-bt" status)
grep -qF -- '-> FULLY DISABLED' <<< "$bt_status" \
    && _pass "zero-controller Bluetooth fixture uses the documented n/a state" \
    || _fail "zero-controller Bluetooth fixture misclassified"
for id_state in '0 1' '1 1'; do
    read -r id state <<< "$id_state"
    mkdir -p "$BT_FIXTURE/sysfs/rfkill$id"
    printf '%s\n' bluetooth > "$BT_FIXTURE/sysfs/rfkill$id/type"
    printf '%s\n' "$state" > "$BT_FIXTURE/sysfs/rfkill$id/soft"
done
bt_status=$(bash "$BT_FIXTURE/toggle-bt" status)
grep -qF -- '-> FULLY DISABLED' <<< "$bt_status" \
    && _pass "all-blocked multi-controller fixture is disabled" \
    || _fail "all-blocked multi-controller fixture misclassified"
printf '%s\n' 0 > "$BT_FIXTURE/sysfs/rfkill1/soft"
bt_status=$(bash "$BT_FIXTURE/toggle-bt" status)
grep -qF -- '-> MIXED' <<< "$bt_status" \
    && _pass "mixed multi-controller fixture is not reported disabled" \
    || _fail "mixed multi-controller fixture false-disabled"
rm -f "$BT_FIXTURE/state/bluetooth-disabled.flag" "$BT_FIXTURE/state/bluez.conf"
printf '%s\n' 0 > "$BT_FIXTURE/sysfs/rfkill0/soft"
bt_status=$(bash "$BT_FIXTURE/toggle-bt" status)
grep -qF -- '-> ENABLED' <<< "$bt_status" \
    && _pass "all-unblocked multi-controller fixture is enabled" \
    || _fail "all-unblocked multi-controller fixture misclassified"
printf '%s\n' 1 > "$BT_FIXTURE/sysfs/rfkill1/soft"
bt_status=$(bash "$BT_FIXTURE/toggle-bt" status)
grep -qF -- '-> MIXED' <<< "$bt_status" \
    && _pass "mixed multi-controller fixture is not reported enabled" \
    || _fail "mixed multi-controller fixture false-enabled"
unset -f systemctl
unset -f selinuxenabled

# /tmp is noexec under the target policy, so export a deterministic shell
# function rather than trying to execute a temporary command-double file.
# Invoked indirectly by the extracted production helper below.
# shellcheck disable=SC2317,SC2329
dnf() {
    case "$*" in
        *'repolist --all'*)
            printf '%s\n' 'repo id repo name' \
              'fedora Fedora' \
              'updates Fedora Updates' \
              'rpmfusion-free RPM Fusion Free' \
              'rpmfusion-free-updates RPM Fusion Free Updates' \
              'rpmfusion-nonfree RPM Fusion Nonfree' \
              'rpmfusion-nonfree-updates RPM Fusion Nonfree Updates' \
              'fedora-cisco-openh264 Cisco OpenH264' \
              'gitlab.com_paulcarroty_vscodium_repo VSCodium' \
              'protonvpn-fedora-stable ProtonVPN' \
              'rpmfusion-nonfree-nvidia-driver NVIDIA'
            ;;
        *'repolist --enabled'*)
            printf '%s\n' 'repo id repo name' \
              'fedora Fedora' \
              'updates Fedora Updates' \
              'rpmfusion-free RPM Fusion Free' \
              'fedora-cisco-openh264 Cisco OpenH264' \
              'protonvpn-fedora-stable ProtonVPN' \
              'rpmfusion-nonfree-nvidia-driver NVIDIA'
            ;;
        *) return 2 ;;
    esac
}
export -f dnf
repo_status_fixture="$TMPDIR/repo-toggle-status-fixture"
cp "$TMPDIR/toggle-thirdparty-repos" "$repo_status_fixture"
sed -i 's|^DNF=/usr/bin/dnf$|DNF=dnf|' "$repo_status_fixture"
repo_status=$(NOID_REPO_TOGGLE_STATE_DIR="$TMPDIR/repo-toggle-status-state" \
    bash "$repo_status_fixture" status)
unset -f dnf
if awk '$1=="rpmfusion-free" && $2=="1" {ok=1} END{exit !ok}' \
        <<< "$repo_status"; then
    _pass "effective enabled repo is reported as 1"
else
    _fail "effective enabled repo is reported as 1"
fi
if awk '$1=="rpmfusion-nonfree" && $2=="0" {ok=1} END{exit !ok}' \
        <<< "$repo_status"; then
    _pass "override-disabled base repo is reported as 0"
else
    _fail "override-disabled base repo is reported as 0"
fi
for dynamic_repo in protonvpn-fedora-stable rpmfusion-nonfree-nvidia-driver; do
    if awk -v r="$dynamic_repo" '$1==r && $2=="1" {ok=1} END{exit !ok}' \
            <<< "$repo_status"; then
        _pass "dynamic enabled repo is covered: $dynamic_repo"
    else
        _fail "dynamic enabled repo is covered: $dynamic_repo"
    fi
done

# Full minimal/restore fixture. Mechanically adapt only root ownership checks
# in the extracted copy; production retains its root-only gate and metadata.
repo_fixture="$TMPDIR/repo-toggle-fixture"
cp "$TMPDIR/toggle-thirdparty-repos" "$repo_fixture"
fixture_user=$(id -un)
fixture_group=$(id -gn)
sed -i \
    -e 's|^DNF=/usr/bin/dnf$|DNF=dnf|' \
    -e 's/\[ "$EUID" -eq 0 \]/[ 0 -eq 0 ]/g' \
    -e "s/-o root -g root/-o $fixture_user -g $fixture_group/g" \
    -e "s/chown root:root/chown $fixture_user:$fixture_group/g" \
    -e "s/root:root:644:1/$fixture_user:$fixture_group:644:1/g" \
    -e "s/root:root:755/$fixture_user:$fixture_group:755/g" \
    "$repo_fixture"
REPO_TEST_ALL="$TMPDIR/repo-all"
REPO_TEST_ENABLED="$TMPDIR/repo-enabled"
export REPO_TEST_ALL REPO_TEST_ENABLED
printf '%s\n' \
    fedora updates \
    rpmfusion-free rpmfusion-nonfree \
    fedora-cisco-openh264 \
    gitlab.com_paulcarroty_vscodium_repo \
    protonvpn-fedora-stable \
    rpmfusion-nonfree-nvidia-driver \
    future-thirdparty > "$REPO_TEST_ALL"
printf '%s\n' \
    fedora updates \
    rpmfusion-free \
    fedora-cisco-openh264 \
    gitlab.com_paulcarroty_vscodium_repo \
    protonvpn-fedora-stable \
    rpmfusion-nonfree-nvidia-driver \
    future-thirdparty > "$REPO_TEST_ENABLED"
# shellcheck disable=SC2317,SC2329
dnf() {
    case "$*" in
        *'repolist --all'*)
            printf '%s\n' 'repo id repo name'
            while IFS= read -r repo; do
                printf '%s configured\n' "$repo"
            done < "$REPO_TEST_ALL"
            ;;
        *'repolist --enabled'*)
            printf '%s\n' 'repo id repo name'
            while IFS= read -r repo; do
                printf '%s enabled\n' "$repo"
            done < "$REPO_TEST_ENABLED"
            ;;
        *'config-manager setopt '*)
            assignment=${*: -1}
            repo=${assignment%.enabled=*}
            wanted=${assignment##*=}
            if [ "$wanted" = 1 ]; then
                grep -qxF "$repo" "$REPO_TEST_ENABLED" ||
                    printf '%s\n' "$repo" >> "$REPO_TEST_ENABLED"
            else
                sed -i "\|^${repo}\$|d" "$REPO_TEST_ENABLED"
            fi
            ;;
        *) return 2 ;;
    esac
}
export -f dnf
REPO_FIXTURE_STATE="$TMPDIR/repo-toggle-state"
export NOID_REPO_TOGGLE_STATE_DIR="$REPO_FIXTURE_STATE"
assert_cmd_success "dynamic Fedora-only transition succeeds" \
    bash "$repo_fixture" minimal
assert_eq $'fedora\nupdates' "$(cat "$REPO_TEST_ENABLED")" \
    "minimal disables every configured enabled non-Fedora repo"
assert_grep_fixed 'future-thirdparty' \
    "$REPO_FIXTURE_STATE/thirdparty-repos-minimal.state" \
    "future third-party repo is captured without source edits"
state_before=$(sha256sum \
    "$REPO_FIXTURE_STATE/thirdparty-repos-minimal.state" | awk '{print $1}')
assert_cmd_success "repeated minimal transition is idempotent" \
    bash "$repo_fixture" minimal
state_after=$(sha256sum \
    "$REPO_FIXTURE_STATE/thirdparty-repos-minimal.state" | awk '{print $1}')
assert_eq "$state_before" "$state_after" \
    "repeated minimal does not erase or duplicate restore evidence"
assert_cmd_success "recorded pre-minimal state restores" \
    bash "$repo_fixture" restore
assert_not_grep '^rpmfusion-nonfree$' "$REPO_TEST_ENABLED" \
    "restore does not enable a repo that was disabled before minimal"
for restored_repo in rpmfusion-free fedora-cisco-openh264 \
        gitlab.com_paulcarroty_vscodium_repo protonvpn-fedora-stable \
        rpmfusion-nonfree-nvidia-driver future-thirdparty; do
    assert_grep_fixed "$restored_repo" "$REPO_TEST_ENABLED" \
        "restore returns exact pre-minimal repo: $restored_repo"
done
if [ ! -e "$REPO_FIXTURE_STATE/thirdparty-repos-minimal.state" ]; then
    _pass "successful restore removes completed transition evidence"
else
    _fail "successful restore removes completed transition evidence"
fi
unset -f dnf
unset NOID_REPO_TOGGLE_STATE_DIR REPO_TEST_ALL REPO_TEST_ENABLED

test_finish

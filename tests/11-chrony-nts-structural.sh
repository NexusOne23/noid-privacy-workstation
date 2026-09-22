#!/bin/bash
# 11-chrony-nts-structural — verify M11 NTS + native restricted chronyd client
#
# Checks:
#   - chrony.conf has 6 operator-supported NTS servers (2-2-2)
#   - all 6 servers have ipv4 + iburst + nts + offline keywords
#   - the dated operator manifest and chrony.conf are exact generated views
#   - minsources=3 minimum-selectable-source threshold
#   - cmdport 0 + bindcmdaddress unix-socket
#   - measurement-file logging DISABLED (retention-scope gap + drift signal)
#   - NO pool/include expansion (closed manifest-generated source set)
#   - NO sourcedir /run/chrony-dhcp (blocks DHCP NTP injection)
#   - Fedora chrony dispatchers remain pristine but are shadowed by exact
#     no-ops, leaving gateway/XDP readiness as the sole online authority
#   - systemd-timesyncd masked in KS source
#   - Fedora's restricted client, maintained -F 2 filter and timedated provider
#     replace the retired library-sensitive custom -F 1 sandbox

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/11-dns-ntp.ks"
MASTER_FILE="$PROJECT_ROOT/kickstart/master.ks"
M08_FILE="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"
M04_FILE="$PROJECT_ROOT/kickstart/snippets/04-arp-hardening.ks"
RUNTIME_GATE="$PROJECT_ROOT/tests/pre-ship/11-chrony-runtime.sh"
SOURCE_MANIFEST="$PROJECT_ROOT/manifests/chrony-nts-sources-v1.tsv"
KNOWN_FAILURES="$PROJECT_ROOT/docs/known-failures.md"
RELEASE_PROCESS="$PROJECT_ROOT/docs/release-process.md"
TEST_STRATEGY="$PROJECT_ROOT/docs/test-strategy.md"

test_start "11-chrony-nts-structural"

assert_file_exists "$KS_FILE"
assert_file_exists "$MASTER_FILE"
assert_grep_fixed \
    'chrony NTS-only (closed EU institutional set + minimum-source threshold)' \
    "$MASTER_FILE" "master accurately summarizes the M11 source boundary"
assert_not_grep 'sovereign-tier server set + minsources quorum' "$MASTER_FILE" \
    "master contains no M11 sovereignty or quorum overclaim"
assert_grep_fixed '# Module 11 — NTP (chrony NTS-only)' "$KS_FILE" \
    "M11 names its chrony-only ownership boundary"
assert_grep_fixed 'echo "[Module 11] NTP (chrony NTS-only)"' "$KS_FILE" \
    "install log names the chrony-only ownership boundary"
assert_not_grep 'DNS + NTP' "$KS_FILE" \
    "M11 does not claim resolver configuration ownership"
assert_file_exists "$M08_FILE"
assert_file_exists "$M04_FILE"
assert_file_executable "$RUNTIME_GATE"
assert_file_exists "$SOURCE_MANIFEST"
assert_file_exists "$KNOWN_FAILURES"
assert_file_exists "$RELEASE_PROCESS"
assert_file_exists "$TEST_STRATEGY"
assert_grep_fixed 'NTS-KE session with ...:4460 (...) timed out' \
    "$KNOWN_FAILURES" "known-failure guide separates NTS-KE TLS from DNS readiness"
assert_grep_fixed 'This proves only that source/exit combination' \
    "$KNOWN_FAILURES" "one measured VPN exit is not generalized to a provider"
for release_doc in "$RELEASE_PROCESS" "$TEST_STRATEGY"; do
    assert_grep_fixed 'QMP `SUSPEND`' "$release_doc" \
        "VM S3 evidence requires the QMP suspend event: $release_doc"
    assert_grep_fixed '`WAKEUP` event evidence' "$release_doc" \
        "VM S3 evidence requires the QMP wakeup event: $release_doc"
    assert_grep_fixed 'A black SPICE scanout' "$release_doc" \
        "black virtual scanout is not accepted as S3 evidence: $release_doc"
    assert_grep_fixed 'virtual-display harness' "$release_doc" \
        "display-only failure is identified as a harness issue: $release_doc"
    assert_grep_fixed 'limitation' "$release_doc" \
        "display-only failure remains explicitly unqualified: $release_doc"
done
assert_grep_fixed '`virsh save`, a snapshot or a paused' "$RELEASE_PROCESS" \
    "release process rejects non-S3 lifecycle substitutes"
assert_grep_fixed 'save, snapshot and pause operations do not' "$TEST_STRATEGY" \
    "test strategy rejects non-S3 lifecycle substitutes"
assert_grep_fixed 'journalctl -b -k --no-pager >"$kernel_journal"' \
    "$RUNTIME_GATE" "post-resume evidence drains journalctl before matching"
assert_not_grep 'journalctl -b -k --no-pager | grep -q' "$RUNTIME_GATE" \
    "post-resume gate cannot false-fail from journalctl SIGPIPE"
assert_grep_fixed 'wait_post_resume_readiness() {' \
    "$RUNTIME_GATE" "post-resume gate measures bounded readiness recovery"
assert_grep_fixed \
    'fail "gateway/XDP readiness did not recover fail-closed within 60 seconds"' \
    "$RUNTIME_GATE" "post-resume readiness recovery has an explicit bound"
assert_grep_fixed '[[ $activity != *$'\''0 sources online'\''* ]]' \
    "$RUNTIME_GATE" "post-resume wait rejects sources online before readiness"
assert_grep_fixed 'readiness_wait_s=$readiness_wait_seconds' \
    "$RUNTIME_GATE" "post-resume PASS evidence reports its bounded wait"
assert_grep_fixed 'live_mutator=/usr/libexec/livesys/livesys-main' \
    "$RUNTIME_GATE" "live pass binds Fedora's native RTC write suppression"
assert_grep_fixed 'grep -qw rd.live.image /proc/cmdline' \
    "$RUNTIME_GATE" "live pass verifies the actual Live-media identity"
assert_grep_fixed \
    "grep -qxF \"sed -i 's/rtcsync//' /etc/chrony.conf\" \"\$live_mutator\"" \
    "$RUNTIME_GATE" "live pass verifies Fedora's exact rtcsync mutation"
assert_grep_fixed \
    '[[ $(rpm -qf --qf '\''%{NAME}'\'' "$live_mutator") == livesys-scripts ]]' \
    "$RUNTIME_GATE" "live RTC mutation remains owned by livesys-scripts"
assert_grep_fixed 'if [[ $PASS_ID != live ]]; then' \
    "$RUNTIME_GATE" "installed passes retain rtcsync in the exact config"
assert_grep_fixed "printf '%s\\n' rtcsync" \
    "$RUNTIME_GATE" "installed expected config contains the RTC sync directive"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

extract_heredoc "$KS_FILE" "CHRONY_EOF" "$TMPDIR/chrony.conf" || _fail "chrony.conf extraction"
extract_heredoc "$KS_FILE" "TIME_RECOVERY_EOF" \
    "$TMPDIR/noid-time-recovery" || _fail "time-recovery helper extraction"
extract_heredoc "$KS_FILE" "TIME_RECOVERY_DOC_EOF" \
    "$TMPDIR/11-time-recovery.md" || _fail "time-recovery guide extraction"
extract_heredoc "$KS_FILE" "NTP_PROVIDER_EOF" \
    "$TMPDIR/50-chronyd.list" || _fail "timedated provider extraction"
extract_heredoc "$KS_FILE" "NTS_SOURCE_MANIFEST_EOF" \
    "$TMPDIR/11-nts-sources.tsv" || _fail "NTS source manifest extraction"
extract_heredoc "$KS_FILE" "CHRONY_PRESET_EOF" \
    "$TMPDIR/05-noid-chrony.preset" || _fail "chrony preset extraction"
extract_heredoc "$KS_FILE" "CHRONY_NETWORK_OFFLINE_SERVICE_EOF" \
    "$TMPDIR/noid-chrony-network-offline.service" \
    || _fail "chrony offline gate service extraction"
extract_heredoc "$KS_FILE" "CHRONY_NETWORK_ONLINE_SERVICE_EOF" \
    "$TMPDIR/noid-chrony-network-online.service" \
    || _fail "chrony readiness service extraction"
extract_heredoc "$KS_FILE" "CHRONY_ONOFFLINE_SHADOW_EOF" \
    "$TMPDIR/20-chrony-onoffline" \
    || _fail "chrony onoffline dispatcher shadow extraction"
extract_heredoc "$KS_FILE" "CHRONY_DHCP_SHADOW_EOF" \
    "$TMPDIR/20-chrony-dhcp" \
    || _fail "chrony DHCP dispatcher shadow extraction"
chmod +x "$TMPDIR/noid-time-recovery"

# --- 6 production/public NTS servers, declaratively offline at start -------
srv_count=$(grep -cE '^server .* iburst nts ipv4 maxpoll 11 offline$' \
    "$TMPDIR/chrony.conf" 2>/dev/null || true)
srv_count=${srv_count:-0}
assert_eq "6" "$srv_count" \
    "6 NTS servers with ipv4 + maxpoll + offline keywords"

# --- Each expected server present (DE×2 PTB / SE×2 Netnod / NL×2 SIDN) -
for srv in ptbtime1.ptb.de ptbtime4.ptb.de \
           lul1.nts.netnod.se mmo1.nts.netnod.se \
           ntppool1.time.nl ntppool2.time.nl; do
    assert_grep_fixed "server ${srv} iburst nts ipv4 maxpoll 11 offline" \
        "$TMPDIR/chrony.conf" "offline NTS server: $srv"
done
retired_server_ere='^server (ptbtime2|ptbtime3)\.ptb\.de|^server (sth1|gbg1)\.nts\.netnod\.se'
assert_not_grep_extended \
    "$retired_server_ere" \
    "$TMPDIR/chrony.conf" \
    "retired duplicate-operator slots stay outside the six-source baseline"
for retired_server in ptbtime2.ptb.de ptbtime3.ptb.de \
        sth1.nts.netnod.se gbg1.nts.netnod.se; do
    if printf 'server %s iburst nts ipv4 maxpoll 11 offline\n' "$retired_server" | \
            grep -qE "$retired_server_ere"; then
        _pass "retired-server guard detects: $retired_server"
    else
        _fail "retired-server guard missed: $retired_server"
    fi
done
assert_not_grep '^server ntppool[34]\.time\.nl ' "$TMPDIR/chrony.conf" \
    "SIDN pre-production sources are absent from the base configuration"
assert_grep_fixed 'ntppool3/4 are pre-production' "$TMPDIR/chrony.conf" \
    "SIDN pre-production exclusion is documented"

# The installed manifest must be a byte-identical view of the canonical source,
# have one closed dated row per configured hostname and generate chrony.conf
# exactly. This prevents comment-only or status-only drift from passing.
assert_cmd_success "M11 embeds the canonical dated NTS source manifest" \
    cmp -s "$SOURCE_MANIFEST" "$TMPDIR/11-nts-sources.tsv"
assert_cmd_success "canonical NTS source manifest has closed schema and metadata" \
    awk -F '\t' '
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
    ' "$SOURCE_MANIFEST"
assert_eq 1 "$(tail -n +2 "$SOURCE_MANIFEST" | cut -f6 | sort -u | wc -l)" \
    "canonical NTS source rows share one manifest-owned review date"
assert_eq 2026-08-14 "$(tail -n +2 "$SOURCE_MANIFEST" | cut -f6 | sort -u)" \
    "canonical NTS operator evidence was revalidated for this audit"
awk -F '\t' \
    'NR > 1 {print "server " $1 " iburst nts ipv4 maxpoll 11 offline"}' \
    "$SOURCE_MANIFEST" > "$TMPDIR/chrony-from-manifest"
grep '^server ' "$TMPDIR/chrony.conf" > "$TMPDIR/chrony-server-lines"
assert_cmd_success "chrony server lines exactly match the dated manifest" \
    cmp -s "$TMPDIR/chrony-from-manifest" "$TMPDIR/chrony-server-lines"
cp "$TMPDIR/chrony-from-manifest" "$TMPDIR/chrony-active.expected"
cat >> "$TMPDIR/chrony-active.expected" <<'EXPECTED_CHRONY_ACTIVE_EOF'
minsources 3
maxupdateskew 100.0
keyfile /dev/null
driftfile /var/lib/chrony/drift
makestep 1.0 3
maxchange 1000 3 0
rtcsync
ntsdumpdir /var/lib/chrony
leapseclist /usr/share/zoneinfo/leap-seconds.list
bindcmdaddress /var/run/chrony/chronyd.sock
cmdport 0
EXPECTED_CHRONY_ACTIVE_EOF
awk '!/^[[:space:]]*(#|$)/ {print}' "$TMPDIR/chrony.conf" \
    > "$TMPDIR/chrony-active.actual"
assert_cmd_success "active chrony.conf is a closed manifest-generated policy" \
    cmp -s "$TMPDIR/chrony-active.expected" "$TMPDIR/chrony-active.actual"

# --- regression guard: dead UNIZG-FER servers MUST stay absent ----------
# nts1/nts2.ntp.hr removed (endpoints dead + lame PTR delegation
# = the interactive `chronyc sources` 4-min stall). Do NOT re-add.
# (Match server lines only — the heredoc removal-documentation comments legitimately
# mention ntp.hr as removal documentation.)
if grep -qE '^server .*ntp\.hr' "$TMPDIR/chrony.conf"; then
    _fail "dead ntp.hr server line present (removed: dead endpoint + lame PTR stall)"
else
    _pass "no ntp.hr server line (regression guard)"
fi

# --- regression guard: anycast nts.netnod.se MUST stay absent -----------
# Replaced with lul1.nts.netnod.se (unicast). The anycast NTS-KE
# endpoint can negotiate another configured source's -ts backend -> chronyd
# duplicate-source refusal, slot stuck at reach 0. Anchored match: bare
# "nts.netnod.se" is a substring of every site-server name.
if grep -qE '^server nts\.netnod\.se ' "$TMPDIR/chrony.conf"; then
    _fail "anycast nts.netnod.se server line present (replaced with unicast site server)"
else
    _pass "no anycast nts.netnod.se server line (regression guard)"
fi

# --- Quorum + command interface hardening ----------------------------------
assert_grep_extended '^minsources 3$' "$TMPDIR/chrony.conf" \
    "minsources=3 minimum selectable-source threshold"
assert_grep_fixed 'CHRONY_MIN_ONLINE=3' "$M04_FILE" \
    "M04 online-consumer readiness matches M11 minsources"
assert_not_grep 'forces majority consensus' "$TMPDIR/chrony.conf" \
    "minsources is not misdescribed as a voting quorum"
assert_grep_fixed 'not a quorum or 3-of-6 vote' "$TMPDIR/chrony.conf" \
    "minsources semantics are documented accurately"
assert_grep_fixed 'does not prevent packet dropping' "$TMPDIR/chrony.conf" \
    "NTS delay/drop boundary is explicit"
assert_grep_extended '^cmdport 0$'    "$TMPDIR/chrony.conf" "cmdport 0 (no UDP:323)"
assert_grep_fixed 'bindcmdaddress /var/run/chrony/chronyd.sock' "$TMPDIR/chrony.conf" "Unix socket"

# --- hardening directives ------------------------------
assert_eq 1 "$(grep -cE '^maxchange 1000 3 0$' "$TMPDIR/chrony.conf")" \
    "maxchange skips all three bootstrap updates, then restores the panic bound"
assert_grep_fixed 'is not authentication' "$TMPDIR/chrony.conf" \
    "maxchange is not misrepresented as an authentication control"
assert_grep_fixed 'firmware RTC containing local civil time' \
    "$TMPDIR/chrony.conf" \
    "normal localtime-as-UTC bootstrap regression is documented"
assert_grep_fixed 'clock outside' "$TMPDIR/chrony.conf" \
    "TLS certificate-validity recovery boundary remains explicit"
assert_grep_extended '^maxupdateskew 100\.0$' "$TMPDIR/chrony.conf" "maxupdateskew"
assert_grep_extended '^keyfile /dev/null$' "$TMPDIR/chrony.conf" \
    "symmetric-key path fails closed"
assert_grep_fixed 'keyfile` does not select an' "$TMPDIR/chrony.conf" \
    "keyfile semantics are not confused with NTS source selection"
assert_grep_fixed 'chronyd -p -f /etc/chrony.conf' "$KS_FILE" "syntax pre-validation"

# --- Logging disabled by design ----------------------------
# Fedora's chrony stanza inherits about 35 days of global weekly retention,
# beyond M42's scoped 30-day boundary; measurement logs also carry source and
# oscillator-frequency timing evidence. Live debug uses `chronyc tracking`.
chrony_log_directive_ere='^[[:space:]]*(log([[:space:]]|$)|logdir([[:space:]]|$)|logbanner([[:space:]]|$))'
if grep -qE "$chrony_log_directive_ere" \
        "$TMPDIR/chrony.conf"; then
    _fail "chrony.conf has a persistent measurement-logging directive"
else
    _pass "chrony measurement-file logging disabled"
fi
assert_grep_fixed \
    "if grep -qE '^[[:space:]]*(log([[:space:]]|$)|logdir([[:space:]]|$)|logbanner([[:space:]]|$))'" \
    "$KS_FILE" "compose verification rejects every chrony logging directive"
for logging_directive in \
        'log rawmeasurements' 'log measurements' 'log statistics' \
        'log selection' 'log tracking' 'log rtc' 'log refclocks' \
        'log tempcomp' $' log\tmeasurements' $'logdir\t/var/log/chrony' \
        $'\tlogbanner 64' 'log'; do
    if printf '%s\n' "$logging_directive" | grep -qE "$chrony_log_directive_ere"; then
        _pass "logging guard rejects: $logging_directive"
    else
        _fail "logging guard missed: $logging_directive"
    fi
done
for non_logging_directive in 'logchange 0.5' 'logratelimit 5' 'clientloglimit 0'; do
    if printf '%s\n' "$non_logging_directive" | grep -qE "$chrony_log_directive_ere"; then
        _fail "logging guard overmatched: $non_logging_directive"
    else
        _pass "logging guard preserves: $non_logging_directive"
    fi
done
assert_not_grep_extended 'unbounded growth|accumulate indefinitely' "$KS_FILE" \
    "chrony logging rationale does not overstate inherited logrotate retention"
assert_grep_fixed 'about 35 days' "$KS_FILE" \
    "chrony logging rationale accounts for inherited weekly rotation"
assert_grep_fixed 'not covered by noid-misc-logs-prune' "$KS_FILE" \
    "chrony logging rationale names the M42 scope gap"

# --- Closed source set + no unauthenticated fallback ------------------------
if grep -qE '^pool ' "$TMPDIR/chrony.conf"; then
    _fail "pool directive present (source set is no longer manifest-closed)"
else
    _pass "no dynamic pool directive (closed source-set mandate)"
fi
if grep -qE '^sourcedir /run/chrony-dhcp' "$TMPDIR/chrony.conf"; then
    _fail "sourcedir /run/chrony-dhcp present (DHCP NTP injection possible)"
else
    _pass "no sourcedir /run/chrony-dhcp (DHCP NTP blocked)"
fi

# --- timesyncd mask in KS source --------------------------------------------
assert_grep_fixed 'systemctl mask systemd-timesyncd.service' "$KS_FILE"

# Existing state directories are reconciled, not trusted based on existence.
assert_grep_fixed 'install -d -o chrony -g chrony -m 0750 "$d"' "$KS_FILE" \
    "chrony state directories have enforced ownership and mode"
assert_grep_fixed 'owner/mode postcondition failed' "$KS_FILE" \
    "chrony directory enforcement has a postcondition"
assert_not_grep 'restorecon .*2>/dev/null' "$KS_FILE" \
    "M11 does not hide SELinux relabel diagnostics"
assert_not_grep 'restorecon .*|| true' "$KS_FILE" \
    "M11 does not swallow SELinux relabel failures"
for labeled_path in \
    /etc/chrony.conf \
    /usr/share/doc/noid-privacy/11-nts-sources.tsv \
    /etc/systemd/ntp-units.d/50-chronyd.list \
    /etc/systemd/system-preset/05-noid-chrony.preset \
    /usr/local/sbin/noid-time-recovery \
    /usr/share/doc/noid-privacy/11-time-recovery.md; do
    assert_grep_fixed "matchpathcon -V $labeled_path" "$KS_FILE" \
        "M11 verifies the active SELinux label: $labeled_path"
done

# --- Fedora-native restricted client; no brittle custom syscall owner ------
assert_not_grep 'OPTIONS="-F 1"\|CHRONYD_OPTS_EOF' "$KS_FILE" \
    "retired custom -F 1 allowlist is absent"
assert_grep_fixed 'OPTIONS="-F 2"' "$KS_FILE" \
    "Fedora-maintained seccomp level remains exact"
assert_grep_fixed "rpm -qf --qf '%{NAME}\\n' \"\$restricted_unit\"" "$KS_FILE" \
    "restricted unit is bound to the chrony RPM"
assert_grep_fixed 'rpm_payload_file_pristine chrony "$restricted_unit"' "$KS_FILE" \
    "restricted unit must remain byte-identical to its signed RPM payload"
assert_grep_fixed 'rpm_payload_file_pristine chrony /etc/sysconfig/chronyd' "$KS_FILE" \
    "chronyd options must remain byte-identical to the package default"
assert_grep_fixed 'rpm_payload_file_pristine chrony "$chrony_vendor_dispatcher"' \
    "$KS_FILE" "vendor chrony dispatchers remain byte-identical to their RPM payload"
assert_grep_fixed "'%{FILEDIGESTALGO}'" "$KS_FILE" \
    "RPM payload comparison requires SHA-256 file digests"
assert_grep_fixed "'[%{FILENAMES}\\t%{FILEDIGESTS}\\n]'" "$KS_FILE" \
    "RPM payload comparison selects the exact file digest"

# Exercise the exact single-file RPM digest oracle without depending on the
# structural-test host having Fedora's chrony package installed.
{
    printf '%s\n' '#!/bin/bash'
    sed -n '/^rpm_payload_file_pristine() {$/,/^}$/p' "$KS_FILE"
} > "$TMPDIR/rpm-payload-function"
assert_cmd_success "RPM payload helper parses" bash -n "$TMPDIR/rpm-payload-function"
printf '%s\n' 'vendor payload bytes' > "$TMPDIR/vendor-file"
vendor_digest=$(sha256sum "$TMPDIR/vendor-file" | awk '{print $1}')
assert_cmd_success "RPM payload helper accepts one exact SHA-256 record" \
    env FIXTURE="$TMPDIR/vendor-file" EXPECTED="$vendor_digest" DUPLICATE=0 \
    bash -c '
        . "$1"
        rpm() {
            case "$*" in
                *FILEDIGESTALGO*) printf 8 ;;
                *FILEDIGESTS*)
                    printf "%s\t%s\n" "$FIXTURE" "$EXPECTED"
                    [[ $DUPLICATE == 0 ]] || printf "%s\t%s\n" "$FIXTURE" "$EXPECTED"
                    ;;
                *) return 2 ;;
            esac
        }
        rpm_payload_file_pristine chrony "$FIXTURE"
    ' _ "$TMPDIR/rpm-payload-function"
printf '%s\n' 'post-package mutation' >> "$TMPDIR/vendor-file"
mutated_digest=$(sha256sum "$TMPDIR/vendor-file" | awk '{print $1}')
assert_cmd_failure "RPM payload helper rejects changed bytes" \
    env FIXTURE="$TMPDIR/vendor-file" EXPECTED="$vendor_digest" DUPLICATE=0 \
    bash -c '
        . "$1"
        rpm() {
            case "$*" in
                *FILEDIGESTALGO*) printf 8 ;;
                *FILEDIGESTS*) printf "%s\t%s\n" "$FIXTURE" "$EXPECTED" ;;
                *) return 2 ;;
            esac
        }
        rpm_payload_file_pristine chrony "$FIXTURE"
    ' _ "$TMPDIR/rpm-payload-function"
assert_cmd_failure "RPM payload helper rejects duplicate path records" \
    env FIXTURE="$TMPDIR/vendor-file" EXPECTED="$mutated_digest" DUPLICATE=1 \
    bash -c '
        . "$1"
        rpm() {
            case "$*" in
                *FILEDIGESTALGO*) printf 8 ;;
                *FILEDIGESTS*)
                    printf "%s\t%s\n%s\t%s\n" \
                        "$FIXTURE" "$EXPECTED" "$FIXTURE" "$EXPECTED"
                    ;;
                *) return 2 ;;
            esac
        }
        rpm_payload_file_pristine chrony "$FIXTURE"
    ' _ "$TMPDIR/rpm-payload-function"
for native_line in \
    'ExecStart=/usr/sbin/chronyd -n -U $OPTIONS' \
    'SELinuxContext=system_u:system_r:chronyd_restricted_t:s0' \
    'AmbientCapabilities=CAP_SYS_TIME' \
    'CapabilityBoundingSet=CAP_SYS_TIME' \
    'NoNewPrivileges=yes' \
    'PrivateDevices=yes' \
    'ProtectSystem=strict' \
    'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX'; do
    assert_grep_fixed "$native_line" "$KS_FILE" \
        "restricted-unit contract: $native_line"
done
assert_grep_fixed 'systemctl disable chronyd.service' "$KS_FILE" \
    "ordinary chronyd service is disabled"
assert_grep_fixed \
    'systemctl enable chronyd-restricted.service noid-chrony-network-online.service' \
    "$KS_FILE" "restricted chronyd service and readiness consumer are enabled"
assert_grep_fixed 'Requires=chronyd-restricted.service' \
    "$TMPDIR/noid-chrony-network-offline.service" \
    "offline gate requires the native restricted daemon"
assert_grep_fixed 'After=chronyd-restricted.service' \
    "$TMPDIR/noid-chrony-network-offline.service" \
    "offline gate runs after the native restricted daemon"
assert_grep_fixed 'Before=noid-chrony-network-online.service' \
    "$TMPDIR/noid-chrony-network-offline.service" \
    "offline transition orders before online consumption"
assert_grep_fixed \
    'ExecStart=/usr/local/libexec/noid-network-readiness offline-consumer' \
    "$TMPDIR/noid-chrony-network-offline.service" \
    "offline gate uses the closed chrony-owned helper action"
assert_grep_fixed 'User=chrony' "$TMPDIR/noid-chrony-network-offline.service" \
    "offline chronyc runs as Fedora's native chrony account"
assert_grep_fixed 'Group=chrony' "$TMPDIR/noid-chrony-network-offline.service" \
    "offline chronyc uses the native chrony socket group"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' \
    "$TMPDIR/noid-chrony-network-offline.service" \
    "offline gate needs no network socket of its own"
assert_grep_fixed 'CapabilityBoundingSet=' \
    "$TMPDIR/noid-chrony-network-offline.service" \
    "offline gate receives no Linux capability"
assert_not_grep '^NoNewPrivileges=yes$' \
    "$TMPDIR/noid-chrony-network-offline.service" \
    "offline gate permits Fedora's chronyc_t SELinux transition"
assert_not_grep 'WantedBy=' "$TMPDIR/noid-chrony-network-offline.service" \
    "offline transition is static and cannot become a boot-time activator"
# ProtectSystem=strict makes /run read-only. Both one-shots write under
# /run/chrony -- the transition lock, and the reply socket chronyc creates
# next to chronyd.sock -- so without this the sandbox kills them before
# chronyc runs at all. Every NTS source ships `offline`, which makes a dead
# online-consumer mean the clock never synchronises on any installed system.
for chrony_transition_unit in offline online; do
    assert_grep_fixed 'ReadWritePaths=/run/chrony' \
        "$TMPDIR/noid-chrony-network-${chrony_transition_unit}.service" \
        "${chrony_transition_unit} transition may write the runtime dir chronyc needs"
    # RuntimeDirectory= would remove /run/chrony, and with it chronyd's own
    # socket, every time this one-shot stops.
    assert_not_grep '^RuntimeDirectory=' \
        "$TMPDIR/noid-chrony-network-${chrony_transition_unit}.service" \
        "${chrony_transition_unit} transition never claims ownership of /run/chrony"
done
assert_grep_fixed 'Requires=chronyd-restricted.service' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "readiness consumer requires the native restricted daemon"
assert_grep_fixed 'After=chronyd-restricted.service' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "readiness consumer runs after the native restricted daemon"
assert_grep_fixed \
    'ConditionPathExists=/run/noid-privacy/gateway-xdp.ready' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "readiness consumer cannot run without the exact M04 signal path"
assert_grep_fixed \
    'ExecStart=/usr/local/libexec/noid-network-readiness online-consumer' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "readiness consumer revalidates the marker and boundary"
assert_grep_fixed 'Restart=on-failure' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "bounded resolver failure remains automatically recoverable"
assert_grep_fixed 'RestartSec=30s' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "first resolver recovery attempt has an explicit delay"
assert_grep_fixed 'RestartSteps=4' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "resolver recovery uses native exponential backoff"
assert_grep_fixed 'RestartMaxDelaySec=15min' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "prolonged upstream failure has a bounded retry cadence"
for chrony_retry_directive in Restart RestartSec RestartSteps RestartMaxDelaySec; do
    assert_not_grep "^${chrony_retry_directive}=" \
        "$TMPDIR/noid-chrony-network-offline.service" \
        "offline transition never retries or activates sources: ${chrony_retry_directive}"
done
assert_grep_fixed 'User=chrony' "$TMPDIR/noid-chrony-network-online.service" \
    "chronyc runs as Fedora's native chrony account"
assert_grep_fixed 'Group=chrony' "$TMPDIR/noid-chrony-network-online.service" \
    "chronyc reaches only Fedora's root-private Unix socket"
assert_grep_fixed \
    'ExecStartPre=!/usr/local/libexec/noid-network-readiness consumer-precheck' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "documented systemd credential prefix isolates the root-only state precheck"
assert_grep_fixed 'WantedBy=chronyd-restricted.service' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "native daemon restarts re-consume an already valid readiness marker"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "readiness consumer needs no network socket of its own"
assert_grep_fixed 'CapabilityBoundingSet=' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "readiness consumer receives no Linux capability"
assert_not_grep '^NoNewPrivileges=yes$' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "readiness consumer permits Fedora's chronyc_t SELinux transition"
assert_grep_fixed 'RestrictSUIDSGID=yes' \
    "$TMPDIR/noid-chrony-network-online.service" \
    "readiness consumer still blocks SUID/SGID privilege acquisition"
assert_grep_fixed \
    'systemctl disable noid-chrony-network-online.path >/dev/null 2>&1 || true' \
    "$KS_FILE" "retired readiness path activation is removed on upgrade"
assert_grep_fixed \
    '/etc/systemd/system/noid-chrony-network-online.path' "$KS_FILE" \
    "retired readiness path file is removed on upgrade"
assert_grep_fixed \
    "rpm -qf --qf '%{NAME}\\n'" "$KS_FILE" \
    "timesyncd ownership check uses Fedora RPM metadata"
assert_grep_fixed \
    '/usr/lib/systemd/system/systemd-timesyncd.service' "$KS_FILE" \
    "timesyncd ownership is checked at its Fedora vendor unit"
assert_grep_fixed '= systemd-udev ]' "$KS_FILE" \
    "Fedora 44 timesyncd is bound to its actual systemd-udev owner"
assert_eq $'disable chronyd.service\nenable chronyd-restricted.service' \
    "$(cat "$TMPDIR/05-noid-chrony.preset")" \
    "native preset keeps the ordinary service disabled in target transactions"
cat > "$TMPDIR/50-chronyd.expected" <<'NTP_PROVIDER_EXPECTED_EOF'
# NoID Privacy — keep systemd-timedated on Fedora's restricted NTS client.
chronyd-restricted.service
NTP_PROVIDER_EXPECTED_EOF
assert_cmd_success "timedated provider is exact and comment-safe" \
    cmp -s "$TMPDIR/50-chronyd.expected" "$TMPDIR/50-chronyd.list"
assert_not_grep_extended "(^|[[:space:]<'])CH_EOF([[:space:]']|$)|/etc/systemd/system/chronyd\\.service\\.d|/etc/systemd/system/chronyd-restricted\\.service\\.d" \
    "$M08_FILE" "M08 has no competing chronyd sandbox owner"

for dispatcher_shadow in 20-chrony-dhcp 20-chrony-onoffline; do
    assert_cmd_success "$dispatcher_shadow shadow parses" \
        sh -n "$TMPDIR/$dispatcher_shadow"
    assert_eq 'exit 0' \
        "$(awk '!/^[[:space:]]*(#|$)/ {print}' "$TMPDIR/$dispatcher_shadow")" \
        "$dispatcher_shadow is an exact functional no-op"
done
assert_grep_fixed \
    'chrony_admin_dispatcher_dir=/etc/NetworkManager/dispatcher.d' \
    "$KS_FILE" "chrony overrides use NetworkManager's native administrator tier"
assert_grep_fixed \
    "matchpathcon -V \\" "$KS_FILE" \
    "chrony dispatcher shadows participate in the SELinux postcondition"
assert_not_grep_extended \
    'rm[[:space:]]+-f.*20-chrony-(dhcp|onoffline)|sed[[:space:]].*20-chrony-(dhcp|onoffline)' \
    "$KS_FILE" "Fedora chrony dispatcher payloads are never deleted or patched"

# --- header and dependency doctrine match the six-source manifest ----------
assert_grep_fixed '6 operator-supported' "$KS_FILE" \
    "header names the six supported servers"
assert_grep_fixed 'ptbtime4.ptb.de' "$KS_FILE" \
    "PTB separate-location slot remains"
assert_grep_fixed 'mmo1.nts.netnod.se' "$KS_FILE" \
    "Netnod Malmö site slot remains"
assert_grep_fixed 'revalidate for every release candidate' "$KS_FILE" \
    "mutable NTS dependencies are release-gated"
assert_grep_fixed 'dated primary operator' "$KS_FILE" \
    "operator status comes from dated primary-source evidence"

# --- Bad-clock recovery: no authentication downgrade -----------------------
assert_cmd_success "time-recovery helper parses" \
    bash -n "$TMPDIR/noid-time-recovery"
assert_cmd_success "time-recovery helper passes ShellCheck" \
    shellcheck "$TMPDIR/noid-time-recovery"
assert_file_min_size "$TMPDIR/11-time-recovery.md" 2500 \
    "time-recovery guide is complete"
assert_grep_fixed 'no authenticated measurement exists to step' \
    "$TMPDIR/chrony.conf" \
    "chrony config explains why makestep cannot break the TLS dependency cycle"
assert_grep_fixed 'use a physical Linux VT such as /dev/tty3' \
    "$TMPDIR/noid-time-recovery" "recovery requires a physical local VT"
assert_grep_fixed 'remote sessions are not accepted for clock recovery' \
    "$TMPDIR/noid-time-recovery" "recovery explicitly rejects SSH state"
assert_grep_fixed 'SET VERIFIED UTC $candidate' "$TMPDIR/noid-time-recovery" \
    "confirmation is bound to the exact candidate timestamp"
assert_grep_fixed 'candidate UTC predates the immutable image timestamp' \
    "$TMPDIR/noid-time-recovery" \
    "candidate cannot predate canonical image provenance"
assert_grep_fixed "stat -c '%u:%g:%a:%h'" "$TMPDIR/noid-time-recovery" \
    "build-floor parser rejects hard-link aliases"
assert_grep_fixed 'candidate UTC exceeds the image-relative five-year recovery horizon' \
    "$TMPDIR/noid-time-recovery" \
    "image-relative upper bound catches confirmed future-year errors"
assert_grep_fixed 'trap recovery_cleanup EXIT' "$TMPDIR/noid-time-recovery" \
    "post-stop failures have a chronyd restoration trap"
assert_grep_fixed 'systemctl stop chronyd-restricted.service' \
    "$TMPDIR/noid-time-recovery" "recovery stops only the restricted client"
assert_grep_fixed 'systemctl start chronyd-restricted.service' \
    "$TMPDIR/noid-time-recovery" "recovery restores only the restricted client"
assert_not_grep 'systemctl stop chronyd\.service' \
    "$TMPDIR/noid-time-recovery" "recovery never stops the ordinary client"
assert_not_grep 'systemctl start chronyd\.service' \
    "$TMPDIR/noid-time-recovery" "recovery never activates the ordinary client"
assert_grep_fixed 'set_system_clock "$candidate_epoch"' \
    "$TMPDIR/noid-time-recovery" "validated epoch is the only clock-set input"
assert_grep_fixed 'sync_rtc' "$TMPDIR/noid-time-recovery" \
    "hardware RTC is updated when present"
assert_not_grep_extended 'curl|wget|(^|[^a-z_])nc |sntp|ntpdate|nocerttimecheck|server pool\.ntp\.org' \
    "$TMPDIR/noid-time-recovery" \
    "recovery helper has no network bootstrap or authentication bypass"
assert_not_grep_extended '^[[:space:]]*nocerttimecheck([[:space:]]|$)' \
    "$TMPDIR/chrony.conf" "chrony certificate-time validation stays enabled"
assert_grep_fixed 'does **not** enable plaintext NTP, `nocerttimecheck`' \
    "$TMPDIR/11-time-recovery.md" \
    "guide explicitly preserves the authenticated-only boundary"
assert_grep_fixed 'large initial offset which is still inside the' \
    "$TMPDIR/11-time-recovery.md" \
    "guide assigns certificate-valid initial offsets to automatic NTS recovery"
assert_grep_fixed 'still cannot validate the server certificates' \
    "$TMPDIR/11-time-recovery.md" \
    "guide limits manual recovery to the NTS certificate-time dependency"
assert_grep_fixed 'sudo chronyc -N authdata' "$TMPDIR/11-time-recovery.md" \
    "guide accounts for the group-restricted chronyd command socket"

assert_cmd_success "three-pass chronyd runtime gate parses" bash -n "$RUNTIME_GATE"
assert_cmd_success "three-pass chronyd runtime gate passes ShellCheck" \
    shellcheck -S warning "$RUNTIME_GATE"
type_stat_count=$(grep -cF "stat -c '%F:%U:%G:%a'" "$RUNTIME_GATE" || true)
c_locale_type_stat_count=$(
    grep -cF "LC_ALL=C stat -c '%F:%U:%G:%a'" "$RUNTIME_GATE" || true
)
assert_eq 3 "$type_stat_count" \
    "chronyd runtime gate has the exact reviewed file-type metadata checks"
assert_eq "$type_stat_count" "$c_locale_type_stat_count" \
    "every localized chronyd file-type check is pinned to the C locale"
assert_grep_fixed 'live|fresh-install|reboot) ;;' "$RUNTIME_GATE" \
    "runtime gate accepts the exact three lifecycle identities"
for action in offline online rtc-bootstrap cookie-restart fresh-ke post-resume; do
    assert_grep_fixed "$action" "$RUNTIME_GATE" \
        "runtime gate carries chronyd lifecycle action: $action"
done
assert_grep_fixed 'fresh-ke|rtc-bootstrap)' "$RUNTIME_GATE" \
    "fresh NTS-KE and RTC bootstrap proofs are fresh-install-only actions"
assert_grep_fixed 'echo "$ACTION is restricted to the fresh-install pass"' \
    "$RUNTIME_GATE" "fresh-install-only action refusal is explicit"
assert_grep_fixed 'rtc_bootstrap_offset_seconds < 6900' "$RUNTIME_GATE" \
    "RTC bootstrap gate requires the lower bound of the injected two-hour offset"
assert_grep_fixed 'rtc_bootstrap_offset_seconds > 7500' "$RUNTIME_GATE" \
    "RTC bootstrap gate requires the upper bound of the injected two-hour offset"
assert_grep_fixed 'system_u:system_r:chronyd_restricted_t:s0' "$RUNTIME_GATE" \
    "runtime gate checks the effective restricted SELinux domain"
assert_grep_fixed '0000000002000000' "$RUNTIME_GATE" \
    "runtime gate checks that CAP_SYS_TIME is the only process capability"
assert_grep_fixed 'chronyd runtime SELinux label mismatch' "$RUNTIME_GATE" \
    "runtime gate verifies socket and state-directory SELinux labels"
assert_grep_fixed 'expected 6 dumped NTS source files' "$RUNTIME_GATE" \
    "runtime gate proves NTS cookie dump cardinality"
assert_grep_fixed 'NTS KeyID changed across restart' "$RUNTIME_GATE" \
    "runtime gate rejects a fresh NTS-KE during cookie reload"
assert_grep_fixed 'print $1, $2, $3, $4, $5' "$RUNTIME_GATE" \
    "runtime gate compares source, mode, KeyID, AEAD and key length"
assert_grep_fixed '$7 != 0 || $8 != 0 ||' "$RUNTIME_GATE" \
    "runtime gate rejects key-establishment attempts and NTS NAKs"
assert_grep_fixed '$9 !~ /^[1-9][0-9]*$/ || $10 !~ /^[1-9][0-9]*$/' \
    "$RUNTIME_GATE" \
    "runtime gate requires positive usable-cookie state per NTS source"
assert_not_grep 'persisted NTS cookie files changed' "$RUNTIME_GATE" \
    "runtime gate does not mistake normal cookie rotation for fresh NTS-KE"
assert_grep_fixed 'restart_service_on_cleanup=1' "$RUNTIME_GATE" \
    "runtime gate restores chronyd after a stopped-state failure"
assert_grep_fixed "trap 'cleanup 129' HUP" "$RUNTIME_GATE" \
    "runtime gate preserves the conventional HUP failure result"
assert_grep_fixed "trap 'cleanup 130' INT" "$RUNTIME_GATE" \
    "runtime gate preserves the conventional INT failure result"
assert_grep_fixed "trap 'cleanup 143' TERM" "$RUNTIME_GATE" \
    "runtime gate preserves the conventional TERM failure result"
assert_grep_fixed 'fresh NTS-KE/certificate validation' "$RUNTIME_GATE" \
    "runtime gate forces a fresh certificate-authenticated NTS-KE"
assert_grep_fixed '/usr/share/doc/noid-privacy/11-nts-sources.tsv' "$RUNTIME_GATE" \
    "runtime gate consumes the installed dated source manifest"
assert_grep_fixed '-verify_hostname "$server"' "$RUNTIME_GATE" \
    "runtime gate verifies every NTS-KE TLS hostname"
assert_grep_fixed '-verify_return_error' "$RUNTIME_GATE" \
    "runtime gate fails closed on the NTS-KE certificate chain"
assert_grep_fixed "grep -qxF 'Protocol: TLSv1.3'" "$RUNTIME_GATE" \
    "runtime gate requires the exact TLS 1.3 result"
assert_grep_fixed "grep -qxF 'ALPN protocol: ntske/1'" "$RUNTIME_GATE" \
    "runtime gate requires the exact NTS-KE ALPN result"
assert_not_grep '-brief' "$RUNTIME_GATE" \
    "runtime gate retains the OpenSSL output surface that exposes negotiated ALPN"
assert_grep_fixed 'duplicate == 0' "$RUNTIME_GATE" \
    "runtime gate rejects duplicate negotiated timestamp backends"
assert_grep_fixed 'NTS_DEPENDENCY' "$RUNTIME_GATE" \
    "runtime gate emits per-pass public-dependency evidence"
assert_grep_fixed '$1 == "^*" || $1 == "^+" || $1 == "^-"' "$RUNTIME_GATE" \
    "runtime gate counts Chrony selectable-but-unused sources"
assert_grep_fixed 'timedatectl show -p NTP --value' "$RUNTIME_GATE" \
    "runtime gate verifies timedated sees the restricted provider"
awk '
    /^validate_ntske_tls_log\(\) \{$/ { copy = 1 }
    copy { print }
    copy && /^}$/ { exit }
' "$RUNTIME_GATE" > "$TMPDIR/validate-ntske-tls-log.sh"
# shellcheck source=/dev/null
. "$TMPDIR/validate-ntske-tls-log.sh"
cat > "$TMPDIR/ntske-valid.log" <<'NTSKE_VALID_EOF'
Verification: OK
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
ALPN protocol: ntske/1
Verify return code: 0 (ok)
NTSKE_VALID_EOF
assert_cmd_success "TLS parser accepts exact TLS 1.3 plus NTS-KE ALPN" \
    validate_ntske_tls_log "$TMPDIR/ntske-valid.log"
sed '/^ALPN protocol:/d' "$TMPDIR/ntske-valid.log" \
    > "$TMPDIR/ntske-missing-alpn.log"
assert_cmd_failure "TLS parser rejects a server that selects no ALPN" \
    validate_ntske_tls_log "$TMPDIR/ntske-missing-alpn.log"
sed 's#ALPN protocol: ntske/1#ALPN protocol: h2#' "$TMPDIR/ntske-valid.log" \
    > "$TMPDIR/ntske-wrong-alpn.log"
assert_cmd_failure "TLS parser rejects a non-NTS ALPN" \
    validate_ntske_tls_log "$TMPDIR/ntske-wrong-alpn.log"
sed 's#Protocol: TLSv1.3#Protocol: TLSv1.2#' "$TMPDIR/ntske-valid.log" \
    > "$TMPDIR/ntske-tls12.log"
assert_cmd_failure "TLS parser rejects TLS 1.2 even with NTS-KE ALPN" \
    validate_ntske_tls_log "$TMPDIR/ntske-tls12.log"
awk '
    /^chronyd_seccomp_failure\(\) \{$/ { copy = 1 }
    copy { print }
    copy && /^}$/ { exit }
' "$RUNTIME_GATE" > "$TMPDIR/chronyd-seccomp-failure.sh"
# shellcheck source=/dev/null
. "$TMPDIR/chronyd-seccomp-failure.sh"
cat > "$TMPDIR/unrelated-seccomp.log" <<'UNRELATED_SECCOMP_EOF'
kernel: audit: type=1326 comm="unrelated" seccomp denied syscall=59
unrelated.service: Main process exited, code=killed, status=31/SYS
chronyd-restricted.service: Active: active (running)
UNRELATED_SECCOMP_EOF
assert_cmd_failure "runtime gate ignores unrelated seccomp failures" \
    chronyd_seccomp_failure < "$TMPDIR/unrelated-seccomp.log"
cat > "$TMPDIR/chronyd-seccomp.log" <<'CHRONYD_SECCOMP_EOF'
kernel: audit: seccomp denied syscall=262 comm="chronyd"
CHRONYD_SECCOMP_EOF
assert_cmd_success "runtime gate detects a chronyd kernel seccomp denial" \
    chronyd_seccomp_failure < "$TMPDIR/chronyd-seccomp.log"
printf '%s\n' \
    'chronyd-restricted.service: Main process exited, code=killed, status=31/SYS' \
    > "$TMPDIR/chronyd-sigsys.log"
assert_cmd_success "runtime gate detects a chronyd service SIGSYS exit" \
    chronyd_seccomp_failure < "$TMPDIR/chronyd-sigsys.log"

# Build-floor parser uses exact owner/mode metadata and one canonical field.
cat > "$TMPDIR/build-info.good" <<'BUILD_INFO_EOF'
NOID_BUILD_TIMESTAMP="2026-07-12T12:00:00Z"
BUILD_INFO_EOF
chmod 0644 "$TMPDIR/build-info.good"
fixture_uid=$(id -u)
fixture_gid=$(id -g)
assert_cmd_success "build-floor parser accepts exact trusted metadata/value" \
    bash -c '. "$1"; test "$(load_build_floor "$2" "$3" "$4" 644)" = "2026-07-12T12:00:00Z"' \
        _ "$TMPDIR/noid-time-recovery" "$TMPDIR/build-info.good" \
        "$fixture_uid" "$fixture_gid"
ln -s build-info.good "$TMPDIR/build-info.link"
assert_cmd_failure "build-floor parser rejects a symlink" \
    bash -c '. "$1"; load_build_floor "$2" "$3" "$4" 644 >/dev/null' \
        _ "$TMPDIR/noid-time-recovery" "$TMPDIR/build-info.link" \
        "$fixture_uid" "$fixture_gid"
ln "$TMPDIR/build-info.good" "$TMPDIR/build-info.hardlink"
assert_cmd_failure "build-floor parser rejects a hard-link alias" \
    bash -c '. "$1"; load_build_floor "$2" "$3" "$4" 644 >/dev/null' \
        _ "$TMPDIR/noid-time-recovery" "$TMPDIR/build-info.hardlink" \
        "$fixture_uid" "$fixture_gid"
cp "$TMPDIR/build-info.good" "$TMPDIR/build-info.mutable"
chmod 0664 "$TMPDIR/build-info.mutable"
assert_cmd_failure "build-floor parser rejects mutable metadata" \
    bash -c '. "$1"; load_build_floor "$2" "$3" "$4" 644 >/dev/null' \
        _ "$TMPDIR/noid-time-recovery" "$TMPDIR/build-info.mutable" \
        "$fixture_uid" "$fixture_gid"
cp "$TMPDIR/build-info.good" "$TMPDIR/build-info.duplicate"
printf '%s\n' 'NOID_BUILD_TIMESTAMP="2026-07-13T12:00:00Z"' \
    >> "$TMPDIR/build-info.duplicate"
assert_cmd_failure "build-floor parser rejects duplicate timestamp fields" \
    bash -c '. "$1"; load_build_floor "$2" "$3" "$4" 644 >/dev/null' \
        _ "$TMPDIR/noid-time-recovery" "$TMPDIR/build-info.duplicate" \
        "$fixture_uid" "$fixture_gid"
assert_cmd_failure "calendar parser rejects an impossible date" \
    bash -c '. "$1"; canonical_timestamp 2026-02-30T12:00:00Z >/dev/null' \
        _ "$TMPDIR/noid-time-recovery"

# Source the production helper and replace only its side-effect functions.
# This exercises main control flow without changing the audit host clock.
run_time_recovery_fixture() {
    local scenario=$1 trace=$2
    (
        # shellcheck source=/dev/null
        . "$TMPDIR/noid-time-recovery"
        # The sourced main invokes these production-function overrides
        # indirectly; ShellCheck cannot follow that dynamic dispatch.
        # shellcheck disable=SC2317,SC2329
        {
            require_root() { printf '%s\n' root >> "$trace"; }
            require_local_vt() { printf '%s\n' local-vt >> "$trace"; }
            load_build_floor() { printf '%s\n' '2026-07-12T12:00:00Z'; }
            current_utc() { printf '%s\n' '1970-01-01T00:00:00Z'; }
            confirm_candidate() {
                printf 'confirm:%s\n' "$1" >> "$trace"
                [[ "$scenario" != confirm-fail ]]
            }
            audit_event() { printf 'audit:%s\n' "$1" >> "$trace"; }
            stop_chronyd() {
                printf '%s\n' stop >> "$trace"
                [[ "$scenario" != stop-fail ]]
            }
            set_system_clock() {
                printf 'set:%s\n' "$1" >> "$trace"
                [[ "$scenario" != set-fail ]]
            }
            rtc_exists() { return 0; }
            sync_rtc() {
                printf '%s\n' rtc >> "$trace"
                [[ "$scenario" != rtc-fail ]]
            }
            start_chronyd() { printf '%s\n' start >> "$trace"; }
            chronyd_active() { printf '%s\n' active >> "$trace"; }
        }
        main set 2026-07-13T18:42:00Z
    ) >"$TMPDIR/${scenario}.stdout" 2>"$TMPDIR/${scenario}.stderr"
}

success_trace="$TMPDIR/recovery-success.trace"
: > "$success_trace"
if run_time_recovery_fixture success "$success_trace"; then
    _pass "recovery success path completes"
else
    _fail "recovery success path failed"
fi
candidate_epoch=$(date --utc --date='2026-07-13T18:42:00Z' +%s)
cat > "$TMPDIR/recovery-success.expected" <<SUCCESS_TRACE_EOF
root
local-vt
confirm:SET VERIFIED UTC 2026-07-13T18:42:00Z
audit:operator confirmed local-VT manual clock recovery
stop
set:${candidate_epoch}
rtc
start
active
audit:manual clock seed applied; NTS-only chronyd restarted
SUCCESS_TRACE_EOF
assert_cmd_success "recovery orders confirmation, stop, set, RTC, start and active check" \
    cmp -s "$TMPDIR/recovery-success.expected" "$success_trace"

for failure_case in confirm-fail stop-fail set-fail rtc-fail; do
    failure_trace="$TMPDIR/recovery-${failure_case}.trace"
    : > "$failure_trace"
    if run_time_recovery_fixture "$failure_case" "$failure_trace"; then
        _fail "recovery unexpectedly accepted $failure_case"
    else
        _pass "recovery rejects/reports $failure_case"
    fi
done
assert_not_grep '^stop$' "$TMPDIR/recovery-confirm-fail.trace" \
    "confirmation failure changes no service/clock state"
assert_grep_extended '^start$' "$TMPDIR/recovery-stop-fail.trace" \
    "stop failure still attempts service restoration"
assert_grep_extended '^start$' "$TMPDIR/recovery-set-fail.trace" \
    "clock-set failure restores chronyd"
assert_grep_extended '^start$' "$TMPDIR/recovery-rtc-fail.trace" \
    "RTC failure restores/verifies chronyd before returning nonzero"
assert_grep_extended '^active$' "$TMPDIR/recovery-rtc-fail.trace" \
    "RTC failure verifies restored chronyd state"

future_trace="$TMPDIR/recovery-future.trace"
: > "$future_trace"
if (
    # shellcheck source=/dev/null
    . "$TMPDIR/noid-time-recovery"
    # shellcheck disable=SC2317,SC2329
    {
        require_root() { printf '%s\n' root >> "$future_trace"; }
        require_local_vt() { printf '%s\n' local-vt >> "$future_trace"; }
        load_build_floor() { printf '%s\n' '2026-07-12T12:00:00Z'; }
        stop_chronyd() { printf '%s\n' stop >> "$future_trace"; }
    }
    main set 2096-07-13T18:42:00Z
) >"$TMPDIR/future.stdout" 2>"$TMPDIR/future.stderr"; then
    _fail "recovery accepted an implausible future-year value"
else
    _pass "recovery rejects an implausible future-year value"
fi
assert_not_grep '^stop$' "$future_trace" \
    "future-horizon rejection changes no service/clock state"

test_finish

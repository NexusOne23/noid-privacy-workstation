#!/bin/bash
# Candidate-only M11 restricted-chronyd lifecycle gate.
# Run each lifecycle identity first offline, then on controlled WAN. Run the
# state-changing cookie actions only in the disposable candidate VM.
set -euo pipefail

TEST_NAME=11-chrony-runtime
PASS_ID=${1:-}
ACTION=${2:-}

case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *)
        echo "usage: sudo $0 {live|fresh-install|reboot} {offline|online|rtc-bootstrap|cookie-restart|fresh-ke|post-resume}" >&2
        exit 2
        ;;
esac
case "$ACTION" in
    offline|online|cookie-restart|post-resume) ;;
    fresh-ke|rtc-bootstrap)
        [[ $PASS_ID == fresh-install ]] || {
            echo "$ACTION is restricted to the fresh-install pass" >&2
            exit 2
        }
        ;;
    *)
        echo "usage: sudo $0 {live|fresh-install|reboot} {offline|online|rtc-bootstrap|cookie-restart|fresh-ke|post-resume}" >&2
        exit 2
        ;;
esac

fail() {
    echo "FAIL  $TEST_NAME [$PASS_ID/$ACTION]: $*" >&2
    exit 1
}

if [[ $EUID -ne 0 ]]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n "$0" "$PASS_ID" "$ACTION"
    fi
    fail "run as root or establish sudo credentials first"
fi

grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for tool in awk cat chronyc chronyd cmp find getenforce getent grep id ip \
            journalctl matchpathcon mkdir mktemp mv openssl paste readlink rm \
            rpm runuser sed sha256sum sleep sort ss stat systemctl timedatectl \
            timeout tr; do
    command -v "$tool" >/dev/null 2>&1 || fail "required command missing: $tool"
done
[[ $(getenforce) == Enforcing ]] || fail "SELinux is not enforcing"

TMPDIR=$(mktemp -d /var/tmp/noid-chrony-runtime.XXXXXX)
cookie_backup=""
restore_cookie_backup=0
restart_service_on_cleanup=0

cleanup() {
    local rc=${1:-$?}
    trap - EXIT HUP INT TERM
    if [[ $restore_cookie_backup -eq 1 && -n $cookie_backup \
          && -d $cookie_backup && ! -L $cookie_backup ]]; then
        systemctl stop chronyd-restricted.service >/dev/null 2>&1 || rc=1
        while IFS= read -r -d '' cookie; do
            rm -f -- "$cookie" || rc=1
        done < <(find /var/lib/chrony -maxdepth 1 -type f -name '*.nts' -print0)
        while IFS= read -r -d '' cookie; do
            mv -- "$cookie" /var/lib/chrony/ || rc=1
        done < <(find "$cookie_backup" -maxdepth 1 -type f -name '*.nts' -print0)
        systemctl start chronyd-restricted.service >/dev/null 2>&1 || rc=1
    elif [[ $restart_service_on_cleanup -eq 1 ]]; then
        systemctl start chronyd-restricted.service >/dev/null 2>&1 || rc=1
    fi
    rm -rf -- "$TMPDIR"
    exit "$rc"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

rpm_payload_file_pristine() {
    local package=$1 path=$2 expected actual
    [[ $(rpm -q --qf '%{FILEDIGESTALGO}' "$package" 2>/dev/null || true) == 8 ]] \
        || return 1
    expected=$(rpm -q --qf '[%{FILENAMES}\t%{FILEDIGESTS}\n]' "$package" \
        2>/dev/null | awk -F '\t' -v target="$path" '
            $1 == target { count++; digest=$2 }
            END { if (count != 1 || digest == "") exit 1; print digest }
        ') || return 1
    actual=$(sha256sum -- "$path" 2>/dev/null) || return 1
    actual=${actual%% *}
    [[ $actual == "$expected" ]]
}

expect_metadata() {
    local path=$1 expected=$2
    [[ -f $path && ! -L $path ]] || fail "missing, non-regular or symlinked: $path"
    [[ $(stat -c '%U:%G:%a:%h' -- "$path") == "$expected" ]] || \
        fail "metadata mismatch for $path"
}

expect_property() {
    local property=$1 expected=$2 actual
    actual=$(systemctl show chronyd-restricted.service \
        --property="$property" --value) || fail "cannot read unit property $property"
    [[ $actual == "$expected" ]] || \
        fail "unit property $property is '$actual', expected '$expected'"
}

restricted_unit=/usr/lib/systemd/system/chronyd-restricted.service
sysconfig=/etc/sysconfig/chronyd
provider_dir=/etc/systemd/ntp-units.d
provider_file=$provider_dir/50-chronyd.list
config=/etc/chrony.conf
helper=/usr/local/sbin/noid-time-recovery
source_manifest=/usr/share/doc/noid-privacy/11-nts-sources.tsv
time_doc=/usr/share/doc/noid-privacy/11-time-recovery.md
preset=/etc/systemd/system-preset/05-noid-chrony.preset
timesyncd_unit=/usr/lib/systemd/system/systemd-timesyncd.service
readiness_helper=/usr/local/libexec/noid-network-readiness
offline_readiness_unit=/etc/systemd/system/noid-chrony-network-offline.service
readiness_unit=/etc/systemd/system/noid-chrony-network-online.service
readiness_marker=/run/noid-privacy/gateway-xdp.ready
live_mutator=/usr/libexec/livesys/livesys-main
chrony_vendor_dispatcher_dir=/usr/lib/NetworkManager/dispatcher.d
chrony_admin_dispatcher_dir=/etc/NetworkManager/dispatcher.d

expect_metadata "$restricted_unit" root:root:644:1
expect_metadata "$sysconfig" root:root:644:1
expect_metadata "$provider_file" root:root:644:1
expect_metadata "$preset" root:root:644:1
expect_metadata "$config" root:root:644:1
expect_metadata "$helper" root:root:755:1
expect_metadata "$source_manifest" root:root:644:1
expect_metadata "$time_doc" root:root:644:1
expect_metadata "$readiness_helper" root:root:755:1
expect_metadata "$offline_readiness_unit" root:root:644:1
expect_metadata "$readiness_unit" root:root:644:1
for chrony_dispatcher_name in 20-chrony-dhcp 20-chrony-onoffline; do
    expect_metadata \
        "$chrony_vendor_dispatcher_dir/$chrony_dispatcher_name" root:root:755:1
    expect_metadata \
        "$chrony_admin_dispatcher_dir/$chrony_dispatcher_name" root:root:755:1
done
[[ ! -L $provider_dir && $(LC_ALL=C stat -c '%F:%U:%G:%a' "$provider_dir") == \
   directory:root:root:755 ]] || fail "timedated provider directory metadata invalid"
for labeled_path in "$provider_file" "$preset" "$config" "$helper" \
                    "$source_manifest" "$time_doc" "$readiness_helper" \
                    "$offline_readiness_unit" "$readiness_unit" \
                    "$chrony_admin_dispatcher_dir/20-chrony-dhcp" \
                    "$chrony_admin_dispatcher_dir/20-chrony-onoffline"; do
    matchpathcon -V "$labeled_path" >/dev/null 2>&1 || \
        fail "SELinux label mismatch for $labeled_path"
done
[[ $(rpm -qf --qf '%{NAME}' "$restricted_unit") == chrony ]] || \
    fail "restricted unit is not owned by chrony RPM"
[[ $(rpm -qf --qf '%{NAME}' "$sysconfig") == chrony ]] || \
    fail "chronyd sysconfig is not owned by chrony RPM"
[[ $(rpm -qf --qf '%{NAME}' "$timesyncd_unit") == systemd-udev ]] || \
    fail "timesyncd vendor unit is not owned by Fedora systemd-udev"
rpm_payload_file_pristine chrony "$restricted_unit" || \
    fail "restricted unit differs from its RPM SHA-256 payload"
rpm_payload_file_pristine chrony "$sysconfig" || \
    fail "chronyd sysconfig differs from its RPM SHA-256 payload"
for chrony_dispatcher_name in 20-chrony-dhcp 20-chrony-onoffline; do
    chrony_vendor_dispatcher=$chrony_vendor_dispatcher_dir/$chrony_dispatcher_name
    chrony_admin_dispatcher=$chrony_admin_dispatcher_dir/$chrony_dispatcher_name
    [[ $(rpm -qf --qf '%{NAME}' "$chrony_vendor_dispatcher") == chrony ]] || \
        fail "$chrony_dispatcher_name vendor script is not owned by chrony RPM"
    rpm_payload_file_pristine chrony "$chrony_vendor_dispatcher" || \
        fail "$chrony_dispatcher_name vendor script differs from its RPM payload"
    [[ $(awk '!/^[[:space:]]*(#|$)/ {print}' \
        "$chrony_admin_dispatcher") == 'exit 0' ]] || \
        fail "$chrony_dispatcher_name administrator shadow is not a functional no-op"
done
[[ $(grep -cE '^[[:space:]]*OPTIONS=' "$sysconfig" || true) -eq 1 ]] \
    && grep -qxF 'OPTIONS="-F 2"' "$sysconfig" || \
    fail "package-owned chronyd options are not exactly -F 2"
[[ $(grep -cEv '^[[:space:]]*(#|$)' "$provider_file" || true) -eq 1 \
   && $(grep -cFx 'chronyd-restricted.service' "$provider_file" || true) -eq 1 ]] || \
    fail "timedated provider does not select exactly the restricted service"
[[ $(cat "$preset") == $'disable chronyd.service\nenable chronyd-restricted.service' ]] || \
    fail "chronyd preset does not preserve exclusive restricted enablement"

for obsolete in \
    /etc/systemd/system/chronyd.service.d/99-noid-hardening.conf \
    /etc/systemd/system/chronyd-restricted.service.d/99-noid-hardening.conf; do
    [[ ! -e $obsolete && ! -L $obsolete ]] || \
        fail "competing custom chronyd sandbox remains: $obsolete"
done
grep -qF '/usr/bin/systemctl stop chronyd-restricted.service' "$helper" || \
    fail "time-recovery helper does not stop the restricted client"
grep -qF '/usr/bin/systemctl start chronyd-restricted.service' "$helper" || \
    fail "time-recovery helper does not restore the restricted client"
! grep -qE 'systemctl (start|stop) chronyd\.service' "$helper" || \
    fail "time-recovery helper can activate the ordinary client"

[[ $(systemctl is-enabled chronyd-restricted.service) == enabled ]] || \
    fail "restricted service is not enabled"
[[ $(systemctl is-enabled noid-chrony-network-online.service) == enabled ]] || \
    fail "chrony readiness consumer is not enabled"
[[ $(systemctl is-enabled noid-chrony-network-offline.service) == static ]] || \
    fail "chrony offline transition is not a static one-shot"
ordinary_state=$(systemctl is-enabled chronyd.service 2>/dev/null || true)
[[ $ordinary_state == disabled ]] || \
    fail "ordinary chronyd service is '$ordinary_state', expected disabled"
[[ $(systemctl is-enabled systemd-timesyncd.service 2>/dev/null || true) == masked ]] || \
    fail "systemd-timesyncd is not masked"
[[ $(readlink /etc/systemd/system/systemd-timesyncd.service 2>/dev/null || true) == \
   /dev/null ]] || fail "systemd-timesyncd mask does not resolve to /dev/null"
systemctl is-active --quiet chronyd-restricted.service || \
    fail "restricted service is not active"
! systemctl is-active --quiet chronyd.service || \
    fail "ordinary chronyd service is active"
[[ $(timedatectl show -p NTP --value) == yes ]] || \
    fail "systemd-timedated does not report the selected NTP provider active"
systemctl show chronyd-restricted.service -p Wants --value \
    | tr ' ' '\n' | grep -qx noid-chrony-network-online.service || \
    fail "native restricted daemon does not want the readiness consumer"
[[ ! -e /etc/systemd/system/noid-chrony-network-online.path \
   && ! -L /etc/systemd/system/noid-chrony-network-online.path ]] || \
    fail "retired readiness path unit remains installed"

expect_property FragmentPath "$restricted_unit"
expect_property User chrony
expect_property CapabilityBoundingSet cap_sys_time
expect_property AmbientCapabilities cap_sys_time
expect_property DevicePolicy closed
expect_property MemoryDenyWriteExecute yes
expect_property NoNewPrivileges yes
expect_property PrivateDevices yes
expect_property ProtectHome yes
expect_property ProtectProc invisible
expect_property ProtectSystem strict
expect_property RestrictAddressFamilies 'AF_INET AF_INET6 AF_UNIX'
expect_property RestrictNamespaces yes
expect_property RestrictSUIDSGID yes
expect_property SystemCallArchitectures native
expect_property UMask 0077

[[ $(systemctl show noid-chrony-network-online.service -p User --value) == \
   chrony ]] || fail "readiness consumer does not run as chrony"
[[ $(systemctl show noid-chrony-network-online.service -p Group --value) == \
   chrony ]] || fail "readiness consumer does not use the chrony socket group"
[[ $(systemctl show noid-chrony-network-online.service \
        -p NoNewPrivileges --value) == no ]] || \
    fail "readiness consumer blocks Fedora's required chronyc_t transition"
[[ $(systemctl show noid-chrony-network-online.service \
        -p CapabilityBoundingSet --value) == '' ]] || \
    fail "readiness consumer has a non-empty capability bounding set"
[[ $(systemctl show noid-chrony-network-online.service \
        -p RestrictSUIDSGID --value) == yes ]] || \
    fail "readiness consumer does not block SUID/SGID privilege acquisition"
grep -qxF \
    'ExecStartPre=!/usr/local/libexec/noid-network-readiness consumer-precheck' \
    "$readiness_unit" || fail "readiness root-only precheck is missing"
grep -qxF 'Restart=on-failure' "$readiness_unit" || \
    fail "readiness resolver failure is not automatically recoverable"
grep -qxF 'RestartSec=30s' "$readiness_unit" || \
    fail "readiness resolver retry delay differs"
grep -qxF 'RestartSteps=4' "$readiness_unit" || \
    fail "readiness resolver retry backoff step count differs"
grep -qxF 'RestartMaxDelaySec=15min' "$readiness_unit" || \
    fail "readiness resolver maximum retry delay differs"
[[ $(systemctl show noid-chrony-network-online.service \
        -p Restart --value) == on-failure ]] || \
    fail "PID 1 did not load the resolver recovery policy"
[[ $(systemctl show noid-chrony-network-online.service \
        -p RestartUSec --value) == 30s ]] || \
    fail "PID 1 did not load the resolver initial retry delay"
[[ $(systemctl show noid-chrony-network-online.service \
        -p RestartSteps --value) == 4 ]] || \
    fail "PID 1 did not load the resolver retry backoff steps"
[[ $(systemctl show noid-chrony-network-online.service \
        -p RestartMaxDelayUSec --value) == 15min ]] || \
    fail "PID 1 did not load the resolver maximum retry delay"
[[ $(systemctl show noid-chrony-network-offline.service -p User --value) == \
   chrony ]] || fail "offline transition does not run as chrony"
[[ $(systemctl show noid-chrony-network-offline.service -p Group --value) == \
   chrony ]] || fail "offline transition does not use the chrony socket group"
[[ $(systemctl show noid-chrony-network-offline.service \
        -p NoNewPrivileges --value) == no ]] || \
    fail "offline transition blocks Fedora's required chronyc_t transition"
[[ $(systemctl show noid-chrony-network-offline.service \
        -p CapabilityBoundingSet --value) == '' ]] || \
    fail "offline transition has a non-empty capability bounding set"
[[ $(systemctl show noid-chrony-network-offline.service \
        -p RestrictSUIDSGID --value) == yes ]] || \
    fail "offline transition does not block SUID/SGID privilege acquisition"
grep -qxF \
    'ExecStart=/usr/local/libexec/noid-network-readiness offline-consumer' \
    "$offline_readiness_unit" || fail "closed offline helper action is missing"
[[ $(systemctl show chronyd-restricted.service -p NRestarts --value) == 0 ]] || \
    fail "restricted service has automatically restarted"
[[ $(systemctl show chronyd-restricted.service -p Result --value) == success ]] || \
    fail "restricted service result is not success"

main_pid=$(systemctl show chronyd-restricted.service -p MainPID --value)
[[ $main_pid =~ ^[1-9][0-9]*$ && -d /proc/$main_pid ]] || \
    fail "restricted service MainPID is invalid"
chrony_uid=$(id -u chrony)
chrony_gid=$(id -g chrony)
[[ $(awk '$1 == "Uid:" {print $2 ":" $3 ":" $4 ":" $5}' \
        "/proc/$main_pid/status") == \
   "$chrony_uid:$chrony_uid:$chrony_uid:$chrony_uid" ]] || \
    fail "chronyd process UID set is not the chrony account"
[[ $(awk '$1 == "Gid:" {print $2 ":" $3 ":" $4 ":" $5}' \
        "/proc/$main_pid/status") == \
   "$chrony_gid:$chrony_gid:$chrony_gid:$chrony_gid" ]] || \
    fail "chronyd process GID set is not the chrony group"
for capability_field in CapInh CapPrm CapEff CapBnd CapAmb; do
    capability_value=$(awk -v key="$capability_field:" '$1 == key {print $2}' \
        "/proc/$main_pid/status")
    [[ $capability_value == 0000000002000000 ]] || \
        fail "$capability_field is $capability_value, expected only CAP_SYS_TIME"
done
[[ $(awk '$1 == "NoNewPrivs:" {print $2}' "/proc/$main_pid/status") == 1 ]] || \
    fail "chronyd process lacks no-new-privileges"
[[ $(awk '$1 == "Seccomp:" {print $2}' "/proc/$main_pid/status") == 2 ]] || \
    fail "chronyd process is not in seccomp filter mode"
seccomp_filters=$(awk '$1 == "Seccomp_filters:" {print $2}' "/proc/$main_pid/status")
[[ $seccomp_filters =~ ^[1-9][0-9]*$ ]] || fail "chronyd has no seccomp filters"
process_context=$(tr -d '\0\n' < "/proc/$main_pid/attr/current")
[[ $process_context == system_u:system_r:chronyd_restricted_t:s0 ]] || \
    fail "chronyd SELinux context is $process_context"
mapfile -d '' -t process_argv < "/proc/$main_pid/cmdline"
expected_argv=(/usr/sbin/chronyd -n -U -F 2)
[[ ${#process_argv[@]} -eq ${#expected_argv[@]} ]] || \
    fail "chronyd argv length differs from restricted -F 2 contract"
for index in "${!expected_argv[@]}"; do
    [[ ${process_argv[$index]} == "${expected_argv[$index]}" ]] || \
        fail "chronyd argv[$index] is '${process_argv[$index]}'"
done

[[ ! -L /run/chrony && $(LC_ALL=C stat -c '%F:%U:%G:%a' /run/chrony) == \
   directory:chrony:chrony:750 ]] || fail "chronyd runtime directory invalid"
for state_dir in /var/lib/chrony /var/log/chrony; do
    [[ ! -L $state_dir && $(LC_ALL=C stat -c '%F:%U:%G:%a' "$state_dir") == \
       directory:chrony:chrony:750 ]] || \
        fail "chronyd state directory invalid: $state_dir"
done
[[ -S /run/chrony/chronyd.sock && ! -L /run/chrony/chronyd.sock ]] || \
    fail "chronyd Unix command socket missing or redirected"
[[ $(stat -c '%U:%G:%a' /run/chrony/chronyd.sock) == chrony:chrony:700 ]] || \
    fail "chronyd Unix command socket metadata drifted"
for runtime_path in /run/chrony /run/chrony/chronyd.sock \
                    /var/lib/chrony /var/log/chrony; do
    matchpathcon -V "$runtime_path" >/dev/null 2>&1 || \
        fail "chronyd runtime SELinux label mismatch: $runtime_path"
done
[[ -z $(ss -H -lun 'sport = :323') ]] || fail "UDP command port 323 is listening"

normal_user=$(getent passwd | awk -F: \
    '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ {print $1; exit}')
[[ -n $normal_user ]] || fail "no normal candidate user found"
if id -nG "$normal_user" | tr ' ' '\n' | grep -qx chrony; then
    fail "normal candidate user is unexpectedly in the chrony group"
fi
if runuser -u "$normal_user" -- chronyc tracking \
        >"$TMPDIR/unprivileged.out" 2>"$TMPDIR/unprivileged.err"; then
    fail "normal user can access the restricted chronyd command socket"
fi
grep -qF '506 Cannot talk to daemon' \
    "$TMPDIR/unprivileged.out" "$TMPDIR/unprivileged.err" || \
    fail "unprivileged chronyc refusal is not the expected closed-socket result"

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
' "$source_manifest" || fail "installed NTS operator manifest is invalid"
cmp -s \
    <(awk -F '\t' \
        'NR > 1 {print "server " $1 " iburst nts ipv4 maxpoll 11 offline"}' \
        "$source_manifest") \
    <(grep '^server ' "$config") || \
    fail "chrony.conf differs from the dated NTS operator manifest"
[[ $(grep -cE '^server .* iburst nts ipv4 maxpoll 11 offline$' \
    "$config" || true) -eq 6 ]] || \
    fail "chrony.conf does not contain exactly 6 offline IPv4 NTS sources"
[[ $(grep -cE '^server ' "$config" || true) -eq 6 ]] || \
    fail "chrony.conf contains a source outside the closed 6-server set"
! grep -qE '^server ntppool[34]\.time\.nl ' "$config" || \
    fail "SIDN pre-production source entered the base configuration"
case "$PASS_ID" in
    live)
        grep -qw rd.live.image /proc/cmdline || \
            fail "live pass is not running from Fedora Live media"
        [[ -f $live_mutator && ! -L $live_mutator ]] || \
            fail "Fedora Live RTC mutator is missing or redirected"
        [[ $(rpm -qf --qf '%{NAME}' "$live_mutator") == livesys-scripts ]] || \
            fail "Fedora Live RTC mutator has an unexpected RPM owner"
        grep -qxF "sed -i 's/rtcsync//' /etc/chrony.conf" "$live_mutator" || \
            fail "Fedora Live RTC write-suppression contract changed"
        ! grep -qxF rtcsync "$config" || \
            fail "live pass retained the installed-system RTC sync directive"
        ;;
    fresh-install|reboot)
        ! grep -qw rd.live.image /proc/cmdline || \
            fail "$PASS_ID pass is still running from Fedora Live media"
        grep -qxF rtcsync "$config" || \
            fail "$PASS_ID pass lost the installed-system RTC sync directive"
        ;;
esac
{
    awk -F '\t' \
        'NR > 1 {print "server " $1 " iburst nts ipv4 maxpoll 11 offline"}' \
        "$source_manifest"
    cat <<'EXPECTED_CHRONY_ACTIVE_PREFIX_EOF'
minsources 3
maxupdateskew 100.0
keyfile /dev/null
driftfile /var/lib/chrony/drift
makestep 1.0 3
maxchange 1000 3 0
EXPECTED_CHRONY_ACTIVE_PREFIX_EOF
    if [[ $PASS_ID != live ]]; then
        printf '%s\n' rtcsync
    fi
    cat <<'EXPECTED_CHRONY_ACTIVE_SUFFIX_EOF'
ntsdumpdir /var/lib/chrony
leapseclist /usr/share/zoneinfo/leap-seconds.list
bindcmdaddress /var/run/chrony/chronyd.sock
cmdport 0
EXPECTED_CHRONY_ACTIVE_SUFFIX_EOF
} > "$TMPDIR/chrony-active.expected"
awk '!/^[[:space:]]*(#|$)/ {print}' "$config" \
    > "$TMPDIR/chrony-active.actual"
cmp -s "$TMPDIR/chrony-active.expected" "$TMPDIR/chrony-active.actual" || \
    fail "active chrony.conf is not the closed manifest-generated policy"
grep -qxF 'minsources 3' "$config" || fail "minsources 3 missing"
grep -qxF 'maxchange 1000 3 0' "$config" || \
    fail "post-bootstrap maxchange panic bound missing"
grep -qxF 'cmdport 0' "$config" || fail "cmdport 0 missing"
grep -qxF 'ntsdumpdir /var/lib/chrony' "$config" || fail "NTS cookie dump missing"
! grep -qE '^(pool|peer|refclock|initstepslew|manual|local|sourcedir|confdir|include|nocerttimecheck)([[:space:]]|$)' \
    "$config" || fail "additional/dynamic/certificate-bypass source directive present"
chronyd -p -f "$config" >/dev/null || fail "installed chrony.conf does not parse"

check_no_seccomp_failure() {
    local seccomp_journal="$TMPDIR/chronyd-seccomp-journal.log"
    {
        journalctl -b -u chronyd-restricted.service --no-pager 2>/dev/null
        journalctl -b -k --no-pager 2>/dev/null
    } > "$seccomp_journal" || fail "cannot capture current chronyd/kernel journal"
    if chronyd_seccomp_failure < "$seccomp_journal"; then
        fail "current boot contains a chronyd seccomp/syscall failure"
    fi
}

chronyd_seccomp_failure() {
    awk '
        {
            line = tolower($0)
            chronyd = (line ~ /chronyd/)
            seccomp_failure = line ~ /bad system call/ ||
                line ~ /sigsys/ ||
                line ~ /status=31\/sys/ ||
                line ~ /seccomp.*(denied|killed|blocked)/
            if (chronyd && seccomp_failure) {
                found = 1
            }
        }
        END { exit !found }
    '
}

online_ready() {
    chronyc -N authdata > "$TMPDIR/authdata" 2>/dev/null || return 1
    chronyc tracking > "$TMPDIR/tracking" 2>/dev/null || return 1
    chronyc -n sources > "$TMPDIR/sources" 2>/dev/null || return 1
    awk '
        $2 == "NTS" {
            count++
            if ($4 !~ /^[1-9][0-9]*$/ || $5 !~ /^[1-9][0-9]*$/ ||
                $9 !~ /^[1-9][0-9]*$/ || $10 !~ /^[1-9][0-9]*$/) bad=1
        }
        END { exit !(count == 6 && bad == 0) }
    ' "$TMPDIR/authdata" || return 1
    while IFS=$'\t' read -r server _; do
        [[ $server == hostname ]] && continue
        awk -v name="$server" '$1 == name && $2 == "NTS" {found=1} END {exit !found}' \
            "$TMPDIR/authdata" || return 1
    done < "$source_manifest"
    grep -qE '^Leap status[[:space:]]*:[[:space:]]*Normal$' \
        "$TMPDIR/tracking" || return 1
    awk '
        $1 ~ /^\^/ {
            count++
            if ($1 == "^?" || $5 == "0") bad=1
            if ($1 == "^*" || $1 == "^+" || $1 == "^-") selectable++
            if (seen[$2]++) duplicate=1
        }
        END { exit !(count == 6 && selectable >= 3 && bad == 0 && duplicate == 0) }
    ' "$TMPDIR/sources"
}

wait_online() {
    local attempt
    attempt=0
    while (( attempt < 60 )); do
        if online_ready; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 5
    done
    return 1
}

wait_post_resume_readiness() {
    local attempt activity
    attempt=0
    while (( attempt < 60 )); do
        if "$readiness_helper" status >/dev/null 2>&1; then
            readiness_wait_seconds=$attempt
            return 0
        fi
        activity=$(chronyc activity 2>/dev/null) || return 1
        if [[ $activity != *$'0 sources online'* ]]; then
            # Readiness and the asynchronous chrony online consumer can become
            # visible between the two probes. Accept only that closed race;
            # online sources without the verified boundary remain a failure.
            "$readiness_helper" status >/dev/null 2>&1 || return 1
            readiness_wait_seconds=$attempt
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    return 1
}

validate_cookie_tree() {
    local count=0 cookie
    while IFS= read -r -d '' cookie; do
        [[ -f $cookie && ! -L $cookie ]] || fail "NTS cookie is not a regular file"
        [[ $(stat -c '%U:%G:%a' "$cookie") == chrony:chrony:600 ]] || \
            fail "NTS cookie metadata invalid: $cookie"
        [[ -s $cookie ]] || fail "empty NTS cookie file: $cookie"
        count=$((count + 1))
    done < <(find /var/lib/chrony -maxdepth 1 -type f -name '*.nts' -print0)
    [[ $count -eq 6 ]] || fail "expected 6 dumped NTS source files, found $count"
}

validate_ntske_tls_log() {
    local tls_log=$1
    grep -qxF 'Protocol: TLSv1.3' "$tls_log" \
        && grep -qxF 'ALPN protocol: ntske/1' "$tls_log"
}

validate_public_dependencies() {
    local server operator country operator_status operator_source reviewed_on
    local ipv4 tls_log
    while IFS=$'\t' read -r server operator country operator_status \
            operator_source reviewed_on; do
        [[ $server == hostname ]] && continue
        ipv4=$(getent ahostsv4 "$server" | \
            awk '$2 == "STREAM" {print $1}' | sort -u | paste -sd, -) || \
            fail "IPv4 lookup command failed for NTS dependency $server"
        [[ -n $ipv4 ]] || fail "no IPv4 address for NTS dependency $server"
        tls_log="$TMPDIR/tls-$server"
        timeout 15 openssl s_client \
            -connect "$server:4460" -servername "$server" \
            -verify_hostname "$server" -verify_return_error -alpn ntske/1 \
            </dev/null >"$tls_log" 2>&1 || \
            fail "NTS-KE TLS chain/hostname verification failed for $server"
        validate_ntske_tls_log "$tls_log" || \
            fail "NTS-KE did not negotiate exact TLS 1.3 + ALPN ntske/1 for $server"
        printf 'NTS_DEPENDENCY\tpass=%s\thost=%s\toperator=%s\tcountry=%s\tstatus=%s\tipv4=%s\treviewed_on=%s\tsource=%s\n' \
            "$PASS_ID" "$server" "$operator" "$country" "$operator_status" \
            "$ipv4" "$reviewed_on" "$operator_source"
    done < "$source_manifest"
}

auth_key_manifest() {
    local destination=$1
    # Cook is transiently below chrony's usual full count while a request is
    # in flight. Key identity is stable as long as every source remains
    # authenticated and retains at least one usable cookie.
    chronyc -N authdata 2>/dev/null | awk '
        $2 == "NTS" {
            count++
            if ($3 !~ /^[0-9]+$/ || $4 !~ /^[1-9][0-9]*$/ ||
                $5 !~ /^[1-9][0-9]*$/ || $7 != 0 || $8 != 0 ||
                $9 !~ /^[1-9][0-9]*$/ || $10 !~ /^[1-9][0-9]*$/) bad=1
            print $1, $2, $3, $4, $5
        }
        END { exit !(count == 6 && bad == 0) }
    ' | sort > "$destination" || \
        fail "cannot capture the exact 6-source NTS key state"
}

cookie_manifest() {
    local destination=$1 cookie
    : > "$destination"
    while IFS= read -r -d '' cookie; do
        printf '%s|' "${cookie##*/}" >> "$destination"
        sha256sum -- "$cookie" | awk '{print $1}' >> "$destination"
    done < <(find /var/lib/chrony -maxdepth 1 -type f -name '*.nts' \
        -print0 | sort -z)
}

readiness_wait_seconds=0
rtc_bootstrap_offset_seconds=0
if [[ $ACTION == post-resume ]]; then
    # Drain journalctl completely before matching. With pipefail, grep -q
    # exits after the first match and journalctl then reports SIGPIPE,
    # turning genuine suspend evidence into a false failure.
    kernel_journal="$TMPDIR/kernel-journal.log"
    journalctl -b -k --no-pager >"$kernel_journal" || \
        fail "cannot capture the current kernel journal"
    grep -qF 'PM: suspend entry' "$kernel_journal" || \
        fail "current boot has no kernel suspend-entry evidence"
    grep -qF 'PM: suspend exit' "$kernel_journal" || \
        fail "current boot has no kernel suspend-exit evidence"
    wait_post_resume_readiness || \
        fail "gateway/XDP readiness did not recover fail-closed within 60 seconds"
elif [[ $ACTION != offline ]]; then
    "$readiness_helper" status >/dev/null || \
        fail "$ACTION phase lacks verified gateway/XDP readiness"
fi

case "$ACTION" in
    offline)
        [[ -z $(ip -4 route show default) && -z $(ip -6 route show default) ]] || \
            fail "offline phase has a default route"
        [[ ! -e $readiness_marker && ! -L $readiness_marker ]] || \
            fail "offline phase retained gateway/XDP readiness"
        [[ $(chronyc activity) == *$'0 sources online'* ]] || \
            fail "offline phase retained an online chrony source"
        ;;
    online)
        wait_online || fail "6-source authenticated online state not reached in 300 seconds"
        validate_public_dependencies
        ;;
    rtc-bootstrap)
        wait_online || fail "authenticated RTC-bootstrap state not reached"
        [[ $(timedatectl show -p LocalRTC --value) == no ]] || \
            fail "RTC is not configured as UTC"
        [[ $(timedatectl show -p NTPSynchronized --value) == yes ]] || \
            fail "systemd-timedated does not report synchronization"
        chrony_boot_journal="$TMPDIR/chronyd-rtc-bootstrap.log"
        journalctl -b -u chronyd-restricted.service -o cat --no-pager \
            > "$chrony_boot_journal" || \
            fail "cannot capture current-boot chronyd journal"
        rtc_bootstrap_offset_seconds=$(awk '
            /System clock (wrong|was stepped) by/ {
                for (i = 1; i < NF; i++) {
                    if ($i == "by" && $(i + 1) ~ /^[-+]?[0-9]+([.][0-9]+)?$/) {
                        offset = $(i + 1) + 0
                        if (offset < 0) offset = -offset
                        if (offset > maximum) maximum = offset
                    }
                }
            }
            END {
                if (maximum > 0) printf "%.0f\n", maximum
                else exit 1
            }
        ' "$chrony_boot_journal") || \
            fail "current boot has no measured initial clock correction"
        if (( rtc_bootstrap_offset_seconds < 6900 || \
              rtc_bootstrap_offset_seconds > 7500 )); then
            fail "measured initial correction is ${rtc_bootstrap_offset_seconds}s, expected injected +7200s RTC class"
        fi
        ;;
    cookie-restart)
        wait_online || fail "pre-restart authenticated state not reached"
        auth_key_manifest "$TMPDIR/keys.before"
        old_pid=$main_pid
        restart_service_on_cleanup=1
        systemctl stop chronyd-restricted.service
        validate_cookie_tree
        systemctl start chronyd-restricted.service
        systemctl is-active --quiet chronyd-restricted.service || \
            fail "restricted service failed after cookie-dump restart"
        restart_service_on_cleanup=0
        new_pid=$(systemctl show chronyd-restricted.service -p MainPID --value)
        [[ $new_pid =~ ^[1-9][0-9]*$ && $new_pid != "$old_pid" ]] || \
            fail "restart did not establish a new restricted MainPID"
        wait_online || fail "authenticated cookie-reload state not reached"
        auth_key_manifest "$TMPDIR/keys.after"
        cmp -s "$TMPDIR/keys.before" "$TMPDIR/keys.after" || \
            fail "NTS KeyID changed across restart; persisted cookies were not reused"
        restart_service_on_cleanup=1
        systemctl stop chronyd-restricted.service
        validate_cookie_tree
        systemctl start chronyd-restricted.service
        restart_service_on_cleanup=0
        wait_online || fail "authenticated state not restored after cookie proof"
        ;;
    fresh-ke)
        wait_online || fail "pre-fresh-KE authenticated state not reached"
        restart_service_on_cleanup=1
        systemctl stop chronyd-restricted.service
        validate_cookie_tree
        cookie_manifest "$TMPDIR/cookies.old"
        cookie_backup="$TMPDIR/original-cookies"
        mkdir -m 0700 "$cookie_backup"
        restore_cookie_backup=1
        while IFS= read -r -d '' cookie; do
            mv -- "$cookie" "$cookie_backup/"
        done < <(find /var/lib/chrony -maxdepth 1 -type f -name '*.nts' -print0)
        systemctl start chronyd-restricted.service
        restart_service_on_cleanup=0
        wait_online || fail "fresh NTS-KE/certificate validation did not reach 6-source auth"
        restart_service_on_cleanup=1
        systemctl stop chronyd-restricted.service
        validate_cookie_tree
        cookie_manifest "$TMPDIR/cookies.new"
        ! cmp -s "$TMPDIR/cookies.old" "$TMPDIR/cookies.new" || \
            fail "fresh NTS-KE reproduced the old cookie bytes"
        systemctl start chronyd-restricted.service
        restart_service_on_cleanup=0
        wait_online || fail "freshly negotiated cookie reload did not authenticate"
        restore_cookie_backup=0
        ;;
    post-resume)
        wait_online || fail "authenticated NTS state did not recover after resume"
        ;;
esac

check_no_seccomp_failure
versions=$(rpm -q chrony glibc gnutls libseccomp libcap nettle systemd | paste -sd, -)
echo "PASS  $TEST_NAME [$PASS_ID/$ACTION]: restricted_uid=$chrony_uid cap=CAP_SYS_TIME seccomp_filters=$seccomp_filters NTS=6 readiness_wait_s=$readiness_wait_seconds rtc_bootstrap_offset_s=$rtc_bootstrap_offset_seconds versions=$versions"

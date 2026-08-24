#!/usr/bin/env bash
# Candidate-only timezone lifecycle gate. The Live pass proves Anaconda's
# neutral default before any deliberate change. GNOME Initial Setup requires a
# timezone selection before the first installed account is usable, so the two
# installed passes prove that exact conscious choice and its reboot persistence:
#   sudo bash tests/pre-ship/01-timezone-runtime.sh live
#   sudo bash tests/pre-ship/01-timezone-runtime.sh fresh-install Europe/Berlin
#   sudo bash tests/pre-ship/01-timezone-runtime.sh reboot Europe/Berlin
set -euo pipefail
export LC_ALL=C

TEST_NAME=01-timezone-runtime
fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }

[[ $# -ge 1 ]] || {
    echo "usage: $0 live | $0 {fresh-install|reboot} IANA_TIMEZONE" >&2
    exit 2
}
PASS_ID=$1
case "$PASS_ID" in
    live)
        [[ $# -eq 1 ]] || exit 2
        EXPECTED_TIMEZONE=UTC
        ;;
    fresh-install|reboot)
        [[ $# -eq 2 ]] || exit 2
        EXPECTED_TIMEZONE=$2
        [[ $EXPECTED_TIMEZONE =~ ^[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$ ]] \
            || fail "expected timezone is not a canonical IANA-style name"
        IFS=/ read -r -a timezone_components <<<"$EXPECTED_TIMEZONE"
        for component in "${timezone_components[@]}"; do
            [[ $component != . && $component != .. ]] \
                || fail "expected timezone contains a traversal component"
        done
        ;;
    *) exit 2 ;;
esac

if [[ $EUID -ne 0 ]]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n "$0" "$PASS_ID"
    fi
    fail "run as root or establish sudo credentials first"
fi

grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for command_name in awk grep readlink timedatectl; do
    command -v "$command_name" >/dev/null 2>&1 || \
        fail "required command missing: $command_name"
done

if [[ $PASS_ID == live ]]; then
    grep -qE '(^|[[:space:]])rd\.live\.image([=[:space:]]|$)' /proc/cmdline || \
        fail "live pass lacks rd.live.image"
else
    ! grep -qE '(^|[[:space:]])rd\.live\.image([=[:space:]]|$)' /proc/cmdline || \
        fail "installed pass retains rd.live.image"
fi

zoneinfo_root=$(readlink -e /usr/share/zoneinfo) || \
    fail "cannot canonicalize the timezone database"
zoneinfo_target=$(readlink -e -- "$zoneinfo_root/$EXPECTED_TIMEZONE") || \
    fail "expected timezone is absent from the installed timezone database"
[[ $zoneinfo_target == "$zoneinfo_root"/* && -f $zoneinfo_target ]] || \
    fail "expected timezone resolves outside the installed timezone database"

[[ -L /etc/localtime ]] || fail "/etc/localtime is not a symlink"
[[ $(readlink /etc/localtime) == "../usr/share/zoneinfo/$EXPECTED_TIMEZONE" ]] || \
    fail "/etc/localtime does not carry the exact expected timezone target"
[[ $(timedatectl show -p Timezone --value) == "$EXPECTED_TIMEZONE" ]] || \
    fail "systemd does not report the exact expected timezone"
[[ -f /etc/adjtime && ! -L /etc/adjtime ]] || \
    fail "/etc/adjtime is missing, non-regular or symlinked"
adjtime_clock=$(awk 'NR == 3 { print; found=1 } END { if (!found) exit 1 }' \
    /etc/adjtime) || fail "cannot read the hardware-clock mode"
[[ $adjtime_clock == UTC ]] || fail "hardware clock is not configured as UTC"

if [[ $PASS_ID == live ]]; then
    echo "PASS  $TEST_NAME [$PASS_ID]: neutral UTC installer default is effective"
else
    echo "PASS  $TEST_NAME [$PASS_ID]: selected timezone is exact and hardware clock remains UTC"
fi

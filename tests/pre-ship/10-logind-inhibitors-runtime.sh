#!/bin/bash
# Candidate-only M10 runtime gate: prove that the installed logind retains
# systemd's maintained inhibitor capacity and accepts more than 16 legitimate
# concurrent inhibitors. Run in live, fresh-install, and reboot passes.

set -euo pipefail

PASS_ID="${1:-}"
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *)
        echo "Usage: sudo bash $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "FAIL [$PASS_ID]: run this gate as root" >&2
    exit 1
fi

fail() {
    echo "FAIL [$PASS_ID]: $*" >&2
    exit 1
}

for cmd in systemctl systemd-inhibit gzip grep awk seq sleep kill; do
    command -v "$cmd" >/dev/null 2>&1 || fail "required command missing: $cmd"
done

if grep -EHqs '^[[:space:]]*InhibitorsMax[[:space:]]*=' \
        /etc/systemd/logind.conf /etc/systemd/logind.conf.d/*.conf 2>/dev/null; then
    fail "an active InhibitorsMax override is installed"
fi

SYSTEMD_VERSION="$(systemctl --version | awk 'NR == 1 { print $2 }')"
[[ "$SYSTEMD_VERSION" =~ ^[0-9]+$ ]] || fail "cannot determine the installed systemd version"

LOGIND_MAN=/usr/share/man/man5/logind.conf.5.gz
[[ -r "$LOGIND_MAN" ]] || fail "installed logind.conf(5) manual is unavailable"
gzip -cd "$LOGIND_MAN" | awk '
    $0 == "\\fIInhibitorsMax=\\fR" { in_stanza=1; heading=1; next }
    in_stanza && /^\.RE$/ { in_stanza=0 }
    in_stanza && /Defaults to 8192 \(8K\)/ { expected_default=1 }
    END { exit !(heading && expected_default) }
' || \
    fail "installed systemd documentation does not declare the expected 8192 default"

pids=()
cleanup() {
    local pid
    for pid in "${pids[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${pids[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

for n in $(seq 1 20); do
    systemd-inhibit \
        --what=sleep \
        --mode=delay \
        --who="noid-inhibitor-fixture-$PASS_ID-$n" \
        --why="NoID Privacy M10 capacity test $PASS_ID/$n" \
        /usr/bin/sleep 60 &
    pids+=("$!")
done

observed=0
for _attempt in $(seq 1 50); do
    observed="$(systemd-inhibit --list --no-legend 2>/dev/null | \
        grep -Fc "noid-inhibitor-fixture-$PASS_ID-" || true)"
    [[ "$observed" -ge 20 ]] && break
    sleep 0.1
done

[[ "$observed" -ge 20 ]] || fail "only $observed of 20 test inhibitors became visible"
for pid in "${pids[@]}"; do
    kill -0 "$pid" 2>/dev/null || fail "an inhibitor process exited before verification"
done

echo "PASS [$PASS_ID]: systemd $SYSTEMD_VERSION retained its documented 8192 default and accepted 20 concurrent sleep inhibitors"

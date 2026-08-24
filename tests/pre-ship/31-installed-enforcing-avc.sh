#!/usr/bin/env bash
# Installed-candidate zero-unexplained-denial gate for the current boot.
# Build-installer permissive AVCs are classified separately and never cross
# this boundary into an enforcing installed-system exception.
set -euo pipefail

TEST_NAME=31-installed-enforcing-avc
if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n "$0"
    fi
    echo "FAIL  $TEST_NAME: run as root or establish sudo credentials first" >&2
    exit 2
fi
for tool in getenforce auditctl ausearch awk grep mktemp rm; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FAIL  $TEST_NAME: missing command: $tool" >&2
        exit 2
    }
done

WORK_DIR=$(mktemp -d /var/tmp/noid-enforcing-avc.XXXXXX)
trap 'rm -rf -- "$WORK_DIR"' EXIT

[ "$(getenforce)" = Enforcing ] || {
    echo "FAIL  $TEST_NAME: SELinux is not enforcing" >&2
    exit 1
}
audit_status=$(auditctl -s)
enabled=$(awk '$1 == "enabled" {print $2}' <<< "$audit_status")
lost=$(awk '$1 == "lost" {print $2}' <<< "$audit_status")
[ "$enabled" = 2 ] || {
    echo "FAIL  $TEST_NAME: audit is not immutable/enabled=2" >&2
    exit 1
}
[[ $lost =~ ^[0-9]+$ ]] && [ "$lost" -eq 0 ] || {
    echo "FAIL  $TEST_NAME: audit reports lost events (${lost:-unknown})" >&2
    exit 1
}

search_rc=0
ausearch --input-logs -m AVC,USER_AVC -ts boot --raw \
    > "$WORK_DIR/avc.log" 2> "$WORK_DIR/ausearch.err" || search_rc=$?
case "$search_rc" in
    0)
        denial_count=$(grep -Eic 'type=(AVC|USER_AVC)|avc:[[:space:]]+denied' \
            "$WORK_DIR/avc.log" || true)
        echo "FAIL  $TEST_NAME: $denial_count enforcing-boot AVC record(s); no allowlist applies" >&2
        exit 1
        ;;
    1)
        [ ! -s "$WORK_DIR/avc.log" ] || {
            echo "FAIL  $TEST_NAME: ausearch returned no-match with nonempty output" >&2
            exit 2
        }
        [ ! -s "$WORK_DIR/ausearch.err" ] || {
            awk '{ print "  ausearch: " $0 }' "$WORK_DIR/ausearch.err" >&2
            echo "FAIL  $TEST_NAME: ausearch emitted diagnostics while reading audit logs" >&2
            exit 2
        }
        ;;
    *)
        awk '{ print "  ausearch: " $0 }' "$WORK_DIR/ausearch.err" >&2
        echo "FAIL  $TEST_NAME: ausearch failed (rc=$search_rc)" >&2
        exit 2
        ;;
esac

echo "PASS  $TEST_NAME: SELinux=enforcing audit=immutable lost=0 AVC=0"

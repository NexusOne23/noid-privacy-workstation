#!/usr/bin/env bash
# Adversarial behavioral fixture for the exact Flatpak remote controller.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT=$(find_project_root)
POLICY="$ROOT/scripts/noid-flatpak-remote-policy.sh"
DESCRIPTOR="$ROOT/manifests/flathub.flatpakrepo"
TMP=$(mktemp -d "${TMPDIR:-/var/tmp}/noid-flatpak-policy.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT HUP INT TERM
FAKEBIN="$TMP/bin"
SYSTEM_ROOT="$TMP/system"
CONFIG="$SYSTEM_ROOT/repo/config"
LOG="$TMP/flatpak.log"
mkdir -p "$FAKEBIN" "$SYSTEM_ROOT/repo"

test_start "18-flatpak-remote-policy-fixture"

cat > "$TMP/canonical-config" <<'CONFIG_EOF'
[core]
repo_version=1

[remote "flathub"]
url=https://dl.flathub.org/repo/
xa.title=Flathub
gpg-verify=true
gpg-verify-summary=true
xa.comment=Central repository of Flatpak applications
xa.description=Central repository of Flatpak applications
xa.icon=https://dl.flathub.org/repo/logo.svg
xa.homepage=https://flathub.org/
xa.prio=1

[remote "flathub-verified"]
url=https://dl.flathub.org/repo/
xa.title=Flathub
gpg-verify=true
gpg-verify-summary=true
xa.comment=Central repository of Flatpak applications
xa.description=Central repository of Flatpak applications
xa.icon=https://dl.flathub.org/repo/logo.svg
xa.homepage=https://flathub.org/
xa.subset=verified
xa.subset-is-set=true
xa.prio=2
CONFIG_EOF
cp "$TMP/canonical-config" "$TMP/remote-add-config"

awk -F= '$1 == "GPGKey" { print substr($0, index($0, "=") + 1) }' \
    "$DESCRIPTOR" | base64 -d > "$TMP/trusted-key.gpg"
assert_eq 8bdc20abc4e19c0796460beb5bfe0e7aa4138716999e19c6f2dbdd78cc41aeaa \
    "$(sha256sum "$TMP/trusted-key.gpg" | awk '{print $1}')" \
    "descriptor decodes to the pinned canonical public-key export"

cat > "$FAKEBIN/flatpak" <<'FLATPAK_STUB_EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$NOID_FIXTURE_LOG"
printf '\n' >> "$NOID_FIXTURE_LOG"
command=$1
shift
case "$command" in
    list)
        [ "${NOID_FIXTURE_LIST_FAILURE:-0}" != 1 ] || exit 74
        case " $* " in
            *' --columns=ref '*) [ "${NOID_FIXTURE_INSTALLED:-0}" != 1 ] || echo app/example.App/x86_64/stable ;;
            *' --columns=origin '*) [ "${NOID_FIXTURE_FEDORA_IN_USE:-0}" != 1 ] || echo fedora ;;
        esac
        ;;
    remotes)
        [ "${NOID_FIXTURE_REMOTES_FAILURE:-0}" != 1 ] || exit 74
        python3 - "$NOID_FIXTURE_CONFIG" <<'PY_EOF'
import configparser
import os
import sys
config = configparser.ConfigParser(interpolation=None)
if os.path.exists(sys.argv[1]):
    config.read(sys.argv[1])
for section in config.sections():
    if section.startswith('remote "') and section.endswith('"'):
        print(section[len('remote "'):-1])
PY_EOF
        ;;
    remote-delete)
        remote=${!#}
        python3 - "$NOID_FIXTURE_CONFIG" "$remote" <<'PY_EOF'
import configparser
import os
import sys
path, remote = sys.argv[1:]
config = configparser.ConfigParser(interpolation=None)
config.read(path)
config.remove_section(f'remote "{remote}"')
with open(path, 'w', encoding='utf-8') as stream:
    config.write(stream, space_around_delimiters=False)
PY_EOF
        rm -f -- "$NOID_FIXTURE_REPO/$remote.trustedkeys.gpg"
        ;;
    remote-add)
        remote=${@: -2:1}
        if [ "$remote" = flathub-verified ]; then
            cp "$NOID_FIXTURE_REMOTE_ADD_CONFIG" "$NOID_FIXTURE_CONFIG"
            cp "$NOID_FIXTURE_KEY" "$NOID_FIXTURE_REPO/flathub.trustedkeys.gpg"
            cp "$NOID_FIXTURE_KEY" "$NOID_FIXTURE_REPO/flathub-verified.trustedkeys.gpg"
            if [ "${NOID_FIXTURE_SYMLINK_CONFIG:-0}" = 1 ]; then
                mv "$NOID_FIXTURE_CONFIG" "$NOID_FIXTURE_CONFIG.target"
                ln -s "${NOID_FIXTURE_CONFIG##*/}.target" "$NOID_FIXTURE_CONFIG"
            fi
        elif [ "$remote" = fedora ]; then
            cat >> "$NOID_FIXTURE_CONFIG" <<'FEDORA_CONFIG_EOF'

[remote "fedora"]
url=oci+https://registry.fedoraproject.org
xa.title=Fedora Flatpaks
xa.title-is-set=true
FEDORA_CONFIG_EOF
            if [ "${NOID_FIXTURE_BAD_NEW_FEDORA:-0}" = 1 ]; then
                printf '%s\n' \
                    'xa.signature-lookaside=https://evil.invalid/signatures' \
                    >> "$NOID_FIXTURE_CONFIG"
            fi
        fi
        ;;
    remote-ls)
        if [ -n "${NOID_FIXTURE_REMOTE_LS_FAILURES:-}" ]; then
            count=0
            [ ! -f "$NOID_FIXTURE_REMOTE_LS_COUNTER" ] \
                || read -r count < "$NOID_FIXTURE_REMOTE_LS_COUNTER"
            if [ "$count" -lt "$NOID_FIXTURE_REMOTE_LS_FAILURES" ]; then
                printf '%s\n' "$((count + 1))" > "$NOID_FIXTURE_REMOTE_LS_COUNTER"
                exit 56
            fi
        fi
        [ "${NOID_FIXTURE_EMPTY_CATALOG:-0}" != 1 ] || exit 0
        printf '%s\n' app/org.example.One/x86_64/stable runtime/org.example.Platform/x86_64/stable
        ;;
    *) exit 64 ;;
esac
FLATPAK_STUB_EOF
chmod 0755 "$FAKEBIN/flatpak"

export NOID_FLATPAK_POLICY_TEST_MODE=1
export NOID_FLATPAK_BIN="$FAKEBIN/flatpak"
export NOID_FLATHUB_DESCRIPTOR="$DESCRIPTOR"
export NOID_FLATPAK_SYSTEM_ROOT="$SYSTEM_ROOT"
export NOID_FIXTURE_CONFIG="$CONFIG"
export NOID_FIXTURE_REPO="$SYSTEM_ROOT/repo"
export NOID_FIXTURE_LOG="$LOG"
export NOID_FIXTURE_REMOTE_LS_COUNTER="$TMP/remote-ls-failures"
export NOID_FIXTURE_CANONICAL_CONFIG="$TMP/canonical-config"
export NOID_FIXTURE_REMOTE_ADD_CONFIG="$TMP/remote-add-config"
export NOID_FIXTURE_KEY="$TMP/trusted-key.gpg"
export NOID_FLATPAK_KEY_TMPDIR="$TMP/key-work"
mkdir -p "$NOID_FLATPAK_KEY_TMPDIR"

install_good_state() {
    rm -f -- "$CONFIG" "$CONFIG.target"
    cp "$TMP/canonical-config" "$CONFIG"
    cp "$TMP/trusted-key.gpg" "$SYSTEM_ROOT/repo/flathub.trustedkeys.gpg"
    cp "$TMP/trusted-key.gpg" "$SYSTEM_ROOT/repo/flathub-verified.trustedkeys.gpg"
    : > "$LOG"
    rm -f -- "$NOID_FIXTURE_REMOTE_LS_COUNTER"
    unset NOID_FIXTURE_INSTALLED NOID_FIXTURE_EMPTY_CATALOG \
        NOID_FIXTURE_FEDORA_IN_USE NOID_FIXTURE_LIST_FAILURE \
        NOID_FIXTURE_REMOTES_FAILURE NOID_FIXTURE_REMOTE_LS_FAILURES \
        NOID_FIXTURE_SYMLINK_CONFIG NOID_FIXTURE_BAD_NEW_FEDORA || true
}

install_good_state
assert_cmd_success "exact config, key bytes and non-empty cached catalogs pass" \
    "$POLICY" verify-default

install_good_state
sed -i 's,gpg-verify-summary=true,gpg-verify-summary=false,' "$CONFIG"
assert_cmd_failure "disabled summary verification fails closed" "$POLICY" verify-default

install_good_state
sed -i '0,/https:\/\/dl.flathub.org\/repo\//s//https:\/\/evil.invalid\/repo\//' "$CONFIG"
assert_cmd_failure "URL drift fails closed" "$POLICY" verify-default

install_good_state
sed -i '/xa.subset=verified/d' "$CONFIG"
assert_cmd_failure "verified-subset drift fails closed" "$POLICY" verify-default

install_good_state
sed -i '/^url=https:\/\/dl\.flathub\.org\/repo\/$/a http2=false' "$CONFIG"
assert_cmd_failure "legacy HTTP/2-disable override fails closed" \
    "$POLICY" verify-default

install_good_state
sed -i '/^url=https:\/\/dl\.flathub\.org\/repo\/$/a http2=true' "$CONFIG"
assert_cmd_failure "explicit HTTP/2-enable override fails closed" \
    "$POLICY" verify-default

install_good_state
printf 'tls-permissive=true\n' >> "$CONFIG"
assert_cmd_failure "an unreviewed TLS-bypass key fails the exact remote policy" \
    "$POLICY" verify-default

install_good_state
sed -i '0,/xa.title=Flathub/s//xa.title=Not Flathub/' "$CONFIG"
assert_cmd_failure "remote presentation-identity drift fails closed" \
    "$POLICY" verify-default

install_good_state
sed -i '0,/^xa.prio=1$/{//d;}' "$CONFIG"
assert_cmd_failure "an implicit full-catalog priority fails the exact policy" \
    "$POLICY" verify-default

install_good_state
printf '\n[remote "rogue"]\nurl=https://evil.invalid/\n' >> "$CONFIG"
assert_cmd_failure "an extra system remote fails the exact default set" "$POLICY" verify-default

install_good_state
printf x >> "$SYSTEM_ROOT/repo/flathub.trustedkeys.gpg"
assert_cmd_failure "trusted-key byte drift fails closed" "$POLICY" verify-default

extra_key_home="$TMP/extra-key-home"
mkdir -m 0700 "$extra_key_home"
gpg --batch --no-options --homedir "$extra_key_home" --passphrase '' \
    --quick-generate-key 'NoID Privacy fixture extra key <fixture@invalid>' \
    ed25519 sign 0 >/dev/null 2>&1
install_good_state
gpg --batch --no-options --homedir "$extra_key_home" --export \
    >> "$SYSTEM_ROOT/repo/flathub.trustedkeys.gpg"
assert_cmd_failure "an additional valid trusted signing key fails closed" \
    "$POLICY" verify-default

cat > "$FAKEBIN/stat-fail-export" <<'STAT_STUB_EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${!#}" in
    */export.gpg) exit 74 ;;
    *) exec /usr/bin/stat "$@" ;;
esac
STAT_STUB_EOF
chmod 0755 "$FAKEBIN/stat-fail-export"
install_good_state
assert_cmd_failure "trusted-key stat failure fails closed" \
    env NOID_STAT_BIN="$FAKEBIN/stat-fail-export" "$POLICY" verify-default
assert_eq 0 "$(find "$NOID_FLATPAK_KEY_TMPDIR" -mindepth 1 -maxdepth 1 | wc -l)" \
    "trusted-key scratch is removed after a stat failure"

install_good_state
export NOID_FIXTURE_EMPTY_CATALOG=1
assert_cmd_failure "an empty cached catalog fails closed" "$POLICY" verify-default

install_good_state
export NOID_FIXTURE_REMOTE_LS_FAILURES=1
assert_cmd_success "one online catalog transport failure is retried" \
    "$POLICY" verify-default --online
assert_eq 1 "$(cat "$NOID_FIXTURE_REMOTE_LS_COUNTER")" \
    "the successful online proof observed one injected transport failure"

install_good_state
export NOID_FIXTURE_REMOTE_LS_FAILURES=3
assert_cmd_failure "three online catalog transport failures exhaust the bound" \
    "$POLICY" verify-default --online
assert_eq 3 "$(cat "$NOID_FIXTURE_REMOTE_LS_COUNTER")" \
    "the online proof stops after exactly three failed attempts"

install_good_state
export NOID_FIXTURE_LIST_FAILURE=1
assert_cmd_failure "failed installed-ref inventory blocks reconciliation" \
    "$POLICY" apply-default
assert_not_grep 'remote-delete\|remote-add' "$LOG" \
    "installed-ref inventory failure occurs before remote mutation"

install_good_state
export NOID_FIXTURE_REMOTES_FAILURE=1
assert_cmd_failure "failed remote inventory blocks reconciliation" \
    "$POLICY" apply-default
assert_not_grep 'remote-delete\|remote-add' "$LOG" \
    "remote inventory failure occurs before remote mutation"

install_good_state
cp "$DESCRIPTOR" "$TMP/altered.flatpakrepo"
printf x >> "$TMP/altered.flatpakrepo"
assert_cmd_failure "descriptor byte drift fails before remote use" \
    env NOID_FLATHUB_DESCRIPTOR="$TMP/altered.flatpakrepo" "$POLICY" verify-default

cat > "$CONFIG" <<'ROGUE_EOF'
[core]
repo_version=1
[remote "rogue"]
url=https://evil.invalid/
ROGUE_EOF
: > "$LOG"
assert_cmd_success "fresh compose removes rogue state and recreates exact remotes" \
    "$POLICY" apply-default
assert_grep_fixed 'remote-delete --system rogue' "$LOG"
assert_not_grep 'remote-delete --system --force' "$LOG" \
    "reconciliation never bypasses Flatpak's in-use protection"
assert_grep_fixed 'remote-add --system --from --prio=1 flathub' "$LOG"
assert_grep_fixed 'remote-add --system --from --prio=2 --subset=verified flathub-verified' "$LOG"
assert_eq 0 "$(grep -c '^http2=' "$CONFIG")" \
    "fresh reconciliation leaves transport negotiation at the OSTree default"

install_good_state
export NOID_FIXTURE_SYMLINK_CONFIG=1
assert_cmd_failure "fresh reconciliation rejects a symlinked repository config" \
    "$POLICY" apply-default

install_good_state
export NOID_FIXTURE_INSTALLED=1
assert_cmd_failure "installed system refs block destructive reconciliation" \
    "$POLICY" apply-default
assert_not_grep 'remote-delete' "$LOG" \
    "installed-ref refusal occurs before any remote deletion"

install_good_state
assert_cmd_success "explicit Fedora stable opt-in adds the exact OCI identity" \
    "$POLICY" fedora-on
assert_grep_fixed "remote-add --system --title=Fedora\\ Flatpaks fedora oci+https://registry.fedoraproject.org" \
    "$LOG" "Fedora opt-in uses the reviewed stable command"
assert_cmd_success "explicit Fedora stable state reports healthy" \
    "$POLICY" fedora-status
assert_cmd_failure "exact-default verification rejects the enabled Fedora opt-in" \
    "$POLICY" verify-default
export NOID_FIXTURE_FEDORA_IN_USE=1
assert_cmd_failure "Fedora opt-out refuses while installed refs use the origin" \
    "$POLICY" fedora-off
unset NOID_FIXTURE_FEDORA_IN_USE
assert_cmd_success "unused Fedora stable remote can be removed" "$POLICY" fedora-off
assert_cmd_success "removed Fedora stable remote reports disabled" "$POLICY" fedora-status

install_good_state
export NOID_FIXTURE_BAD_NEW_FEDORA=1
assert_cmd_failure "a newly added Fedora remote with authority drift is rolled back" \
    "$POLICY" fedora-on
assert_grep_fixed 'remote-add --system --title=Fedora\ Flatpaks fedora oci+https://registry.fedoraproject.org' \
    "$LOG"
assert_grep_fixed 'remote-delete --system fedora' "$LOG" \
    "failed new Fedora identity is removed without force"

install_good_state
export NOID_FIXTURE_REMOTES_FAILURE=1
assert_cmd_failure "Fedora opt-in fails closed when remote inventory fails" \
    "$POLICY" fedora-on
assert_not_grep 'remote-add\|remote-delete' "$LOG" \
    "failed Fedora opt-in inventory causes no mutation"
assert_cmd_failure "Fedora status fails closed when remote inventory fails" \
    "$POLICY" fedora-status

install_good_state
assert_cmd_success "fixture Fedora remote is enabled for origin-failure test" \
    "$POLICY" fedora-on
: > "$LOG"
export NOID_FIXTURE_LIST_FAILURE=1
assert_cmd_failure "Fedora opt-out fails closed when origin inventory fails" \
    "$POLICY" fedora-off
assert_not_grep 'remote-delete' "$LOG" \
    "failed origin inventory cannot remove the Fedora update source"

install_good_state
cat >> "$CONFIG" <<'FEDORA_TESTING_EOF'

[remote "fedora-testing"]
url=oci+https://registry.fedoraproject.org#testing
FEDORA_TESTING_EOF
: > "$LOG"
assert_cmd_failure "fedora-testing blocks opt-in before any mutation" "$POLICY" fedora-on
assert_not_grep 'remote-add' "$LOG" \
    "fedora-testing refusal occurs before stable-remote addition"
assert_cmd_failure "status reports fedora-testing as drift, not disabled" \
    "$POLICY" fedora-status

install_good_state
cat >> "$CONFIG" <<'HOSTILE_FEDORA_EOF'

[remote "fedora"]
url=oci+https://evil.invalid
xa.title=Fedora Flatpaks
HOSTILE_FEDORA_EOF
assert_cmd_failure "a hostile pre-existing fedora name cannot satisfy opt-in" \
    "$POLICY" fedora-on

install_good_state
cat >> "$CONFIG" <<'FEDORA_AUTHORITY_DRIFT_EOF'

[remote "fedora"]
url=oci+https://registry.fedoraproject.org
xa.title=Fedora Flatpaks
xa.title-is-set=true
xa.signature-lookaside=https://evil.invalid/signatures
FEDORA_AUTHORITY_DRIFT_EOF
assert_cmd_failure "extra Fedora OCI authority configuration fails closed" \
    "$POLICY" fedora-on

assert_cmd_success "controller help succeeds" "$POLICY" --help
assert_cmd_failure "controller rejects unknown actions" "$POLICY" unknown
assert_cmd_failure "controller rejects extra verify arguments" "$POLICY" verify-default --online extra

# `verify-default [--online]` has two exact valid forms. Instrument the first
# verification effect so an explicit empty argument cannot be mistaken for an
# omitted optional argument, and so all hostile forms prove the same constant
# parser boundary before config, key or catalog access.
verify_gate="$TMP/verify-effect-gate"
awk '
    $0 == "verify_default() {" {
        print
        print "    printf \047NOID_VERIFY_EFFECT_REACHED\\n\047"
        print "    return 97"
        inserted = 1
        next
    }
    { print }
    END { if (!inserted) exit 1 }
' "$POLICY" > "$verify_gate"
chmod 0755 "$verify_gate"
expected_usage=$("$verify_gate" --help)

verify_hostile_case() {
    local label=$1 rc=0 stdout stderr
    shift
    stdout=$("$verify_gate" verify-default "$@" \
        2>"$TMP/verify-effect-gate.stderr") || rc=$?
    stderr=$(<"$TMP/verify-effect-gate.stderr")
    assert_eq 2 "$rc" "verify-default rejects $label before verification"
    assert_eq "" "$stdout" "verify-default keeps stdout empty for $label"
    assert_eq "$expected_usage" "$stderr" \
        "verify-default emits constant usage for $label"
}

verify_hostile_case "an empty optional argument" ""
verify_hostile_case "an unknown optional argument" --unknown
verify_hostile_case "surplus arguments" --online extra
verify_hostile_case "a newline argument" $'line\nbreak'
verify_hostile_case "an escape-sequence argument" $'\033[31mred'

for valid_verify_argument in absent --online; do
    verify_gate_rc=0
    verify_gate_stdout=
    if [ "$valid_verify_argument" = absent ]; then
        verify_gate_stdout=$("$verify_gate" verify-default \
            2>"$TMP/verify-effect-gate.stderr") || verify_gate_rc=$?
    else
        verify_gate_stdout=$("$verify_gate" verify-default --online \
            2>"$TMP/verify-effect-gate.stderr") || verify_gate_rc=$?
    fi
    assert_eq 97 "$verify_gate_rc" \
        "verify-default preserves the valid $valid_verify_argument form"
    assert_eq NOID_VERIFY_EFFECT_REACHED "$verify_gate_stdout" \
        "valid $valid_verify_argument form reaches verification"
    assert_eq "" "$(<"$TMP/verify-effect-gate.stderr")" \
        "valid $valid_verify_argument form keeps stderr empty at the marker"
done

public_toggle="$TMP/noid-toggle-fedora-flatpaks"
cp -- "$POLICY" "$public_toggle"
chmod 0755 "$public_toggle"
install_good_state
cat >> "$CONFIG" <<'PUBLIC_TOGGLE_DRIFT_EOF'

[remote "fedora"]
url=oci+https://evil.invalid
xa.title=Fedora Flatpaks
PUBLIC_TOGGLE_DRIFT_EOF
public_toggle_rc=0
public_toggle_error=$("$public_toggle" on 2>&1) || public_toggle_rc=$?
assert_eq 1 "$public_toggle_rc" \
    "public toggle surfaces a deterministic remote-policy failure"
assert_eq 'noid-toggle-fedora-flatpaks: existing fedora remote has an unexpected identity; remove it explicitly first' \
    "$public_toggle_error" \
    "public toggle diagnostics name the command the user invoked"

test_finish

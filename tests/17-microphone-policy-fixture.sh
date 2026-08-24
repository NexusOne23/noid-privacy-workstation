#!/usr/bin/env bash
# Isolated behavioral test for M17's persistent WirePlumber microphone policy.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT=$(find_project_root)
CONF="$ROOT/scripts/noid-microphone-privacy.conf"
LUA="$ROOT/scripts/noid-microphone-privacy.lua"
TOGGLE="$ROOT/scripts/noid-toggle-microphone.sh"
TEST_TMPDIR=$(mktemp -d /var/tmp/noid-mic-policy.XXXXXXXX)
trap 'rm -rf -- "$TEST_TMPDIR"' EXIT HUP INT TERM

test_start "17-microphone-policy-fixture"

# Linux sockaddr_un.sun_path has 108 bytes including the terminating NUL.
# Keep the fixture independent of checkout depth and bind the longest native
# PipeWire socket name before starting either daemon.
pipewire_manager_socket="$TEST_TMPDIR/runtime/pipewire-0-manager"
pipewire_manager_socket_bytes=$(LC_ALL=C printf '%s' "$pipewire_manager_socket" | wc -c)
assert_cmd_success "fixture PipeWire socket path fits sockaddr_un.sun_path" \
    test "$pipewire_manager_socket_bytes" -le 107

assert_file_exists "$CONF" "canonical WirePlumber policy fragment exists"
assert_file_exists "$LUA" "canonical WirePlumber policy script exists"
assert_file_executable "$TOGGLE" "canonical microphone helper is executable"

# A successful command with an unknown output grammar is not evidence of an
# unmuted source. Exercise that fail-visible boundary without a running audio
# session by overriding only the fixture copy's closed command path.
PARSER_FIXTURE="$TEST_TMPDIR/parser"
mkdir -p "$PARSER_FIXTURE/bin" "$PARSER_FIXTURE/home"
cp "$TOGGLE" "$PARSER_FIXTURE/toggle"
sed -i "s#^export PATH=/usr/bin\$#export PATH=$PARSER_FIXTURE/bin:/usr/bin#" \
    "$PARSER_FIXTURE/toggle"
assert_grep_fixed "export PATH=$PARSER_FIXTURE/bin:/usr/bin" \
    "$PARSER_FIXTURE/toggle" "parser fixture installs its closed command path"
cat >"$PARSER_FIXTURE/bin/gsettings" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${NOID_FIXTURE_GNOME:-false}"
EOF
cat >"$PARSER_FIXTURE/bin/pw-dump" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' \
  '[{"id":7,"type":"PipeWire:Interface:Node","info":{"props":{"media.class":"Audio/Source"}}}]'
EOF
cat >"$PARSER_FIXTURE/bin/wpctl" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    settings)
        active=${NOID_FIXTURE_ACTIVE:-false}
        saved=${NOID_FIXTURE_SAVED:-false}
        case "$saved" in
            missing) printf 'Value: %s\n' "$active" ;;
            true|false)
                printf 'Value: %s (Saved: %s)\n' "$active" "$saved"
                ;;
            *) exit 2 ;;
        esac
        ;;
    get-volume) printf '%s\n' "${NOID_FIXTURE_VOLUME:-Volume: unknown}" ;;
    *) exit 2 ;;
esac
EOF
chmod 0700 "$PARSER_FIXTURE/toggle" "$PARSER_FIXTURE/bin/"*
assert_cmd_failure "unknown wpctl volume output is fail-visible" \
    env HOME="$PARSER_FIXTURE/home" "$PARSER_FIXTURE/toggle" status
assert_grep_fixed \
    '^Volume:[[:space:]]+[0-9]+(\.[0-9]+)?([[:space:]]+\[MUTED\])?$' \
    "$TOGGLE" "microphone status accepts only WirePlumber numeric volume evidence"
for saved_fixture in true missing; do
    if saved_output=$(env HOME="$PARSER_FIXTURE/home" \
            NOID_FIXTURE_SAVED="$saved_fixture" \
            NOID_FIXTURE_VOLUME='Volume: 1.00' \
            "$PARSER_FIXTURE/toggle" status); then
        _fail "nonpersistent WirePlumber state is fail-visible: $saved_fixture"
    else
        _pass "nonpersistent WirePlumber state is fail-visible: $saved_fixture"
    fi
    assert_eq microphone=degraded \
        "$(grep '^microphone=' <<<"$saved_output")" \
        "nonpersistent WirePlumber state is reported degraded: $saved_fixture"
done

if default_off_output=$(env HOME="$PARSER_FIXTURE/home" \
        NOID_FIXTURE_GNOME=true \
        NOID_FIXTURE_ACTIVE=true \
        NOID_FIXTURE_SAVED=missing \
        NOID_FIXTURE_VOLUME='Volume: 1.00 [MUTED]' \
        "$PARSER_FIXTURE/toggle" status); then
    _pass "schema-default WirePlumber policy is accepted when fully enforced"
else
    _fail "schema-default WirePlumber policy is accepted when fully enforced"
fi
assert_eq wireplumber_saved_value=default \
    "$(grep '^wireplumber_saved_value=' <<<"$default_off_output")" \
    "missing WirePlumber saved state is reported as the schema default"
assert_eq microphone=off \
    "$(grep '^microphone=' <<<"$default_off_output")" \
    "safe schema default plus muted capture is reported off"

if default_unmuted_output=$(env HOME="$PARSER_FIXTURE/home" \
        NOID_FIXTURE_GNOME=true \
        NOID_FIXTURE_ACTIVE=true \
        NOID_FIXTURE_SAVED=missing \
        NOID_FIXTURE_VOLUME='Volume: 1.00' \
        "$PARSER_FIXTURE/toggle" status); then
    _fail "schema-default policy remains fail-visible when capture is unmuted"
else
    _pass "schema-default policy remains fail-visible when capture is unmuted"
fi
assert_eq microphone=degraded \
    "$(grep '^microphone=' <<<"$default_unmuted_output")" \
    "unmuted capture cannot be hidden by the safe schema default"

missing_commands=()
for command in dbus-run-session pipewire wireplumber wpctl pw-cli pw-dump \
               python3 gsettings spa-json-dump; do
    command -v "$command" >/dev/null 2>&1 || missing_commands+=("$command")
done
if ((${#missing_commands[@]} > 0)); then
    _pass "isolated runtime fixture deferred; host lacks: ${missing_commands[*]}"
    test_finish
    exit 0
fi
for command in dbus-run-session pipewire wireplumber wpctl pw-cli pw-dump \
               python3 gsettings spa-json-dump; do
    _pass "required fixture command: $command"
done
assert_cmd_success "canonical WirePlumber fragment parses" spa-json-dump "$CONF"
assert_cmd_success "canonical microphone helper parses" bash -n "$TOGGLE"

mkdir -p \
    "$TEST_TMPDIR/config/wireplumber.conf.d" \
    "$TEST_TMPDIR/data/wireplumber/scripts" \
    "$TEST_TMPDIR/runtime" \
    "$TEST_TMPDIR/home" \
    "$TEST_TMPDIR/state" \
    "$TEST_TMPDIR/user-config"
chmod 0700 "$TEST_TMPDIR/runtime" "$TEST_TMPDIR/home" \
    "$TEST_TMPDIR/state" "$TEST_TMPDIR/user-config"
cp /usr/share/wireplumber/wireplumber.conf \
    "$TEST_TMPDIR/config/wireplumber.conf"
cp "$CONF" \
    "$TEST_TMPDIR/config/wireplumber.conf.d/90-noid-microphone-privacy.conf"
cp "$LUA" \
    "$TEST_TMPDIR/data/wireplumber/scripts/noid-microphone-privacy.lua"

export TEST_TMPDIR TOGGLE
assert_cmd_success "isolated WirePlumber policy lifecycle" \
    dbus-run-session -- bash -Eeuo pipefail -c '
export HOME="$TEST_TMPDIR/home"
export XDG_RUNTIME_DIR="$TEST_TMPDIR/runtime"
export XDG_STATE_HOME="$TEST_TMPDIR/state"
export XDG_CONFIG_HOME="$TEST_TMPDIR/user-config"
export XDG_DATA_DIRS="$TEST_TMPDIR/data:/usr/share"
export WIREPLUMBER_CONFIG_DIR="$TEST_TMPDIR/config"
export GSETTINGS_BACKEND=keyfile

# The microphone fixture has no network-discovery role. Disable the optional
# system RAOP fragment explicitly so a generic CI host with
# pipewire-config-raop installed cannot request Avahi or pollute host logs.
pipewire -P "{ module.raop = false }" >"$TEST_TMPDIR/pipewire.log" 2>&1 &
pw_pid=$!
wp_pid=""
cli_pid=""

cleanup_session() {
    # Keep PipeWire alive until its clients have finished their own shutdown.
    # Signalling all three processes before waiting races WirePlumber teardown
    # against loss of the PipeWire server and can turn a passing fixture into a
    # host-audit ANOM_ABEND record.
    if [[ -n ${cli_pid:-} ]]; then
        kill "$cli_pid" 2>/dev/null || true
        wait "$cli_pid" 2>/dev/null || true
    fi
    if [[ -n ${wp_pid:-} ]]; then
        kill "$wp_pid" 2>/dev/null || true
        wait "$wp_pid" 2>/dev/null || true
    fi
    if [[ -n ${pw_pid:-} ]]; then
        kill "$pw_pid" 2>/dev/null || true
        wait "$pw_pid" 2>/dev/null || true
    fi
}
trap cleanup_session EXIT HUP INT TERM

for _ in {1..50}; do
    [[ -S "$XDG_RUNTIME_DIR/pipewire-0" ]] && break
    sleep 0.1
done
[[ -S "$XDG_RUNTIME_DIR/pipewire-0" ]]
if grep -Eq "libpipewire-module-raop-discover|libavahi-(client|common)" \
        "/proc/$pw_pid/maps"; then
    printf "%s\n" "isolated microphone fixture loaded LAN-discovery code" >&2
    exit 1
fi

start_wireplumber() {
    wireplumber -p video-only >>"$TEST_TMPDIR/wireplumber.log" 2>&1 &
    wp_pid=$!
    for _ in {1..80}; do
        wpctl settings noid.microphone.disabled >/dev/null 2>&1 && return 0
        kill -0 "$wp_pid"
        sleep 0.1
    done
    return 1
}

add_source() {
    local name=$1
    local node_id=""
    printf "%s\n" \
        "create-node adapter { factory.name=support.null-audio-sink node.name=$name media.class=Audio/Source audio.position=[ MONO ] }" \
        >&"${CLI[1]}"
    for _ in {1..50}; do
        node_id=$(pw-dump | python3 -c \
            "import json,sys; n=sys.argv[1]; print(next((x[\"id\"] for x in json.load(sys.stdin) if x.get(\"info\",{}).get(\"props\",{}).get(\"node.name\")==n), \"\"))" \
            "$name")
        [[ -n $node_id ]] && { printf "%s\n" "$node_id"; return 0; }
        sleep 0.1
    done
    return 1
}

wait_mute() {
    local node_id=$1 wanted=$2 output
    for _ in {1..50}; do
        output=$(wpctl get-volume "$node_id" 2>/dev/null) || {
            sleep 0.1
            continue
        }
        if [[ $wanted == 1 && $output == *"[MUTED]"* ]] ||
           [[ $wanted == 0 && $output != *"[MUTED]"* ]]; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

start_wireplumber
grep -qx "Value: true" <(wpctl settings noid.microphone.disabled)

coproc CLI { pw-cli >"$TEST_TMPDIR/pw-cli.log" 2>&1; }
cli_pid=$CLI_PID
node_1=$(add_source noid_fixture_source_1)
wait_mute "$node_1" 1

# A direct hardware/panel-equivalent unmute must be reversed while disabled.
wpctl set-mute "$node_1" 0
wait_mute "$node_1" 1

"$TOGGLE" off >"$TEST_TMPDIR/off.out"
"$TOGGLE" status >"$TEST_TMPDIR/status-off.out"
grep -qxF "noid.microphone.disabled=true" \
    "$XDG_STATE_HOME/wireplumber/sm-settings"
grep -qx "capture_sources=1" "$TEST_TMPDIR/status-off.out"
grep -qx "capture_source_mute=muted" "$TEST_TMPDIR/status-off.out"
grep -qx "microphone=off" "$TEST_TMPDIR/status-off.out"

"$TOGGLE" on >"$TEST_TMPDIR/on.out"
wait_mute "$node_1" 0
"$TOGGLE" status >"$TEST_TMPDIR/status-on.out"
grep -qxF "noid.microphone.disabled=false" \
    "$XDG_STATE_HOME/wireplumber/sm-settings"
grep -qx "capture_sources=1" "$TEST_TMPDIR/status-on.out"
grep -qx "capture_source_mute=unmuted" "$TEST_TMPDIR/status-on.out"
grep -qx "microphone=on" "$TEST_TMPDIR/status-on.out"

# New sources created while enabled are not forcibly muted.
node_2=$(add_source noid_fixture_source_2)
wait_mute "$node_2" 0

"$TOGGLE" off >"$TEST_TMPDIR/off-two.out"
wait_mute "$node_1" 1
wait_mute "$node_2" 1
"$TOGGLE" status >"$TEST_TMPDIR/status-two-off.out"
grep -qx "capture_sources=2" "$TEST_TMPDIR/status-two-off.out"
grep -qx "capture_source_mute=muted" "$TEST_TMPDIR/status-two-off.out"
grep -qx "microphone=off" "$TEST_TMPDIR/status-two-off.out"

# The saved policy must survive a real WirePlumber process restart.
kill "$wp_pid"
wait "$wp_pid" || true
wp_pid=""
start_wireplumber
grep -qx "Value: true (Saved: true)" \
    <(wpctl settings noid.microphone.disabled)
wait_mute "$node_1" 1
wait_mute "$node_2" 1
"$TOGGLE" status >"$TEST_TMPDIR/status-restart.out"
grep -qx "capture_sources=2" "$TEST_TMPDIR/status-restart.out"
grep -qx "microphone=off" "$TEST_TMPDIR/status-restart.out"
'

assert_grep_fixed 'Microphone: OFF' "$TEST_TMPDIR/off.out" \
    "disable transaction reports success"
assert_grep_fixed 'Microphone: ON' "$TEST_TMPDIR/on.out" \
    "enable transaction reports success"
assert_grep_fixed 'capture_sources=2' "$TEST_TMPDIR/status-restart.out" \
    "restart retains both fixture sources"
assert_grep_fixed 'microphone=off' "$TEST_TMPDIR/status-restart.out" \
    "saved disabled policy survives WirePlumber restart"

test_finish

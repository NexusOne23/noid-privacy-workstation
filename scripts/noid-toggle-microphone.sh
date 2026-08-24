#!/bin/bash
# noid-toggle-microphone — transactional two-layer microphone privacy control
set -Eeuo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/bin

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Microphone" \
    NOID_FMT_AUTO_SUBTITLE="GNOME and WirePlumber policy" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

readonly GNOME_SCHEMA="org.gnome.desktop.privacy"
readonly GNOME_KEY="disable-microphone"
readonly WP_KEY="noid.microphone.disabled"

WP_ACTIVE=""
WP_SAVED=""
SOURCE_IDS=()
SOURCE_STATE="unavailable"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'USAGE_EOF'
Usage: noid-toggle-microphone on|off|status

  on      Allow GNOME application access and unmute current capture sources.
  off     Block GNOME application access and persistently enforce source mute.
  status  Show both policy layers and the current PipeWire source state.
USAGE_EOF
}

gnome_get() {
    local value
    value=$(gsettings get "$GNOME_SCHEMA" "$GNOME_KEY" 2>/dev/null) || return 1
    case "$value" in
        true|false) printf '%s\n' "$value" ;;
        *) return 1 ;;
    esac
}

gnome_set() {
    local value=$1
    local _ current
    gsettings set "$GNOME_SCHEMA" "$GNOME_KEY" "$value" >/dev/null || return 1
    # dconf commits asynchronously; a successful setter can briefly be followed
    # by the previous value in a separate gsettings process.
    for _ in {1..30}; do
        current=$(gnome_get) || current=""
        [[ $current == "$value" ]] && return 0
        sleep 0.1
    done
    return 1
}

wp_get() {
    local output
    output=$(wpctl settings "$WP_KEY" 2>/dev/null) || return 1
    output=${output//$'\r'/}
    if [[ $output =~ ^Value:[[:space:]]+(true|false)([[:space:]]+\(Saved:[[:space:]]+(true|false)\))?$ ]]; then
        WP_ACTIVE=${BASH_REMATCH[1]}
        WP_SAVED=${BASH_REMATCH[3]:-}
        return 0
    fi
    return 1
}

wp_set_saved() {
    local value=$1
    local _ state_home state_file
    state_home=${XDG_STATE_HOME:-"$HOME/.local/state"}
    [[ $state_home == /* ]] || state_home="$HOME/.local/state"
    state_file="$state_home/wireplumber/sm-settings"
    wpctl settings --save "$WP_KEY" "$value" >/dev/null 2>&1 || return 1
    # WirePlumber first updates metadata, then flushes persistent state
    # asynchronously. Require both postconditions before reporting success.
    for _ in {1..40}; do
        if wp_get && [[ $WP_ACTIVE == "$value" && $WP_SAVED == "$value" ]] &&
           [[ -f $state_file && ! -L $state_file ]] &&
           grep -qxF "$WP_KEY=$value" "$state_file"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

load_source_ids() {
    local output
    output=$(python3 - <<'PY_EOF'
import json
import subprocess
import sys

try:
    proc = subprocess.run(
        ["pw-dump"], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, timeout=5,
    )
    objects = json.loads(proc.stdout)
except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)

ids = set()
for obj in objects:
    if obj.get("type") != "PipeWire:Interface:Node":
        continue
    props = obj.get("info", {}).get("props", {})
    media_class = props.get("media.class")
    if media_class == "Audio/Source" or (
            isinstance(media_class, str) and media_class.startswith("Audio/Source/")):
        node_id = obj.get("id")
        if isinstance(node_id, int) and node_id >= 0:
            ids.add(node_id)

for node_id in sorted(ids):
    print(node_id)
PY_EOF
    ) || return 1

    SOURCE_IDS=()
    if [[ -n $output ]]; then
        mapfile -t SOURCE_IDS <<<"$output"
    fi
}

set_sources_mute() {
    local desired=$1
    local node_id
    load_source_ids || return 1
    for node_id in "${SOURCE_IDS[@]}"; do
        wpctl set-mute "$node_id" "$desired" >/dev/null 2>&1 || return 1
    done
}

source_state() {
    local node_id output mute_state
    local muted=0
    local unmuted=0
    SOURCE_STATE="unavailable"
    load_source_ids || return 1
    if ((${#SOURCE_IDS[@]} == 0)); then
        SOURCE_STATE="not-present"
        return 0
    fi
    for node_id in "${SOURCE_IDS[@]}"; do
        output=$(wpctl get-volume "$node_id" 2>/dev/null) || {
            return 1
        }
        # WirePlumber renders `Volume: %.2f` with an optional `[MUTED]`
        # suffix. Reject successful-but-unexpected output instead of treating
        # every string without that suffix as proof that capture is unmuted.
        if [[ $output =~ ^Volume:[[:space:]]+[0-9]+(\.[0-9]+)?([[:space:]]+\[MUTED\])?$ ]]; then
            if [[ -n ${BASH_REMATCH[2]:-} ]]; then
                mute_state=muted
            else
                mute_state=unmuted
            fi
        else
            return 1
        fi
        case "$mute_state" in
            muted) ((muted += 1)) ;;
            unmuted) ((unmuted += 1)) ;;
        esac
    done
    if ((muted > 0 && unmuted == 0)); then
        SOURCE_STATE="muted"
    elif ((unmuted > 0 && muted == 0)); then
        SOURCE_STATE="unmuted"
    else
        SOURCE_STATE="mixed"
    fi
}

force_disabled() {
    local failed=0
    gnome_set true || failed=1
    wp_set_saved true || failed=1
    set_sources_mute 1 || failed=1
    return "$failed"
}

verify_mode() {
    local mode=$1
    local gnome_value
    gnome_value=$(gnome_get) || return 1
    wp_get || return 1
    source_state || return 1
    case "$mode" in
        off)
            [[ $gnome_value == true && $WP_ACTIVE == true && $WP_SAVED == true &&
               ($SOURCE_STATE == muted || $SOURCE_STATE == not-present) ]]
            ;;
        on)
            [[ $gnome_value == false && $WP_ACTIVE == false && $WP_SAVED == false &&
               ($SOURCE_STATE == unmuted || $SOURCE_STATE == not-present) ]]
            ;;
        *) return 1 ;;
    esac
}

show_status() {
    local gnome_value="unknown"
    local wp_value="unknown"
    local saved_value="default"
    local state="unavailable"
    local coherent=1

    gnome_value=$(gnome_get) || coherent=0
    if wp_get; then
        wp_value=$WP_ACTIVE
        [[ -z $WP_SAVED ]] || saved_value=$WP_SAVED
    else
        coherent=0
    fi
    source_state || coherent=0
    state=$SOURCE_STATE

    printf 'gnome_disable_microphone=%s\n' "$gnome_value"
    printf 'wireplumber_policy_disabled=%s\n' "$wp_value"
    printf 'wireplumber_saved_value=%s\n' "$saved_value"
    printf 'capture_sources=%s\n' "${#SOURCE_IDS[@]}"
    printf 'capture_source_mute=%s\n' "$state"

    if [[ $gnome_value == true && $wp_value == true &&
          ($saved_value == true || $saved_value == default) &&
          ($state == muted || $state == not-present) ]]; then
        printf 'microphone=off\n'
    elif [[ $gnome_value == false && $wp_value == false &&
            $saved_value == false &&
            ($state == unmuted || $state == not-present) ]]; then
        printf 'microphone=on\n'
    else
        printf 'microphone=degraded\n'
        coherent=0
    fi
    return $((coherent == 1 ? 0 : 1))
}

case "${1:-}" in
    off)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        force_disabled || die "microphone disable incomplete; privacy-safe layers were retained where possible"
        verify_mode off || die "microphone disable postcondition failed"
        printf 'Microphone: OFF (GNOME access blocked; WirePlumber persistent mute active)\n'
        ;;
    on)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        # Keep the GNOME application block engaged until policy and source
        # unmute both succeed. Any failure returns to the privacy-safe state.
        if ! wp_set_saved false || ! set_sources_mute 0 || ! gnome_set false ||
           ! verify_mode on; then
            if force_disabled; then
                die "microphone enable failed; restored the disabled state"
            fi
            die "microphone enable failed and fail-closed restoration was incomplete"
        fi
        printf 'Microphone: ON (GNOME access allowed; persistent mute inactive)\n'
        ;;
    status)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        show_status
        ;;
    -h|--help|help)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

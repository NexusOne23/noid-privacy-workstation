#!/usr/bin/env bash
# Candidate-only codec state, software decode and advertised VA-API decode gate.
# Run as root in the canonical candidate sequence:
#   live pristine -> fresh-install pristine -> explicit codec opt-in ->
#   fresh-install complete -> reboot -> reboot complete
set -euo pipefail
umask 077
ulimit -c 0

TEST_NAME=08-codec-runtime
PASS_ID=${1:-}
EXPECTED_STATE=${2:-}
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *)
        echo "Usage: sudo bash $0 {live|fresh-install|reboot} {pristine|complete}" >&2
        exit 2
        ;;
esac
case "$EXPECTED_STATE" in
    pristine|complete) ;;
    *)
        echo "Usage: sudo bash $0 {live|fresh-install|reboot} {pristine|complete}" >&2
        exit 2
        ;;
esac
RUN_ID=$PASS_ID/$EXPECTED_STATE

fail() { echo "FAIL  $TEST_NAME [$RUN_ID]: $*" >&2; exit 1; }
note() { echo "  [$RUN_ID] $*"; }

[[ $EUID -eq 0 ]] || fail "run as root"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null \
    || fail "not running inside the NoID Privacy candidate"

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV CDPATH ENV FFREPORT GLOBIGNORE GST_PLUGIN_PATH \
    GST_PLUGIN_SYSTEM_PATH LD_LIBRARY_PATH LD_PRELOAD LIBVA_DRIVER_NAME \
    MESA_LOADER_DRIVER_OVERRIDE PYTHONHOME PYTHONPATH

for command_name in awk bash cmp dnf ffmpeg grep gst-inspect-1.0 \
        gst-launch-1.0 lspci mktemp readlink restorecon rpm sed stat \
        systemctl systemd-analyze vainfo; do
    command -v "$command_name" >/dev/null 2>&1 \
        || fail "required command missing: $command_name"
done

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
KS_FILE=$REPO_ROOT/kickstart/snippets/08-service-minimization.ks
HELPER=/usr/local/bin/noid-firstboot-setup.sh
UNIT=/etc/systemd/system/noid-firstboot-setup.service
WRAPPER=/usr/local/bin/noid-complete-setup.sh
FLAG=/var/lib/noid-privacy/firstboot-setup-done.flag
STATE_DIR=/var/lib/noid-privacy/firstboot-setup
LOG=/var/log/noid-firstboot-setup.log

[[ -f $KS_FILE && ! -L $KS_FILE ]] || fail "canonical Module 08 source is unsafe"
TMPDIR=$(mktemp -d /var/tmp/noid-codec-runtime.XXXXXX)
cleanup() { rm -rf -- "$TMPDIR"; }
trap cleanup EXIT HUP INT TERM

extract_payload() {
    local marker=$1 target=$2
    awk -v m="$marker" '
        $0 ~ "<<-?[[:space:]]*[\047\"]?" m "[\047\"]?([[:space:]]|$)" {
            in_hd=1
            next
        }
        in_hd && ($0 == m || $0 ~ "^[\t]+" m "$") {
            closed=1
            exit
        }
        in_hd { print }
        END { if (!closed) exit 1 }
    ' "$KS_FILE" > "$target" || return 1
    [[ -s $target ]]
}

extract_payload FIRSTBOOT_SCRIPT_EOF "$TMPDIR/helper" \
    || fail "cannot extract canonical codec helper"
extract_payload FIRSTBOOT_UNIT_EOF "$TMPDIR/unit" \
    || fail "cannot extract canonical codec unit"
extract_payload COMPLETE_SETUP_EOF "$TMPDIR/wrapper" \
    || fail "cannot extract canonical codec wrapper"

require_regular() {
    local path=$1 metadata=$2
    [[ -f $path && ! -L $path ]] || fail "missing or unsafe regular file: $path"
    [[ $(stat -c '%u:%g:%a:%h' "$path") == "$metadata" ]] \
        || fail "wrong ownership/mode/link count: $path"
}

require_regular "$HELPER" 0:0:755:1
require_regular "$UNIT" 0:0:644:1
require_regular "$WRAPPER" 0:0:755:1
cmp -s "$TMPDIR/helper" "$HELPER" || fail "installed codec helper differs from Module 08"
cmp -s "$TMPDIR/unit" "$UNIT" || fail "installed codec unit differs from Module 08"
cmp -s "$TMPDIR/wrapper" "$WRAPPER" || fail "installed codec wrapper differs from Module 08"
bash -n "$HELPER" || fail "installed codec helper does not parse"
bash -n "$WRAPPER" || fail "installed codec wrapper does not parse"
systemd-analyze verify "$UNIT" >/dev/null \
    || fail "installed codec unit fails native verification"

[[ $(systemctl is-enabled noid-firstboot-setup.service 2>/dev/null || true) == disabled ]] \
    || fail "opt-in codec service is not disabled"
[[ $(systemctl is-active noid-firstboot-setup.service 2>/dev/null || true) != active ]] \
    || fail "opt-in codec service is unexpectedly active"
[[ ! -e /etc/systemd/system/multi-user.target.wants/noid-firstboot-setup.service ]] \
    || fail "opt-in codec service has an unexpected wants symlink"
[[ $(systemctl show noid-firstboot-setup.service -p UMask --value) == 0077 ]] \
    || fail "codec service UMask is not 0077"
[[ $(systemctl show noid-firstboot-setup.service -p Environment --value) == \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin ]] \
    || fail "codec service PATH is not the exact trusted path"
[[ $(systemctl show noid-firstboot-setup.service -p UnsetEnvironment --value) == \
    'BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME' ]] \
    || fail "codec service interpreter-injection environment guard differs"

for installed_path in "$HELPER" "$UNIT" "$WRAPPER"; do
    # restorecon's passive check is silent unless verbose output is enabled;
    # capture the proposed relabel so a successful command cannot hide drift.
    relabel_output=$(restorecon -nv "$installed_path" 2>/dev/null) \
        || fail "cannot evaluate SELinux label: $installed_path"
    [[ -z $relabel_output ]] \
        || fail "SELinux label drift: $installed_path"
done

path_exists() { [[ -e $1 || -L $1 ]]; }
valid_receipt() {
    [[ -f $1 && ! -L $1 ]] \
        && [[ $(stat -c '%u:%g:%a:%h:%s' "$1" 2>/dev/null || true) == 0:0:600:1:0 ]]
}
require_package() {
    rpm -q "$1" >/dev/null 2>&1 || fail "required package missing: $1"
}
reject_package() {
    ! rpm -q "$1" >/dev/null 2>&1 || fail "forbidden package present: $1"
}

# DNF5 rewrites this complete package-reason/group inventory after every
# transaction. It is system state, not codec-private evidence: ordinary users
# must retain read-only package queries even though this gate and the codec
# service themselves use umask 0077.
for state_name in environments groups modules nevras packages system; do
    state_file=/usr/lib/sysimage/libdnf5/$state_name.toml
    [[ -f $state_file && ! -L $state_file ]] \
        || fail "DNF5 system-state file missing or unsafe: $state_file"
    [[ $(stat -c '%U:%G:%a:%h' "$state_file") == root:root:644:1 ]] \
        || fail "DNF5 system-state file is not public package inventory: $state_file"
done

GPU_CONTROLLER_RE=' (VGA|3D|Display) (compatible )?controller'
GPU_LINES=$(lspci -Dnn 2>/dev/null | grep -iE "$GPU_CONTROLLER_RE" || true)
intel_gpu=0
amd_gpu=0
grep -qE 'Intel' <<<"$GPU_LINES" && intel_gpu=1
grep -qE 'AMD|ATI|Radeon' <<<"$GPU_LINES" && amd_gpu=1

if ! path_exists "$FLAG"; then
    [[ $EXPECTED_STATE == pristine ]] \
        || fail "expected completed codec state but the completion receipt is absent"
    ! path_exists "$STATE_DIR" \
        || fail "incomplete codec attempt left state without a completion receipt"
    ! path_exists "$LOG" \
        || fail "incomplete codec attempt left a log without a completion receipt"
    for package_name in ffmpeg gstreamer1-plugins-bad-freeworld \
            openh264 mozilla-openh264 gstreamer1-plugin-openh264 \
            intel-media-driver mesa-va-drivers-freeworld; do
        reject_package "$package_name"
    done
    require_package ffmpeg-free
    require_package gstreamer1-plugin-libav
    require_package gstreamer1-plugin-dav1d
    if [[ $intel_gpu == 1 ]]; then
        require_package libva-intel-media-driver
    fi
    note "pristine Silent-Machine codec deferral and disabled service verified"
    echo "PASS  $TEST_NAME [$RUN_ID]: canonical private opt-in path is dormant; no deferred codec payload is installed"
    exit 0
fi

[[ $EXPECTED_STATE == complete ]] \
    || fail "expected pristine codec state but a completion receipt exists"
valid_receipt "$FLAG" || fail "completion receipt metadata is unsafe"
[[ -d $STATE_DIR && ! -L $STATE_DIR ]] \
    || fail "codec task-state directory is missing or unsafe"
[[ $(stat -c '%u:%g:%a:%h' "$STATE_DIR") == 0:0:700:1 ]] \
    || fail "codec task-state directory metadata differs"
for receipt in task1-ffmpeg.ok task2-openh264.ok; do
    valid_receipt "$STATE_DIR/$receipt" || fail "invalid task receipt: $receipt"
done
if [[ $intel_gpu == 1 ]]; then
    valid_receipt "$STATE_DIR/task3-intel-media.ok" \
        || fail "Intel codec completion lacks an exact transaction receipt"
fi
if [[ $amd_gpu == 1 ]]; then
    valid_receipt "$STATE_DIR/task3-amd-mesa.ok" \
        || fail "AMD codec completion lacks an exact transaction receipt"
fi
require_regular "$LOG" 0:0:600:1

for package_name in ffmpeg gstreamer1-plugins-bad-freeworld \
        openh264 mozilla-openh264 gstreamer1-plugin-openh264 \
        gstreamer1-plugin-libav gstreamer1-plugin-dav1d; do
    require_package "$package_name"
done
reject_package ffmpeg-free
reject_package noopenh264
if [[ $intel_gpu == 1 ]]; then
    require_package intel-media-driver
    reject_package libva-intel-media-driver
fi
if [[ $amd_gpu == 1 ]]; then
    require_package mesa-va-drivers-freeworld
fi

verify_packages=(ffmpeg gstreamer1-plugins-bad-freeworld openh264
    mozilla-openh264 gstreamer1-plugin-openh264
    gstreamer1-plugin-libav gstreamer1-plugin-dav1d)
[[ $intel_gpu == 0 ]] || verify_packages+=(intel-media-driver)
[[ $amd_gpu == 0 ]] || verify_packages+=(mesa-va-drivers-freeworld)
rpm -V "${verify_packages[@]}" >/dev/null \
    || fail "codec package payload verification failed"
dnf --cacheonly check --duplicates --dependencies >/dev/null \
    || fail "cached RPM dependency/duplicate check failed"
note "package state, receipts, payload digests and dependency graph verified"

MEDIA=$TMPDIR/media
mkdir "$MEDIA"
ffmpeg -hide_banner -loglevel error -f lavfi \
    -i testsrc2=size=320x180:rate=30 -frames:v 30 -an \
    -c:v libx264 -preset ultrafast -pix_fmt yuv420p "$MEDIA/h264.mp4" \
    || fail "cannot generate H.264 validation stream"
ffmpeg -hide_banner -loglevel error -f lavfi \
    -i testsrc2=size=320x180:rate=30 -frames:v 30 -an \
    -c:v libx265 -preset ultrafast -pix_fmt yuv420p \
    -tag:v hvc1 -x265-params log-level=error "$MEDIA/hevc.mp4" \
    || fail "cannot generate HEVC validation stream"
ffmpeg -hide_banner -loglevel error -f lavfi \
    -i testsrc2=size=320x180:rate=30 -frames:v 30 -an \
    -c:v libvpx-vp9 -deadline realtime -cpu-used 8 -pix_fmt yuv420p \
    "$MEDIA/vp9.mkv" || fail "cannot generate VP9 validation stream"
if ! ffmpeg -hide_banner -loglevel error -f lavfi \
        -i testsrc2=size=320x180:rate=30 -frames:v 30 -an \
        -c:v libsvtav1 -preset 10 -pix_fmt yuv420p "$MEDIA/av1.mkv" \
        >"$TMPDIR/av1-encode.log" 2>&1; then
    sed 's/^/    /' "$TMPDIR/av1-encode.log" >&2
    fail "cannot generate AV1 validation stream"
fi

for sample in h264.mp4 hevc.mp4 vp9.mkv av1.mkv; do
    ffmpeg -hide_banner -loglevel error -i "$MEDIA/$sample" -f null - \
        || fail "FFmpeg software decode failed: $sample"
done

for factory in openh264dec libde265dec avdec_vp9 dav1ddec; do
    gst-inspect-1.0 "$factory" >/dev/null \
        || fail "GStreamer decoder factory missing: $factory"
done
gst-launch-1.0 -q filesrc location="$MEDIA/h264.mp4" ! qtdemux ! \
    h264parse ! openh264dec ! fakesink sync=false \
    || fail "GStreamer H.264 decode failed"
gst-launch-1.0 -q filesrc location="$MEDIA/hevc.mp4" ! qtdemux ! \
    h265parse ! libde265dec ! fakesink sync=false \
    || fail "GStreamer HEVC decode failed"
gst-launch-1.0 -q filesrc location="$MEDIA/vp9.mkv" ! matroskademux ! \
    vp9parse ! avdec_vp9 ! fakesink sync=false \
    || fail "GStreamer VP9 decode failed"
gst-launch-1.0 -q filesrc location="$MEDIA/av1.mkv" ! matroskademux ! \
    av1parse ! dav1ddec ! fakesink sync=false \
    || fail "GStreamer AV1 decode failed"
note "real FFmpeg and GStreamer H.264/HEVC/VP9/AV1 software decode passed"

va_nodes=0
va_decodes=0
while IFS= read -r gpu_line; do
    [[ -n $gpu_line ]] || continue
    case "$gpu_line" in
        *Intel*|*AMD*|*ATI*|*Radeon*) ;;
        *) continue ;;
    esac
    bdf=${gpu_line%% *}
    by_path=/dev/dri/by-path/pci-${bdf}-render
    [[ -L $by_path ]] || fail "GPU has no stable render-node link: $bdf"
    render_node=$(readlink -f "$by_path")
    [[ -c $render_node ]] || fail "GPU render node is not a character device: $bdf"
    profiles=$TMPDIR/vainfo-${bdf//[:.]/_}
    vainfo --display drm --device "$render_node" >"$profiles" 2>&1 \
        || fail "vainfo failed on $bdf ($render_node)"
    va_nodes=$((va_nodes + 1))

    if grep -Eq 'VAProfileH264.*VAEntrypointVLD' "$profiles"; then
        ffmpeg -hide_banner -loglevel error -hwaccel vaapi \
            -hwaccel_device "$render_node" -hwaccel_output_format vaapi \
            -i "$MEDIA/h264.mp4" -f null - \
            || fail "advertised H.264 VA-API decode failed on $bdf"
        va_decodes=$((va_decodes + 1))
    fi
    if grep -Eq 'VAProfileHEVCMain[[:space:]]*:[[:space:]]*VAEntrypointVLD' \
            "$profiles"; then
        ffmpeg -hide_banner -loglevel error -hwaccel vaapi \
            -hwaccel_device "$render_node" -hwaccel_output_format vaapi \
            -i "$MEDIA/hevc.mp4" -f null - \
            || fail "advertised HEVC VA-API decode failed on $bdf"
        va_decodes=$((va_decodes + 1))
    fi
    if grep -Eq 'VAProfileVP9Profile0.*VAEntrypointVLD' "$profiles"; then
        ffmpeg -hide_banner -loglevel error -hwaccel vaapi \
            -hwaccel_device "$render_node" -hwaccel_output_format vaapi \
            -i "$MEDIA/vp9.mkv" -f null - \
            || fail "advertised VP9 VA-API decode failed on $bdf"
        va_decodes=$((va_decodes + 1))
    fi
    if grep -Eq 'VAProfileAV1Profile0.*VAEntrypointVLD' "$profiles"; then
        ffmpeg -hide_banner -loglevel error -hwaccel vaapi \
            -hwaccel_device "$render_node" -hwaccel_output_format vaapi \
            -i "$MEDIA/av1.mkv" -f null - \
            || fail "advertised AV1 VA-API decode failed on $bdf"
        va_decodes=$((va_decodes + 1))
    fi
done <<<"$GPU_LINES"

if [[ $intel_gpu == 1 || $amd_gpu == 1 ]]; then
    [[ $va_nodes -gt 0 ]] || fail "no Intel/AMD VA-API render node was exercised"
    [[ $va_decodes -gt 0 ]] || fail "no advertised VA-API decode profile was exercised"
    note "$va_decodes advertised VA-API decode paths passed across $va_nodes render node(s)"
else
    note "no Intel/AMD VA-API consumer detected; NVIDIA remains the documented sandboxed software path"
fi

echo "PASS  $TEST_NAME [$RUN_ID]: exact dormant opt-in service, private receipts, complete package state, four-codec FFmpeg/GStreamer playback and every advertised Intel/AMD VA-API path verified"

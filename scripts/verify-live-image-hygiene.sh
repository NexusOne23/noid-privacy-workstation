#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Verify the final rootfs.img nested in a published Live ISO candidate.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin

if [ "$#" -ne 2 ]; then
    echo "Usage: sudo $0 ISO REPORT.json" >&2
    exit 2
fi
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: final image extraction requires root for a read-only loop mount" >&2
    exit 2
fi

ISO=$1
REPORT=$2
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
VERIFIER=$SCRIPT_DIR/verify-rootfs-hygiene.py
STAGE=""
LOOP_DEVICE=""
MOUNT_DIR=""

cleanup() {
    local saved_rc=$?
    trap - EXIT HUP INT TERM
    if [ -n "${MOUNT_DIR:-}" ] && mountpoint -q -- "$MOUNT_DIR"; then
        umount -- "$MOUNT_DIR" || saved_rc=1
    fi
    if [ -n "${LOOP_DEVICE:-}" ] && losetup "$LOOP_DEVICE" >/dev/null 2>&1; then
        losetup -d -- "$LOOP_DEVICE" || saved_rc=1
    fi
    if [ -n "${STAGE:-}" ] && [ -d "$STAGE" ]; then
        rm -rf -- "$STAGE" || saved_rc=1
    fi
    exit "$saved_rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$ISO" = /* && "$REPORT" = /* ]] || {
    echo "ERROR: ISO and report paths must be absolute" >&2
    exit 2
}
[ -f "$ISO" ] && [ ! -L "$ISO" ] || {
    echo "ERROR: ISO must be a regular, non-symlink file" >&2
    exit 2
}
[ "$(readlink -e -- "$ISO" 2>/dev/null)" = "$ISO" ] || {
    echo "ERROR: ISO path must be canonical" >&2
    exit 2
}
[ -x "$VERIFIER" ] && [ ! -L "$VERIFIER" ] || {
    echo "ERROR: rootfs hygiene verifier is missing or unsafe" >&2
    exit 2
}
REPORT_PARENT=${REPORT%/*}
[ -d "$REPORT_PARENT" ] && [ ! -L "$REPORT_PARENT" ] || {
    echo "ERROR: report parent must be a real directory" >&2
    exit 2
}
[ "$(readlink -e -- "$REPORT_PARENT" 2>/dev/null)" = "$REPORT_PARENT" ] || {
    echo "ERROR: report parent path must be canonical" >&2
    exit 2
}
[ ! -e "$REPORT" ] && [ ! -L "$REPORT" ] || {
    echo "ERROR: report target already exists" >&2
    exit 2
}
for command_name in xorriso unsquashfs losetup mount umount mountpoint python3; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "ERROR: required command missing: $command_name" >&2
        exit 2
    }
done

STAGE=$(mktemp -d /var/tmp/noid-live-image-hygiene.XXXXXXXX)
chmod 0700 "$STAGE"
xorriso -osirrox on -indev "$ISO" \
    -extract /LiveOS/squashfs.img "$STAGE/squashfs.img" \
    >/dev/null 2>"$STAGE/xorriso.err" || {
    sed -n '1,20p' "$STAGE/xorriso.err" >&2
    echo "ERROR: cannot extract final squashfs.img" >&2
    exit 3
}
[ -s "$STAGE/squashfs.img" ] || {
    echo "ERROR: extracted squashfs.img is empty" >&2
    exit 3
}
if unsquashfs -ll "$STAGE/squashfs.img" \
        | grep -qE '/LiveOS/rootfs\.img$'; then
    install -d -m 0700 "$STAGE/squashfs-root"
    unsquashfs -no-progress -d "$STAGE/squashfs-root" \
        "$STAGE/squashfs.img" LiveOS/rootfs.img \
        >"$STAGE/unsquashfs.out" 2>"$STAGE/unsquashfs.err" || {
        sed -n '1,20p' "$STAGE/unsquashfs.err" >&2
        echo "ERROR: cannot extract final rootfs.img" >&2
        exit 3
    }
    ROOTFS_IMAGE=$STAGE/squashfs-root/LiveOS/rootfs.img
    [ -s "$ROOTFS_IMAGE" ] || {
        echo "ERROR: extracted rootfs.img is empty" >&2
        exit 3
    }
    MOUNT_DIR=$STAGE/root
    install -d -m 0700 "$MOUNT_DIR"
    LOOP_DEVICE=$(losetup --find --show --read-only "$ROOTFS_IMAGE")
    [[ "$LOOP_DEVICE" == /dev/loop* ]] || {
        echo "ERROR: read-only loop setup returned an invalid device" >&2
        exit 3
    }
    mount -t ext4 -o ro,noload "$LOOP_DEVICE" "$MOUNT_DIR"
    mountpoint -q -- "$MOUNT_DIR" || {
        echo "ERROR: final rootfs image is not mounted" >&2
        exit 3
    }
    ROOT_PATH=$MOUNT_DIR
else
    unsquashfs -no-progress -d "$STAGE/root" "$STAGE/squashfs.img" \
        >"$STAGE/unsquashfs.out" 2>"$STAGE/unsquashfs.err" || {
        sed -n '1,20p' "$STAGE/unsquashfs.err" >&2
        echo "ERROR: cannot extract final SquashFS root" >&2
        exit 3
    }
    ROOT_PATH=$STAGE/root
fi
[ -d "$ROOT_PATH" ] && [ ! -L "$ROOT_PATH" ] || {
    echo "ERROR: extracted final root is missing or unsafe" >&2
    exit 3
}

REPORT_CANDIDATE=$STAGE/rootfs-hygiene.json
verify_rc=0
python3 -B -I "$VERIFIER" --root "$ROOT_PATH" \
    --report "$REPORT_CANDIDATE" --expected-uid 0 --expected-gid 0 \
    || verify_rc=$?
[ -f "$REPORT_CANDIDATE" ] && [ ! -L "$REPORT_CANDIDATE" ] || {
    echo "ERROR: rootfs verifier did not publish its report" >&2
    exit 3
}
install -m 0600 "$REPORT_CANDIDATE" "$REPORT"
if [[ ${SUDO_UID:-} =~ ^[0-9]+$ && ${SUDO_GID:-} =~ ^[0-9]+$ ]]; then
    chown "$SUDO_UID:$SUDO_GID" "$REPORT"
fi
sync -- "$REPORT"
sync -- "$REPORT_PARENT"
if [ "$verify_rc" -ne 0 ]; then
    echo "ERROR: final Live ISO image-hygiene gate failed (rc=$verify_rc)" >&2
    exit "$verify_rc"
fi
echo "final Live ISO image-hygiene gate: PASS"

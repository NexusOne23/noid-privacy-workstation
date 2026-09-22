#!/usr/bin/env bash
#
# DEPRECATED — replaced by scripts/build-iso.sh.
#
# This wrapper used to be the canonical build path. It carried two
# release-relevant defects which scripts/build-iso.sh fixes:
#
#   1. HTTP server bound to 0.0.0.0 (all interfaces) — `python3 -m http.server`
#      without `--bind`. On a build host on a LAN, the updates.img staging
#      and any other payloads in the same CWD become reachable to other
#      hosts. scripts/build-iso.sh binds to 127.0.0.1 explicitly.
#
#   2. No build-time bootloader/partition munging for lorax phase 2, no
#      branding/audit-tool SHA-verified HTTP staging, no
#      SOURCE_DATE_EPOCH variance reduction — all of which the new wrapper
#      handles.
#
# Use scripts/build-iso.sh instead. This stub remains so muscle-memory
# invocations get a clear error rather than executing the legacy logic.

export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

cat <<'DEPRECATION_EOF' >&2
ERROR: scripts/anaconda-patch/build-with-patched-anaconda.sh is DEPRECATED.

The canonical build path is now:

    sudo -v
    ./scripts/build-iso.sh

scripts/build-iso.sh handles end-to-end:
  - ksflatten (resolves all kickstart %include chains)
  - Minimal authenticated inst.updates profile/mask payload over loopback HTTP
    (no RPM-transaction override)
  - Build-time bootloader/partition munging for lorax phase 2 live-ISO
  - Branding asset SHA-verified HTTP staging (Module 32)
  - Audit-tool (noid-privacy-linux.sh) SHA pinning + delivery (Module 40)
  - SOURCE_DATE_EPOCH/UTC variance reduction (not a reproducibility claim)
  - Clean trap-based cleanup of HTTP server + temp files

For details: scripts/anaconda-patch/README.md (deprecation note).
DEPRECATION_EOF
exit 1

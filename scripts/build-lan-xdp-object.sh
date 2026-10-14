#!/usr/bin/env bash
# Reproducibly compile and verify the NoID Privacy physical-link BPF payload.
# Run inside an updated Fedora 44 environment with clang, libbpf-devel,
# binutils and bpftool installed.
# Usage: scripts/build-lan-xdp-object.sh [--check]
set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$REPO_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c"
SOURCE_DIR="${SOURCE%/*}"
OBJECT_B64="$REPO_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64"
CONTROLLER="$REPO_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh"
MODE=build
case "$#:${1:-}" in
    0:) ;;
    1:--check) MODE=check ;;
    1:-h|1:--help)
        echo "Usage: scripts/build-lan-xdp-object.sh [--check]"
        exit 0
        ;;
    *)
        echo "Usage: scripts/build-lan-xdp-object.sh [--check]" >&2
        exit 2
        ;;
esac

log() { echo "[build-lan-xdp-object] $*"; }
for command in clang strip base64 sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        log "ERROR: missing build command: $command"
        exit 2
    }
done
if [ ! -r /etc/os-release ] \
   || ! grep -qE '^VERSION_ID="?44"?$' /etc/os-release \
   || ! grep -qE '^(ID|ID_LIKE)=.*fedora' /etc/os-release; then
    log "ERROR: the pinned object must be built on Fedora 44"
    exit 2
fi

tmp=$(mktemp /var/tmp/noid-lan-xdp-object.XXXXXX)
verify_root=''
controller_candidate=''
object_candidate=''
trap '[ -z "$verify_root" ] || rm -rf "$verify_root"; rm -f "$tmp" "$controller_candidate" "$object_candidate"' EXIT
clang -target bpf -O2 -g -Wall -Wextra -Werror \
    -fdebug-prefix-map="$SOURCE_DIR=/usr/src/noid-privacy-fedora" \
    -c "$SOURCE" -o "$tmp"
# Remove host/toolchain DWARF while retaining BTF/BTF.ext required for typed
# maps and verifier diagnostics. GNU binutils strip on Fedora supports eBPF.
strip --strip-debug "$tmp"
hash=$(sha256sum "$tmp" | awk '{print $1}')

if [ "$(id -u)" -eq 0 ] && command -v bpftool >/dev/null 2>&1 \
   && mountpoint -q /sys/fs/bpf; then
    verify_root="/sys/fs/bpf/noid_lan_xdp_verify_${$}"
    mkdir -p "$verify_root/progs" "$verify_root/maps"
    bpftool prog loadall "$tmp" "$verify_root/progs" pinmaps "$verify_root/maps"
    rm -rf "$verify_root"
    verify_root=''
    log "kernel verifier accepted both programs"
else
    log "NOTICE: kernel verifier skipped (requires root, bpftool and bpffs)"
fi

current_hash=$(base64 -d "$OBJECT_B64" | sha256sum | awk '{print $1}')
mapfile -t controller_hashes < <(
    sed -n 's/^OBJECT_SHA256=\([0-9a-f]\{64\}\)$/\1/p' "$CONTROLLER"
)
[ "${#controller_hashes[@]}" -eq 1 ] || {
    log "ERROR: controller has no unique object hash"
    exit 3
}
controller_hash=${controller_hashes[0]}
if [ "$MODE" = check ]; then
    [ "$controller_hash" = "$current_hash" ] || {
        log "DRIFT: controller hash and repository object disagree"
        exit 1
    }
    [ "$hash" = "$current_hash" ] || {
        log "DRIFT: rebuilt $hash, repository pins $current_hash"
        exit 1
    }
    log "REPRODUCIBLE: rebuilt object matches $hash"
    exit 0
fi
if [ "$controller_hash" != "$current_hash" ]; then
    log "NOTICE: repairing an interrupted object/controller publication"
fi

object_candidate=$(mktemp "${OBJECT_B64}.tmp.XXXXXX")
chmod --reference="$OBJECT_B64" "$object_candidate"
base64 -w76 "$tmp" > "$object_candidate"
[ "$(base64 -d "$object_candidate" | sha256sum | awk '{print $1}')" = "$hash" ] \
    || { log "ERROR: staged base64 object digest mismatch"; exit 4; }

controller_candidate=$(mktemp "${CONTROLLER}.tmp.XXXXXX")
chmod --reference="$CONTROLLER" "$controller_candidate"
sed "s/^OBJECT_SHA256=${controller_hash}$/OBJECT_SHA256=${hash}/" \
    "$CONTROLLER" > "$controller_candidate"
[ "$(grep -Fxc "OBJECT_SHA256=$hash" "$controller_candidate" || true)" -eq 1 ] \
    || { log "ERROR: staged controller has no unique updated digest"; exit 4; }
bash -n "$controller_candidate" \
    || { log "ERROR: staged controller is invalid Bash"; exit 4; }

mv -T "$object_candidate" "$OBJECT_B64"
object_candidate=''
mv -T "$controller_candidate" "$CONTROLLER"
controller_candidate=''
"$REPO_ROOT/scripts/regen-lan-xdp-embed.sh"
log "updated object, controller hash and M03 embed: $hash"

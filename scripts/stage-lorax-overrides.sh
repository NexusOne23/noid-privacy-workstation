#!/usr/bin/env bash
# Stage private, exact-version Lorax Python overrides for canonical ISO builds.
set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

EXPECTED_NEVRA='lorax-44.6-1.fc44.x86_64'
EXPECTED_MONITOR_SHA256='47931372d5fb992a62abc05d83db2b2b362cd53ca7498518fa1d2f28cbaef91c'
EXPECTED_CREATOR_SHA256='c91902f78a5fb79cb3b44a812f155df44f45138098086c62f0aaa94fbac88cdb'
EXPECTED_EXECUTILS_SHA256='0ecf52f4c18797e76b8ef9b44490fdafaf301805c10fb290ddbda81258372be6'
SOURCE_ROOT='/usr/lib/python3.14/site-packages'
SOURCE_MONITOR="$SOURCE_ROOT/pylorax/monitor.py"
SOURCE_CREATOR="$SOURCE_ROOT/pylorax/creator.py"
SOURCE_EXECUTILS="$SOURCE_ROOT/pylorax/executils.py"
NOID_RPM=(
    rpm
    --rcfile=/usr/lib/rpm/rpmrc
    '--macros=/usr/lib/rpm/macros:/usr/lib/rpm/macros.d/macros.*:/usr/lib/rpm/platform/%{_target}/macros:/usr/lib/rpm/fileattrs/*.attr:/usr/lib/rpm/redhat/macros:/etc/rpm/macros.*:/etc/rpm/macros:/etc/rpm/%{_target}/macros'
)

if [ "$#" -ne 1 ]; then
    echo "usage: $0 EMPTY-DESTINATION-DIRECTORY" >&2
    exit 2
fi
DESTINATION=$1
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MONITOR_PATCH="$REPO_ROOT/overrides/lorax/0001-drain-monitor-before-shutdown.patch"
CREATOR_PATCH="$REPO_ROOT/overrides/lorax/0002-precompute-live-required-space.patch"
EXECUTILS_PATCH="$REPO_ROOT/overrides/lorax/0003-terminate-cancelled-process.patch"
MONITOR_VERIFIER="$REPO_ROOT/scripts/verify-lorax-monitor-drain.py"
CREATOR_VERIFIER="$REPO_ROOT/scripts/verify-lorax-live-required-space.py"
EXECUTILS_VERIFIER="$REPO_ROOT/scripts/verify-lorax-cancel-cleanup.py"

[[ "$DESTINATION" = /* ]] || {
    echo 'ERROR: Lorax override destination must be absolute' >&2
    exit 2
}
[ -d "$DESTINATION" ] && [ ! -L "$DESTINATION" ] || {
    echo 'ERROR: Lorax override destination must be a real directory' >&2
    exit 2
}
[ -z "$(find "$DESTINATION" -mindepth 1 -maxdepth 1 -print -quit)" ] || {
    echo 'ERROR: Lorax override destination must be empty' >&2
    exit 2
}
for input in \
    "$MONITOR_PATCH" \
    "$CREATOR_PATCH" \
    "$EXECUTILS_PATCH" \
    "$MONITOR_VERIFIER" \
    "$CREATOR_VERIFIER" \
    "$EXECUTILS_VERIFIER"
do
    [ -f "$input" ] && [ ! -L "$input" ] || {
        echo "ERROR: Lorax override input is missing or symlinked: $input" >&2
        exit 2
    }
done
[ -x "$MONITOR_VERIFIER" ] && [ -x "$CREATOR_VERIFIER" ] \
    && [ -x "$EXECUTILS_VERIFIER" ] || {
    echo 'ERROR: Lorax override inputs are missing, symlinked or non-executable' >&2
    exit 2
}

installed_nevra=$("${NOID_RPM[@]}" -q \
    --qf '%|EPOCH?{%{EPOCH}:}|%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' lorax)
[ "$installed_nevra" = "$EXPECTED_NEVRA" ] || {
    echo "ERROR: unsupported Lorax package: $installed_nevra" >&2
    exit 3
}
[ -f "$SOURCE_MONITOR" ] && [ ! -L "$SOURCE_MONITOR" ] || {
    echo 'ERROR: pinned Lorax monitor source is missing or symlinked' >&2
    exit 3
}
[ -f "$SOURCE_CREATOR" ] && [ ! -L "$SOURCE_CREATOR" ] || {
    echo 'ERROR: pinned Lorax creator source is missing or symlinked' >&2
    exit 3
}
[ -f "$SOURCE_EXECUTILS" ] && [ ! -L "$SOURCE_EXECUTILS" ] || {
    echo 'ERROR: pinned Lorax executils source is missing or symlinked' >&2
    exit 3
}
# The complete pylorax package is placed ahead of the vendor installation in
# root's PYTHONPATH. Bind that entire shadow tree to Fedora's installed RPM,
# not merely the three files patched below. --noscript keeps verification
# read-only, and the exact inventory rejects unowned modules or bytecode that
# rpm --verify deliberately does not report.
if ! "${NOID_RPM[@]}" --verify --nodeps --noscript lorax; then
    echo 'ERROR: installed Lorax package failed RPM file verification' >&2
    exit 3
fi
if ! diff -u \
        <("${NOID_RPM[@]}" -ql lorax \
            | awk -v root="$SOURCE_ROOT/pylorax" \
                '$0 == root || index($0, root "/") == 1' \
            | sort) \
        <(find "$SOURCE_ROOT/pylorax" -xdev -print | sort); then
    echo 'ERROR: installed pylorax tree differs from the RPM-owned inventory' >&2
    exit 3
fi
monitor_source_sha256=$(sha256sum "$SOURCE_MONITOR" | awk '{print $1}')
creator_source_sha256=$(sha256sum "$SOURCE_CREATOR" | awk '{print $1}')
executils_source_sha256=$(sha256sum "$SOURCE_EXECUTILS" | awk '{print $1}')
[ "$monitor_source_sha256" = "$EXPECTED_MONITOR_SHA256" ] || {
    echo "ERROR: Lorax monitor source hash drifted: $monitor_source_sha256" >&2
    exit 3
}
[ "$creator_source_sha256" = "$EXPECTED_CREATOR_SHA256" ] || {
    echo "ERROR: Lorax creator source hash drifted: $creator_source_sha256" >&2
    exit 3
}
[ "$executils_source_sha256" = "$EXPECTED_EXECUTILS_SHA256" ] || {
    echo "ERROR: Lorax executils source hash drifted: $executils_source_sha256" >&2
    exit 3
}

cp -a -- "$SOURCE_ROOT/pylorax" "$DESTINATION/pylorax"
patch --batch --fuzz=0 -d "$DESTINATION" -p1 < "$MONITOR_PATCH"
patch --batch --fuzz=0 -d "$DESTINATION" -p1 < "$CREATOR_PATCH"
patch --batch --fuzz=0 -d "$DESTINATION" -p1 < "$EXECUTILS_PATCH"
python3 -B -I "$MONITOR_VERIFIER" "$DESTINATION/pylorax/monitor.py"
python3 -B -I "$CREATOR_VERIFIER" "$DESTINATION/pylorax/creator.py"
python3 -B -I "$EXECUTILS_VERIFIER" "$DESTINATION/pylorax/executils.py"

monitor_patched_sha256=$(sha256sum "$DESTINATION/pylorax/monitor.py" | awk '{print $1}')
creator_patched_sha256=$(sha256sum "$DESTINATION/pylorax/creator.py" | awk '{print $1}')
executils_patched_sha256=$(sha256sum "$DESTINATION/pylorax/executils.py" | awk '{print $1}')
monitor_patch_sha256=$(sha256sum "$MONITOR_PATCH" | awk '{print $1}')
creator_patch_sha256=$(sha256sum "$CREATOR_PATCH" | awk '{print $1}')
executils_patch_sha256=$(sha256sum "$EXECUTILS_PATCH" | awk '{print $1}')
cat > "$DESTINATION/NOID-LORAX-OVERRIDE-EVIDENCE" <<EOF
NOID_LORAX_OVERRIDES_V4
source_nevra=$installed_nevra
source_package_verify=pass
source_package_inventory=pass
source_monitor_sha256=$monitor_source_sha256
monitor_patch_sha256=$monitor_patch_sha256
patched_monitor_sha256=$monitor_patched_sha256
monitor_semantic_fixture=pass
source_creator_sha256=$creator_source_sha256
creator_patch_sha256=$creator_patch_sha256
patched_creator_sha256=$creator_patched_sha256
live_required_space_semantic_fixture=pass
source_executils_sha256=$executils_source_sha256
executils_patch_sha256=$executils_patch_sha256
patched_executils_sha256=$executils_patched_sha256
cancelled_process_cleanup_semantic_fixture=pass
EOF
chmod 0600 "$DESTINATION/NOID-LORAX-OVERRIDE-EVIDENCE"

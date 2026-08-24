#!/usr/bin/env bash
# Stage the exact Fedora Lorax templates with NoID Privacy's reviewed Live-menu
# default. The vendor installation is never modified.
set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

EXPECTED_NEVRA='lorax-templates-generic-44.6-1.fc44.x86_64'
EXPECTED_EFI_SHA256='9acb83e8ad908769cf185de744ce8301ea91f4c2704bb511f72dc7ec307fec4e'
EXPECTED_BIOS_SHA256='e8cf76567ebdb2c22b728b9958b02af6c7958288852966e881c3c5e9178ec776'
SOURCE_ROOT=/usr/share/lorax/templates.d/99-generic
EFI_REL=live/config_files/x86/grub2-efi.cfg
BIOS_REL=live/config_files/x86/grub2-bios.cfg
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
PATCH_FILE="$REPO_ROOT/overrides/lorax/0004-live-menu-default.patch"

[[ "$DESTINATION" = /* ]] \
    && [ -d "$DESTINATION" ] && [ ! -L "$DESTINATION" ] || {
    echo 'ERROR: Lorax template destination must be an absolute real directory' >&2
    exit 2
}
[ -z "$(find "$DESTINATION" -mindepth 1 -maxdepth 1 -print -quit)" ] || {
    echo 'ERROR: Lorax template destination must be empty' >&2
    exit 2
}
[ -f "$PATCH_FILE" ] && [ ! -L "$PATCH_FILE" ] || {
    echo 'ERROR: Lorax Live-menu patch is missing or symlinked' >&2
    exit 2
}

installed_nevra=$("${NOID_RPM[@]}" -q \
    --qf '%|EPOCH?{%{EPOCH}:}|%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' \
    lorax-templates-generic)
[ "$installed_nevra" = "$EXPECTED_NEVRA" ] || {
    echo "ERROR: unsupported Lorax template package: $installed_nevra" >&2
    exit 3
}
if ! "${NOID_RPM[@]}" --verify --nodeps --noscript lorax-templates-generic; then
    echo 'ERROR: installed Lorax template package failed RPM verification' >&2
    exit 3
fi
if ! diff -u \
        <("${NOID_RPM[@]}" -ql lorax-templates-generic \
            | awk -v root="$SOURCE_ROOT" \
                '$0 == root || index($0, root "/") == 1' \
            | sort) \
        <(find "$SOURCE_ROOT" -xdev -print | sort); then
    echo 'ERROR: installed Lorax template tree differs from RPM inventory' >&2
    exit 3
fi

efi_sha256=$(sha256sum "$SOURCE_ROOT/$EFI_REL" | awk '{print $1}')
bios_sha256=$(sha256sum "$SOURCE_ROOT/$BIOS_REL" | awk '{print $1}')
[ "$efi_sha256" = "$EXPECTED_EFI_SHA256" ] || {
    echo "ERROR: Lorax EFI Live-menu source hash drifted: $efi_sha256" >&2
    exit 3
}
[ "$bios_sha256" = "$EXPECTED_BIOS_SHA256" ] || {
    echo "ERROR: Lorax BIOS Live-menu source hash drifted: $bios_sha256" >&2
    exit 3
}

cp -a -- "$SOURCE_ROOT/." "$DESTINATION/"
chmod 0700 "$DESTINATION"
[ "$(stat -Lc '%a' "$DESTINATION")" = 700 ] || {
    echo 'ERROR: staged Lorax template root is not private' >&2
    exit 3
}
patch --batch --fuzz=0 -d "$DESTINATION" -p1 < "$PATCH_FILE"
for config in "$DESTINATION/$EFI_REL" "$DESTINATION/$BIOS_REL"; do
    [ "$(grep -cFx 'set default="0"' "$config")" -eq 1 ] \
        && [ "$(grep -cFx 'set timeout=3' "$config")" -eq 1 ] \
        && [ "$(grep -cF 'rd.live.check' "$config")" -eq 1 ] \
        && [ "$(grep -cE '^[[:space:]]*linux ' "$config")" -eq 3 ] || {
        echo "ERROR: staged Lorax Live-menu contract differs: $config" >&2
        exit 3
    }
done

patch_sha256=$(sha256sum "$PATCH_FILE" | awk '{print $1}')
cat > "$DESTINATION/NOID-LORAX-TEMPLATE-EVIDENCE" <<EOF
NOID_LORAX_TEMPLATES_V1
source_nevra=$installed_nevra
source_package_verify=pass
source_package_inventory=pass
source_efi_sha256=$efi_sha256
source_bios_sha256=$bios_sha256
menu_patch_sha256=$patch_sha256
normal_default=0
menu_timeout_seconds=3
media_check_entry=preserved
EOF
chmod 0600 "$DESTINATION/NOID-LORAX-TEMPLATE-EVIDENCE"

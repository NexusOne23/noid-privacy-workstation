#!/bin/bash
# 15b-amd-psp-doc-structural — M15 AMD-side regression test
#
# Covers: 15-amd-psp-hardware-layer.md content invariants —
# OS-driver, firmware, manageability, IOMMU and physical-access boundaries,
# AMD-SB-4011 guidance, ccp default policy and the PSB warning.
# Would catch: boundary statements or bulletin guidance dropped, or a ccp
# blacklist described as the default.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/15-intel-me-mitigation.ks"
AMD_DOC=""

test_start "15b-amd-psp-doc-structural"

assert_file_exists "$KS_FILE"
TMPDIR="$(mktemp -d "${TMPDIR:-/var/tmp}/noid-amd-doc.XXXXXX")"
trap 'rm -rf "$TMPDIR"' EXIT
AMD_DOC="$TMPDIR/15-amd-psp-hardware-layer.md"
extract_heredoc "$KS_FILE" AMD_DOC_EOF "$AMD_DOC" \
    || _fail "AMD hardware-layer document extraction"
assert_file_min_size "$AMD_DOC" 5000 \
    "AMD hardware-layer document remains substantial"

# AMD doc heredoc marker + target path
assert_grep_fixed "<<'AMD_DOC_EOF'" "$KS_FILE"
assert_grep_fixed '/usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md' "$KS_FILE"

# The rewritten document deliberately avoids a fabricated layer count and
# hardware-universal claims. It must keep OS-driver, firmware, manageability,
# IOMMU and physical-access boundaries separate.
assert_grep_fixed 'This image therefore makes two deliberately separate claims:' "$AMD_DOC"
assert_grep_fixed 'Default: the driver stays active.' "$AMD_DOC"
assert_grep_fixed 'Disabling it would not stop ASP firmware.' "$AMD_DOC"
assert_grep_fixed 'firmware TPM is not universally controlled' "$AMD_DOC"
# Fedora 44 builds the CCP/PSP driver into the kernel: a modprobe.d blacklist
# cannot apply, so the document must not offer one as a working switch.
assert_grep_fixed '`CONFIG_CRYPTO_DEV_CCP_DD=y`' "$AMD_DOC"
assert_grep_fixed '`blacklist ccp` in `/etc/modprobe.d` has no effect' "$AMD_DOC"
assert_not_grep 'Blacklisting `ccp` can' "$AMD_DOC" \
    "AMD document does not present a no-op blacklist as a working switch"

# OOB manageability is platform/OEM specific and a separate NIC is not a
# blanket mitigation.
assert_grep_fixed 'AMD PRO manageability / AIM-T / DASH' "$AMD_DOC"
assert_grep_fixed 'host firewall cannot enforce their network path' "$AMD_DOC"
assert_grep_fixed 'A separate card alone is not a guarantee.' "$AMD_DOC"
assert_grep_fixed 'inspect the exact SKU' "$AMD_DOC"

# PSB is an irreversible OEM firmware boundary and is never auto-enrolled.
assert_grep_fixed 'AMD Platform Secure Boot (PSB)' "$AMD_DOC"
assert_grep_extended 'one-time-programmable|processor fuses' "$AMD_DOC"
assert_grep_fixed 'difficult or impossible to' "$AMD_DOC"
assert_grep_fixed 'reverse once fused' "$AMD_DOC"
assert_grep_fixed 'NoID Privacy does not enroll PSB.' "$AMD_DOC"

# IOMMU and HSI wording must remain bounded rather than absolute.
assert_grep_fixed 'It is not proof that ASP or' "$AMD_DOC"
assert_grep_fixed 'overall HSI level is a summary' "$AMD_DOC"
assert_grep_fixed 'missing data is inconclusive' "$AMD_DOC"

# Current AMD bulletin treatment: family-specific firmware table, explicitly no
# one-size-fits-all AGESA claim.
assert_grep_fixed 'CVE-2025-2884 / AMD-SB-4011' "$AMD_DOC"
assert_grep_fixed 'There is no single' "$AMD_DOC"
assert_grep_fixed 'product table' "$AMD_DOC"
assert_grep_fixed 'faulTPM' "$AMD_DOC"

assert_grep_fixed 'AMD Secure Processor (ASP, formerly Platform Security Processor or PSP)' \
    "$AMD_DOC"
assert_grep_fixed 'chmod 644 /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md' "$KS_FILE"
assert_grep_fixed 'chown root:root /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md' "$KS_FILE"
test_finish

#!/bin/bash
# 00-compose-sources — installation payload source correctness
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/master.ks"
FRESHNESS_TEST="$PROJECT_ROOT/tests/pre-ship/29-installed-package-freshness.sh"
PERMISSION_TEST="$PROJECT_ROOT/tests/pre-ship/10-permission-policy-runtime.sh"
CHRONY_TEST="$PROJECT_ROOT/tests/pre-ship/11-chrony-runtime.sh"
BUILD_SCRIPT="$PROJECT_ROOT/scripts/build-iso.sh"
BUILD_HOST_LOCK_LIB="$PROJECT_ROOT/scripts/lib/build-host-lock.sh"
PARTITION_COLLAPSE_AWK="$PROJECT_ROOT/scripts/collapse-live-partition-layout.awk"
CANDIDATE_TRANSACTION_LIB="$PROJECT_ROOT/scripts/lib/candidate-transaction.sh"
LOCALE_CONTRACT="$PROJECT_ROOT/tests/00-locale-contract.py"
SANDBOX_CONTRACT="$PROJECT_ROOT/tests/00-sandbox-path-contract.py"
ERRTRACE_CONTRACT="$PROJECT_ROOT/tests/00-errtrace-contract.py"
DEGRADATION_CONTRACT="$PROJECT_ROOT/tests/00-degradation-contract.py"
GATE_LITERAL_CONTRACT="$PROJECT_ROOT/tests/00-gate-literal-contract.py"
LOG_AUDITOR="$PROJECT_ROOT/scripts/audit-compose-log.py"
LOG_POLICY="$PROJECT_ROOT/manifests/compose-log-policy-v1.json"
PIN_INVENTORY="$PROJECT_ROOT/docs/pin-inventory.md"
LMC_SUCCESS_AUDITOR="$PROJECT_ROOT/scripts/verify-livemedia-success.py"
LORAX_STAGE="$PROJECT_ROOT/scripts/stage-lorax-overrides.sh"
LORAX_TEMPLATE_STAGE="$PROJECT_ROOT/scripts/stage-lorax-templates.sh"
LORAX_MONITOR_VERIFY="$PROJECT_ROOT/scripts/verify-lorax-monitor-drain.py"
LORAX_SIZE_VERIFY="$PROJECT_ROOT/scripts/verify-lorax-live-required-space.py"
LORAX_CANCEL_VERIFY="$PROJECT_ROOT/scripts/verify-lorax-cancel-cleanup.py"
LORAX_MONITOR_PATCH="$PROJECT_ROOT/overrides/lorax/0001-drain-monitor-before-shutdown.patch"
LORAX_SIZE_PATCH="$PROJECT_ROOT/overrides/lorax/0002-precompute-live-required-space.patch"
LORAX_CANCEL_PATCH="$PROJECT_ROOT/overrides/lorax/0003-terminate-cancelled-process.patch"
LORAX_MENU_PATCH="$PROJECT_ROOT/overrides/lorax/0004-live-menu-default.patch"
ENFORCING_AVC_GATE="$PROJECT_ROOT/tests/pre-ship/31-installed-enforcing-avc.sh"
SMOKE_ROOTFS_PREP="$PROJECT_ROOT/tests/smoke/prep-rootfs.sh"
SMOKE_LIB="$PROJECT_ROOT/tests/smoke/lib.sh"
SMOKE_README="$PROJECT_ROOT/tests/smoke/README.md"
GITIGNORE="$PROJECT_ROOT/.gitignore"
README_FILE="$PROJECT_ROOT/README.md"
BUILD_DOC="$PROJECT_ROOT/docs/build.md"
RELEASE_DOC="$PROJECT_ROOT/docs/release-process.md"

test_start "00-compose-sources"

for release_surface in "$BUILD_DOC" "$RELEASE_DOC"; do
    assert_grep_fixed 'livemedia-creator -V' "$release_surface" \
        "$(basename "$release_surface") uses Lorax's supported version flag"
    assert_not_grep 'livemedia-creator --version' "$release_surface" \
        "$(basename "$release_surface") has no unsupported long version flag"
done
assert_grep_fixed 'rpm -q pykickstart' "$BUILD_DOC" \
    "build guide queries the installed pykickstart package version"
assert_not_grep 'ksflatten --version' "$BUILD_DOC" \
    "build guide does not misread ksflatten's Kickstart-format option as a version query"
assert_grep_fixed 'patch python3 unsquashfs umount xorriso; do' \
    "$BUILD_SCRIPT" "canonical builder preflights patch and final-image inspection dependencies"
assert_grep_fixed \
    'sudo dnf install lorax-lmc-virt lorax-lmc-novirt anaconda pykickstart genisoimage patch' \
    "$BUILD_SCRIPT" "missing-tool guidance includes the Lorax patch dependency"
assert_grep_extended '^[[:space:]]+patch$' "$BUILD_DOC" \
    "build guide installs the Lorax patch dependency"
assert_grep_fixed 'warns above 50 MiB and blocks regular Git-repository files above' \
    "$GITIGNORE" "repository-size note uses GitHub's current warning/block boundary"
assert_grep_fixed 'Release assets are a separate surface and must each be under 2 GiB' \
    "$GITIGNORE" "repository and release-asset limits remain distinct"
for release_surface in "$README_FILE" "$BUILD_DOC" "$RELEASE_DOC"; do
    assert_grep_fixed 'release asset to be under 2 GiB' "$release_surface" \
        "$(basename "$release_surface") uses GitHub's exact per-asset boundary"
    assert_not_grep_extended '2 GB (asset|per-asset)|soft-limit per file|hard-limit = 2 GB' \
        "$release_surface" \
        "$(basename "$release_surface") has no stale decimal or conflated limit"
done
assert_not_grep_extended 'soft-limit per file|hard-limit = 2 GB' "$GITIGNORE" \
    ".gitignore does not conflate regular Git and release-asset limits"

assert_grep_fixed 'url --metalink="https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64&protocol=https"' \
    "$KS_FILE" "Fedora base compose source is declared as Metalink over HTTPS mirrors"
assert_grep_fixed 'repo --name=fedora-updates --metalink="https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64&protocol=https"' \
    "$KS_FILE" "Fedora updates compose source is declared as Metalink over HTTPS mirrors"
assert_not_grep '--mirrorlist="https://mirrors.fedoraproject.org/metalink' \
    "$KS_FILE" "Metalink XML is never mislabeled as a plain mirrorlist"
assert_not_grep 'repo.protonvpn.com' "$KS_FILE" \
    "provider-neutral master imports and documents no ProtonVPN trust-root egress"
assert_grep_fixed './scripts/build-iso.sh' "$KS_FILE" \
    "master directs release builds through the canonical safety wrapper"
assert_not_grep 'sudo livemedia-creator' "$KS_FILE" \
    "master does not advertise the unsupported bare compose path"
assert_grep_extended '^@\^workstation-product-environment$' "$KS_FILE" \
    "Workstation is selected with canonical Kickstart environment syntax"
assert_not_grep_extended '^@workstation-product-environment$' "$KS_FILE" \
    "Workstation is not misparsed as an ordinary package group"
assert_grep_extended '^-glibc-all-langpacks$' "$KS_FILE" \
    "Workstation's complete locale catalog is excluded before the reviewed set"
assert_grep_extended '^user --name=liveuser --groups=wheel --lock$' "$KS_FILE" \
    "the compose account begins explicitly locked before M17's live-mode unlock"
assert_grep_extended '^services --enabled=NetworkManager,livesys,livesys-late$' \
    "$KS_FILE" "master enables only real Fedora 44 system services"
assert_not_grep_extended '^services .*firstboot' "$KS_FILE" \
    "the distinct firstboot command is not treated as a system service"
assert_grep_fixed 'AIDE trust remains user-owned/uninitialized' "$KS_FILE" \
    "master describes the compose-time AIDE trust boundary"
assert_not_grep 'bootloader files needed for aide baseline' "$KS_FILE" \
    "master has no stale compose-created AIDE baseline dependency"
assert_grep_extended '^cryptsetup$' "$KS_FILE" \
    "master explicitly retains M22's user-facing LUKS recovery CLI"
assert_grep_fixed 'The boot path can use systemd-cryptsetup instead' "$KS_FILE" \
    "cryptsetup package rationale distinguishes boot from the user workflow"
assert_grep_fixed "rpm -ql gnome-shell | grep -c '^/usr/share/locale/.*\\.mo$'" \
    "$KS_FILE" "locale-filter verification uses a retained core package"
assert_grep_fixed "find /usr/share/locale -path '*/LC_MESSAGES/gnome-shell.mo'" \
    "$KS_FILE" "locale-filter verification measures installed translation bytes"
assert_not_grep 'find /usr/share/locale -name "anaconda.mo"' "$KS_FILE" \
    "locale-filter verification does not depend on firstboot-removed Anaconda"
module40_line=$(grep -nF '%include snippets/40-audit-bundle.ks' "$KS_FILE" \
    | cut -d: -f1)
module37_line=$(grep -nF '%include snippets/37-noid-tools-app.ks' "$KS_FILE" \
    | cut -d: -f1)
module41_line=$(grep -nF '%include snippets/41-anaconda-cleanup.ks' "$KS_FILE" \
    | cut -d: -f1)
if [ -n "$module40_line" ] && [ -n "$module37_line" ] \
   && [ -n "$module41_line" ] && [ "$module40_line" -lt "$module37_line" ] \
   && [ "$module37_line" -lt "$module41_line" ]; then
    _pass "Tools runs after its audit-helper producer and before firstboot cleanup"
else
    _fail "M37 include ordering no longer satisfies the curated-helper dependency"
fi
assert_grep_fixed '37 must run AFTER 40' "$KS_FILE" \
    "master records the build-critical M40-to-M37 ordering constraint"
assert_grep_fixed 'removed in the Fedora 35 command set' "$KS_FILE" \
    "master records the correct auth/authconfig removal boundary"
assert_not_grep 'pykickstart 3.66 (F43+)' "$KS_FILE" \
    "master has no stale auth-removal version claim"
assert_grep_fixed 'VOLID="NOID_PRIVACY_F44"' "$BUILD_SCRIPT" \
    "canonical ISO label uses ECMA-119 d-characters"
assert_not_grep 'VOLID="noid-privacy-f44"' "$BUILD_SCRIPT" \
    "warning-producing lowercase/hyphen volume label is absent"
assert_grep_fixed "[[ \"\$VOLID\" =~ ^[A-Z0-9_]{1,32}\$ ]]" "$BUILD_SCRIPT" \
    "build fails early on a non-compliant ECMA-119 volume ID"
assert_grep_fixed 'BUG_URL="https://github.com/NexusOne23/noid-privacy-workstation/issues"' \
    "$BUILD_SCRIPT" "compose metadata uses the deliberate NoID Privacy support boundary"
assert_grep_fixed "--release \"\$PRODUCT_RELEASE\"" "$BUILD_SCRIPT" \
    "Lorax receives the source-derived NoID Privacy product release"
assert_grep_fixed "--bugurl \"\$BUG_URL\"" "$BUILD_SCRIPT" \
    "Lorax receives the canonical NoID Privacy bug-report URL"
assert_grep_fixed "--logfile \"\$LMC_LOG\"" "$BUILD_SCRIPT" \
    "compose metadata is checked against the candidate-specific Lorax log"
assert_grep_fixed "release='\${PRODUCT_RELEASE}'" "$BUILD_SCRIPT" \
    "post-compose gate confirms parsed release metadata"
assert_grep_fixed "bugurl='\${BUG_URL}'" "$BUILD_SCRIPT" \
    "post-compose gate confirms parsed bug-report metadata"
assert_grep_fixed "volid='\${VOLID}'" "$BUILD_SCRIPT" \
    "post-compose gate confirms parsed volume metadata"
assert_file_executable "$LMC_SUCCESS_AUDITOR" \
    "host-side livemedia success auditor is executable"
assert_grep_fixed 'verify-livemedia-success.py' "$BUILD_SCRIPT" \
    "post-compose gate invokes the host-side success auditor"
assert_grep_fixed '--mode "$LMC_SUCCESS_MODE"' "$BUILD_SCRIPT" \
    "host-side success auditor receives the explicit compose mode"
assert_grep_fixed '--log "$LMC_LOG" --report "$LMC_SUCCESS_REPORT"' \
    "$BUILD_SCRIPT" "host-side success report binds the exact livemedia log"
assert_grep_fixed 'livemedia success evidence is incomplete or invalid' \
    "$BUILD_SCRIPT" "missing, duplicate, reordered or drifted host success is fatal"
assert_grep_fixed 'livemedia-success-audit.json' "$BUILD_SCRIPT" \
    "host-side success report is retained in failure and candidate evidence"
assert_grep_fixed 'your distribution provided bug reporting tool' "$BUILD_SCRIPT" \
    "post-compose gate rejects Lorax's generic bug-report placeholder"
assert_grep_fixed '-volid text does not comply to ISO 9660 / ECMA 119 rules' \
    "$BUILD_SCRIPT" "post-compose gate rejects xorriso's volume-ID warning"
assert_file_executable "$LOG_AUDITOR" \
    "canonical KVM installer-log classifier is executable"
assert_file_exists "$LOG_POLICY" "versioned compose-log policy exists"
assert_grep_fixed 'audit-compose-log.py' "$BUILD_SCRIPT" \
    "build invokes the fail-closed installer-log classifier"
assert_grep_fixed 'private-build-evidence' "$BUILD_SCRIPT" \
    "classified full logs are retained as private candidate evidence"
assert_file_executable "$LORAX_STAGE" \
    "exact-version private Lorax compose override stager is executable"
assert_file_executable "$LORAX_MONITOR_VERIFY" \
    "Lorax shutdown-drain semantic fixture is executable"
assert_file_executable "$LORAX_SIZE_VERIFY" \
    "Lorax Live required-space semantic fixture is executable"
assert_file_executable "$LORAX_CANCEL_VERIFY" \
    "Lorax cancelled-process cleanup semantic fixture is executable"
assert_file_exists "$LORAX_MONITOR_PATCH" "Lorax shutdown-drain patch exists"
assert_file_exists "$LORAX_SIZE_PATCH" "Lorax Live required-space patch exists"
assert_file_exists "$LORAX_CANCEL_PATCH" "Lorax cancelled-process cleanup patch exists"
assert_grep_fixed '| Lorax compose overrides |' "$PIN_INVENTORY" \
    "pin inventory includes every exact-version Lorax override"
assert_grep_fixed '| Anaconda Live required-space overlay |' "$PIN_INVENTORY" \
    "pin inventory includes the exact Anaconda Live payload boundary"
assert_grep_fixed '| Fedora Firefox launcher payload |' "$PIN_INVENTORY" \
    "pin inventory includes the exact Fedora Firefox launcher boundary"
assert_grep_fixed '| Fedora Thunderbird launcher payload |' "$PIN_INVENTORY" \
    "pin inventory includes the exact Fedora Thunderbird launcher boundary"
assert_grep_fixed '| TuneD PPD profile map |' "$PIN_INVENTORY" \
    "pin inventory includes the package-owned TuneD mapping boundary"
assert_grep_fixed '| Optional local-AI evaluation artifacts ' "$PIN_INVENTORY" \
    "pin inventory includes documentation-only local-AI review pins"
assert_grep_fixed '| actions/checkout | github.com/actions/checkout releases |' \
    "$PIN_INVENTORY" "pin inventory includes the commit-pinned CI action"
assert_grep_fixed '`scripts/build-audit-support-media.sh`; parity-gated by `tests/40`' \
    "$PIN_INVENTORY" "pin inventory includes every M40 pin carrier"
assert_grep_fixed \
    '`scripts/verify-fedora-base-iso.sh`, `scripts/build-audit-support-media.sh`, `scripts/archive-build.sh`' \
    "$PIN_INVENTORY" "pin inventory names the actual script-owned GPG anchors"
assert_grep_fixed "update both staging helpers' closed constants" "$PIN_INVENTORY" \
    "Lorax re-pin coordinates both NEVRAs and all five source hashes"
assert_grep_fixed 'update the closed base hash in Lorax patch 0002' \
    "$PIN_INVENTORY" \
    "Anaconda Live re-pin coordinates M17, its generator and Lorax"
assert_grep_fixed 'reconciling every semantic mapping with' "$PIN_INVENTORY" \
    "TuneD payload re-pin requires complete semantic reconciliation"
assert_grep_fixed 'reviewing the complete old/new script' "$PIN_INVENTORY" \
    "Fedora browser launcher re-pins require complete source review"
assert_grep_fixed 'patches with zero fuzz' "$PIN_INVENTORY" \
    "Lorax re-pin retains every zero-fuzz review boundary"
assert_grep_fixed 'self.request.settimeout(5.0)' "$LORAX_MONITOR_PATCH" \
    "Lorax shutdown drain retains a bounded five-second delayed-delivery window"
assert_grep_fixed 'if len(data) > 1024 * 1024:' "$LORAX_MONITOR_PATCH" \
    "Lorax monitor bounds an unterminated virtio log record"
assert_grep_fixed 'time.sleep(0.25)' "$LORAX_MONITOR_VERIFY" \
    "Lorax semantic fixture exceeds the retired 100-ms idle window"
assert_grep_fixed 'emit_with_shutdown_gap' "$LORAX_MONITOR_VERIFY" \
    "Lorax semantic fixture streams its final record after handler startup"
assert_grep_fixed 'idle drain did not request the exact five-second production bound' \
    "$LORAX_MONITOR_VERIFY" \
    "Lorax semantic fixture exercises the bounded idle-timeout path"
assert_grep_fixed 'idle_writer.sendall(fatal)' "$LORAX_MONITOR_VERIFY" \
    "idle-drain fixture retains an unterminated fatal record without EOF"
assert_grep_fixed '_noid_prepare_live_required_space(mount_dir)' \
    "$LORAX_SIZE_PATCH" \
    "Lorax creates the manifest from the final mounted runtime tree"
assert_grep_fixed 'if opts.project == NOID_LIVE_PROJECT:' \
    "$LORAX_SIZE_PATCH" "compose mutation is scoped to the exact NoID Privacy project"
assert_grep_fixed 'verified_space != measured_space' "$LORAX_SIZE_PATCH" \
    "Lorax aborts when required-space publication is not a fixed point"
assert_grep_fixed 'os.O_NOFOLLOW' "$LORAX_SIZE_PATCH" \
    "Lorax rejects symlinked manifest inputs and publication directories"
assert_grep_fixed 'root_metadata = os.lstat(root)' "$LORAX_SIZE_PATCH" \
    "Lorax rejects a symlinked or mutable compose root before traversal"
assert_grep_fixed 'os.path.lexists(manifest_path)' "$LORAX_SIZE_PATCH" \
    "Lorax never overwrites a pre-existing manifest"
assert_grep_fixed 'make_runtime docstring contract differs' "$LORAX_SIZE_VERIFY" \
    "semantic verifier gates the insertion point before exercising helpers"
assert_grep_fixed 'a symlinked compose root was accepted' "$LORAX_SIZE_VERIFY" \
    "semantic verifier exercises the compose-root symlink rejection"
assert_grep_fixed 'compose ownership constants are not root' "$LORAX_SIZE_VERIFY" \
    "semantic verifier binds the production root-ownership constants"
for required_size_symbol in NOID_REQUIRED_SPACE_MINIMUM NOID_REQUIRED_UID \
        NOID_REQUIRED_GID; do
    assert_grep_fixed "\"${required_size_symbol}\"" "$LORAX_SIZE_VERIFY" \
        "semantic verifier requires $required_size_symbol before fixture overrides"
done
assert_grep_fixed 'proc.communicate(timeout=10)' "$LORAX_CANCEL_PATCH" \
    "Lorax cancellation gives TERM-responsive QEMU a bounded drain window"
assert_grep_fixed 'proc.kill()' "$LORAX_CANCEL_PATCH" \
    "Lorax cancellation has a bounded hard-stop fallback"
assert_grep_fixed 'cancelled child process remained active' "$LORAX_CANCEL_VERIFY" \
    "Lorax semantic fixture rejects an orphaned cancelled process"
assert_grep_fixed 'TERM-resistant cancellation did not use the bounded kill-and-reap fallback' \
    "$LORAX_CANCEL_VERIFY" \
    "Lorax semantic fixture exercises the hard-stop fallback"
if git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    for tracked_executable in \
        scripts/archive-build.sh \
        scripts/build-iso.sh \
        scripts/build-audit-support-media.sh \
        scripts/pii-sweep.sh \
        scripts/anaconda-patch/build-updates-img.sh \
        scripts/stage-lorax-overrides.sh \
        scripts/stage-lorax-templates.sh \
        scripts/verify-lorax-live-required-space.py \
        scripts/verify-lorax-monitor-drain.py \
        scripts/verify-lorax-cancel-cleanup.py \
        scripts/verify-livemedia-success.py; do
        tracked_mode=$(git -C "$PROJECT_ROOT" ls-files -s -- "$tracked_executable" \
            | awk 'NR == 1 { print $1 }')
        assert_eq 100755 "$tracked_mode" \
            "Git archive preserves executable mode for $tracked_executable"
    done
fi
assert_grep_fixed "EXPECTED_NEVRA='lorax-44.6-1.fc44.x86_64'" \
    "$LORAX_STAGE" "Lorax override is gated to the reviewed Fedora NEVRA"
assert_grep_fixed '%|EPOCH?{%{EPOCH}:}|' "$LORAX_STAGE" \
    "Lorax package query includes a nonzero RPM epoch"
assert_grep_fixed "EXPECTED_MONITOR_SHA256='47931372d5fb992a62abc05d83db2b2b362cd53ca7498518fa1d2f28cbaef91c'" \
    "$LORAX_STAGE" "Lorax override is gated to the reviewed source bytes"
assert_grep_fixed "EXPECTED_CREATOR_SHA256='c91902f78a5fb79cb3b44a812f155df44f45138098086c62f0aaa94fbac88cdb'" \
    "$LORAX_STAGE" "Lorax creator override is gated to reviewed source bytes"
assert_grep_fixed "EXPECTED_EXECUTILS_SHA256='0ecf52f4c18797e76b8ef9b44490fdafaf301805c10fb290ddbda81258372be6'" \
    "$LORAX_STAGE" "Lorax executils override is gated to reviewed source bytes"
assert_grep_fixed 'patch --batch --fuzz=0' "$LORAX_STAGE" \
    "all Lorax patches reject contextual drift"
assert_grep_fixed 'python3 -B -I "$MONITOR_VERIFIER"' "$LORAX_STAGE" \
    "staged monitor override must pass its isolated semantic fixture"
assert_grep_fixed 'python3 -B -I "$CREATOR_VERIFIER"' "$LORAX_STAGE" \
    "staged creator override must pass its isolated semantic fixture"
assert_grep_fixed 'python3 -B -I "$EXECUTILS_VERIFIER"' "$LORAX_STAGE" \
    "staged executils override must pass its isolated semantic fixture"
assert_grep_fixed '--rcfile=/usr/lib/rpm/rpmrc' "$LORAX_STAGE" \
    "Lorax verification closes the per-user RPM configuration tier"
assert_grep_fixed '--verify --nodeps --noscript lorax' "$LORAX_STAGE" \
    "complete installed Lorax payload passes read-only RPM verification"
assert_grep_fixed 'find "$SOURCE_ROOT/pylorax" -xdev -print' "$LORAX_STAGE" \
    "private Lorax shadow tree contains no unowned package-path additions"
assert_grep_fixed 'source_package_inventory=pass' "$LORAX_STAGE" \
    "retained Lorax evidence records the complete package inventory gate"
assert_file_executable "$LORAX_TEMPLATE_STAGE" \
    "private Lorax template staging helper is executable"
assert_file_exists "$LORAX_MENU_PATCH" \
    "reviewed Live-menu default patch exists"
assert_grep_fixed "EXPECTED_NEVRA='lorax-templates-generic-44.6-1.fc44.x86_64'" \
    "$LORAX_TEMPLATE_STAGE" \
    "Lorax template override is gated to the reviewed Fedora NEVRA"
assert_grep_fixed '%|EPOCH?{%{EPOCH}:}|' "$LORAX_TEMPLATE_STAGE" \
    "Lorax template package query includes a nonzero RPM epoch"
assert_grep_fixed "EXPECTED_EFI_SHA256='9acb83e8ad908769cf185de744ce8301ea91f4c2704bb511f72dc7ec307fec4e'" \
    "$LORAX_TEMPLATE_STAGE" \
    "Lorax EFI template override is gated to reviewed source bytes"
assert_grep_fixed "EXPECTED_BIOS_SHA256='e8cf76567ebdb2c22b728b9958b02af6c7958288852966e881c3c5e9178ec776'" \
    "$LORAX_TEMPLATE_STAGE" \
    "Lorax BIOS template override is gated to reviewed source bytes"
assert_grep_fixed '--verify --nodeps --noscript lorax-templates-generic' \
    "$LORAX_TEMPLATE_STAGE" \
    "complete installed Lorax template payload passes read-only RPM verification"
assert_grep_fixed 'find "$SOURCE_ROOT" -xdev -print' "$LORAX_TEMPLATE_STAGE" \
    "private Lorax template tree contains no unowned package-path additions"
assert_grep_fixed 'patch --batch --fuzz=0' "$LORAX_TEMPLATE_STAGE" \
    "Live-menu patch rejects contextual drift"
assert_grep_fixed 'chmod 0700 "$DESTINATION"' "$LORAX_TEMPLATE_STAGE" \
    "private Lorax template root mode is restored after archive copying"
assert_grep_fixed "stat -Lc '%a' \"\$DESTINATION\"" "$LORAX_TEMPLATE_STAGE" \
    "private Lorax template root mode is postchecked"
assert_grep_fixed 'set default="0"' "$LORAX_MENU_PATCH" \
    "normal Live entry is the reviewed default"
assert_grep_fixed 'set timeout=3' "$LORAX_MENU_PATCH" \
    "Live menu uses the reviewed three-second countdown"
assert_grep_fixed "grep -cF 'rd.live.check'" "$LORAX_TEMPLATE_STAGE" \
    "staged templates preserve exactly one media-check entry"
assert_grep_fixed \
    "sudo -n /usr/bin/sh -c 'umask 022; exec \"\$@\"' noid-lmc \\" \
    "$BUILD_SCRIPT" "compose process gets Fedora's public system-metadata umask"
assert_grep_fixed \
    '/usr/bin/env PYTHONPATH="$LORAX_OVERRIDE_DIR"' \
    "$BUILD_SCRIPT" "only the absolute native env receives the Lorax override"
assert_grep_fixed \
    '/usr/bin/livemedia-creator "${LMC_ARGS[@]}"' \
    "$BUILD_SCRIPT" "privileged compose binds the absolute native builder"
assert_not_grep \
    'sudo -n env PYTHONPATH=' \
    "$BUILD_SCRIPT" "compose cannot inherit the caller's restrictive interactive umask"
assert_grep_fixed 'lorax-overrides.txt' "$BUILD_SCRIPT" \
    "all Lorax source, patch and result hash sets are retained as evidence"
assert_grep_fixed '--lorax-templates "$LORAX_TEMPLATE_DIR"' "$BUILD_SCRIPT" \
    "canonical builder uses the private reviewed Lorax template tree"
assert_grep_fixed 'chmod 0700 "$LORAX_TEMPLATE_DIR"' "$BUILD_SCRIPT" \
    "canonical builder restores the private template-tree mode after staging"
assert_grep_fixed 'lorax-templates.txt' "$BUILD_SCRIPT" \
    "Lorax template source and menu patch evidence are retained"
assert_grep_fixed 'BUILD_LOCK_FILE="$BUILD_RUNTIME_DIR/noid-privacy-iso-build.lock"' \
    "$BUILD_SCRIPT" "all checkouts use one release-user-wide build lock"
assert_grep_fixed 'HTTP_ROOT="$BUILD_STAGE_DIR/http-root"' \
    "$BUILD_SCRIPT" "build payload server has a dedicated document root"
assert_grep_fixed "grep -q -- '--location=mbr' \"\$FLAT_KS\"" \
    "$BUILD_SCRIPT" "build-only bootloader rewrite rejects a surviving MBR target"
assert_grep_fixed 'cannot stage mandatory top-level branding PNGs' \
    "$BUILD_SCRIPT" "mandatory branding copy failures remain fatal inside the function"
assert_grep_fixed 'cannot stage the verified uBO cache payload' \
    "$BUILD_SCRIPT" "reduced-dependency copy failures remain fatal inside the function"
for loopback_assignment in BRANDING_HTTP_URL NOID_AUDIT_URL CODIUM_LOCAL_BASE; do
    assert_grep_fixed \
        "${loopback_assignment}=\\\"http://127.0.0.1:\${HTTP_PORT}/branding" \
        "$BUILD_SCRIPT" \
        "$loopback_assignment no-virt rewrite follows the canonical HTTP port"
done
assert_grep_fixed 'BRANDING_STAGE_DIR="$HTTP_ROOT/branding"' \
    "$BUILD_SCRIPT" "branding is staged inside the dedicated document root"
assert_grep_fixed 'UPDATES_IMG="$HTTP_ROOT/noid-anaconda-updates.img"' \
    "$BUILD_SCRIPT" "Anaconda updates image is staged inside the dedicated document root"
assert_grep_fixed 'cd "$HTTP_ROOT" && exec python3 -m http.server' \
    "$BUILD_SCRIPT" "loopback server exposes only the dedicated payload document root"
assert_not_grep 'cd "$BUILD_STAGE_DIR" && exec python3 -m http.server' \
    "$BUILD_SCRIPT" "loopback server never exposes private host-side build state"
assert_grep_fixed 'flock --exclusive --nonblock 9' "$BUILD_HOST_LOCK_LIB" \
    "canonical build lock fails immediately on a concurrent builder"
assert_grep_fixed 'if [ "$selinux_mode" != "Enforcing" ]; then' \
    "$BUILD_SCRIPT" \
    "no-virt build fails closed unless observed SELinux is Enforcing"
assert_grep_fixed 'systemd-detect-virt --vm' "$BUILD_SCRIPT" \
    "no-virt build requires a full virtual machine rather than a container"
assert_grep_fixed 'if [ ! -d /sys/firmware/efi ]; then' "$BUILD_SCRIPT" \
    "no-virt build requires its disposable VM to be UEFI-booted"
assert_grep_fixed 'Do not weaken SELinux; use an Enforcing disposable build VM or the default KVM build.' \
    "$BUILD_SCRIPT" \
    "no-virt refusal never directs an operator to disable enforcement"
assert_not_grep 'requires SELinux=Permissive' "$BUILD_SCRIPT" \
    "no-virt builder has no stale host-Permissive requirement"
assert_grep_fixed 'Anaconda image install (no-virt)' "$BUILD_DOC" \
    "build guide links the upstream no-virt safety and SELinux contract"
no_virt_guard_line=$(grep -nF 'if [ "$NO_VIRT" = "1" ]; then' "$BUILD_SCRIPT" \
    | head -1 | cut -d: -f1)
sudo_preflight_line=$(grep -nF 'sudo -n true ||' "$BUILD_SCRIPT" \
    | head -1 | cut -d: -f1)
if [ -n "$no_virt_guard_line" ] && [ -n "$sudo_preflight_line" ] \
        && [ "$no_virt_guard_line" -lt "$sudo_preflight_line" ]; then
    _pass "no-virt host guard runs before sudo and mutable build setup"
else
    _fail "no-virt host guard no longer fails before sudo and mutable build setup"
fi
kvm_mode_line=$(grep -nF '# KVM-mode (default) requires the exact reviewed Fedora Server netinst ISO' \
    "$BUILD_SCRIPT" | head -1 | cut -d: -f1)
virt_uefi_line=$(grep -nF -- '--virt-uefi' "$BUILD_SCRIPT" | tail -1 | cut -d: -f1)
ram_line=$(grep -nF -- '--ram "${QEMU_RAM:-16384}"' "$BUILD_SCRIPT" \
    | head -1 | cut -d: -f1)
vcpus_line=$(grep -nF -- '--vcpus "${QEMU_VCPUS:-8}"' "$BUILD_SCRIPT" \
    | head -1 | cut -d: -f1)
if [ -n "$kvm_mode_line" ] && [ -n "$virt_uefi_line" ] \
        && [ -n "$ram_line" ] && [ -n "$vcpus_line" ] \
        && [ "$virt_uefi_line" -gt "$kvm_mode_line" ] \
        && [ "$ram_line" -gt "$kvm_mode_line" ] \
        && [ "$vcpus_line" -gt "$kvm_mode_line" ]; then
    _pass "QEMU firmware and resource arguments are confined to the KVM branch"
else
    _fail "a QEMU-only argument escaped the KVM branch"
fi
assert_grep_fixed 'inst.profile=noid-privacy-workstation rd.driver.blacklist=bochs modprobe.blacklist=bochs' \
    "$BUILD_SCRIPT" \
    "KVM installer excludes the failing bochs DRM path without changing image boot arguments"
assert_not_grep 'KSPP_KERNEL_ARGS=.*blacklist=bochs' "$BUILD_SCRIPT" \
    "build-only bochs exclusion cannot leak into the candidate Live kernel arguments"
assert_not_grep 'KSPP_KERNEL_ARGS="rhgb' "$BUILD_SCRIPT" \
    "Lorax-owned entry-specific rhgb is not duplicated in extra boot arguments"
assert_grep_fixed 'python3 "$KARG_CONTRACT" live-config' "$BUILD_SCRIPT" \
    "canonical builder audits both final Live GRUB argument surfaces"
assert_grep_fixed "'efi|/EFI/BOOT/grub.cfg'" "$BUILD_SCRIPT" \
    "canonical builder extracts the final UEFI GRUB config"
assert_grep_fixed "'bios|/boot/grub2/grub.cfg'" "$BUILD_SCRIPT" \
    "canonical builder extracts the final BIOS GRUB config"
assert_grep_fixed 'live-boot-config-audit.txt' "$BUILD_SCRIPT" \
    "final Live boot-config evidence is retained beside private compose evidence"
assert_file_exists "$CANDIDATE_TRANSACTION_LIB" \
    "candidate publication transaction library exists"
assert_file_exists "$PARTITION_COLLAPSE_AWK" \
    "live-build partition collapse has a standalone reviewed program"
assert_grep_fixed 'awk -v no_virt="$NO_VIRT" -f "$PARTITION_COLLAPSE_AWK"' \
    "$BUILD_SCRIPT" \
    "canonical builder uses the tested mode-specific partition-collapse program"
assert_not_grep 'sudo rm -rf -- "$RESULT_DIR"' "$BUILD_SCRIPT" \
    "canonical build never recursively deletes a prior result directory"
assert_not_grep 'Removing pre-existing' "$BUILD_SCRIPT" \
    "canonical build has no legacy output-destruction branch"
assert_grep_fixed 'noid_candidate_publish' "$BUILD_SCRIPT" \
    "canonical build publishes only through the checked transaction helper"
assert_grep_fixed 'brltty.service' \
    "$PROJECT_ROOT/scripts/anaconda-patch/build-updates-img.sh" \
    "noninteractive build-installer stages the BRLTTY service mask"
assert_grep_fixed 'ln -s /dev/null "$SYSTEMD_DIR/brltty.service"' \
    "$PROJECT_ROOT/scripts/anaconda-patch/build-updates-img.sh" \
    "BRLTTY suppression uses the native transient systemd mask"
assert_not_grep 'brltty' "$LOG_POLICY" \
    "historical BRLTTY error flood is not allowlisted"
assert_file_executable "$ENFORCING_AVC_GATE" \
    "installed enforcing-boot zero-AVC gate is executable"
assert_file_executable "$SMOKE_ROOTFS_PREP" \
    "Fedora smoke-rootfs preparation is executable"
assert_grep_fixed '/usr/lib/rpm/redhat/rpmrc' "$SMOKE_ROOTFS_PREP" \
    "smoke preflight requires Fedora's vendor rpmrc"
assert_grep_fixed '/usr/lib/rpm/redhat/macros' "$SMOKE_ROOTFS_PREP" \
    "smoke preflight requires Fedora's vendor macro tier"
assert_grep_fixed 'sudo dnf install redhat-rpm-config' "$SMOKE_ROOTFS_PREP" \
    "missing Fedora RPM configuration has an exact recovery command"
assert_grep_fixed '**redhat-rpm-config**' "$SMOKE_README" \
    "smoke requirements document the Fedora RPM vendor configuration"
assert_not_grep '--nogpgcheck' "$SMOKE_ROOTFS_PREP" \
    "smoke evidence never weakens Fedora package signature verification"
assert_grep_fixed 'HOST_GPG_KEY="/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-${RELEASEVER}-x86_64"' \
    "$SMOKE_ROOTFS_PREP" "smoke rootfs requires the exact release/architecture key"
assert_grep_fixed '"$ROOTFS_DIR/usr/lib/sysimage/rpm"' \
    "$SMOKE_ROOTFS_PREP" "empty smoke rootfs bootstraps the RPM database parent"
assert_grep_fixed 'chcon --reference=/usr/lib/sysimage/rpm "$ROOTFS_DIR/usr/lib/sysimage/rpm"' \
    "$SMOKE_ROOTFS_PREP" "enforcing-host fixture uses Fedora's native RPM database label"
assert_not_grep_extended 'setenforce[[:space:]]+0|semanage[[:space:]]+fcontext' \
    "$SMOKE_ROOTFS_PREP" "smoke preparation neither disables SELinux nor changes host policy"
assert_grep_fixed "RPM_BOOTSTRAP_RCFILES='/usr/lib/rpm/rpmrc:/usr/lib/rpm/redhat/rpmrc'" \
    "$SMOKE_ROOTFS_PREP" "smoke RPM bootstrap closes the per-user rpmrc tier"
assert_grep_fixed "RPM_BOOTSTRAP_MACROFILES='/usr/lib/rpm/macros:/usr/lib/rpm/macros.d/macros.*:/usr/lib/rpm/platform/%{_target}/macros:/usr/lib/rpm/fileattrs/*.attr:/usr/lib/rpm/redhat/macros:/etc/rpm/macros.*:/etc/rpm/macros:/etc/rpm/%{_target}/macros'" \
    "$SMOKE_ROOTFS_PREP" "smoke RPM bootstrap closes the per-user macro tier"
assert_not_grep_extended 'RPM_BOOTSTRAP_(RCFILES|MACROFILES)=.*~/' \
    "$SMOKE_ROOTFS_PREP" "smoke RPM bootstrap cannot inspect an account home"
assert_grep_fixed 'RPM_BOOTSTRAP_CONFIG_HOME="$ROOTFS_DIR/.noid-rpm-config"' \
    "$SMOKE_ROOTFS_PREP" "smoke RPM bootstrap has a fixture-owned config home"
assert_grep_fixed 'install -d -m 0755 -o root -g root "$RPM_BOOTSTRAP_CONFIG_HOME"' \
    "$SMOKE_ROOTFS_PREP" "smoke RPM config home is root-owned and searchable"
assert_grep_fixed 'RPM_BOOTSTRAP=(env XDG_CONFIG_HOME="$RPM_BOOTSTRAP_CONFIG_HOME"' \
    "$SMOKE_ROOTFS_PREP" "smoke RPM bootstrap uses one closed argument vector"
assert_grep_fixed '"${RPM_BOOTSTRAP[@]}" --initdb' \
    "$SMOKE_ROOTFS_PREP" "smoke rootfs initializes RPM with closed system configuration"
assert_grep_fixed '"${RPM_BOOTSTRAP[@]}" --import "$ROOT_GPG_KEY"' \
    "$SMOKE_ROOTFS_PREP" "smoke rootfs imports its Fedora key fail-closed"
assert_grep_fixed '"${RPM_BOOTSTRAP[@]}" -q gpg-pubkey >/dev/null' \
    "$SMOKE_ROOTFS_PREP" "smoke rootfs verifies imported RPM trust state"
assert_grep_fixed 'env XDG_CONFIG_HOME="$RPM_BOOTSTRAP_CONFIG_HOME" dnf --installroot="$ROOTFS_DIR"' \
    "$SMOKE_ROOTFS_PREP" "smoke DNF transaction cannot inherit user RPM configuration"
assert_grep_fixed 'glib2 dconf desktop-file-utils pipewire-utils' "$SMOKE_ROOTFS_PREP" \
    "GNOME smoke rootfs includes M17's launcher generator + SPA JSON validator"
assert_grep_fixed 'gnome-software gnome-online-accounts localsearch tinysparql' \
    "$SMOKE_ROOTFS_PREP" "GNOME smoke rootfs includes every M17 vendor-descriptor owner"
assert_grep_fixed 'SANDBOX_PARENT="${NOID_SMOKE_SANDBOX_PARENT:-/var/tmp}"' \
    "$SMOKE_LIB" "smoke snapshots have a configurable disk-backed parent"
assert_grep_fixed 'mktemp -d -p "$SANDBOX_PARENT" noid-smoke-XXXXXX' \
    "$SMOKE_LIB" "smoke snapshot names remain atomically allocated"
assert_grep_fixed 'cp -a --reflink=auto "$ROOTFS_SRC"/. "$SANDBOX_DIR/"' \
    "$SMOKE_LIB" "smoke snapshots use native CoW with safe copy fallback"
assert_grep_fixed 'smoke_register_temp_file()' "$SMOKE_LIB" \
    "smoke harness centrally owns module temporary files"
assert_grep_fixed "trap 'smoke_cleanup' EXIT" "$SMOKE_LIB" \
    "smoke harness retains one EXIT cleanup owner"
assert_grep_fixed "trap 'exit 130' INT" "$SMOKE_LIB" \
    "smoke SIGINT retains its conventional exit status"
assert_grep_fixed "trap 'exit 143' TERM" "$SMOKE_LIB" \
    "smoke SIGTERM retains its conventional exit status"
for smoke_module in "$PROJECT_ROOT"/tests/smoke/M*-smoke.sh; do
    assert_grep_fixed 'smoke_register_temp_file "$TMP_POST"' "$smoke_module" \
        "$(basename "$smoke_module") registers its extracted post with central cleanup"
    assert_not_grep_extended '^trap[[:space:]]' "$smoke_module" \
        "$(basename "$smoke_module") cannot replace the central cleanup trap"
done
assert_grep_fixed 'scripts/build-iso.sh rewrites its first flattened occurrence' \
    "$KS_FILE" \
    "master documents the actual live-compose bootloader rewrite owner"
assert_not_grep 'bootloader.*last-wins' "$KS_FILE" \
    "master has no misleading bootloader last-wins claim"
assert_grep_fixed '22  LUKS/partitioning docs + header backup + mount/discard hardening' \
    "$KS_FILE" "master index describes M22 beyond mount flags"
assert_file_executable \
    "$FRESHNESS_TEST" \
    "installed-VM package/advisory freshness gate is present"
assert_grep_fixed 'blocking_severities = {"critical", "important", "moderate"}' \
    "$FRESHNESS_TEST" \
    "release gate blocks Critical, Important and Moderate advisories"
assert_grep_fixed 'check-upgrade --json' \
    "$FRESHNESS_TEST" \
    "release gate also rejects any immediately available Fedora package update"
assert_grep_fixed '0|100)' "$FRESHNESS_TEST" \
    "DNF's documented upgrades-present exit status reaches the JSON gate"
assert_grep_fixed 'if upgrade_document == {}:' "$FRESHNESS_TEST" \
    "DNF's empty-object no-upgrade response is accepted explicitly"
assert_grep_fixed 'set(upgrade_document) == {"upgrades"}' "$FRESHNESS_TEST" \
    "only the explicit upgrades schema is accepted otherwise"
assert_grep_fixed 'mktemp -d /var/tmp/noid-package-freshness.XXXXXX' \
    "$FRESHNESS_TEST" "package-freshness evidence uses disk-backed /var/tmp"
assert_grep_fixed 'mktemp /var/tmp/noid-pam-timestamp-check.XXXXXX' \
    "$PERMISSION_TEST" "permission-policy evidence uses disk-backed /var/tmp"
assert_grep_fixed 'mktemp -d /var/tmp/noid-chrony-runtime.XXXXXX' \
    "$CHRONY_TEST" "chrony runtime evidence uses disk-backed /var/tmp"
assert_grep_fixed 'mktemp -d /var/tmp/noid-enforcing-avc.XXXXXX' \
    "$ENFORCING_AVC_GATE" "enforcing-AVC evidence uses disk-backed /var/tmp"

TMPDIR="$(mktemp -d "${NOID_TEST_TMPDIR:-/var/tmp}/noid-compose-sources.XXXXXX")"
trap 'rm -rf -- "$TMPDIR"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

assert_cmd_success \
    "smoke cleanup removes its registered temp file and complete sandbox" \
    bash -c '
        set -euo pipefail
        smoke_lib=$1
        work=$2
        . "$smoke_lib"
        SANDBOX_DIR="$work/sandbox"
        temp_file="$work/extracted-post.sh"
        mkdir -p "$SANDBOX_DIR/nested"
        : > "$SANDBOX_DIR/nested/payload"
        : > "$temp_file"
        smoke_register_temp_file "$temp_file"
        smoke_cleanup
        [ ! -e "$SANDBOX_DIR" ]
        [ ! -e "$temp_file" ]
        [ -z "$SANDBOX_DIR" ]
        [ "${#SMOKE_TEMP_FILES[@]}" -eq 0 ]
    ' _ "$SMOKE_LIB" "$TMPDIR/smoke-cleanup"
assert_cmd_success "missing bwrap reaches the documented smoke skip status" \
    bash -c '
        set -euo pipefail
        command() {
            if [ "$#" -eq 2 ] && [ "$1" = -v ] && [ "$2" = bwrap ]; then
                return 1
            fi
            builtin command "$@"
        }
        BWRAP=
        . "$1"
        set +e
        (smoke_start missing-bwrap >/dev/null 2>&1)
        rc=$?
        set -e
        [ "$rc" -eq 77 ]
    ' _ "$SMOKE_LIB"
assert_grep_fixed 'expected_rootfs_leaf="rootfs-f${RELEASEVER}"' \
    "$SMOKE_ROOTFS_PREP" \
    "rootfs preparation confines an override to the release-specific leaf"
assert_grep_fixed 'validate_private_root_directory "$ROOTFS_PARENT" "smoke rootfs parent"' \
    "$SMOKE_ROOTFS_PREP" \
    "rootfs preparation verifies the destructive target parent"
assert_grep_fixed '/usr/bin/mountpoint -q -- "$ROOTFS_DIR"' \
    "$SMOKE_ROOTFS_PREP" \
    "rootfs preparation refuses a mounted deletion target"
assert_grep_fixed 'NOID_SMOKE_ROOTFS_V1 releasever=$RELEASEVER' \
    "$SMOKE_ROOTFS_PREP" \
    "rootfs preparation owns its disposable target with a release-bound marker"
assert_grep_fixed '0:0:640:1|0:0:644:1)' "$SMOKE_ROOTFS_PREP" \
    "legacy rootfs replacement accepts both historically produced safe manifest modes"
assert_grep_fixed 'chmod 0644 "$ROOTFS_DIR/.noid-smoke-rootfs-manifest"' \
    "$SMOKE_ROOTFS_PREP" \
    "new smoke manifests have one explicit canonical public-read mode"
assert_grep_fixed 'rm -rf --one-file-system -- "$ROOTFS_DIR"' \
    "$SMOKE_ROOTFS_PREP" \
    "rootfs replacement cannot cross nested filesystem boundaries"
assert_not_grep 'rm -rf "\$ROOTFS_DIR"' "$SMOKE_ROOTFS_PREP" \
    "unbounded legacy rootfs deletion is absent"

ANACONDA_EVR=$(python3 - "$LOG_POLICY" <<'PY'
import json
import pathlib
import sys

policy = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert policy["schema_version"] == 3
print(policy["bindings"]["anaconda_evr"])
PY
)

PARTITION_INPUT="$TMPDIR/partition-input.ks"
PARTITION_OUTPUT="$TMPDIR/partition-output.ks"
write_partition_fixture() {
    printf '%s\n' "$@" > "$PARTITION_INPUT"
}
run_partition_collapse() {
    awk -f "$PARTITION_COLLAPSE_AWK" "$PARTITION_INPUT" \
        > "$PARTITION_OUTPUT"
}
run_partition_collapse_no_virt() {
    awk -v no_virt=1 -f "$PARTITION_COLLAPSE_AWK" "$PARTITION_INPUT" \
        > "$PARTITION_OUTPUT"
}
write_partition_fixture \
    'lang en_US.UTF-8' \
    'zerombr' \
    'clearpart --all --initlabel' \
    'part /boot/efi --fstype="efi" --size=600' \
    'part /boot --fstype="ext4" --size=2048' \
    'part / --fstype="ext4" --size=12000' \
    '%packages' \
    'bash' \
    '%end'
assert_cmd_success "canonical flattened partition block collapses" \
    run_partition_collapse
assert_eq 1 "$(grep -c '^zerombr$' "$PARTITION_OUTPUT")" \
    "collapsed output has one start marker"
assert_eq 1 "$(grep -c '^clearpart --all --initlabel --drives=sda$' "$PARTITION_OUTPUT")" \
    "collapsed output has one build-only clearpart"
assert_eq 1 "$(grep -c '^part / --fstype="ext4" --size=12000 --ondisk=sda$' "$PARTITION_OUTPUT")" \
    "collapsed output has one build-only root partition"
assert_not_grep '^part /boot' "$PARTITION_OUTPUT" \
    "separate boot partitions are absent only from the build copy"
assert_grep_fixed '%packages' "$PARTITION_OUTPUT" \
    "content after the collapse block is preserved"
assert_cmd_success "no-virt flattened partition block collapses" \
    run_partition_collapse_no_virt
assert_eq 0 "$(grep -c '^zerombr$' "$PARTITION_OUTPUT" || true)" \
    "no-virt output omits the physical-disk initialization command"
assert_eq 1 "$(grep -c '^clearpart --all --initlabel$' "$PARTITION_OUTPUT")" \
    "no-virt output has one generic clearpart command"
assert_eq 1 "$(grep -c '^part / --fstype="ext4" --size=12000$' "$PARTITION_OUTPUT")" \
    "no-virt output has one generic root size anchor"
assert_not_grep_extended '^clearpart .*--drives=|^part .*--ondisk=' \
    "$PARTITION_OUTPUT" \
    "no-virt output never binds Anaconda dirinstall to a physical disk"
write_partition_fixture 'zerombr' 'clearpart --all --initlabel'
assert_cmd_failure "missing partition end marker is rejected" \
    run_partition_collapse
write_partition_fixture \
    'part / --fstype="ext4" --size=12000' 'zerombr' \
    'part / --fstype="ext4" --size=12000'
assert_cmd_failure "partition end marker before start is rejected" \
    run_partition_collapse
write_partition_fixture \
    'zerombr' 'zerombr' 'part / --fstype="ext4" --size=12000'
assert_cmd_failure "duplicate partition start marker is rejected" \
    run_partition_collapse
write_partition_fixture \
    'zerombr' 'part / --fstype="ext4" --size=12000' \
    'part / --fstype="ext4" --size=12000'
assert_cmd_failure "duplicate partition end marker is rejected" \
    run_partition_collapse
write_partition_fixture \
    'zerombr' 'part / --fstype="xfs" --size=12000'
assert_cmd_failure "ksflatten partition-format drift is rejected" \
    run_partition_collapse

# The canonical builder's lock is an open-file-description lock, not a stale
# PID file. Exercise real contention from another shell, exact conflict status,
# release on descriptor close and rejection of weak lock metadata.
assert_file_exists "$BUILD_HOST_LOCK_LIB" "canonical build-host lock library exists"
# shellcheck source=scripts/lib/build-host-lock.sh
. "$BUILD_HOST_LOCK_LIB"
BUILD_LOCK_FIXTURE_PARENT="$TMPDIR/build-lock-runtime"
BUILD_LOCK_FIXTURE="$BUILD_LOCK_FIXTURE_PARENT/noid-privacy-iso-build.lock"
mkdir -m 0700 "$BUILD_LOCK_FIXTURE_PARENT"
assert_cmd_success "first canonical builder acquires the host lock" \
    noid_build_lock_acquire "$BUILD_LOCK_FIXTURE"
assert_eq "$(id -u):$(id -g):600:1" \
    "$(stat -c '%u:%g:%a:%h' "$BUILD_LOCK_FIXTURE")" \
    "canonical build lock has closed same-user metadata"
set +e
env LOCK_LIB="$BUILD_HOST_LOCK_LIB" LOCK_PATH="$BUILD_LOCK_FIXTURE" \
    bash -c 'exec 9>&-; . "$LOCK_LIB"; noid_build_lock_acquire "$LOCK_PATH"' \
    >/dev/null 2>&1
contender_status=$?
set -e
assert_eq 75 "$contender_status" \
    "concurrent checkout receives the dedicated lock-conflict status"
exec 9>&-
assert_cmd_success "canonical build lock releases with its descriptor" \
    env LOCK_LIB="$BUILD_HOST_LOCK_LIB" LOCK_PATH="$BUILD_LOCK_FIXTURE" \
        bash -c '. "$LOCK_LIB"; noid_build_lock_acquire "$LOCK_PATH"; exec 9>&-'
WEAK_LOCK_PARENT="$TMPDIR/weak-build-lock-runtime"
WEAK_LOCK="$WEAK_LOCK_PARENT/noid-privacy-iso-build.lock"
mkdir -m 0700 "$WEAK_LOCK_PARENT"
install -m 0644 /dev/null "$WEAK_LOCK"
assert_cmd_failure "weak canonical build-lock metadata fails closed" \
    noid_build_lock_acquire "$WEAK_LOCK"

# --help is parsed before signing variables, Git cleanliness, tools, sudo and
# output setup. Deliberately invalid build inputs must therefore remain inert.
if env NOID_REQUIRE_SIGNATURE=bad \
        NOID_ISO_TMPDIR=relative SOURCE_DATE_EPOCH=bad \
        bash "$BUILD_SCRIPT" --help > "$TMPDIR/build-help.out" 2>&1; then
    _pass "build --help is side-effect-free and independent of build preconditions"
else
    _fail "build --help was gated by a build precondition"
fi
assert_grep_fixed 'Existing candidates and archived evidence are never removed or overwritten.' \
    "$TMPDIR/build-help.out" "build help states the write-once output contract"
for closed_path_script in \
    "$BUILD_SCRIPT" \
    "$PROJECT_ROOT/scripts/build-audit-support-media.sh" \
    "$LORAX_STAGE"; do
    assert_grep_fixed 'export PATH=/usr/sbin:/usr/bin' "$closed_path_script" \
        "release producer resolves only Fedora system tools"
done
assert_grep_fixed 'mv -T --update=none-fail -- "$RESULT_DIR" "$CANDIDATE_DIR"' \
    "$CANDIDATE_TRANSACTION_LIB" \
    "candidate publication closes the final no-replace collision window"
for signal_contract in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_contract" "$BUILD_SCRIPT" \
        "canonical builder preserves the signal-derived exit status"
    assert_grep_fixed "$signal_contract" \
        "$PROJECT_ROOT/scripts/build-audit-support-media.sh" \
        "support-media builder preserves the signal-derived exit status"
done

# Exercise the same publication helper used by the wrapper. Pre-existing
# artifacts must survive two unique transactions, incomplete results remain
# hidden, and a destination collision must retain both sides without replace.
# shellcheck source=scripts/lib/candidate-transaction.sh
. "$CANDIDATE_TRANSACTION_LIB"
OUTPUT_FIXTURE="$TMPDIR/build-output"
mkdir -p "$OUTPUT_FIXTURE"
printf '%s\n' retained-iso > "$OUTPUT_FIXTURE/prior.iso"
printf '%s\n' retained-signature > "$OUTPUT_FIXTURE/SHA256SUMS.asc"
prior_manifest=$(sha256sum "$OUTPUT_FIXTURE/prior.iso" \
    "$OUTPUT_FIXTURE/SHA256SUMS.asc")

assert_cmd_success "first candidate transaction initializes safely" \
    noid_candidate_begin "$OUTPUT_FIXTURE" 0123456789ab-1783900000 \
        unsigned-candidate
first_destination=$CANDIDATE_DIR
assert_cmd_failure "incomplete transaction is not visible at final path" \
    test -e "$first_destination"
mkdir "$RESULT_DIR"
printf '%s\n' first > "$RESULT_DIR/candidate.iso"
assert_cmd_success "complete first candidate publishes atomically" \
    noid_candidate_publish
assert_file_exists "$first_destination/candidate.iso" \
    "first published candidate remains addressable"

assert_cmd_success "second same-source transaction receives a unique path" \
    noid_candidate_begin "$OUTPUT_FIXTURE" 0123456789ab-1783900000 \
        unsigned-candidate
second_destination=$CANDIDATE_DIR
if [ "$first_destination" != "$second_destination" ]; then
    _pass "same source/epoch builds cannot overwrite one another"
else
    _fail "same source/epoch builds reused one candidate path"
fi
mkdir "$RESULT_DIR"
printf '%s\n' second > "$RESULT_DIR/candidate.iso"
assert_cmd_success "complete second candidate publishes atomically" \
    noid_candidate_publish
assert_file_exists "$first_destination/candidate.iso" \
    "second publication preserves the first candidate"

assert_cmd_success "collision fixture initializes a fresh transaction" \
    noid_candidate_begin "$OUTPUT_FIXTURE" 0123456789ab-1783900000 \
        unsigned-candidate
mkdir "$RESULT_DIR" "$CANDIDATE_DIR"
printf '%s\n' pending > "$RESULT_DIR/candidate.iso"
printf '%s\n' existing > "$CANDIDATE_DIR/existing.iso"
assert_cmd_failure "publication collision fails instead of replacing output" \
    noid_candidate_publish
assert_file_exists "$RESULT_DIR/candidate.iso" \
    "collision leaves the unpublished source intact"
assert_file_exists "$CANDIDATE_DIR/existing.iso" \
    "collision leaves the existing destination intact"

publish_with_injected_collision() (
    # noid_candidate_publish resolves mv at runtime; ShellCheck cannot see this
    # fixture replacement through the sourced helper's indirect call graph.
    # shellcheck disable=SC2317,SC2329
    mv() {
        local destination=${!#}
        mkdir -- "$destination"
        printf '%s\n' competing-publisher > "$destination/OWNER"
        command /usr/bin/mv "$@"
    }
    noid_candidate_publish
)
assert_cmd_success "race-collision fixture initializes a fresh transaction" \
    noid_candidate_begin "$OUTPUT_FIXTURE" 0123456789ab-1783900000 \
        unsigned-candidate
mkdir "$RESULT_DIR"
printf '%s\n' pending-race > "$RESULT_DIR/candidate.iso"
assert_cmd_failure "publication-time race cannot replace a new destination" \
    publish_with_injected_collision
assert_file_exists "$RESULT_DIR/candidate.iso" \
    "publication-time race preserves the unpublished source"
assert_file_exists "$CANDIDATE_DIR/OWNER" \
    "publication-time race preserves the competing destination"

assert_cmd_success "post-publish cleanup fixture initializes a fresh transaction" \
    noid_candidate_begin "$OUTPUT_FIXTURE" 0123456789ab-1783900000 \
        unsigned-candidate
post_publish_transaction=$TRANSACTION_ROOT
post_publish_destination=$CANDIDATE_DIR
mkdir "$RESULT_DIR"
printf '%s\n' completed > "$RESULT_DIR/candidate.iso"
printf '%s\n' unexpected > "$TRANSACTION_ROOT/unexpected"
assert_cmd_failure "post-publish shell cleanup failure remains fail-visible" \
    noid_candidate_publish
assert_file_exists "$post_publish_destination/candidate.iso" \
    "published candidate survives a later transaction-shell cleanup failure"
assert_file_exists "$post_publish_transaction/unexpected" \
    "unexpected transaction residue is retained for inspection"
assert_eq "" "$TRANSACTION_ROOT" \
    "post-publication state no longer exposes the stale transaction path"
assert_eq "$post_publish_destination" "$RESULT_DIR" \
    "post-publication result state names the visible candidate"

assert_eq "$prior_manifest" \
    "$(sha256sum "$OUTPUT_FIXTURE/prior.iso" "$OUTPUT_FIXTURE/SHA256SUMS.asc")" \
    "candidate transactions preserve prior ISO and signature bytes"
mkdir "$TMPDIR/real-output"
ln -s "$TMPDIR/real-output" "$TMPDIR/symlink-output"
assert_cmd_failure "symlinked output root is rejected" \
    noid_candidate_begin "$TMPDIR/symlink-output" \
        0123456789ab-1783900000 unsigned-candidate

extract_heredoc "$FRESHNESS_TEST" "PY" "$TMPDIR/freshness-parser.py" \
    || _fail "freshness JSON parser extraction"
printf '[]\n' > "$TMPDIR/security.json"
printf '{}\n' > "$TMPDIR/upgrades-empty.json"
printf '{"upgrades": []}\n' > "$TMPDIR/upgrades-list.json"
printf '{"packages": []}\n' > "$TMPDIR/upgrades-unknown.json"
assert_cmd_success "freshness parser accepts DNF's empty-object response" \
    python3 "$TMPDIR/freshness-parser.py" "$TMPDIR/security.json" \
        "$TMPDIR/upgrades-empty.json"
assert_cmd_success "freshness parser accepts an explicit empty upgrades list" \
    python3 "$TMPDIR/freshness-parser.py" "$TMPDIR/security.json" \
        "$TMPDIR/upgrades-list.json"
if python3 "$TMPDIR/freshness-parser.py" "$TMPDIR/security.json" \
        "$TMPDIR/upgrades-unknown.json" >/dev/null 2>&1; then
    _fail "freshness parser accepted an unknown DNF JSON schema"
else
    _pass "freshness parser rejects unknown DNF JSON schemas"
fi

# Host-side Lorax success is a separate, deterministic trust source from the
# guest's asynchronous Boss tail. Exercise the exact auditor used by the
# canonical builder, including cardinality, order, format and file-type drift.
printf '%s\n' \
    '2026-07-17 19:13:41,420 INFO livemedia-creator: Shutting down log processing' \
    '2026-07-17 19:13:42,430 INFO pylorax: Installation finished without errors.' \
    '2026-07-17 19:13:42,437 INFO pylorax: Disk Image install successful' \
    > "$TMPDIR/livemedia-valid.log"
assert_cmd_success "host-side success auditor accepts exact ordered markers" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode kvm \
        --log "$TMPDIR/livemedia-valid.log" \
        --report "$TMPDIR/livemedia-valid.json"
assert_cmd_success "host-side success report binds hash, counts and order" \
    python3 - "$TMPDIR/livemedia-valid.log" "$TMPDIR/livemedia-valid.json" <<'PY'
import hashlib
import json
import pathlib
import sys

log, report = map(pathlib.Path, sys.argv[1:])
document = json.loads(report.read_text(encoding="utf-8"))
assert document["result"] == "pass"
assert document["schema_version"] == 2
assert document["mode"] == "kvm"
assert document["log_sha256"] == hashlib.sha256(log.read_bytes()).hexdigest()
assert document["counts"] == {"disk_image_success": 1, "installation_finished": 1}
assert document["marker_lines"]["installation_finished"][0] < document["marker_lines"]["disk_image_success"][0]
PY

printf '%s\n' \
    '2026-08-03 04:53:28,473 INFO pylorax: Complete!' \
    '2026-08-03 04:53:34,827 INFO pylorax: Disk Image install successful' \
    > "$TMPDIR/livemedia-no-virt-valid.log"
assert_cmd_success "host-side success auditor accepts exact no-virt markers" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode no-virt \
        --log "$TMPDIR/livemedia-no-virt-valid.log" \
        --report "$TMPDIR/livemedia-no-virt-valid.json"
assert_cmd_success "no-virt success report binds mode, counts and order" \
    python3 - "$TMPDIR/livemedia-no-virt-valid.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["schema_version"] == 2
assert document["mode"] == "no-virt"
assert document["result"] == "pass"
assert document["counts"] == {"anaconda_complete": 1, "disk_image_success": 1}
assert document["marker_lines"]["anaconda_complete"][0] < document["marker_lines"]["disk_image_success"][0]
PY
assert_cmd_failure "KVM mode cannot accept no-virt success evidence" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode kvm \
        --log "$TMPDIR/livemedia-no-virt-valid.log" \
        --report "$TMPDIR/livemedia-no-virt-as-kvm.json"
assert_cmd_failure "no-virt mode cannot accept KVM success evidence" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode no-virt \
        --log "$TMPDIR/livemedia-valid.log" \
        --report "$TMPDIR/livemedia-kvm-as-no-virt.json"
printf '%s\n' \
    '2026-08-03 04:53:28,473 INFO pylorax: Complete!' \
    '2026-08-03 04:53:29,473 INFO pylorax: Complete!' \
    '2026-08-03 04:53:34,827 INFO pylorax: Disk Image install successful' \
    > "$TMPDIR/livemedia-no-virt-duplicate.log"
assert_cmd_failure "duplicate no-virt completion marker fails closed" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode no-virt \
        --log "$TMPDIR/livemedia-no-virt-duplicate.log" \
        --report "$TMPDIR/livemedia-no-virt-duplicate.json"
printf '%s\n' \
    '2026-08-03 04:53:34,827 INFO pylorax: Disk Image install successful' \
    '2026-08-03 04:53:28,473 INFO pylorax: Complete!' \
    > "$TMPDIR/livemedia-no-virt-reordered.log"
assert_cmd_failure "reordered no-virt success markers fail closed" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode no-virt \
        --log "$TMPDIR/livemedia-no-virt-reordered.log" \
        --report "$TMPDIR/livemedia-no-virt-reordered.json"

head -n 2 "$TMPDIR/livemedia-valid.log" > "$TMPDIR/livemedia-missing.log"
assert_cmd_failure "missing disk-image success marker fails closed" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode kvm \
        --log "$TMPDIR/livemedia-missing.log" \
        --report "$TMPDIR/livemedia-missing.json"
cp "$TMPDIR/livemedia-valid.log" "$TMPDIR/livemedia-duplicate.log"
printf '%s\n' \
    '2026-07-17 19:13:42,438 INFO pylorax: Disk Image install successful' \
    >> "$TMPDIR/livemedia-duplicate.log"
assert_cmd_failure "duplicate disk-image success marker fails closed" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode kvm \
        --log "$TMPDIR/livemedia-duplicate.log" \
        --report "$TMPDIR/livemedia-duplicate.json"
printf '%s\n' \
    '2026-07-17 19:13:42,437 INFO pylorax: Disk Image install successful' \
    '2026-07-17 19:13:42,430 INFO pylorax: Installation finished without errors.' \
    > "$TMPDIR/livemedia-reordered.log"
assert_cmd_failure "reordered host-side success markers fail closed" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode kvm \
        --log "$TMPDIR/livemedia-reordered.log" \
        --report "$TMPDIR/livemedia-reordered.json"
sed 's/INFO pylorax: Disk Image/INFO livemedia-creator: Disk Image/' \
    "$TMPDIR/livemedia-valid.log" > "$TMPDIR/livemedia-drifted.log"
assert_cmd_failure "format-drifted host-side success marker fails closed" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode kvm \
        --log "$TMPDIR/livemedia-drifted.log" \
        --report "$TMPDIR/livemedia-drifted.json"
ln -s "$TMPDIR/livemedia-valid.log" "$TMPDIR/livemedia-symlink.log"
assert_cmd_failure "symlinked livemedia log fails closed" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode kvm \
        --log "$TMPDIR/livemedia-symlink.log" \
        --report "$TMPDIR/livemedia-symlink.json"
truncate -s $((256 * 1024 * 1024 + 1)) "$TMPDIR/livemedia-oversized.log"
assert_cmd_failure "oversized sparse livemedia log fails before content read" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode kvm \
        --log "$TMPDIR/livemedia-oversized.log" \
        --report "$TMPDIR/livemedia-oversized.json"
assert_grep_fixed 'exceeds the 256 MiB bound' \
    "$TMPDIR/livemedia-oversized.json" \
    "oversized livemedia report records the bounded-read rejection"
mkfifo "$TMPDIR/livemedia-fifo.log"
assert_cmd_failure "FIFO livemedia input is rejected without blocking" \
    python3 "$LMC_SUCCESS_AUDITOR" --mode kvm \
        --log "$TMPDIR/livemedia-fifo.log" \
        --report "$TMPDIR/livemedia-fifo.json"
assert_grep_fixed 'must be a regular non-symlink file' \
    "$TMPDIR/livemedia-fifo.json" \
    "FIFO rejection records the regular-file boundary"

# Candidate installer logs: require the three deterministic guest markers,
# accept the exact redundant Boss tail at most once, classify every high-
# severity/nonzero line exactly once, and bind the report to policy+log hashes.
# The builder separately requires both exact host-side livemedia success lines.
# Negative fixtures prove no generic error, BRLTTY flood, enforcing AVC or
# over-budget reviewed event can hide behind a successful exit.
printf '%s\n' \
    '18:00:00,000 INFO anaconda:anaconda: core.configuration.anaconda: Load the '\''noid-privacy-workstation'\'' profile configuration.' \
    "18:00:00,001 INFO anaconda:anaconda: main: /usr/bin/anaconda ${ANACONDA_EVR}" \
    '18:00:00,002 NOTICE audit:AVC avc:  denied  { read } for pid=1 scontext=system_u:system_r:kernel_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=1' \
    '18:00:00,003 NOTICE audit:AVC avc:  denied  { search } for pid=2 comm="dracut-install" name="modules" dev="sda1" ino=3 scontext=system_u:system_r:kernel_generic_helper_t:s0 tcontext=system_u:object_r:modules_object_t:s0 tclass=dir permissive=1' \
    '18:00:00,004 NOTICE audit:AVC avc:  denied  { search } for pid=3 comm="cp" name="kernel" dev="sda1" ino=4 scontext=system_u:system_r:kernel_generic_helper_t:s0 tcontext=system_u:object_r:modules_object_t:s0 tclass=dir permissive=1' \
    '18:00:00,005 WARNING org.fedoraproject.Anaconda.Modules.Runtime:INFO:program:[2026-07-13 18:00:00] [Module 99] === Module 99: Finalize COMPLETE ===' \
    '18:00:00,006 WARNING org.fedoraproject.Anaconda.Boss:INFO:anaconda.modules.boss.installation:All tasks in the installation queue are done. Installation successfully finished.' \
    > "$TMPDIR/compose-valid.log"
assert_cmd_success "closed compose-log policy accepts classified success fixture" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-valid.log" --report "$TMPDIR/compose-valid.json"
assert_cmd_success "compose report binds exact policy/log hashes" \
    python3 - "$LOG_POLICY" "$TMPDIR/compose-valid.log" \
        "$TMPDIR/compose-valid.json" <<'PY'
import hashlib
import json
import pathlib
import sys

policy, log, report = map(pathlib.Path, sys.argv[1:])
document = json.loads(report.read_text(encoding="utf-8"))
assert document["result"] == "pass"
assert document["policy_sha256"] == hashlib.sha256(policy.read_bytes()).hexdigest()
assert document["log_sha256"] == hashlib.sha256(log.read_bytes()).hexdigest()
assert document["counts"]["installer_permissive_avc"] == 1
assert document["counts"]["installer_dracut_module_traversal_avc"] == 2
assert document["bindings"] == json.loads(policy.read_text(encoding="utf-8"))["bindings"]
PY

# Reverse-DNS misses are exact QEMU user-network diagnostics, but their count
# follows compose duration because NetworkManager repeats hostname resolution.
# Bind both halves to the exact bounded reverse-lookup sequence and equal
# cardinality. NetworkManager timestamps the two log calls independently, so
# the positive fixture deliberately uses adjacent rather than identical
# monotonic timestamps. Prove that one-sided/unpaired evidence still closes.
python3 - "$LOG_POLICY" "$TMPDIR/compose-valid.log" \
    "$TMPDIR/compose-reverse-dns-at-budget.log" \
    "$TMPDIR/compose-reverse-dns-over-budget.log" \
    "$TMPDIR/compose-reverse-dns-helper-only.log" \
    "$TMPDIR/compose-reverse-dns-device-only.log" \
    "$TMPDIR/compose-reverse-dns-interleaved.log" \
    "$TMPDIR/compose-reverse-dns-key-mismatch.log" <<'PY'
import json
import pathlib
import sys

(policy_path, base_path, at_path, over_path, helper_path, device_path,
 interleaved_path, mismatch_path) = map(pathlib.Path, sys.argv[1:])
policy = json.loads(policy_path.read_text(encoding="utf-8"))
budgets = {
    row["id"]: row["max_count"]
    for row in policy["allowed_events"]
    if row["id"] in {
        "qemu_reverse_dns_helper_exit",
        "qemu_reverse_dns_device_result",
    }
}
assert budgets == {
    "qemu_reverse_dns_helper_exit": 16,
    "qemu_reverse_dns_device_result": 16,
}
correlations = {
    row["id"]: (row.get("correlation_id"), row.get("correlation_key_group"))
    for row in policy["allowed_events"]
    if row["id"] in budgets
}
assert correlations == {
    "qemu_reverse_dns_helper_exit": (
        "qemu_reverse_dns_pair", "qemu_reverse_dns_event"
    ),
    "qemu_reverse_dns_device_result": (
        "qemu_reverse_dns_pair", "qemu_reverse_dns_event"
    ),
}
base = base_path.read_text(encoding="utf-8")
pairs = []
for sequence in range(16):
    helper_stamp = f"1786630000.{sequence:03d}3"
    device_stamp = f"1786630000.{sequence:03d}4"
    pairs.extend([
        f"18:00:{sequence:02d},099 DEBUG NetworkManager:<debug> [{helper_stamp}] "
        f"nm-daemon-helper[0123456789abcdef,{3000 + sequence}]: spawned process with args: "
        "resolve-address 10.0.2.15 files",
        f"18:00:{sequence:02d},100 DEBUG NetworkManager:<debug> [{helper_stamp}] "
        f"nm-daemon-helper[0123456789abcdef,{3000 + sequence}]: process exited with status 3",
        f"18:00:{sequence:02d},100 DEBUG NetworkManager:<debug> [{device_stamp}] "
        "resolve-addr[fedcba9876543210,10.0.2.15]: helper returned hostname '(null)'",
        f"18:00:{sequence:02d},101 DEBUG NetworkManager:<debug> [{device_stamp}] "
        "device[0123456789abcdef] (enp0s2): hostname-from-dns: ipv4 resolver DONE: "
        "lookup error for 10.0.2.15: helper process exited with status 3",
    ])
at_path.write_text(base + "\n".join(pairs) + "\n", encoding="utf-8")
over_path.write_text(
    at_path.read_text(encoding="utf-8")
    + "18:01:00,099 DEBUG NetworkManager:<debug> [1786630060.0002] "
      "nm-daemon-helper[0123456789abcdef,4000]: spawned process with args: "
      "resolve-address 10.0.2.15 files\n"
    + "18:01:00,100 DEBUG NetworkManager:<debug> [1786630060.0003] "
      "nm-daemon-helper[0123456789abcdef,4000]: process exited with status 3\n"
    + "18:01:00,100 DEBUG NetworkManager:<debug> [1786630060.0004] "
      "resolve-addr[fedcba9876543210,10.0.2.15]: helper returned hostname '(null)'\n"
    + "18:01:00,101 DEBUG NetworkManager:<debug> [1786630060.0004] "
      "device[0123456789abcdef] (enp0s2): hostname-from-dns: ipv4 resolver DONE: "
      "lookup error for 10.0.2.15: helper process exited with status 3\n",
    encoding="utf-8",
)
helper_path.write_text(base + "\n".join(pairs[0:2]) + "\n", encoding="utf-8")
device_path.write_text(base + pairs[3] + "\n", encoding="utf-8")
interleaved = [
    "18:00:30,080 DEBUG NetworkManager:<debug> [1786630030.0800] "
    "nm-daemon-helper[aaaaaaaaaaaaaaaa,4100]: spawned process with args: "
    "resolve-address 10.0.2.15 files",
]
interleaved.extend(
    f"18:00:30,{81 + offset:03d} INFO NetworkManager:bounded unrelated line {offset}"
    for offset in range(16)
)
interleaved.extend([
    "18:00:30,097 DEBUG NetworkManager:<debug> [1786630030.0973] "
    "nm-daemon-helper[aaaaaaaaaaaaaaaa,4100]: process exited with status 3",
    "18:00:30,097 DEBUG NetworkManager:<debug> [1786630030.0974] "
    "resolve-addr[fedcba9876543210,10.0.2.15]: helper returned hostname '(null)'",
    "18:00:30,097 DEBUG NetworkManager:<debug> [1786630030.0974] "
    "device[0123456789abcdef] (enp0s2): hostname-from-dns: ipv4 resolver DONE: "
    "lookup error for 10.0.2.15: helper process exited with status 3",
])
interleaved_path.write_text(
    base + "\n".join(interleaved) + "\n", encoding="utf-8"
)
mismatch_path.write_text(
    base + "\n".join(interleaved).replace(
        "nm-daemon-helper[aaaaaaaaaaaaaaaa,4100]: process exited",
        "nm-daemon-helper[bbbbbbbbbbbbbbbb,4101]: process exited",
    ) + "\n",
    encoding="utf-8",
)
PY
assert_cmd_success "exact paired QEMU reverse-DNS misses pass at the duration budget" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-reverse-dns-at-budget.log" \
        --report "$TMPDIR/compose-reverse-dns-at-budget.json"
assert_cmd_failure "paired QEMU reverse-DNS misses still fail above the duration budget" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-reverse-dns-over-budget.log" \
        --report "$TMPDIR/compose-reverse-dns-over-budget.json"
assert_cmd_failure "a generic helper exit without its QEMU device result fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-reverse-dns-helper-only.log" \
        --report "$TMPDIR/compose-reverse-dns-helper-only.json"
assert_cmd_failure "a QEMU device result without its helper exit fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-reverse-dns-device-only.log" \
        --report "$TMPDIR/compose-reverse-dns-device-only.json"
assert_cmd_success "matching helper identity survives observed asynchronous interleaving" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-reverse-dns-interleaved.log" \
        --report "$TMPDIR/compose-reverse-dns-interleaved.json"
assert_cmd_failure "a different helper identity in the same event window fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-reverse-dns-key-mismatch.log" \
        --report "$TMPDIR/compose-reverse-dns-key-mismatch.json"
assert_cmd_success "QEMU helper-identity mismatch remains explicit in the report" \
    python3 - "$TMPDIR/compose-reverse-dns-key-mismatch.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["result"] == "fail"
assert document["budget_failures"] == []
assert [row["reason"] for row in document["violations"]] == ["unclassified"]
assert document["violations_truncated"] == 0
assert document["correlation_failures"] == [{
    "id": "qemu_reverse_dns_pair",
    "members": [
        {"id": "qemu_reverse_dns_helper_exit", "count": 0},
        {"id": "qemu_reverse_dns_device_result", "count": 1},
    ],
}]
PY
ln -s "$TMPDIR/compose-valid.log" "$TMPDIR/compose-symlink.log"
assert_cmd_failure "symlinked compose log fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-symlink.log" \
        --report "$TMPDIR/compose-symlink.json"
truncate -s $((256 * 1024 * 1024 + 1)) "$TMPDIR/compose-oversized.log"
assert_cmd_failure "oversized sparse compose log fails before content read" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-oversized.log" \
        --report "$TMPDIR/compose-oversized.json"
mkfifo "$TMPDIR/compose-fifo.log"
assert_cmd_failure "FIFO compose log is rejected without blocking" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-fifo.log" \
        --report "$TMPDIR/compose-fifo.json"
assert_grep_fixed 'must be a regular non-symlink file' \
    "$TMPDIR/compose-fifo.json" \
    "FIFO compose rejection records the regular-file boundary"
ln -s "$LOG_POLICY" "$TMPDIR/compose-policy-symlink.json"
assert_cmd_failure "symlinked compose policy fails closed" \
    python3 "$LOG_AUDITOR" --policy "$TMPDIR/compose-policy-symlink.json" \
        --log "$TMPDIR/compose-valid.log" \
        --report "$TMPDIR/compose-policy-symlink-report.json"
assert_not_grep 'policy_path.read_bytes()' "$LOG_AUDITOR" \
    "compose report hashes the exact policy bytes already classified"

python3 - "$LOG_POLICY" "$TMPDIR/compose-binding-drift.json" <<'PY'
import json
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:])
policy = json.loads(source.read_text(encoding="utf-8"))
policy["bindings"]["anaconda_evr"] = "44.31-1.fc44"
target.write_text(json.dumps(policy), encoding="utf-8")
PY
assert_cmd_failure "Anaconda binding cannot drift from its marker/scope" \
    python3 "$LOG_AUDITOR" --policy "$TMPDIR/compose-binding-drift.json" \
        --log "$TMPDIR/compose-valid.log" \
        --report "$TMPDIR/compose-binding-drift-report.json"

python3 - "$LOG_POLICY" "$TMPDIR/compose-scope-drift.json" <<'PY'
import json
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:])
policy = json.loads(source.read_text(encoding="utf-8"))
policy["scope"] = "drifted human scope"
target.write_text(json.dumps(policy), encoding="utf-8")
PY
assert_cmd_failure "compose policy scope cannot drift from exact bindings" \
    python3 "$LOG_AUDITOR" --policy "$TMPDIR/compose-scope-drift.json" \
        --log "$TMPDIR/compose-valid.log" \
        --report "$TMPDIR/compose-scope-drift-report.json"

grep -v 'All tasks in the installation queue are done' \
    "$TMPDIR/compose-valid.log" > "$TMPDIR/compose-valid-no-boss.log"
assert_cmd_success "closed guest-log policy accepts transport EOF after exact M99" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-valid-no-boss.log" \
        --report "$TMPDIR/compose-valid-no-boss.json"
assert_cmd_success "Boss-tail-absent fixture reports an exact zero count" \
    python3 - "$TMPDIR/compose-valid-no-boss.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["result"] == "pass"
assert document["counts"]["anaconda_complete"] == 0
PY

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-duplicate-boss.log"
printf '%s\n' \
    '18:00:00,005 WARNING org.fedoraproject.Anaconda.Boss:INFO:anaconda.modules.boss.installation:All tasks in the installation queue are done. Installation successfully finished.' \
    >> "$TMPDIR/compose-duplicate-boss.log"
assert_cmd_failure "duplicate guest Boss success marker fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-duplicate-boss.log" \
        --report "$TMPDIR/compose-duplicate-boss.json"

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-unknown-error.log"
printf '%s\n' '18:00:00,005 ERR kernel:unreviewed failure' \
    >> "$TMPDIR/compose-unknown-error.log"
assert_cmd_failure "unclassified ERR line fails a successful compose" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-unknown-error.log" \
        --report "$TMPDIR/compose-unknown-error.json"

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-brltty.log"
printf '%s\n' \
    '18:00:00,005 ERR brltty:file system mount error: usbfs[brltty-usbfs] -> /run/brltty/usbfs: No such device' \
    >> "$TMPDIR/compose-brltty.log"
assert_cmd_failure "BRLTTY usbfs error is forbidden instead of budgeted" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-brltty.log" --report "$TMPDIR/compose-brltty.json"

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-nonzero.log"
printf '%s\n' \
    '18:00:00,005 WARNING org.fedoraproject.Anaconda.Modules.Storage:DEBUG:program:Return code of unknown: 1' \
    >> "$TMPDIR/compose-nonzero.log"
assert_cmd_failure "unknown nonzero event fails a successful compose" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-nonzero.log" --report "$TMPDIR/compose-nonzero.json"

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-fcoe-interleaved.log"
printf '%s\n' \
    '18:00:00,005 WARNING org.fedoraproject.Anaconda.Modules.Storage:INFO:program:Running... /usr/libexec/fcoe/fcoe_edd.sh -i' \
    >> "$TMPDIR/compose-fcoe-interleaved.log"
for second in 006 007 008 009 010 011 012 013 014; do
    printf '18:00:00,%s INFO systemd:bounded FCoE probe interleave fixture\n' \
        "$second" >> "$TMPDIR/compose-fcoe-interleaved.log"
done
printf '%s\n' \
    '18:00:00,015 WARNING org.fedoraproject.Anaconda.Modules.Storage:DEBUG:program:Return code: 1' \
    '18:00:00,016 WARNING org.fedoraproject.Anaconda.Modules.Storage:INFO:blivet:No FCoE EDD info found: No FCoE boot disk information is found in EDD!' \
    >> "$TMPDIR/compose-fcoe-interleaved.log"
assert_cmd_success "bounded interleaving preserves the exact FCoE absence sequence" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-fcoe-interleaved.log" \
        --report "$TMPDIR/compose-fcoe-interleaved.json"
assert_cmd_success "interleaved FCoE fixture classifies the paired event once" \
    python3 - "$TMPDIR/compose-fcoe-interleaved.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["result"] == "pass"
assert document["counts"]["fcoe_edd_absence_probe"] == 1
PY

sed 's/No FCoE EDD info found: No FCoE boot disk information is found in EDD!/FCoE probe failed without a reviewed absence result/' \
    "$TMPDIR/compose-fcoe-interleaved.log" \
    > "$TMPDIR/compose-fcoe-wrong-result.log"
assert_cmd_failure "FCoE return code without the exact absence result fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-fcoe-wrong-result.log" \
        --report "$TMPDIR/compose-fcoe-wrong-result.json"

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-fcoe-missing-invocation.log"
tail -n 2 "$TMPDIR/compose-fcoe-interleaved.log" \
    >> "$TMPDIR/compose-fcoe-missing-invocation.log"
assert_cmd_failure "FCoE return code without its exact invocation fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-fcoe-missing-invocation.log" \
        --report "$TMPDIR/compose-fcoe-missing-invocation.json"

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-rhsm-interleaved.log"
printf '%s\n' \
    '18:00:00,005 WARNING org.fedoraproject.Anaconda.Modules.Subscription:INFO:program:Running... systemctl list-unit-files rhsm.service --no-legend' \
    >> "$TMPDIR/compose-rhsm-interleaved.log"
for sequence in $(seq -w 006 032); do
    printf '18:00:00,%s INFO systemd:bounded RHSM probe interleave fixture\n' \
        "$sequence" >> "$TMPDIR/compose-rhsm-interleaved.log"
done
printf '%s\n' \
    '18:00:00,033 WARNING org.fedoraproject.Anaconda.Modules.Subscription:DEBUG:program:Return code of systemctl: 1' \
    "18:00:00,034 WARNING org.fedoraproject.Anaconda.Modules.Subscription:DEBUG:anaconda.modules.subscription.initialization:subscription: The required rhsm systemd service is not available. The Subscription module won't be started." \
    >> "$TMPDIR/compose-rhsm-interleaved.log"
assert_cmd_success "bounded interleaving preserves the exact RHSM absence sequence" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-rhsm-interleaved.log" \
        --report "$TMPDIR/compose-rhsm-interleaved.json"
assert_cmd_success "interleaved RHSM fixture classifies the paired event once" \
    python3 - "$TMPDIR/compose-rhsm-interleaved.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["result"] == "pass"
assert document["counts"]["rhsm_service_probe"] == 1
PY

sed "s/The Subscription module won't be started\./The Subscription module entered an unreviewed state./" \
    "$TMPDIR/compose-rhsm-interleaved.log" \
    > "$TMPDIR/compose-rhsm-wrong-result.log"
assert_cmd_failure "RHSM return code without the exact disabled result fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-rhsm-wrong-result.log" \
        --report "$TMPDIR/compose-rhsm-wrong-result.json"

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-rhsm-missing-invocation.log"
tail -n 2 "$TMPDIR/compose-rhsm-interleaved.log" \
    >> "$TMPDIR/compose-rhsm-missing-invocation.log"
assert_cmd_failure "RHSM return code without its exact invocation fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-rhsm-missing-invocation.log" \
        --report "$TMPDIR/compose-rhsm-missing-invocation.json"

sed 's/permissive=1/permissive=0/' "$TMPDIR/compose-valid.log" \
    > "$TMPDIR/compose-enforcing-avc.log"
assert_cmd_failure "enforcing AVC cannot use the installer-permissive class" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-enforcing-avc.log" \
        --report "$TMPDIR/compose-enforcing-avc.json"

grep -v 'Module 99: Finalize COMPLETE' "$TMPDIR/compose-valid.log" \
    > "$TMPDIR/compose-missing-success.log"
assert_cmd_failure "missing exact M99 completion marker fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-missing-success.log" \
        --report "$TMPDIR/compose-missing-success.json"

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-tmux-interleaved.log"
printf '%s\n' \
    '18:00:00,005 NOTICE systemd:anaconda-tmux@tty1.service: Main process exited, code=exited, status=1/FAILURE' \
    '18:00:00,006 INFO multipathd:disable queueing (operator)' \
    '18:00:00,007 INFO multipathd:ok' \
    "18:00:00,008 WARNING systemd:anaconda-tmux@tty1.service: Failed with result 'exit-code'." \
    >> "$TMPDIR/compose-tmux-interleaved.log"
assert_cmd_success "bounded shutdown interleaving preserves the exact tmux pair" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-tmux-interleaved.log" \
        --report "$TMPDIR/compose-tmux-interleaved.json"
assert_cmd_success "interleaved tmux fixture classifies both paired events once" \
    python3 - "$TMPDIR/compose-tmux-interleaved.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["result"] == "pass"
assert document["counts"]["anaconda_tmux_shutdown_exit"] == 1
assert document["counts"]["anaconda_tmux_shutdown_result"] == 1
PY

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-tmux-too-far.log"
printf '%s\n' \
    '18:00:00,005 NOTICE systemd:anaconda-tmux@tty1.service: Main process exited, code=exited, status=1/FAILURE' \
    >> "$TMPDIR/compose-tmux-too-far.log"
for second in 006 007 008 009 010 011 012 013; do
    printf '18:00:00,%s INFO systemd:bounded shutdown interleave fixture\n' \
        "$second" >> "$TMPDIR/compose-tmux-too-far.log"
done
printf '%s\n' \
    "18:00:00,014 WARNING systemd:anaconda-tmux@tty1.service: Failed with result 'exit-code'." \
    >> "$TMPDIR/compose-tmux-too-far.log"
assert_cmd_failure "tmux result outside the bounded context still fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-tmux-too-far.log" \
        --report "$TMPDIR/compose-tmux-too-far.json"

cp "$TMPDIR/compose-valid.log" "$TMPDIR/compose-over-budget.log"
for second in 010 011 012; do
    printf '18:00:00,%s ERR rsyslogd:imfile: on startup file '\''/tmp/X.log'\'' does not exist but is configured in static file monitor - this may indicate a misconfiguration. If the file appears at a later time, it will automatically be processed. Reason: No such file or directory [v8.2510.0-3.fc44]\n' \
        "$second" >> "$TMPDIR/compose-over-budget.log"
done
assert_cmd_failure "reviewed event exceeding its explicit budget fails closed" \
    python3 "$LOG_AUDITOR" --policy "$LOG_POLICY" \
        --log "$TMPDIR/compose-over-budget.log" \
        --report "$TMPDIR/compose-over-budget.json"

python3 - "$LOG_POLICY" "$TMPDIR/compose-dracut-budget-one.json" <<'PY'
import json
import pathlib
import sys

source, target = map(pathlib.Path, sys.argv[1:])
policy = json.loads(source.read_text(encoding="utf-8"))
for event in policy["allowed_events"]:
    if event["id"] == "installer_dracut_module_traversal_avc":
        event["max_count"] = 1
        break
else:
    raise SystemExit("missing dracut traversal event")
target.write_text(json.dumps(policy), encoding="utf-8")
PY
assert_cmd_failure "dracut module traversal exceeding its separate budget fails closed" \
    python3 "$LOG_AUDITOR" --policy "$TMPDIR/compose-dracut-budget-one.json" \
        --log "$TMPDIR/compose-valid.log" \
        --report "$TMPDIR/compose-dracut-over-budget.json"

if command -v ksvalidator >/dev/null 2>&1; then
    assert_cmd_success "F44 pykickstart accepts the compose sources" \
        ksvalidator --version F44 "$KS_FILE"
else
    _fail "ksvalidator missing (required canonical-build dependency)"
fi

# Locale contract: helpers that parse translated tool output must pin and export
# a C locale, or they pass in the en_US.UTF-8 compose and fail closed on the
# twelve localized installations this image supports.
assert_file_executable "$LOCALE_CONTRACT" \
    "deployed-helper locale contract is executable"
assert_cmd_success "every locale-sensitive deployed helper pins an exported C locale" \
    python3 "$LOCALE_CONTRACT" "$PROJECT_ROOT"
LOCALE_FIXTURE="$TMPDIR/locale-fixture"
mkdir -p "$LOCALE_FIXTURE/kickstart/snippets"
{
    printf 'cat > /usr/local/bin/fixture <<%s\n' "'FIXTURE_EOF'"
    printf '#!/bin/bash\n'
    printf 'LC_ALL=C.UTF-8\n'
    printf '[ "$(stat -c %%F /tmp)" = directory ]\n'
    printf 'FIXTURE_EOF\n'
} > "$LOCALE_FIXTURE/kickstart/snippets/fixture.ks"
assert_cmd_failure "an unexported LC_ALL is rejected as a false green" \
    python3 "$LOCALE_CONTRACT" "$LOCALE_FIXTURE"
printf 'export LC_ALL\n' >> "$LOCALE_FIXTURE/kickstart/snippets/fixture.ks"
assert_cmd_failure "the fixture only passes once the export is inside the helper" \
    python3 "$LOCALE_CONTRACT" "$LOCALE_FIXTURE"
sed -i '/^LC_ALL=C.UTF-8$/d; s/$(stat /$(LC_ALL=C stat /' \
    "$LOCALE_FIXTURE/kickstart/snippets/fixture.ks"
assert_cmd_success "a command-local LC_ALL=C prefix pins the sensitive tool" \
    python3 "$LOCALE_CONTRACT" "$LOCALE_FIXTURE"
cat > "$LOCALE_FIXTURE/kickstart/snippets/fixture.ks" <<'LOCALE_ORDER_FIXTURE_EOF'
cat > /usr/local/bin/fixture <<'FIXTURE_EOF'
#!/bin/bash
[ "$(stat -c %F /tmp)" = directory ]
export LC_ALL=C.UTF-8
FIXTURE_EOF
LOCALE_ORDER_FIXTURE_EOF
assert_cmd_failure "a locale pin after the first sensitive use is rejected" \
    python3 "$LOCALE_CONTRACT" "$LOCALE_FIXTURE"
cat > "$LOCALE_FIXTURE/kickstart/snippets/fixture.ks" <<'LOCALE_NESTED_FIXTURE_EOF'
cat > /usr/local/bin/fixture <<'FIXTURE_EOF'
#!/bin/bash
[ "$(stat -c %F /tmp)" = directory ]
cat > /usr/local/bin/inner <<'INNER_EOF'
#!/bin/bash
export LC_ALL=C.UTF-8
INNER_EOF
FIXTURE_EOF
LOCALE_NESTED_FIXTURE_EOF
assert_cmd_failure "a nested heredoc cannot lend its locale pin to its writer" \
    python3 "$LOCALE_CONTRACT" "$LOCALE_FIXTURE"
cat > "$LOCALE_FIXTURE/kickstart/snippets/fixture.ks" <<'LOCALE_DEAD_FIXTURE_EOF'
cat > /usr/local/bin/fixture <<'FIXTURE_EOF'
#!/bin/bash
unused_setup() {
    export LC_ALL=C.UTF-8
}
[ "$(stat -c %F /tmp)" = directory ]
FIXTURE_EOF
LOCALE_DEAD_FIXTURE_EOF
assert_cmd_failure "an uncalled function cannot establish the helper locale" \
    python3 "$LOCALE_CONTRACT" "$LOCALE_FIXTURE"

# Sandbox path contract: ProtectSystem=strict leaves /run read-only inside the
# unit namespace, so a helper that opens a lock outside its ReadWritePaths dies
# at the redirection while `systemctl enable --now` has already recorded the
# unit as enabled -- a silently broken opt-in with a green GUI switch.
assert_file_executable "$SANDBOX_CONTRACT" \
    "sandboxed runtime-path contract is executable"
sandbox_contract_output=$(python3 "$SANDBOX_CONTRACT" "$PROJECT_ROOT") || \
    _fail "every sandboxed unit opens its runtime locks inside ReadWritePaths"
assert_eq \
    'sandbox path contract exact: 43 strict unit(s), 13 sandboxed runtime write(s) writable' \
    "$sandbox_contract_output" \
    "sandbox contract retains the complete deployed strict-unit/write inventory"
SANDBOX_FIXTURE="$TMPDIR/sandbox-fixture"
mkdir -p "$SANDBOX_FIXTURE/kickstart/snippets"
{
    printf 'cat > /etc/systemd/system/fixture.service <<%s\n' "'UNIT_EOF'"
    printf '[Service]\n'
    printf 'ProtectSystem=strict\n'
    printf 'ReadWritePaths=/run/noid-privacy\n'
    printf 'ExecStart=/usr/local/sbin/fixture-helper\n'
    printf 'UNIT_EOF\n'
    printf 'cat > /usr/local/sbin/fixture-helper <<%s\n' "'HELPER_EOF'"
    printf '#!/bin/bash\n'
    printf 'exec 9>/run/fixture-toggle.lock\n'
    printf 'HELPER_EOF\n'
    printf 'stage_root_file /etc/systemd/system/variable.service 0644 <<%s\n' "'VARIABLE_UNIT_EOF'"
    printf '[Service]\n'
    printf 'ProtectSystem=strict\n'
    printf 'ReadWritePaths=/run/noid-privacy\n'
    printf 'ExecStart=/usr/local/sbin/variable-helper\n'
    printf 'VARIABLE_UNIT_EOF\n'
    printf 'write_file /usr/local/bin/variable-helper 0755 <<%s\n' "'VARIABLE_HELPER_EOF'"
    printf '#!/bin/bash\n'
    printf 'LOCK=/run/variable-toggle.lock\n'
    printf 'exec 8>"$LOCK"\n'
    printf 'VARIABLE_HELPER_EOF\n'
    printf 'sudo tee /etc/systemd/system/tee.service >/dev/null <<%s\n' "'TEE_UNIT_EOF'"
    printf '[Service]\n'
    printf 'ProtectSystem=strict\n'
    printf 'ReadWritePaths=/run/noid-privacy\n'
    printf 'ExecStart=/usr/local/sbin/tee-helper\n'
    printf 'TEE_UNIT_EOF\n'
    printf 'publish_root_file /usr/local/sbin/tee-helper 0755 <<%s\n' "'TEE_HELPER_EOF'"
    printf '#!/bin/bash\n'
    printf 'TEE_LOCK=/run/noid-privacy/tee.lock\n'
    printf 'exec 7>"$TEE_LOCK"\n'
    printf 'TEE_HELPER_EOF\n'
} > "$SANDBOX_FIXTURE/kickstart/snippets/fixture.ks"
assert_cmd_failure "a lock outside the writable set is rejected" \
    python3 "$SANDBOX_CONTRACT" "$SANDBOX_FIXTURE"
sed -i 's#exec 9>/run/fixture-toggle.lock#exec 9>/run/noid-privacy/fixture-toggle.lock#' \
    "$SANDBOX_FIXTURE/kickstart/snippets/fixture.ks"
assert_cmd_failure "a variable lock from stage_root_file remains visible" \
    python3 "$SANDBOX_CONTRACT" "$SANDBOX_FIXTURE"
sed -i 's#LOCK=/run/variable-toggle.lock#LOCK=/run/noid-privacy/variable-toggle.lock#' \
    "$SANDBOX_FIXTURE/kickstart/snippets/fixture.ks"
sandbox_fixture_output=$(python3 "$SANDBOX_CONTRACT" "$SANDBOX_FIXTURE") || \
    _fail "fixture passes once every runtime write moves inside ReadWritePaths"
assert_eq \
    'sandbox path contract exact: 3 strict unit(s), 3 sandboxed runtime write(s) writable' \
    "$sandbox_fixture_output" \
    "cat, stage_root_file, write_file, sudo tee, publish_root_file and bin/sbin aliases are audited"

# --- ERR traps must actually be inherited by functions ----------------------
# bash propagates an ERR trap into a function body only under `set -E`. Both
# shipped traps lacked it, so a rollback and an exit-code remapping that both
# review as armed did nothing for a failure inside a function -- which is where
# their guarded work lives.
assert_file_executable "$ERRTRACE_CONTRACT" \
    "errtrace contract is executable"
assert_cmd_success "every ERR trap is armed under errtrace" \
    python3 "$ERRTRACE_CONTRACT" "$PROJECT_ROOT"
ERRTRACE_FIXTURE="$TMPDIR/errtrace-fixture"
mkdir -p "$ERRTRACE_FIXTURE"
{
    printf '#!/bin/bash\n'
    printf 'set -euo pipefail\n'
    printf 'work() { /bin/false; }\n'
    printf 'trap rollback ERR\n'
    printf 'work\n'
} > "$ERRTRACE_FIXTURE/fixture.sh"
assert_cmd_failure "an ERR trap without errtrace is rejected" \
    python3 "$ERRTRACE_CONTRACT" "$ERRTRACE_FIXTURE"
sed -i 's/^set -euo pipefail$/set -Eeuo pipefail/' "$ERRTRACE_FIXTURE/fixture.sh"
assert_cmd_success "the same fixture passes once errtrace is enabled" \
    python3 "$ERRTRACE_CONTRACT" "$ERRTRACE_FIXTURE"
printf '#!/bin/bash\nset -euo pipefail\nset -o errtrace\ntrap rollback ERR\n' \
    > "$ERRTRACE_FIXTURE/fixture.sh"
assert_cmd_success "the long errtrace option is accepted" \
    python3 "$ERRTRACE_CONTRACT" "$ERRTRACE_FIXTURE"
printf '#!/bin/bash\nset -euo pipefail\nset -E\ntrap rollback ERR\n' \
    > "$ERRTRACE_FIXTURE/fixture.sh"
assert_cmd_success "a standalone short errtrace option is accepted" \
    python3 "$ERRTRACE_CONTRACT" "$ERRTRACE_FIXTURE"
# Disarming is not an installation and must not be flagged.
printf '#!/bin/bash\nset -euo pipefail\ntrap - ERR\n' > "$ERRTRACE_FIXTURE/fixture.sh"
assert_cmd_success "disarming an ERR trap is not an unprotected installation" \
    python3 "$ERRTRACE_CONTRACT" "$ERRTRACE_FIXTURE"
printf '#!/bin/bash\nset -euo pipefail\ntrap rollback ERR  # armed\n' \
    > "$ERRTRACE_FIXTURE/fixture.sh"
assert_cmd_failure "a trailing comment cannot hide an unprotected ERR trap" \
    python3 "$ERRTRACE_CONTRACT" "$ERRTRACE_FIXTURE"
ERRTRACE_SCOPE_FIXTURE="$TMPDIR/errtrace-scope-fixture"
mkdir -p "$ERRTRACE_SCOPE_FIXTURE/kickstart/snippets"
cat > "$ERRTRACE_SCOPE_FIXTURE/kickstart/snippets/fixture.ks" <<'ERRTRACE_SCOPE_EOF'
%post
set -euo pipefail
cat > /usr/local/bin/inner <<'INNER_EOF'
#!/bin/bash
set -Eeuo pipefail
trap inner_rollback ERR
INNER_EOF
trap outer_rollback ERR
%end
ERRTRACE_SCOPE_EOF
assert_cmd_failure "an embedded script cannot lend errtrace to its writer" \
    python3 "$ERRTRACE_CONTRACT" "$ERRTRACE_SCOPE_FIXTURE"
sed -i 's/^set -euo pipefail$/set -Eeuo pipefail/' \
    "$ERRTRACE_SCOPE_FIXTURE/kickstart/snippets/fixture.ks"
assert_cmd_success "independent outer and embedded errtrace scopes pass" \
    python3 "$ERRTRACE_CONTRACT" "$ERRTRACE_SCOPE_FIXTURE"
ERRTRACE_GIT_FIXTURE="$TMPDIR/errtrace-git-fixture"
mkdir -p "$ERRTRACE_GIT_FIXTURE"
git -C "$ERRTRACE_GIT_FIXTURE" init -q
printf '#!/bin/bash\nset -Eeuo pipefail\ntrap rollback ERR\n' \
    > "$ERRTRACE_GIT_FIXTURE/tracked.sh"
git -C "$ERRTRACE_GIT_FIXTURE" add tracked.sh
printf '#!/bin/bash\nset -euo pipefail\ntrap rollback ERR\n' \
    > "$ERRTRACE_GIT_FIXTURE/ignored-scratch.sh"
assert_cmd_success "untracked scratch cannot enter the tracked-source contract" \
    python3 "$ERRTRACE_CONTRACT" "$ERRTRACE_GIT_FIXTURE"

# --- a consumer may not out-strict the layer that owns a boundary -----------
# M03 owns the XDP/TC boundary and exits 0 for every DEGRADED reason when no
# LAN peer requires XDP. M04 only reads that health to decide whether the
# readiness marker may be published, which is what lets chrony come online, so
# refusing a reason M03 waved through does not repair anything -- it just stops
# the clock on hardware M03 already declared survivable.
assert_file_executable "$DEGRADATION_CONTRACT" \
    "boundary degradation contract is executable"
assert_cmd_success "every published boundary state is handled by its consumer" \
    python3 "$DEGRADATION_CONTRACT" "$PROJECT_ROOT"
DEGRADATION_FIXTURE="$TMPDIR/degradation-fixture"
mkdir -p "$DEGRADATION_FIXTURE/kickstart/snippets"
cp "$PROJECT_ROOT/kickstart/snippets/03-firewalld.ks" \
   "$PROJECT_ROOT/kickstart/snippets/04-arp-hardening.ks" \
   "$DEGRADATION_FIXTURE/kickstart/snippets/"
sed -i "/'STATE=DEGRADED:DETAIL=controller-missing'/d" \
    "$DEGRADATION_FIXTURE/kickstart/snippets/04-arp-hardening.ks"
assert_cmd_failure "a consumer that refuses a published state is rejected" \
    python3 "$DEGRADATION_CONTRACT" "$DEGRADATION_FIXTURE"
cp "$PROJECT_ROOT/kickstart/snippets/04-arp-hardening.ks" \
   "$DEGRADATION_FIXTURE/kickstart/snippets/"
assert_cmd_success "the same fixture passes once the state is handled again" \
    python3 "$DEGRADATION_CONTRACT" "$DEGRADATION_FIXTURE"
sed -i "/'STATE=ACTIVE:DETAIL=verified')/,/;;/ s/return 0/return 1/" \
    "$DEGRADATION_FIXTURE/kickstart/snippets/04-arp-hardening.ks"
assert_cmd_failure "an accepted label whose own branch returns failure is rejected" \
    python3 "$DEGRADATION_CONTRACT" "$DEGRADATION_FIXTURE"
cp "$PROJECT_ROOT/kickstart/snippets/04-arp-hardening.ks" \
   "$DEGRADATION_FIXTURE/kickstart/snippets/"
assert_cmd_success "the same fixture passes once the branch succeeds again" \
    python3 "$DEGRADATION_CONTRACT" "$DEGRADATION_FIXTURE"
# A newly declared producer state must fail the build, not the clock.
sed -i 's/^        verified|controller-missing|sync-or-postcheck-failed|\\$/        verified|controller-missing|sync-or-postcheck-failed|newly-added|\\/' \
    "$DEGRADATION_FIXTURE/kickstart/snippets/03-firewalld.ks"
assert_cmd_failure "a new producer state cannot slip past the consumer" \
    python3 "$DEGRADATION_CONTRACT" "$DEGRADATION_FIXTURE"
cp "$PROJECT_ROOT/kickstart/snippets/03-firewalld.ks" \
   "$DEGRADATION_FIXTURE/kickstart/snippets/"
sed -i '/case "$detail" in/a\        # closed six-value vocabulary' \
    "$DEGRADATION_FIXTURE/kickstart/snippets/03-firewalld.ks"
assert_cmd_success "comments inside the producer case are not vocabulary" \
    python3 "$DEGRADATION_CONTRACT" "$DEGRADATION_FIXTURE"
sed -i 's/case "$state" in ACTIVE|DEGRADED)/case "$state" in ACTIVE|DEGRADED|FAILED)/' \
    "$DEGRADATION_FIXTURE/kickstart/snippets/03-firewalld.ks"
sed -i '/publish_xdp_health DEGRADED controller-missing/a\        publish_xdp_health FAILED controller-missing' \
    "$DEGRADATION_FIXTURE/kickstart/snippets/03-firewalld.ks"
assert_cmd_failure "a newly declared state axis cannot evade extraction" \
    python3 "$DEGRADATION_CONTRACT" "$DEGRADATION_FIXTURE"

# --- build gates may only grep for strings their heredoc actually ships ------
# Moving a function between two shipped scripts updates the heredocs and the
# 99-finalize mirror, and silently leaves the module's own older verification
# block greping the file the code left. That costs the entire compose:
# `%post --erroronfail` aborts on the first failed gate and no ISO is produced.
# Both halves are in this tree, so the agreement is checkable before a build.
assert_file_executable "$GATE_LITERAL_CONTRACT" \
    "build-gate literal contract is executable"
assert_cmd_success "every build-gate literal exists in the heredoc that ships it" \
    python3 "$GATE_LITERAL_CONTRACT" "$PROJECT_ROOT"
GATE_FIXTURE="$TMPDIR/gate-literal-fixture"
mkdir -p "$GATE_FIXTURE/kickstart/snippets"
cp "$PROJECT_ROOT/kickstart/snippets/12-selinux-auditd.ks" \
   "$GATE_FIXTURE/kickstart/snippets/"
# Reinstate the exact staleness that would abort every compose: assert a
# delivery-side literal against the plugin the delivery code moved out of.
sed -i "s|&& grep -qF 'def queue_notification' /usr/local/bin/audit-notify.sh|\&\& grep -qF 'LockedHint' /usr/local/bin/audit-notify.sh|" \
    "$GATE_FIXTURE/kickstart/snippets/12-selinux-auditd.ks"
assert_cmd_failure "a gate greping a string its own heredoc lost is rejected" \
    python3 "$GATE_LITERAL_CONTRACT" "$GATE_FIXTURE"
cp "$PROJECT_ROOT/kickstart/snippets/12-selinux-auditd.ks" \
   "$GATE_FIXTURE/kickstart/snippets/"
assert_cmd_success "the same fixture passes once the gate names a live invariant" \
    python3 "$GATE_LITERAL_CONTRACT" "$GATE_FIXTURE"

# --- test scratch must never become repository content ----------------------
# Several structural tests deliberately place their working tree inside the
# checkout. .gitignore covers the pattern, but a `git add -A` issued while such
# a run was in flight once committed 28 scratch files, so assert the tracked
# set directly rather than trusting the ignore rule to have been present.
tracked_scratch=$(git -C "$PROJECT_ROOT" ls-files -- '.test-*' | head -5)
assert_eq "" "$tracked_scratch" \
    "no test scratch tree is tracked in the repository"
assert_grep_fixed '.test-*/' "$PROJECT_ROOT/.gitignore" \
    "test scratch trees are ignored by pattern"
unset tracked_scratch

test_finish

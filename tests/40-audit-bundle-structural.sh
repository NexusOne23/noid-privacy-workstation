#!/bin/bash
# 40-audit-bundle-structural — verify the bundled root audit stays pinned and
# cannot replace itself from an unauthenticated mutable network response.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/40-audit-bundle.ks"

test_start "40-audit-bundle-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
SECURITY_POLICY="$PROJECT_ROOT/SECURITY.md"
assert_file_exists "$SECURITY_POLICY" "repository security policy exists"
assert_grep_fixed '| `main` (v1.7 release line) | :white_check_mark: (active maintained line) |' \
    "$SECURITY_POLICY" \
    "security policy identifies main as the active maintained release line"
assert_grep_fixed '| v1.7 | :white_check_mark: (current Fedora 44 release line) |' \
    "$SECURITY_POLICY" \
    "security policy names the current supported release line"
assert_cmd_failure "security policy does not retire the current supported release" \
    grep -qF -- '| v1.7 and older |' "$SECURITY_POLICY"
assert_grep_fixed 'v1.7/Fedora 44 release and the `main` release line' \
    "$SECURITY_POLICY" \
    "security policy scopes support to the maintained release lines"
COMPARISON_DOC="$PROJECT_ROOT/docs/comparison.md"
assert_file_exists "$COMPARISON_DOC" "repository comparison document exists"
assert_grep_fixed 'Peer-project facts were checked against project-controlled sources on' \
    "$COMPARISON_DOC" \
    "comparison document scopes its peer-project snapshot"
assert_grep_fixed '**2026-07-29**. The NoID Privacy Workstation row was refreshed against the' \
    "$COMPARISON_DOC" \
    "comparison document separates the peer and local verification dates"
assert_grep_fixed 'local v1.7 release source on **2026-08-23**:' \
    "$COMPARISON_DOC" \
    "comparison document dates the current local release-source review"
assert_grep_fixed '| NoID Privacy Workstation | local v1.7 release source |' \
    "$COMPARISON_DOC" \
    "comparison document identifies the local v1.7 release source"
assert_grep_fixed 'Release qualification binds the exact source commit, ISO digest, signature and required evidence;' \
    "$COMPARISON_DOC" \
    "comparison document retains the exact-byte release boundary"
assert_not_grep_extended 'v1\.7 (development|is not (published|released))' \
    "$SECURITY_POLICY" \
    "security policy has no stale v1.7 pre-release label"
assert_not_grep_extended 'v1\.7 (development|is not (published|released))' \
    "$COMPARISON_DOC" \
    "comparison document has no stale v1.7 pre-release label"
assert_grep_fixed '| Kicksecure | stable LXQt ISO 18.2.1.9;' \
    "$COMPARISON_DOC" \
    "comparison document records the current project-published Kicksecure ISO"
assert_not_grep 'v1\.x\.x' "$SECURITY_POLICY" \
    "security policy has no generic stale active-version placeholder"
assert_not_grep 'end-to-end-encrypted' "$SECURITY_POLICY" \
    "GitHub private reporting is not mislabeled as E2E encryption"
assert_grep_fixed 'privately-reporting-a-security-vulnerability' "$SECURITY_POLICY" \
    "GitHub confidentiality wording links to maintained official documentation"
assert_grep_fixed 'M40 **NoID Privacy for Linux** auditor payload' \
    "$SECURITY_POLICY" "supply-chain inventory includes the M40 payload"
assert_grep_fixed 'any repository-owned source, configuration,' \
    "$SECURITY_POLICY" "security scope covers every repository-owned surface"
assert_grep_fixed 'stages the auditor byte-for-byte from a public raw URL containing its full,' \
    "$SECURITY_POLICY" "security policy describes the public M40 source boundary"
assert_grep_fixed 'from an exact clean checkout.' "$SECURITY_POLICY" \
    "security policy retains the controlled offline source boundary"
assert_cmd_failure "security policy does not claim the retired M40 patch stack" \
    grep -qF -- 'reviewed downstream patch stack' "$SECURITY_POLICY"
assert_grep_fixed 'A digest proves that the bytes match the reviewed selection' \
    "$SECURITY_POLICY" "digest claim is scoped to byte identity"
assert_not_grep '`\*\.noid1` RPM)' "$SECURITY_POLICY" \
    "Mutter supply-chain description has no stray parenthesis"
assert_grep_extended '^NOID_AUDIT_VERSION="v[0-9]+\.[0-9]+\.[0-9]+"$' "$KS_FILE"
assert_grep_extended '^NOID_AUDIT_COMMIT="[a-f0-9]{40}"$' "$KS_FILE"
assert_grep_extended '^NOID_AUDIT_SIZE="[1-9][0-9]*"$' "$KS_FILE"
assert_grep_extended '^NOID_AUDIT_SHA256="[a-f0-9]{64}"$' "$KS_FILE"
assert_grep_fixed 'ACTUAL_SIZE=$(stat -c %s "$AUDIT_CANDIDATE")' "$KS_FILE" \
    "install-time audit payload byte-count verification exists"
assert_grep_fixed 'ACTUAL_SHA=$(sha256sum "$AUDIT_CANDIDATE"' "$KS_FILE" \
    "install-time audit payload digest verification exists"
assert_grep_fixed '--output "$AUDIT_CANDIDATE" "$NOID_AUDIT_URL"' "$KS_FILE" \
    "download cannot truncate the installed root-executed payload"
assert_grep_fixed \
    'publish_root_file "$AUDIT_CANDIDATE" "$NOID_AUDIT_DEST" 0755' \
    "$KS_FILE" "validated audit payload is atomically published"
assert_grep_fixed \
    'publish_root_file "$VERSION_CANDIDATE" /etc/noid/audit-version 0644' \
    "$KS_FILE" "validated version marker is atomically published"
assert_grep_fixed \
    'publish_root_file "$WRAPPER_CANDIDATE" /usr/local/bin/noid-audit 0755' \
    "$KS_FILE" "validated wrapper is atomically published"
assert_grep_fixed \
    'publish_root_file "$STAMP_CANDIDATE" "$STAMP" 0644' \
    "$KS_FILE" "fresh health evidence is atomically published last"
assert_not_grep 'cat > /usr/local/bin/noid-audit' "$KS_FILE" \
    "wrapper is never truncated in place"
assert_not_grep 'cat > /etc/noid/audit-version' "$KS_FILE" \
    "version marker is never truncated in place"
assert_not_grep 'cat > "$STAMP"' "$KS_FILE" \
    "health evidence is never truncated in place"
assert_not_grep 'api.github.com' "$KS_FILE" \
    "wrapper has no mutable GitHub API self-update"
assert_not_grep 'raw.githubusercontent.com' "$KS_FILE" \
    "wrapper has no raw-script self-update"
assert_not_grep 'cmd_update' "$KS_FILE" \
    "TLS-only root script replacement is absent"
assert_grep_fixed 'self-update is disabled' "$KS_FILE" \
    "legacy --update request fails closed"
assert_grep_fixed 'audit-version template substitution failed — comment lines empty (regression)' \
    "$KS_FILE" "template corruption detector exists"
assert_cmd_success "template corruption detector aborts the build" \
    awk '/audit-version template substitution failed — comment lines empty/ {
             if ((getline next_line) > 0 && next_line ~ /^[[:space:]]*exit 1[[:space:]]*$/) ok=1
             exit
         }
         END { exit(ok ? 0 : 1) }' "$KS_FILE"

BUILD_SCRIPT="$PROJECT_ROOT/scripts/build-iso.sh"
SUPPORT_BUILDER="$PROJECT_ROOT/scripts/build-audit-support-media.sh"
CI_WORKFLOW="$PROJECT_ROOT/.github/workflows/ci.yml"
RUN_ALL="$PROJECT_ROOT/tests/run-all.sh"
assert_cmd_success "retired noid-audit downstream patch directory has no files" \
    bash -c '[ -z "$(find "$1" -mindepth 1 -type f -print -quit 2>/dev/null)" ]' \
    _ "$PROJECT_ROOT/overrides/noid-audit"
assert_not_grep 'audit_patches\|runtime-accuracy\|bounded-local-evidence' \
    "$BUILD_SCRIPT" "build stage never modifies the exact public auditor"
assert_grep_extended '^[[:space:]]+local source_commit="[a-f0-9]{40}"$' \
    "$BUILD_SCRIPT" "build stage pins a reviewed public commit"
assert_grep_fixed 'local source_url="https://raw.githubusercontent.com/NexusOne23/noid-privacy-linux/${source_commit}/noid-privacy-linux.sh"' \
    "$BUILD_SCRIPT" "build stage uses the immutable public commit URL"
assert_grep_fixed "--proto '=https' --proto-redir '=https' --tlsv1.2" \
    "$BUILD_SCRIPT" "public audit fetch cannot downgrade from HTTPS"
assert_grep_fixed '--output "$audit_candidate" "$source_url"' \
    "$BUILD_SCRIPT" "public audit fetch writes only the private staging candidate"
assert_grep_extended '^[[:space:]]+local expected_size="[1-9][0-9]*"$' \
    "$BUILD_SCRIPT" "build stage pins the reviewed byte count"
assert_grep_extended '^[[:space:]]+local expected_sha="[a-f0-9]{64}"$' \
    "$BUILD_SCRIPT" "build stage pins the reviewed digest"
assert_grep_extended "^AUDITOR_SOURCE_COMMIT='[a-f0-9]{40}'$" \
    "$SUPPORT_BUILDER" "offline support media pins a sibling-repository commit"
assert_grep_extended "^AUDITOR_SOURCE_SIZE='[1-9][0-9]*'$" \
    "$SUPPORT_BUILDER" "offline support media pins a byte count"
assert_grep_extended "^AUDITOR_SOURCE_SHA256='[a-f0-9]{64}'$" \
    "$SUPPORT_BUILDER" "offline support media pins a source digest"
assert_grep_fixed 'id: audit-pin' "$CI_WORKFLOW" \
    "CI derives the auditor checkout from the canonical M40 pin"
assert_grep_fixed 'repository: NexusOne23/noid-privacy-linux' "$CI_WORKFLOW" \
    "CI checks out the required auditor sibling"
assert_grep_fixed 'ref: ${{ steps.audit-pin.outputs.commit }}' "$CI_WORKFLOW" \
    "CI auditor checkout uses the derived exact commit"
assert_grep_fixed 'path: noid-privacy-fedora' "$CI_WORKFLOW" \
    "CI places the primary source in its own workspace child"
assert_cmd_success "CI pin extraction and structural suite run inside the primary source" \
    awk '
        /^[[:space:]]*- name: Read exact M40 auditor source pin$/ {
            step="pin"
            next
        }
        /^[[:space:]]*- name: Run all structural tests$/ {
            step="suite"
            next
        }
        /^[[:space:]]*- (name:|uses:)/ {
            step=""
        }
        step == "pin" && $0 == "        working-directory: noid-privacy-fedora" {
            pin=1
        }
        step == "suite" && $0 == "        working-directory: noid-privacy-fedora" {
            suite=1
        }
        END {
            exit(pin && suite ? 0 : 1)
        }
    ' "$CI_WORKFLOW"
assert_grep_fixed 'NOID_AUDIT_SRC: ${{ github.workspace }}/noid-privacy-linux/noid-privacy-linux.sh' \
    "$CI_WORKFLOW" "CI supplies the exact sibling path to the structural suite"
assert_grep_fixed \
    'for tool in aide base64 bwrap checkmodule clang dconf' \
    "$RUN_ALL" "full source suite begins the exact mandatory BPF/tool preflight"
assert_grep_fixed \
    'desktop-file-validate git gsettings jq ksvalidator patch' \
    "$RUN_ALL" "full source suite includes parser and SELinux prerequisites"
assert_grep_fixed \
    'python3 semodule_package sha256sum setfacl shellcheck strip' \
    "$RUN_ALL" "full source suite includes BPF and SELinux build prerequisites"
assert_grep_fixed \
    'systemd-analyze systemd-tmpfiles udevadm' \
    "$RUN_ALL" "full source suite includes systemd validation prerequisites"
assert_grep_fixed \
    'usbguard usbguard-notifier visudo; do' \
    "$RUN_ALL" "full source suite closes USBGuard and sudo parser prerequisites"
assert_grep_fixed "python3 -c 'import auparse'" "$RUN_ALL" \
    "full source suite preflights the audit Python binding"
assert_grep_fixed '/usr/include/bpf/bpf_helpers.h' "$RUN_ALL" \
    "full source suite preflights the libbpf development header"
assert_grep_fixed '/usr/include/linux/bpf.h' "$RUN_ALL" \
    "full source suite preflights the Linux UAPI BPF header"
assert_grep_fixed \
    'for schema in org.gnome.system.wsdd org.gnome.system.dns_sd; do' \
    "$RUN_ALL" "full source suite preflights its mandatory GSettings schemas"
assert_grep_fixed 'ERROR: full-suite prerequisites missing:' \
    "$RUN_ALL" "missing audit tools fail once as a named harness error"
assert_cmd_success "semantic CI job uses Fedora 44 and installs its exact prerequisites" \
    awk '
        /^  tests:$/ {
            in_tests=1
            seen_tests=1
            next
        }
        in_tests && /^  [[:alnum:]_-]+:$/ {
            in_tests=0
        }
        in_tests && $0 == "    container: fedora:44" {
            container=1
        }
        in_tests && $0 == "        shell: bash" {
            shell=1
        }
        in_tests && /dnf install -y git ShellCheck aide acl bubblewrap checkpolicy dconf desktop-file-utils/ {
            packages_a=1
        }
        in_tests && /glib2 gvfs jq pykickstart patch policycoreutils python3 python3-audit sudo systemd/ {
            packages_b=1
        }
        in_tests && /systemd-udev usbguard usbguard-notifier clang libbpf-devel kernel-headers binutils/ {
            packages_c=1
        }
        END {
            exit(seen_tests && container && shell && packages_a && packages_b && packages_c ? 0 : 1)
        }
    ' "$CI_WORKFLOW"
assert_cmd_success "every CI checkout discards its persisted credential" \
    awk '
        function close_checkout() {
            if (checkout && !secured) bad=1
            checkout=0
            secured=0
        }
        /^[[:space:]]*-[[:space:]]+(name:|uses:)/ {
            close_checkout()
        }
        /uses:[[:space:]]+actions\/checkout@/ {
            checkout=1
            next
        }
        checkout && /persist-credentials:[[:space:]]+false/ {
            secured=1
        }
        END {
            close_checkout()
            exit(bad ? 1 : 0)
        }
    ' "$CI_WORKFLOW"
ks_sha=$(sed -n 's/^NOID_AUDIT_SHA256="\([a-f0-9]\{64\}\)"$/\1/p' "$KS_FILE")
ks_version=$(sed -n 's/^NOID_AUDIT_VERSION="\([^"]*\)"$/\1/p' "$KS_FILE")
ks_commit=$(sed -n 's/^NOID_AUDIT_COMMIT="\([a-f0-9]\{40\}\)"$/\1/p' "$KS_FILE")
ks_size=$(sed -n 's/^NOID_AUDIT_SIZE="\([0-9]*\)"$/\1/p' "$KS_FILE")
build_sha=$(awk '
    /^stage_noid_audit\(\)/ {inside=1}
    inside && /local expected_sha=/ {
        value=$0
        sub(/^.*local expected_sha="/, "", value)
        sub(/".*$/, "", value)
        print value
        exit
    }
' "$BUILD_SCRIPT")
build_version=$(awk '
    /^stage_noid_audit\(\)/ {inside=1}
    inside && /local version=/ {
        value=$0
        sub(/^.*local version="/, "", value)
        sub(/".*$/, "", value)
        print value
        exit
    }
' "$BUILD_SCRIPT")
build_commit=$(awk '
    /^stage_noid_audit\(\)/ {inside=1}
    inside && /local source_commit=/ {
        value=$0
        sub(/^.*local source_commit="/, "", value)
        sub(/".*$/, "", value)
        print value
        exit
    }
' "$BUILD_SCRIPT")
build_size=$(awk '
    /^stage_noid_audit\(\)/ {inside=1}
    inside && /local expected_size=/ {
        value=$0
        sub(/^.*local expected_size="/, "", value)
        sub(/".*$/, "", value)
        print value
        exit
    }
' "$BUILD_SCRIPT")
support_commit=$(sed -n \
    "s/^AUDITOR_SOURCE_COMMIT='\\([a-f0-9]\\{40\\}\\)'$/\\1/p" \
    "$SUPPORT_BUILDER")
support_size=$(sed -n \
    "s/^AUDITOR_SOURCE_SIZE='\\([0-9][0-9]*\\)'$/\\1/p" \
    "$SUPPORT_BUILDER")
support_sha=$(sed -n \
    "s/^AUDITOR_SOURCE_SHA256='\\([a-f0-9]\\{64\\}\\)'$/\\1/p" \
    "$SUPPORT_BUILDER")
assert_eq "$ks_sha" "$build_sha" \
    "build-stage and install-stage exact auditor digests match"
assert_eq "$ks_version" "$build_version" \
    "build-stage and install-stage exact auditor versions match"
assert_eq "$ks_commit" "$build_commit" \
    "build-stage and install-stage exact auditor commits match"
assert_eq "$ks_size" "$build_size" \
    "build-stage and install-stage exact auditor byte counts match"
assert_eq "$ks_commit" "$support_commit" \
    "support-media and install-stage exact auditor commits match"
assert_eq "$ks_size" "$support_size" \
    "support-media and install-stage exact auditor byte counts match"
assert_eq "$ks_sha" "$support_sha" \
    "support-media and install-stage exact auditor digests match"
assert_grep_fixed "git -C ../noid-privacy-linux checkout $ks_commit" \
    "$PROJECT_ROOT/README.md" \
    "README source-test setup checks out the canonical auditor commit"
assert_grep_fixed "readonly SCRIPT_SIZE=\"$ks_size\"" "$KS_FILE" \
    "runtime wrapper byte-count pin matches the install pin"
assert_grep_fixed "readonly SCRIPT_SHA256=\"$ks_sha\"" "$KS_FILE" \
    "runtime wrapper digest pin matches the install pin"
assert_grep_fixed 'locally patched security auditor with the byte-identical' \
    "$PROJECT_ROOT/CHANGELOG.md" \
    "release highlights name the shipped public-auditor transition"
assert_grep_fixed 'reviewed public `v3.7.1` payload' \
    "$PROJECT_ROOT/CHANGELOG.md" \
    "release highlights name the shipped auditor version"
assert_grep_fixed 'immutable Git commit URL and independently enforces commit, byte count and' \
    "$PROJECT_ROOT/CHANGELOG.md" \
    "release highlights identify the public exact-pin trust contract"
assert_grep_fixed 'non-remediating-by-default Bash posture audit with explicit evidence-capture opt-ins' \
    "$PROJECT_ROOT/README.md" \
    "ecosystem table distinguishes the default audit from explicit evidence capture"
assert_grep_fixed 'offline and non-remediating by default; ordinary service/access logging can still occur.' \
    "$PROJECT_ROOT/INDEX.md" \
    "module index states the default boundary without denying ordinary logs"
assert_grep_fixed 'Explicit evidence-capture flags remain separate operator actions.' \
    "$PROJECT_ROOT/INDEX.md" \
    "module index preserves the explicit upstream evidence workflow"
assert_grep_fixed '        --update)' "$KS_FILE" \
    "legacy --update is rejected in every argument position"
assert_grep_fixed 'STAMP=/var/lib/noid-privacy/stamp-40-audit-bundle.ok' \
    "$KS_FILE" "M40 health-stamp path is stable"
assert_grep_fixed 'audit_version=$NOID_AUDIT_VERSION' "$KS_FILE" \
    "M40 stamp records the reviewed auditor version"
assert_grep_fixed 'audit_commit=$NOID_AUDIT_COMMIT' "$KS_FILE" \
    "M40 stamp records the reviewed auditor commit"
assert_grep_fixed 'audit_size=$NOID_AUDIT_SIZE' "$KS_FILE" \
    "M40 stamp records the reviewed auditor byte count"
assert_grep_fixed 'audit_sha256=$NOID_AUDIT_SHA256' "$KS_FILE" \
    "M40 stamp records the verified auditor digest"
assert_grep_fixed 'version_marker_sha256=$VERSION_MARKER_SHA256' "$KS_FILE" \
    "M40 stamp records the exact version-marker digest"
assert_grep_fixed 'wrapper_sha256=$WRAPPER_SHA256' "$KS_FILE" \
    "M40 stamp records the exact wrapper digest"
assert_not_grep 'seventh adopter\|eighth adopter' "$KS_FILE" \
    "M40 health-stamp documentation carries no drifting adopter ordinal"
assert_grep_fixed 'audit_version + audit_commit + audit_size + audit_sha256 +' \
    "$KS_FILE" "M40 health-stamp documentation names every extension"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h'" "$KS_FILE" \
    "M40 verifies exact ownership, mode and link count"
assert_grep_fixed 'readonly SUDO="/usr/bin/sudo"' "$KS_FILE" \
    "root authorization never resolves sudo through the caller PATH"
assert_grep_fixed \
    'exec "$SUDO" -- "$ENV_BIN" "${root_environment[@]}" "$BASH_BIN" "$SCRIPT" "$@"' \
    "$KS_FILE" \
    "root audit execution uses closed binaries and a sanitized environment"
assert_grep_fixed 'Ambient NOID_* evidence variables are deliberately ignored.' \
    "$KS_FILE" "wrapper documents ambient opt-in rejection"
assert_grep_fixed \
    '--aide-live           fresh AIDE check only; never creates/replaces its baseline' \
    "$KS_FILE" "wrapper documents the AIDE check-only boundary"
assert_grep_fixed 'local -a root_environment=(-i' "$KS_FILE" \
    "wrapper starts the root auditor with an empty environment"
for assignment in HOME=/root USER=root LOGNAME=root SHELL=/bin/bash \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C; do
    assert_grep_fixed "$assignment" "$KS_FILE" \
        "wrapper adds only a canonical root environment value: $assignment"
done
assert_grep_fixed 'root_environment+=(NOID_AIDE_LIVE=1)' "$KS_FILE" \
    "wrapper forwards only the exact explicit AIDE opt-in"
assert_grep_fixed 'root_environment+=(NOID_RPM_BASELINE_INIT=1)' "$KS_FILE" \
    "wrapper forwards only the exact explicit RPM-init opt-in"
assert_grep_fixed 'root_environment+=(NOID_RPM_BASELINE_UPDATE=1)' "$KS_FILE" \
    "wrapper forwards only the exact explicit RPM-update opt-in"
assert_grep_fixed 'trusted_script() {' "$KS_FILE" \
    "wrapper revalidates the root-executed payload before every run"
assert_grep_fixed 'trusted_root_dir() {' "$KS_FILE" \
    "wrapper validates each root-owned payload parent"
assert_grep_fixed '"$READLINK" -e -- "$SCRIPT"' "$KS_FILE" \
    "wrapper binds the canonical auditor path"
assert_grep_fixed '"$MATCHPATHCON" -V "$SCRIPT"' "$KS_FILE" \
    "wrapper binds the auditor SELinux label"
assert_grep_fixed 'VERSION_MAX_BYTES="4096"' "$KS_FILE" \
    "wrapper bounds the root-owned version marker"
assert_grep_fixed 'failed its pinned identity check' "$KS_FILE" \
    "runtime payload drift fails closed visibly"
assert_not_grep 'restorecon .*2>/dev/null || true' "$KS_FILE" \
    "M40 does not hide SELinux relabel failures"
assert_grep_fixed 'verify_m40_health_stamp()' "$KS_FILE" \
    "M40 validates staged and final health evidence with one exact schema"
assert_grep_fixed 'STAMP_PUBLICATION_ACTIVE=1' "$KS_FILE" \
    "published M40 evidence remains removable through every final gate"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP_CANDIDATE"' "$KS_FILE" \
    "M40 verifies the staged candidate SELinux context"
assert_grep_fixed '/usr/sbin/matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M40 verifies the final stamp SELinux context"
assert_grep_fixed \
    'cmp -s -- "$AUDIT_CANDIDATE" "$NOID_AUDIT_DEST"' \
    "$KS_FILE" "M40 final verification binds installed auditor bytes"
assert_grep_fixed \
    'cmp -s -- "$WRAPPER_CANDIDATE" /usr/local/bin/noid-audit' \
    "$KS_FILE" "M40 final verification binds installed wrapper bytes"
assert_grep_fixed 'matchpathcon -V "$path"' "$KS_FILE" \
    "M40 final verification binds every installed payload label"

invalidate_line=$(grep -nF \
    '# M40_HEALTH_INVALIDATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
first_payload_line=$(grep -nF \
    'ensure_root_dir /usr/local/bin 0755' "$KS_FILE" | cut -d: -f1 || true)
verify_guard_line=$(grep -nF \
    'if [ "$verify_fail" -gt 0 ]; then' "$KS_FILE" | cut -d: -f1 || true)
publish_line=$(grep -nF \
    '# M40_HEALTH_PUBLICATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
complete_line=$(grep -nF \
    'log "=== Module 40 noid-audit complete ==="' \
    "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$invalidate_line" ] && [ -n "$first_payload_line" ] \
   && [ -n "$verify_guard_line" ] && [ -n "$publish_line" ] \
   && [ -n "$complete_line" ] \
   && [ "$invalidate_line" -lt "$first_payload_line" ] \
   && [ "$verify_guard_line" -lt "$publish_line" ] \
   && [ "$publish_line" -lt "$complete_line" ]; then
    _pass "M40 retires old health before mutation and publishes after verification"
else
    _fail "M40 health-stamp ordering is not failure-atomic"
fi
assert_file_executable "$SUPPORT_BUILDER" \
    "offline audit support-media builder is executable"
assert_grep_fixed 'mkdir -p "$STAGE/noid-privacy-fedora"' "$SUPPORT_BUILDER" \
    "support media reproduces the Fedora/sibling directory layout"
assert_grep_fixed 'bundle create' "$SUPPORT_BUILDER" \
    "support media carries the exact source commit's complete Git history"
assert_grep_fixed 'bundle verify' "$SUPPORT_BUILDER" \
    "support builder verifies staged and extracted Git bundles"
assert_grep_fixed '"$SOURCE_COMMIT HEAD"' "$SUPPORT_BUILDER" \
    "source bundle advertises only the exact audited HEAD"
assert_grep_fixed 'git clone --no-hardlinks --quiet' "$SUPPORT_BUILDER" \
    "extracted bundle must produce an independent checkout"
assert_grep_fixed 'status --porcelain=v1 --untracked-files=all' "$SUPPORT_BUILDER" \
    "bundle checkout must be clean before publication"
assert_grep_fixed 'cmp -s "$checkout_path" "$exported_path"' "$SUPPORT_BUILDER" \
    "bundle checkout and exported source bytes are compared"
assert_grep_fixed 'exported executable file contract drifted' "$SUPPORT_BUILDER" \
    "bundle verification binds Git executable modes"
assert_grep_fixed 'git clone /media/noid-privacy-fedora.bundle' "$SUPPORT_BUILDER" \
    "support README directs audits through the history-complete checkout"
assert_grep_fixed '"$STAGE/noid-privacy-linux.bundle" HEAD' \
    "$SUPPORT_BUILDER" \
    "support media carries the pinned auditor repository history"
assert_grep_fixed '"$AUDITOR_SOURCE_COMMIT HEAD"' "$SUPPORT_BUILDER" \
    "auditor bundle advertises only the exact pinned HEAD"
assert_grep_fixed 'git clone /media/noid-privacy-linux.bundle /writable/noid-privacy-linux' \
    "$SUPPORT_BUILDER" \
    "support README clones the history-complete auditor sibling"
assert_grep_fixed 'git clone --no-hardlinks --quiet "$auditor_bundle"' \
    "$SUPPORT_BUILDER" \
    "extracted auditor bundle must produce an independent checkout"
assert_grep_fixed 'auditor bundle checkout is not clean' "$SUPPORT_BUILDER" \
    "auditor bundle checkout must be clean before publication"
assert_grep_fixed 'cmp -s "$AUDITOR_BUNDLE_CHECKOUT/repo/noid-privacy-linux.sh"' \
    "$SUPPORT_BUILDER" \
    "auditor bundle source is compared with the exported byte reference"
assert_grep_fixed '"$STAGE/noid-privacy-linux/noid-privacy-linux.sh"' \
    "$SUPPORT_BUILDER" "support media publishes the reviewed sibling path"
assert_grep_fixed '> "$STAGE/noid-privacy-linux/SOURCE-COMMIT"' \
    "$SUPPORT_BUILDER" "support media publishes exact auditor commit evidence"
assert_grep_fixed 'sudo -- dnf --repo=fedora,updates download --resolve --alldeps' "$SUPPORT_BUILDER" \
    "offline dependency closure is explicit and independent of host installs"
assert_grep_fixed 'for tool in cmp createrepo_c dnf git gpg patch rpm rpmkeys' \
    "$SUPPORT_BUILDER" "support builder requires the native rpm-md generator"
assert_not_grep 'disable-plugin=versionlock' "$SUPPORT_BUILDER" \
    "support builder reads rather than bypasses the hardened host version lock"
assert_grep_fixed 'sudo -- chown --no-dereference "$build_uid:$build_gid" -- "${rpms[@]}"' \
    "$SUPPORT_BUILDER" \
    "only the closed downloaded RPM list crosses back to the invoking user"
assert_grep_fixed "stat -c '%u:%g:%a:%h'" "$SUPPORT_BUILDER" \
    "downloaded RPM type, owner, private mode and link count are revalidated"
assert_grep_fixed '--from-repo=fedora,updates' "$SUPPORT_BUILDER" \
    "top-level support packages are also selected only from Fedora stable repos"
assert_grep_fixed '--arch=x86_64 --arch=noarch' "$SUPPORT_BUILDER" \
    "DNF5 receives each supported audit-media architecture separately"
assert_grep_fixed '--destdir="$STAGE/fedora-rpms" ShellCheck pykickstart patch' \
    "$SUPPORT_BUILDER" "support media includes ShellCheck, pykickstart and GNU patch"
assert_grep_fixed 'noid_verify_rpms_with_isolated_key' "$SUPPORT_BUILDER" \
    "every dependency RPM is verified against the isolated Fedora key"
assert_grep_fixed 'createrepo_c --quiet --no-database --checksum sha256' \
    "$SUPPORT_BUILDER" "support RPM closure becomes a native rpm-md repository"
assert_grep_fixed '--revision "$SOURCE_COMMIT" "$STAGE/fedora-rpms"' \
    "$SUPPORT_BUILDER" "repository metadata binds the exact source commit"
assert_grep_fixed 'RPM-GPG-KEY-fedora-${FEDORA_RELEASE}-x86_64' \
    "$SUPPORT_BUILDER" "support media carries the fingerprint-checked Fedora key"
assert_grep_fixed '--repofrompath=noid-audit-support,"file://$EXTRACTED/fedora-rpms"' \
    "$SUPPORT_BUILDER" "extracted repository is parsed by DNF5 before publication"
assert_grep_fixed '--installroot="$REPO_CHECK_ROOT" --releasever="$FEDORA_RELEASE"' \
    "$SUPPORT_BUILDER" "repository verification cannot depend on host package state"
assert_grep_fixed '--setopt=reposdir=/dev/null' "$SUPPORT_BUILDER" \
    "repository verification cannot load ambient repository definitions"
assert_grep_fixed '--setopt=noid-audit-support.pkg_gpgcheck=1' \
    "$SUPPORT_BUILDER" "offline install keeps package signature verification enabled"
assert_grep_fixed '--setopt=noid-audit-support.repo_gpgcheck=0' \
    "$SUPPORT_BUILDER" "unsigned local metadata trust is stated explicitly"
assert_grep_fixed '--setopt=noid-audit-support.skip_if_unavailable=0' \
    "$SUPPORT_BUILDER" "offline repository failure cannot be skipped"
assert_grep_fixed '--setopt=noid-audit-support.gpgkey="file://$media/RPM-GPG-KEY-fedora-44-x86_64"' \
    "$SUPPORT_BUILDER" "offline install trusts only the media-carried Fedora key"
assert_grep_fixed '--setopt=install_weak_deps=False' "$SUPPORT_BUILDER" \
    "download and install use the same hard dependency boundary"
assert_grep_fixed 'install ShellCheck pykickstart patch' "$SUPPORT_BUILDER" \
    "support README requests only the three intended audit tools"
assert_not_grep "/path/to/fedora-rpms/\\*\\.rpm" "$SUPPORT_BUILDER" \
    "support workflow never marks the entire dependency closure as explicit"
assert_grep_fixed 'sha256sum -c MANIFEST.sha256' "$SUPPORT_BUILDER" \
    "extracted support-media bytes are verified before publication"
assert_grep_fixed "sed -n 's/^Volume Id[[:space:]]*:[[:space:]]*//p'" \
    "$SUPPORT_BUILDER" "support ISO label parser matches xorriso PVD stdout"
assert_grep_fixed '"$AUDITOR_BUNDLE_CHECKOUT" "$REPO_CHECK_ROOT"' "$SUPPORT_BUILDER" \
    "cleanup reopens only private extracted ISO trees before removal"

# The wrapper deliberately requires an executable underlying payload. NoID Privacy
# mounts /tmp noexec, so executable fixtures belong on disk-backed /var/tmp.
TMPDIR="$(mktemp -d /var/tmp/noid-audit-m40.XXXXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

# Execute the exact production health-boundary blocks under every material
# publication failure.
m40_stamp_root="$TMPDIR/health-stamp"
m40_stamp_state="$m40_stamp_root/state"
m40_stamp_bin="$m40_stamp_root/bin"
m40_stamp_invalidate="$m40_stamp_root/invalidate.sh"
m40_stamp_publish="$m40_stamp_root/publish.sh"
m40_stamp_uid=$(id -u)
m40_stamp_gid=$(id -g)
mkdir -p "$m40_stamp_bin"

cat > "$m40_stamp_bin/restorecon" <<'M40_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-40-audit-bundle.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M40_STAMP_RESTORECON_EOF
cat > "$m40_stamp_bin/matchpathcon" <<'M40_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M40_STAMP_MATCHPATHCON_EOF
cat > "$m40_stamp_bin/mv" <<'M40_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M40_STAMP_MV_EOF
chmod 0700 "$m40_stamp_bin/restorecon" \
    "$m40_stamp_bin/matchpathcon" "$m40_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' 'fail() { exit 1; }' \
        "STAMP_DIR=$m40_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-40-audit-bundle.ok"'
    sed -n \
        '/^# M40_HEALTH_INVALIDATION_BEGIN$/,/^# M40_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|-o root -g root|-o $m40_stamp_uid -g $m40_stamp_gid|" \
            -e "s|0:0:755|$m40_stamp_uid:$m40_stamp_gid:755|" \
            -e "s|/usr/sbin/restorecon|$m40_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m40_stamp_bin/matchpathcon|g"
} > "$m40_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' 'fail() { exit 1; }' \
        'AUDIT_CANDIDATE=' 'VERSION_CANDIDATE=' 'WRAPPER_CANDIDATE=' \
        'STAMP_CANDIDATE=' 'ROOT_PUBLICATION_TMP=' \
        'STAMP_PUBLICATION_ACTIVE=0' \
        "STAMP_DIR=$m40_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-40-audit-bundle.ok"' \
        "NOID_AUDIT_VERSION=$ks_version" \
        "NOID_AUDIT_COMMIT=$ks_commit" \
        "NOID_AUDIT_SIZE=$ks_size" \
        "NOID_AUDIT_SHA256=$ks_sha" \
        'VERSION_MARKER_SHA256=1111111111111111111111111111111111111111111111111111111111111111' \
        'WRAPPER_SHA256=2222222222222222222222222222222222222222222222222222222222222222' \
        'checks_total=9' 'verify_fail=0'
    sed -n '/^cleanup_candidates() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' 'trap cleanup_candidates EXIT'
    awk '
        /^publish_root_file\(\) \{$/ { capture = 1 }
        capture { print }
        capture && /^\}$/ { exit }
    ' "$KS_FILE" |
        sed -e "s|-o root -g root|-o $m40_stamp_uid -g $m40_stamp_gid|g" \
            -e "s|chown root:root|chown $m40_stamp_uid:$m40_stamp_gid|g" \
            -e "s|0:0:|$m40_stamp_uid:$m40_stamp_gid:|g"
    sed -n \
        '/^# M40_HEALTH_PUBLICATION_BEGIN$/,/^# M40_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|chown root:root|chown $m40_stamp_uid:$m40_stamp_gid|g" \
            -e "s|0:0:|$m40_stamp_uid:$m40_stamp_gid:|g" \
            -e "s|/usr/sbin/restorecon|$m40_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m40_stamp_bin/matchpathcon|g"
} > "$m40_stamp_publish"
chmod 0700 "$m40_stamp_invalidate" "$m40_stamp_publish"

mkdir -m 0755 "$m40_stamp_state"
printf '%s\n' 'module=40' 'name=audit-bundle' 'status=ok' \
    > "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_cmd_success "M40 rerun invalidates its prior build-success stamp" \
    env PATH="$m40_stamp_bin:$PATH" "$m40_stamp_invalidate"
if [ ! -e "$m40_stamp_state/stamp-40-audit-bundle.ok" ]; then
    _pass "M40 old success evidence is absent before payload publication"
else
    _fail "M40 old success evidence is absent before payload publication"
fi

chmod 0777 "$m40_stamp_state"
printf '%s\n' 'must-survive' > "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_cmd_failure "M40 rejects shared state-directory metadata drift" \
    env PATH="$m40_stamp_bin:$PATH" "$m40_stamp_invalidate"
assert_eq "$m40_stamp_uid:$m40_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m40_stamp_state")" \
    "M40 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m40_stamp_state/stamp-40-audit-bundle.ok" \
    "M40 does not traverse a drifted shared state boundary"
rm "$m40_stamp_state/stamp-40-audit-bundle.ok"
chmod 0755 "$m40_stamp_state"

assert_cmd_failure "M40 rejects a health-stamp candidate label failure" \
    env PATH="$m40_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        "$m40_stamp_publish"
if [ ! -e "$m40_stamp_state/stamp-40-audit-bundle.ok" ] \
   && [ -z "$(find "$m40_stamp_state" -maxdepth 1 \
        \( -name '.stamp-40-audit-bundle.ok.*' \
        -o -name '.noid-audit-publish.*' \) -print -quit)" ]; then
    _pass "M40 candidate-label failure leaves no plausible health evidence"
else
    _fail "M40 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M40 retires a stamp after final-label failure" \
    env PATH="$m40_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        "$m40_stamp_publish"
if [ ! -e "$m40_stamp_state/stamp-40-audit-bundle.ok" ]; then
    _pass "M40 final-label failure removes the published success stamp"
else
    _fail "M40 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M40 rejects an atomic health-stamp rename failure" \
    env PATH="$m40_stamp_bin:$PATH" FAKE_MV_FAIL=1 "$m40_stamp_publish"
if [ ! -e "$m40_stamp_state/stamp-40-audit-bundle.ok" ] \
   && [ -z "$(find "$m40_stamp_state" -maxdepth 1 \
        \( -name '.stamp-40-audit-bundle.ok.*' \
        -o -name '.noid-audit-publish.*' \) -print -quit)" ]; then
    _pass "M40 rename failure leaves no stamp or staged candidate"
else
    _fail "M40 rename failure leaves no stamp or staged candidate"
fi

assert_cmd_success "M40 publishes exact health evidence after all gates" \
    env PATH="$m40_stamp_bin:$PATH" "$m40_stamp_publish"
assert_grep_fixed 'module=40' \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed 'name=audit-bundle' \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed 'checks_passed=9' \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed 'checks_total=9' \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed "audit_version=$ks_version" \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed "audit_commit=$ks_commit" \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed "audit_size=$ks_size" \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed "audit_sha256=$ks_sha" \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed \
    'version_marker_sha256=1111111111111111111111111111111111111111111111111111111111111111' \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed \
    'wrapper_sha256=2222222222222222222222222222222222222222222222222222222222222222' \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed '# NoID Privacy — Module 40 Health Stamp' \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed \
    '# Written at end of %post verification when all checks pass.' \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_grep_fixed \
    '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
    "$m40_stamp_state/stamp-40-audit-bundle.ok"
assert_eq 16 "$(wc -l < "$m40_stamp_state/stamp-40-audit-bundle.ok")" \
    "M40 published health stamp has the exact sixteen-line extended schema"

# Exercise the exact publication boundary as namespace root. This proves
# symlink replacement, parent/source rejection and last-known-good retention
# when relabeling fails before rename.
awk '
    /^log\(\) \{/ { copy=1 }
    /^log "=== Module 40/ { exit }
    copy { print }
' "$KS_FILE" > "$TMPDIR/root-publish-helpers.sh"
cat > "$TMPDIR/root-publish-fixture.sh" <<'M40_ROOT_PUBLISH_FIXTURE_EOF'
#!/usr/bin/bash
set -euo pipefail
. /mnt/root-publish-helpers.sh
restorecon() { return 0; }
matchpathcon() { return 0; }

ensure_root_dir /mnt/managed 0750
[ "$(stat -Lc '%u:%g:%a' /mnt/managed)" = 0:0:750 ]
printf '%s\n' candidate > /mnt/source
chmod 0600 /mnt/source

mkdir /mnt/open-parent
chmod 0777 /mnt/open-parent
if ( ensure_root_dir /mnt/open-parent/child 0755 ); then
    exit 9
fi
[ ! -e /mnt/open-parent/child ]

printf '%s\n' victim > /mnt/victim
ln -s /mnt/victim /mnt/managed/target
publish_root_file /mnt/source /mnt/managed/target 0600
[ -f /mnt/managed/target ] && [ ! -L /mnt/managed/target ]
cmp -s /mnt/source /mnt/managed/target
[ "$(stat -Lc '%u:%g:%a:%h' /mnt/managed/target)" = 0:0:600:1 ]
[ "$(cat /mnt/victim)" = victim ]

chmod 0775 /mnt/managed
if ( publish_root_file /mnt/source /mnt/managed/writable-parent 0644 ); then
    exit 10
fi
[ ! -e /mnt/managed/writable-parent ]
chmod 0750 /mnt/managed

ln /mnt/source /mnt/source-hardlink
if ( publish_root_file /mnt/source /mnt/managed/hardlinked-source 0644 ); then
    exit 11
fi
[ ! -e /mnt/managed/hardlinked-source ]
unlink /mnt/source-hardlink

chmod 0666 /mnt/source
if ( publish_root_file /mnt/source /mnt/managed/writable-source 0644 ); then
    exit 14
fi
[ ! -e /mnt/managed/writable-source ]
chmod 0600 /mnt/source

mkdir /mnt/managed/directory-target
if ( publish_root_file /mnt/source /mnt/managed/directory-target 0644 ); then
    exit 12
fi
[ -d /mnt/managed/directory-target ]

printf '%s\n' previous > /mnt/managed/failure-target
if (
    restorecon() { return 1; }
    publish_root_file /mnt/source /mnt/managed/failure-target 0644
); then
    exit 13
fi
[ "$(cat /mnt/managed/failure-target)" = previous ]
! find /mnt/managed -maxdepth 1 -name '.noid-audit-publish.*' \
    -print -quit | grep -q .
M40_ROOT_PUBLISH_FIXTURE_EOF
chmod 0700 "$TMPDIR/root-publish-fixture.sh"
if command -v bwrap >/dev/null 2>&1 && \
   bwrap --unshare-user --uid 0 --gid 0 --die-with-parent \
       --ro-bind / / --dev-bind /dev /dev --proc /proc /bin/true \
       >/dev/null 2>&1; then
    if bwrap --unshare-user --uid 0 --gid 0 --die-with-parent \
            --ro-bind / / --dev-bind /dev /dev --proc /proc \
            --bind "$TMPDIR" /mnt \
            /mnt/root-publish-fixture.sh; then
        _pass "root publication is atomic, path-bounded and failure-safe"
    else
        _fail "root publication behavioral trust-boundary fixture failed"
    fi
else
    printf '%s\n' \
        '  [SKIP] root publication namespace fixture unavailable; structural gates retained'
fi

# A signal outside the rename/final-verification window must preserve its
# signal-derived status and retire every registered publication candidate.
m40_signal_script="$TMPDIR/root-signal-cleanup.sh"
m40_signal_ready="$TMPDIR/root-signal.ready"
m40_signal_candidate="$TMPDIR/root-signal.candidate"
{
    printf '%s\n' '#!/usr/bin/bash' 'set -euo pipefail' \
        'log() { :; }' \
        "STAMP_DIR=$TMPDIR" \
        'STAMP="$STAMP_DIR/stamp-40-audit-bundle.ok"' \
        'STAMP_PUBLICATION_ACTIVE=0' \
        "ROOT_PUBLICATION_TMP=$m40_signal_candidate" \
        'AUDIT_CANDIDATE=' 'VERSION_CANDIDATE=' \
        'WRAPPER_CANDIDATE=' 'STAMP_CANDIDATE='
    sed -n '/^cleanup_candidates() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' \
        'trap cleanup_candidates EXIT' \
        "trap 'exit 129' HUP" \
        "trap 'exit 130' INT" \
        "trap 'exit 143' TERM" \
        "printf '%s\\n' candidate > \"$m40_signal_candidate\"" \
        "printf '%s\\n' ready > \"$m40_signal_ready\"" \
        'while :; do /usr/bin/sleep 0.1; done'
} > "$m40_signal_script"
chmod 0700 "$m40_signal_script"
"$m40_signal_script" &
m40_signal_pid=$!
m40_signal_ready_seen=0
for _ in $(seq 1 500); do
    if [ -e "$m40_signal_ready" ] \
       && [ -e "$m40_signal_candidate" ]; then
        m40_signal_ready_seen=1
        break
    fi
    sleep 0.01
done
if [ "$m40_signal_ready_seen" -ne 1 ]; then
    _fail "M40 signal fixture never created its ready candidate"
    kill -TERM "$m40_signal_pid" 2>/dev/null || true
    wait "$m40_signal_pid" 2>/dev/null || true
else
    set +e
    kill -TERM "$m40_signal_pid" 2>/dev/null
    wait "$m40_signal_pid"
    m40_signal_rc=$?
    set -e
    if [ "$m40_signal_rc" -eq 143 ] \
       && [ ! -e "$m40_signal_candidate" ]; then
        _pass "M40 TERM cleanup retires the active root-publication candidate"
    else
        _fail "M40 TERM cleanup leaked a candidate or returned $m40_signal_rc"
    fi
fi

extract_heredoc "$KS_FILE" "WRAPPER_EOF" "$TMPDIR/noid-audit" \
    || _fail "M40 wrapper extraction"
mkdir -p "$TMPDIR/fake-bin"
cat > "$TMPDIR/fake-bin/matchpathcon" <<'FAKE_MATCHPATHCON_EOF'
#!/bin/bash
[ -z "${FAKE_MATCHPATHCON_REJECT:-}" ] \
    || [ "${!#}" != "$FAKE_MATCHPATHCON_REJECT" ] \
    || exit 1
exit 0
FAKE_MATCHPATHCON_EOF
chmod 0755 "$TMPDIR/fake-bin/matchpathcon"
fixture_parent_metadata="$(id -u):$(id -g):$(stat -c %a "$TMPDIR")"
sed -i "s|^readonly SCRIPT_PARENT=.*|readonly SCRIPT_PARENT=\"$TMPDIR\"|" \
    "$TMPDIR/noid-audit"
sed -i "s|^readonly SCRIPT_PARENT_METADATA=.*|readonly SCRIPT_PARENT_METADATA=\"$fixture_parent_metadata\"|" \
    "$TMPDIR/noid-audit"
sed -i "s|^readonly VERSION_PARENT=.*|readonly VERSION_PARENT=\"$TMPDIR\"|" \
    "$TMPDIR/noid-audit"
sed -i "s|^readonly VERSION_PARENT_METADATA=.*|readonly VERSION_PARENT_METADATA=\"$fixture_parent_metadata\"|" \
    "$TMPDIR/noid-audit"
sed -i "s|^readonly MATCHPATHCON=.*|readonly MATCHPATHCON=\"$TMPDIR/fake-bin/matchpathcon\"|" \
    "$TMPDIR/noid-audit"
sed -i "s|^readonly VERSION_FILE=.*|readonly VERSION_FILE=\"$TMPDIR/audit-version\"|" \
    "$TMPDIR/noid-audit"
sed -i "s|^readonly VERSION_METADATA=.*|readonly VERSION_METADATA=\"$(id -u):$(id -g):644:1\"|" \
    "$TMPDIR/noid-audit"
sed -i "s|^readonly SCRIPT=.*|readonly SCRIPT=\"$TMPDIR/missing-auditor\"|" \
    "$TMPDIR/noid-audit"
printf '# comments only\n\n' > "$TMPDIR/audit-version"
chmod 0644 "$TMPDIR/audit-version"
assert_cmd_success "comment-only version marker degrades to explicit unknown" \
    bash -c 'out=$(bash "$1" --version); [ "$out" = "noid-audit wrapper: unknown (bundled)" ]' \
    _ "$TMPDIR/noid-audit"
/usr/bin/head -c 4097 /dev/zero > "$TMPDIR/audit-version"
chmod 0644 "$TMPDIR/audit-version"
assert_cmd_success "oversized version marker degrades to explicit unknown" \
    bash -c 'out=$(bash "$1" --version); [ "$out" = "noid-audit wrapper: unknown (bundled)" ]' \
    _ "$TMPDIR/noid-audit"

assert_not_grep 'RPM_POLICY_PATHS_EOF' "$KS_FILE" \
    "M40 no longer ships a self-generated RPM expected-state scope"

# Cross-repo pin parity uses an exact local checkout supplied by CI or the
# release operator. The ISO builder itself defaults to the commit-qualified
# public URL; this source-suite gate independently compares its reviewed bytes.
SIBLING_AUDIT_TOOL="${NOID_AUDIT_SRC:-$PROJECT_ROOT/../noid-privacy-linux/noid-privacy-linux.sh}"
if [ ! -f "$SIBLING_AUDIT_TOOL" ]; then
    _fail "exact noid-privacy-linux checkout is required for source-suite pin parity (clone github.com/NexusOne23/noid-privacy-linux next to this repo or set NOID_AUDIT_SRC)"
    exit 1
fi
sibling_repo=$(git -C "$(dirname "$SIBLING_AUDIT_TOOL")" rev-parse --show-toplevel)
assert_cmd_success "pinned auditor commit exists in the sibling repository" \
    git -C "$sibling_repo" cat-file -e "$ks_commit^{commit}"
assert_eq "$ks_commit" \
    "$(git -C "$sibling_repo" rev-parse --verify "refs/tags/$ks_version^{commit}")" \
    "published auditor tag resolves to the pinned commit"
# Pin parity is a content boundary. Checkout filesystems may present tracked
# modes differently; content edits and every untracked path remain fatal.
assert_eq "" "$(git -c core.filemode=false -C "$sibling_repo" \
    status --porcelain=v1 --untracked-files=all)" \
    "sibling auditor checkout is content-clean"
assert_cmd_success "sibling working-tree source equals the pinned commit object" \
    bash -o pipefail -c 'git -C "$1" show "$2:noid-privacy-linux.sh" | cmp -s - "$3"' \
    _ "$sibling_repo" "$ks_commit" "$SIBLING_AUDIT_TOOL"
cp "$SIBLING_AUDIT_TOOL" "$TMPDIR/noid-privacy-linux.sh"
chmod 0755 "$TMPDIR/noid-privacy-linux.sh"
assert_cmd_success "exact auditor remains valid bash" \
    bash -n "$TMPDIR/noid-privacy-linux.sh"
exact_sha=$(sha256sum "$TMPDIR/noid-privacy-linux.sh" | awk '{print $1}')
exact_size=$(stat -c %s "$TMPDIR/noid-privacy-linux.sh")
assert_eq "$ks_sha" "$exact_sha" \
    "unchanged sibling source produces the pinned deployed digest"
assert_eq "$ks_size" "$exact_size" \
    "unchanged sibling source has the pinned deployed byte count"
assert_grep_extended '^  --ai[[:space:]]' "$TMPDIR/noid-privacy-linux.sh" \
    "exact auditor retains its AI prompt mode"
assert_grep_fixed 'Risk-weight coverage:' "$TMPDIR/noid-privacy-linux.sh" \
    "exact auditor retains its complete percentage and coverage summary"
assert_grep_fixed '--offline       Skip only checks that make network requests' \
    "$TMPDIR/noid-privacy-linux.sh" \
    "exact auditor exposes the offline mode used by the NoID Privacy wrapper"
assert_grep_fixed 'DSA:%{DSAHEADER:pgpsig}' \
    "$TMPDIR/noid-privacy-linux.sh" \
    "upstream RPM signature inventory retains the legacy DSA header field"
assert_grep_fixed 'rpm --querytags 2>/dev/null | grep -qx OPENPGP' \
    "$TMPDIR/noid-privacy-linux.sh" \
    "RPM 6 OPENPGP signature support is capability-gated"
assert_grep_fixed "_RPM_NO_SIG_MARKERS+=' OPGP:(none)'" \
    "$TMPDIR/noid-privacy-linux.sh" \
    "unsigned classification expands with the detected RPM 6 field"

sed -i "s|^readonly SCRIPT=.*|readonly SCRIPT=\"$TMPDIR/noid-privacy-linux.sh\"|" \
    "$TMPDIR/noid-audit"
sed -i "s|^readonly SCRIPT_METADATA=.*|readonly SCRIPT_METADATA=\"$(id -u):$(id -g):755:1\"|" \
    "$TMPDIR/noid-audit"
printf '%s\n' "$ks_version" > "$TMPDIR/audit-version"
chmod 0644 "$TMPDIR/audit-version"
cat > "$TMPDIR/fake-bin/sudo" <<'FAKE_SUDO_EOF'
#!/bin/bash
printf '%s\n' "$*"
FAKE_SUDO_EOF
chmod 0755 "$TMPDIR/fake-bin/sudo"
sed -i "s|^readonly SUDO=.*|readonly SUDO=\"$TMPDIR/fake-bin/sudo\"|" \
    "$TMPDIR/noid-audit"
assert_cmd_success "version-marker SELinux drift degrades to explicit unknown" \
    bash -c 'first=$(FAKE_MATCHPATHCON_REJECT="$2" bash "$1" --version | /usr/bin/head -n 1);
             [ "$first" = "noid-audit wrapper: unknown (bundled)" ]' \
    _ "$TMPDIR/noid-audit" "$TMPDIR/audit-version"
assert_cmd_success "auditor SELinux drift fails before sudo" \
    bash -c 'set +e
             out=$(FAKE_MATCHPATHCON_REJECT="$2" bash "$1" 2>&1)
             rc=$?
             [ "$rc" -eq 2 ] &&
             [[ "$out" == *"failed its pinned identity check"* ]] &&
             [[ "$out" != "-- /usr/bin/env "* ]]' \
    _ "$TMPDIR/noid-audit" "$TMPDIR/noid-privacy-linux.sh"
assert_cmd_success "wrapper no-argument path is offline and includes the AI prompt" \
    bash -c 'out=$(PATH="$1/fake-bin:$PATH" bash "$1/noid-audit");
             [ "$out" = "-- /usr/bin/env -i HOME=/root USER=root LOGNAME=root SHELL=/bin/bash PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/bash $1/noid-privacy-linux.sh --offline --ai" ]' \
    _ "$TMPDIR"
assert_cmd_success "wrapper explicit flags remain offline by default" \
    bash -c 'out=$(PATH="$1/fake-bin:$PATH" bash "$1/noid-audit" --no-color);
             [ "$out" = "-- /usr/bin/env -i HOME=/root USER=root LOGNAME=root SHELL=/bin/bash PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/bash $1/noid-privacy-linux.sh --offline --no-color" ]' \
    _ "$TMPDIR"
assert_cmd_success "wrapper active network checks require the explicit online path" \
    bash -c 'out=$(PATH="$1/fake-bin:$PATH" bash "$1/noid-audit" --online --ai);
             [ "$out" = "-- /usr/bin/env -i HOME=/root USER=root LOGNAME=root SHELL=/bin/bash PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/bash $1/noid-privacy-linux.sh --ai" ]' \
    _ "$TMPDIR"
assert_cmd_success "ambient evidence variables are stripped after sudo" \
    bash -c 'out=$(PATH="$1/fake-bin:$PATH" \
                 NOID_AIDE_LIVE=1 NOID_RPM_BASELINE_INIT=1 \
                 NOID_RPM_BASELINE_UPDATE=1 bash "$1/noid-audit" --no-color);
             [ "$out" = "-- /usr/bin/env -i HOME=/root USER=root LOGNAME=root SHELL=/bin/bash PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/bash $1/noid-privacy-linux.sh --offline --no-color" ]' \
    _ "$TMPDIR"
assert_cmd_success "empty root environment blocks shell and runtime injection variables" \
    bash -c 'out=$(BASH_ENV=/attacker/bash-env TMPDIR=/attacker/tmp \
                 PYTHONPATH=/attacker/python RUBYOPT=-rattacker \
                 /usr/bin/env -i HOME=/root USER=root LOGNAME=root \
                 SHELL=/bin/bash PATH=/usr/sbin:/usr/bin:/sbin:/bin \
                 LANG=C LC_ALL=C /usr/bin/bash -c \
                 '\''printf "%s|%s|%s|%s\n" \
                     "${BASH_ENV-unset}" "${TMPDIR-unset}" \
                     "${PYTHONPATH-unset}" "${RUBYOPT-unset}"'\'');
             [ "$out" = "unset|unset|unset|unset" ]'
assert_cmd_success "explicit AIDE check opt-in crosses sudo exactly" \
    bash -c 'out=$(PATH="$1/fake-bin:$PATH" bash "$1/noid-audit" --aide-live --no-color);
             [ "$out" = "-- /usr/bin/env -i HOME=/root USER=root LOGNAME=root SHELL=/bin/bash PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C NOID_AIDE_LIVE=1 /usr/bin/bash $1/noid-privacy-linux.sh --offline --no-color" ]' \
    _ "$TMPDIR"
assert_cmd_success "explicit RPM-baseline init crosses sudo exactly" \
    bash -c 'out=$(PATH="$1/fake-bin:$PATH" bash "$1/noid-audit" --rpm-baseline-init --no-color);
             [ "$out" = "-- /usr/bin/env -i HOME=/root USER=root LOGNAME=root SHELL=/bin/bash PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C NOID_RPM_BASELINE_INIT=1 /usr/bin/bash $1/noid-privacy-linux.sh --offline --no-color" ]' \
    _ "$TMPDIR"
assert_cmd_success "explicit RPM-baseline update crosses sudo exactly" \
    bash -c 'out=$(PATH="$1/fake-bin:$PATH" bash "$1/noid-audit" --rpm-baseline-update --no-color);
             [ "$out" = "-- /usr/bin/env -i HOME=/root USER=root LOGNAME=root SHELL=/bin/bash PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C NOID_RPM_BASELINE_UPDATE=1 /usr/bin/bash $1/noid-privacy-linux.sh --offline --no-color" ]' \
    _ "$TMPDIR"
assert_cmd_success "conflicting network modes fail before sudo" \
    bash -c 'set +e
             out=$(PATH="$1/fake-bin:$PATH" bash "$1/noid-audit" --online --offline 2>&1)
             rc=$?
             [ "$rc" -eq 2 ] && [[ "$out" == *"conflicts"* ]] &&
             [[ "$out" != "-- /usr/bin/env "* ]]' _ "$TMPDIR"
assert_cmd_success "conflicting RPM-baseline actions fail before sudo" \
    bash -c 'set +e
             out=$(PATH="$1/fake-bin:$PATH" bash "$1/noid-audit" --rpm-baseline-init --rpm-baseline-update 2>&1)
             rc=$?
             [ "$rc" -eq 2 ] && [[ "$out" == *"choose only one"* ]] &&
             [[ "$out" != "-- /usr/bin/env "* ]]' _ "$TMPDIR"
assert_cmd_success "RPM-policy refresh rejects unrelated stateful actions" \
    bash -c 'set +e
             out=$(PATH="$1/fake-bin:$PATH" bash "$1/noid-audit" --refresh-noid-rpm-policy --aide-live 2>&1)
             rc=$?
             [ "$rc" -eq 2 ] && [[ "$out" == *"cannot be combined"* ]] &&
             [[ "$out" != "-- /usr/bin/env "* ]]' _ "$TMPDIR"
assert_cmd_success "retired updater token cannot hide behind online mode" \
    bash -c 'set +e; bash "$1" --online --update >/dev/null 2>&1; rc=$?;
             [ "$rc" -eq 2 ]' _ "$TMPDIR/noid-audit"
assert_cmd_success "version mode rejects trailing arguments" \
    bash -c 'set +e; bash "$1" --version extra >/dev/null 2>&1; rc=$?;
             [ "$rc" -eq 2 ]' _ "$TMPDIR/noid-audit"
assert_cmd_success "help mode rejects trailing arguments" \
    bash -c 'set +e; bash "$1" --help extra >/dev/null 2>&1; rc=$?;
             [ "$rc" -eq 2 ]' _ "$TMPDIR/noid-audit"
assert_cmd_success "help and version cannot hide behind earlier flags" \
    bash -c 'probe() {
                 set +e
                 out=$(bash "$1" "${@:2}" 2>&1)
                 rc=$?
                 set -e
                 [ "$rc" -eq 2 ] && [ "$(printf "%s\n" "$out" | wc -l)" -eq 1 ] \
                     && [[ "$out" == ERROR:* ]] \
                     && [[ "$out" != *"-- /usr/bin/env "* ]]
             }
             probe "$1" --no-color --help extra \
                 && probe "$1" --offline -h $'\''line\nforged'\'' \
                 && probe "$1" --no-color --version extra \
                 && probe "$1" --offline -V $'\''\033[31mcontrol'\''' \
    _ "$TMPDIR/noid-audit"
assert_cmd_success "wrapper reports bundle and underlying auditor versions" \
    bash -c 'out=$(bash "$1" --version); [ "$out" = "$2" ]' _ \
    "$TMPDIR/noid-audit" \
    "$(printf 'noid-audit wrapper: %s (bundled)\nnoid-audit upstream: NoID Privacy for Linux %s' \
        "$ks_version" "${ks_version#v}")"
printf '\n# drift fixture\n' >> "$TMPDIR/noid-privacy-linux.sh"
assert_cmd_success "runtime payload digest drift fails before sudo" \
    bash -c 'set +e; out=$(bash "$1" 2>&1); rc=$?;
             [ "$rc" -eq 2 ] &&
             [[ "$out" == *"failed its pinned identity check"* ]]' \
    _ "$TMPDIR/noid-audit"

test_finish

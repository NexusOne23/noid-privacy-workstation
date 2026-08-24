# ============================================================================
# Module 32 — Branding / Fedora Trademark Rebrand
# Source of truth: docs/trademark-notice.md
# Status: LOCKED 2026-08-22 (v3.62) — stamp v1.7 as the released image version.
#
# Covers:
#   STEP 1   /etc/os-release rebrand + compose-exclusive BLS title resync
#   STEP 1b  /etc/anaconda/profile.d/noid-privacy.conf (profile detection)
#   STEP 2   /etc/issue + /etc/issue.net
#   STEP 3   /etc/system-release overlay · STEP 3b system-release-cpe
#   STEP 3c  dnf5-actions identity restore + durable runtime BLS refresh
#   STEP 4   branding assets (mandatory BUILD-TIME-ONLY HTTP transport with
#            exact SHA256SUMS hard-abort) + avatar trio + two avatar-backfill
#            services + /etc/passwd path-unit + Plymouth bgrt theme +
#            watermark; M21 owns the sole target-kernel Dracut transaction
#   STEP 5   wallpaper dconf (active distro profile) + 90_ gschema overrides
#   STEP 5b  login-screen-logo dconf REMOVED (pre-compile retirement + gate)
#   STEP 7   /etc/noid-build-info · STEP 7a.1 32-branding.md ·
#            STEP 7b trademark-notice.md · STEP 7c ecosystem-and-support.md
#   STEP 8   Anaconda welcome dialog + installer icon rebrand (8a-8g),
#            including noid-restore-branding + the second dnf5 action
#   STEP 9   dracut branding drop-ins · STEP 10 summary · Phase 11 stamp
#
# Deliberate deviations / constraint notes:
#   - NOID_VERSION (currently v1.7) bumps ONLY on an explicit release GO.
#   - Identity persistence: /usr/lib/* targets are NOT %config(noreplace),
#     so every fedora-release-* upgrade restores stock identity files. The
#     dnf5 actions plugin (libdnf5-plugin-actions — dnf5 does NOT load the
#     dnf4 post-transaction-actions plugin) triggers
#     /usr/local/sbin/noid-restore-identity on fedora-release* transactions.
#     A future own *-release RPM (Rocky/Alma pattern) could replace the
#     overlay; today the dnf5 action is the maintained implementation.
#   - Plymouth = stock bgrt theme, NOT a custom script-theme. Its maintained
#     two-step + label path is already supplied by Fedora and keeps the LUKS
#     prompt independent of a locally maintained Plymouth script. The two-step
#     plugin reads
#     {ImageDir}/watermark.png -> the NoID Privacy logo deploys to
#     /usr/share/plymouth/themes/spinner/watermark.png (192x192) AND to
#     /usr/share/pixmaps/system-logo-white.png (GDM/Anaconda/About).
#   - bgrt.plymouth convergence: WatermarkVerticalAlignment=.73 +
#     VerticalAlignment=.82 + UseFirmwareBackground=false in every section
#     (LUKS-dialog clearance + no OEM/BGRT bleed-through). The M32 DNF action
#     and M25 both invoke the same value-independent helper after package updates;
#     M13 now content-tracks the stabilized RPM-owned modification.
#   - Avatar branding = DEFAULTS, never locks (user freedom). A dedicated
#     128x128 source avoids relying on greeter-side resampling. The greeter runs as
#     user gdm and cannot traverse a 0700 home -> Icon= must point at the
#     world-readable /var/lib/AccountsService/icons/<user> copy. The passwd
#     watcher can fire inside AccountsService.CreateUser(); FindUserById plus
#     SetIconFile serializes the pointer update through the owning daemon, and
#     the 10s strict second pass closes later GIS writes before the per-user
#     sentinel seals (user-chosen avatars persist once sealed). Path-units
#     must NOT carry After= deps toward basic.target-bound services
#     (systemd ordering cycle deletes the paths.target job).
#   - The login-screen-logo dconf stays REMOVED (rendered oversized on
#     GDM 50, overlapping the avatar slot). The defensive cleanup of
#     42-noid-login-logo is load-bearing; never re-add a login-screen
#     logo write (tests/32 asserts the absence).
#   - Target-kernel initramfs ownership is centralized in M21. M32 installs
#     Plymouth configuration/assets before M21's ordered first-boot build;
#     no second Dracut writer is permitted to race or overwrite that validated
#     candidate and its Generic recovery transaction.
#   - BLS title ownership has two explicit phases. This kickstart's initial
#     compose is exclusive and publishes each title rewrite atomically before
#     runtime services exist. Later fedora-release transactions only queue a
#     durable request; noid-identity-bls-refresh.service runs after M21, takes
#     the shared boot-mutation lock, requires a terminal guard basis and then
#     atomically converges every regular BLS entry. The dnf action never waits
#     on /boot while M25 holds that lock.
#   - NOID_KERNEL via `rpm -q kernel-core`, never uname -r (%post runs
#     under the build VM kernel).
#   - The wallpaper factory default needs the 90_ gschema overrides (GIS
#     runs before dconf profiles apply; 90_ sorts after Fedora's 10_ and
#     wins). screensaver picture-uri-dark deliberately omitted (key absent
#     from that schema -> compile WARN).
#   - Trademark posture: "independent derivative of Fedora", NEVER
#     branded as "Fedora Remix" (an optional Secondary Mark) — locked phrasing in
#     trademark-notice.md + os-release UPSTREAM_BASE + welcome dialog.
#
# Cross-Module: M21 (sole transactional target-kernel initramfs builder),
# M26 (generic-logos swap + plymouth-plugin-label +
# libdnf5-plugin-actions package), M25 (identity + canonical branding recheck on
# update), M13 (AIDE content-tracks the bgrt override), M41 (avatar backfill
# ordered after anaconda-cleanup — an orphan AccountsService file broke GIS),
# M01 (BLS titles from PRETTY_NAME), M99 (cross-checks + stamp).
# A custom noid-privacy release/logo RPM remains a possible future packaging
# improvement, not a component promised or required by this release.
# ============================================================================

%post --erroronfail --log=/var/log/ks-32-branding.log
set -euo pipefail

log() { echo "[noid-32-brand] $*"; }
log "=== Module 32 post-install: Fedora trademark rebrand ==="

BRAND_NAME="NoID Privacy Workstation"
BRAND_ID="noid-privacy-workstation"
BRAND_HOME_URL="https://github.com/NexusOne23/noid-privacy-workstation"
BRAND_SUPPORT_URL="${BRAND_HOME_URL}/issues"
BRAND_BUG_URL="${BRAND_HOME_URL}/issues"
BRAND_LOGO="noid-privacy-logo"
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-32-branding.ok"

# ====================================================================
# Verification counter + check() helper — declared at top so every STEP
# verifies inline right after its writes (no mid-flow verification gap).
# ====================================================================
ver_ok=0
ver_fail=0

check() {
    if [ "$1" = "ok" ]; then
        log "  [OK] $2"
        ver_ok=$((ver_ok + 1))
    else
        log "  [FAIL] $2"
        ver_fail=$((ver_fail + 1))
    fi
}

# Publish root-owned configuration without following an existing destination
# symlink or preserving an attacker-selected hardlink. Fedora's unified-sbin
# filesystem contract makes /usr/local/sbin a root-owned relative link to bin;
# that one exact parent link is resolved to /usr/local/bin before staging.
# Every other parent must be a real root-owned directory that is not
# group/other writable. Every rename is same-directory and therefore atomic.
# SELinux labeling is a release gate.
publish_root_file() (
    set -e
    target=$1
    requested_target=$target
    mode=$2
    parent=${target%/*}
    base=${target##*/}
    temporary=
    trap '[ -z "${temporary:-}" ] || rm -f -- "$temporary"' EXIT

    trusted_publication_directory() {
        directory=$1
        [ -d "$directory" ] && [ ! -L "$directory" ] \
            || return 1
        directory_owner=$(stat -Lc '%u:%g' -- "$directory")
        directory_mode=$(stat -Lc %a -- "$directory")
        [ "$directory_owner" = 0:0 ] \
            && (( (8#$directory_mode & 0022) == 0 ))
    }

    if [ -L "$parent" ]; then
        link_container=${parent%/*}
        [ "$parent" = /usr/local/sbin ] \
            && [ "$(readlink -- "$parent")" = bin ] \
            && [ "$(stat -c '%u:%g:%h' -- "$parent")" = 0:0:1 ] \
            && trusted_publication_directory "$link_container" \
            || { log "  [FAIL] unsafe publication parent link: $parent"; exit 1; }
        parent=$(readlink -e -- "$parent")
        [ "$parent" = /usr/local/bin ] \
            || { log "  [FAIL] unexpected publication parent target: $parent"; exit 1; }
        target="$parent/$base"
    fi
    trusted_publication_directory "$parent" \
        || { log "  [FAIL] writable or non-root publication parent: $parent"; exit 1; }

    temporary=$(mktemp "$parent/.${base}.noid-publish.XXXXXX")
    cat >"$temporary"
    chown root:root "$temporary"
    chmod "$mode" "$temporary"
    [ -x /usr/sbin/restorecon ] && [ -x /usr/sbin/matchpathcon ] \
        || { log "  [FAIL] SELinux label tools unavailable for $target"; exit 1; }
    /usr/sbin/restorecon -F "$temporary"
    sync -- "$temporary"
    mv -fT -- "$temporary" "$target"
    temporary=
    /usr/sbin/restorecon -F "$target"
    /usr/sbin/matchpathcon -V "$target" >/dev/null
    [ -f "$target" ] && [ ! -L "$target" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$target")" = "0:0:${mode#0}:1" ] \
        && [ -f "$requested_target" ] && [ ! -L "$requested_target" ] \
        && [ "$requested_target" -ef "$target" ] \
        || { log "  [FAIL] publication metadata invalid: $target"; exit 1; }
    sync -- "$target"
    sync -- "$parent"
)

# os-release(5) defines the /etc compatibility link as a relative link to the
# vendor file. Stage the link under the trusted parent and atomically replace
# any prior regular file, symlink or hardlink name.
publish_relative_symlink() (
    set -e
    target=$1
    link_text=$2
    parent=${target%/*}
    base=${target##*/}
    staging=
    trap '[ -z "${staging:-}" ] || { rm -f -- "$staging/link"; rmdir -- "$staging"; }' EXIT

    [ -d "$parent" ] && [ ! -L "$parent" ] \
        || { log "  [FAIL] unsafe symlink parent: $parent"; exit 1; }
    parent_uid=$(stat -Lc %u "$parent")
    parent_mode=$(stat -Lc %a "$parent")
    [ "$parent_uid" -eq 0 ] \
        && (( (8#$parent_mode & 0022) == 0 )) \
        || { log "  [FAIL] writable or non-root symlink parent: $parent"; exit 1; }

    staging=$(mktemp -d "$parent/.${base}.noid-link.XXXXXX")
    ln -s -- "$link_text" "$staging/link"
    chown -h root:root "$staging/link"
    mv -fT -- "$staging/link" "$target"
    rmdir -- "$staging"
    staging=
    [ -L "$target" ] && [ "$(readlink -- "$target")" = "$link_text" ] \
        || { log "  [FAIL] relative symlink publication failed: $target"; exit 1; }
    [ -x /usr/sbin/restorecon ] && [ -x /usr/sbin/matchpathcon ] \
        || { log "  [FAIL] SELinux label tools unavailable for $target"; exit 1; }
    /usr/sbin/restorecon -F "$target"
    /usr/sbin/matchpathcon -V "$target" >/dev/null
    sync -- "$parent"
)

# M32_HEALTH_INVALIDATION_BEGIN
# The branding stamp covers every publication below. Validate the shared state
# boundary without normalizing drift, then retire historical success before
# the first owned branding mutation.
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    log "  [FAIL] $STAMP_DIR exists but is not a real directory"
    exit 1
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ]; then
    log "  [FAIL] $STAMP_DIR metadata is not root:root 0755"
    exit 1
fi
if [ ! -x /usr/sbin/restorecon ] || [ ! -x /usr/sbin/matchpathcon ] \
   || ! /usr/sbin/restorecon -F -- "$STAMP_DIR" \
   || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
    log "  [FAIL] $STAMP_DIR SELinux context is not canonical"
    exit 1
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        log "  [FAIL] health-stamp target is not a file or symlink: $STAMP"
        exit 1
    fi
    rm -f -- "$STAMP" || {
        log "  [FAIL] cannot invalidate stale Module 32 health stamp"
        exit 1
    }
    sync -- "$STAMP_DIR"
fi
log "  [OK] prior Module 32 health stamp is absent"
# M32_HEALTH_INVALIDATION_END

# ====================================================================
# STEP 1: /etc/os-release rebrand
# ====================================================================
# fedora-release ships /etc/os-release; upgrades can restore it, so STEP 3c's
# package action re-applies the project identity and verifies the result.
# Keep VARIANT_* + ID_LIKE=fedora (dnf/rpm/systemd compat). The
# REDHAT_BUGZILLA_*/REDHAT_SUPPORT_* fields stay REMOVED (libreport would
# misroute derivative bug reports — Oracle/Amazon/Rocky pattern).
log "STEP 1: publishing /usr/lib/os-release + relative /etc/os-release link"

# VARIANT_ID=workstation is LOAD-BEARING: Anaconda profile detection needs
# the (ID, VARIANT_ID) tuple to match STEP 1b's profile.d entry — without
# it Anaconda falls back to defaults (efi_dir=default -> gen_grub_cfgstub
# install-fail; en_*-only Welcome language list). pattern.
publish_root_file /usr/lib/os-release 0644 <<OSREL_EOF
NAME="${BRAND_NAME}"
VERSION="44 (Workstation Edition)"
ID=${BRAND_ID}
ID_LIKE=fedora
VARIANT="Workstation Edition"
VARIANT_ID=workstation
VERSION_ID=44
VERSION_CODENAME=""
PLATFORM_ID="platform:f44"
PRETTY_NAME="${BRAND_NAME} 44"
ANSI_COLOR="0;34"
LOGO=${BRAND_LOGO}
CPE_NAME="cpe:/o:noid-privacy:workstation:44"
HOME_URL="https://noid-privacy.com"
DOCUMENTATION_URL="${BRAND_HOME_URL}/tree/main/docs"
SUPPORT_URL="${BRAND_SUPPORT_URL}"
BUG_REPORT_URL="${BRAND_BUG_URL}"
# REDHAT_BUGZILLA_PRODUCT/_VERSION + REDHAT_SUPPORT_PRODUCT/_VERSION are
# deliberately not set. /usr/bin/reporter-bugzilla (libreport) queries those fields
# to populate the bug-report Product field — keeping "Fedora" would misroute
# NoID Privacy derivative bug reports to upstream Fedora. Derivative identity
# policy therefore omits these RH-vendor-specific fields. BUG_REPORT_URL +
# SUPPORT_URL above keep primary bug-route on NoID Privacy
# GitHub. abrt is masked + abrt-cli not installed in NoID Privacy, but field-misuse
# would persist for any libreport consumer; clean removal is the simplest fix.
DEFAULT_HOSTNAME="noid-privacy"
UPSTREAM_BASE="Fedora Linux 44"
OSREL_EOF
publish_relative_symlink /etc/os-release ../usr/lib/os-release

# Compose-exclusive BLS title resync: kernel-install (Module 01, runs before
# this module) wrote titles from the then-upstream os-release. No installed
# systemd service or package transaction can run concurrently in this phase,
# but every file is still published with same-directory rename + fsync. Runtime
# fedora-release recovery uses the separately locked durable queue in STEP 3c.
if [ -d /boot/loader/entries ]; then
    for bls in /boot/loader/entries/*.conf; do
        [ -e "$bls" ] || continue
        [ -f "$bls" ] && [ ! -L "$bls" ] \
            && [ "$(stat -Lc %h "$bls")" -eq 1 ] || {
            log "  [FAIL] unsafe compose-time BLS entry: $bls"
            exit 1
        }
        [ "$(grep -c '^title ' "$bls" || true)" -eq 1 ] || {
            log "  [FAIL] ambiguous compose-time BLS title: $bls"
            exit 1
        }
        bls_dir=${bls%/*}
        bls_base=${bls##*/}
        bls_tmp=$(mktemp "$bls_dir/.${bls_base}.noid-title.XXXXXX")
        if ! awk -v brand="$BRAND_NAME" '
            /^title Fedora Linux/ { sub(/^title Fedora Linux/, "title " brand) }
            { print }
        ' "$bls" >"$bls_tmp"; then
            rm -f -- "$bls_tmp"
            log "  [FAIL] cannot stage compose-time BLS title: $bls"
            exit 1
        fi
        if cmp -s "$bls" "$bls_tmp"; then
            rm -f -- "$bls_tmp"
            continue
        fi
        chown --reference="$bls" "$bls_tmp"
        chmod --reference="$bls" "$bls_tmp"
        if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
            chcon --reference="$bls" "$bls_tmp"
        fi
        sync -- "$bls_tmp"
        mv -fT -- "$bls_tmp" "$bls"
        /usr/sbin/restorecon -F "$bls"
        /usr/sbin/matchpathcon -V "$bls" >/dev/null
        sync -- "$bls"
        sync -- "$bls_dir"
    done
fi

log "  [OK] canonical os-release published for ${BRAND_NAME}"

grep -q "^NAME=\"${BRAND_NAME}\"" /etc/os-release \
    && [ -L /etc/os-release ] \
    && [ "$(readlink /etc/os-release)" = ../usr/lib/os-release ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' /usr/lib/os-release)" = 0:0:644:1 ] \
    && check ok "STEP 1: canonical os-release content/link/metadata" \
    || check fail "STEP 1: canonical os-release content/link/metadata"

grep -q "^VARIANT_ID=workstation$" /etc/os-release \
    && check ok "STEP 1: os-release VARIANT_ID" \
    || check fail "STEP 1: os-release VARIANT_ID"

# ====================================================================
# STEP 1b: Anaconda profile.d/noid-privacy.conf
# ====================================================================
# Anaconda profile-detection requires (ID, VARIANT_ID) to match a
# profile.d entry; the default-config fallback breaks the EFI install
# (efi_dir=default vs shim's /boot/efi/EFI/fedora/) and narrows the
# Welcome language list to en_*. This profile inherits fedora-workstation
# and overrides use_geolocation=False (privacy + no 30s startup wait).
# Reference: anaconda-installer.readthedocs.io Configuration Files.
# Read by BOTH the Live installer and any future Anaconda invocation on
# the installed system.
log "STEP 1b: writing /etc/anaconda/profile.d/noid-privacy.conf"

install -d -m 0755 -o root -g root /etc/anaconda/profile.d

publish_root_file /etc/anaconda/profile.d/noid-privacy.conf 0644 <<'NOIDPROF_EOF'
# Anaconda profile for NoID Privacy Workstation 44.
#
# Inherits fedora-workstation defaults (efi_dir=fedora, btrfs+zstd:1, etc.)
# and overrides: use_geolocation=False (privacy by design — NoID Privacy firewall
# blocks geo-fetches anyway, this prevents the 30s Anaconda startup delay
# waiting for geo-IP lookup that will fail).

[Profile]
profile_id = noid-privacy-workstation
base_profile = fedora-workstation

[Profile Detection]
os_id = noid-privacy-workstation
variant_id = workstation

[Localization]
# Privacy: never fetch IP-based geolocation. User picks language manually
# from Anaconda Welcome screen (now showing all installed glibc-langpacks).
use_geolocation = False

[Timezone]
# Defense-in-depth: even with use_geolocation=False above, neutralise the
# default geolocation_provider URL (anaconda.conf upstream-default points to
# https://geoip.fedoraproject.org/city — a HTTP geo-IP lookup API). Empty
# value means no URL exists for any accidental code-path to query. Time
# synchronization is handled by M11 chrony NTS-NTP at runtime — orthogonal
# to this HTTP geo-IP API (different protocol, different purpose).
geolocation_provider =

[User Interface]
# Anaconda inherits profile options individually. Keep Fedora Workstation's
# maintained GTK-spoke list, WebUI page list and stylesheet inherited instead
# of copying them here; copied lists become stale when Anaconda changes its UI.
# In Fedora 44 the inherited WebUI list hides the accounts and date-time pages.
#
# Keep the configured-account mutation policy explicit. rootpw is supplied by
# kickstart as locked, so can_change_root=False prevents an automated install
# UI from changing that already-configured state. can_change_users=False
# likewise prevents mutation of users supplied through kickstart/DBus; the
# inherited hidden accounts page is what leaves first-user creation to GIS.
can_change_root = False

can_change_users = False

# Hard-enforce a uniform minimum length 15 for LUKS and account fields
# rendered by Anaconda WebUI (replaces deprecated `pwpolicy` kickstart
# directive, removed in pykickstart F41+).
# Format: <name> (quality <N>, length <N>, [empty], [strict])
# Defaults Fedora ships: length=6 — too weak for privacy distro.
# NoID Privacy raises to length=15 with strict mode (refuses install if user
# enters a short secret, vs warning-only without strict). NIST's
# single-factor account-password rule does not itself govern LUKS; the image
# deliberately uses one uniform minimum while making no entropy claim.
#
# IMPORTANT LIMITATION (cross-ref GNOME wiki PinAuthentication design):
# gnome-initial-setup creates the user account via accountsservice D-Bus
# SetPassword() — admin-level operation that BYPASSES pam_pwquality AND
# this password_policies setting entirely. NoID Privacy does NOT force pw-expiry
# (NIST 800-63B: no scheduled expiration). User-facing reminder lives in
# Module 13 noid-welcome.py "Verify Account Password Strength" row.
password_policies =
    root (quality 1, length 15, strict)
    user (quality 1, length 15, strict)
    luks (quality 1, length 15, strict)
NOIDPROF_EOF

[ -f /etc/anaconda/profile.d/noid-privacy.conf ] \
    && check ok "STEP 1b: anaconda profile.d/noid-privacy.conf written" \
    || check fail "STEP 1b: anaconda profile.d/noid-privacy.conf"

grep -q "profile_id = noid-privacy-workstation" /etc/anaconda/profile.d/noid-privacy.conf \
    && check ok "STEP 1b: profile_id set" \
    || check fail "STEP 1b: profile_id"

grep -q "variant_id = workstation" /etc/anaconda/profile.d/noid-privacy.conf \
    && check ok "STEP 1b: variant_id matches os-release" \
    || check fail "STEP 1b: variant_id"

log "  [OK] /etc/anaconda/profile.d/noid-privacy.conf written"

# ====================================================================
# STEP 2: /etc/issue + /etc/issue.net
# ====================================================================
# Login banner. Fedora default: "Fedora Linux 44 (Workstation Edition) \n"
# Replace with brand-aware banner + trademark disclaimer pointer.
log "STEP 2: publishing canonical issue files + relative /etc links"

publish_root_file /usr/lib/issue 0644 <<ISSUE_EOF
${BRAND_NAME} 44 \\n

ISSUE_EOF

publish_root_file /usr/lib/issue.net 0644 <<ISSUENET_EOF
${BRAND_NAME} 44
ISSUENET_EOF
publish_relative_symlink /etc/issue ../usr/lib/issue
publish_relative_symlink /etc/issue.net ../usr/lib/issue.net

# /etc/issue stays minimal (no trademark text on tty1) — the disclosure
# lives in os-release UPSTREAM_BASE + trademark-notice.md + the welcome
# dialog + repo README/LICENSE (the trademark-disclosure trinity).

log "  [OK] /etc/issue + /etc/issue.net rebranded"

grep -q "${BRAND_NAME}" /etc/issue \
    && check ok "STEP 2: issue banner" || check fail "STEP 2: issue banner"

# ====================================================================
# STEP 3: /etc/system-release overlay
# ====================================================================
# fedora-release ships /etc/system-release as symlink to /etc/fedora-release.
# We want user-facing "NoID Privacy Workstation 44" while keeping the
# compatibility fedora-release for package deps.
#
# Strategy: unlink system-release symlink (if it's a symlink to fedora-release),
# write our own text. fedora-release RPM file list still includes system-release
# as alternative — on RPM upgrade the symlink may come back, STEP 3c's
# host-only identity action re-applies it.
log "STEP 3: overlaying /etc/system-release"

publish_root_file /etc/system-release 0644 <<SYSTEM_RELEASE_EOF
${BRAND_NAME} release 44
SYSTEM_RELEASE_EOF

log "  [OK] /etc/system-release set to \"${BRAND_NAME} release 44\""

grep -q "${BRAND_NAME}" /etc/system-release \
    && check ok "STEP 3: system-release overlay" || check fail "STEP 3: system-release overlay"

# ====================================================================
# STEP 3b: /etc/system-release-cpe override
# ====================================================================
# fedora-release-common ships system-release-cpe with the Fedora CPE while
# os-release carries the NoID Privacy CPE — OpenSCAP/compliance consumers would
# see two identities. Override to match os-release CPE_NAME (Oracle/Rocky
# derivative pattern). RPM verify flags M on fedora-release-common =
# accepted; AIDE exclusion deliberately NOT added (content drift IS a
# wanted signal); the identity-restore path re-applies after upgrades.
log "STEP 3b: overriding /etc/system-release-cpe with NoID Privacy CPE"

publish_root_file /etc/system-release-cpe 0644 <<SYSTEM_RELEASE_CPE_EOF
cpe:/o:noid-privacy:workstation:44
SYSTEM_RELEASE_CPE_EOF

log "  [OK] /etc/system-release-cpe set to cpe:/o:noid-privacy:workstation:44"

grep -q "^cpe:/o:noid-privacy:workstation:44$" /etc/system-release-cpe \
    && check ok "STEP 3b: system-release-cpe matches os-release CPE_NAME" \
    || check fail "STEP 3b: system-release-cpe override"

# ====================================================================
# STEP 3c: dnf5-actions identity restore (fedora-release-* stomp recovery)
# ====================================================================
# fedora-release-* upgrades stomp the identity files (/usr/lib/* targets
# carry no %config(noreplace) protection — the /etc symlinks resolve
# there). Fix: a libdnf5-plugin-actions action-file (dnf5 does NOT load
# the dnf4 python post-transaction-actions plugin) triggers
# /usr/local/sbin/noid-restore-identity on every fedora-release*
# transaction; the helper re-applies STEPS 1+2+3+3b idempotently.
# Rejected alternatives: %config(noreplace) (ineffective for /usr/lib
# targets), a path watcher as the identity-file repair authority (race-prone),
# and a custom dnf plugin (over-engineered). The narrow PathChanged unit below
# only retries an already-durable BLS request; it never performs or detects the
# identity repair itself. An own *-release RPM could eventually replace
# this maintained overlay, but is not part of the current release.
# Refs: dnf-plugins-core post-transaction-actions docs · rpm_config notes
# (cl.cam.ac.uk) · Bugzilla 445202.
log "STEP 3c: dnf5 actions plugin identity-restore for fedora-release stomp recovery"

install -d -m 0755 -o root -g root /etc/dnf/libdnf5-plugins/actions.d
publish_root_file /etc/dnf/libdnf5-plugins/actions.d/noid-identity.actions \
    0644 <<'ACTION_EOF'
# NoID Privacy — identity-file recovery action for fedora-release-* upgrades.
# dnf5 actions plugin (libdnf5-plugin-actions); the dnf4 post-transaction-actions
# plugin does not run under dnf5.
# Format: callback:package_filter:direction:options:command
#   callback:       post_transaction (after the rpm transaction completes).
#   package_filter: glob against NEVRA — fedora-release* covers fedora-release-
#                   common, fedora-release-identity-workstation, etc.
#   direction:      in (entering the system: install/upgrade/reinstall/downgrade);
#                   dnf5 "in" already includes upgrade.
#   command:        /usr/local/sbin/noid-restore-identity (idempotent). Run via
#                   sh -c with output redirected — the actions plugin consumes the
#                   process stdout as its IPC channel, so the helper's log lines go
#                   to the journal (logger) only.
# Cross-ref: M32 STEP 3c, M26 (libdnf5-plugin-actions).
post_transaction:fedora-release*:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-identity\ >/dev/null
ACTION_EOF

[ -f /etc/dnf/libdnf5-plugins/actions.d/noid-identity.actions ] \
    && [ ! -L /etc/dnf/libdnf5-plugins/actions.d/noid-identity.actions ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' \
        /etc/dnf/libdnf5-plugins/actions.d/noid-identity.actions)" = 0:0:644:1 ] \
    && check ok "STEP 3c: noid-identity.actions exact metadata" \
    || check fail "STEP 3c: noid-identity.actions unsafe or missing"

# noid-restore-identity helper — idempotent identity re-apply plus a durable,
# nonblocking BLS request. --bls-only is service-owned and is the only runtime
# branch allowed to mutate BLS entries.
# Single-source via post-heredoc sed: @@BRAND_*@@ placeholders are
# injected from the BRAND_* declarations at script-top; the heredoc stays
# single-quoted to preserve runtime $-expansion.
mkdir -p /usr/local/sbin
publish_root_file /usr/local/sbin/noid-restore-identity 0755 <<'RESTORE_EOF'
#!/bin/bash
# noid-restore-identity — re-apply NoID Privacy identity files after fedora-release-*
# upgrade. Auto-invoked by /etc/dnf/libdnf5-plugins/actions.d/
# noid-identity.actions via libdnf5-plugin-actions (dnf5 actions plugin).
#
# Idempotent: safe to run any number of times. Mirrors M32 STEPS 1+2+3+3b.
# Skip in Live-ISO mode (rd.live.image kernel cmdline).
set -euo pipefail

LOG_TAG="noid-restore-identity"
STATE_DIR=/var/lib/noid-privacy
PENDING=$STATE_DIR/identity-bls-refresh.pending
BOOT_LOCK=/run/lock/noid-boot-mutation.lock
QUEUE_LOCK=/run/lock/noid-identity-bls-refresh.lock
BLS_DIR=/boot/loader/entries
GUARD=/usr/libexec/noid-boot-mutation-guard
SERVICE=noid-identity-bls-refresh.service
SYSTEMCTL=/usr/bin/systemctl
RESTORECON=/usr/sbin/restorecon
MATCHPATHCON=/usr/sbin/matchpathcon
CHCON=/usr/bin/chcon
EXPECTED_OWNER=root:root
log() { logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "[$LOG_TAG] $*"; }
fail() { log "FAIL: $*"; exit 1; }

restore_label() {
    [ -x "$RESTORECON" ] && [ -x "$MATCHPATHCON" ] \
        || fail "SELinux label tools are unavailable"
    "$RESTORECON" -F "$1"
    "$MATCHPATHCON" -V "$1" >/dev/null \
        || fail "SELinux context is not canonical: $1"
}

validate_publish_parent() {
    local parent=$1 parent_mode
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        && [ "$(stat -Lc '%U:%G' "$parent")" = "$EXPECTED_OWNER" ] \
        || fail "unsafe publication parent: $parent"
    parent_mode=$(stat -Lc %a "$parent")
    (( (8#$parent_mode & 0022) == 0 )) \
        || fail "publication parent is group/other writable: $parent"
}

publish_root_file() (
    local target=$1 mode=$2 parent base temporary=
    parent=${target%/*}
    base=${target##*/}
    trap '[ -z "${temporary:-}" ] || rm -f -- "$temporary"' EXIT
    validate_publish_parent "$parent"
    temporary=$(mktemp "$parent/.${base}.noid-publish.XXXXXX")
    cat >"$temporary"
    chown "$EXPECTED_OWNER" "$temporary"
    chmod "$mode" "$temporary"
    restore_label "$temporary"
    sync -- "$temporary"
    mv -fT -- "$temporary" "$target"
    temporary=
    restore_label "$target"
    [ -f "$target" ] && [ ! -L "$target" ] \
        && [ "$(stat -Lc '%U:%G:%a:%h' "$target")" = \
            "${EXPECTED_OWNER}:${mode#0}:1" ] \
        || fail "published identity file has unsafe metadata: $target"
    sync -- "$target"
    sync -- "$parent"
)

publish_relative_symlink() (
    local target=$1 link_text=$2 parent base staging=
    parent=${target%/*}
    base=${target##*/}
    trap '[ -z "${staging:-}" ] || { rm -f -- "$staging/link"; rmdir -- "$staging"; }' EXIT
    validate_publish_parent "$parent"
    staging=$(mktemp -d "$parent/.${base}.noid-link.XXXXXX")
    ln -s -- "$link_text" "$staging/link"
    chown -h "$EXPECTED_OWNER" "$staging/link"
    mv -fT -- "$staging/link" "$target"
    rmdir -- "$staging"
    staging=
    [ -L "$target" ] && [ "$(readlink -- "$target")" = "$link_text" ] \
        || fail "relative identity symlink publication failed: $target"
    restore_label "$target"
    sync -- "$parent"
)

ensure_state_dir() {
    if [ -e "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
        [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] \
            && [ "$(stat -Lc '%U:%G:%a' "$STATE_DIR")" = \
                "$EXPECTED_OWNER:755" ] \
            || fail "identity state directory is unsafe"
        return
    fi
    validate_publish_parent "${STATE_DIR%/*}"
    mkdir --mode 0755 -- "$STATE_DIR"
    chown "$EXPECTED_OWNER" "$STATE_DIR"
    restore_label "$STATE_DIR"
}

mode=restore
case "${1-}" in
    '') ;;
    --bls-only) mode=bls ;;
    *) fail "usage: noid-restore-identity [--bls-only]" ;;
esac
[ "$#" -le 1 ] || fail "usage: noid-restore-identity [--bls-only]"
[ "$(id -u)" -eq 0 ] || fail "must run as root"

if grep -q "rd.live.image" /proc/cmdline 2>/dev/null; then
    log "skip: rd.live.image (Live-ISO identity/BLS bytes are compose-owned)"
    exit 0
fi

queue_bls_refresh() (
    local temporary
    trap '[ -z "${temporary:-}" ] || rm -f -- "$temporary"' EXIT
    ensure_state_dir
    [ -f "$QUEUE_LOCK" ] && [ ! -L "$QUEUE_LOCK" ] \
        && [ "$(stat -c '%U:%G:%a' "$QUEUE_LOCK")" = root:root:600 ] \
        || fail "identity BLS queue lock is missing or unsafe"
    exec 8>"$QUEUE_LOCK"
    flock -w 300 8 || fail "timed out publishing the identity BLS request"
    if [ -e "$PENDING" ] || [ -L "$PENDING" ]; then
        [ -f "$PENDING" ] && [ ! -L "$PENDING" ] \
            && [ "$(stat -c '%U:%G:%a:%h' "$PENDING")" = root:root:600:1 ] \
            || fail "existing identity BLS request is unsafe"
    fi
    temporary=$(mktemp "$STATE_DIR/.identity-bls-refresh.XXXXXX")
    printf 'version=1\n' >"$temporary"
    chown root:root "$temporary"
    chmod 0600 "$temporary"
    restore_label "$temporary"
    sync -- "$temporary"
    mv -fT -- "$temporary" "$PENDING"
    temporary=
    restore_label "$PENDING"
    sync -- "$PENDING"
    sync -- "$STATE_DIR"
    flock -u 8
    exec 8>&-
)

publish_bls_titles() (
    local basis_record guard_rc bls bls_dir bls_base temporary title_count seen=0
    trap '[ -z "${temporary:-}" ] || rm -f -- "$temporary"' EXIT
    [ -f "$BOOT_LOCK" ] && [ ! -L "$BOOT_LOCK" ] \
        && [ "$(stat -c '%U:%G:%a' "$BOOT_LOCK")" = root:wheel:660 ] \
        || fail "shared boot-mutation lock is missing or unsafe"
    [ -f "$QUEUE_LOCK" ] && [ ! -L "$QUEUE_LOCK" ] \
        && [ "$(stat -c '%U:%G:%a' "$QUEUE_LOCK")" = root:root:600 ] \
        || fail "identity BLS queue lock is missing or unsafe"
    [ -f "$GUARD" ] && [ ! -L "$GUARD" ] && [ -x "$GUARD" ] \
        && [ "$(stat -c '%U:%G:%a' "$GUARD")" = root:root:755 ] \
        || fail "M21 boot-mutation guard is missing or unsafe"
    exec 9>"$BOOT_LOCK"
    flock -w 1800 9 || fail "timed out waiting for another boot mutation"
    guard_rc=0
    basis_record=$("$GUARD" 2>&1) || guard_rc=$?
    if [ "$guard_rc" -ne 0 ]; then
        basis_record=${basis_record//$'\n'/; }
        log "defer: M21 has no terminal boot basis yet (guard rc=$guard_rc, ${basis_record:-no output})"
        return 75
    fi
    case "$basis_record" in
        basis=hostonly|basis=generic) ;;
        *) fail "M21 returned an invalid stable-basis record" ;;
    esac

    # Serialize the pending-file handoff after acquiring the shared boot lock.
    # Publishers take only this short queue lock, never BOOT_LOCK, so M25's dnf
    # action cannot deadlock while it owns the outer boot transaction.
    exec 8>"$QUEUE_LOCK"
    flock -w 300 8 || fail "timed out taking the identity BLS queue lock"
    if [ ! -e "$PENDING" ] && [ ! -L "$PENDING" ]; then
        return 0
    fi
    [ -f "$PENDING" ] && [ ! -L "$PENDING" ] \
        && [ "$(stat -c '%U:%G:%a:%h' "$PENDING")" = root:root:600:1 ] \
        && [ "$(cat "$PENDING")" = version=1 ] \
        || fail "identity BLS request is malformed or unsafe"
    [ -d "$BLS_DIR" ] && [ ! -L "$BLS_DIR" ] \
        || fail "BLS entry directory is missing or unsafe"

    for bls in "$BLS_DIR"/*.conf; do
        [ -e "$bls" ] || continue
        seen=$((seen + 1))
        [ -f "$bls" ] && [ ! -L "$bls" ] \
            && [ "$(stat -Lc %h "$bls")" -eq 1 ] \
            || fail "BLS entry is not a regular non-symlink: $bls"
        title_count=$(grep -c '^title ' "$bls" || true)
        [ "$title_count" -eq 1 ] || fail "BLS entry has $title_count title rows: $bls"
        bls_dir=${bls%/*}
        bls_base=${bls##*/}
        temporary=$(mktemp "$bls_dir/.${bls_base}.noid-title.XXXXXX")
        if ! awk -v brand='@@BRAND_NAME@@' '
            /^title Fedora Linux/ { sub(/^title Fedora Linux/, "title " brand) }
            { print }
        ' "$bls" >"$temporary"; then
            fail "cannot stage BLS title for $bls"
        fi
        if cmp -s "$bls" "$temporary"; then
            rm -f -- "$temporary"
            temporary=
            continue
        fi
        chown --reference="$bls" "$temporary"
        chmod --reference="$bls" "$temporary"
        if [ -x "$CHCON" ]; then
            "$CHCON" --reference="$bls" "$temporary"
        fi
        restore_label "$temporary"
        sync -- "$temporary"
        mv -fT -- "$temporary" "$bls"
        temporary=
        restore_label "$bls"
        sync -- "$bls"
        sync -- "$bls_dir"
    done
    [ "$seen" -gt 0 ] || fail "no BLS entries were found"
    rm -f -- "$PENDING"
    sync -- "$STATE_DIR"
    log "BLS titles converged on the confirmed $basis_record basis"
)

if [ "$mode" = bls ]; then
    publish_bls_titles
    exit $?
fi

# os-release(5) vendor file plus its canonical relative /etc compatibility link.
publish_root_file /usr/lib/os-release 0644 <<OSREL_EOF
NAME="@@BRAND_NAME@@"
VERSION="44 (Workstation Edition)"
ID=@@BRAND_ID@@
ID_LIKE=fedora
VARIANT="Workstation Edition"
VARIANT_ID=workstation
VERSION_ID=44
VERSION_CODENAME=""
PLATFORM_ID="platform:f44"
PRETTY_NAME="@@BRAND_NAME@@ 44"
ANSI_COLOR="0;34"
LOGO=noid-privacy-logo
CPE_NAME="cpe:/o:noid-privacy:workstation:44"
HOME_URL="https://noid-privacy.com"
DOCUMENTATION_URL="https://github.com/NexusOne23/noid-privacy-workstation/tree/main/docs"
SUPPORT_URL="https://github.com/NexusOne23/noid-privacy-workstation/issues"
BUG_REPORT_URL="https://github.com/NexusOne23/noid-privacy-workstation/issues"
DEFAULT_HOSTNAME="noid-privacy"
UPSTREAM_BASE="Fedora Linux 44"
OSREL_EOF
publish_relative_symlink /etc/os-release ../usr/lib/os-release

# issue(5) vendor files plus canonical relative /etc compatibility links.
publish_root_file /usr/lib/issue 0644 <<'ISSUE_EOF'
@@BRAND_NAME@@ 44 \n

ISSUE_EOF
publish_root_file /usr/lib/issue.net 0644 <<'ISSUENET_EOF'
@@BRAND_NAME@@ 44
ISSUENET_EOF
publish_relative_symlink /etc/issue ../usr/lib/issue
publish_relative_symlink /etc/issue.net ../usr/lib/issue.net

# /etc/system-release remains a project-owned regular overlay.
publish_root_file /etc/system-release 0644 <<'SYSTEM_RELEASE_EOF'
@@BRAND_NAME@@ release 44
SYSTEM_RELEASE_EOF

# /etc/system-release-cpe
publish_root_file /etc/system-release-cpe 0644 <<'SYSTEM_RELEASE_CPE_EOF'
cpe:/o:noid-privacy:workstation:44
SYSTEM_RELEASE_CPE_EOF

[ -L /etc/os-release ] \
    && [ "$(readlink /etc/os-release)" = ../usr/lib/os-release ] \
    && [ -L /etc/issue ] && [ "$(readlink /etc/issue)" = ../usr/lib/issue ] \
    && [ -L /etc/issue.net ] \
    && [ "$(readlink /etc/issue.net)" = ../usr/lib/issue.net ] \
    && grep -qx 'NAME="@@BRAND_NAME@@"' /usr/lib/os-release \
    && grep -qx '@@BRAND_NAME@@ release 44' /etc/system-release \
    && grep -qx 'cpe:/o:noid-privacy:workstation:44' /etc/system-release-cpe \
    || fail "identity publication postcondition failed"

# Never mutate /boot inside the package-manager callback. M25 may own the
# shared boot lock around this very transaction; queue publication is durable,
# short and independent, while the service performs the guarded mutation later.
queue_bls_refresh
if ! "$SYSTEMCTL" start --no-block "$SERVICE" >/dev/null 2>&1; then
    log "defer: queued BLS title refresh will retry through its enabled service/path units"
fi

log "NoID Privacy identity files restored; guarded BLS refresh queued"
RESTORE_EOF
# Inject M32 BRAND_* into the helper at build time (single-source pattern;
# source of truth = the BRAND_* declarations at script-top).
sed -i "s|@@BRAND_NAME@@|${BRAND_NAME}|g; s|@@BRAND_ID@@|${BRAND_ID}|g" \
    /usr/local/sbin/noid-restore-identity
# Defense-in-depth: assert no placeholder survived injection
if grep -q '@@BRAND' /usr/local/sbin/noid-restore-identity; then
    check fail "STEP 3c: noid-restore-identity placeholder substitution incomplete"
fi
# Queue handoff is independent of the global boot lock. This closes the narrow
# service-exit race: a publisher that arrives while the service owns the queue
# lock waits, creates a new pending file after removal, and PathChanged queues a
# fresh activation. No publisher ever waits for BOOT_LOCK.
mkdir -p /usr/lib/tmpfiles.d /run/lock /etc/systemd/system
publish_root_file /usr/lib/tmpfiles.d/noid-identity-bls-refresh.conf \
    0644 <<'IDENTITY_BLS_TMPFILES_EOF'
f /run/lock/noid-identity-bls-refresh.lock 0600 root root -
IDENTITY_BLS_TMPFILES_EOF
install -m 0600 -o root -g root /dev/null /run/lock/noid-identity-bls-refresh.lock

publish_root_file /etc/systemd/system/noid-identity-bls-refresh.service \
    0644 <<'IDENTITY_BLS_SERVICE_EOF'
[Unit]
Description=NoID Privacy guarded BLS identity convergence
# Ordering-only: M21's timer owns activation of the long Dracut transaction.
# Pulling that service in here would put it back on multi-user.target's path.
After=local-fs.target systemd-tmpfiles-setup.service noid-dracut-hostonly-firstboot.service
RequiresMountsFor=/boot
ConditionKernelCommandLine=!rd.live.image
ConditionPathExists=/var/lib/noid-privacy/identity-bls-refresh.pending

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-restore-identity --bls-only
SuccessExitStatus=75
TimeoutStartSec=35min
UMask=0077
ProtectSystem=strict
ReadWritePaths=/boot /var/lib/noid-privacy /run/lock/noid-identity-bls-refresh.lock /run/lock/noid-boot-mutation.lock
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
# noid-boot-mutation-guard compares the running initramfs with exact signed
# objects under /usr/lib/modules. ProtectKernelModules=yes would hide that
# tree, so preserve its privilege/syscall denial explicitly while allowing
# the read-only comparison through ProtectSystem=strict.
ProtectKernelModules=no
CapabilityBoundingSet=~CAP_SYS_MODULE
SystemCallFilter=~@module
SystemCallErrorNumber=EPERM
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
IPAddressDeny=any

[Install]
WantedBy=multi-user.target
IDENTITY_BLS_SERVICE_EOF

publish_root_file /etc/systemd/system/noid-identity-bls-refresh.path \
    0644 <<'IDENTITY_BLS_PATH_EOF'
[Unit]
Description=Watch durable NoID Privacy BLS identity requests
After=local-fs.target systemd-tmpfiles-setup.service
ConditionKernelCommandLine=!rd.live.image

[Path]
PathChanged=/var/lib/noid-privacy/identity-bls-refresh.pending
Unit=noid-identity-bls-refresh.service

[Install]
WantedBy=multi-user.target
IDENTITY_BLS_PATH_EOF

/usr/sbin/restorecon -F /usr/local/sbin/noid-restore-identity \
    /usr/lib/tmpfiles.d/noid-identity-bls-refresh.conf \
    /etc/systemd/system/noid-identity-bls-refresh.service \
    /etc/systemd/system/noid-identity-bls-refresh.path
systemctl enable noid-identity-bls-refresh.service \
    noid-identity-bls-refresh.path >/dev/null

# Seed the installed target's first request in the compose-exclusive phase.
# The Live ISO skips both units; the installed system processes this only after
# M21 reaches complete or recovered-generic on a real boot.
if [ -e /var/lib/noid-privacy ] || [ -L /var/lib/noid-privacy ]; then
    [ -d /var/lib/noid-privacy ] && [ ! -L /var/lib/noid-privacy ] \
        && [ "$(stat -Lc '%u:%g:%a' /var/lib/noid-privacy)" = 0:0:755 ] \
        || { log "  [FAIL] unsafe shared state directory"; exit 1; }
else
    install -d -m 0755 -o root -g root /var/lib/noid-privacy
    /usr/sbin/restorecon -F /var/lib/noid-privacy
fi
printf 'version=1\n' \
    | publish_root_file /var/lib/noid-privacy/identity-bls-refresh.pending 0600

[ -f /usr/local/sbin/noid-restore-identity ] \
    && [ ! -L /usr/local/sbin/noid-restore-identity ] \
    && [ -x /usr/local/sbin/noid-restore-identity ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' /usr/local/sbin/noid-restore-identity)" = \
        0:0:755:1 ] \
    && check ok "STEP 3c: noid-restore-identity exact metadata" \
    || check fail "STEP 3c: noid-restore-identity unsafe or missing"

[ -L /etc/systemd/system/multi-user.target.wants/noid-identity-bls-refresh.service ] \
    && [ -L /etc/systemd/system/multi-user.target.wants/noid-identity-bls-refresh.path ] \
    && [ -f /var/lib/noid-privacy/identity-bls-refresh.pending ] \
    && [ ! -L /var/lib/noid-privacy/identity-bls-refresh.pending ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' \
        /var/lib/noid-privacy/identity-bls-refresh.pending)" = 0:0:600:1 ] \
    && [ "$(cat /var/lib/noid-privacy/identity-bls-refresh.pending)" = version=1 ] \
    && check ok "STEP 3c: durable guarded BLS identity queue installed" \
    || check fail "STEP 3c: durable guarded BLS identity queue incomplete"

log "  [OK] dnf5 actions plugin: noid-identity.actions + helper installed"

# ====================================================================
# STEP 4: Branding assets install (mandatory verified build payload)
# ====================================================================
# livemedia-creator has no first-class file embedding. The canonical wrapper
# serves the source-tree payload from a loopback-bound HTTP endpoint. The
# disposable flattened kickstart rewrites the URL to 127.0.0.1 in --no-virt
# mode; KVM mode reaches the same host endpoint through qemu user-mode NAT.
log "STEP 4: branding assets install (mandatory + SHA256-verified)"

# This is the sole payload transport: there is no local or unverified fallback.
fetch_verified_branding_payload() {
    BRANDING_FETCH_DIR=$(mktemp -d /var/tmp/noid-branding-fetch.XXXXXX)
    BRANDING_EXPECTED="$BRANDING_FETCH_DIR/.expected-assets"
    BRANDING_MANIFEST_MAX_BYTES=65536
    BRANDING_ASSET_MAX_BYTES=8388608
    cleanup_branding_fetch() {
        rm -rf -- "$BRANDING_FETCH_DIR"
    }
    trap cleanup_branding_fetch EXIT
    : >"$BRANDING_EXPECTED"
    BRANDING_HTTP_URL="http://10.0.2.2:8000/branding"
    log "  [info] fetching the mandatory build-stage payload from $BRANDING_HTTP_URL"
    mkdir -p "$BRANDING_FETCH_DIR/plymouth"
    fetch_count=0
    required_asset_count=0
    fetch_branding_asset() {
        local rel_path=$1 destination
        case "$rel_path" in
            /*|*..*|*//*|'') log "  [ABORT] unsafe branding asset path: $rel_path"; exit 11 ;;
        esac
        destination="$BRANDING_FETCH_DIR/$rel_path"
        mkdir -p -- "${destination%/*}"
        printf '%s\n' "$rel_path" >>"$BRANDING_EXPECTED"
        required_asset_count=$((required_asset_count + 1))
        if curl -fsSL --proto '=http' --proto-redir '=http' --max-redirs 0 \
            --connect-timeout 5 --max-time 30 \
            --max-filesize "$BRANDING_ASSET_MAX_BYTES" \
            -o "$destination" "$BRANDING_HTTP_URL/$rel_path" 2>/dev/null \
            && [ -f "$destination" ] && [ ! -L "$destination" ] \
            && [ -s "$destination" ] \
            && [ "$(stat -Lc %h "$destination")" -eq 1 ]; then
            fetch_count=$((fetch_count + 1))
        fi
    }
    # The manifest is mandatory. Every expected file must be fetched and
    # checked; partial or unverified branding would create a misleading ISO.
    if curl -fsSL --proto '=http' --proto-redir '=http' --max-redirs 0 \
        --connect-timeout 5 --max-time 30 \
        --max-filesize "$BRANDING_MANIFEST_MAX_BYTES" \
        -o "$BRANDING_FETCH_DIR/SHA256SUMS" \
        "$BRANDING_HTTP_URL/SHA256SUMS" 2>/dev/null \
        && [ -f "$BRANDING_FETCH_DIR/SHA256SUMS" ] \
        && [ ! -L "$BRANDING_FETCH_DIR/SHA256SUMS" ] \
        && [ -s "$BRANDING_FETCH_DIR/SHA256SUMS" ] \
        && [ "$(stat -Lc %h "$BRANDING_FETCH_DIR/SHA256SUMS")" -eq 1 ]; then
        BRANDING_SHASUMS="$BRANDING_FETCH_DIR/SHA256SUMS"
        log "  [info] SHA256SUMS manifest fetched ($(grep -cv '^#' "$BRANDING_SHASUMS") entries) — assets will be hash-verified"
    else
        log "  [ABORT] mandatory branding SHA256SUMS could not be fetched"
        exit 11
    fi
    # avatar-128.png must stay in this fetch list — it once existed only in
    # the fallback-selector chain (search AVATAR_SOURCE=), so the preferred
    # 128px variant was never fetched and GDM rendered the oversized 256px.
    for asset in wallpaper.png wallpaper-dark.png noid-privacy-logo.png \
                 noid-privacy-logo-512.png noid-privacy-avatar-256.png \
                 noid-privacy-avatar-128.png; do
        fetch_branding_asset "$asset"
    done
    # Plymouth subdirectory cleanup:
    # Removed vestigial dot.png + .plymouth + .script (custom theme dir was
    # cleanup-removed; bgrt theme is registered, not custom). Added
    # logo-watermark-192.png (192×192 Lanczos for bgrt watermark).
    # logo.png stays as fallback when 192-variant absent (forward-compat).
    for plymouth_asset in logo.png \
                          logo-watermark-192.png; do
        fetch_branding_asset "plymouth/$plymouth_asset"
    done
    # NoID Privacy app icons: 28 PNGs (7 labels x 4 sizes), pre-rendered on the
    # build host (branding/icons/regenerate-icons.sh), fetched like the
    # other assets.
    mkdir -p "$BRANDING_FETCH_DIR/icons"
    for label in setup wizard update welcome install network tools; do
        for size in 48 64 128 256; do
            asset="noid-privacy-${label}-${size}.png"
            fetch_branding_asset "icons/$asset"
        done
    done

    # NoID Privacy logo size variants (8 sizes: 16/24/32/48/
    # 64/96/128/256). Replaces former Module 32 runtime `magick` resize block
    # — pre-rendered on host removes ImageMagick from image runtime deps.
    # GTK icon-name lookup for `noid-privacy-logo` reads from these paths.
    for size in 16 24 32 48 64 96 128 256; do
        asset="noid-privacy-logo-${size}.png"
        fetch_branding_asset "icons/$asset"
    done

    if [ "$fetch_count" -eq "$required_asset_count" ]; then
        # Strict exact-set verification. A count alone is insufficient: a
        # duplicate valid row could otherwise hide a missing expected asset,
        # while an unchecked relative path could escape the private fetch tree.
        # First parse only canonical sha256sum rows, then compare the unique
        # manifest path set byte-for-byte with the independently enumerated set.
        manifest_paths="$BRANDING_FETCH_DIR/.manifest-paths"
        expected_sorted="$BRANDING_FETCH_DIR/.expected-assets.sorted"
        manifest_sorted="$BRANDING_FETCH_DIR/.manifest-paths.sorted"
        : >"$manifest_paths"
        manifest_invalid=0
        while IFS= read -r manifest_line || [ -n "$manifest_line" ]; do
            case "$manifest_line" in
                ''|\#*) continue ;;
            esac
            if [[ "$manifest_line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9._/-]+)$ ]]; then
                rel_path=${BASH_REMATCH[2]}
            else
                manifest_invalid=1
                break
            fi
            case "$rel_path" in
                /*|*..*|*//*|'') manifest_invalid=1; break ;;
            esac
            local_file="$BRANDING_FETCH_DIR/$rel_path"
            if [ ! -f "$local_file" ] || [ -L "$local_file" ] \
                || [ "$(stat -Lc %h "$local_file" 2>/dev/null || echo 0)" -ne 1 ]; then
                manifest_invalid=1
                break
            fi
            printf '%s\n' "$rel_path" >>"$manifest_paths"
        done < "$BRANDING_SHASUMS"

        LC_ALL=C sort -u "$BRANDING_EXPECTED" >"$expected_sorted"
        LC_ALL=C sort -u "$manifest_paths" >"$manifest_sorted"
        expected_rows=$(wc -l <"$BRANDING_EXPECTED")
        expected_unique=$(wc -l <"$expected_sorted")
        manifest_rows=$(wc -l <"$manifest_paths")
        manifest_unique=$(wc -l <"$manifest_sorted")

        if [ "$manifest_invalid" -ne 0 ] \
            || [ "$expected_rows" -ne "$required_asset_count" ] \
            || [ "$expected_unique" -ne "$required_asset_count" ] \
            || [ "$manifest_rows" -ne "$required_asset_count" ] \
            || [ "$manifest_unique" -ne "$required_asset_count" ] \
            || ! cmp -s "$expected_sorted" "$manifest_sorted" \
            || ! (cd -- "$BRANDING_FETCH_DIR" \
                && sha256sum --check --strict --status SHA256SUMS); then
            log "  [ABORT] branding manifest gate failed (invalid, duplicate, unexpected, missing or hash-mismatched asset)"
            exit 11
        fi
        log "  [verify] exact manifest set + SHA-256 verified ($required_asset_count assets)"
        BRANDING_PAYLOAD="$BRANDING_FETCH_DIR"
        log "  [OK] build-stage transport fetched and verified $fetch_count branding asset(s) → $BRANDING_FETCH_DIR"
    else
        log "  [ABORT] branding payload incomplete: fetched $fetch_count of $required_asset_count required assets"
        exit 11
    fi
}
fetch_verified_branding_payload

log "  [found] verified branding payload at $BRANDING_PAYLOAD"

{
    # Install logo to standard Fedora icon paths
    if [ -f "$BRANDING_PAYLOAD/noid-privacy-logo.png" ]; then
        install -Dm0644 "$BRANDING_PAYLOAD/noid-privacy-logo.png" \
            /usr/share/icons/hicolor/1024x1024/apps/noid-privacy-logo.png
        log "  [OK] logo → /usr/share/icons/hicolor/1024x1024/apps/"
    fi
    if [ -f "$BRANDING_PAYLOAD/noid-privacy-logo-512.png" ]; then
        install -Dm0644 "$BRANDING_PAYLOAD/noid-privacy-logo-512.png" \
            /usr/share/icons/hicolor/512x512/apps/noid-privacy-logo.png
        install -Dm0644 "$BRANDING_PAYLOAD/noid-privacy-logo-512.png" \
            /usr/share/pixmaps/noid-privacy-logo.png
        log "  [OK] logo-512 → /usr/share/icons/hicolor/512x512/apps/ + pixmaps/"
    fi

    # Wallpaper — light + dark variants
    # wallpaper.png        = light mode default (GNOME `drool-l`, from
    #                        gnome-backgrounds package, CC-BY-SA-3.0)
    # wallpaper-dark.png   = dark mode default (GNOME `drool-d`, from
    #                        gnome-backgrounds package, CC-BY-SA-3.0)
    # Both files are mandatory members of the exact verified payload set.
    if [ -f "$BRANDING_PAYLOAD/wallpaper.png" ]; then
        install -Dm0644 "$BRANDING_PAYLOAD/wallpaper.png" \
            /usr/share/backgrounds/noid-privacy/default.png
        log "  [OK] wallpaper (light) → /usr/share/backgrounds/noid-privacy/default.png"
    fi
    if [ -f "$BRANDING_PAYLOAD/wallpaper-dark.png" ]; then
        install -Dm0644 "$BRANDING_PAYLOAD/wallpaper-dark.png" \
            /usr/share/backgrounds/noid-privacy/default-dark.png
        log "  [OK] wallpaper (dark) → /usr/share/backgrounds/noid-privacy/default-dark.png"
    fi

    # User-avatar DEFAULTS (never locks — user can override each via GNOME
    # Settings without root). Three parallel slots so the NoID Privacy logo appears
    # across GNOME's avatar touchpoints:
    #   1. /etc/skel/.face.icon  (AccountsService fallback, copied on useradd)
    #   2. /etc/skel/.face       (legacy path — belt-and-suspenders)
    #   3. /usr/share/pixmaps/faces/noid-privacy.png (system face gallery —
    #      lets the user pick the NoID Privacy avatar back after changing it)
    # 128x128 source preferred: GDM 50 does not auto-scale AccountsService
    # Icon= files (larger variants render oversized on the lock screen).
    # Fallback chain: avatar-128 -> avatar-256 -> logo-512.
    AVATAR_SOURCE=""
    if [ -f "$BRANDING_PAYLOAD/noid-privacy-avatar-128.png" ]; then
        AVATAR_SOURCE="$BRANDING_PAYLOAD/noid-privacy-avatar-128.png"
    elif [ -f "$BRANDING_PAYLOAD/noid-privacy-avatar-256.png" ]; then
        AVATAR_SOURCE="$BRANDING_PAYLOAD/noid-privacy-avatar-256.png"
        log "  [warn] avatar-128.png missing, falling back to avatar-256.png (may render oversized on GDM 50 lock-screen)"
    elif [ -f "$BRANDING_PAYLOAD/noid-privacy-logo-512.png" ]; then
        AVATAR_SOURCE="$BRANDING_PAYLOAD/noid-privacy-logo-512.png"
        log "  [warn] avatar-128.png + avatar-256.png missing, falling back to logo-512.png (will display oversized)"
    fi
    if [ -n "$AVATAR_SOURCE" ]; then
        install -Dm0644 "$AVATAR_SOURCE" /etc/skel/.face.icon
        install -Dm0644 "$AVATAR_SOURCE" /etc/skel/.face
        install -Dm0644 "$AVATAR_SOURCE" /usr/share/pixmaps/faces/noid-privacy.png
        log "  [OK] user-avatar defaults (from $(basename "$AVATAR_SOURCE")) → /etc/skel/.face + .face.icon + /usr/share/pixmaps/faces/noid-privacy.png"
    fi

    # Live-mode avatar backfill: anaconda %post already created liveuser, so
    # livesys' useradd exits USER_EXISTS and skips its skel-copy — the .face
    # files never reach /home/liveuser and the greeter shows a letter
    # avatar. The oneshot below copies skel .face* after livesys, before
    # GDM; its conditions keep it Live-ISO-only and idempotent.
    if [ -n "$AVATAR_SOURCE" ]; then
        publish_root_file /usr/local/sbin/noid-live-avatar-backfill.sh \
            0755 <<'LIVE_AVATAR_SCRIPT_EOF'
#!/usr/bin/env bash
# Live-image-only repair for the livesys USER_EXISTS path. Publication uses
# same-directory rename and never follows an existing destination link.
set -euo pipefail
SOURCE=/etc/skel/.face
HOME_DIR=/home/liveuser
USERS_DIR=/var/lib/AccountsService/users
USER_RECORD="$USERS_DIR/liveuser"
RESTORECON=/usr/sbin/restorecon
MATCHPATHCON=/usr/sbin/matchpathcon

fail() {
    logger -t noid-live-avatar-backfill -- "FAIL: $*" 2>/dev/null || true
    printf 'noid-live-avatar-backfill: FAIL: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 0 ] || fail "usage: noid-live-avatar-backfill"

restore_label() {
    [ -x "$RESTORECON" ] && [ -x "$MATCHPATHCON" ] \
        || fail "SELinux label tools are unavailable"
    "$RESTORECON" -F "$1"
    "$MATCHPATHCON" -V "$1" >/dev/null \
        || fail "SELinux context is not canonical: $1"
}

publish_file() (
    local target=$1 owner=$2 group=$3 mode=$4
    local parent base temporary=
    parent=${target%/*}
    base=${target##*/}
    trap '[ -z "${temporary:-}" ] || rm -f -- "$temporary"' EXIT
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        && [ "$(stat -Lc '%U:%G' "$parent")" = "$owner:$group" ] \
        || fail "unsafe publication parent: $parent"
    temporary=$(mktemp "$parent/.${base}.noid-live-avatar.XXXXXX")
    cat >"$temporary"
    chown "$owner:$group" "$temporary"
    chmod "$mode" "$temporary"
    restore_label "$temporary"
    sync -- "$temporary"
    mv -fT -- "$temporary" "$target"
    temporary=
    restore_label "$target"
    [ -f "$target" ] && [ ! -L "$target" ] \
        && [ "$(stat -Lc '%U:%G:%a:%h' "$target")" = \
            "$owner:$group:${mode#0}:1" ] \
        || fail "published file is unsafe: $target"
)

live_record=$(getent passwd liveuser) \
    || fail "liveuser account is unavailable"
IFS=: read -r live_name _ live_uid _ _ live_home _ <<<"$live_record"
[ "$live_name" = liveuser ] && [ "$live_home" = "$HOME_DIR" ] \
    && [[ "$live_uid" =~ ^[0-9]+$ ]] \
    && [ "$live_uid" -ge 1000 ] && [ "$live_uid" -lt 60000 ] \
    || fail "liveuser account metadata is unexpected"
[ -d "$HOME_DIR" ] && [ ! -L "$HOME_DIR" ] \
    && [ "$(stat -Lc '%U:%G' "$HOME_DIR")" = liveuser:liveuser ] \
    || fail "liveuser home is unsafe"
[ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] \
    && [ "$(stat -Lc '%U:%G:%a:%h' "$SOURCE")" = root:root:644:1 ] \
    || fail "avatar source is unsafe"

if [ -e "$USERS_DIR" ] || [ -L "$USERS_DIR" ]; then
    [ -d "$USERS_DIR" ] && [ ! -L "$USERS_DIR" ] \
        || fail "AccountsService users path is unsafe"
else
    install -d -m0700 -o root -g root -- "$USERS_DIR"
fi
chown root:root "$USERS_DIR"
chmod 0700 "$USERS_DIR"
restore_label "$USERS_DIR"
[ "$(stat -Lc '%U:%G:%a' "$USERS_DIR")" = root:root:700 ] \
    || fail "AccountsService users directory metadata drift"

for face in .face .face.icon; do
    target="$HOME_DIR/$face"
    if [ -e "$target" ] || [ -L "$target" ]; then
        [ -f "$target" ] && [ ! -L "$target" ] \
            && [ "$(stat -Lc '%U:%G:%a:%h' "$target")" = \
                liveuser:liveuser:644:1 ] \
            || fail "existing liveuser avatar is unsafe: $target"
    else
        publish_file "$target" liveuser liveuser 0644 <"$SOURCE"
    fi
done

if [ -e "$USER_RECORD" ] || [ -L "$USER_RECORD" ]; then
    [ -f "$USER_RECORD" ] && [ ! -L "$USER_RECORD" ] \
        && [ "$(stat -Lc '%U:%G:%h' "$USER_RECORD")" = root:root:1 ] \
        || fail "existing liveuser AccountsService record is unsafe"
    if grep -q '^Icon=.' "$USER_RECORD"; then
        [ "$(stat -Lc '%a' "$USER_RECORD")" = 600 ] \
            || publish_file "$USER_RECORD" root root 0600 <"$USER_RECORD"
    else
        awk '
            BEGIN { injected = 0 }
            /^\[User\]$/ {
                print
                if (!injected) {
                    print "Icon=/usr/share/pixmaps/faces/noid-privacy.png"
                    injected = 1
                }
                next
            }
            { print }
            END {
                if (!injected) {
                    if (NR > 0) print ""
                    print "[User]"
                    print "Icon=/usr/share/pixmaps/faces/noid-privacy.png"
                    print "SystemAccount=false"
                }
            }
        ' "$USER_RECORD" | publish_file "$USER_RECORD" root root 0600
    fi
else
    printf '%s\n' \
        '[User]' \
        'Icon=/usr/share/pixmaps/faces/noid-privacy.png' \
        'SystemAccount=false' \
        | publish_file "$USER_RECORD" root root 0600
fi

# AccountsService monitors the directory mtime for record changes.
touch "$USERS_DIR"
exit 0
LIVE_AVATAR_SCRIPT_EOF

        publish_root_file /etc/systemd/system/noid-skel-avatar-backfill.service \
            0644 <<'AVATAR_BACKFILL_EOF'
[Unit]
Description=NoID Privacy: backfill liveuser .face avatar (livesys useradd-exists workaround)
Documentation=https://github.com/NexusOne23/noid-privacy-workstation/issues
DefaultDependencies=no
After=livesys.service local-fs.target
Before=display-manager.service gdm.service
# rd.live.image gate.
# This service is a LIVE-MODE-ONLY workaround (livesys useradd-exists). On
# installed systems M41 removes the liveuser account; a stray /home/liveuser
# directory (e.g. created by a mistaken manual mkdir in the installed system)
# would otherwise satisfy the path-conditions below and the service would
# FAIL trying to `install -o liveuser` to a non-existent account. The cmdline
# gate guarantees this unit only ever runs in the live-ISO, where it belongs.
ConditionKernelCommandLine=rd.live.image
ConditionPathExists=/home/liveuser
ConditionPathExists=/etc/skel/.face
ConditionFileIsExecutable=/usr/local/sbin/noid-live-avatar-backfill.sh

[Service]
Type=oneshot
RemainAfterExit=yes
# The helper publishes both home fallbacks and the AccountsService record
# atomically. Existing valid avatars and a later user-chosen Icon= are kept.
ExecStart=/usr/local/sbin/noid-live-avatar-backfill.sh

# Strict per-service hardening, symmetric with the sister
# noid-user-avatar-backfill.service. Service writes to /home/liveuser by design
# — ProtectHome= would break it. Service writes to /var/lib/AccountsService
# — ProtectSystem=strict alone would break it. Strict mode achieved via
# ReadWritePaths whitelist of those two directories. Live-ISO single-
# session impact only (ConditionPathExists=/home/liveuser fails on
# installed-system).
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/home/liveuser /var/lib/AccountsService
PrivateTmp=true
PrivateDevices=true
ProtectKernelLogs=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectClock=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
IPAddressDeny=any

[Install]
WantedBy=multi-user.target
AVATAR_BACKFILL_EOF
        systemctl enable noid-skel-avatar-backfill.service
        log "  [OK] noid-skel-avatar-backfill.service enabled (live-mode avatar fix)"
    fi

    # ====================================================================
    # Generic user-avatar backfill (sentinel-based oneshot + path-unit)
    # ====================================================================
    # AccountsService user records expose the greeter image through their
    # Icon= field. The oneshot iterates UID>=1000 users and provisions the
    # NoID Privacy default once per
    # user (sentinel under /var/lib/noid-privacy/avatar-set/ — afterwards
    # the user has full control); the /etc/passwd path-unit re-triggers it
    # when GIS creates the user.
    if [ -f /usr/share/pixmaps/faces/noid-privacy.png ]; then
        publish_root_file /etc/systemd/system/noid-user-avatar-backfill.service \
            0644 <<'AVATAR_SVC_EOF'
[Unit]
Description=NoID Privacy — One-shot avatar Icon backfill for human users (sentinel-idempotent)
Documentation=file:///usr/share/doc/noid-privacy/32-branding.md
# Ordering rationale for the GDM empty-username regression fix:
# The original design ran at multi-user.target via WantedBy and
# After=accounts-daemon. PROBLEM: M41 noid-anaconda-cleanup.service runs
# at graphical.target (WantedBy=graphical) Before=gdm. multi-user reaches
# BEFORE graphical, so avatar-backfill ran FIRST while liveuser was still
# in /etc/passwd (Anaconda copied it from Live-ISO). Avatar-backfill wrote
# /var/lib/AccountsService/users/liveuser with Icon=NoID Privacy. Then M41 ran
# userdel -r liveuser BUT did NOT remove the orphan AccountsService file.
# Result: AccountsService still reported `liveuser` as existing user →
# GDM saw "user exists" → did NOT trigger gnome-initial-setup → empty
# Username field instead of first-boot wizard.
#
# Fix: serialize avatar-backfill AFTER M41 cleanup completes. WantedBy
# graphical.target so it runs in same target as M41, with explicit After=
# anaconda-cleanup ensuring strict ordering.
After=accounts-daemon.service noid-anaconda-cleanup.service
Wants=noid-anaconda-cleanup.service
Before=gdm.service display-manager.service
ConditionPathExists=/usr/share/pixmaps/faces/noid-privacy.png
ConditionFileIsExecutable=/usr/local/sbin/noid-user-avatar-backfill.sh
# Defense-in-depth: skip on Live-ISO (M41 also skips, no human-installed
# users to backfill anyway — liveuser is build-time artifact).
ConditionPathExists=!/run/livesys

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-user-avatar-backfill.sh
StandardOutput=journal
StandardError=journal

# 2026 baseline hardening — strict-mode sandbox for a file-write script,
# symmetric with the sister noid-skel-avatar-backfill.service (the sister
# writes to /home/liveuser and therefore cannot carry ProtectHome; this
# unit only needs read-only /home enumeration). Baseline per Fedora
# SystemdSecurityHardening + openSUSE/Rocky/ArchWiki canonical set.
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/AccountsService /var/lib/noid-privacy
ProtectHome=read-only
PrivateTmp=true
PrivateDevices=true
ProtectKernelLogs=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectClock=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
IPAddressDeny=any

[Install]
# graphical.target ensures M41 anaconda-cleanup
# (also WantedBy=graphical, Before=gdm) has run first via After= ordering
# above. Subsequent boots: sentinel-idempotent → no-op.
WantedBy=graphical.target
AVATAR_SVC_EOF

        publish_root_file /usr/local/sbin/noid-user-avatar-backfill.sh \
            0755 <<'AVATAR_SCRIPT_EOF'
#!/usr/bin/env bash
# NoID Privacy — user-avatar backfill (greeter-readable Icon + provision-once)
#
# Two idempotent jobs, run Before=gdm and on every /etc/passwd change (path-unit):
#   1. PROVISION (firstboot window, until the per-user sentinel is sealed):
#      establish the NoID Privacy default avatar in the world-readable
#      /var/lib/AccountsService/icons/<user> copy, beating the GIS letter-avatar
#      via a +10s second pass. Once sealed, the icon content is never overwritten
#      again, so a user-chosen avatar (set via Settings) persists.
#   2. ICON POINTER (every run, regardless of sentinel): force
#      Icon=/var/lib/AccountsService/icons/<user> in the AccountsService user
#      file through SetIconFile. The GDM greeter runs as user 'gdm' and cannot
#      traverse a 0700 home, so an Icon at /home/<user>/.face (set by GIS from
#      /etc/skel/.face) is unreadable at the login screen — pointing Icon at the
#      world-readable icons/<user> copy makes the avatar appear persistently.
#
# Combined with the PathChanged=/etc/passwd watcher (noid-user-avatar-backfill.path),
# every user-create triggers the backfill; eventually-consistent.
set -euo pipefail
SOURCE="/usr/share/pixmaps/faces/noid-privacy.png"
SENTINEL_DIR="/var/lib/noid-privacy/avatar-set"
ICONS_DIR="/var/lib/AccountsService/icons"
USERS_DIR="/var/lib/AccountsService/users"
RESTORECON=/usr/sbin/restorecon
MATCHPATHCON=/usr/sbin/matchpathcon
BUSCTL=/usr/bin/busctl
ACCOUNTS_DEST=org.freedesktop.Accounts
ACCOUNTS_ROOT=/org/freedesktop/Accounts
log_fail() {
    logger -t noid-avatar-backfill -- "FAIL: $*" 2>/dev/null || true
    printf 'noid-avatar-backfill: FAIL: %s\n' "$*" >&2
    exit 1
}

log_info() {
    logger -t noid-avatar-backfill -- "$*" 2>/dev/null \
        || printf 'noid-avatar-backfill: %s\n' "$*" >&2
}

[ "$#" -eq 0 ] || log_fail "usage: noid-user-avatar-backfill"

restore_label() {
    [ -x "$RESTORECON" ] && [ -x "$MATCHPATHCON" ] \
        || log_fail "SELinux label tools are unavailable"
    "$RESTORECON" -F "$1"
    "$MATCHPATHCON" -V "$1" >/dev/null \
        || log_fail "SELinux context is not canonical: $1"
}

ensure_root_dir() {
    local path=$1 mode=$2
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ -d "$path" ] && [ ! -L "$path" ] \
            || log_fail "unsafe directory: $path"
    else
        mkdir --mode "$mode" -- "$path"
    fi
    chown root:root "$path"
    chmod "$mode" "$path"
    restore_label "$path"
    [ "$(stat -Lc '%U:%G:%a' "$path")" = "root:root:${mode#0}" ] \
        || log_fail "directory metadata drift: $path"
}

publish_root_file() (
    local target=$1 mode=$2 parent base temporary=
    parent=${target%/*}
    base=${target##*/}
    trap '[ -z "${temporary:-}" ] || rm -f -- "$temporary"' EXIT
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        && [ "$(stat -Lc '%U:%G' "$parent")" = root:root ] \
        || log_fail "unsafe publication parent: $parent"
    temporary=$(mktemp "$parent/.${base}.noid-avatar.XXXXXX")
    cat >"$temporary"
    chown root:root "$temporary"
    chmod "$mode" "$temporary"
    restore_label "$temporary"
    sync -- "$temporary"
    mv -fT -- "$temporary" "$target"
    temporary=
    restore_label "$target"
    [ -f "$target" ] && [ ! -L "$target" ] \
        && [ "$(stat -Lc '%U:%G:%a:%h' "$target")" = \
            "root:root:${mode#0}:1" ] \
        || log_fail "published avatar file is unsafe: $target"
)

[ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] \
    && [ "$(stat -Lc '%U:%G:%a:%h' "$SOURCE")" = root:root:644:1 ] \
    || log_fail "default avatar source is unsafe"
[ -x "$BUSCTL" ] || log_fail "AccountsService D-Bus client is unavailable"
ensure_root_dir "$SENTINEL_DIR" 0755
ensure_root_dir "$ICONS_DIR" 0775
ensure_root_dir "$USERS_DIR" 0700

# Provision the NoID Privacy default avatar CONTENT into the world-readable
# /var/lib/AccountsService/icons/<user> copy. Does NOT touch the Icon= field
# (that is enforced separately by ensure_icon_field).
provision_default() {
    local user="$1"
    local icon_target="$ICONS_DIR/$user"
    publish_root_file "$icon_target" 0644 <"$SOURCE"
}

# Resolve the AccountsService object through its maintained D-Bus API. The
# passwd path watcher can fire before the daemon reflects a newly added user;
# bounded retries cover that observable lag, and the returned object's name and
# UID are checked before SetIconFile is called. The later settling pass remains
# the guard against a competing GIS avatar write; no D-Bus call-order guarantee
# is assumed here.
account_object_for_user() {
    local user=$1 uid=$2
    local attempt=0 response signature quoted extra object_path
    local property_type property_value
    # Every D-Bus operation and this retry loop are independently bounded. The
    # service also inherits the system manager's start timeout as an outer bound.
    while [ "$attempt" -lt 12 ]; do
        attempt=$((attempt + 1))
        if response=$("$BUSCTL" --system --timeout=1s call \
                "$ACCOUNTS_DEST" "$ACCOUNTS_ROOT" \
                org.freedesktop.Accounts FindUserById x "$uid" 2>/dev/null); then
            read -r signature quoted extra <<<"$response"
            [ "$signature" = o ] && [[ "$quoted" == \"/*\" ]] \
                && [ -z "${extra:-}" ] || return 2
            object_path=${quoted#\"}
            object_path=${object_path%\"}
            [[ "$object_path" =~ ^/org/freedesktop/Accounts/User[0-9]+$ ]] \
                || return 2

            response=$("$BUSCTL" --system --timeout=1s get-property \
                "$ACCOUNTS_DEST" "$object_path" \
                org.freedesktop.Accounts.User UserName 2>/dev/null) || return 2
            read -r property_type quoted extra <<<"$response"
            [ "$property_type" = s ] && [[ "$quoted" == \"*\" ]] \
                && [ -z "${extra:-}" ] || return 2
            property_value=${quoted#\"}
            property_value=${property_value%\"}
            [ "$property_value" = "$user" ] || return 2

            response=$("$BUSCTL" --system --timeout=1s get-property \
                "$ACCOUNTS_DEST" "$object_path" \
                org.freedesktop.Accounts.User Uid 2>/dev/null) || return 2
            read -r property_type property_value extra <<<"$response"
            [ "$property_type" = t ] && [ "$property_value" = "$uid" ] \
                && [ -z "${extra:-}" ] || return 2
            printf '%s\n' "$object_path"
            return 0
        fi
        sleep 0.25
    done
    return 1
}

account_record_safe() {
    local path=$1 mode
    [[ -f "$path" && ! -L "$path" ]] || return 1
    [[ "$(stat -Lc '%U:%G:%h' "$path")" == root:root:1 ]] || return 1
    mode=$(stat -Lc '%a' "$path") || return 1
    [[ "$mode" == 600 || "$mode" == 644 ]]
}

normalize_account_record() {
    local user_file=$1 mode
    account_record_safe "$user_file" \
        || log_fail "unsafe AccountsService user record: $user_file"
    mode=$(stat -Lc '%a' "$user_file")
    if [ "$mode" = 644 ]; then
        publish_root_file "$user_file" 0600 <"$user_file"
    fi
}

# Force Icon= to point at the world-readable icons/<user> copy through
# AccountsService itself. The first pass for an unsealed account is provisional:
# a later GIS SetPassword call may still rewrite the safe record. The existing
# 10-second second pass performs the strict normalization/postcondition before
# sealing. Sealed users and pass 2 are always strict.
ensure_icon_field() {
    local user=$1 uid=$2 provisional=$3
    local icon_target="$ICONS_DIR/$user"
    local user_file="$USERS_DIR/$user"
    local cur="" icon_count=0 object_path
    if [[ -e "$user_file" || -L "$user_file" ]]; then
        account_record_safe "$user_file" \
            || log_fail "unsafe AccountsService user record: $user_file"
        cur="$(grep -m1 '^Icon=' "$user_file" 2>/dev/null | cut -d= -f2- || true)"
        icon_count="$(grep -c '^Icon=' "$user_file" 2>/dev/null || true)"
    fi

    if [[ "$cur" != "$icon_target" || "$icon_count" -ne 1 ]]; then
        object_path=$(account_object_for_user "$user" "$uid") \
            || log_fail "AccountsService user object unavailable or invalid for $user (uid=$uid)"
        "$BUSCTL" --system --timeout=5s call \
            "$ACCOUNTS_DEST" "$object_path" \
            org.freedesktop.Accounts.User SetIconFile s "$icon_target" \
            >/dev/null \
            || log_fail "AccountsService SetIconFile failed for $user (uid=$uid)"
        log_info "Icon requested through AccountsService for $user (uid=$uid)"
    fi

    if [ "$provisional" = yes ]; then
        return 0
    fi

    normalize_account_record "$user_file"
    cur="$(grep -m1 '^Icon=' "$user_file" 2>/dev/null | cut -d= -f2- || true)"
    icon_count="$(grep -c '^Icon=' "$user_file" 2>/dev/null || true)"
    [[ "$cur" == "$icon_target" && "$icon_count" -eq 1 \
       && "$(stat -Lc '%U:%G:%a:%h' "$user_file")" == root:root:600:1 ]] \
        || log_fail "AccountsService Icon postcondition failed for $user"
}

valid_user_name() {
    local user=$1
    [[ "$user" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*[$]?$ ]]
}

avatar_file_safe() {
    local path=$1
    [[ -f "$path" && ! -L "$path" ]] \
        && [[ "$(stat -Lc '%U:%G:%a:%h' "$path")" == root:root:644:1 ]]
}

process_users() {
    local pass_label="$1"
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        [[ "$uid" -ge 1000 && "$uid" -lt 60000 ]] || continue
        [[ -d "$home" ]] || continue
        [[ "$user" == "nobody" || "$user" == "nfsnobody" ]] && continue
        valid_user_name "$user" || continue

        local icon_target="$ICONS_DIR/$user"
        local sentinel="$SENTINEL_DIR/$user"
        local provisional

        # Provision the NoID Privacy default ONCE, during the firstboot window (before
        # the sentinel is sealed). After sealing, the icon content is never
        # written again — so a user-chosen avatar (set via Settings) persists.
        if [[ ! -f "$sentinel" ]]; then
            if [[ ! -f "$icon_target" ]] || ! cmp -s "$SOURCE" "$icon_target"; then
                provision_default "$user"
                log_info "[$pass_label] default avatar provisioned for $user (uid=$uid)"
            fi
        fi

        if [[ -e "$icon_target" || -L "$icon_target" ]]; then
            avatar_file_safe "$icon_target" \
                || log_fail "unsafe AccountsService avatar: $icon_target"
        fi

        # Enforce the greeter-readable Icon= pointer whenever a safe icon is
        # present. A sealed user may legitimately have removed their avatar;
        # keep that no-op status-neutral so it cannot trip the outer set -e.
        if avatar_file_safe "$icon_target"; then
            provisional=no
            [[ ! -f "$sentinel" && "$pass_label" = pass-1 ]] \
                && provisional=yes
            ensure_icon_field "$user" "$uid" "$provisional"
        fi
    done < <(getent passwd)
}

# The +10s GIS-race second pass is only meaningful while a present human user is
# still unsealed (the firstboot settling window). Once every human user is
# sealed, skip it so a steady-state boot does not hold gdm (this unit is
# Before=gdm) for the settle interval.
needs_settle() {
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        [[ "$uid" -ge 1000 && "$uid" -lt 60000 ]] || continue
        [[ -d "$home" ]] || continue
        [[ "$user" == "nobody" || "$user" == "nfsnobody" ]] && continue
        valid_user_name "$user" || continue
        [[ -f "$SENTINEL_DIR/$user" ]] || return 0
    done < <(getent passwd)
    return 1
}

# Pass 1 — initial run at /etc/passwd-modified trigger (path-watcher fired
# because GIS called useradd, or this is a regular boot).
process_users "pass-1"

# Pass 2 — GIS races the path-watcher and may write a letter-avatar /
# Icon=~/.face shortly after; after 10s GIS is finished and this pass re-asserts
# the NoID Privacy default content + the correct Icon pointer. Gated on an
# unsealed human user so a sealed steady-state boot skips the 10s wait entirely.
if needs_settle; then
    sleep 10
    process_users "pass-2-postrace"
fi

# Seal the per-user sentinel AFTER the firstboot settling passes. From the next
# run on, content-provisioning is skipped (user-chosen avatars persist) while
# the Icon= pointer is still kept greeter-correct on every run.
while IFS=: read -r user _ uid _ _ home _; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [[ "$uid" -ge 1000 && "$uid" -lt 60000 ]] || continue
    [[ -d "$home" ]] || continue
    [[ "$user" == "nobody" || "$user" == "nfsnobody" ]] && continue
    valid_user_name "$user" || continue
    if [[ -f "$ICONS_DIR/$user" ]]; then
        sentinel="$SENTINEL_DIR/$user"
        if [[ -e "$sentinel" || -L "$sentinel" ]]; then
            [[ -f "$sentinel" && ! -L "$sentinel" ]] \
                && [[ "$(stat -Lc '%U:%G:%a:%h' "$sentinel")" == \
                    root:root:600:1 ]] \
                || log_fail "unsafe avatar sentinel: $sentinel"
        else
            publish_root_file "$sentinel" 0600 </dev/null
        fi
    fi
done < <(getent passwd)

touch "$USERS_DIR"
exit 0
AVATAR_SCRIPT_EOF

        # Pre-create sentinel dir (baseline: ReadWritePaths target must exist)
        mkdir -p /var/lib/noid-privacy/avatar-set
        chmod 0755 /var/lib/noid-privacy/avatar-set
        chown root:root /var/lib/noid-privacy /var/lib/noid-privacy/avatar-set

        systemctl enable noid-user-avatar-backfill.service
        log "  [OK] noid-user-avatar-backfill.service enabled (Option B sentinel-based, one-shot per user)"

        # VM-tested root cause:
        # The avatar-backfill.service runs at graphical.target, BEFORE GDM
        # starts gnome-initial-setup. With the F44 NoID Privacy flow (no Anaconda
        # `user --name=` — relies on GIS for user creation), no human user
        # exists when avatar-backfill runs → it iterates getent and finds
        # no UID 1000-60000 humans → no Icon= written. ~5s later GIS creates
        # `n` (or whichever name user picks) → has GIS-generated letter
        # avatar instead of NoID Privacy logo. Sentinel-design prevents re-run.
        #
        # Live VM evidence:
        #   /home/<new-user>/.face = NoID Privacy logo via /etc/skel
        #   AccountsService Icon= still pointed at the GIS-generated letter
        #   noid-user-avatar-backfill.service status: inactive (ran once, dead)
        #
        # Fix: path-unit watcher on /etc/passwd. systemd PathChanged= triggers
        # the avatar-backfill.service whenever /etc/passwd is modified —
        # specifically when GIS calls useradd to create the new user. The
        # service itself is sentinel-idempotent so re-triggering is safe:
        # already-set users get skipped, only the new user gets its Icon
        # written. Backfill becomes eventually-consistent rather than
        # ordering-dependent.
        publish_root_file /etc/systemd/system/noid-user-avatar-backfill.path \
            0644 <<'AVATAR_PATH_EOF'
[Unit]
Description=NoID Privacy — Watch /etc/passwd for new users (avatar Icon backfill trigger)
Documentation=file:///usr/share/doc/noid-privacy/32-branding.md
# CONSTRAINT: path units must NOT have After= dependencies on
# services inside basic.target's dependency chain. paths.target (auto-pulled
# by basic.target) wants .path units. If a .path has After= a service that
# itself depends on basic.target (anaconda-cleanup → NetworkManager →
# basic.target), systemd detects an ordering cycle and DELETES the
# paths.target/start job to break it ("basic.target: Found ordering cycle:
# paths.target/start after noid-user-avatar-backfill.path/start after
# noid-anaconda-cleanup.service/start after basic.target/start").
#
# The path-unit only ARMS a watcher — no ordering needed. The TRIGGERED service
# (noid-user-avatar-backfill.service) has its own After= chain ensuring it runs
# AFTER M41 cleanup completes.
ConditionPathExists=!/run/livesys

[Path]
# PathChanged: fires once when /etc/passwd is modified-and-closed. PathModified
# would fire on every write (noisier, no benefit). Combined with the service's
# sentinel directory (/var/lib/noid-privacy/avatar-set/<user>) this is safe to
# fire on any /etc/passwd edit — already-processed users are skipped.
PathChanged=/etc/passwd
Unit=noid-user-avatar-backfill.service

[Install]
WantedBy=multi-user.target
AVATAR_PATH_EOF
        systemctl enable noid-user-avatar-backfill.path
        log "  [OK] noid-user-avatar-backfill.path enabled (re-triggers backfill when GIS adds user)"
    fi

    # Plymouth activation is split: build-time registers the theme +
    # plymouthd.conf; first-boot regenerates the initramfs against the
    # TARGET kernel (dracut here would use the build-host kernel). First
    # boot after install shows stock Plymouth; boot 2+ shows NoID Privacy.
    #
    # NoID Privacy app icons: hicolor PNGs for five current launcher names plus
    # the wizard/welcome compatibility aliases (freedesktop icon-naming;
    # current .desktop files reference Icon=noid-privacy-<label>).
    # All four sizes carry the white outlined label; see regenerate-icons.sh's
    # LABELED_PT/LABELED_SW/LABELED_YOFF.
    if [ -d "$BRANDING_PAYLOAD/icons" ]; then
        icons_installed=0
        # wizard/welcome remain compatibility aliases for older user-created
        # launchers; current shipped Setup surfaces use the setup family.
        for label in setup wizard update welcome install network tools; do
            for size in 48 64 128 256; do
                src="$BRANDING_PAYLOAD/icons/noid-privacy-${label}-${size}.png"
                if [ -f "$src" ]; then
                    install -Dm0644 "$src" \
                        "/usr/share/icons/hicolor/${size}x${size}/apps/noid-privacy-${label}.png"
                    icons_installed=$((icons_installed + 1))
                fi
            done
        done
        if [ "$icons_installed" -gt 0 ]; then
            # Refresh the optional hicolor lookup cache. A failed refresh is
            # non-fatal because the icon-theme specification keeps uncached
            # file lookup authoritative; only lookup performance is affected.
            if command -v gtk-update-icon-cache >/dev/null 2>&1; then
                gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null \
                    || log "  [warn] gtk-update-icon-cache returned non-zero (non-fatal)"
            fi
            log "  [OK] $icons_installed NoID Privacy app icons → /usr/share/icons/hicolor/.../apps/"
        fi
    else
        log "  [skip] no $BRANDING_PAYLOAD/icons — NoID Privacy app launchers will fall back to generic icon"
    fi

    if [ -d "$BRANDING_PAYLOAD/plymouth" ]; then
        # ====================================================================
        # bgrt theme (maintained LUKS-prompt rendering path)
        # ====================================================================
        # Stock bgrt uses Fedora's maintained two-step + label plugin stack,
        # retains the distro-tested encrypted-root prompt path and avoids a
        # locally maintained Plymouth script. The image intentionally accepts
        # the stock spinner and adds only the NoID Privacy watermark/layout.
        # Any future custom theme needs its own initramfs dependency proof,
        # prompt test and transactional M21 content contract.

        # The two-step plugin reads ONLY {ImageDir}/watermark.png (bgrt's
        # ImageDir = themes/spinner) — system-logo-white.png is NOT read by
        # Plymouth, and M26's -fedora-logos exclusion means no stock
        # watermark exists (bgrt would fall back to the OEM/BGRT firmware
        # bitmap). Deploy the logo to BOTH paths:
        #   1. /usr/share/pixmaps/system-logo-white.png (GDM / Anaconda /
        #      About dialog)
        #   2. /usr/share/plymouth/themes/spinner/watermark.png (the path
        #      that actually shows during boot + LUKS prompt)
        if [ -f "$BRANDING_PAYLOAD/plymouth/logo.png" ]; then
            # Path 1 — GDM/Anaconda/About-dialog branding
            # 512×512 source (better quality on hi-DPI GDM/About dialog renders)
            install -Dm0644 "$BRANDING_PAYLOAD/plymouth/logo.png" \
                /usr/share/pixmaps/system-logo-white.png
            log "  [OK] /usr/share/pixmaps/system-logo-white.png replaced with NoID Privacy logo (GDM/Anaconda/About dialog)"

            # Path 2 — bgrt watermark, 192x192 (covers 720p..4K comfortably
            # while leaving room for the LUKS prompt + spinner).
            if [ -f "$BRANDING_PAYLOAD/plymouth/logo-watermark-192.png" ]; then
                install -Dm0644 "$BRANDING_PAYLOAD/plymouth/logo-watermark-192.png" \
                    /usr/share/plymouth/themes/spinner/watermark.png
                log "  [OK] /usr/share/plymouth/themes/spinner/watermark.png deployed (192×192 Lanczos)"
            else
                # Fallback: 512×512 if 192-variant absent (forward-compat for
                # legacy branding/ trees that haven't been regenerated).
                install -Dm0644 "$BRANDING_PAYLOAD/plymouth/logo.png" \
                    /usr/share/plymouth/themes/spinner/watermark.png
                log "  [WARN] logo-watermark-192.png missing — using 512×512 logo.png as fallback"
            fi
        fi

        # Set Plymouth default theme to bgrt (not custom NoID Privacy script-theme)
        if command -v plymouth-set-default-theme >/dev/null 2>&1; then
            if plymouth-set-default-theme bgrt 2>/dev/null; then
                log "  [OK] Plymouth default theme set to bgrt"
            else
                check fail "STEP 4: plymouth-set-default-theme bgrt failed"
            fi
        else
            check fail "STEP 4: plymouth-set-default-theme unavailable"
        fi

        # bgrt.plymouth layout convergence: stock values put the
        # watermark at the very bottom and render the OEM/BGRT firmware
        # bitmap. NoID Privacy values: WatermarkVerticalAlignment=.73 (clears the
        # LUKS dialog), VerticalAlignment=.82 (spinner under the logo),
        # UseFirmwareBackground=false x3 (no vendor-logo bleed-through).
        # The stock bgrt theme stays registered (two-step + label plugin
        # stack). Package updates and M25 use the same value-independent
        # contract below; M13 content-tracks the converged file.
        BGRT_PLY=/usr/share/plymouth/themes/bgrt/bgrt.plymouth
        if [ -f "$BGRT_PLY" ] && [ ! -L "$BGRT_PLY" ] \
            && [ "$(stat -Lc %h "$BGRT_PLY")" -eq 1 ]; then
            watermark_keys=$(grep -c '^WatermarkVerticalAlignment=' "$BGRT_PLY" 2>/dev/null || true)
            spinner_keys=$(grep -c '^VerticalAlignment=' "$BGRT_PLY" 2>/dev/null || true)
            firmware_keys=$(grep -c '^UseFirmwareBackground=' "$BGRT_PLY" 2>/dev/null || true)
            watermark_keys=${watermark_keys:-0}
            spinner_keys=${spinner_keys:-0}
            firmware_keys=${firmware_keys:-0}
            if [ "$watermark_keys" -ne 1 ] || [ "$spinner_keys" -ne 1 ] \
               || [ "$firmware_keys" -lt 1 ]; then
                check fail "STEP 4: bgrt.plymouth key shape drifted; refusing ambiguous layout rewrite"
            else
                # Converge by key, not by Fedora's current default values.
                # Exact key-count gates above make structural drift fail loud
                # while harmless upstream value changes remain supported.
                if sed -E \
                    -e 's|^WatermarkVerticalAlignment=.*$|WatermarkVerticalAlignment=.73|' \
                    -e 's|^VerticalAlignment=.*$|VerticalAlignment=.82|' \
                    -e 's|^UseFirmwareBackground=.*$|UseFirmwareBackground=false|g' \
                    "$BGRT_PLY" | publish_root_file "$BGRT_PLY" 0644 \
                   && grep -qx 'WatermarkVerticalAlignment=.73' "$BGRT_PLY" \
                   && grep -qx 'VerticalAlignment=.82' "$BGRT_PLY" \
                   && [ "$(grep -c '^UseFirmwareBackground=false$' "$BGRT_PLY" 2>/dev/null || true)" -eq "$firmware_keys" ]; then
                    log "  [OK] bgrt.plymouth layout applied (Watermark .73, Spinner .82, firmware background disabled)"
                else
                    check fail "STEP 4: bgrt.plymouth layout convergence failed"
                fi
            fi
        else
            check fail "STEP 4: $BGRT_PLY missing while Plymouth branding is mandatory"
        fi

        # Write plymouthd.conf — NoID Privacy ships with bgrt.
        # Plymouth defaults already specify Theme=bgrt; write the theme
        # explicitly because it is the branding contract. Do not override
        # UseSimpledrmNoLuks: Fedora 44 defaults it to 1, and Plymouth ignores
        # that no-LUKS-only switch when rd.luks.uuid is present. A local value
        # therefore provides no encrypted-root hardening and would only change
        # Fedora's maintained behavior on an unencrypted installation.
        install -d -m 0755 -o root -g root /etc/plymouth
        publish_root_file /etc/plymouth/plymouthd.conf 0644 <<'PLYMOUTHD_EOF'
# NoID Privacy Workstation — Plymouth daemon configuration
# Switched from the custom NoID Privacy script theme to Fedora bgrt
# (two-step + label plugins) for reliable LUKS prompt rendering.
# NoID Privacy branding preserved via /usr/share/pixmaps/system-logo-white.png swap.
[Daemon]
Theme=bgrt
ShowDelay=0
DeviceTimeout=8
PLYMOUTHD_EOF
        log "  [OK] /etc/plymouth/plymouthd.conf written (Theme=bgrt; Fedora renderer defaults inherited)"

        # Target-kernel initramfs ownership is centralized in Module 21.
        # Its ordered, transactional first-boot builder runs after Module 20
        # and includes the Plymouth config/assets installed above. Keeping a
        # second M32 Dracut writer would race or overwrite the validated
        # candidate and Generic recovery transaction.
        log "  [OK] Plymouth assets staged for Module 21 target-kernel initramfs"
    fi

    # Permission fix (Immutable project lesson: build-host umask 077 can
    # make files unreadable for GDM/plymouth. Force world-readable for
    # all installed assets.)
    chmod -R u=rwX,go=rX \
        /usr/share/icons/hicolor/1024x1024/apps/noid-privacy-logo.png \
        /usr/share/icons/hicolor/512x512/apps/noid-privacy-logo.png \
        /usr/share/pixmaps/noid-privacy-logo.png \
        /usr/share/backgrounds/noid-privacy
}

# STEP 4 verification: base release-critical asset classes must be installed.
if [ -f /usr/share/pixmaps/noid-privacy-logo.png ] \
    && [ -f /usr/share/backgrounds/noid-privacy/default.png ] \
    && [ -f /usr/share/backgrounds/noid-privacy/default-dark.png ] \
    && [ -f /usr/share/plymouth/themes/spinner/watermark.png ]; then
    check ok "STEP 4: mandatory logo, wallpapers and Plymouth watermark installed"
else
    check fail "STEP 4: one or more mandatory branding asset classes missing"
fi

# The manifest and `set -e` already make partial installs fail, but these
# postconditions independently prove the two multi-file classes consumed by
# every first-party launcher and by the AccountsService avatar backfill.
app_icon_count=0
# Keep the wizard/welcome compatibility aliases in the verified inventory.
for label in setup wizard update welcome install network tools; do
    for size in 48 64 128 256; do
        if [ -f "/usr/share/icons/hicolor/${size}x${size}/apps/noid-privacy-${label}.png" ]; then
            app_icon_count=$((app_icon_count + 1))
        fi
    done
done
if [ "$app_icon_count" -eq 28 ] \
    && [ -f /etc/skel/.face ] \
    && [ -f /etc/skel/.face.icon ] \
    && [ -f /usr/share/pixmaps/faces/noid-privacy.png ]; then
    check ok "STEP 4: 28 launcher icons and all 3 avatar targets installed"
else
    check fail "STEP 4: launcher/avatar payload incomplete (icons=$app_icon_count/28)"
fi

# ====================================================================
# STEP 5: GNOME dconf default wallpaper (only if wallpaper shipped)
# ====================================================================
# Override Fedora default background. User can override at runtime.
# Lock only if we want to enforce (we don't — user freedom).
log "STEP 5: GNOME dconf wallpaper override"

if [ -f /usr/share/backgrounds/noid-privacy/default.png ]; then
    # Both variants passed STEP 4's exact manifest and install postcondition.
    DARK_URI="file:///usr/share/backgrounds/noid-privacy/default-dark.png"

    install -d -m 0755 -o root -g root /etc/dconf/db/distro.d
    publish_root_file /etc/dconf/db/distro.d/40-noid-wallpaper \
        0644 <<DCONF_EOF
# NoID Privacy Workstation — default wallpaper
# Light = drool-l, Dark = drool-d (GNOME gnome-backgrounds, CC-BY-SA-3.0).
# User can override at runtime via GNOME Settings > Appearance.
[org/gnome/desktop/background]
picture-uri='file:///usr/share/backgrounds/noid-privacy/default.png'
picture-uri-dark='${DARK_URI}'
picture-options='zoom'
primary-color='#000000'
secondary-color='#000000'

[org/gnome/desktop/screensaver]
picture-uri='${DARK_URI}'
picture-options='zoom'
DCONF_EOF

    # M08/M17 define the single shared profile as user-db:user, site, distro.
    # `local` is not loaded. Retire the historical duplicate and compile the
    # active distro database now; dbus-update-activation-environment does not
    # compile dconf keyfiles and therefore is not a valid first-boot fallback.
    rm -f -- /etc/dconf/db/local.d/40-noid-wallpaper
    # Retire the historical GDM logo keyfile before this single compiler pass;
    # deleting it only after dconf update would leave the stale key compiled.
    rm -f -- /etc/dconf/db/distro.d/42-noid-login-logo
    if ! command -v dconf >/dev/null 2>&1; then
        check fail "STEP 5: dconf compiler unavailable"
    elif ! dconf update; then
        check fail "STEP 5: dconf database compilation failed"
    elif [ ! -s /etc/dconf/db/distro ]; then
        check fail "STEP 5: compiled distro database missing or empty"
    elif [ "$(DCONF_PROFILE=user dconf read -d \
            /org/gnome/desktop/background/picture-uri 2>/dev/null || true)" != \
            "'file:///usr/share/backgrounds/noid-privacy/default.png'" ] \
       || [ "$(DCONF_PROFILE=user dconf read -d \
            /org/gnome/desktop/background/picture-uri-dark 2>/dev/null || true)" != \
            "'${DARK_URI}'" ]; then
        check fail "STEP 5: active dconf profile does not expose both wallpaper defaults"
    else
        check ok "STEP 5: active dconf wallpaper defaults compiled and verified"
        log "  [OK] dconf wallpaper override written (light=default.png, dark=${DARK_URI##*/}) — distro profile"
    fi

    # gschema-level factory default: GIS runs as a fresh GDM child session
    # BEFORE any user dconf exists, so it falls back to gschema FACTORY
    # defaults (Fedora's 10_*.fedora.gschema.override). The 90_ prefix
    # sorts later in glib-compile-schemas and wins; Fedora's files stay
    # untouched. screensaver picture-uri-dark deliberately NOT set (key
    # absent from that schema -> compile WARN).

    publish_root_file \
        /usr/share/glib-2.0/schemas/90_org.gnome.desktop.background.noid.gschema.override \
        0644 <<'GSCHEMA_BG_EOF'
# NoID Privacy Workstation — wallpaper factory default override
# Priority 90_ supersedes Fedora's 10_org.gnome.desktop.background.fedora.
# Visible during gnome-initial-setup first-boot wizard (= first user impression).
[org.gnome.desktop.background]
picture-uri='file:///usr/share/backgrounds/noid-privacy/default.png'
picture-uri-dark='file:///usr/share/backgrounds/noid-privacy/default-dark.png'
picture-options='zoom'
primary-color='#000000'
secondary-color='#000000'
GSCHEMA_BG_EOF

    publish_root_file \
        /usr/share/glib-2.0/schemas/90_org.gnome.desktop.screensaver.noid.gschema.override \
        0644 <<'GSCHEMA_SS_EOF'
# NoID Privacy Workstation — screensaver factory default override
# Priority 90_ supersedes Fedora's 10_org.gnome.desktop.screensaver.fedora.
[org.gnome.desktop.screensaver]
picture-uri='file:///usr/share/backgrounds/noid-privacy/default-dark.png'
picture-options='zoom'
GSCHEMA_SS_EOF

    # Re-compile gschemas to pick up new overrides. Idempotent — also runs
    # when other modules drop schemas (e.g. NoID Privacy dnf upgrade can trigger
    # /usr/share/glib-2.0/schemas/* changes via post-upgrade gtk hooks).
    if command -v glib-compile-schemas >/dev/null 2>&1; then
        # Suppress harmless ibus deprecation warnings (path-prefix `/desktop/`)
        # and Fedora's pre-existing screensaver picture-uri-dark warning.
        if glib_output=$(glib-compile-schemas /usr/share/glib-2.0/schemas/ 2>&1); then
            printf '%s\n' "$glib_output" \
                | grep -vE "Schema .*has path .*deprecated|picture-uri-dark.*screensaver" \
                || :
            log "  [OK] gschema override compiled (90_..noid.gschema.override → wins over 10_..fedora)"
        else
            printf '%s\n' "$glib_output" >&2
            check fail "STEP 5: glib schema compilation failed"
        fi
    else
        check fail "STEP 5: glib-compile-schemas unavailable"
    fi

    # Verify the compiled gschema factory default without a user database or
    # session bus. The in-memory backend is deterministic in the build chroot.
    if command -v gsettings >/dev/null 2>&1; then
        FACTORY_BG=$(GSETTINGS_BACKEND=memory gsettings get \
            org.gnome.desktop.background picture-uri 2>/dev/null || true)
        FACTORY_BG_DARK=$(GSETTINGS_BACKEND=memory gsettings get \
            org.gnome.desktop.background picture-uri-dark 2>/dev/null || true)
        if [ "$FACTORY_BG" = \
                "'file:///usr/share/backgrounds/noid-privacy/default.png'" ] \
           && [ "$FACTORY_BG_DARK" = \
                "'file:///usr/share/backgrounds/noid-privacy/default-dark.png'" ]; then
            check ok "STEP 5: light/dark gschema factory defaults verified"
        else
            check fail "STEP 5: light/dark gschema factory defaults are incorrect"
        fi
    else
        check fail "STEP 5: gsettings unavailable for factory-default verification"
    fi
else
    log "  [skip] no wallpaper asset present — dconf step skipped"
fi

# STEP 5 verification: wallpaper asset OR
# dconf override must accompany the mandatory wallpaper payload.
if [ -f /etc/dconf/db/distro.d/40-noid-wallpaper ]; then
    check ok "STEP 5: dconf wallpaper override installed"
else
    check fail "STEP 5: dconf wallpaper override missing"
fi

# ====================================================================
# STEP 5b: GDM login-screen logo — REMOVED
# ====================================================================
# The login-screen-logo dconf override rendered massively oversized on
# GDM 50 and overlapped the user-avatar slot — removed by user decision;
# the user-avatar carries the NoID Privacy identity instead. STEP 5 deletes
# the historical keyfile before its mandatory dconf compiler pass.
log "STEP 5b: login-screen-logo dconf override removed (user-avatar carries NoID Privacy branding instead)"

# Verify both source and compiled database; keyfile absence alone would not
# prove that a pre-existing compiled logo default was retired.
if command -v dconf >/dev/null 2>&1 \
   && [ ! -e /etc/dconf/db/distro.d/42-noid-login-logo ] \
   && [ ! -L /etc/dconf/db/distro.d/42-noid-login-logo ] \
   && [ -z "$(DCONF_PROFILE=user dconf read -d \
        /org/gnome/login-screen/logo 2>/dev/null || true)" ]; then
    check ok "STEP 5b: login-screen-logo keyfile and compiled default absent"
else
    check fail "STEP 5b: stale login-screen-logo keyfile or compiled default present"
fi

# Verification is inline per STEP (counter + check() live at the top);
# the issue.d trademark file is gone — no verify for it.

# ====================================================================
# STEP 7: /etc/noid-build-info — build-provenance tracking
# ====================================================================
# Build-provenance metadata, KEY=VALUE (`source /etc/noid-build-info`).
# Fields include the canonical source commit, deterministic build ID and the
# signed-manifest-verified Fedora base-ISO digest.
# Shipped to BOTH live and installed systems.
log "STEP 7: writing /etc/noid-build-info (build-provenance metadata)"

# NOID_KERNEL uses `rpm -q kernel-core` — `uname -r` in Anaconda %post
# returns the livemedia-creator build-VM kernel, not the installed one.
# NOID_VERSION bumps only on an explicit release GO (currently v1.7).
NOID_BUILD_EPOCH="@@NOID_BUILD_EPOCH@@"
case "$NOID_BUILD_EPOCH" in
    ''|*[!0-9]*)
        log "  [FAIL] STEP 7: invalid canonical build epoch: $NOID_BUILD_EPOCH"
        exit 1
        ;;
esac
NOID_BUILD_DATE_VALUE="$(date -u -d "@${NOID_BUILD_EPOCH}" +%F)"
NOID_BUILD_TIMESTAMP_VALUE="$(date -u -d "@${NOID_BUILD_EPOCH}" +%FT%TZ)"
NOID_BUILD_ID_VALUE="@@NOID_BUILD_ID@@"
NOID_SOURCE_COMMIT_VALUE="@@NOID_SOURCE_COMMIT@@"
NOID_BASE_ISO_SHA256_VALUE="@@NOID_BASE_ISO_SHA256@@"
NOID_KERNEL_VALUE="$(rpm -q kernel-core \
    --queryformat '%{version}-%{release}.%{arch}\n' 2>/dev/null \
    | LC_ALL=C sort -V | tail -1)"
[[ "$NOID_BUILD_ID_VALUE" =~ ^[0-9a-f]{12}-[0-9]+$ ]] || {
    log "  [FAIL] STEP 7: invalid canonical build ID"
    exit 1
}
[[ "$NOID_SOURCE_COMMIT_VALUE" =~ ^[0-9a-f]{40}$ ]] || {
    log "  [FAIL] STEP 7: invalid canonical source commit"
    exit 1
}
[[ "$NOID_BASE_ISO_SHA256_VALUE" == "not-applicable" \
   || "$NOID_BASE_ISO_SHA256_VALUE" =~ ^[0-9a-f]{64}$ ]] || {
    log "  [FAIL] STEP 7: invalid base-ISO provenance"
    exit 1
}
[[ "$NOID_KERNEL_VALUE" =~ ^[0-9][0-9A-Za-z._+~-]*-[0-9][0-9A-Za-z._+~-]*\.x86_64$ ]] || {
    log "  [FAIL] STEP 7: installed kernel-core provenance is empty or malformed"
    exit 1
}
publish_root_file /etc/noid-build-info 0644 <<BUILDINFO_EOF
NOID_NAME="NoID Privacy Workstation"
NOID_VERSION="v1.7"
NOID_BUILD_ID="${NOID_BUILD_ID_VALUE}"
NOID_BUILD_DATE="${NOID_BUILD_DATE_VALUE}"
NOID_BUILD_TIMESTAMP="${NOID_BUILD_TIMESTAMP_VALUE}"
NOID_SOURCE_COMMIT="${NOID_SOURCE_COMMIT_VALUE}"
NOID_BASE_ISO_SHA256="${NOID_BASE_ISO_SHA256_VALUE}"
NOID_BASE="Fedora Linux 44"
NOID_KERNEL="${NOID_KERNEL_VALUE}"
NOID_REPO="https://github.com/NexusOne23/noid-privacy-workstation"
BUILDINFO_EOF

if grep -qxF "NOID_BUILD_DATE=\"${NOID_BUILD_DATE_VALUE}\"" /etc/noid-build-info \
    && grep -qxF "NOID_BUILD_TIMESTAMP=\"${NOID_BUILD_TIMESTAMP_VALUE}\"" /etc/noid-build-info \
    && grep -qxF "NOID_SOURCE_COMMIT=\"${NOID_SOURCE_COMMIT_VALUE}\"" /etc/noid-build-info \
    && grep -qxF "NOID_BASE_ISO_SHA256=\"${NOID_BASE_ISO_SHA256_VALUE}\"" /etc/noid-build-info \
    && grep -qxF "NOID_KERNEL=\"${NOID_KERNEL_VALUE}\"" /etc/noid-build-info; then
    check ok "STEP 7: noid-build-info carries canonical source/base provenance"
else
    check fail "STEP 7: noid-build-info date/timestamp missing or incorrect"
fi

# ====================================================================
# STEP 7a.1: Branding behavior documentation
# ====================================================================
# Target for the Documentation= links on avatar and Plymouth maintenance
# units. Branding changes no network or security policy.
# Shipped Markdown target: /usr/share/doc/noid-privacy/32-branding.md
install -d -m 0755 -o root -g root /usr/share/doc/noid-privacy
publish_root_file /usr/share/doc/noid-privacy/32-branding.md 0644 <<'BRANDING_DOC_EOF'
# NoID Privacy Branding Components

Module 32 installs the NoID Privacy desktop, boot, installer and account-avatar
artwork. Branding is presentation only; it grants no security property and
does not contact a project service.

## First-boot maintenance

- `noid-user-avatar-backfill.service` provisions the default avatar during a
  newly discovered user's initial settling window, then seals that user with a
  sentinel. The companion path unit notices newly created accounts, while the
  helper uses AccountsService's maintained `SetIconFile` API and verifies the
  result during the strict settling pass. Avatar choices made after sealing persist.
- Module 21's `noid-dracut-hostonly-firstboot.service` is the sole
  target-kernel initramfs writer. Its staged candidate must contain this
  module's Plymouth configuration, bgrt theme and watermark before atomic
  publication.

Inspect them with:

```bash
systemctl status noid-user-avatar-backfill.service
systemctl status noid-dracut-hostonly-firstboot.service
journalctl -u noid-dracut-hostonly-firstboot.service -b
```

Users may replace their avatar or desktop background normally. Trademark and
upstream attribution are documented separately in `trademark-notice.md`.
BRANDING_DOC_EOF

# ====================================================================
# STEP 7b: /usr/share/doc/noid-privacy/trademark-notice.md
# ====================================================================
# Trademark + attribution disclosure (Fedora Trademark Guidelines;
# Rocky/Alma derivatives ship equivalents). Covers product identity
# (independent derivative, NOT "Fedora Remix"), Fedora/Red Hat/GNOME/
# Linux trademark notices, licensing boundaries, bug-routing direction and
# GPL source-availability responsibilities.
log "STEP 7b: writing /usr/share/doc/noid-privacy/trademark-notice.md"

# Shipped Markdown target: /usr/share/doc/noid-privacy/trademark-notice.md
publish_root_file /usr/share/doc/noid-privacy/trademark-notice.md 0644 <<'TRADEMARK_EOF'
# NoID Privacy Workstation — Trademark + Attribution Notice

## Product identity

**NoID Privacy Workstation** is an independent Linux distribution
derived from Fedora Linux 44. It is **NOT** affiliated with, endorsed
by, or sponsored by:

- The Fedora Project
- Red Hat, Inc.
- The GNOME Project
- Any other upstream project whose software is included.

NoID Privacy Workstation is built upon Fedora Linux 44 and is a
"derivative of Fedora" — it is **NOT** an "edition of Fedora", nor
is it branded as a "Fedora Remix". The project does not use the optional
Fedora Remix Secondary Mark or present this image as a Fedora product.

## Trademark notices

- **"Fedora"** is a registered trademark of Red Hat, Inc. The
  trademark appears in this distribution **only** to indicate
  upstream-base attribution: `/etc/os-release UPSTREAM_BASE="Fedora
  Linux 44"` and `ID_LIKE=fedora`. NoID Privacy Workstation does not
  use the Fedora name, the Infinity design logo, the "Fedora Remix"
  Secondary Mark, or any other Fedora trademarks as identifying marks
  for this product.

- **"Red Hat"** and the Red Hat logo are registered trademarks of
  Red Hat, Inc. Red Hat-vendor-specific os-release fields
  (REDHAT_BUGZILLA_PRODUCT, REDHAT_SUPPORT_PRODUCT) have been REMOVED
  from this distribution per current derivative-distro practice.

- **"GNOME"** is a trademark of the GNOME Foundation. This image uses
  Fedora's GNOME packages together with NoID Privacy policy, defaults,
  branding and locally maintained integration components.

- **"Linux"** is a registered trademark of Linus Torvalds.

## Licensing boundary

NoID Privacy-owned code and machine-readable policy are open-source under
the licenses inventoried in the repository `LICENSING.md`. Documentation,
original artwork and third-party components retain their separately stated
licenses; in particular, original NoID Privacy branding artwork is not
relicensed as open-source merely because it is included in this image.

Fedora RPM metadata records the license expression for each packaged
component. Packages install applicable license or notice files in their
declared payload locations, commonly below `/usr/share/licenses/`; the exact
path and terms are package-specific.

## Bug reports + support

- **Bug reports + feature requests:**
  https://github.com/NexusOne23/noid-privacy-workstation/issues
- **Documentation:**
  https://github.com/NexusOne23/noid-privacy-workstation/tree/main/docs
- **Project website:** https://noid-privacy.com
- **Other NoID Privacy platforms (Windows / Android):**
  https://noid-privacy.com — see also `ecosystem-and-support.md` in
  this directory
- **Support the project (optional donation):**
  https://buymeacoffee.com/noidprivacy

Start with the NoID Privacy issue tracker when a problem may involve this
image's policy, integration or rebranding. A bug independently confirmed in
an unmodified upstream component may be reported to that component's
maintainer; disclose that the observation came from a Fedora-derived image
and include a reproducer that separates upstream behavior from local policy.

## Why "derivative" not "Fedora Remix"?

Fedora documents "Fedora Remix" as an optional Secondary Mark for
Fedora-derived combinations that follow its branding conditions.
Substantive modification does not itself disqualify a project from being a
Remix. NoID Privacy Workstation simply does not adopt that optional mark or naming:
its product identity is NoID Privacy Workstation, with Fedora stated only as
the upstream base.

NoID Privacy is therefore presented as "an independent Linux distribution
derived from Fedora Linux 44" — a descriptive upstream attribution that
avoids implying endorsement by upstream projects.

## Source code availability (GPL compliance)

Useful source-location starting points for GPL-licensed components are:

- **Upstream Fedora packages:** https://src.fedoraproject.org/
  (resolves binary RPMs to SRPM source via dist-git)
- **NoID Privacy-specific kickstart + scripts:**
  https://github.com/NexusOne23/noid-privacy-workstation
- **Installed license/notice files:** package-declared payload locations,
  commonly under `/usr/share/licenses/`
- **dnf source command:** `dnf download --source <package>` may
  resolve upstream SRPMs (depending on repo configuration)

These links do not by themselves replace a distributor's obligation to
provide the exact corresponding source in the manner required by the
applicable license and distribution method. Anyone redistributing this image
or its binaries must independently preserve the applicable notices and
source-provision obligations. This section is operational guidance, not legal
advice.

## Removing this notice

This file may be removed by the user without breaking system
functionality. However, the trademark + attribution claims above
remain factually applicable to any redistribution of NoID Privacy
Workstation, regardless of whether this notice file is present.

---
NoID Privacy Workstation 44
TRADEMARK_EOF

[ -f /usr/share/doc/noid-privacy/trademark-notice.md ] \
    && check ok "STEP 7b: trademark-notice.md deployed" \
    || check fail "STEP 7b: trademark-notice.md missing"

grep -q "Fedora.*registered trademark of Red Hat" /usr/share/doc/noid-privacy/trademark-notice.md \
    && check ok "STEP 7b: trademark-notice.md content verified (Fedora trademark disclosure)" \
    || check fail "STEP 7b: trademark-notice.md content incomplete"

log "  [OK] trademark-notice.md written (full Fedora/RedHat/GNOME/Linux disclosure)"

# ====================================================================
# STEP 7c: Ecosystem + support doc (website / siblings / donations)
# ====================================================================
# 2026-07-05: before this step the installed system carried ZERO donation
# surface and the Android/Windows sibling products were invisible outside
# the GitHub README. This doc is the canonical in-system reference for
# the project website, the sibling platforms, and how to support
# development. Surfaced in three places: noid-help (auto-indexes *.md in
# this directory), the 00-README.md doc index (M29), and the welcome
# dialog's "Project & Ecosystem" group (M13). Deliberately a
# static file — no timer, no popup, no nag (Silent-Machine posture: M17
# locks the GNOME Foundation donation reminder off; shipping our own recurring
# reminder would be the same noise class). Mutable counts and release versions stay on the project
# website instead of being copied into installed image bytes.

log "STEP 7c: ecosystem-and-support.md"

# Shipped Markdown target: /usr/share/doc/noid-privacy/ecosystem-and-support.md
publish_root_file /usr/share/doc/noid-privacy/ecosystem-and-support.md 0644 <<'ECOSYSTEM_EOF'
# NoID Privacy — Ecosystem + Supporting the Project

NoID Privacy Workstation is part of a small cross-platform family of
privacy tools. This static document is indexed by the local help system and
linked from the welcome/documentation surfaces; there are no recurring project
marketing reminders, telemetry beacons or automatic support-page checks.

## The NoID Privacy family

| Platform | What it is | Where |
|----------|------------|-------|
| **Linux distro** | This system — NoID Privacy Workstation | You are running it |
| **Windows** | Open-source PowerShell hardening engine (GPL-3.0); optional commercial Pro GUI | <https://github.com/NexusOne23/noid-privacy> + <https://noid-privacy.com> |
| **Android** | Local privacy/security audit and hardening guidance, including device, account, permission and anti-theft checks | Google Play: <https://play.google.com/store/apps/details?id=com.noid.privacy> |
| **Linux audit tool** | Non-remediating-by-default privacy/security audit (single-file pure Bash; applicable host tools are detected at runtime) — bundled in this image as `noid-privacy-linux.sh` | <https://github.com/NexusOne23/noid-privacy-linux> |

Everything current — downloads, docs, and pricing for the one
commercial component (the Windows Pro GUI) — lives on the project
website:

> **<https://noid-privacy.com>**

## Supporting the project

The NoID Privacy system code and policy are open-source under their stated
licenses. Documentation, third-party payloads and original artwork retain
their separately stated licenses. The image adds no NoID Privacy telemetry or
ads and contains no in-OS upsell workflow. Documented network control traffic
and third-party applications remain outside that narrow claim. If it is useful
to you, there are three ways to support it — all strictly optional:

- **Donate a coffee:** <https://buymeacoffee.com/noidprivacy>
- **Star / share the repos:**
  <https://github.com/NexusOne23/noid-privacy-workstation>
- **Report bugs + ideas:**
  <https://github.com/NexusOne23/noid-privacy-workstation/issues>

If NoID Privacy saves you or your company real hardening hours on
Windows machines, the commercial Pro GUI is how the project finances
itself: <https://noid-privacy.com>

## Privacy note (why this page is static)

Consistent with the Silent-Machine posture documented in
`00-architecture.md`:

- The links above are plain text — no beacons, no tracking parameters,
  no unique URLs.
- The OS never opens or checks these sites on its own; every visit is
  a deliberate click by you.
- The GNOME Foundation donation reminder (GNOME 49+) is disabled in this
  image (Module 17). The same courtesy applies to our own project: one static
  page, no nags.

---
NoID Privacy Workstation 44
ECOSYSTEM_EOF

[ -f /usr/share/doc/noid-privacy/ecosystem-and-support.md ] \
    && check ok "STEP 7c: ecosystem-and-support.md deployed" \
    || check fail "STEP 7c: ecosystem-and-support.md missing"

grep -q "buymeacoffee.com/noidprivacy" /usr/share/doc/noid-privacy/ecosystem-and-support.md \
    && check ok "STEP 7c: ecosystem-and-support.md content verified (donation link)" \
    || check fail "STEP 7c: ecosystem-and-support.md content incomplete"

log "  [OK] ecosystem-and-support.md written (website + siblings + donations, static/no-nag)"

# ====================================================================
# STEP 8: Anaconda Welcome-Dialog + dock icon rebrand
# ====================================================================
# The Welcome dialog + installer launcher carry hardcoded Fedora-mascot
# icon names + "Welcome to Fedora" labels — sed the GJS script, the
# .desktop files and the icon-theme entries to the NoID Privacy logo (assets
# already installed by STEP 4; GTK icon-name lookup finds them).
log "STEP 8: Anaconda welcome dialog + dock icon rebrand"

# 1. fedora-welcome GJS script — replace iconName lookup
if [ -f /usr/share/anaconda/gnome/fedora-welcome ]; then
    sed -i "s/iconName: *'fedora-logo-icon'/iconName: 'noid-privacy-logo'/" \
        /usr/share/anaconda/gnome/fedora-welcome
    if grep -q "iconName: 'noid-privacy-logo'" /usr/share/anaconda/gnome/fedora-welcome; then
        log "  [OK] fedora-welcome GJS script: iconName → noid-privacy-logo"
    else
        log "  [WARN] fedora-welcome iconName sed had no effect"
    fi
fi

# 2. anaconda.desktop — replace Icon + ALL Name[xx] lines (de-localize)
# Switched Icon from noid-privacy-logo (plain shield) to
# noid-privacy-install (shield with "Install" text label) for visual consistency
# with the other labeled NoID Privacy app launchers. The plain
# shield logo stays as noid-privacy-logo for /usr/share/pixmaps/ + os-release LOGO=.
if [ -f /usr/share/applications/anaconda.desktop ]; then
    # Icon line — was fedora-logo-icon (Hot-Dog), now noid-privacy-install
    sed -i 's/^Icon=fedora-logo-icon/Icon=noid-privacy-install/' \
        /usr/share/applications/anaconda.desktop
    # Upgrade the former Icon=noid-privacy-logo value to the install variant.
    sed -i 's/^Icon=noid-privacy-logo$/Icon=noid-privacy-install/' \
        /usr/share/applications/anaconda.desktop
    # English Name (drop all Name[xx]= localized variants — single English line)
    sed -i '/^Name\[/d' /usr/share/applications/anaconda.desktop
    sed -i 's/^Name=Welcome to Fedora/Name=Welcome to NoID Privacy Workstation 44/' \
        /usr/share/applications/anaconda.desktop
    # GenericName + Comment if "Fedora" present
    sed -i 's/^GenericName=.*Fedora.*/GenericName=NoID Privacy Workstation/' \
        /usr/share/applications/anaconda.desktop 2>/dev/null || true
    sed -i 's/^Comment=.*Fedora.*/Comment=NoID Privacy Workstation Live & Installer/' \
        /usr/share/applications/anaconda.desktop 2>/dev/null || true
    if grep -q "Icon=noid-privacy-install" /usr/share/applications/anaconda.desktop \
       && grep -q "Name=Welcome to NoID Privacy" /usr/share/applications/anaconda.desktop; then
        log "  [OK] anaconda.desktop: Icon + Name rebranded to NoID Privacy"
    else
        log "  [INFO] anaconda.desktop sed dead during build (livesys-gnome renames"
        log "         liveinst.desktop → anaconda.desktop at Live boot — see liveinst handler)"
    fi
fi

# 3. liveinst.desktop (the "Install" launcher). livesys-gnome renames it
# to anaconda.desktop at LIVE BOOT, not at build time — so the
# anaconda.desktop sed above is build-time dead code and THIS block is
# the one that actually lands; the renamed file inherits the icon.
if [ -f /usr/share/applications/liveinst.desktop ]; then
    sed -i 's/^Icon=.*/Icon=noid-privacy-install/' /usr/share/applications/liveinst.desktop
    sed -i '/^Name\[/d' /usr/share/applications/liveinst.desktop
    sed -i 's/^Name=.*Fedora.*/Name=Install NoID Privacy Workstation/' \
        /usr/share/applications/liveinst.desktop
    sed -i 's/^Name=Install to Hard Drive$/Name=Install NoID Privacy Workstation/' \
        /usr/share/applications/liveinst.desktop
    if grep -q "^Icon=noid-privacy-install$" /usr/share/applications/liveinst.desktop; then
        log "  [OK] liveinst.desktop: Icon=noid-privacy-install + Name rebranded"
    else
        log "  [WARN] liveinst.desktop: sed had partial effect"
    fi
fi

# 4. noid-privacy-logo in all standard hicolor sizes (pre-rendered on the
# build host — no ImageMagick in the image runtime). The full size set
# matters: GNOME shell falls back to the executable-name icon at 32-64px
# when a requested size is missing. STEP 4 adds 512 + 1024 separately ->
# 10 hicolor variants total + the pixmaps copy.
LOGO_VARIANT_COUNT=0
for size in 16 24 32 48 64 96 128 256; do
    src="$BRANDING_PAYLOAD/icons/noid-privacy-logo-${size}.png"
    dst="/usr/share/icons/hicolor/${size}x${size}/apps/noid-privacy-logo.png"
    if [ -f "$src" ]; then
        install -Dm0644 "$src" "$dst"
        LOGO_VARIANT_COUNT=$((LOGO_VARIANT_COUNT + 1))
    fi
done
if [ "$LOGO_VARIANT_COUNT" -eq 8 ]; then
    check ok "STEP 8: all 8 noid-privacy-logo variants installed (16-256)"
else
    check fail "STEP 8: logo variant payload incomplete ($LOGO_VARIANT_COUNT/8)"
fi

# 8a. Override anaconda.png across all icon sizes with noid-privacy-logo
# Defensive fallback: if GNOME shell falls back to executable name "anaconda"
# (e.g. cache miss for noid-privacy-logo at unusual size), the anaconda.png
# MUST also show NoID Privacy logo, not Fedora hot-dog character.
ANACONDA_OVERRIDE_COUNT=0
while IFS= read -r anaconda_icon; do
    [ -n "$anaconda_icon" ] || continue
    size_dir=$(basename "$(dirname "$(dirname "$anaconda_icon")")")
    size_num=${size_dir%x*}
    src_logo="/usr/share/icons/hicolor/${size_num}x${size_num}/apps/noid-privacy-logo.png"
    [ -f "$src_logo" ] || src_logo="/usr/share/pixmaps/noid-privacy-logo.png"
    if cp "$src_logo" "$anaconda_icon" 2>/dev/null; then
        ANACONDA_OVERRIDE_COUNT=$((ANACONDA_OVERRIDE_COUNT + 1))
    fi
done < <(find /usr/share/icons -name 'anaconda.png' 2>/dev/null)
# Remove anaconda.svg → force PNG-only fallback (which is now NoID Privacy logo)
find /usr/share/icons -name 'anaconda.svg' -delete 2>/dev/null || true
log "  [OK] anaconda.png overridden with NoID Privacy logo in $ANACONDA_OVERRIDE_COUNT sizes"

# 8b. Anaconda's INTERNAL pixmaps (sidebar-logo.png + anaconda_header.png)
# are referenced by path from Python — not via icon-theme lookup — and
# carry the Fedora mascot; override both. Backgrounds stay (aspect-ratio
# UI chrome, not logo placements).
if [ -d /usr/share/anaconda/pixmaps ]; then
    if [ -f /usr/share/icons/hicolor/128x128/apps/noid-privacy-logo.png ]; then
        cp /usr/share/icons/hicolor/128x128/apps/noid-privacy-logo.png \
            /usr/share/anaconda/pixmaps/sidebar-logo.png 2>/dev/null \
            && log "  [OK] /usr/share/anaconda/pixmaps/sidebar-logo.png overridden with NoID Privacy logo (128×128)" \
            || log "  [WARN] sidebar-logo.png override failed"
    fi
    if [ -f /usr/share/icons/hicolor/96x96/apps/noid-privacy-logo.png ]; then
        cp /usr/share/icons/hicolor/96x96/apps/noid-privacy-logo.png \
            /usr/share/anaconda/pixmaps/anaconda_header.png 2>/dev/null \
            && log "  [OK] /usr/share/anaconda/pixmaps/anaconda_header.png overridden with NoID Privacy logo (96×96)" \
            || log "  [WARN] anaconda_header.png override failed"
    fi
fi

# 8c. generic-logos (M26 swap) STILL ships the Fedora mascot under the
# fedora-logo-icon/-sprite names that the Welcome dialog resolves via
# icon-theme. Delete the SVGs (forces PNG fallback) + provide NoID Privacy PNGs
# under the fedora-logo-icon name.
log "STEP 8c: override generic-logos hot-dog SVG/PNG with NoID Privacy logo"

# Delete hot-dog SVGs in scalable theme — forces PNG-only icon theme resolution
find /usr/share/icons -name 'fedora-logo-icon.svg' -delete 2>/dev/null || true
find /usr/share/icons -name 'fedora-logo-sprite.svg' -delete 2>/dev/null || true
rm -f /usr/share/pixmaps/fedora-logo-sprite.svg 2>/dev/null || true
log "  [OK] fedora-logo-icon.svg + fedora-logo-sprite.svg deleted (forces PNG fallback)"

# Provide PNG sizes for fedora-logo-icon icon-name lookup (theme resolution path)
for size in 16 24 32 48 64 96 128 256 512; do
    src="/usr/share/icons/hicolor/${size}x${size}/apps/noid-privacy-logo.png"
    dst="/usr/share/icons/hicolor/${size}x${size}/apps/fedora-logo-icon.png"
    if [ -f "$src" ]; then
        cp "$src" "$dst" 2>/dev/null \
            && log "  [OK] fedora-logo-icon.png ${size}×${size} created from NoID Privacy logo" \
            || log "  [WARN] fedora-logo-icon.png ${size}×${size} create failed"
    fi
done

# Override fedora-logo.png (portrait 240×310 hot-dog) with NoID Privacy logo at 256×256
if [ -f /usr/share/icons/hicolor/256x256/apps/noid-privacy-logo.png ]; then
    cp /usr/share/icons/hicolor/256x256/apps/noid-privacy-logo.png \
        /usr/share/pixmaps/fedora-logo.png 2>/dev/null \
        && log "  [OK] /usr/share/pixmaps/fedora-logo.png overridden with NoID Privacy logo" \
        || log "  [WARN] fedora-logo.png override failed"
fi

# 8d. Override org.fedoraproject.welcome-screen.desktop — live testing
# revealed: this .desktop file is owned by anaconda-live and was missed by Module 32's
# anaconda.desktop sed. It still has Icon=fedora-logo-icon + Name=Welcome to Fedora.
# Plus there's a parallel copy at /usr/share/anaconda/gnome/org.fedoraproject.welcome-screen.desktop
# (the package source — gets installed to /usr/share/applications/ at runtime).
log "STEP 8d: rebrand org.fedoraproject.welcome-screen.desktop"

for ws_desktop in /usr/share/applications/org.fedoraproject.welcome-screen.desktop \
                  /usr/share/anaconda/gnome/org.fedoraproject.welcome-screen.desktop; do
    if [ -f "$ws_desktop" ]; then
        sed -i 's|^Icon=fedora-logo-icon|Icon=noid-privacy-logo|' "$ws_desktop"
        # Drop all localized Name[xx] lines — single canonical English Name
        sed -i '/^Name\[/d' "$ws_desktop"
        sed -i 's|^Name=Welcome to Fedora|Name=Welcome to NoID Privacy Workstation 44|' "$ws_desktop"
        log "  [OK] $(basename "$ws_desktop") rebranded (Icon + Name)"
    fi
done

# 8e. fedora-welcome reads NAME= -> patch to PRETTY_NAME= so the version
# number shows in title/description/install button. User decision:
# version-display wins over button-fit (Pango truncation of the long
# install-button label accepted as cosmetic).
log "STEP 8e: patch fedora-welcome NAME → PRETTY_NAME (user decision: show 44 everywhere)"
if [ -f /usr/share/anaconda/gnome/fedora-welcome ]; then
    sed -i "s|line.startsWith('NAME=')|line.startsWith('PRETTY_NAME=')|" \
        /usr/share/anaconda/gnome/fedora-welcome
    if grep -q "startsWith('PRETTY_NAME=')" /usr/share/anaconda/gnome/fedora-welcome; then
        log "  [OK] fedora-welcome reads PRETTY_NAME → 44 visible in title/description/button"
    else
        log "  [WARN] fedora-welcome PRETTY_NAME patch had no effect"
    fi
else
    log "  [WARN] /usr/share/anaconda/gnome/fedora-welcome not found — skipping PRETTY_NAME patch"
fi

# 8f. Update icon cache so GTK picks up the changes immediately
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null \
        || log "  [WARN] gtk-update-icon-cache returned non-zero (non-fatal)"
fi

log "STEP 8 done — anaconda welcome+dock icon rebranded"

# STEP 8 verification: anaconda welcome rebrand. fedora-welcome is the
# surface that exists at build time (anaconda.desktop only appears at Live
# boot via the liveinst.desktop rename) — when it is present its iconName
# patch is the load-bearing gate; anaconda.desktop gates the rare case it
# already exists; both absent = nothing to rebrand.
if [ -f /usr/share/anaconda/gnome/fedora-welcome ]; then
    if grep -q "iconName: 'noid-privacy-logo'" /usr/share/anaconda/gnome/fedora-welcome; then
        check ok "STEP 8: anaconda welcome rebrand (fedora-welcome iconName patched)"
    else
        check fail "STEP 8: anaconda welcome rebrand — fedora-welcome iconName not patched"
    fi
elif [ -f /usr/share/applications/anaconda.desktop ]; then
    if grep -q "^Icon=noid-privacy-install" /usr/share/applications/anaconda.desktop; then
        check ok "STEP 8: anaconda welcome rebrand (anaconda.desktop Icon patched)"
    else
        check fail "STEP 8: anaconda welcome rebrand — anaconda.desktop Icon not patched"
    fi
else
    check ok "STEP 8: anaconda welcome rebrand (no welcome sources present)"
fi

# The HTTP payload is build-only and lives in a collision-safe private tree.
# Retire it only after STEP 8 has consumed the verified 16–256 px logo sources
# and every resulting icon/welcome surface has reached its postcondition.
if [ -n "${BRANDING_FETCH_DIR:-}" ]; then
    cleanup_branding_fetch
    trap - EXIT
    BRANDING_FETCH_DIR=
    BRANDING_PAYLOAD=
fi

# ====================================================================
# STEP 8g: runtime branding recovery (generic-logos / plymouth stomps)
# ====================================================================
# generic-logos upgrades reinstall the stock logo pixmaps/hicolor icons and
# recreate the SVGs deleted in STEP 8c; plymouth-theme-spinner upgrades
# reinstall bgrt.plymouth with stock layout values. None of those payload
# files carry %config protection, so the stomp is silent — and afterwards
# rpm -Va reports a clean file, so there is no detection path either.
# Same recovery pattern as STEP 3c (identity): cache the NoID Privacy
# sources in an own namespace, ship an idempotent helper, and trigger it
# from a libdnf5-actions file scoped to the owning packages. The canonical
# helper invocation in noid-update-all.sh stays as an end-to-end postcondition
# for orchestrated updates; this action covers direct `dnf upgrade` runs.
log "STEP 8g: runtime branding recovery (helper + dnf5 action)"

install -d -m 0755 /usr/share/noid-privacy/branding
for cache_pair in \
    "/usr/share/pixmaps/system-logo-white.png::system-logo-white.png" \
    "/usr/share/plymouth/themes/spinner/watermark.png::watermark.png"; do
    cache_src="${cache_pair%%::*}"
    cache_dst="/usr/share/noid-privacy/branding/${cache_pair##*::}"
    if [ -f "$cache_src" ]; then
        publish_root_file "$cache_dst" 0644 <"$cache_src"
        log "  [OK] branding cache: $cache_dst"
    else
        log "  [WARN] branding cache source missing: $cache_src"
    fi
done

mkdir -p /usr/local/sbin
publish_root_file /usr/local/sbin/noid-restore-branding 0755 <<'RESTORE_BRAND_EOF'
#!/bin/bash
# noid-restore-branding — re-apply NoID Privacy branding that lives inside
# package-owned payload paths. generic-logos upgrades reinstall the stock
# pixmaps/hicolor icons and recreate the deleted vendor SVGs;
# plymouth-theme-spinner upgrades reinstall bgrt.plymouth with stock layout
# values. Auto-invoked by /etc/dnf/libdnf5-plugins/actions.d/
# noid-branding.actions (libdnf5-plugin-actions); safe to run manually.
# Idempotent: mirrors Module 32 STEPS 8/8c. Skips in Live-ISO mode.
set -euo pipefail

LOG_TAG="noid-restore-branding"
CACHE=/usr/share/noid-privacy/branding
HICOLOR=/usr/share/icons/hicolor
BGRT=/usr/share/plymouth/themes/bgrt/bgrt.plymouth
RESTORECON=/usr/sbin/restorecon
MATCHPATHCON=/usr/sbin/matchpathcon
CHCON=/usr/bin/chcon
EXPECTED_OWNER=root:root
log() { logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "[$LOG_TAG] $*"; }
fail() {
    logger -t "$LOG_TAG" -- "FAIL: $*" 2>/dev/null || true
    printf '[%s] FAIL: %s\n' "$LOG_TAG" "$*" >&2
    exit 1
}

[ "$#" -eq 0 ] || fail "usage: noid-restore-branding"
[ "$(id -u)" -eq 0 ] || fail "must run as root"
if grep -q "rd.live.image" /proc/cmdline 2>/dev/null; then
    log "skip: rd.live.image (Live-ISO branding bytes are compose-owned)"
    exit 0
fi

changed=0
icons_changed=0

restore_label() {
    [ -x "$RESTORECON" ] && [ -x "$MATCHPATHCON" ] \
        || fail "SELinux label tools are unavailable"
    "$RESTORECON" -F "$1"
    "$MATCHPATHCON" -V "$1" >/dev/null \
        || fail "SELinux context is not canonical: $1"
}

validate_publish_parent() {
    local parent=$1 parent_mode
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        && [ "$(stat -Lc '%U:%G' "$parent")" = "$EXPECTED_OWNER" ] \
        || fail "unsafe branding publication parent: $parent"
    parent_mode=$(stat -Lc %a "$parent")
    (( (8#$parent_mode & 0022) == 0 )) \
        || fail "branding publication parent is group/other writable: $parent"
}

atomic_copy() (
    local src=$1 dst=$2 parent base temporary=
    parent=${dst%/*}
    base=${dst##*/}
    trap '[ -z "${temporary:-}" ] || rm -f -- "$temporary"' EXIT
    [ -f "$src" ] && [ ! -L "$src" ] \
        && [ "$(stat -Lc '%U:%G:%a:%h' "$src")" = \
            "$EXPECTED_OWNER:644:1" ] \
        || fail "required branding source has unsafe metadata: $src"
    validate_publish_parent "$parent"
    temporary=$(mktemp "$parent/.${base}.noid-publish.XXXXXX")
    install -m 0644 "$src" "$temporary"
    chown "$EXPECTED_OWNER" "$temporary"
    restore_label "$temporary"
    sync -- "$temporary"
    mv -fT -- "$temporary" "$dst"
    temporary=
    restore_label "$dst"
    [ -f "$dst" ] && [ ! -L "$dst" ] \
        && [ "$(stat -Lc '%U:%G:%a:%h' "$dst")" = \
            "$EXPECTED_OWNER:644:1" ] \
        && cmp -s "$src" "$dst" \
        || fail "atomic branding publication failed: $dst"
    sync -- "$dst"
    sync -- "$parent"
)

atomic_converge_bgrt() (
    local parent base temporary=
    parent=${BGRT%/*}
    base=${BGRT##*/}
    trap '[ -z "${temporary:-}" ] || rm -f -- "$temporary"' EXIT
    validate_publish_parent "$parent"
    temporary=$(mktemp "$parent/.${base}.noid-publish.XXXXXX")
    sed -E \
        -e 's|^WatermarkVerticalAlignment=.*$|WatermarkVerticalAlignment=.73|' \
        -e 's|^VerticalAlignment=.*$|VerticalAlignment=.82|' \
        -e 's|^UseFirmwareBackground=.*$|UseFirmwareBackground=false|g' \
        "$BGRT" >"$temporary"
    chown "$EXPECTED_OWNER" "$temporary"
    chmod 0644 "$temporary"
    if [ -x "$CHCON" ]; then
        "$CHCON" --reference="$BGRT" "$temporary"
    fi
    restore_label "$temporary"
    sync -- "$temporary"
    mv -fT -- "$temporary" "$BGRT"
    temporary=
    restore_label "$BGRT"
    [ -f "$BGRT" ] && [ ! -L "$BGRT" ] \
        && [ "$(stat -Lc '%U:%G:%a:%h' "$BGRT")" = \
            "$EXPECTED_OWNER:644:1" ] \
        || fail "atomic bgrt publication failed"
    sync -- "$BGRT"
    sync -- "$parent"
)

copy_if_differs() {
    local src=$1 dst=$2 cache_class=${3:-plain}
    case "$cache_class" in
        plain|icon) ;;
        *) fail "invalid branding cache class: $cache_class" ;;
    esac
    [ -f "$src" ] && [ ! -L "$src" ] \
        && [ "$(stat -Lc '%U:%G:%a:%h' "$src")" = \
            "$EXPECTED_OWNER:644:1" ] \
        || fail "required branding source has unsafe metadata: $src"
    if [ ! -f "$dst" ] || [ -L "$dst" ] \
        || [ "$(stat -Lc '%U:%G:%a:%h' "$dst" 2>/dev/null || echo unsafe)" != \
            "$EXPECTED_OWNER:644:1" ] \
        || ! cmp -s "$src" "$dst"; then
        atomic_copy "$src" "$dst"
        changed=1
        [ "$cache_class" != icon ] || icons_changed=1
        log "restored: $dst"
    fi
}

# generic-logos surfaces (GDM/About logo, legacy fedora-logo lookups)
copy_if_differs "$CACHE/system-logo-white.png" /usr/share/pixmaps/system-logo-white.png
copy_if_differs "$HICOLOR/256x256/apps/noid-privacy-logo.png" /usr/share/pixmaps/fedora-logo.png
copy_if_differs "$HICOLOR/128x128/apps/noid-privacy-logo.png" /usr/share/pixmaps/fedora-logo-small.png

# Anaconda resolves these generic-logos payloads by exact path or legacy icon
# name. A generic-logos transaction restores all four independently of the
# fedora-logo surfaces above, so they belong to the same recovery contract.
copy_if_differs "$HICOLOR/48x48/apps/noid-privacy-logo.png" \
    "$HICOLOR/48x48/apps/anaconda.png" icon
copy_if_differs "$HICOLOR/48x48/apps/noid-privacy-logo.png" \
    /usr/share/icons/oxygen/48x48/apps/anaconda.png icon
copy_if_differs "$HICOLOR/128x128/apps/noid-privacy-logo.png" \
    /usr/share/anaconda/pixmaps/sidebar-logo.png
copy_if_differs "$HICOLOR/96x96/apps/noid-privacy-logo.png" \
    /usr/share/anaconda/pixmaps/anaconda_header.png
for size in 16 24 32 48 64 96 128 256 512; do
    copy_if_differs "$HICOLOR/${size}x${size}/apps/noid-privacy-logo.png" \
        "$HICOLOR/${size}x${size}/apps/fedora-logo-icon.png" icon
done
for vendor_svg in "$HICOLOR/scalable/apps/fedora-logo-icon.svg" \
                  "$HICOLOR/scalable/apps/fedora-logo-sprite.svg" \
                  "$HICOLOR/scalable/apps/anaconda.svg" \
                  /usr/share/pixmaps/fedora-logo-sprite.svg; do
    if [ -e "$vendor_svg" ] || [ -L "$vendor_svg" ]; then
        rm -f "$vendor_svg"
        changed=1
        icons_changed=1
        log "removed restored vendor logo asset: $vendor_svg"
    fi
done
if [ "$icons_changed" -eq 1 ] && command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$HICOLOR" 2>/dev/null \
        || log "WARNING: gtk-update-icon-cache returned non-zero"
fi

# plymouth-theme-spinner surfaces (bgrt layout + spinner watermark)
copy_if_differs "$CACHE/watermark.png" /usr/share/plymouth/themes/spinner/watermark.png
if [ -f "$BGRT" ] && [ ! -L "$BGRT" ] \
    && [ "$(stat -Lc '%U:%G:%a:%h' "$BGRT")" = "$EXPECTED_OWNER:644:1" ]; then
    watermark_keys=$(grep -c '^WatermarkVerticalAlignment=' "$BGRT" 2>/dev/null || true)
    spinner_keys=$(grep -c '^VerticalAlignment=' "$BGRT" 2>/dev/null || true)
    firmware_keys=$(grep -c '^UseFirmwareBackground=' "$BGRT" 2>/dev/null || true)
    watermark_keys=${watermark_keys:-0}
    spinner_keys=${spinner_keys:-0}
    firmware_keys=${firmware_keys:-0}
    [ "$watermark_keys" -eq 1 ] \
        || fail "bgrt.plymouth must contain exactly one WatermarkVerticalAlignment key"
    [ "$spinner_keys" -eq 1 ] \
        || fail "bgrt.plymouth must contain exactly one VerticalAlignment key"
    [ "$firmware_keys" -ge 1 ] \
        || fail "bgrt.plymouth has no UseFirmwareBackground key"

    if ! grep -qx 'WatermarkVerticalAlignment=.73' "$BGRT" \
       || ! grep -qx 'VerticalAlignment=.82' "$BGRT" \
       || [ "$(grep -c '^UseFirmwareBackground=false$' "$BGRT" 2>/dev/null || true)" -ne "$firmware_keys" ]; then
        # Converge the documented keys independently of Fedora's current
        # default values. Exact key-count gates above make format drift loud;
        # matching only .96/.7/true would silently stop working on a harmless
        # upstream default-value change.
        atomic_converge_bgrt
        changed=1
        if grep -qx 'WatermarkVerticalAlignment=.73' "$BGRT" \
           && grep -qx 'VerticalAlignment=.82' "$BGRT" \
           && [ "$(grep -c '^UseFirmwareBackground=false$' "$BGRT" 2>/dev/null || true)" -eq "$firmware_keys" ]; then
            log "bgrt.plymouth layout restored; visible at the LUKS prompt after the next boot-image rebuild"
        else
            fail "bgrt.plymouth restore did not fully apply — review layout values manually"
        fi
    fi
else
    fail "$BGRT missing or unsafe while the managed Plymouth contract is active"
fi

if [ "$changed" -eq 1 ]; then
    log "branding re-applied after package transaction"
else
    log "branding already current — no changes"
fi
exit 0
RESTORE_BRAND_EOF

install -d -m 0755 -o root -g root /etc/dnf/libdnf5-plugins/actions.d
publish_root_file /etc/dnf/libdnf5-plugins/actions.d/noid-branding.actions \
    0644 <<'BRAND_ACTION_EOF'
# NoID Privacy — branding recovery for package payload stomps.
# generic-logos upgrades reinstall the stock logo pixmaps/hicolor icons and
# recreate the deleted vendor SVGs; plymouth-theme-spinner upgrades reinstall
# bgrt.plymouth with stock layout values. None of those files carry %config
# protection, so the stomp is silent and rpm -Va clean afterwards.
# Format: callback:package_filter:direction:options:command
# (field semantics documented in noid-identity.actions).
post_transaction:generic-logos*:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-branding\ >/dev/null
post_transaction:plymouth-theme-spinner:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-branding\ >/dev/null
BRAND_ACTION_EOF

if [ -f /usr/local/sbin/noid-restore-branding ] \
    && [ ! -L /usr/local/sbin/noid-restore-branding ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' /usr/local/sbin/noid-restore-branding)" = \
        0:0:755:1 ] \
    && /usr/local/sbin/noid-restore-branding >/dev/null 2>&1; then
    check ok "STEP 8g: noid-restore-branding exact metadata + smoke-run"
else
    check fail "STEP 8g: noid-restore-branding metadata/smoke-run failed"
fi
[ -f /etc/dnf/libdnf5-plugins/actions.d/noid-branding.actions ] \
    && [ ! -L /etc/dnf/libdnf5-plugins/actions.d/noid-branding.actions ] \
    && [ "$(stat -Lc '%u:%g:%a:%h' \
        /etc/dnf/libdnf5-plugins/actions.d/noid-branding.actions)" = \
        0:0:644:1 ] \
    && check ok "STEP 8g: noid-branding.actions exact metadata" \
    || check fail "STEP 8g: noid-branding.actions unsafe or missing"

# ====================================================================
# STEP 9: Dracut branding drop-in (belt+suspenders)
# ====================================================================
# /usr/lib/dracut/dracut.conf.d/ = canonical distribution-default dir
# (user files in /etc/dracut.conf.d/ override). Belt+suspenders so the
# Plymouth assets survive kernel-update initramfs rebuilds.
# CRITICAL: += append only — plain = would overwrite user customizations.
log "STEP 9: dracut branding drop-in (belt+suspenders)"

install -d -m 0755 -o root -g root /usr/lib/dracut/dracut.conf.d
publish_root_file /usr/lib/dracut/dracut.conf.d/10-noid-branding.conf \
    0644 <<'DRACUT_EOF'
# NoID Privacy Workstation — Plymouth branding drop-in
# Distribution-provided default per FHS + dracut.conf(5) — user
# customizations in /etc/dracut.conf.d/ override this file.
#
# Append (NOT overwrite) to ensure NoID Privacy Plymouth assets are always
# included in initramfs even if dracut auto-detection of the bgrt
# watermark/font assets fails (e.g. on minimal initramfs rebuilds,
# host-only mode, or after Plymouth package updates).
#
# Trade-off: a small, explicit initramfs size increase for the current
# Cantarell + Adwaita Sans font assets. M21 independently verifies the
# resulting Plymouth artifacts in the candidate image.
#
# Fedora 44's label-freetype plugin invokes fc-match for its selected font and
# carries /usr/share/fonts/Plymouth.ttf as its fallback. Pin both current
# desktop-font paths explicitly so a host-only rebuild does not depend on
# unrelated transitive pulls. This is a concrete F44 package contract, not a
# claim about every distribution or future Plymouth release.
#
# The vestigial `themes/noid-privacy-workstation/` install_items entry was
# dropped (~280 KB initramfs savings); the configuration switched from
# the custom script-theme to bgrt + label-freetype and the custom theme
# directory has been dormant since.
install_items+=" /usr/share/fonts/abattis-cantarell-vf-fonts/Cantarell-VF.otf /usr/share/fonts/abattis-cantarell-fonts/Cantarell-Regular.otf /usr/share/fonts/abattis-cantarell-fonts/Cantarell-Bold.otf /usr/share/fonts/adwaita-sans-fonts/AdwaitaSans-Regular.ttf "

# system logo replaced by NoID Privacy for the bgrt theme, plus
# fontconfig DB for label-freetype's fc-match font lookup. When the
# fontconfig data is incomplete, label-freetype can fall back to
# /usr/share/fonts/Plymouth.ttf; carrying the current config keeps its normal
# fc-match path deterministic.
#
# NOTE: /usr/share/pixmaps/system-logo-white.png is NOT
# the path bgrt actually reads — Plymouth two-step plugin uses
# {ImageDir}/watermark.png. bgrt has ImageDir=/usr/share/plymouth/themes/spinner
# so the watermark file is /usr/share/plymouth/themes/spinner/watermark.png.
# The /usr/share/pixmaps/ line is kept for GDM/Anaconda/About-dialog
# consumers (where it IS the canonical path). The new spinner/watermark.png
# line is what makes the NoID Privacy logo actually appear during boot + LUKS prompt.
install_items+=" /usr/share/pixmaps/system-logo-white.png "
install_items+=" /usr/share/plymouth/themes/spinner/watermark.png "
install_items+=" /etc/fonts/fonts.conf "
DRACUT_EOF

# Explicit fontconfig conf.d drop-in (each .conf file by name).
# We can't use install_items+=" /etc/fonts/conf.d/ " because dracut-install
# rejects directory paths (only files). Glob through and emit each .conf
# explicitly into a SECOND drop-in file alongside 10-noid-branding.conf.
{
cat <<'DRACUT_FC_EOF'
# NoID Privacy — fontconfig DB for label-freetype font resolution
# in initramfs. Fedora 44 label-freetype.so calls /usr/bin/fc-match to resolve
# font names; without fontconfig conf.d in initramfs, fc-match returns
# defaults. Embed all conf.d files for full font-alias resolution
# (e.g. "Sans" → "Noto Sans" via 30-metric-aliases.conf).
DRACUT_FC_EOF

if [ -d /etc/fonts/conf.d ]; then
    for f in /etc/fonts/conf.d/*.conf; do
        [ -f "$f" ] || continue
        printf 'install_optional_items+=" %s "\n' "$f"
    done
fi
} | publish_root_file /usr/lib/dracut/dracut.conf.d/11-noid-fontconfig.conf 0644
log "  [OK] /usr/lib/dracut/dracut.conf.d/11-noid-fontconfig.conf written ($(wc -l < /usr/lib/dracut/dracut.conf.d/11-noid-fontconfig.conf) lines)"

[ -f /usr/lib/dracut/dracut.conf.d/10-noid-branding.conf ] \
    && grep -q '^install_optional_items+=" /etc/fonts/conf.d/[^ ]*\.conf "$' \
        /usr/lib/dracut/dracut.conf.d/11-noid-fontconfig.conf \
    && check ok "STEP 9: dracut branding and drift-safe fontconfig drop-ins installed" \
    || check fail "STEP 9: dracut branding/fontconfig drop-ins incomplete"

# ====================================================================
# STEP 10: Final verification summary
# ====================================================================
# All STEPs check inline right after their writes — this step only
# summarizes + aborts on fail.
log "STEP 10: verification summary"
log "Verification summary: ${ver_ok} ok, ${ver_fail} fail"

if [ "$ver_fail" -gt 0 ]; then
    log "ERROR: rebrand verification failed — check output above"
    exit 1
fi

# ====================================================================
# Phase 11 — Health Stamp (pattern)
# ====================================================================
# Lets 99-finalize verify success via one machine-parseable file (see
# docs/engineering-health-stamp-pattern.md).
# M32_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
    log "  [FAIL] shared health-stamp directory drifted before Module 32 publication"
    exit 1
fi

STAMP_SOURCE=
STAMP_PUBLICATION_ACTIVE=0
cleanup_m32_health_stamp() {
    if [ -n "${STAMP_SOURCE:-}" ]; then
        rm -f -- "$STAMP_SOURCE" || true
    fi
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "  [FAIL] could not retire incomplete Module 32 health stamp"
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
}
verify_m32_health_content() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(wc -l < "$path")" -eq 10 ] \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_passed=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_total=' "$path" || true)" -eq 1 ] \
        && grep -qFx '# NoID Privacy — Module 32 Health Stamp' "$path" \
        && grep -qFx \
            '# Written at end of %post verification when all checks pass.' \
            "$path" \
        && grep -qFx \
            '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
            "$path" \
        && grep -qFx 'module=32' "$path" \
        && grep -qFx 'name=branding' "$path" \
        && grep -qFx 'version=1' "$path" \
        && grep -qFx 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path" \
        && grep -qFx "checks_passed=${ver_ok}" "$path" \
        && grep -qFx "checks_total=$((ver_ok + ver_fail))" "$path"
}
trap cleanup_m32_health_stamp EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

STAMP_SOURCE=$(mktemp "$STAMP_DIR/.stamp-32-branding.ok.source.XXXXXXXX")
cat > "$STAMP_SOURCE" <<STAMP_EOF
# NoID Privacy — Module 32 Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.
module=32
name=branding
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=${ver_ok}
checks_total=$((ver_ok + ver_fail))
STAMP_EOF
chown root:root "$STAMP_SOURCE"
chmod 0600 "$STAMP_SOURCE"
/usr/sbin/restorecon -F -- "$STAMP_SOURCE"
/usr/sbin/matchpathcon -V "$STAMP_SOURCE" >/dev/null
verify_m32_health_content "$STAMP_SOURCE" || {
    log "  [FAIL] staged Module 32 health-stamp content is invalid"
    exit 1
}
sync -- "$STAMP_SOURCE"

STAMP_PUBLICATION_ACTIVE=1
publish_root_file "$STAMP" 0644 < "$STAMP_SOURCE"
if [ "$(stat -Lc '%u:%g:%a:%h' -- "$STAMP" 2>/dev/null || true)" != \
        0:0:644:1 ] \
   || ! verify_m32_health_content "$STAMP" \
   || ! /usr/sbin/matchpathcon -V "$STAMP" >/dev/null; then
    log "  [FAIL] health stamp content/metadata contract failed"
    exit 1
fi
rm -f -- "$STAMP_SOURCE"
STAMP_SOURCE=
STAMP_PUBLICATION_ACTIVE=0
trap - EXIT INT TERM
log "  [OK] exact Module 32 health stamp published atomically"
# M32_HEALTH_PUBLICATION_END

log "=== Module 32 complete ==="
%end

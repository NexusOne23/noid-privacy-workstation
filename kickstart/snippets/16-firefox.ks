# ============================================================================
# Module 16 — Firefox Hardening (NoID Privacy-owned user.js + uBlock Origin)
# Canonical source-of-truth files:
#   - firefox/noid-firefox-hardening.js (user.js, derived from arkenfox v144.0 MIT)
# Status: LOCKED 2026-08-20 (v3.97) — bind and test Gecko LNA WebSocket coverage.
#
# Covers:
#   - NoID Privacy Firefox Hardening (consolidated user.js — derived from
#     arkenfox v144.0, MIT) — gzip+base64-embedded, no GitHub fetch;
#     regenerate the blob via scripts/regen-firefox-embed.sh after ANY edit
#     to firefox/noid-firefox-hardening.js (CI gates on --check)
#   - Mozilla AutoConfig (autoconfig.js + mozilla.cfg, sandbox_enabled=true)
#     generated from user.js (user_pref -> defaultPref) + lockPref appends
#     (current profile-manager kill-switch, regional top-sites + search-
#     shortcut blockers) + reviewed user-owned application defaults, pinned
#     tiles and initial toolbar placement (all user-customizable)
#   - noid-locale.js system-pref (intl.locale.requested="" OS-locale
#     flow-through) + langpack activation via distribution/extensions/
#   - uBlock Origin pinned XPI (immutable GitHub release URL + SHA256 +
#     size + ZIP-magic check; offline-cache aware) staged to the
#     System-scope path; its exact curated filter-list baseline is enforced
#     through the current narrow managed-storage schema
#   - firefox-profiles.sh shared helper (registered-profile discovery,
#     apply_userjs, uBO profile-local install + PB permission)
#   - policies.json with EXACTLY ONE policy (SearchEngines.Default=
#     DuckDuckGo — the only working mechanism on Rapid Release)
#   - M26 fedora-bookmarks exclusion + empty default-bookmarks fallback (keeps
#     the Fedora first-run bookmark source empty without replacing distribution.ini)
#     + /etc/skel profile pre-bake, including uBO private-window permission
#     (1st-launch race fix) + mirror to pre-existing users (liveuser)
#   - first-run setup script + XDG autostart (silent-launch profile
#     detection, registration reconciliation, user.js + uBO + empty-
#     bookmarks-backup install) — full flow in SETUPSCRIPT_EOF
#   - noid-firefox-relax-fpp + noid-firefox-relax-webrtc +
#     noid-firefox-drm + noid-firefox-harden-profile CLIs and the
#     16-firefox-hardening.md user doc
#   - NoID Privacy-owned /usr/local launcher + XDG desktop overlay generated
#     from the exact signed Fedora payload; no Firefox-RPM file is rewritten
#   - Anaconda WebUI firefox-theme user.js hardening append (Normandy/
#     Nimbus/Push/Safe-Browsing/region/telemetry off during install)
#
# Deliberate deviations (do NOT re-litigate):
#   - uBO delivery is PROFILE-LOCAL (verified FF150 mechanism):
#     distribution-bundled scan does NOT auto-install regular extensions
#     (verified across all launch modes; locale addons DO
#     distribution-install — different code path). policies.json
#     ExtensionSettings was rejected ("managed by your organization" UI).
#   - omni.ja and distribution.ini are NEVER patched. The reviewed Fedora 44
#     distribution.ini declares no bookmarks; M16 does not synthesize a dead
#     distributor "processed" preference.
#   - defaultPref (not lockPref) for reviewed application/UI state, pinned
#     tiles and initial toolbar state: user_pref would wipe later user changes
#     every start, lockPref would block customization.
#   - AutoConfig uses defaultPref semantics (user override survives);
#     only the profile-manager + top-sites injectors are lockPref.
#   - installs.ini is NOT pre-baked (Firefox computes the install-hash
#     from the executable path; a hand-rolled hash forks a new profile).
#
# Constraint notes (keep when editing):
#   - mozilla.cfg line 1 MUST be a comment (parser skips L1); the
#     user_pref->defaultPref count parity is verify-gated.
#   - extensions.autoDisableScopes=10 is load-bearing (profile-scope XPIs
#     bit 1 + app-global langpacks bit 4 auto-enable).
#   - The skel profile dir ships 700 (cookies/keys after first run);
#     parent dirs 755.
#   - Verify-blocks use the canonical grep -c pattern; tests/16 has
#     whole-file negative asserts (AMO latest.xpi URL, active arkenfox
#     fetch, OMNI_JA=, active X-GNOME-Autostart-Phase line).
#
# Cross-references:
#   - Module 05: Firefox follows the system/VPN resolver by default; direct
#                WAN retains Module 05's strict-default Quad9 DoT boundary
#   - Module 07: the system boundary blocks unqualified physical-WAN IPv6;
#                Firefox must retain provider tunnel IPv6/NAT64 compatibility
#   - Module 13: AIDE /usr PERMS rule covers new paths, no aide.conf change needed
#   - Module 25: noid-update-all.sh rebuilds each supported user.js from the
#                canonical base plus reviewed consent overlay when present
#   - M33/M34: isolated + playground profiles source firefox-profiles.sh
#
# Testing: after image build, boot + create user + first GNOME login →
#   wait 10s → Firefox setup fires → browserleaks.com verification
# ============================================================================

%post --erroronfail --log=/var/log/ks-16-firefox.log

#==============================================================================
# Module 16 — Firefox Hardening
#==============================================================================

set -euo pipefail

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [Module 16] $*"
}

log "=== Start Module 16: Firefox Hardening ==="

#------------------------------------------------------------------------------
# Variables
#------------------------------------------------------------------------------
# Supply-chain pinning (Rule 11): every external download uses an immutable
# URL (commit SHA, release tag) + SHA256 verify. A git-tag move or AMO mirror
# compromise cannot silently swap the payload. Update expected SHAs when
# bumping versions; see docs/pin-inventory.md for the refresh workflow.

# Firefox hardening v1.0 — absorbed from arkenfox v144.
# See firefox/noid-firefox-hardening.js in repo + NoID Privacy-specific overrides.
# Shipped as base64+gzip-embedded in Step 3 below (no external fetch).
# Upstream attribution kept in file header (MIT, arkenfox @Thorin-Oakenpants).
NOID_FIREFOX_HARDENING_VERSION="1.0.0-arkenfox144"

# uBlock Origin — pin the image's first-install seed to one reviewed GitHub
# release. Later executable-extension updates are owned exclusively by the
# user-started M25 Update All workflow; Firefox background checks stay off.
UBO_VERSION="1.73.0"
UBO_URL="https://github.com/gorhill/uBlock/releases/download/${UBO_VERSION}/uBlock0_${UBO_VERSION}.firefox.signed.xpi"
UBO_SHA256="bccc51a773150af4af6e1fd62c7bfdeb7238b79ff2381b998fa9f2e38f64786a"
UBO_SIZE_EXPECTED=4679419

SHARE_DIR="/usr/share/noid-firefox"
UBO_POLICY_SOURCE="$SHARE_DIR/uBlock0@raymondhill.net.json"
EXTENSIONS_DIR="/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}"
MANAGED_STORAGE_DIR="/usr/lib64/mozilla/managed-storage"
XDG_AUTOSTART_DIR="/etc/xdg/autostart"
LOCAL_BIN_DIR="/usr/local/bin"
UBO_POLICY_VALIDATOR="/usr/local/lib/noid-privacy/validate-ubo-policy.py"
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-16-firefox.ok"

EXPECTED_FILTER_LIST_COUNT=13

# Supply-chain verify helper: fail the build loud if hash mismatches.
verify_sha256() {
    local file="$1" expected="$2" label="$3"
    local actual
    actual=$(sha256sum "$file" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        log "  FAIL: SHA256 mismatch on $label"
        log "        expected: $expected"
        log "        actual:   $actual"
        exit 1
    fi
    log "  SHA256 verified: $label"
}

# Reduced-dependency cache support. The canonical builder exposes the reviewed
# bytes through its loopback-only payload server and sets NOID_CACHE_BASE_URL
# in the disposable flattened kickstart. SHA256 + exact-size verification
# below is authoritative. This is not an offline-build switch.
#
# arkenfox cache layout removed (user.js is embedded now,
# no GitHub fetch). Only uBO remains as external download.
#
fetch_or_cache() {
    local cache_relative="$1" url="$2" dest="$3"
    if [ -n "${NOID_CACHE_BASE_URL:-}" ]; then
        # The canonical builder injects one fixed loopback/build-gateway HTTP
        # origin. It serves reviewed local bytes directly and must never
        # redirect the guest to another origin or protocol.
        curl -fsS --proto '=http' --max-redirs 0 \
            --connect-timeout 15 --max-time 300 \
            --max-filesize "$UBO_SIZE_EXPECTED" --retry 3 --retry-delay 2 \
            -o "$dest" "${NOID_CACHE_BASE_URL%/}/${cache_relative}"
        log "  (cache) fetched $(basename "$dest") from build-host loopback payload"
    else
        # GitHub release assets redirect to their HTTPS asset host. Keep the
        # complete redirect chain encrypted and bounded; the exact size,
        # SHA-256 and extension identity gates below remain authoritative.
        curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --max-redirs 3 --connect-timeout 15 --max-time 300 \
            --max-filesize "$UBO_SIZE_EXPECTED" --retry 3 --retry-delay 2 \
            -o "$dest" "$url"
    fi
}

NOID_CACHE_BASE_URL="${NOID_CACHE_BASE_URL:-}"
UBO_CACHE_RELATIVE="ubo/${UBO_VERSION}/uBlock0_${UBO_VERSION}.firefox.signed.xpi"

#------------------------------------------------------------------------------
# Step 1: Verify Firefox package installed
#------------------------------------------------------------------------------
log "Step 1/8: Verify Firefox package installed"
if rpm -q firefox >/dev/null 2>&1; then
    FIREFOX_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' firefox)
    log "  Firefox installed: $FIREFOX_VERSION"
else
    log "  FAIL: Firefox package not installed (expected via @workstation-product-environment)"
    exit 1
fi

# Fedora's launcher is an RPM-owned input. Pin its exact compose-time bytes;
# Step 6f derives a NoID Privacy-owned /usr/local launcher from this pristine
# payload and keeps the vendor file byte-identical across updates.
FIREFOX_LAUNCHER=/usr/bin/firefox
FIREFOX_LAUNCHER_SOURCE_SHA256=12e361bb42c030a9ffa940c641ff3ddf53ea097d40a7b2ea4903cd2c954dcc2e

verify_sha256 "$FIREFOX_LAUNCHER" "$FIREFOX_LAUNCHER_SOURCE_SHA256" \
    "pristine Fedora Firefox launcher"
FIREFOX_WIDEVINE_ANCHOR_COUNT=$(grep -cF \
    '    (restorecon -vr $MOZ_CONFIG_DIR/firefox/*/gmp-widevinecdm/* &)' \
    "$FIREFOX_LAUNCHER" 2>/dev/null || true)
FIREFOX_WIDEVINE_ANCHOR_COUNT=${FIREFOX_WIDEVINE_ANCHOR_COUNT:-0}
if [ "$FIREFOX_WIDEVINE_ANCHOR_COUNT" -ne 1 ]; then
    log "  FAIL: Fedora Widevine restorecon line is not the reviewed shape"
    exit 1
fi
bash -n "$FIREFOX_LAUNCHER"
log "  Firefox RPM launcher is pristine and structurally reviewed"

# M16_HEALTH_INVALIDATION_BEGIN
# A health stamp describes one fully completed M16 publication, not merely the
# last successful historical run. Validate the shared state boundary first,
# then retire any prior success before the first Firefox payload mutation. A
# failed rerun therefore cannot leave plausible green build evidence behind.
log "Step 1b/8: Invalidate stale Firefox build-health evidence"
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    log "  FAIL: $STAMP_DIR exists but is not a real directory"
    exit 1
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        "0:0:755" ]; then
    log "  FAIL: $STAMP_DIR metadata is not root:root 0755"
    exit 1
fi
if ! restorecon -F -- "$STAMP_DIR" \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    log "  FAIL: $STAMP_DIR SELinux context is not canonical"
    exit 1
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        log "  FAIL: health-stamp target is not a file or symlink: $STAMP"
        exit 1
    fi
    rm -f -- "$STAMP" || {
        log "  FAIL: cannot invalidate stale Module 16 health stamp"
        exit 1
    }
    sync -- "$STAMP_DIR"
fi
log "  Prior Module 16 health stamp is absent"
# M16_HEALTH_INVALIDATION_END

#------------------------------------------------------------------------------
# Step 2: Create directories
#------------------------------------------------------------------------------
log "Step 2/8: Create directories"
mkdir -p "$SHARE_DIR"
mkdir -p "$EXTENSIONS_DIR"
mkdir -p "$MANAGED_STORAGE_DIR"
mkdir -p "$XDG_AUTOSTART_DIR"
log "  Created: $SHARE_DIR, $EXTENSIONS_DIR, $MANAGED_STORAGE_DIR"

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# Step 3: Install NoID Privacy Firefox Hardening (consolidated user.js)
#------------------------------------------------------------------------------
# Single consolidated noid-firefox-hardening.js (arkenfox v144.0 core, MIT,
# attribution in the file header + NoID Privacy image-scope overrides + ETP-tighten),
# embedded as deterministic gzip+base64 and decoded to
# /usr/share/noid-firefox/user.js — no external fetch and no runtime merge.
# NoID Privacy owns ongoing release-note, source-default and runtime review.
# The image stays self-contained; source of truth is firefox/noid-firefox-
# hardening.js (git-tracked; regenerate the blob after edits — see header).
log "Step 3/8: Install NoID Privacy Firefox hardening v${NOID_FIREFOX_HARDENING_VERSION}"

# Decode gzip+base64 blob into consolidated user.js
base64 -d <<'HARDENING_GZ_B64_EOF' | gunzip > "$SHARE_DIR/user.js"
H4sIAAAAAAAAA6Rb63LayLb+76fo7VO1YydIYBt7Mk5lassgx+xw20iMkzPlyghojGIhsdXChPl1
HuI84XmS863VLSEMTjx7XFOxQep1729duqf6mn8OXgv8xMFcXopu0mqKfho+BuO1uE3SB5UFWZjE
4v/+53/FdZjKafJN3ATpRMZhfI+VjzJVeH4pTuyaXRNHE4nFciKmaTIXQfogY1qxVDK1vyrxeFKv
27Vj5hjOg/vvcazXmWnb6VqhSqIgk5OKuMWnJI7WWuZULpJLMcuyhbqsVu/DbLYc2eNkXu3Kb0vV
i+XpWTVOwom10PSt1YY+KIyTxToN72fZpWjkf4qj8bE4rZ1ebAs2TuIsDUfLLEkVVkbhWMYK0nda
PlYk81EYQ2lWHtQf5TsxXUaRiJMMb0LOLOAXRjJKVlAfJIZ9zx+4Tkc4vj9oXQ39Vq97yWo195mw
um1CcUQyWrW6dWrMOVyoLJXBfK89nlLZWvFEm+cFF0E8EWEMA0YRvgsyJgOaaVXNglRWDSG1ZfSC
uWWYW2BjZ9+ybbnFHJyYW6ouxT/8WZKGsdULsHYRxJmqiH/IIM1mUXwPi6dyEiIgIA0bWpt0y2Od
XrN13Wo4ZFdPG9aCm2OEUjihYNpE5yhQUrzZXs7RaSmEiBQJgjwNJ1KBXZbo0BNJLIXCHoikmIb4
5yhOhJKLIAVtjnerWAadj23Rkem9FLNgsYCNcuOZbSBGyzCaiCycywrZHo/FKE1WICNg7jRbLmyj
ghuF8zDeVmC5II1SW80QgiCP3QkVaPdo6moWLpTIZqFiWQ3nCbbzOIvWtvDWKpNzQ0aRKnCf/mTB
16B7jFCwIHq01mHJdHORBnKUIjQgEdRPIf2cJEvFYxAtQS5LwEplsNUyhIS8fpl7PdfByHSUzaRY
AGbEg1yL37+YkLE14d8FNFjG41kQ39MGSVIQTyLszvkC224URmG2flc4CMKGmRKe7wz8aqPX6bdd
382lgmPiLJyuRaC2PU9mewxVOIJTw9gQ+z0YJcvsUi0XiyTNfj8uvOH3LQ/IMM62hRAwW7KKoDbp
Hoxov4zW8M40WEYAmYywBibKoIph0Un+CKMoEIZcJ5lIRI1PThsHMSy+SBFRIkuDMRl3FCXjB9gU
oUMGXyNeZPBgaG3LAjAtxIEcCjtHvRMpw2BAWioxScbLOQzCWyrCJswVLJvGUgs5DqfheLMjLsV1
vy9WQBrRCOLHQFVv5ehDW1A8JPPwDw3lwZgwsWKEIz2wNrVyKSGC4gis/trvimbXK5mqkmedVwop
isiw/Pnm4cRALHKkqojxMk2hSWFPpyVkDDOPJSmotOGgZzZLk+X9zFBC3IXpBoMmGvGTCLgjv2XY
sWBiGcknotMu3FoR3XA+WipDR35bAL41p1gu4a0o/IPeIuyk4O4m6Rx/rxkjvoRgFAHX5MRmCOs4
ra7vdp1uwyUEc9saufx865KvSkLCTppmKX4h5Ffsa7tI16kEByAccEUq7QSVLFPAu7GxYuGC6RTL
QDRdxgREwPxZ8Bhij0E8EHkM5cpsOhmMZxoCmJpGCopVaQAHxlOIJ5ggQXaBzz6E2c1yVEanXYR7
VxZN73EFvqSuYR/oPcl5H1GQpGsBw9Bvbb1uDwXCYOB0/c+8jRnxZnm1QrYbSZVZcgolYCAnWgVr
YhEU0ZDzBbERjAfFGfRoNWAsIOOyG9bJEruSHhMu2OIKm3K5YOQiuC8Wx1SpzIOvMFruDlMxwWr3
aTAxZgtGKklHZUynPK8zE8Qm3Imk3qAk2q7brWRFAdHveb7FSxWcSWw2mdvEgUVxYAyKX+MknfCu
B909di3EPjk/zRcFE1qBSEe+DzPxodOv3mJbPCIk81QEYiRzKpXSQowDxDtLbbxuhRPYMQvUA8Nb
gkfpKsQ7U5khuubYz6AUGEuCXnPQ4biCEcpSnW1LRRw8o/rPtdqZcLwBPIQoy2EHpPK4f8f5oZ2M
g0h0ZUbVoXDGYwhdIDWMH0QUIeuNwmRMxSjN1CA4svZqRnHhIfVl4jYE+q1M7AK+CS71bgWqL/Ha
ycUrDjFtCjsIbQM3tuH7/tDA1KFwUHSibpmG9wgkRWm+pH2dvbbr140xCqnbXUcAnD0iCx3SOZYe
xVprO4oDeyURhPTQljFD2/E7pmDoA4DZSUQ7JPuiUFCsbhaMQOseG2gBuATe/nsZjh8Y9ZO4UuyZ
Ee+RiginKXoNSmSx0uitjsUKFqKtgfTCIZ4bvWQ7rY2uJMDFMibTyLohpgFeaURAhd3suKIqhp7z
wdVgSkUgBQIQmCj52JtXBonwZwfl5CMAIf8qnNJmp0wNgZBpkZYjJpNKqIkAB/8kXs8p0R5R6fZ1
iaRvat9jhiElJSVYVdU0LKZhzycimTKlZ1sgLnCgtS6f2JymItiAGrDzXmY6/RiubJEpHsoU38Rs
LwgKIpQFOVsDRFF6ZOW8X1ZQZ4luz98op+3Z6jbdT+IojBEIXIBv93mEPMfayrWTWu1S117Dvtjz
c1qjF/rt4YcWMn5VdNxmy8HvW/dq4Dc0jVN65YPba/d0Ib9Do04vNHsdcdTsNYYdt+uL3tU/3Yav
s6duMWpn9Na/hi2UfwNx3fu0Q+aCXui0vIbbRr/p9oaeXsjkPefaFVeD3q3X6n54svAnegFFoDhy
uzeUtZvCHziNj3jT8GbSV1Dgo2ihAm010GP1hv5Vb9htMom3zONm6Dd7t13xd7DrtvzWf4OCJsAs
mmyiZnKDf/uD3qfP+O2BpidEne1IZdjRts/7qJg1EhpRmFNhyitnQERcZ9C40drUz+mFXp8eO20x
uAZJHTfXG8KG1s/sPMfzbnuDJslGf390P3vGMue1LVq9vudqn57wg2bL+yicX3utJpc65Z/zbSlu
nEHT7ebWOOGIuPH9vieOPK9d9dvEvNfw+se8+kKT73Vf+cLvDRs3ehl7YeBeuwN34Indn59Ky656
/o070OvY+I1e10ddtm/l25115ApTC/7g5y0r6rttt+P6g88vW/QzM+z2uhbCgAN94LYd322+cDl+
IK/bH7gNWgXbDVBudsz6LhxymZcOVMWsE0AJLRLvt2FqtxU40NOk6sFB9bVwBh/dLu00GikAR1pw
8pWLnX5AX7T1nODgYGfsUts0hAd9mc5DXT8Q4iENIAmgZop5EjRNgarJlAo2AGCFy7MY1S+qKyxI
RlQhE/AFPOY5wJtcDapkmq24cKOSVyHhhdxL50BogBf5Sulm9NAzKw6PmclEBtEBwyeyfU6MIBVV
BqEs1wWc94DY0XJCMuSPqXU3HDixkubqAERRG1VYzgrhL7pS/Jas1mI5Qts2q3AO4AkUvlT0JZuQ
+4oq0oSSUXQACiHkZl030pneIyHbgL8xEfflqxnQe0uTUB1Ml2kMlpLXTBKYjDlSU0Hf0OvThPpJ
Ug1J2FQDlwcHupKlLrUYreWTJN3+wAGLjVfNIzVDd4pYMwbTU52gpE5K7Cl5ZSEKNWrAOTqfqGmD
/40LVLz20QS4ouURUv7aaiLKDx0Pnw8r4rbl3wB9N21C71o43c8CgN2sCPcT9oXnid7ggLHaxXet
bqM9bBLyXw05lEW7hRgmoO8JYmhItVyPiHVcwCk+Oletdsv/XDm4bvldonndGwgHKDnAXhi2gb39
4QDVugv2TdrPre71AFxcymE2uFIz4/5KCc27cdptYnXgDCH9gOQDJvU/D1ofbnxx02s3CZquXEjm
XLVdzQpKNdpOq1MRTaeD2odXaWSj17R04vbGpa+In4P/GpwZoAZBHvKYX4GWA79YetvyXFR4gxan
wutBr1M5IHNiRY+JYF3X1VTI1GLLI3iFPg89tyAIKHLaoOXRYlIxf9k+2AchLmxFCMO9MzVbR4dP
RkTw8SEXHT+YZe+fU1P9cnj8jiGsxkhr2nzd512OdR2OcGNsYbgryVLU8/SyrtltNUtWt/p9yDYN
IiU1g9evxW+esRUVS3ebaukp3T060gqh1gCsbwIAnKSXvBn0C6+ofwkmfyNVSJOT2imhepZ32ngN
TTq4g5nVuIEb3bsDgRffj6IgfqiIk/cABgDH6fsILQePwzIe7xEknb0HzAEsqdt9DJMlQFW3eUTi
N3jKvUMLprf4QFIbyT2smXNQQW2aS91cqaR4dHT69uTkzbEGLKqloTejAXsR3Q0X5WR5qlKZHXTw
ET934oOMZRpEv3haxV9yzvuELEfGK5rqhowsPBlkoeJy11W0gvGmfQMoioBI0blEyrMcZKKE4WyZ
PiK0VGn+wmbXU5Yh98fCiSJbu1n750z75waeeNN1b28BR71btjcx0cFHLnlfnMHgA522mCEZtRgg
c35M8y8oPhfDQVvZtl0RV+RS0TekNgYjCr900SvqblWL5wcj9Qs94QhhN+CNlX6D1vOMx9hrI9bG
dDypCJ80u3qmnfeBeTCX9a9r/aE6kLPQO0uXL9GYN5UO3WLpS/SkL9G77uhl2t+/rNT5Bj7Ugk4e
UjNXpPEkNse2Zg4NSamL9HgyfrxHi60FDU2IXiuFpZZUMRhQR0c10tQi5CuN+/J6xNRuukziSCZq
xcTABHT4RFI4itqLbV0vLvUuLnZLlix40FwCBe5cJwmPBTPdpvMgTWPwhOXgXjtZxc9iK+IRPiM3
24GxmKXPEvLZic18CSQP9yDtKSNtuad8Cdqe/ghtpxQ8MqK59ZimJRvwPSXwzePgWk6SNMCKnifu
ZQIT6JQEjo9k66ey4B07H1zZ+P4LvkCRJDepRFSr4rfra0D8mzvxG3Lp8NPdjtJnrHS5A36J0mff
V5rDn4rsV8WgYvo1SSfKqE7Tl0avg4KmqU/hNvFydlpKrTSDnKP2nmhTLIKYY06jC8KCJ00QT4kP
SULnbU4cRGuUjup4R41iVq/se5k5vJhTcB9UnxjtptVEZ4ki0b2+M1KdPCeVeirRK+EWrDSizCQN
vEl6RQ65eAt/fEe8WTaPmKCmZz/hl8/gSjWDFrEUTLqQ1wcMG3GQc78rOUvrdHos5Pmbu6cblE/f
ZgHP7iWfCaBNkLG4QeOTzUCdCnB4BO3ryTGfDeRHIduIlVdef6d57DLFPi3wq0mD3QZ6CDOo5cSo
5C8OdRXbahUWe+oQZnZyV5x2m6M5e66Pfewkva8+jKplYtbmJOepd59DG6jGE8j1Hn9wiFPJ/CtK
aWFO8zchflaC/+8jvQBwIHgyVET/AeoVi5+K5vnoW9zyrquXdp2XoTc18PxXfNbS9wH0CcMSSKbp
7mgSLBbYiKGMJnayyBCO5sXnAr1e2ov5mVnVYwIcuTUdueYbKtpKZtTHiXrESacLi6Wa6RYUtZg4
hPfDBVLE0xjKY8fcnAiTapxz3qtP/nSPDs+9GSzCL8s0Kmcn0Rg43g3Aso9Wq+yu85K7GmmgNptv
N0xk8LAIJnbKL6D2yxnsiSUqeewx0dPkkHZtha2gP+1klnqdLC3o0x5iJTrKXsZo1Odhhl6hMZPj
h127GJrnJ5Ssmu61M2yjU+OHBoPP4XdqxugQkK5UEEHdS6DfpyOEKLmnw/9tgxDNtwbL/ko0e7BD
mQurJ1LD5dnt+X0rBOglPP7q9IklnlqAw0E3xpswuCiHQbDgM/A+OKFSnUgz4X0ayavVygZ4MwpO
pERBFz+o6mnt5Kdq7W0V+dAaa0rWgikpK0Q1mU5lKq1VSCc+SlnKWM2CdfLbPDsmMHS0JPaYzgvC
cRDtD8H8uGmbuWWqn+fDBbWNsUUZFcyJHQrhWOaQOiaLq63cVjLLaHmvd3g5S5zUL2rnZz/taFYI
W6L/vKg7NVddt/RbhwdH3tUx7aU8DLmqoSIwQuWoj04n1LlZY/Tdis7CUkG3NhRXWAuk5xl2a0XM
g4gne0TLHBRaw0GLwxg9ThwlwcSYwhYeJR0vmJbbZ0nn3KGa67sldJQFYCRqM4p3upgRSTNl4+42
P1qy6EiXTMBHSnAd3xTg0zfypT4wzK9BET3kX6uQiM7SQ13xIgMvlll+d4PZ85BAn+lF3PbntwXo
jtIBEdvK92g2xjMYkX041Qa16MC1qq8QVOlq0EOYVUmbJKYbGVUgb8m0VTJKbhMbOcOef1XM5/SH
dQVtIWplrNwpvEmMX+iiiNmYfOWQaZ5taE7ko4wSKk3sey5p+ZKegjTWyIhThT7YjPFYHrykVK9/
v1RfQGWYNImLrqReK+0k7wqRWQ4Q3XzeOoMuA2kz0bNbZNOiP0tD9fA3qnoRHFQEEj99Pi0U+ksE
349ri+IP27bFFfeDE7p+kdK8hmMZzZQGvLxtZmM8m43IhLkFbeOMPVv1Zetzzz5TodTLfR0saJCH
Nmoe8KiSRwlqZt7h+Dd5WC6UeEMXAxAfx3ruALuGatd8RU+1JVNB+bW+ayKOIMdZhaSpH/85ex8+
NXhB+/DPWLlY9ayZzl5gprJFEn0PYF1oT1fYpmIsUzrTQUcALTImx8c0xQ0xvgWnU69QhHkhlRFz
cwWNOiCiSCxoXfl8hhjR/ecK0C68D+OKUOgX9BERSoA16tX7NEA8jDU+mpMHE5Oqkh+L6P6Uy9It
uM27+xUozMRMRovNdJASZzqnqzPosvh+BSxDrTX30zRaQvu6jOgKbg71uZ+HfQvZBrjvf74TLb6n
QOc1PDgFbqZ0ZKJPXUgxfrwK4sycwxQQVSFWcXGQpx8/V+k843vtv/94q+0Q2pTItLwJLIyVRI1i
ISdkMwqsj6hqzMYyG726yY/P5USLb2RuVDc3E+18Alhc4OVL0Fu5a0++0kdd+S2fvAtmYm3wMTdo
85xGw/c1Y6i5mfhq6ypfcTU0v3xjv8wHuyhHU9P9lf+P4O2FK/dt+RcuNY6BX/Ys1nBRfw4ulvGK
z36LM9w/iXd0CsObQGNBQY4CZBnTPIAGcflp73+GgSZ8Wc0vi4TgIaTi7kvO7a9vDU07F3gHbUtT
h8PwPk5Ss6HNmdUhDZ5hV/ORK+W6qZQBIWPUZw90vA4MHa25bNC5SU9rdU5CCJvDFLvIXwFqShSB
/EYwmYf6fDlv5Lwr9pXvev4dT+5f8P8oVFfhQ1h16Lr8JPxmOZZPdzc9mu3+l2WqsZfV96enF/Wf
a3/GoXxdumcA8Ts1/gXX+M/d7vmNkDifpkd00/zBXKC1hLTv7dzacMnuqHBflXfxo4GsmMPfRY13
Ua7xqAPkmoGuV9L/u/PEdEVNumU7vrZ2K0dVunJTbYPGlxKNL9fOv55tm/L3rFh+y56E6UW5dqK7
TX9RsBsZUL6rfrJAzOrnnBsGeZ8TcRIr20iRr9kLZd95/zpN5nwdaRvGLsowRqZHxIIg5VgBXWJz
dSI2aShL+CXCNpQK+himbINYrpSt0LjMJknG+vMBavXknNr5k3r19Oz05LR2ym1Jllj/XuJV6/+b
e9ftxrEjXfC/nwJDrzklVRK8k6JUk9nN1CVTtm4WpSq73V40SIISKkmAJkgp5fGcdX7NA8zME/aT
THwRsTc2eM+0z6xxu10lCdjY19hx+eILNYrIkCc1Ip77em+tXu5mfPhcCciexTgQ+5xuQzLGxj4j
V2iIFTs+R87w0CCnPOddZ3gpZE6ftF/khYhibyLAJH2O1znKzamcjoNBmLp9Umt/g7bZqlZy7qPC
5zfaObz3OwsAVSABD/jcSSaFNXaWnCfUdjilP8J4BHyYRRSWoWxuiDLDun3taYppR6wZEy0TA6Mw
Gfn8Md98zKaiwX4q75JJJPp66EW6h9/IlUtHLJc2gwb3ETZH24XNE60FQOz826fnJJ1buXNk4AaS
zJN8fdNtrYAi4LTQN2MQcXhBwLjcPQ5CQj6Stv+QzIqK3EJEUexPUfvQhLbLEcQvsUCS+BGgeoch
YLOB8Y8FuKXkEuU/x8kQyC1S9J5pS47FhEWj1h2S3xZYwhLtWpNggWOo/56W6fdyYZFgKlPrZL98
vv3l4RYySqHEm88dz1EJ4Ou0Jx3skajJS5Qj146SyXq8OfUOHuMIVo53E0zwOzoe2IIAfdJazZ/F
FVbNXKMZ4gMZO5I1lEVZ1NEkQW0+t9pHjzP8VqIuGxxq1Xq71d44XLRt5CgUmR531A53fXDuyJU4
sqkkgY3OQDRmwYquq+ffijoIGDP6zJ9hYtQzxXt4xtXpjcJgvgA88AlKPTKrcHvDPHbmiGZgzXSq
BQZvWaA9hKjD7+hDqfpOsmZW5nKcPOXm0XSqTJK9Wq5WyrWm/o7kCG1Wnz/iB9PIp6Ebce8Hw6FP
zW8SLvlNZyavJ5O5JE6PENfPT7pohWvmmtdhMZPo57GqlPe8m7uKGCgq/KUr9nDRe7ARGzOldo1o
Nrknevr5nMpmZcOYriW46aUfgkrIr2D6bSuUM5id1qLJlGzEvbY9/RLmZWnwFP0b/XsvGr6vHtVr
R8e1Iv2zfnzc4H822tW9VoZ10J5M9/KyyC1ntCfONPUVFE3i/tANkFXeW8hM7X0UD2aMTvAOHu7v
6X+wL+mneww3xa19H6bJmJo79Gg7pfNDwL0mdAXw80ippN803yejESe8wlVLthTfoFDrC8Pk2ddf
lgAMIp3jifZ64QQJGF6tUj0uQuwEwwBo32rRu1+QIRGUH7/MYAbjlzW4SneadpDTfOh52Mvr8xzA
8+0uDn26Xa40y4E/CGbzJIkR8JgluLVJ1MoM8ttlbstxAEOq55oyfSif3X6m8cl8+dOEBMUbv1zf
6T02RzX/aX65sTuIU6uQTVPGu5hu+J0T/Av9d/Lmv4XBzJcsIJ8B1dv32nwGvZqNnLrdXXp9Q3Ow
WVPqIVF0GU2A8VoKSgoYi1huchynwulzknDYQF7/cMrvfSg4aAM9jYCDaqvsh8p1jb5TcBxgRqlI
g8lu6z+/RT5cmr1fvg6+fljq3x6zhK6QXmQWJ/waIEgCm6Cwzph3X5Xh9ba3sKzDtVmHW5+uoT88
fvpEFjVDa8re58vuw+09dLyL2/vr/XS89nYdT5BM0Nr6mVXZzlmVBsDUD5A9ywnJm4wABPJa+8bk
SEzWjpob7YLFjMT/bH+7oO0anLlOsxP363xBCmW6eHqCymjuZgOKCb3Hy6XglKajma+x/ZrfkF2O
T33oDIdIgvQ+BrMP3ax91lhLpdJOHQA5kHL/V45h7uFnPvJGhGinVwEKS1PFOXn68MZA6zECrVum
W1/PtRUnsUU3rjbY/PYGt7Rm4sBtVxnmBGMJB25Ywo8IwkyggvVDUfqgNrjvIRcCWq4mdrg7ZI0e
cZu5yhH+khRBVfLYm6gKhogkWv8pzgAHAvhrYfxEl93a/dIlObpmMN4/vE1/AbxLNxn2M7DZ47UQ
EWNTooXSxp2wx2pJE+GyVtJ2NXR5heYE3rts5G7HgVqsroA2zDzI886RkanZ1uABGjxeBQUuDcM0
UVJN8RNppCtDaa0Mxf3Sji8opG9t+wavWd1+Muhq2P5+AxCaYHgNt+mc3SRbWiMtFkiLeH4Ggo8d
Dde3doy5Pea7m4C9Tvq5PL6tvWG8Y6KOLP5oCbfvsqzwSr1SO4igOcnba6HbW7oDbW8aDqNg9+xv
aeUtHO9YvlpjZwP3AFxGk3BHTxpWJh6t7NnBOJr2k2A2XHvwdniftCu2ja3npZ1DziJSb6SEDLeS
A5reLz0CAMH6/JCl1JA9UZ/SsO8M2tyX+41ZhmC6t23gVQecpSKJs6/hktFhOOP+JXQSXvgh5jhI
ENWO5rlByo3zy/lHur7orVfBWAR0wSzoYAlAJ5TvcBvA8fRDIbNg7SSaMR/PHGBMmjIyaXZqzJ+l
w6qse8Zs/0BWfDjpA5qwZYQrWgwAPENjSLP/lIww9mO4Q2BHC6Ohlw2vtYphvV1tGQN6zfqhVyN6
WO+1ldVybqh50If1p0OiTdpWn0VnPA9nwjUzfisq1QdWiLMTmU2HQ8Nyi4OjA8Qib0xMFAonD0mh
CS7m26leXfyRnQriL5kjFFqIc60XzQE2F6N8PN1vO2eXPb+0PCsuGH+QjEG89QSMg0n7YrvT2ZSS
kk37cjH+4s2CaZT589M4Go045TVIvUk0j54Cpemita/oPix53XHyCiYJ2keIWDFrTgz/A75Cx30W
vIIMixNT5nMY80IQMUau7/gt3/LFxdHRO1jdJe+R544T1xsMTx8tZnwjPNN9Cg+sNMreYGm35Omm
5zXmw9nPZNHSwaSHqd904dByIHF4rMsQ8oz9ufZbDpOkfyEj/s9N3ksMIRm+gHdhqFQN4XB5aAM2
b0lOAXMwo0tqAA+vylLW5r4xJnba7Zb1ePeoBz2agt6JrmYvDQF6TWbLx21IOyWJuSFttKyvmJjF
snNjveXWqteOWs1lX4bhbnOw1cBiA9Gemu/0eKOxLPAO4E6SZz3cyV7n7u785uzyj14Hq8KqIOdN
i7RsZl8aD4LJfDFCnPyJTIm5kTwthMoGaepPoq8+zS3geskw9KPU7wdD9qB+kZiP9GD9yRoHb/Bt
UTulXK97G+zOeuaps+ASo57krAE3zdHNVANDDZmfmnS1VoQYd7aKhnNuz3g4AjraI4YSzjd8GLbQ
8peZYzGfWRaSMPcYzhasUb1MbpmiVpadGcfszFjHF7GC61x/o9MHsQ1JnXzz4REla21oYJY+Z3oO
fVrwiG56RisH6V64yePtDhCSS6Q2ZLlcx67diVvMx2WDs4y2ASGj69R0T67IEfIT+ABDwIzhwKaV
HswSAKwjvcJJjlOvf2QX1zRJRorxEqXhcU3THA+DvAhegmgsyq/xvYHORdOx8O2dt/6dNpp+QNIr
BuTJTPL+M59ckUEgYBgmE9yhc8SuZ+agHcE7WTsqx4nfTxbxMJiRCsLni3eNEO9BLfFfw76vfHap
D6BEEs1NQFVW058EMYmI2apbFt7ltBSmwbz0hbbo4iWMS/2w/N+DNIyTcRkT/ebz3K66RlIAY2LG
5WO4F3hq6eAeuwF8NANEvMyLB/Q6YkR8cMyKXEtHbXbDhm+apk6ljQ3uqmOY0nyZeAcIZEo/DtmT
iX33jClUFwW4MAVmBAxaAKlHVnJEN77yJqWLPrupAYoWvI8GxIREKLWxLotXyrVpcGIcTPDee2Ta
/jAXQsGlpkkgA9uwby/RYHWpQTkXgsL851uvUev/go7arONV14Lx8qIRUrP65hvs0PfxW587QOtb
tWvbykEUsAsBUh0s94T+ex1hQpLRXEgbTTTT+7MkiHe9amWPpJer7DQ7Z53nxch7ZTLFJvWFeGqN
c3KDaNbscD8l3Wm7G53xJc7jG/yQ6/KCjmHdfv+sVes8bdedU56u29ibBIPbbtHrdm+FKZSpgfH2
IJnRKOWeRpRyk46dG9TEfJKsApJo3zq4JdSKBrZJPwwNZ0UUsyT+Er6lmdkvfdrpTEdspkd/4cgk
opLHZAi1VxNerK1GchmzShKSGRJ7EoqUXvWcXn0bKgXMT39ZoX7a45bGi1uhKODipTM9CcO59wMz
ZNKNYi5tetsJWNA/QTg4ECD4WrOc/7rFJl+KJoNM7YvTruK7STkfKbJ6FIZj4SuC4NkLZs0tASPx
Za0lS2PSGN0Evir98DqiDPoibtFwAhNH+JslDMaK5ST4Gk0WE4a7O/Nx3T33Dq655a7QcWbJzpLy
a+j5RPNyPoE+fNwM55LuWZwl73j+0DW/fopx5IEgZN0teUp5yCX5Xo9H3qNx9DAGerXVbNZbdpYc
dQ1dxYyEX+mAGgCr+E5WmVA4oZ83gWD2RZDQZKbBS7iuiXQxYMWYdT5NDAClU/IlClX03nYf+FmJ
ysOMfHsV7sjq+0UcxpxoYPh5Ea2PE/77Flc+d4DXoKQ2Wm8M05DmoSY5+O75E+qDteRp9I/Tc2Sf
lr3Pd7+/4yS1PwGuMoimz2qpC/ujYX8wDidD0aJILDArLnEPsoYv0F83sp2mJJ+QiYrUp3QMoVJG
1Pr67XQcgeRTfEIr7+rooeDZl9c89mtQV5V02cLgj6uoI6uUhXhokiNr+O98nAK2Byhffig+mDOg
oZb3sS6qO1gjAujwo5GlS6AloXVBz8BqBSbO1LsK3gDGKHtYq4MHk2gnv7dX/KFNF6VvkrRTbkrO
nvHi8CkhfcbA4DjtJ81FZrGveflSwwoJjUyve+/+4tRrHjVarH4HHPR/+wHMOhm83XtZjEG/w341
Zca5jh6u1cUhzpmO2SOGfsQ2rFuJe8tQPvZ+yavRCFh0PcQg63WGw0pef2GBhvTERGAJwdzlmsUH
aEAACPLfSsa1aVJhwhGn8CgcbM7iHzpB8GbSsPhL2hoD29OFJL3NFEPY55t7EfMg8r30lO8NOZdx
iEfnr2EY53qYAY8s/tfxANPO6J3f39/e9x5vkFHauzn/dPtwyciAE3SZpoj2MdnmDqWL8L0bxL7w
1c/Df5O2HzoPXW6XdlKfNNyb5AXgm+ahTXYOxpOEjILj41K7+b9yylMyVTn4HLwoRGppqHD5rKBp
N+FnTu7Dpa2Zc0eRpFTbsBSF85HxcJUhFsqz0QA7Z9kjNXgJSRWbkzjE06Tu+P0oxm9hP7P6g395
f/rzuU9n89ivN5srnqo1ssmfLujqXWNHGoWJninpmethA/ScgeVgnHQ8ncginelqqe5V/PuHB+9g
BmOZ7OFoyoUADo0padME+aKJhHiF1vWV4zohXed00wS8B+iPzj2SjOErZWSbx4qjIT1jFzMTLD0z
PxBbinfd3zMX9UzyOWkzPy0CZlsUSsFYknbHoJrXDezIkOVVdxI7SJq+PuF/q3VmkC9HaboggQvF
bAVsRZNPa+ujvAPZIFhF+hH/f0xP85XwWyyh9sRXF6rI5Yo/m89XnJSIRQzGyWI4GiNPSnvkV/06
O7AYKAWX0d/4f4Mtq0yvqTbWq9CXeliPZdIN9xb1DtjAvGO2Ru/34Zt3F8WA/rviulbPHITC/M9v
rnlJ0XyWd776XmxbJh9jaWvs1J+sOsKQUxAnvkSzRXoIrUK+sixhrm//4/LqqtO7+/3lH1XU/P78
T727yxvAMXsXncurx/tVbT0L74SzOaDqsWSUsWIHPs0lfQQDbtgBn95fwQMGHa+uaEX4Axw6GfgH
mEx+PDdPQ96zdB4IfUNG+2FM/qUXIFqNccX+y8J9+JIwtzb+VLih42R/Y+AT1uRHo/Xtja5tocgd
HSKLGxcGK1kQxtnHOekVxxHmXHMltLk3xrRRO25XKsVq66hy3G4Wq0fNeuVo5WRtRhfPAxKVszGN
qrx8eNbhKGuccyIv+KMgnfuq1fP5QVhvFj5LNMfHrgBLLP46o3Fr7r+JkyGhU+OyW46dIuIt7Zh8
ujeKEKdbTSPMm6L43V/WNjula0mbUgBkbfnlGi8NQEd8tq8v/3h+xtSYoOXMjrBLVRPFei/CWncT
1w/MkeQKCWRGIYqBaWbKuk1OBtvbSfQ1HPa0Mc0BpG9CCJrf5mZgOWVWAirU18ahdjo7hmwR+Lc4
U5gJpV91Wf84MMmUcsnU5xONq4bfK2ZDdvxfqVqJZFRrnYMh9YDTkBgnvpSrDp1xKJYP4qyhhE1P
vLtgiJF+WOrhh9vYOwhGcHMXkOMVxQvWO1ncIkOwsDsX3mkSpVaoPQQj2YnrdOHQyVvEajmwTdrp
3p91cH9ZfQz/QOWCF7VCvH+4fynhlv9zbGdn1V88TCbWSmEfU9qD1DN7NW8ht9ZR9GxroTftT5Zb
aVcESUJ7o7lxbzBwjtNvci7lo6ONcJJt3Sjp8Hvc5JKm1HA0JV5ZAP6fWEvK5Xe0a3J38CaFd2oy
navrQ5tHzQFHu2YOQhgEQOaB4FoZ8evQpuhnh1IAGVh8AgJn63NnTNaDMWaQw4KTg3IaLPFZyC19
WE0qPTqa6e/SQAzVlRW8JBH1K+CMNUmqZaUQXxKPxDz4QlN/XDF9/u7ro9Wo1dtHdH20KseNVcTt
1l3ECWr4ZS9bm57OzLJm9HjpHSCU5V0y01AwCF016EgwCKxeGnpdNZumIgTk9iR76UsY2/wMukVp
hmH0Yvbke2zkLp5ObDumAejNJNP4OpI83JzEYmCHld5P4f/iGczMP2/NbAA5N+tHldUpz5kVIHmb
98SudM2KXpD2ZDKWjs1RLZtJCz1wqTDov5dGZJ9mOajZbD1J8ozjFufYYsRMMkkqpbFUZAswRqQl
XopKYYkNdj1ijKrFVH/ukl4MOj3S3KlP8IodZIGFPm0z4IBoApDsHg79ZzrdpX4wxBxAfi5LYkHQ
c3jWfWyjs+zrYlxiJ0yPB1jiQk1z2rd0q4az7PJc8VpLjrepHfCbVU595op4vL88cfplr4iTNv2n
PEqSMoA4sF/YA1+rN6SldADeyHfIn3wH0fAOcmTPlpy+LDezuYVlb9goDBkMyyZS6SkMv5Tiv5dp
mZHU+BoypN9nMqJZOOMorslgdZS3vbxh27LXmSSZsczTkCSD9d1zorgh0GCv0IRkzJz5YNxQobu/
2ZsVDy1xGJtN/BuzUpl2Dytq7RKwpbT0h+1500LYNCv98Za79DCLJkD53HFekBpAy3tL8nSd+hL7
zOOOxNx+JL6v4SJLyaV3qpnVlWidRWZBXgMy4ZlbCSwagm2mTj5f1xTHlHdmTZ3ahIvepUAB3np3
kkZbtu2tRkZ014EEd6ZNbKUfWff8IlpLOlK1Ccu25Blto8I7DKoAM24uu8pI1YEdNVm4Czw7Dkdz
YXNgZaixxKoayoNMd84lxyRbCi8mkLiM8mMCTS6ZwA196+R/sGjNLgO8uPCFecAWbYuF8nqDqrZu
zugNat5+6za+orGeooeb5lK5zJHoOovBewV8lI25I1QAy9EWEBlka85I4XouV5mdE2dMBKcqAbs0
sqHZfNoDhKbEixplYQr2crk04uyshSYwMPiorK0DMlfySbrwHPPNIxzjuUa0AcMExU0A9OK05zoR
duc8tY8azePjHZBOzKbEzXraOsuInuYxkUrXo7/2zOz3MOnpxtutJjHZTVWY9pFHtR3R2TRejEZQ
Qaw0qnH0Unwnv4R9fCfiklwOYQCOUWUNjEaCf9MwnGXOxxIIGfk1UU2jUY8OcgTuBPwytz9rHBOU
bwcG9mBy3COjmfKBQcEJWv5hJFVRn/gIipf74qLhGh0C2Q00Idp/xVD408yjszAcOjIy+5FvBHV2
7i7LNFWXg/DUdGpnqiqHVssyxwYRuv+Umv2lOGSe3OXJbJjJZHi04WlVj5B3eSeZbstz6Xi2lzDF
DzbZW8F9ciCzBj1QbDAzxP1jF2VY0gHJoVmUkARljwA9j3a5UJBCOLyAi/qJSy6hp2Lr54uUAgFm
P/UdyaB8goV8kfXhcTBXjN7ag7lx+uKkB9VhacZcsPWn6zvv4BOZiYkn0fa78QJQnVVGkuWF5Zf4
HX1la+eeJlPfssjvZC6tCXPplqpqe4mFHZSUXyKtwgqPLmKdVjowsaJSqdDqzqLpXHfRJGHiUSlm
mUZ/5xsBl4q6qtYar4ZoQp7pweXa47fDzVJRdP5cQbi9xryDoAn82MyTw3fGgvkM7bBbEEziEvbg
w9AiVBifqVODEMzdRztaLrvLBpjetA6/6ve6A+qVWqNeB1FBu3nU2MyLrqxkJS5t0rMkZb0o7s0n
U2CFlt1LXKFgXVvAy4SzznSaksRBSsgDjf6CBn8bn3+Nls5Py42fPV4+QDjA9wD1Pk00IMsxMg63
DkzSjCF+4bomiDcvGAKzOZMvmlPT30JoqG/sZi6kMbSx0lCStFfDkKb/SZ1WOTr9fEhtHPSXGWjm
06TsrDsz0RgMbdm3sbZWrVZbPR7hC0hyMe/4fjhTX7u/N3St1nJTalBBlAPEThQ6K9/8JXzTXLRn
MqYGizxtd8VBWdLlq8EtmGHs7N7PX3w6n43fXX7IKselH2yu7u/N57v28xu04OztrKSIeSeLZNHQ
W/bAsjYbjJ3qZhJ6N6Sleuo8cXPwwOsOP7VxQtEq01qWDZi+7Da3YhA53VSUtOlu+pgxzEtPj094
w98t4reBuvjZDRdrEXCutXDGnQOTkGCdQlNqPvP6MDrdyUOw4UM2XAAHiockW2cGNs0iCwn6CClM
n4N+yPrQjBGndDjHIe3qaMJX+9nND07YYKpdHa7x+yBK/DX2/XYl+NIKguOahHW9A/wBh4F/3n2L
0id7ZxpE6YyfErJPnyfLSlUYO0mheItpnvDqczIRXtiehKH3RiPQSWCZS/8EGPe9Ges79aesgyR8
XQzJVvw7DxSxPMErRcPYMlCv+r6MfwKdZRCo+dCSTK058NO7s4vfdYv2SPOPegvrurOKZlwFpky6
cXQnfBS9gk6rUzyowPavTVfQTHvTDpepRuseX+/9N1N7xH7A0ONSj2SbCGsXgw8NiiaZ2ctw/OYd
FDrplwJ+WbiFlvALLa9Ghn75/CcxzPuLaDwn8exxefOZON5TbltUDdrRc2XJoS9LmclEs4zTL/Nk
qp3ORLDWh4adr2ZNJgM1VAdtjMtM2wL2Je/MkMZJg/iYnXbkxC3go4ajRjhrfRNYTBdsTZQ4TyQV
EmRODWGoYiCtmfKWnpSKFP+ATUiaMX2ieHnFfMa2GY25hrVWOY7mJcenQXsCl6h8yFhT0+HIMfPt
otBa9kkscJoM+g8FaODUb3MgtX9KFjwApoOc5XKX0Lj2kz33xp3k9DRIDRBlxW/ScW7ID1w8gbmT
zKxcsPPQO6BJX5Ea+5/i4YjUwXe5RGNXXg9Hv1r6yF1X68p7ciN3zYZYyQNvt97phVxzElcm0RDE
duKZYjI3cf+oT8swUaJWnOwMzccWgzbLHjeEBRvVJa4pIq/bt5BEIB3g728dMVe01eJVPIp6LidV
dnqAuk+abHt2RaYTV/G4orvJuxNzgWnv6CaMJWUSD8lPLDCc+KGeP4n6yO059AzXowIIBV3D2VRk
fqZyJ06SGMgkW7SBVPrYZJQ6e0z4zdG98CuACuo44E6mRRPCew5N2il9qSwUu/1AmPqVE0nYDJgh
GqNhlilUzRGvtlC4I1hvAqJwaDPRcRLnfk93I39zDFApBC+jhoaktQxDhgVJPoj7yhZI1+CZzJFo
Qf8iS9MzS9NLh182g9rlYfPsRhaaam1teZg9WjQeC7Huha/UNnqUa7RiNlrTZS6QMIdK8GTGRRDZ
d8ALmsUKoxgKuORXWUGspiqnmxyvOSzGvQo8luEDLckNEGo1Pzng9+Y7S/e0W78JeKIrDkfXPFvH
R1JD1vnNMqBWOtUqQetLG3CsFqXIr247Z1k1olqrmUUQeO+wHysY2EL1ljKPpkTd3EHK2fCCYmfu
TzET11HqxF4nHs4Q9Wbcal9QyvCPz+lgGbOf7jS+RiYmSLkq6s+MLfqhY3sh3PemG3wxinW9076l
v5kGz9imdbIwaE4cVqmsmgFqwI2tcJVjP3vLCrMgi6u1RZjaj8s0QndB+brxytfdZFQpn5h1QksS
iEuSNI+C0nIYTSAtcGWZ3Z0wtgV94SER4g66N9OVzjS+d3toLreSsOKKmkSTcP421dStSnVTKOqC
15Dr2bn3+y/MUC6kcbbMQiLuElHd9lx8k/6Ufun1Q4B5etxJMF9TN3vcxbwTyTv/48P5TTdX7bDW
QgUnyeZkSZ8raydZVclMa7FV3yv5KmQy+lb0Gu+dm6Xotd/LmpKkb72Ho4jE1Oyt6NXZZBYFPRRM
u1Dz0WmHsyFWwZ8uJidCr9skNU+J9UwZU+YrcFTZpd4tHdqP8JxCW2Dv6UinVS4aLiYuteFwn5Hp
DE3YjH+5XeeagQ6BmgxRWj7706+mpJ6zTE4RRRVf3UEiK9HcwB57p5XPZZR+iuddQteso0rsJgSK
9HOuiLR4qjBJS/e9tijVPb1xED8tMCVTwCd/8kArIBnzIsMkSsCvoB2nH5xSbgtJeFXAYRkzc1A7
9N55XSFcPWgfMlJblJDQKVCM5mKSob78hdRRyUDjWz/DNAls9tldIHfR0f+p2rM2HcNYLNrytlXB
KMSaCe3KVCtGULglvITdFEKgrmw1b87R0N7h05NpHuv1fUin5nGzDqBsu1qvr3LIOCMA/MGI/Qcw
6dyha3fcj2XB16rlHGBuwUqBWpsUkE2+oAOuSQGfRxzSSjSalXqOwfW7xlpvN+oYa6PSOjpu0j+r
zVajQf9s1o/b7Q2eL2cG3JGg9IQMJRyKj2hTdd2aABrOH0g5P7/5jATPMw+F5H+P6md392Q78oP7
RRB2AB1+TVgtluoUjGL5gUsW4+4BNwf90jrXXfwDetcVqD0jP431RFO9/Cd5I/UeElTbO+VsPpIG
tnzMwcPp3aFjFnfkFl7yS2bZS9jN+EZWgcbJ0EkNrtykaIq8BlE8CVdmkMhYI6Sis9EiRZ47X0Sj
AMJ2uEH820ct0ME7+VQY+ecmsREOHfB7r/icd3BSV2rlWr08x+z4kuvolD4r7+ezfWSOog889c+r
hBWwuQSVu/KmYVdag+49j58F+PZgZihbtQ9C1eCdZ9O1w2JhZZRBUjTpTwmXWi3IiShsuHFqRy7j
KAZHJ4otTFppQ1HtHUhhXvk1H/rj+tqw6CXXqqI3SGWaSknAIl1HNNgUhZC9g+6E1pXNQUFBZPnx
HAjlWxaKpBo3tNSSY+60gRubH1ZwZL1CFuxbKqXWDSfzN+yNo3K1Xk7RL54//6W2SuKRb0D/3R9w
Ev24TLdwOWw22vXRsNE6Dvq/HTdK1dqym3VH3Fx3R7mLE9PD9o+w6LScv1UTrycmXs+Zi+34mJwB
JzKCviSruHQ9MG09Ij2ZaCkrvZrdylri8UB4BUmeZLv/e7d47kukJ6M42q+0pn+Ge4EU2PAv3j9I
zY7xqwGXDIhQa5DWeBfhQxj7j13QPsip9EPthlvhwhY/zE7rb/I+9fnU+Vuu/Y1Ws2k/a14p0vnu
M+PaKx1kPzZJZ152M0ouX4TC3tz9/PgAWxrr1rm5fLj8D1pVfF5UdFB9MU2yUb+ZgCDVdH7Lsmc4
AtPnxXwoNNsReyugTmiCtWaaFw0TW9ExBVnphPB0Q0am7/WGpSSQ+2nENGwe4tPseFWZB8CuLUlo
HMcm88ekwus4SvvgQWs7yKftnT4MqdMZCVOt7bDfG512bsgbaJiT1J2s3YkgG0gPT7k9Q2zHvnHz
tcE4we38D/swfQTfyRkLumV8FNMF3wKsgFScG4Y1GpQTa5ZaS5sZEjqTbWnS/UtKxJ5bnjdvNA6e
Uomj6Nawm4KBmfvtC1P/Q3emb3Ym+OiiMRxIaOxuHLzZTAw/2z/z1Y4x/UHKuj1MRLvrfuAraXkD
YczxYkrmxVoZkAYxCe+/h/ZfbuOurnPODrcrVW3WaSt19ekZRxBS5cZ60fOWtdF7qbnd5rmU8UZx
bmwvdRKeT+rUZYpbVKHwAimakB3UQRADaogJeqXNFmrObRrasmBioyu+ZRw+Yee8VDUAAtFDy82l
DpmWWv4uy8omKGgZRiMIPp+3jrYWjKOnWK9xp8ag1CgoP16qIhI5SypEHycuhjdfYnf5ctYquwZq
MOGFTct2rk1B3V1LubQGpecgvea5DYcPyU34ikpbaX0rxne5Cd3360mtN72k8wgcyrI7VGX3uUeS
3Yj0E+/y083t/XnXK3Surm5/KXjdy4dz7/yPp+d3D3n/T7tKxoc9FvnPqsBCFgsEG9MPYJzLrpZN
t+LqDjaj78TDrug33zQPaMHws6hopJasU/Wb2xrkKF32fMkw437re5BmRiYvKWJk84si1lVRcx8y
cUp2dbg37Jr1uLio53HdyPqFxS6cxcvNap4+06McVKqVGsNaJEffsOcYCc+eSXPTuIRDtlAG+lC0
bBUcRWIII/OIsuzgEvRsUsCTAJW9Wam0D3dosiuHgEwE5QRbcmzaM8Db/Kzz0PmWEwCEASbfnAJS
HlFxoSCXLOJ4BT0Jq1w8RpbPlIXYFAELUgZxRywjM9yoAKuYgddSIjJKzTS0UyPQel3mTx9OHRYf
mNLc3w9Z17cfTryBp/Y9Cdnz33GO7cv/3BG2zex/EO0rG85gfhNpsZJv2UL1rVtIx6m7qCj+tJco
YEiY332ORnP/LBz//2F7bVc4DR3xpj2V3ZvT4XfflfqRfbekffw7dqR595/bkKaV/fejeWOv7Xjd
uXnsXJ14D5fX5/edm0/nzr5r6L4rPEQTMrpQLt3eGQVJSnWl2AGE3TtxwizvzQPsYhHtu3fd2k2n
IZ3NO0+JxeZSB7v6nht8pqYRT+If5q8J/yJFaS/+zQhf1l813s+TYfDGJkNT/wxNmS6aBdOSteSX
tYa8sXufIm25Ow1irR66ZCg3JAHl4u7OO8hzbWXeDGYjc0i9M3uDXvsN/ngJFnDUNOCGIik4+uYE
RmwCgcFOH9CHq4fqbuWXj9/la/ygXWqDfdnwHx+WuHFeDyE2SEOtb0dneCZUkdTWaMHksLRFyPIj
2xYvOf5eNGso5MX6EgJ5Rou6Wjl3sXFY4gF+k0oOTO+XaF5Gc0kMXaEMwHs6z09wmab0gSnJU2WQ
LkXxIPe1bf4fU4DIcfcokewSadpvX3soS4uMYB9JaO4bQG/xAE1hCNsl7x07IxdjaGaZgwI0E8kk
fIXDnFN4IwSzgX1n+oa3jEA9xp8Zo2FJ1D1TePliFkzCey7OHsSS6NwPnbXnxdGIV5H1uCmjC5HY
yd2ttoHGaFN7JjTCwAKJz40SqGcHXz6S2X/B//7O+3JFguMuGHzhXxx6B6plFb3rYFCUEoZXdMa+
HmoZm3eHmt5bPa612YsYKD4CfydV1Px9z63Bf/03pLa+76LMYTAbcld+NItebTfb1XaVhpQu+ihX
TbM/TCZ0hDFJLwFTWnrhw9XZu2pRdq+qvEwTzbxuGBKzqnMnaxXpZLXdPmq1a9QyjsxoOI76QCTQ
bQCGRNGrqEs4PL+mE/AouEOsHjcb1eMGvZ2BR5FFLkk8yXiBjQQgNh27mE3wryFbxRCZzyEDk1lD
1pd4aTWnRwQp82khNVifOJASNvp1BNLq9HWwJaMKx2kSiwoyeDvxmBV6/kydb5seNLwQgDb9qb3U
2tFRu96i1ibB14dkMXi+S+iQpLb7E9qokT9PlCumufR29ahVOVq3Qr+E/U9XyDAhu+KOJmCs7uQm
vbmHL66xI4ePLihkuCYjbxyNbFStUXGiaix4mfxzokG1ajVvL10aOVvkh5nUgiYdj1NvScK2Dj3H
OcZGkROQEyG8w57ZdIWUpv1V4pQlr7CMSDOBn8ZJn6QKOppJH3dQnNVXyORVgT3ngn2gZ6eQ7JhD
Zm4Xn4/QqqlNSFcLvczxf0ikwrvOeKxNFf3TbveOPUDpKepxdDkRvej/rov6TdBDHh9OC0JurVUl
Us5tE8iiOI9Sn2t5+JLFzodsmGjmqygx1M7fE6lDJn3wnT68O+VDf69bTMAn71Z6ECe5DgzlWsS0
qdDAd9d80LGh9ZaROYEvLYYQ884jhurwLUt3P+0WtBrYKgYrwJH/SXcj5OP37jq7dZxsjEbFZEjb
+y23yzCs33VJNRJGA8HqFP78v/9ngZ2LHL+VKPx/Fk68/wTIfzSOvgKX+Z/0mf8s2Jbk7/66hfTt
DVj8z8L/8ZfCv2hJvneezEzcrp+vhgvRZIVr9VzWNjMQ7fy8NGo/vjtFkvRQaK23bKR2rkQ5lX10
kfuIVV1zOiurdpVD1iTQddJbOzrJrtrKIoYft9FcxhxvkJBQUOHvBWvnNEymYw7jzJVZCKICFgM8
VmRaJHYVobHRrVHk6LyjZc81F972vCju5qlkDKE+iMfvjMm6Cmf95Ct8UXi5cViURKFeGAOZ8sy/
bR1KA3xV4Te1iiq33AtICnTSJ5GFBAtOClkggeTElGBiPQxIdpEpnH3PiiCCC6lgPIN4LvpkVuz7
1qONzWVmHaQV0Ajgj+OPq0JKUwoewWiQchNeo9o+buOyFuyeqDclVRL+m0dCWum3/7YIOWBwgNoK
tOQodMoXNmkOrSarVJgOgXJ1AEin12+CF9QwohXr3F2qLve77okpAILr37DzVytF77br/ZH+pVRt
Fi1SFr+n91lv1BaYm+oz50lsaApvZA0gvSUaYxeSWsJYMdpnnAOAtB+8LwNpHderxzQQi3aVxOo0
RKlOMwJ+rHnkPCZYFUP18Pckmei8HFVbmJdngAKfSBRNEZcRR6ZgLuS5o1rlqGbnL8vTz9he6NMY
X2ERg943LohKh8RfehoP2hqt7/met+vSqLL2zsZCXjJAj6Fd2p2GIV3mPDZa0SM7wsqx7ZGsP9Ph
M3BAnmnXGsfHWeu6YwYJ7e2hJNStfpC1QTuRtepR7bhCu6TaqBy3jjClhiQUlsLS6yJ5ONsVWhWf
MOlJs9Fi5VV2MCeMn0O/K01IcQ3EkxFAa5mHCKPzQNvvsrmvm5FqdsJqv7nNM62UgMWgQ9A8NsZJ
F+9CR1xMwlxNhSBlRuKCZiGOvdMATwglZ/4vXM5h+ky/LGirjHM54VtqJlkcQtksjau2wV5yHkml
flxpYT1AcSX7I4NowmNmNTP2siReIYx/LDgDqdboP+0mL0e93jzOdqTNaVWfPIdUtVvZH0n1pP0P
60meWp0iTOaE1miQWj4RSAnbzUSy6wx4u+SdiheUboNI6VAttxxb6CVt/Xrp03bOhjzo7ufLiwfJ
uAMarHP1wEzB1D4yPGwUI+BcPLo4eDYazeNK2xUGJJsUihppUZXOAOAO/8r0/5klEo28c3N2f3t5
xlZuqyaz2zg6rtXlvLARVIgTPwuAFuSeM0qtnCnU7hIEHjVT12aOa0etll2aacIQ9HOMu6Q/iPXc
auoL7WaNXzDjCL9OE+b1ptfVlmcdmq8LiPtkZtRaNHNkvtuo1BtO98ewOZe6ndPFnZeByqxl+ylY
DKNEqXcAmp4u5ld0bMjWxEtHFX3puNmu1bMv5t5Kme+LnRvUz0ajSqYd3tXJJgOyXl2ZJTw6oL2a
iqHwzHXTAyw+HcXcoh01tJ0azgL6sOwmOECEKkoWKW1KFifazXBorniWN/q4NNrWgVVaJJj33Ans
roEv8gDcldorwFuPrMCDJ4bLGKpLDZXMF5I1yv5ZeGg8doMUdnhkzAcaLdr+DTt96SShc/OemePZ
DYK6huejEZK04vl7yW0TpkGjUcuVYSTnaTAVYIXqD21ZJq9J1221+W0uk+N60Tvv3h9XS1WdjeNa
q+JcRHSla+lBmsNBlCpbWrVVah1NVhau+Y6rONL+mcgqIYgpk0DisH7kLFM6e+rr6shGpyt9MRdP
lk7c0XGjVWvnljY2KxrFtN1QaFBPG7+n++yofXREN6FPW5GufCSqL7nZWIFWPxPJZl59WRxjb2Ij
d+ZjoPYG5fvw7cuvpHp92TBcsmsPc422mq360dFasULr8PeIBvrcYRohxl2O59F8MQzlN+zH0sVo
01qQLvjf4NA6ajXb9G/ASR7xKssda2+OOz2V55ovqMpGzmckjdeKzFFcL9PCk65Qkp+bFXO75MbY
arzzDkiFqTcRGeZ0FE7Esedz6Qs0HRVth791wvzck2Dg/UNyE17NkRnjoBTpoqO9HGavNOr2FX1m
6U36sYm/83v0Q5xwyheci7KErBXd5eb8H5zIqaeJtq8ZefbZZuWEmx0bxZh2RqPOnjMdMU6VnF1o
Z4nU8JMJNa62Nq1Ods5FhQMuKJ6b0vCaqGm0bH0GzDIiC4yT0Wl3eUWalXfr1oH26jAdBFNb81D2
Flyt2FbUoYroaMeVRgv7h/PKYOLBMxjNxxKKIEXwZ1QW+BmsRt4DbgcGi+pxruvF2T6q19k9i7pJ
djiiTLEz8R4j5i6s2jxsLrjNLQ+xUX232hZOGhyqzPCAfVbl5sWOx8+1TU2t9oArwzqmDqwMT5h6
mfll5eM0fVX1LDcbtWYmk+jMWwX67hFzCZDb9Dr42sWi8iBVKhy3Wu1Wxe4PMWqZRgUVMYZggmQz
RdywG46jLD7mIuN8YZFHs+CI12rlU/RRbhHNSUVRaybNEOsNpW1JewexgHnCALn587WiOSRV44Zm
qqJluyojsBLK1ofrKzEZxszl7yk768ZGm+1mNes2X4rMAWIs3VISX6Gs0qb36zXezEYdo0k9pf0x
sHYFvbTklNf+2w+scdKzFqRga5ZdS555szTeynUQzbMTWZPvHh9Xay02xrRYm/3ydDj6mSkkztXc
DAQ5pKKASbrKSGx84MRG3f++HACF7XGHjvbz2De3e+ynyXRKDf/AJdSTp9Q405qOy179z+r3Ew+5
JIKFwudhus/WFQe/QHGDzEJDtrzMAwNvCkJqg4AlLHQoJQWyNGsnjEgcv6n+V2RZHBjlMZ/kwQgO
zlaXQtb4HD7B8ddneJe9UfgqRaeELyS1zUsRIKMCUIc/XT+IB8rSFCnPHHNNsNLOuI5whxtxnZ9v
mexKSmx+SwtrIxQm3iArp6EJTACyZOUKlfuGLm6P8bjZZvozb2I3mcRgCfFGKo8LHRldFc/0A2mJ
NH2v0ZBuRbpXa5WKKJoaRIOmSL8q4l9GkRLzyaW3H79lvV5pt1dZqMysqH+NhnJJYmj2C/qBzEGS
VOtxHksvfOZu0hvHlYrd7U6KNPWlMxwmsanUSuKFBQsm6ijP2JoY8oecw5BlJFxO17dSFj5L2kMa
4P/UXL19d5FUhlgaao5GAA5aKwJyvlvkHOpEnL3FwUTdzUKWl2rCaGwDvRwbIGnxxs6LYMY0hKB3
nYcsexgqkxoSda2WuFDG1CHi9pozEJpCiexkpSPJ/gxumn6fcDDVBHqF+QIAeHEB4mAXeMtWv8o+
rRZlC9f0Z7pnSqUS2XcS42pXKl9pRxW5HOVX/E9WLMJIMcPGT8Nk5tlQGKcz53hJh4MyaAtTc14r
vkTpOPoSmpphOi86QCmspnNva48VPS08jtkj82woskvrObFYi15QysnxvqEFYTJa9XOfrJlhAcWg
ikMIXkzO5IAWoVReO89uo3JUb7W+I3/rqFatDvqNUbM9Gv123CxV698hXkvuPs2LyFzi3fc3WrLT
ZWJPa9P6aPUdvhBsCMRrhDdNi/NmcuQky8SXag2DZDLJaJeMpNZs/MKP0k61NB8Pi57+VMNPHJ77
haSPUDzw15TXnd4u2ACdMrRECYbwY/aT5KYI2mZ9E1ny/bqm8u2ueeZ7ljT8ikIduYziH0uGrT4i
ZWAcDTOtpZWfddH7THhJEsRZkB8bwnf5HSBwWcWs2nuNBTiyngl82WVsodSCsSO5MVVCmKF1xJKO
9gP1f1wK2MHZs7//4dD4ShmrV1oWKex11q8jo5Ls2B/YUVuk3/4gdEFCmWZrMPDdKw/9AH1RM+/X
U2EYT+uHU4mLKWvucv/Xfkjf+XCvJU3OZVpJam5G97nhvay4NS3U0YnkqNoipUAoLqZ0MQXxF3Gx
QbfUmB9DIZgwp7UzfLt2F+Fb58Fs/PYR7V9IhDxaKoa0DunRdGsunxpX4qmWGkhGI+mWYad8b0Ow
2FL0Z+wmoWjaviCGniRELb0Brc/yp7bTfetalYznv8cuMhgEMuv54VWZR0uLg5txOnwLclep/wxb
GAkp4nNbXmm6Q59oH4O/ESSRL6HPujEIceTffHl/O63XUldq2ZQrKzxjLNCpTKPNccUHlrNM49RC
ksJBbmW0UW0EN1rQ57q5tilAXPV9znGaJ1N4LJB5RYaeq0Fr6AYGywq4zJNas2jhTxKJVuI7puv3
hV0t4BFpiNztu3xkC50/cxPKdCDNDDUZdKxcdjGbl38lISwplqsMGDmOeYwCNDfycVrm+vIS182y
Kp4F/ieHjhnB9OdEqIiCPkw0uiu3fgPaVbW2wsC3F7BniLqOoC2zGWn6zx5+y3w9ygANGW8rqf26
Ofl/TQ9LDqeH4pl5BlxSb8U3wLr4BHJQxPSuoj5Iejah18ggfRq71IDraamblTzq5PaO/oLWzkAR
wcyVEDHFPIOPFA1Vmkm6bd7CPi1UStJ9Hz9DcwcyEIpNzG4GhoX3aRVlUpoMDszh0xUfeLBcpPyQ
MYB5pCArx+KQyErRcciysATlLlgXhcEeRgOQx8htrPIzd+VDK8uBFbX+8IRUdzp11KMTKN/ClxEn
XiHzrxWk0Luwb5iKfia1lpN2kVHBnAlCpVjMMrP5/tbEiSKNcUga0PDsoxfOB4adT4EuJJqfo/CF
w6kS9uB+HrIIoskZBQPSbEzvOdTF/I1CRiyWWpCFvEz9HJZuEklOQ3GFGEQQHvvbIpq7qQk2MQ7i
voTPgZcNCgLf2ux9gWsFd6We+IPrMF58uCGRZdZYbnxGEykDPeetepa4CnREI1szY8jyToHFJe90
zCU62EuTx++7nUPXzCvfnX3TyQID5lsmZSXbntvIhHXEPbOrl22ldWD6L30AESd0x07e5s+pz3Qg
tp6m/f52FUEfN08z/RKfu5zZ36y4hCQT2imzN9mtsm2nwQBVzDyfFOZwjoRwWtqh4wZwaiZV3iN4
V/Ti97YdeR0b9kvUj/pv840lLS23Cr5dkgYUo7MPzXruNfPdTBY3K67LR+kCQTIFitY0JwS43F4o
YkL2UhC/Zc/aLE3QBQ537qurhP0fOFR3pokPHZIVhnBwnD2QfQPquHVHmpyjZg7x6CbnKxefmCnI
KM8o478Yt6P35/vz7kPn/uEvy6MVgcaDtG0qNlczKxTQD0fBXm6B4xZiFXvwqMt65SuIrDWwaexN
t5oqdiJCEMALZMVkeeOqy2r7mAW5ksrsl9FE+UtIJntfaRSUZVoBkqT5DaWmfW5CfPRbsuSxF9Yv
pcEQ2SyFEnKBQ1OcPhyZuhV8JXJ6kIRJkEq4o/prnKDnw/7yiXas4hFt9YFw2dlUYsH1JF/AUODu
fVxCIsFZO+iPk76kLmkbpfRvqItbVNy6eK2Qdsx5NpJcJj4qmJks0Aco6JXlMOe+fGiP0jApQYXO
aDX4kp8BFkbiX0zjhOWRLfkGR5howz+Jn8QM2BJaDHJEHaDb/BrNJaygV6Qz9KUhMqGLZqpxMDdH
8bFLgjFGijMMe9xoPuWc1oeMYa6LQ7d04ZEuLrnQhlywq4AZX84a3/5BwwCCR+H27sFY6C2o4ZwA
bLtwac0RN0c7yxV3ePWVhQq/JcUONtU39IM/EapWjSZWZuE4609B7YP5Mw/fUqLSCadD5Rae62zU
YSGW9nNa1trV4+auglqW7ZNkMVkpXDCrxz3MH7aqo+OPtZK11w8A7Xl6gisVYBrE9vJXRZcVwQ8d
qaHkfQxmH5yaUayp6Z+oraJpbEefNRymD5d07+9VpST/pjmj3/Eq5mmazwHe91WY4bjxVpifj9rv
9BZwvRa52R7Okqnh9WEJL946WyZAqlQjIzBeILHWYz/hnJECMETZE2OqD6xteb+5p+N3Tyr7veQW
uuevWtvQdShmo0g4WnfRbJFmqPvCp1d9vIqUFZTHMVU3f/vao77k/rRf1/HGBX1p+aBWHc3J6p6B
Bgn5mOpGc92nWq4jL4Tdl1IjknPMFt+jot9rrvT2zm3SRsYBMvn1oTUpHjIFjuJlIPO/LmhyQZX8
Z+PN2jHN8yD9gnlmWrdvKSGUf3HEROzx/PtbEAfZ97+Pn9YNQKZKlI8BXedwc5plMBppVhyj8l5/
YGe83RWOPbHek/qQsFdJ6j3KVjCZMQXbTOFkDfF3NyP4pq7sLf7Hw3B2FXHFtpod5VG2IVAlwus4
h/hy5JUssPMUhWlZzESGrJG7PgufGKicXZ64EErya8lAzxpBq4howgQbzAvuJM21OgcKtXKUFBVd
SkaX0ytSUeyo7VyU/CGkku08cRdc34491Tq8D+ZfzPW0StS8YgGr7lS+UHrLMprt2YZ2cs5yRFef
LtnPbiwTIOiGfduDah/NTwNS1Te32LLXT9swditunhXRDNkSAGDjL6Zbat7TA4tpTwmve9IMPGri
Lh72x/IvkwTeFFw7iixlMjO7/RzdiUuXzZ/pVotJV4bffqxgrR3+AXrPvpbCZqbVAYf5isNxg0WW
826qUJSYALabmGRCX00biGdnOuW/mN8bdzbjWdhc2yFJgzGZOyliDUJ5/VEqvCniIy3lPhvOXvYp
a9hcytkTalXlY7zhwB18MQj3D0vebVbBTIygbO1tvUjNe+dthtwbca0XJesufGOLEIGK1ch90fos
58+o785WythjPAA488XjAifLV/E77uWqXQcJ0+Q/3MC+PGqyt5sMBTPreh3Mn6+vvAP8M9RUQ/rl
7AvtcRPKOszV7fyeEjlAqk82SQL546obHI9Vq0f16vGx9rvmeghsIaTuz5+8gy71m//wM/PLWxe8
9L3+T/Rdta536csmhxz9ZUPva9VW+7iuvXe0LK4epryA/1Sncg3tLF72SZ/uHXQvrzYFJZ5GX0uA
2PcEzwrPovnKBpWg6bqtgnSC4ArNem2Jsx0wg3RCWxf9We7w3iOX9pe5gGfPlWH4kiETnFJptK99
cbn4yQghTP/XaF7eMPhfg5dA6rmUEiWp5T6vjNhxVl0qFYahovV+d/kghS1mQ7q6lRwFSRggf0zg
s1/ntmLrkLOxTINoB7IkAzKw9JCqZJApg2hKnVLdwYIMWGG4lBrWGrDsh5Z8wIG2HVSbx8e1Wuv7
S1+ZbfirRBDcBZ0gey9F0d3hU+gsDH58mZXBtJ+WuwuSo/4Z/y8rJaEP/vVvWB0JyG3Ub9e8YZbp
12j+jW/SG72V2V8Gbh6hXNbqZcpIliyH2o0adkjbmfTHXPu6qWeGLVwT1gmYQzz8ShPE175WfmPY
WV9KcTj1FN0Y8E/sozMp5tg9OaparpqK+iaIdL9wXVSTNKuGMuOFjEKx/6q80qFZOTJHrntKRQus
dMhvxMIBkNbknr0lE5wRcL70IIM3SSfHLwZn79k9ChxHNGF01d0jlJ96ApgE0OLQJmEenF+fn3jn
8WD2JqBkqdV8bg7QoXCr2yV9NpXMSVE35Q21JgosZVsMAI+gD4JUWg8QwN+1NNQHkO7iBd/hKbLJ
0is1MvvRnMslc72uIe2gtDycTVZ0+NfXUjgaCWN6GE4ZhiDyslrBC6k/JM3NJxESzN588Di9kuCk
ve+P6eTSD30fKfj4LTwAcTj0o7lPO8z+GuFFf5jQP79ucmtJlWqgS77BVGUwSrRxsR3F+fLupQXM
kSnT/vPdjT1byjvgVj/hzBFqbIw0I6cuo7ajMdAhJ5ahKJ132y1rBgWa5fdZRJeZ0iseRU8LmGi0
ziTfxhwkUwgOV4qn7mCfLKapW2Hx7vNdRqtBtwh/nLPlChxI5tLiXPTRK0yfp57fJTXjqFSh/6ue
3N3ePxSWIWh3973T25sbUod7dO2cP/TO7+9v79dsnWgKwEt2PS/tF7ZSaMBpMojC+ZuAToIneu2l
5dsaAKRKIqTp1YqNYrPY2qRlmBKlw9jWRsRI875XxmqZkIBUqYRvAClRWhNDshOkgFs4U8SWRHQd
E7r6niGwtBUg/G0BFk5hghfC/BVzq792L2bcoHkTgEQ5nAasvk/S8iyR8oEZlIjjenTt0QfpYBW9
l2gSJkUvGoyTBV3RXOGGtKpNASAzO5j+kg6u9MdbHuwdkzk7vgpGesFjcpZ8RvBlns5JX7PuZZQ5
UXSkCXIsTOq8bsezmy5mNkI8xEC/k/GLSLPLO9tUMhLXBj6k5hcjVJ+ZpXwupAIM4Cx6BnMqblo2
ow3DBLdhxzifwUEZFbyDylG1duiSGr5yAMpAx7POMgxb+4ZQLp6SfDTWfdA9eZWR+9unGJ+3kwZv
PUyqakUO1Fo48JJ92RJ0ztntzQ8P3sPt4+nnfYrctHbga34Qf6Ux2lpKuSUYOrOODPoX/gZT2/Zy
nrmhFtNhMFf6/sIsfEm+4ObIoqlp4VtKe1Sb5Uod/+WWUPDBjdL6brv4C9Px4SmSl4PZeLW+g+Ow
sePYq4qDTIcDKYwTIwDydap5QizNAuNrJOp72r2/8A5OWYIwsa9BwF7QmEPgtdxCPZuqK+cOJ39Y
uNR3V09vVSQVwxTQtTXyhiHueqh4kCJ8hxi+E4mUpRZ8pEWyioy8KwNpsE5mp39bkAUxmoVSKbtG
H0aBlkq1PCMNEhrFkKuiYMmsDPf1W6trZgPT8kRPlqvH3S5IasUKNBXHQwfdzq0Zg3alLpF3mQX5
HFeDzXG4D9mNr9RHJm1x6tR04Rz6pvKvPpwa7k4xmbibeOgCNCs/uqpYkobg97wUH6pJQna48zWB
kMTXQwJqaAZc8pHCz0oZLRWe6cLfCJxmDi8udGYqf+61TY6zGcsq/XjpczRZV0SovcZHs6taTx2V
nNzzmlXu2XpmX03hGz2zPe7UZpfi+mPsgrFp+h+uSJspVcrVUpUDC3RFKjPakqoyH6f+S9WvkjU3
TNMxNvdJlVrbsmXpldILAH1JrF0mFRd8CEjJ2Gcxqo4EHlrlUJKASVl3KVylMCttJONcxi25+Sm6
X2HlFeQXwjV+CadiwVRsNnoPu/vph2tZ0EzMPSSGIB55xWx76DMAa4LBmI9OYCIqrHjutb7+TLu5
wX2+fq4c8fyHBSDwc6llrKqXKSydDWBHUPRvWSO+0d+29N55XD+5/9UCFgGmBwKLcww+LaFhdvKE
pRS7MteLmT4UiIU1tqUg754of/pTT9QbwflbHrxdId0R8oumybykpcU+iWBZ/649Cren3TtnPvZ5
WuvBb6j/d+TqQB9vHz6f3++jBB3tUIKmi5QhR7RTh0GURmFq9KGjiuvE7txdspC40qi730EuuMUZ
F70LsLx2s5RVOTLP/KaCeuFBC9Jo1WfPKu6nMBEL8Dli60Mzjw6oHzXw7zkssjpT6Wo53A1ejTDZ
x/wFUa0vn/CD6Qb798jymJqIqQPGc2eoqLxbRYdlq4hoiBPV+TOT+PzF+zmaMcjrPgxYbMHJVbfp
MVmt5ZzBxfEv2FZ8k+QmXRlRl6aZU77vHMwjLU3R3L4/35e835HgspUEmbs0q+MXpLla6ridTRSd
FhREQCTjy2ASfDN1GtMTjyaxxIFTIX3Ne2I2lS1EXYF3lx+cnn5YefE7Che67Rngwx74Sp3yEm0i
haLs9fhASNe+4Y1JRsb2DW8pAMB343bf8v7XWcHWcl/ahrrdnaAKUpZgkM9ibxBNQViaLtgON7gx
3oAA6UYvy1R6JToHcTQJxuWYy9dJ9M1E6eiOt9oIaYJzUKms6FkimCVlCLo2qSW74J30SL0UDobP
YY/+Nw16QZj2qrU26VLBNlmwvYFas/U9Dcz+ue/Pvvfr7nefBhO8TG3klQxSDe8uuvu2hC5oS/V2
459paWUuvq8zm5qQLdzIfFzQf1VHTXdtWfE2Gctxx05zld9JFG/I6trz/eArvd+wN44TCut2ryzi
9PKMr5B6693O02cj6uA4mwtCW28JF4nNwQwUbhADak9rUL2xbM7NNslUd+2MP7Kn3+5FjA0Hm6JT
HEnGfnRiXA/Oet0yy8ka/yRCbq1KrciezUO4rKD97+EChO5/L20Ix6u6//ZzHM5n0QRgYOs5rNj+
t0VbYN4A1RjuJXeYbF1+PJ9dHSe+topLPqVrRIeIq15S5PQXPvy1vjsLnJSp71MD8oCVq9n0nRnv
t2oJXBElfDPZWspLjNAqiCj4lnVDI8v9/wYPq06B62HNn5HamjOyu6WM4mVdg7wQLshYiDTHzILK
ZkbXVBnBcTpyj1NH8fXfcCL2mI6AJv9lsEnDdBG6huPHyC+mj9SbMJclO1CSykkYL7Lus0oH967U
aeJYnH/KL2zGV7GRW9IG0d7GjrpwkQFzWzF93tP4bfqciqeIQyo26JPFJbM+flSXf1FIJe2jsBdI
0X8JxiCb0sJThllpF0L9qH181G4vh8zX5/VK8ccyyuBmabztRrO5JUpqwI0sxnjYG7Fv6xmLNjRi
Rm89fn7VzrajidESToUBtyMON5nKiyXDys4taG1BzT99K08D0ryMDcU9YnhDZkUVTfqN2GwM1pM8
xlEyYJAD8H6SGoOq4pskvrOVTG8Fq7dxOzkgF0Gnoew7XUzGz55zwjNsjGxEshMjMGKZ+8W8GoCm
B9XXo2nGbqqkWMJ9sxM2KQ4D5vspSRc2LnKrtgMyuaatxWzsMqLQTlFGKpqK5klGZhN6ZzcP3sFZ
wmA65hk8FBkm5L9b1l8qg4DdD03AA4siVgaDUDK/TUW2MYWFeuxsOoiXrzLSqBTNW+p+Upm4pli2
BucNGwVd0ytVR7j9nekmx62jRq2yg8WCZjaZcy1rmZYVf5RObetEXXSg90KH0qzWsBnr9qpZzGD0
FDM8mIOmDrl/hhNyLhHjssrTSae58isyV8xfokVN5t4MLIQbadPMlSJ50PqPj+Fz8BIl0F+ay3dh
c8vlurYRwE0uY7eye965h9ljCs51m3/9tU3nG34EDg3BDXuPUl7UsOok2WL9a9pDRkxPuQTFNM6T
wFUq2+jk+skiHoRmZzt1LVTbqGYN1Rl9ayakvq3VTftqLUOdbbN6vK1Nq4mUdJp67HQrJYN02ssX
I1znlt3YLqhA33rYqdMpcwut8/FiHrfS8q2pML9yOL/lZQAkSIfSP/xzbTH4iIRBvHF4+87VmsaX
fCB7esiPcskRqSinHGrPWUHrddMsNOc6U8PRlltav/CLfGDj9eygvBBqWfFlWjgq9271EVgb6/27
O0NqYVzW0umpKY8nnsic48ufSZQ53QRvxGBJo86B3DcO18E53S3S59XxNhpL42VNvQCfeiFzUqeL
vmD3rGo1V7c4AxD5Kbl6T++v0MBBtVZruFWKHxKNgBgeYtseqTMSOZG8CPowAh0zLoRyebYCPtgQ
+cF7uXlMTSLctiQMfGzD1C2Rttw/nAprCxyLPhf7PE0mk0Wsnzt0FRj5rro1laODLk0G1EwAowGE
iEt/Jf3RIlVNBdPHloZQLsTDSIAZfQFfak2VzAEqjIKSA62FGLwnQQZ6l3cA3LFH/UmCXCHNPNvZ
HuOQUvCXJV9N4WKgzAwYTbcUg8ewzKb8Euc0nZ5nyZRAqqmSVEOMhtUInavJgimYhElONbV1OMRl
fyjt7Nl8sMJlBKLltPSUJE9jwSg8lZFdtkhTX94oD8qtdP6HP0ZHtY/nj+VJuXbx+h/DWuOx84fO
75ZNKMRHWdDR5RuFcwU4JoPy83wyLg9nAZmZ+L1PC5xGA38yBPQBSAi7Kr/Vkfv1EsLQ25CL0zCc
ZdzJG/dbxrz76Y722icpMWeCAMoHdiikL7F/9zHH+5RzmzEbuMQeV/zXknACxv94GDA91nq1V+yp
NRX22J8oOfEc2I41Gf6g1q5U0l0V+CSGoj/pRtqg49bIMO+zDmuw2BcbdVlWXo5zPo/16urqeERl
lS5IPS3dkz7DLw+UYYfNSaFSwUdsjqlS26ijIRXuTy0zu4SShh/MujiClAcnxQ6F/xE2CwgmUNx3
+yzumpA9lIhdTWwuuvb9Ta7Uu1uKD7dX48Mn3sXlzafz+7v7y5sHzcayIULJoYridGFKakhML+81
zjQZU+WQOSWeg9lEanOSVBlKuxvIUsWpyN4FKOxyZvqLaExSAiAs5Z61oCvmoAZf/d3dPplZ7R3x
bZbaoVy5v0tmdGw1vN3m8PY6EIJADuhTXIGUa2nSZCxV3v0G1IHlF2QHz07YATj2pbS21vba+IZc
aiUpFJbuRBuwO0aARE5q3T6PA6sK2F1PSpxsfUUrju3Vm0nw9fMqq/zWV17rgx5XruituJK2vBT2
uY7PzoexQuqoKdnKXRufVn2hFEyn0EfsEd3nBRPp2fsdHJnh5dn+LyTpYLrY/3FTUmP/N/CrAIrm
7lfkLs8Y/XetgzwPSrOEzdjdyyxvwFnOpeVKEAnPO99aRIILQtVmEoV0Qmc9iQjsAgkJr6AFufUX
T74pTuGjOMUmKS2Zsg/nV+fX5w/3f5IEWSdfyOIm3bwJ2ochyicq+wMAamQEGJqprKwl1xAzGjRX
3AqV25bVlgHJP4jCrLW58tPkP4D0OXwErVl9FQT4M0sY4X1Yk+u+F+the0d1BVDecfbua/RkoEh4
xwEhhK8rc2C97MwckGXzxYk3lRgVnJzPyAUneb6YMquFag6AvRaRjD7bj/oGtU2aq1z76JLg+Ljk
gISl8Muu7eb5Ou21nUsW/kwWEl2QAlNc4rtZxy6gi32G+TjN0taxjGSCfOgC0Ug3+DNMrTFoh3nm
tvf9mfsgP5dkrjb2vJ91/SwAtOuRax/eKYNYta6cQ4qUhFMe9FiWqdtjcnZcsvJ6R1Rv6vssNSVD
i/gE9Wwg1cbR3OYuegd2uGUXGYYhkoL5C6kfCVt+yhBv2OQfL73Bczj40qfZLHQFCBqx3cm1DJV7
Q4dRAKLtLfXoROMaEuMtQa4fmspO05cY9F8Bl70blTK9+qXaaHhPwXQ3p+JeC7zS0+3ryw/uWFgn
sGeHI5ldIQqCIlQ/LCj3mvLA4dT21W9sqioWjATmR9GAjwOatWCqnUhaSfZ4nnTITugkGS6EnX+1
Ha6pstQMGzC2LVomrrLMDHGQhpKqO1SSD8fjUtBi1iX7aXuXiL/g1bu6Pf39+Zm0NcKyYIgzehz5
TwdsQghxqPyG7+/UO5BpNqUbXGmjLhdfdC2f1MY0J3jW1Ne2vXP+LdLinml5OjPl/dISjPOV/GG6
MxcT8QiE9AV/RFvu7yikyEa+Ux7QVypDpDCYbjbbfm3YHI6OB41au99c2XOrM2gWK9trWx9fG2lL
w1DXaPvLkjuFCwdDOSkWdn0NzDEkedZ4GLa+RpcRGWkgxLnL+3fXEKps7/DzYo5wMJrpsibxTzQm
8cXtPWrtaqT/PNveAsqCgz7kSerdfA5QrEOR7Nub5lSNrjPirR9RkeREvx+sQDiF7knibKcDGdsA
KVbtcqVN/yw7xT/8CZ1Q5m3xhUHI2ear2Q5mNAP9MkJkPl0pyxGRVmMlS31bK7TkzFLDnoAN2uOx
2Pggor+7v/0d/da7P7/qPJAY2kPzOt5lKgfpszhcuLTVczS1WPDjHBb8NRwPkDzFPDThZpZvU5/g
OYFJ+BT2jJ1QmqRzgbkWJIq6qSYIvutoGEaJKHwiM51bNzEPvSYLqs+aHjKvD7zD2G+cQRwsYrIO
cmpA0ajPvpHVUBTl5jHXbxIzfIF1lbFQzh+AwUuyRiwNtx8gqZsbK3opjY3dV4ltpvsWD4omr8y7
SwZfQnownA9K7AIXdxpcyaQ8zlMZmmse/MA6i+9kPgsDBrsnkcSuR/EZ2i0NzcnEGjL623qRftIa
OG7ePK89p+8KDiA3KasFK8wy85TrjK930B7nCJJNAr7JHfhwb9iBHOaMsmZbMPAcVNryNVNIaWNn
SB7Pgz7WvcReXOTapfNZGExKQSpJxGy4suOnNBjNSgITWS/vv79V0/2ViajnmRLMzrjmouHYX4pe
UUrvmSTyNOu57GL6mbZCp3vPn2YPG8dpM8Fo2E/ph4BV/kxPFbQTmtML2dGvoqxeIiCBwdxiTblm
ExDbhouBXpZkZvC7MkE77SQh5JWe0+lDtbNnzGHWscd5NE5/gL4V+lHqw6wcSRYgRBJMUlhi3D31
HpNmbo5t3lQ2DNMA9GSZWII3yw5s0Tu9uOf+IYY2B0E312f3OS4CFW1i5t4nmzmcRVqQUeffpSnA
8MKvtAXQ3Ag51s6KOEvGBQNMWS/O1vZghJvgXzTjOqt6WA27wavKJJtKSbeQkoDzoXSMdCYsodcC
bqFke/EZQu9BuAG7DMyH7eFYWx3dvfDj0+71RqHWa9ZoU8awvBI6zFWKMEogXjJlIkxxiGA6RawW
OpF5ztAJ1b6nPUffNYetLHZAWjZH4M5RddM30pu3FJ/Y5zBnq5/bLewPihfjceH75UTWdLZH/6XN
kvj5l7a37njkJkIEW8MFLGBtPaSuax5iJauWmOPulX8wda+JmDqcvVKYVR7BJs1gPB+6z6gu437H
KezyeH+1rsLSMmUuNSHff0ADu2nujuk/CLGck35yylpXmfSvm871nvoX/Web/kUWwGiEWxgusB+E
vhv8OYMkGhtFTMu6flXSKQ6KQ7DMuWofcFAStaFr6DdQqMSanUluNz/1o8lSTcek71m2XpBq0UUO
QgoYtL5GUzUSSseP2wP8r41/qbTci2wKAkjmhCtLYaw5U8j/hp2mf/Z3ONRqFWqt1l6X/28b3isx
lrvXyJs1m1ryTT9X0bpIyFtNuVVDgBfh5uzEM2a2yfYVX1LCpf9k3zorvSqM1uyP7uPp6Xm3e5K/
5f7rf/w/mZLnIUXxTQvJcgk32aP/uv/glP7r/iPNvf/e/6xvbmV6Lq87n8797unt3bl3+/P5/f3l
2XnXO+iHqDPKjj5s78P/r/r3L569c6hDUhfAGRGYxZH7muamw081ZsjzgjBsLmO6lGv4OmNg6DNR
WX5mAQZLtSC7Actv6+e/dNj/yv+UVY4/ds/vnf3xX//j/9484EbD+4cYKjSXlxOYkT9KCZEf4cuG
8uFVW/RMrgWrhtnzeoBch9XMdfh/S5VDz+mduWVOPPqXx/vLhz/9JZM4yA8/4VKmUtp6BJZadilb
/bNR86akPCqEjFaWqwIBMMfu4hRRHcZGATEfPsPMYsHuKzQKlDMaboLe/pMUQKqpYpjhMfiSYO3w
r2vT19+zwPxrpp1bimfp6Q+pQ/0hWrn9MEzrEqD9Rn9ezGLJXSNrw6qmPBtuQklK6uHQZjGAIMmt
tk5vkSFG2sB6zoql1Hvn6mfOJrlURZW/7RrWphlOTMTbwoTenF0BwAwX+tbQAj7rq+WtEayMGAnT
/L5pU8NgLi2enpks+lT4TmaBOK2fg9i0RhcHynl4N9KQ1iIuS+R66Gsvh2wYPidkRzFGzYHh+GCj
Q2tM9dSRLgLxMIBLxbormC+S58EadRmhYbqYvUQgT1S9ShaT3TKphTla+m3vkX2SXgfF/cjgjwfR
OOJl56XBfP8e+5vJ2II4fYUdtTBMtFyGnKt3sT5Co5EaM0pYZdKxANceBlovDJuPFcoskloUPidE
M/+2ILOMrd/p81uKcJH/S+eGP/+Twz2CnyXgBOxKshgPxWWCcbGaGtip+SHHETlf0BYc8/vlm85D
q8HHankbbuZoczeiwgLPLrudj1ekbEK4T2dKn20WiyWMxOYZoKIvXZ6el7sPjzd5XGRRKayUtUl+
m/GRKyc3D7f/hkI8soHSdDFR/smlgeyJ1mP1SegeaeZPx4w7+hzSGfMOzk8/H/LQQnkg9bo3l3BZ
zERzlYKWkvJvMWnRfMuMhoNncZWtouQ2vAFFtd7b8h4GIBQ6de/5rU8n2vtjrdmsHl9f/f78+qjV
9gYyKNTPEhIa2alSHYG5n1lVBGKEnSaIIxa+vPXDWeEnTzAwc++m280o5EYR9MyLy7uuV6vUvesr
nz4FGUc2m8h3lsfn6kH2jE/Zyu44fErmcth8W3Z7o0REIrICf6RbucGbClymYFaR9vUbe0zgZio6
ewhLaT2L6zQMw8EodcdldYHTgRmvpk3MLkHWs6dLH4bnJgCdV9QP2bcRRLOnYIqkGvrp6W1lfHA1
xyTqpdJFl3/c4Pf7Lqb7fRrYQr3Ps+s6ijXGjFZBawu43EGcoLYsyiEsOYIR2oZzL7AJfXwBqw+a
Los5WDssNkQRm+xqQ61nmH8ZjoSXTnKQ6GigMXwsDRVHZwBt4RLXLQiHqS8nWZU2vga4CCvKMvGA
0Bq8XGClxSAXMcPs0C6P1NqeqZTvEtxJQWsvg/mUfe70akG88PKaBCiBKAWMNLuLk9fYpFM5V6rZ
eT/Z8vD4ltM19V+ZyxZ69qvwK34x0tHkHeJsmCssr8c9dD5eXuUVOQa3Zo4KgB0x1wYv6uAtix7P
i2XEZ7Qlns+VVkeXcaMKEBYnSF1+ck8qtwtH5k1DXDVL+F/YnsD1b5HzwFRgpU0Bu5A2jaiRiJEb
FIbUYcXangbxC3RLVoWeEUCiOcX08Fz2EYUV1c6C7BdxBOwbo4KT+G0CZyQgOXEELhkM2WLuMToW
bFLna+gd5ClCD08ECHDa7Yr/Lz0FaKs7QA3lE6Grof1EnyKd4Et5jNxnXmgFEPyue0aSAukIjw+n
J/Iksu3+Dv5Z1530cCov3EO9kDIN3ejvob7ilDqWx24Mzu1HfcKkawvLAQ34gI8w4gWioYvbRSqv
02RdRfHi66E09vvwjb2E53zba4Nf9JfeOHijHStPdh3M6H8kyeRE8vatSQhgqadFM3RmO7RVfz4/
8S6Qd+0U4C3SYRlGyangrYs0UyheUDT8S4YCsqjr/443BOt/tCmQV6na1udffAfYWRR65zM2OEgF
YRyn1Oagn9DG3aOWXF0W3tsKla+XwHvn2n3LS3kU9js6eXJtpUV/7SYs+rk9VvSXdlDRt3vlTvGX
zq9ugeB0fn40mT1F/zPpKc6P9pHOdPqzIEuLfn7nFP3l/VEwZo5lDOfwCESJHWZe1TTxV1Y1Z5pn
yS8gtqjvbyJn3DCj8pYFym+4F7kG1m1sIAO9l5omqqadeKiFfyF/uGou3bbPpGrNhdoBeR1PMWso
ERtQXZN2065W1Zw1FogINmPqYuwYnPzWiFcV0TamgvqtND3DZFY2CNDsgCgrIb2upYQRUaM18JBu
OFlMEHvuL5565s0esKOkry1QfxuBtcOl+VypZ50zWO+vy79EMOjj8IRLIUSDaM6aIoavuVAgy55F
4RwVggcw8lHL4/rOhgpL+UhjzQMiiMMteOxSgtfXbrnUwKZ9REMAxkBVZuONYooxHTur7q9YJVIJ
wuFP3go7uXgPSEphHTNT0zgT2IjhjBlmzjexTbGsWM2eBpxNJwCYmffOM/ORocDYjRKIVsM3Wmiv
+2Q0Ek84qu3EGqdHKFQBia/PidR0xmhIJ4P7HO50dofESTS06KjhbKL76K9eMOIgLfWbj4s88RMP
4TkcT8FOOYVSbh0GYEEMXzkej7tSCFlAW8v5Q8bsFoPaF4Pad6zc9bbZeg74lceeJlNfNWyFEa1C
BNe+9KoTPRhO9v2O+wpfTD7X/YwWE18+vTEWAxDM5ZlP98vZ+ent2flfTjyTSeD9DNi41xkMwnEo
+XiY0yXLw1gNdHq5MEPq+KeetSWfAeg86TCmQ+NkEs7NlBaeubaDucZ0lUvGmjXeRUhSIVjRunMl
yS7pih2XO9dn3s8dH0mh2Mypo4z/5PQMF6Rlci7aN2ZJn/csd46LvfqcZfbmczRC2BfdpMK8hEQR
QTYEGMHqDeGxnBnl6yzRwmdz76+ycvnpIYOShAh0UZ4WVd6HfyWpwqcCNCfIMhRIG63yXz2rMJqZ
OpGiLJwebEaX3UFFc/IVDyBfYIFu1qDkdZPRnFff8QuK8Zv5DY1P6v7sDM3xaJCONwTm11JjWJOV
WQa/hOJ9zPxYPF56jn0G6z24j91Vzb87STDG7gAcSpADuF0cnyFJlVStt5yvkMw9aOPKZ2u9jdoq
B/zLHsrCk4XFeKcTp1W3ygFGjms0zqMFpgqeM+gDzoESxrAlr6CBceG+UGiXxfuuNYCub//j8uqq
43UuqYunV7ePZz68SNTdy+uPj13vIyC0rnGk/bq8cylEDozWcQpif24B2sZFwMmY153uHx7Pixz6
q787lErSDv+LF02nPltDUI/+3cQdB4jYLcbjVEtEACzq8bbTgGiGz0CL//V//l88GalhyqfTjlwC
fllT2IpWPcJvI8mYSPk2ymVo/LjBU+zZSqMre4CuJV/YHDwpY47RNsvVRov+/1gx9Sjwwz77dNH3
58nTE0TNgdungi2ZKmsKLdh7x5RvZBr7vKZFU/rGZl4CfVT1Hi8PxY81AS3QzFu5sIWJ4Mmw9LDt
TnrRTHys0ohxL6BubACuE+opO8Pe2xgs5IxVXAJuiqxUKXuSLlL2XdEy2I1tSj+RUrqA88EugoGv
0YU+tcfF7DDakadGHQjUvegQkvMC0CTgFOh4ITsU08VeOyP8o9iFAJXWnT2Lk4tKJmn3RxxIFnVy
CQQ57FtpYtN6mXQJU8Nhkdy1ZQMsRlAa7UHwXfaztjHj58EanTiXivE5upMyTIzQfZ1BaVOPRzji
sAMkPQOU5oxVELe41DeysD36/Bf4o1j3cQIhdnUZQqbueOwWXJf8bmaxZlPIgU/BPLD+x4og9akP
nwKUIjCq+/OgLzgddA6Vid/UuvRAo6Mlz/WWHjwn0SBc2RnVRvudV3CmogD82TSAL//AyX5ynhCh
w4kRwh1PfwvjZyRXClTG7CE5lLDgh2t3hSsj9FMS7KVNUNDdUvCwoVPdsW6ztzca3cBrnasrs65m
f+n5WOqcd5AFAoDysOeHjCmU9wB71pT24Vs4l3He0RfNM3opwiFIDV2Efa9WqbUOT6QiiRytgnoc
Crg27CjycvCHdFXm2bVnb7Y7Xs7QBw9G9NUdIxnVEWkkC0bMyMrY1T3lEso30aS/SD0H5BfGuI35
X3EdQ92nGSp/9FRvmvFq0/UBneWCzFypfLgUceBmS2pDXNpswzXIIzqL2LUleWXNg4hzAZuUf4BG
oH0Xh69/f3tF1+lDF5SDtGOL3npB+16yUETT4CXzwdohMkerKWhmB8sWakVxwvdiy5sNX2QswRNz
zPQZf1JiZSwe2jSN96J8jjn5BedMU29gwAjESMTSjb5X7j6DO44meUH3hgRN6Io5NdZdBthUL7eH
pYKGgh7jOKYsoxgYgeQ+mnumolZwjFF5sspq6xZN29zkdujKcpx4QTRQqpCgn4orwRTysZFOeVa9
9qNFPBCorJUOgPzjAcYzppFxixrTmfSJcCi6OgvZNVqCYWjdeFiyDR9M6X7CLWjUqAw9ym4NFXcp
m50Dfdoa1PnyBwfBct6a6gIWmfmDwQf4T0r0zhQ3pw+39zbx66CDs6N+g7sAx9ZCNeXlDMT5k/A9
fIlAyM5XrVsKhC/gcJ4eOiEmvY7SeTI12lSWK8eHFq7XGV2cyztBB29nqhSsB5w5gmQKF5vQVzvE
tfmAl70IZyG0Csvk9vh4eaYRL4h2Ke7OplPKf6NtrhgUa5bZxYKCxrpoOIV3EVw1mVroDCl3Pvn3
0TqptJYyaG3mCZnb5794D52P3l3n0znp8uedm8c7R3WXVAaumI2NelC4zyr+mt8WDnUEkuIrOAfn
Dli7s3O2yso2V443QJ4V7xxOpvM3V+JpkXAEAcyNcvCLqdta/lOyeFj0Qy7Gdh8Oh9G83JkEfwcI
JlRCIRKgXCH0LQ4mWj1Yo+wsDNmNriBaAVWbXU2H4imc/4yr8ODQCgQJiSkKSa53uyR8Vc+NcSVn
jHYjrjRh3aeHIZ3x7zgsB8xoY22a0RP0fZ1PViLm4dSr90t1CFaEWzj8bGiHKtVKSzGfg2A2M2YI
nFRj6xLzueYexxPpcMZpiNyoYTglU1bKjo2Y+3koag3D5XVtsjV5QpRcxCLqBDAvpdtpVQIzCH82
v7pmbFFw0Xlh5A4VXD9YyGP5MGSk9bJnzC2DWGmQWQyQrZIJBF1CYodKBhnY9eEec1/F7Fa3ycLK
acdjzOicsjWtcCM3a3Su4XceeO+oby8BqhEius2+ncOSdblzdJ8h+Lz7X0PkCJiwrNHLgTOhf0rz
LF8ze/KEc5W0E+o2hWFg8C+Qh9lX1G8PcBADPzA3s7fyAEPEsDmHRKl5r0HSm5Q7g8FCm3eNG/hQ
ZQlenxNGfM9Xzq6do3s+gWcsYJEajMZeETpVGhKO87PnWHtEGzxBdWxj3NmdwQuXGbFKi8dVfU3O
GQO6S3Los/u6JOAi1NRUijhRgp7CxLYXzcksHmX+op9EhXGUCOipcZqw+RIOrWRhbSq3h0z/hXM9
Soa0E2aoEZY+58oNu56BFUuEdtEriZtpMOWUEk7kWNLLZFnhq7AQC155xvf72dv+Sy13IUKDRo2F
Z1Z9T89uSt7HhJN1rAVn/YmhaCVvLLbFjgpWLDmjRYohl+0TR7CsFe95z4aKDZEacOSlPDYTZGAW
Bdq3M+aUHUjNpiwB9Y4Ui4fnxaRPZ5wz6cTyQZBZSgpp+kBo3WEkKaBzPd5fmdiIhSEwpzbgRRJX
YAiYMKI7fgJXP6FzSBboIJoNFojzQKugWbwcXUunDw7NJ4L4TbZxMPzJu6Y5sngy1vEkfYnzrx/v
L2kWXjBS5SGC1aMGGaTc8r1vDgG8dHPMRExbOS1JX6gTvZUS6uJEjJ6ex1Kk9wA0Wm5FF/YPQvPk
G/hff4Oz/aIb1isoOpFJDAp8i5917sq3THWskUSfxeGMBZi+Jum7bM+yornNGFILQ0sEd+4cvXg+
C+KUCSU2TOuWtJkstVmHsD6p+TcretX5w53ffbi/PH3wHi4/fX44v3G0KnNNOMRrhQuyeicRIJ0c
TROy8oI3yJU9Y5ubqz0a48NWTndK+uQZBj1GDPPckrGWoKaC0IC/mYnNfWM5LY426UsYC3aLHalc
S4C1FqYMU8pAX4QVmgMMC46QhTzLx4ChHZ6ojnMu6joMk9Qzt0Y2sFDrBmmVZvUnKMeIeejEJp6E
86mfjTyXfrLFI7uyl8W+zUns5QW9u7/8uXP6p7Kl+DHrymlPdmk/hgEEGMI32OYIG7KPc5QwDM4w
yfpTFvN4hEnIzO+Xdyi3tsFmcV3AwfAFRURTSS+Ea2v9Vn+Zxj0AnNbVzXIvqZ+j8NXcGP4cCZHu
F9Bt8Kog6oBSeGs/ZSKmCHmW3KYcU4TuPYglX9PF0sUTCSXZxBgF5DdZUYJVECVwe+aXvF8SYScq
Qy5VF59czyGpjOsimxSPqw67eGjOAjgo9bkoFcwT6RwMxgvUC+ngIVIr2gJEsIwQFR12HI3mioRT
aBpDmi10akAjI230I4PCxKuMRGonLu2ksZvc9IymBYBC6ekhc5ZKLjEZjgs2dNRxbHATK9xP0Ugp
/mglBlq47zWIBXF2enrXKX86u7v3lCFBJ2BTDGRN8Ct33iS/GLhkdt0aKzxdfw6R7UGStXOPPL3H
u7POw3nXu725yqHxJD5rMIIWpzWlQyaYO7nizm4ufiLBGQ4WUvUg4KIESuzzqnkMiqsDoYRBu9pA
Rs4+cYDwiCFK0gOrp1nms/ionSThfoQq8eXALYcwkxQQwxVUzmKnKhU9YQBw8n/Zu7OU9Ev2FuZc
84CY/Au5cmxYTS20k+ms1vgZtJQBIkg7obCbSihsfxxNy5xlFPHbX9ynbMMayX3bffDZw6Uy3DvI
5VY5it+qQ8z1hejzd5mi0pnT7d1fiIF4d9fJ+WTJqgiGPt+fM83Zt/rMMhaHnr0TBcNpsquGkAQW
1GiJUpcfDWrvT0YazMI5hyXZ/6P5IEHWnI09MclylObDTmTkkKgZLm+FTW1lfdhwk1yxvquJLIza
SEkNvbqhOTKAxBR2m93TM4QOMamsKYMMmvfyVedGE1A4ezzVI7Vk0RjWcTajBSQrlNzWfWyLKdIU
zoY+1xM2yksqlgh/2Ddf0gh9ybvKkj+Yb0TeNSar9BQFUMbJdCIDWQYoGHnDzlMutigBJen0ptyR
cRzsld+A50yAaL8He2bceXvhl7DfZX8fFmYGMQevm/EvoPO0fDLFZIepm8ME9TIni9qEUr/KQmQR
A58Yd0fKpTkYgfVx8eRVj49bTWj0CkBXJDaddVLbAxGd0hnzDUgzxc5jjD9xM7VKo1avH3sOzlx6
CxsrO2yNpcNXt1Fu113G8WvosNa9GM1t1NaxRQSFxMdvEXNWGzOCHbKv30AuonnOqM4slVcosUqo
keS2VJk2PqMeDXkNaTMalWBHWI6VLYuWs/uLVY2pmDAAnYWzLI+t0sSR0tICTKBn4s0MimEBY5mw
GYhNnR/O4H6/vzitHlfbXvjEGVKJ4AhMmhWScb+IiT6GoZFM2cZ3dgRJm5eIrExk16DGJ5wPfOr5
kLDLBJqEHFxG3Y2D2Be4N5D0cwEYCsZP3ZkYC7KToEVx1awSPA3i3XR4BbBy2WllEIfQ28kdf+Ae
Ef5gD+VFuBWnyIjWRBc5MU98senFkobnTHeCgkiy46QeJwultaXtVOLRvz9peZg9ZALIULnd9VlM
7saeBNM0K6D0t9dgkLoIhH+/7PZubh96nZuz+9vLs38Xejvd0srUr1Idq92JaR9ESElREZxF3Q2t
vxwLEQZlJUsWrIfs1KUk+DiM2PzLcMksUsTzEicze5T/8EvnlIO3PMUzrmcbk744S2VJEtBtAPhK
k373+0uPuVlk5a04drFxotqznD8xPmtLE3VxeX9+cfvHHs1gr9K7J4Ov0z0nQ53eHMA9fwUD/C2Y
jK23o3t3e3vhn998urrsfvbee1XvwLhkRCWwikWjWbEQkiJtmmke/cH9+lmi7Ae5l5xY8EsWzder
6p2HIK93cXF44lXo+xppECws9lORuvTe4U+t0U+2VlRuSTg/C+hoiIT7i7uiof+hs/i0UFCZZDSo
Y5UZLehhTujDYD8+PghJpLpkvXM6qlH6bOtzFsx1DRsx1eiIhB0q8L4GsyEnyWgmzYHEa3zEZosI
GPoaMMQnaUGfQjqY04Tr2IhwGEbBOHmypEPKM4Q9HHChANMhUBBx2yWZdPo8wykRFe+z95sdhDSw
n2BALQVaeC0l0MLVnar0AVDOZpHLvnG+yoSp69U95qR6jkvQNKbznplhTksah6O58WeK3iviJuRs
au8gDcUlzGJSxvArQhDrbCYE+e7uby8ur869685N59P5vTFy18D0qvX2O/TLpAcF/L5GuX04nIYW
WG1y9gQZMOVdzAuKcFb3D5yzDtuEiY5IzP33ckmi/mU9dLboi7Itep+Yj6es1UoZSXtzent913m4
pO4KyYkDO9COpCXaHF7Z+6upb+Lfef8b9NwPf9XZkzgMbtM3T+uKLNPDvQNnsKFaA+DEN8Ok5V1M
DXIW3sdKFqixzlnTEwOcYFmaIQzBcClRTB0qo24i6GFmv3LEgz3UDqBcNy89ddAPJVEKTMmaIY3c
iFhT+eT7HL4AoAbnXC5j+G/WzRdeZhcE9BxqlI+2tCv8fVB6Ds24OZIgfwZghSs9i4aUAFE0sJVf
SD36qIQwwPakvlDUpoIiEu2Lpn+JAM9duqWV+SvvBveBbKH+KkE/naIp14Xl657tDmogotV4K2Lt
rx+7Dxn77bM7jxYVvRQMPRH3paCbOIYr0yP6BTa5G/A08VtWKTJPiIZr5SZQ5Ay7RAYokZ2dplSJ
AsfQm2wEGWQy2rv7cJSySuZZB6hmZecJZZumDgwz7tFIfRqp2cyaBQA921fBEqX+CAof6+fj8Zsv
IL/8l9bVGApj/7HLlYZybZuR+VLdSEMpNofCDPc3m8IcSydpO4effVpnc8kVwF5yRfV4C7G7bkX/
MsAdJlGSRKIlo1hBQbgAlr1bHKsGUBKO8YBDnauJqHcGWWlRmawMKTJIJmsotE7IRoWPTmEl5t5a
H8y2Yj5/d4fx0E9GPoss4R8S+Bu751ImGWKXXsLKEQw7PGmAVTuJjDg1A7L46vzh/ESayyiMHPKi
/xcANVdYJocBAA==
HARDENING_GZ_B64_EOF
chmod 644 "$SHARE_DIR/user.js"

# Sanity: size + NoID Privacy parrot marker
USERJS_SIZE=$(stat -c%s "$SHARE_DIR/user.js")
if [ "$USERJS_SIZE" -lt 80000 ]; then
    log "  FAIL: noid-firefox-hardening.js decoded too small ($USERJS_SIZE bytes, expected >80KB)"
    exit 1
fi
if ! grep -q 'NOID-COMPLETE' "$SHARE_DIR/user.js"; then
    log "  FAIL: NoID Privacy parrot marker NOID-COMPLETE missing in decoded user.js"
    exit 1
fi
log "  Installed $SHARE_DIR/user.js ($USERJS_SIZE bytes, NoID Privacy parrot verified)"

# Reviewed inverse overlay for the explicit DRM/Widevine consent action.  The
# canonical profile keeps EME and GMP updates off; firefox-profiles.sh appends
# this exact block only when the profile-local versioned opt-in sentinel is
# present.  Keeping the overlay root-owned and separate makes Update-All
# re-application preserve consent without weakening fresh profiles.
cat > "$SHARE_DIR/user-drm-overrides.js" <<'DRM_OVERRIDES_EOF'

// NOID-DRM-OPT-IN-BEGIN
// Explicit proprietary DRM opt-in. Managed with `noid-firefox-drm`.
user_pref("media.eme.enabled", true);
user_pref("media.gmp-manager.updateEnabled", true);
user_pref("media.gmp-widevinecdm.enabled", true);
user_pref("media.gmp-widevinecdm.allow-chromium-update", true);
user_pref("_noid.drm.enabled", true);
// NOID-DRM-OPT-IN-END
DRM_OVERRIDES_EOF
chmod 0644 "$SHARE_DIR/user-drm-overrides.js"
chown root:root "$SHARE_DIR/user-drm-overrides.js"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$SHARE_DIR/user-drm-overrides.js" 2>/dev/null || true
fi

# Retain the exact MIT notice from the embedded arkenfox-derived source in the
# image-wide license inventory. The pinned digest is from upstream tag 144.0
# (commit bb45863be796d331717e2b5d6e490f0d3e3cf93f).
LICENSE_DIR=/usr/share/licenses/noid-privacy
ARKENFOX_LICENSE="$LICENSE_DIR/arkenfox-user.js-MIT.txt"
install -d -m 0755 "$LICENSE_DIR"
awk '/^\/\* ARKENFOX MIT NOTICE BEGIN$/ { copy=1; next }
     /^ARKENFOX MIT NOTICE END \*\/$/ { copy=0; found_end=1; next }
     copy { print }
     END { if (!found_end) exit 1 }' \
    "$SHARE_DIR/user.js" > "$ARKENFOX_LICENSE"
chmod 0644 "$ARKENFOX_LICENSE"
chown root:root "$ARKENFOX_LICENSE"
printf '%s  %s\n' \
    2bf289bdd22188ccff2bf34c9a20a75c45b84f42f887da7e177d9bfd1bac3c1a \
    "$ARKENFOX_LICENSE" | sha256sum -c -
log "  Installed exact arkenfox v144 MIT notice: $ARKENFOX_LICENSE"

# No updater.sh (eliminated — image updates via M25 noid-update-all.sh
# which re-runs kickstart-equivalent re-install). No separate user-overrides.js
# (consolidated into user.js). No merge step.

#------------------------------------------------------------------------------
# Step 3b: Install Mozilla AutoConfig (mozilla.cfg) — global pref enforcement
#------------------------------------------------------------------------------
# AutoConfig (mozilla.cfg) applies the prefs globally BEFORE profile-init —
# every current AND future profile (user.js-only delivery is fragile under
# FF150 profiles.ini/installs.ini semantics). Two files: the autoconfig.js
# pointer (obscure_value=0, sandbox enabled) + mozilla.cfg generated from
# user.js via user_pref->defaultPref sed; FIRST LINE of mozilla.cfg must be
# a comment (parser skips L1). defaultPref keeps user overrides possible —
# only the targeted kill-switches below use lockPref.
log "Step 3b/8: Install Mozilla AutoConfig (global pref enforcement)"

FIREFOX_LIB_DIR=/usr/lib64/firefox
AUTOCONFIG_PREF_DIR="${FIREFOX_LIB_DIR}/defaults/pref"

if [ ! -d "$FIREFOX_LIB_DIR" ]; then
    log "  FAIL: Firefox lib directory $FIREFOX_LIB_DIR missing"
    exit 1
fi

mkdir -p "$AUTOCONFIG_PREF_DIR"

# 3b.1 — autoconfig.js pointer (registers mozilla.cfg)
cat > "${AUTOCONFIG_PREF_DIR}/autoconfig.js" <<'AUTOCONFIG_EOF'
// NoID Privacy Workstation 44 — AutoConfig pointer (Module 16)
// Tells Firefox to load /usr/lib64/firefox/mozilla.cfg at startup,
// before any profile is initialized. Applies globally to all profiles.
//
// sandbox_enabled = true: NoID Privacy's mozilla.cfg uses only pref() /
// defaultPref() / lockPref() — all prefcalls.js-API functions that work
// in sandbox-enabled mode. Sandbox-enabled reduces blast-radius if
// mozilla.cfg is ever tampered with (no Components / Services / Cu.import /
// eval reachable from sandboxed code). Mozilla's long-term direction
// (Bug 1455601, Bug 1514451) is to remove the sandbox-disable option
// from release channels — NoID Privacy anticipates this.
// Cross-ref: M35 thunderbird.ks autoconfig pointer mirror.
pref("general.config.filename", "mozilla.cfg");
pref("general.config.obscure_value", 0);
pref("general.config.sandbox_enabled", true);
AUTOCONFIG_EOF
chmod 644 "${AUTOCONFIG_PREF_DIR}/autoconfig.js"
log "  Installed ${AUTOCONFIG_PREF_DIR}/autoconfig.js"

# 3b.2 — mozilla.cfg generated from user.js
# First line must be a comment (Mozilla parser skips L1 unconditionally).
# Convert user_pref( -> defaultPref( for AutoConfig syntax. Comments and
# block comments /* ... */ are valid JS, no further conversion needed.
{
    echo "// NoID Privacy Workstation 44 — Firefox AutoConfig (Module 16)"
    echo "// Source of truth: firefox/noid-firefox-hardening.js (sed-derived)"
    echo "// Generated at build time. To regenerate: re-run kickstart M16."
    echo "//"
    sed 's/^user_pref(/defaultPref(/g' "$SHARE_DIR/user.js"
} > "${FIREFOX_LIB_DIR}/mozilla.cfg"
chmod 644 "${FIREFOX_LIB_DIR}/mozilla.cfg"

# Sanity: defaultPref count must roughly match user_pref count in source
# minimal pattern (`2>/dev/null || true; ${var:-0}`)
# replaces broken `|| echo 0` (would produce multi-line "0\n0" on zero matches,
# breaking subsequent -ne arithmetic). Never fires in practice (files always
# have content) but pattern-consistency with M03/M11/M12/M14/M17 (reference).
SRC_USER_PREF_COUNT=$(grep -c '^user_pref(' "$SHARE_DIR/user.js" 2>/dev/null || true)
SRC_USER_PREF_COUNT=${SRC_USER_PREF_COUNT:-0}
CFG_DEFAULT_PREF_COUNT=$(grep -c '^defaultPref(' "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
CFG_DEFAULT_PREF_COUNT=${CFG_DEFAULT_PREF_COUNT:-0}
if [ "$SRC_USER_PREF_COUNT" != "$CFG_DEFAULT_PREF_COUNT" ]; then
    log "  FAIL: mozilla.cfg conversion mismatch (user_pref=$SRC_USER_PREF_COUNT, defaultPref=$CFG_DEFAULT_PREF_COUNT)"
    exit 1
fi
if ! head -1 "${FIREFOX_LIB_DIR}/mozilla.cfg" | grep -q '^//'; then
    log "  FAIL: mozilla.cfg first line is not a comment (Mozilla parser will swallow first pref)"
    exit 1
fi
log "  Installed ${FIREFOX_LIB_DIR}/mozilla.cfg ($CFG_DEFAULT_PREF_COUNT defaultPref entries)"

# 3b.3 — Append user-overridable application defaults + narrow lockPref entries.
# Firefox Secure DNS is off by image default so the OS resolver can honor the
# active VPN/private-link DNS scope. Keep this out of profile user.js: a user
# who deliberately enables Firefox Secure DNS must survive every restart and
# the M25 Update All profile reconciliation. The URI/provider remains entirely
# user-selected instead of retaining a stale bootstrap address.
#
# The same ownership rule applies to user-facing browser state whose documented
# contract promises a later Settings/about:config choice: startup/home,
# current-session closed-tab recovery, Home content, AI controls, Firefox IP
# Protection, Sync selection, GPC, private search, ETP convenience compatibility
# and hardware/accessibility preferences. They remain secure image defaults but
# never live in profile user.js.
#
# The toolbar state is application data, not a hardening control. Seed it only
# as a default so uBlock Origin is visible on the first launch while Firefox's
# prefs.js user value remains authoritative after any toolbar customization.
# Schema 24 matches the reviewed Fedora 44 Firefox CustomizableUI kVersion and
# includes its standard reset-pbm button migration.
USER_OWNED_DEFAULT_PREFS=(
    # Startup, search and compatibility/performance choices.
    'defaultPref("browser.startup.page", 1);'
    'defaultPref("browser.startup.homepage", "about:home");'
    'defaultPref("browser.newtabpage.enabled", true);'
    'defaultPref("browser.sessionstore.persist_closed_tabs_between_sessions", false);'
    'defaultPref("browser.search.separatePrivateDefault", true);'
    'defaultPref("browser.search.separatePrivateDefault.ui.enabled", true);'
    'defaultPref("general.smoothScroll", true);'
    'defaultPref("privacy.trackingprotection.allow_list.convenience.enabled", false);'
    'defaultPref("privacy.globalprivacycontrol.enabled", false);'

    # Account data stays local by default, but Firefox owns later Sync choices.
    'defaultPref("services.sync.engine.passwords", false);'
    'defaultPref("services.sync.engine.tabs", false);'

    # Optional Mozilla VPN/IP Protection starts inert without becoming a lock.
    'defaultPref("browser.ipProtection.enabled", false);'
    'defaultPref("browser.ipProtection.locationListCache", "");'
    'defaultPref("browser.ipProtection.userEnabled", false);'
    'defaultPref("browser.ipProtection.autoStartEnabled", false);'
    'defaultPref("browser.ipProtection.autoStartPrivateEnabled", false);'

    # Firefox AI Controls: block by default, preserve an explicit later choice.
    'defaultPref("extensions.ml.enabled", false);'
    'defaultPref("browser.ml.chat.enabled", false);'
    'defaultPref("browser.ml.chat.shortcuts", false);'
    'defaultPref("browser.ml.chat.sidebar", false);'
    'defaultPref("browser.tabs.groups.smart.enabled", false);'
    'defaultPref("browser.tabs.groups.smart.userEnabled", false);'
    'defaultPref("browser.ai.control.default", "blocked");'
    'defaultPref("browser.ai.control.sidebarChatbot", "blocked");'
    'defaultPref("browser.ai.control.linkPreviewKeyPoints", "blocked");'
    'defaultPref("browser.ai.control.smartTabGroups", "blocked");'
    'defaultPref("browser.ai.control.translations", "blocked");'
    'defaultPref("browser.ai.control.pdfjsAltText", "blocked");'
    'defaultPref("browser.ai.control.smartWindow", "blocked");'
    'defaultPref("sidebar.main.tools", "syncedtabs,history,bookmarks");'
    'defaultPref("sidebar.notification.badge.aichat", false);'

    # Firefox Home: local, quiet defaults. Visible controls and advanced
    # about:config feature gates remain owned by prefs.js after a user change.
    'defaultPref("browser.newtabpage.activity-stream.showSponsored", false);'
    'defaultPref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);'
    'defaultPref("browser.newtabpage.activity-stream.showSponsoredCheckboxes", false);'
    'defaultPref("browser.newtabpage.activity-stream.feeds.section.topstories", false);'
    'defaultPref("browser.newtabpage.activity-stream.feeds.topsites", true);'
    'defaultPref("browser.newtabpage.activity-stream.feeds.section.highlights", false);'
    'defaultPref("browser.newtabpage.activity-stream.feeds.weatherfeed", false);'
    'defaultPref("browser.newtabpage.activity-stream.showWeather", false);'
    'defaultPref("browser.newtabpage.activity-stream.system.showWeather", false);'
    'defaultPref("browser.newtabpage.activity-stream.widgets.weather.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.widgets.weatherForecast.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.widgets.system.weather.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.widgets.system.weatherForecast.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.weather.locationSearchEnabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.nova.enabled", false);'
    'defaultPref("browser.urlbar.weather.featureGate", false);'
    'defaultPref("browser.urlbar.suggest.weather", false);'
    # Keep the DoH chooser usable without reviving Firefox's country lookup.
    # `global` selects only Mozilla's provider-neutral fallback catalogue; it
    # neither enables DoH nor selects a provider while network.trr.mode=5.
    'defaultPref("doh-rollout.home-region", "global");'
    'defaultPref("browser.region.network.url", "");'
    'defaultPref("browser.region.network.scan", false);'
    'defaultPref("browser.region.update.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.newtabWallpapers.enabled", false);'
    'defaultPref("browser.newtabpage.activity-stream.newtabWallpapers.user.enabled", false);'
)
TOOLBAR_DEFAULT_PREF='defaultPref("browser.uiCustomization.state", "{\"placements\":{\"widget-overflow-fixed-list\":[],\"unified-extensions-area\":[],\"nav-bar\":[\"back-button\",\"forward-button\",\"stop-reload-button\",\"customizableui-special-spring1\",\"vertical-spacer\",\"urlbar-container\",\"customizableui-special-spring2\",\"downloads-button\",\"fxa-toolbar-menu-button\",\"unified-extensions-button\",\"ublock0_raymondhill_net-browser-action\",\"reset-pbm-toolbar-button\"],\"toolbar-menubar\":[\"menubar-items\"],\"TabsToolbar\":[\"firefox-view-button\",\"tabbrowser-tabs\",\"new-tab-button\",\"alltabs-button\"],\"vertical-tabs\":[],\"PersonalToolbar\":[\"personal-bookmarks\"]},\"seen\":[\"developer-button\",\"screenshot-button\",\"ublock0_raymondhill_net-browser-action\",\"reset-pbm-toolbar-button\"],\"dirtyAreaCache\":[\"nav-bar\",\"vertical-tabs\",\"toolbar-menubar\",\"TabsToolbar\",\"PersonalToolbar\",\"unified-extensions-area\"],\"currentVersion\":24,\"newElementCount\":2}");'
{
    echo ""
    echo "// NoID Privacy — provider-neutral, user-overridable DNS default"
    echo "// Firefox Secure DNS is off; NetworkManager/systemd-resolved owns"
    echo "// VPN/private split DNS and the direct-WAN Quad9 resolver path."
    echo 'defaultPref("network.trr.mode", 5);'
    echo ""
    echo "// NoID Privacy — secure user-facing defaults (all user-overridable)"
    printf '%s\n' "${USER_OWNED_DEFAULT_PREFS[@]}"
    echo ""
    echo "// NoID Privacy — initial uBO toolbar placement (user-overridable)"
    echo "// A prefs.js user value overrides this default after customization."
    printf '%s\n' "$TOOLBAR_DEFAULT_PREF"
} >> "${FIREFOX_LIB_DIR}/mozilla.cfg"

for expected_user_default in "${USER_OWNED_DEFAULT_PREFS[@]}"; do
    expected_user_default_count=$(grep -Fxc -- "$expected_user_default" \
        "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
    expected_user_default_count=${expected_user_default_count:-0}
    if [ "$expected_user_default_count" -ne 1 ]; then
        log "  FAIL: mozilla.cfg requires exactly one user-owned default: $expected_user_default"
        exit 1
    fi
done
log "  Appended ${#USER_OWNED_DEFAULT_PREFS[@]} secure user-overridable application defaults"

# Append lockPref() entries for FF150 new-profile-manager kill-switch.
# FF150 fix: the default browser.profiles.enabled=true
# triggers an empty Profile Picker dialog when users click `firefox -P
# default-release` launcher (the new toolbar-based profile manager is a
# parallel system that ignores legacy profiles.ini and shows empty list).
#
# user.js sets this to false per-profile, but new user-created profiles
# inherit Firefox defaults until first launch. lockPref enforces system-
# wide BEFORE any profile init, covering edge case: user creates profile
# via about:profiles or manual `firefox -P newprofile`. Cannot be unset
# via UI or about:config (lockPref is hard-locked).
{
    echo ""
    echo "// ============================================================"
    echo "// NoID Privacy — FF150 new profile manager kill-switch"
    echo "// lockPref overrides any user attempt to re-enable via UI."
    echo "// Why locked (not just default): without this, FF150 picker"
    echo "// dialog appears even with profiles.ini Default=1 set."
    echo "// ============================================================"
    echo 'lockPref("browser.profiles.enabled", false);'
    echo 'lockPref("browser.profiles.created", false);'
    echo ""
    echo "// ============================================================"
    echo "// NoID Privacy — Mozilla regional default top sites kill-switch"
    echo "// ============================================================"
    echo "// Mozilla's ActivityStream.sys.mjs has a getValue() function in"
    echo "// PREFS_CONFIG that dynamically generates locale-specific default"
    echo "// top-site URLs (Wikipedia, YouTube, Reddit, Amazon per locale)"
    echo "// at runtime, OVERRIDING any user_pref(default.sites, \"\") set in"
    echo "// user.js. The only Mozilla-supported way to defeat this dynamic"
    echo "// override on Rapid Release Firefox is lockPref() in AutoConfig —"
    echo "// it forces the value regardless of getValue(). tested on"
    echo "// ISO VM validation: with this lockPref, Wikipedia/YouTube/"
    echo "// Amazon/Reddit no longer appear in the new-tab Top Sites grid."
    echo 'lockPref("browser.newtabpage.activity-stream.default.sites", "");'
    echo ""
    echo "// ============================================================"
    echo "// NoID Privacy — block Mozilla search-engine shortcut auto-pin"
    echo "// ============================================================"
    echo "// SEPARATE Mozilla mechanism from regional default.sites (above):"
    echo "// TopSitesFeed.sys.mjs::_maybeInsertSearchShortcuts() reads"
    echo "// browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts"
    echo "// (default=true) and pins CUSTOM_SEARCH_SHORTCUTS = [@google,"
    echo "// @amazon, @baidu, @ecosia] into free Top-Sites slots automatically."
    echo "// default.sites=\"\" lockPref above does NOT block this — different"
    echo "// code path. Discovered during deployment validation (Google appeared"
    echo "// in fresh VM despite default.sites lockPref). Source verified via"
    echo "// firefox/components/newtab/lib/TopSitesFeed.sys.mjs."
    echo "//"
    echo "// Fix: lockPref both the master toggle + havePinned cache string."
    echo 'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts", false);'
    echo 'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "");'
    echo ""
    echo "// ============================================================"
    echo "// NoID Privacy — initial pinned tiles + grid layout (defaultPref)"
    echo "// ============================================================"
    echo "// 8 NoID Privacy-curated tiles pre-pin the new-tab Top Sites grid out-of-"
    echo "// the-box: NoID Privacy / DuckDuckGo / Duck.ai / Proton Mail /"
    echo "// Signal / Mullvad VPN / Tor Project / Privacy Guides discuss."
    echo "//"
    echo "// CRITICAL: defaultPref (NOT user_pref in user.js, NOT lockPref)."
    echo "// user_pref re-applies every Firefox start and would WIPE user-"
    echo "// added shortcuts (live-confirmed: user-added Google"
    echo "// tile vanished after restart with user_pref). lockPref would"
    echo "// fully prevent customization. defaultPref sets the initial value"
    echo "// only when prefs.js has no user-set value yet — so user-added/"
    echo "// removed tiles in subsequent sessions are persisted in prefs.js"
    echo "// and override the default."
    echo "//"
    echo "// topSitesRows=4 matches host-Firefox UX (4-row grid = 24-32 slots"
    echo "// depending on window width; user can shrink via Settings > Home)."
    echo 'defaultPref("browser.newtabpage.activity-stream.topSitesRows", 4);'
} >> "${FIREFOX_LIB_DIR}/mozilla.cfg"

# Emit eight fully local, distinct monogram favicons. Current Firefox accepts the
# pinned-link favicon/faviconSize fields directly; a >=96 px declared icon
# prevents TopSitesFeed from entering its rich-icon/screenshot fallback. The
# canonical capture kill-switch remains the independent backstop.
python3 - "${FIREFOX_LIB_DIR}/mozilla.cfg" <<'PINNED_SITES_PYEOF'
import json
import sys
from urllib.parse import quote

sites = [
    ("https://noid-privacy.com/linux.html", "NoID Privacy", "N", "#5b4bdb", "#ffffff"),
    ("https://duckduckgo.com/", "DuckDuckGo", "D", "#de5833", "#ffffff"),
    ("https://duck.ai/", "Duck.ai", "AI", "#7a5cff", "#ffffff"),
    ("https://proton.me/mail", "Proton Mail", "P", "#6d4aff", "#ffffff"),
    ("https://signal.org/", "Signal", "S", "#3a76f0", "#ffffff"),
    ("https://mullvad.net/en", "Mullvad VPN", "M", "#ffcc00", "#111111"),
    ("https://www.torproject.org/download/", "Tor Project", "T", "#7d4698", "#ffffff"),
    ("https://discuss.privacyguides.net/", "Privacy Guides", "PG", "#246b5a", "#ffffff"),
]
pins = []
for url, title, label, background, foreground in sites:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96">'
        f'<rect width="96" height="96" rx="20" fill="{background}"/>'
        '<text x="48" y="61" text-anchor="middle" font-family="sans-serif" '
        f'font-size="36" font-weight="700" fill="{foreground}">{label}</text>'
        '</svg>'
    )
    pins.append({
        "url": url,
        "title": title,
        "favicon": "data:image/svg+xml," + quote(svg, safe=""),
        "faviconSize": 96,
    })

with open(sys.argv[1], "a", encoding="utf-8") as handle:
    handle.write(
        'defaultPref("browser.newtabpage.pinned", '
        + json.dumps(json.dumps(pins, separators=(",", ":")))
        + ');\n'
    )
PINNED_SITES_PYEOF

# Verify the complete lockPref identity set, not merely an aggregate count.
# An exact count alone could accept five duplicated or unrelated preferences.
EXPECTED_LOCK_PREFS=(
    'lockPref("browser.profiles.enabled", false);'
    'lockPref("browser.profiles.created", false);'
    'lockPref("browser.newtabpage.activity-stream.default.sites", "");'
    'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts", false);'
    'lockPref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "");'
)
for expected_lock_pref in "${EXPECTED_LOCK_PREFS[@]}"; do
    expected_lock_pref_count=$(grep -Fxc -- "$expected_lock_pref" "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
    expected_lock_pref_count=${expected_lock_pref_count:-0}
    if [ "$expected_lock_pref_count" -ne 1 ]; then
        log "  FAIL: mozilla.cfg requires exactly one: $expected_lock_pref"
        exit 1
    fi
done
LOCK_PREF_COUNT=$(grep -c '^lockPref(' "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
LOCK_PREF_COUNT=${LOCK_PREF_COUNT:-0}
if [ "$LOCK_PREF_COUNT" -ne "${#EXPECTED_LOCK_PREFS[@]}" ]; then
    log "  FAIL: mozilla.cfg lockPref set contains unexpected entries — expected ${#EXPECTED_LOCK_PREFS[@]}, got $LOCK_PREF_COUNT"
    exit 1
fi
DEFAULT_PINNED_COUNT=$(grep -c 'defaultPref("browser.newtabpage.pinned"' "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
DEFAULT_PINNED_COUNT=${DEFAULT_PINNED_COUNT:-0}
if [ "$DEFAULT_PINNED_COUNT" -ne 1 ]; then
    log "  FAIL: mozilla.cfg requires exactly one pinned defaultPref"
    exit 1
fi
TOOLBAR_DEFAULT_COUNT=$(grep -Fxc -- "$TOOLBAR_DEFAULT_PREF" \
    "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)
TOOLBAR_DEFAULT_COUNT=${TOOLBAR_DEFAULT_COUNT:-0}
if [ "$TOOLBAR_DEFAULT_COUNT" -ne 1 ]; then
    log "  FAIL: mozilla.cfg requires exactly one reviewed toolbar defaultPref"
    exit 1
fi
if [ "$(grep -Fxc 'defaultPref("network.trr.mode", 5);' \
        "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)" -ne 1 ] || \
   [ "$(grep -Fxc 'defaultPref("doh-rollout.home-region", "global");' \
        "${FIREFOX_LIB_DIR}/mozilla.cfg" 2>/dev/null || true)" -ne 1 ] || \
   grep -Eq '^defaultPref\("network\.trr\.(uri|custom_uri|bootstrapAddr)"' \
        "${FIREFOX_LIB_DIR}/mozilla.cfg"; then
    log "  FAIL: Firefox DNS default/chooser must remain user-overridable without a forced DoH provider"
    exit 1
fi
if ! python3 - "${FIREFOX_LIB_DIR}/mozilla.cfg" <<'PINNED_VALIDATE_PYEOF'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    lines = [line.rstrip("\n") for line in handle]
matches = [line for line in lines if line.startswith(
    'defaultPref("browser.newtabpage.pinned", ')]
assert len(matches) == 1
match = re.fullmatch(
    r'defaultPref\("browser\.newtabpage\.pinned", ("(?:\\.|[^"\\])*")\);',
    matches[0],
)
assert match
pins = json.loads(json.loads(match.group(1)))
assert len(pins) == 8
assert len({pin["url"] for pin in pins}) == 8
assert pins[0]["url"] == "https://noid-privacy.com/linux.html"
assert all(set(pin) == {"url", "title", "favicon", "faviconSize"} for pin in pins)
assert all(pin["favicon"].startswith("data:image/svg+xml,%3Csvg") for pin in pins)
assert all(pin["faviconSize"] == 96 for pin in pins)

toolbar_matches = [line for line in lines if line.startswith(
    'defaultPref("browser.uiCustomization.state", ')]
assert len(toolbar_matches) == 1
toolbar_match = re.fullmatch(
    r'defaultPref\("browser\.uiCustomization\.state", ("(?:\\.|[^"\\])*")\);',
    toolbar_matches[0],
)
assert toolbar_match
toolbar = json.loads(json.loads(toolbar_match.group(1)))
assert set(toolbar) == {
    "placements", "seen", "dirtyAreaCache", "currentVersion", "newElementCount",
}
assert toolbar["currentVersion"] == 24
nav_bar = toolbar["placements"]["nav-bar"]
assert nav_bar.count("ublock0_raymondhill_net-browser-action") == 1
assert nav_bar.count("reset-pbm-toolbar-button") == 1
assert toolbar["placements"]["unified-extensions-area"] == []
PINNED_VALIDATE_PYEOF
then
    log "  FAIL: pinned-tile or initial-toolbar defaults differ"
    exit 1
fi
log "  Appended $LOCK_PREF_COUNT lockPref entries (profiles + topsites default-blocker)"
log "  Appended pinned, toolbar + topSitesRows defaults (user-customizable)"

#------------------------------------------------------------------------------
# Step 3c: System-locale flow-through (parity with M35 Thunderbird)
#------------------------------------------------------------------------------
# OS-locale flow-through: empty intl.locale.requested + autoDisableScopes=10
# lets the matching RPM langpack auto-enable. MUST live in a system-pref
# file (read BEFORE autoconfig.cfg) — rationale + refs in the deployed
# NOID_LOCALE_JS_EOF heredoc. Pairs with Step 3d langpack activation.

log "Step 3c/8: Installing /usr/lib64/firefox/defaults/pref/noid-locale.js (locale flow-through)"

cat > "${AUTOCONFIG_PREF_DIR}/noid-locale.js" <<'NOID_LOCALE_JS_EOF'
// NoID Privacy Workstation 44 — system-locale flow-through (defense-in-depth)
// Empty intl.locale.requested triggers Firefox to read $LANG via libc setlocale.
// Reference: Mozilla Bug 1423532 + Debian Bug #997841.
// MUST be in system-pref-file (NOT user.js or mozilla.cfg) — Firefox Init-timing
// reads system-prefs BEFORE autoconfig.cfg, so empty here lets locale-init
// fall back to OS locale via gnu_get_libc_version() / setlocale().
// No JS, no sandbox-bypass, no env-var access from JS context.
// Paired with extensions.autoDisableScopes=10 in user.js (Mozilla langpacks
// at location=app-global auto-enable, allowing fr_FR → langpack-firefox-fr
// to activate matching OS-locale).
pref("intl.locale.requested", "");
pref("intl.regional_prefs.use_os_locales", true);
NOID_LOCALE_JS_EOF
chmod 644 "${AUTOCONFIG_PREF_DIR}/noid-locale.js"
chown root:root "${AUTOCONFIG_PREF_DIR}/noid-locale.js"

if ! grep -q '^pref("intl.locale.requested", "");$' "${AUTOCONFIG_PREF_DIR}/noid-locale.js"; then
    log "  FAIL: noid-locale.js missing intl.locale.requested pref"
    exit 1
fi
log "  Installed ${AUTOCONFIG_PREF_DIR}/noid-locale.js (2 prefs: intl.locale.requested + use_os_locales)"

#------------------------------------------------------------------------------
# Step 3d: Activate Firefox langpacks via distribution/extensions/
#------------------------------------------------------------------------------
# The firefox-langpacks RPM path (/usr/lib64/firefox/langpacks/) is NOT
# scanned since FF91 — the XPIs sit inert. Copying them to
# /usr/lib64/firefox/distribution/extensions makes Firefox distribution-
# install them per profile (locale-type addons ARE distribution-installed,
# UNLIKE regular WebExtensions — empirically verified, see Step 4). Without
# this, the Step-3c locale flow-through has no langpack to activate and the
# UI stays en-US.
log "Step 3d/8: Activate Firefox langpacks (distribution/extensions/)"

FIREFOX_LANGPACK_SRC="${FIREFOX_LIB_DIR}/langpacks"
FIREFOX_DIST_EXT="${FIREFOX_LIB_DIR}/distribution/extensions"

if [ ! -d "$FIREFOX_LANGPACK_SRC" ]; then
    log "  FAIL: $FIREFOX_LANGPACK_SRC missing — firefox-langpacks not installed (check master.ks %packages)"
    exit 1
fi

mkdir -p "$FIREFOX_DIST_EXT"
chmod 0755 "${FIREFOX_LIB_DIR}/distribution" "$FIREFOX_DIST_EXT"

_lp_count=0
for _lp in "$FIREFOX_LANGPACK_SRC"/langpack-*.xpi; do
    [ -f "$_lp" ] || continue
    install -m 0644 "$_lp" "$FIREFOX_DIST_EXT/"
    _lp_count=$((_lp_count + 1))
done

# SELinux context for the new distribution tree (M16 defense-in-depth pattern)
command -v restorecon >/dev/null 2>&1 && restorecon -R "${FIREFOX_LIB_DIR}/distribution" 2>/dev/null || true

if [ "$_lp_count" -eq 0 ]; then
    log "  FAIL: no langpack-*.xpi found in $FIREFOX_LANGPACK_SRC"
    exit 1
fi
log "  Activated ${_lp_count} Firefox langpacks via distribution/extensions/ (FF picks the OS-locale match on first profile start)"

#------------------------------------------------------------------------------
# Step 4: Fetch uBlock Origin XPI to system-scope staging path
#------------------------------------------------------------------------------
# The System-scope path is a stable STAGING location only — the setup
# script (Step 6) copies the verified XPI profile-local. Do NOT re-litigate:
# FF150 distribution-bundled scan does NOT auto-install regular extensions
# (verified across all launch modes), and policies.json
# ExtensionSettings triggers the "managed by your organization" UI hint.
# autoDisableScopes=10 keeps profile-scope XPIs + app-global langpacks
# auto-enabled.

log "Step 4/8: Acquire pinned uBlock Origin XPI v${UBO_VERSION}"

fetch_or_cache "$UBO_CACHE_RELATIVE" \
    "$UBO_URL" "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi"
verify_sha256 "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" "$UBO_SHA256" "uBO XPI v${UBO_VERSION}"
UBO_SIZE=$(stat -c%s "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi")
if [ "$UBO_SIZE" -ne "$UBO_SIZE_EXPECTED" ]; then
    log "  FAIL: uBO XPI size mismatch ($UBO_SIZE bytes, expected $UBO_SIZE_EXPECTED)"
    exit 1
fi
# XPIs are ZIP files — verify magic bytes (defense in depth after SHA)
if ! file "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" | grep -q 'Zip archive'; then
    log "  FAIL: uBO XPI not a valid ZIP archive"
    exit 1
fi
chmod 644 "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi"
chown root:root "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi"

log "  Fetched uBO XPI: $UBO_SIZE bytes → $EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi"
log "  (System-scope build-time cache — setup-script copies into active profile in Step 6)"

#------------------------------------------------------------------------------
# Step 5: Install uBlock Origin Managed Storage Manifest
#------------------------------------------------------------------------------
log "Step 5/8: Install uBO Managed Storage Manifest"
cat > "$UBO_POLICY_SOURCE" <<'UBOMANIFEST_EOF'
{
  "name": "uBlock0@raymondhill.net",
  "description": "NoID Privacy Workstation 44 - uBlock Origin managed filter-list baseline (Module 16)",
  "type": "storage",
  "data": {
    "toOverwrite": {
      "filterLists": [
        "user-filters",
        "ublock-filters",
        "ublock-badware",
        "ublock-privacy",
        "ublock-quick-fixes",
        "ublock-unbreak",
        "easylist",
        "easyprivacy",
        "urlhaus-1",
        "plowe-0",
        "adguard-spyware-url",
        "block-lan",
        "curben-phishing"
      ]
    }
  }
}
UBOMANIFEST_EOF
chmod 644 "$UBO_POLICY_SOURCE"
chown root:root "$UBO_POLICY_SOURCE"
install -o root -g root -m 0644 -- "$UBO_POLICY_SOURCE" \
    "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json"
log "  Installed canonical and active uBO Managed Storage manifests"

#------------------------------------------------------------------------------
# Step 5b: Install /usr/local/lib/noid-privacy/firefox-profiles.sh
#------------------------------------------------------------------------------
# Single source of truth for profile discovery (registered profiles.ini
# entries, never `find -type d`). Sourced by the M16 CLIs + M33/M34/M25;
# the function inventory + per-function contracts live in the
# FF_PROFILES_EOF heredoc.
log "Step 5b/8: Install /usr/local/lib/noid-privacy/firefox-profiles.sh"

mkdir -p /usr/local/lib/noid-privacy
chmod 755 /usr/local/lib/noid-privacy

cat > "$UBO_POLICY_VALIDATOR" <<'UBO_POLICY_VALIDATOR_PYEOF'
#!/usr/bin/python3
"""Validate a uBO managed filter-list policy against one candidate XPI."""

import json
import os
import stat
import sys
import zipfile


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 3:
    print("Usage: validate-ubo-policy.py UBO_XPI MANAGED_STORAGE_JSON", file=sys.stderr)
    raise SystemExit(2)

xpi_path, policy_path = sys.argv[1:]
for path, label in ((xpi_path, "uBO XPI"), (policy_path, "managed policy")):
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        fail(f"{label} is not inspectable: {exc}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
        fail(f"{label} is not a nonempty regular file")

try:
    with open(policy_path, encoding="utf-8") as handle:
        policy = json.load(handle)
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    fail(f"managed policy is not strict UTF-8 JSON: {exc}")

if not isinstance(policy, dict):
    fail("managed policy root is not an object")
if set(policy) != {"name", "description", "type", "data"}:
    fail("managed policy top-level keys differ")
if policy["name"] != "uBlock0@raymondhill.net" or policy["type"] != "storage":
    fail("managed policy identity or type differs")
if not isinstance(policy["description"], str) or not policy["description"]:
    fail("managed policy description is empty")
data = policy["data"]
if not isinstance(data, dict) or set(data) != {"toOverwrite"}:
    fail("managed policy must contain only toOverwrite")
overwrite = data["toOverwrite"]
if not isinstance(overwrite, dict) or set(overwrite) != {"filterLists"}:
    fail("managed policy must overwrite only filterLists")
filter_lists = overwrite["filterLists"]
if (
    not isinstance(filter_lists, list)
    or not filter_lists
    or any(not isinstance(item, str) or not item for item in filter_lists)
    or len(filter_lists) != len(set(filter_lists))
):
    fail("managed filter-list tokens are empty, duplicated or malformed")
if filter_lists.count("user-filters") != 1:
    fail("managed policy must select user-filters exactly once")

try:
    archive = zipfile.ZipFile(xpi_path)
except (OSError, zipfile.BadZipFile) as exc:
    fail(f"uBO XPI is not a valid ZIP archive: {exc}")

with archive:
    members = archive.infolist()

    def read_unique_json(name, maximum):
        matches = [entry for entry in members if entry.filename == name]
        if len(matches) != 1:
            fail(f"uBO XPI must contain exactly one {name}")
        entry = matches[0]
        if entry.is_dir() or entry.file_size == 0 or entry.file_size > maximum:
            fail(f"uBO XPI {name} has an invalid size or type")
        try:
            return json.loads(archive.read(entry).decode("utf-8"))
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            RuntimeError,
            zipfile.BadZipFile,
        ) as exc:
            fail(f"uBO XPI {name} is not strict UTF-8 JSON: {exc}")

    manifest = read_unique_json("manifest.json", 262144)
    if not isinstance(manifest, dict):
        fail("uBO XPI manifest root is not an object")
    browser_settings = manifest.get("browser_specific_settings")
    if not isinstance(browser_settings, dict):
        fail("uBO XPI browser-specific settings are malformed")
    gecko = browser_settings.get("gecko")
    if not isinstance(gecko, dict) or gecko.get("id") != "uBlock0@raymondhill.net":
        fail("uBO XPI manifest identity differs")

    schema = read_unique_json("managed_storage.json", 262144)
    try:
        filter_schema = (
            schema["properties"]["toOverwrite"]["properties"]["filterLists"]
        )
    except (KeyError, TypeError):
        fail("uBO XPI does not advertise toOverwrite.filterLists")
    if (
        not isinstance(filter_schema, dict)
        or filter_schema.get("type") != "array"
        or not isinstance(filter_schema.get("items"), dict)
        or filter_schema["items"].get("type") != "string"
    ):
        fail("uBO XPI filter-list policy schema differs")

    assets = read_unique_json("assets/assets.json", 4194304)
    if not isinstance(assets, dict):
        fail("uBO XPI asset registry root is not an object")
    for token in filter_lists:
        if token == "user-filters":
            continue
        record = assets.get(token)
        if not isinstance(record, dict) or record.get("content") != "filters":
            fail(f"uBO XPI does not provide selected filter list: {token}")
        locations = record.get("contentURL")
        if isinstance(locations, str):
            locations = [locations]
        if (
            not isinstance(locations, list)
            or not locations
            or any(
                not isinstance(location, str)
                or not (
                    location.startswith("https://")
                    or location.startswith("assets/")
                )
                for location in locations
            )
        ):
            fail(f"selected filter list has an unsafe content location: {token}")

print(f"OK: uBO policy selects {len(filter_lists)} candidate-supported filter lists")
UBO_POLICY_VALIDATOR_PYEOF
chmod 755 "$UBO_POLICY_VALIDATOR"
chown root:root "$UBO_POLICY_VALIDATOR"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$UBO_POLICY_VALIDATOR" 2>/dev/null || true
fi

cat > /usr/local/lib/noid-privacy/validate-webextension.py <<'WEBEXT_VALIDATOR_PYEOF'
#!/usr/bin/python3
"""Validate a bounded Firefox/Thunderbird WebExtension archive.

Usage: validate-webextension.py ARCHIVE ID VERSION REQUIRE_SIGNATURE PRODUCT_VERSION [ALLOW_MISSING_ID]
Use '-' for any archive version or for no product-compatibility check. On
success the exact manifest version is printed; every failure is non-zero.
"""

import json
import os
from pathlib import PurePosixPath
import re
import stat
import sys
import zipfile

if len(sys.argv) not in {6, 7}:
    raise SystemExit(2)

archive, expected_id, expected_version, signature_arg, product_version = sys.argv[1:6]
allow_missing_arg = sys.argv[6] if len(sys.argv) == 7 else "0"
if signature_arg not in {"0", "1"} or allow_missing_arg not in {"0", "1"}:
    raise SystemExit(2)
require_signature = signature_arg == "1"
allow_missing_id = allow_missing_arg == "1"
version_pattern = re.compile(r"^[0-9]+(?:[.][0-9]+)*$")
if expected_version != "-" and not version_pattern.fullmatch(expected_version):
    raise SystemExit(2)

def numeric_version(value):
    match = re.match(r"^[0-9]+(?:[.][0-9]+)*", value)
    if not match:
        raise ValueError(f"invalid numeric version: {value!r}")
    return tuple(int(part) for part in match.group(0).split("."))

def pad(left, right):
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)), right + (0,) * (width - len(right))

def compatible(product, minimum, maximum):
    current = numeric_version(product)
    if minimum:
        low = numeric_version(minimum)
        if pad(current, low)[0] < pad(current, low)[1]:
            return False
    if maximum and maximum != "*":
        wildcard = maximum.endswith(".*")
        raw_maximum = maximum[:-2] if wildcard else maximum
        high = numeric_version(raw_maximum)
        if wildcard:
            width = len(high)
            if current[:width] > high:
                return False
        elif pad(current, high)[0] > pad(current, high)[1]:
            return False
    return True

archive_stat = os.lstat(archive)
if not stat.S_ISREG(archive_stat.st_mode) or stat.S_ISLNK(archive_stat.st_mode):
    raise SystemExit("archive is not a regular file")
if archive_stat.st_size <= 0 or archive_stat.st_size > 64 * 1024 * 1024:
    raise SystemExit("archive size outside policy")

with zipfile.ZipFile(archive) as bundle:
    entries = bundle.infolist()
    if not entries or len(entries) > 8192:
        raise SystemExit("entry count outside policy")
    seen = set()
    total = 0
    for entry in entries:
        name = entry.filename
        if not name or "\x00" in name or "\\" in name or name.startswith("/"):
            raise SystemExit("unsafe archive path")
        parts = PurePosixPath(name).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise SystemExit("unsafe archive component")
        normalized = "/".join(parts)
        if normalized in seen:
            raise SystemExit("duplicate archive path")
        seen.add(normalized)
        if entry.flag_bits & 1:
            raise SystemExit("encrypted archive entry")
        mode = (entry.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if entry.is_dir():
            if file_type not in {0, stat.S_IFDIR}:
                raise SystemExit("directory/type mismatch")
        else:
            if file_type not in {0, stat.S_IFREG}:
                raise SystemExit("non-regular archive entry")
            if entry.file_size < 0 or entry.file_size > 64 * 1024 * 1024:
                raise SystemExit("entry size outside policy")
            total += entry.file_size
            if total > 256 * 1024 * 1024:
                raise SystemExit("expanded archive outside policy")
    if bundle.testzip() is not None:
        raise SystemExit("archive CRC failure")
    try:
        manifest_raw = bundle.read("manifest.json")
    except KeyError as exc:
        raise SystemExit("manifest.json missing") from exc
    if len(manifest_raw) > 1024 * 1024:
        raise SystemExit("manifest too large")
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit("manifest unreadable") from exc
    if not isinstance(manifest, dict):
        raise SystemExit("manifest is not an object")
    gecko = (manifest.get("browser_specific_settings") or
             manifest.get("applications") or {}).get("gecko", {})
    if not isinstance(gecko, dict) or (gecko.get("id") is None and not allow_missing_id) \
            or (gecko.get("id") is not None and gecko.get("id") != expected_id):
        raise SystemExit("extension identity mismatch")
    version = manifest.get("version")
    if not isinstance(version, str) or not version_pattern.fullmatch(version):
        raise SystemExit("extension version is not bounded numeric form")
    if expected_version != "-" and version != expected_version:
        raise SystemExit("extension version mismatch")
    if manifest.get("update_url") not in {None, ""} or gecko.get("update_url") not in {None, ""}:
        raise SystemExit("archive carries an autonomous update URL")
    if require_signature:
        signature_files = {
            "META-INF/manifest.mf", "META-INF/mozilla.sf", "META-INF/mozilla.rsa"
        }
        if not signature_files.issubset(seen):
            raise SystemExit("Mozilla signature container missing")
    if product_version != "-" and not compatible(
            product_version, gecko.get("strict_min_version"),
            gecko.get("strict_max_version")):
        raise SystemExit("extension is incompatible with installed product")

print(version)
WEBEXT_VALIDATOR_PYEOF
chmod 755 /usr/local/lib/noid-privacy/validate-webextension.py
chown root:root /usr/local/lib/noid-privacy/validate-webextension.py
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/lib/noid-privacy/validate-webextension.py 2>/dev/null || true
fi
if ! python3 -c 'import pathlib; p=pathlib.Path("/usr/local/lib/noid-privacy/validate-webextension.py"); compile(p.read_text(), str(p), "exec")'; then
    log "FAIL: validate-webextension.py has syntax errors"
    exit 1
fi

cat > /usr/local/lib/noid-privacy/verify-firefox-xpi-signature <<'FIREFOX_XPI_SIGNATURE_EOF'
#!/bin/bash
# Ask the installed Firefox build to verify one candidate XPI in a disposable,
# network-isolated profile. A ZIP signature filename is not proof; Firefox's
# native add-on verifier is the authority. No candidate reaches a real profile
# unless this helper observes the exact signed/active identity below.
set -euo pipefail
PATH=/usr/sbin:/usr/bin
umask 077

[ "$#" -eq 3 ] || exit 2
archive=$1
expected_id=$2
expected_version=$3
[[ "$expected_id" =~ ^[A-Za-z0-9._+@{}-]+$ ]] || exit 2
[[ "$expected_version" =~ ^[0-9]+([.][0-9]+)*$ ]] || exit 2
[ "$(id -u)" -ne 0 ] || exit 2
[ -f "$archive" ] && [ ! -L "$archive" ] || exit 2
for required in /usr/bin/firefox /usr/bin/python3 /usr/bin/unshare; do
    [ -x "$required" ] || exit 1
done

work=$(mktemp -d /var/tmp/noid-firefox-xpi-verify.XXXXXX)
child=
cleanup() {
    if [ -n "${child:-}" ]; then
        # Firefox owns/reaps its content children. Signal only the exact
        # parent PID: a negative process-group signal can cross the caller's
        # group boundary when setsid fails before exec.
        kill -TERM -- "$child" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$child" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL -- "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    [ ! -L "$work" ] && rm -rf --one-file-system -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

profile=$work/profile
target=$profile/extensions/${expected_id}.xpi
install -d -m 0700 "$work/home" "$work/state" "$work/cache" \
    "$work/config" "$work/runtime" "$work/tmp" "$profile/extensions"
install -m 0600 -- "$archive" "$target"
cat > "$profile/user.js" <<'FIREFOX_XPI_PREFS_EOF'
user_pref("network.trr.mode", 5);
user_pref("extensions.update.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
FIREFOX_XPI_PREFS_EOF
chmod 0600 "$profile/user.js"

env -u DBUS_SESSION_BUS_ADDRESS -u DISPLAY -u WAYLAND_DISPLAY \
    HOME="$work/home" XDG_STATE_HOME="$work/state" \
    XDG_CACHE_HOME="$work/cache" XDG_CONFIG_HOME="$work/config" \
    XDG_RUNTIME_DIR="$work/runtime" TMPDIR="$work/tmp" \
    MOZ_CRASHREPORTER_DISABLE=1 \
    /usr/bin/unshare --user --map-current-user --net --pid --fork \
    --kill-child=KILL --mount-proc \
    /usr/bin/firefox --headless --no-remote --profile "$profile" \
    about:blank >/dev/null 2>&1 &
child=$!

for _ in $(seq 1 300); do
    if /usr/bin/python3 - "$profile/extensions.json" "$expected_id" \
            "$expected_version" "$target" <<'FIREFOX_SIGNED_STATE_PY' 2>/dev/null
import json
import os
import sys

path, expected_id, expected_version, expected_path = sys.argv[1:]
with open(path, encoding="utf-8") as source:
    database = json.load(source)
matches = [addon for addon in database.get("addons", [])
           if addon.get("id") == expected_id]
assert len(matches) == 1
addon = matches[0]
assert addon.get("version") == expected_version
assert addon.get("type") == "extension"
assert addon.get("signedState") == 2
assert addon.get("active") is True and addon.get("visible") is True
assert os.path.realpath(addon.get("path", "")) == os.path.realpath(expected_path)
FIREFOX_SIGNED_STATE_PY
    then
        exit 0
    fi
    kill -0 "$child" 2>/dev/null || exit 1
    sleep 0.1
done
exit 1
FIREFOX_XPI_SIGNATURE_EOF
chmod 755 /usr/local/lib/noid-privacy/verify-firefox-xpi-signature
chown root:root /usr/local/lib/noid-privacy/verify-firefox-xpi-signature
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/lib/noid-privacy/verify-firefox-xpi-signature 2>/dev/null || true
fi
if ! bash -n /usr/local/lib/noid-privacy/verify-firefox-xpi-signature; then
    log "FAIL: verify-firefox-xpi-signature has syntax errors"
    exit 1
fi

cat > /usr/local/lib/noid-privacy/firefox-profiles.sh <<'FF_PROFILES_EOF'
#!/bin/bash
# /usr/local/lib/noid-privacy/firefox-profiles.sh
#
# NoID Privacy Firefox profile management — single source of truth.
# All NoID Privacy Firefox modules source this library to get a consistent view
# of registered profiles and apply the supported user.js composition per profile.
#
# Profile discovery is via registered profiles.ini entries (not `find -type d`,
# which previously matched non-profile dirs: Crash Reports, Pending Pings,
# Profile Groups, firefox-mpris). Mozilla Bug 2003137 can make Firefox prefer an
# otherwise empty legacy ~/.mozilla/firefox tree over a valid XDG registry
# (https://bugzilla.mozilla.org/show_bug.cgi?id=2003137). The owned
# launcher therefore resolves registered XDG profiles through this helper and
# passes their validated path explicitly.

NOID_FF_USERJS_BASE="/usr/share/noid-firefox/user.js"
NOID_FF_USERJS_PLAYGROUND_OVERRIDES="/usr/share/noid-firefox/user-playground-overrides.js"
NOID_FF_USERJS_DRM_OVERRIDES="/usr/share/noid-firefox/user-drm-overrides.js"
NOID_FF_DRM_SENTINEL_BASENAME=".noid-drm-enabled"
NOID_FF_AUTO_EXCLUSION_BASENAME=".noid-firefox-hardening-disabled"
NOID_FF_AUTO_EXCLUSION_CONTENT="NOID_FIREFOX_HARDENING_DISABLED_V1"
NOID_FF_RELAX_FPP_BEGIN="// NOID-RELAX-FPP-BEGIN"
NOID_FF_RELAX_FPP_END="// NOID-RELAX-FPP-END"
NOID_FF_RELAX_WEBRTC_BEGIN="// NOID-RELAX-WEBRTC-BEGIN"
NOID_FF_RELAX_WEBRTC_END="// NOID-RELAX-WEBRTC-END"
NOID_FF_UBO_XPI="/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi"
NOID_FF_UBO_SHA256="bccc51a773150af4af6e1fd62c7bfdeb7238b79ff2381b998fa9f2e38f64786a"
NOID_FF_UBO_SIZE=4679419
NOID_FF_WEBEXT_VALIDATOR="/usr/local/lib/noid-privacy/validate-webextension.py"

validate_ubo_profile_xpi() {
    local archive="$1"
    [ -x "$NOID_FF_WEBEXT_VALIDATOR" ] || return 1
    "$NOID_FF_WEBEXT_VALIDATOR" "$archive" \
        uBlock0@raymondhill.net - 1 - >/dev/null
}

noid_atomic_install_file() {
    local source="$1" destination="$2" mode="$3" parent temporary
    parent=$(dirname "$destination") || return 1
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
    [ ! -L "$destination" ] || return 1
    if [ -e "$destination" ] && [ ! -f "$destination" ]; then
        return 1
    fi
    temporary=$(mktemp "$parent/.$(basename "$destination").tmp.XXXXXXXX") || return 1
    if ! install -m "$mode" -- "$source" "$temporary" || \
       ! sync -- "$temporary" || \
       ! mv -fT -- "$temporary" "$destination" || \
       ! sync -- "$parent"; then
        rm -f -- "$temporary"
        return 1
    fi
}

profile_auto_hardening_excluded() {
    local pdir="$1" marker metadata
    marker="$pdir/$NOID_FF_AUTO_EXCLUSION_BASENAME"
    [ ! -L "$marker" ] || return 2
    if [ ! -e "$marker" ]; then
        return 1
    fi
    [ -f "$marker" ] || return 2
    metadata=$(stat -Lc '%u:%a:%h' -- "$marker" 2>/dev/null) || return 2
    [ "$metadata" = "$(id -u):600:1" ] || return 2
    cmp -s -- "$marker" \
        <(printf '%s\n' "$NOID_FF_AUTO_EXCLUSION_CONTENT") || return 2
}

publish_profile_auto_hardening_exclusion() {
    local pdir="$1" marker temporary
    [ -d "$pdir" ] && [ ! -L "$pdir" ] || return 1
    marker="$pdir/$NOID_FF_AUTO_EXCLUSION_BASENAME"
    [ ! -L "$marker" ] || return 1
    if [ -e "$marker" ]; then
        profile_auto_hardening_excluded "$pdir"
        return
    fi
    temporary=$(mktemp "$pdir/.noid-firefox-auto-exclusion.XXXXXXXX") \
        || return 1
    if ! printf '%s\n' "$NOID_FF_AUTO_EXCLUSION_CONTENT" > "$temporary" || \
       ! chmod 0600 "$temporary" || \
       ! noid_atomic_install_file "$temporary" "$marker" 600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary"
    profile_auto_hardening_excluded "$pdir"
}

clear_profile_auto_hardening_exclusion() {
    local pdir="$1" marker
    marker="$pdir/$NOID_FF_AUTO_EXCLUSION_BASENAME"
    [ ! -L "$marker" ] || return 1
    if [ ! -e "$marker" ]; then
        return 0
    fi
    profile_auto_hardening_excluded "$pdir" || return 1
    rm -f -- "$marker" && sync -- "$pdir"
}

# Output XDG-Compliant Firefox profile root.
firefox_root() {
    printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/mozilla/firefox"
}

noid_require_desktop_user() {
    [ "$(id -u)" -ne 0 ] && [ -n "${HOME:-}" ] && [ -d "$HOME" ]
}

# pgrep deliberately reports defunct tasks. A zombie (State Z) and the
# transient dead states (X/x) cannot execute or retain Firefox profile files,
# so they must not strand every profile-management workflow behind a false
# "Firefox is running" result. Every other state remains fail-closed. If an
# extant candidate cannot be parsed safely, treat it as active.
firefox_process_active() {
    local process_name firefox_pid status_file firefox_state
    for process_name in firefox firefox-bin; do
        while IFS= read -r firefox_pid; do
            [[ "$firefox_pid" =~ ^[0-9]+$ ]] || continue
            status_file="/proc/${firefox_pid}/status"
            if [ ! -r "$status_file" ]; then
                [ -e "/proc/${firefox_pid}" ] && return 0
                continue
            fi
            firefox_state=$(awk '$1 == "State:" { print $2; exit }' \
                "$status_file" 2>/dev/null || true)
            case "$firefox_state" in
                Z|X|x) continue ;;
                "") [ -e "/proc/${firefox_pid}" ] || continue ;;
            esac
            return 0
        done < <(pgrep -u "$(id -u)" -x "$process_name" 2>/dev/null || true)
    done
    return 1
}

# Serialize every NoID Privacy profile mutation, including independent CLIs and the
# guided update workflow. The descriptor remains held by the calling shell.
acquire_firefox_profile_lock() {
    local state_dir lock_file
    noid_require_desktop_user || return 1
    state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy"
    [ ! -L "$state_dir" ] || return 1
    mkdir -p "$state_dir" || return 1
    chmod 700 "$state_dir" || return 1
    lock_file="$state_dir/firefox-profile-operations.lock"
    [ ! -L "$lock_file" ] || return 1
    exec {NOID_FF_PROFILE_LOCK_FD}>"$lock_file" || return 1
    flock -n "$NOID_FF_PROFILE_LOCK_FD"
}

# Parse profiles.ini with a closed record model. Output:
#   name<TAB>relative-path<TAB>IsRelative<TAB>default
# NoID Privacy helpers intentionally manage only regular, current-user-owned profiles
# below the canonical Firefox root. Firefox may support external absolute
# profiles, but treating profiles.ini as authority to write arbitrary paths is
# outside this helper's safe boundary.
list_registered_profiles() {
    local root
    noid_require_desktop_user || return 1
    root=$(firefox_root) || return 1
    python3 - "$root" <<'PROFILE_LIST_PYEOF'
import configparser
import os
import re
import stat
import sys

raw_root = sys.argv[1]
uid = os.geteuid()
if not os.path.isabs(raw_root) or os.path.normpath(raw_root) != raw_root:
    raise SystemExit(f"unsafe Firefox root: {raw_root!r}")
if os.path.lexists(raw_root):
    root_stat = os.lstat(raw_root)
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise SystemExit("Firefox root is not a regular directory")
    if root_stat.st_uid != uid or root_stat.st_mode & 0o022:
        raise SystemExit("Firefox root ownership/mode is unsafe")
else:
    raise SystemExit(0)

ini = os.path.join(raw_root, "profiles.ini")
if not os.path.lexists(ini):
    raise SystemExit(0)
ini_stat = os.lstat(ini)
if not stat.S_ISREG(ini_stat.st_mode) or stat.S_ISLNK(ini_stat.st_mode):
    raise SystemExit("profiles.ini is not a regular file")
if ini_stat.st_uid != uid or ini_stat.st_mode & 0o022:
    raise SystemExit("profiles.ini ownership/mode is unsafe")

parser = configparser.ConfigParser(strict=True, interpolation=None)
parser.optionxform = str
with open(ini, encoding="utf-8") as handle:
    parser.read_file(handle)

seen_names = set()
seen_paths = set()
records = []
for section in parser.sections():
    if not re.fullmatch(r"Profile[0-9]+", section):
        continue
    name = parser.get(section, "Name", fallback="")
    path = parser.get(section, "Path", fallback="")
    relative = parser.get(section, "IsRelative", fallback="")
    default = parser.get(section, "Default", fallback="0")
    # Firefox supports absolute profiles, but they are outside this helper's
    # write boundary. Ignore that one registration instead of making an
    # unrelated safe default profile (and therefore the owned launcher)
    # unusable. Unknown IsRelative values remain malformed and fail closed.
    if relative == "0":
        continue
    if relative != "1":
        raise SystemExit(f"{section}: invalid IsRelative value")
    if not name or any(ch in name for ch in "\t\r\n"):
        raise SystemExit(f"{section}: invalid profile name")
    if name in seen_names:
        raise SystemExit(f"duplicate profile name: {name}")
    if (not path or os.path.isabs(path) or any(ch in path for ch in "\t\r\n")
            or os.path.normpath(path) != path
            or ".." in path.split(os.sep)):
        raise SystemExit(f"{section}: unsafe relative profile path")
    if path in seen_paths:
        raise SystemExit(f"duplicate profile path: {path}")
    if default not in {"0", "1"}:
        raise SystemExit(f"{section}: invalid Default value")
    candidate = os.path.join(raw_root, path)
    current = raw_root
    for component in path.split(os.sep):
        current = os.path.join(current, component)
        if not os.path.lexists(current):
            break
        component_stat = os.lstat(current)
        if stat.S_ISLNK(component_stat.st_mode):
            raise SystemExit(f"{section}: symlinked profile path component")
    if os.path.lexists(candidate):
        profile_stat = os.lstat(candidate)
        if not stat.S_ISDIR(profile_stat.st_mode):
            raise SystemExit(f"{section}: profile path is not a directory")
        if profile_stat.st_uid != uid or profile_stat.st_mode & 0o022:
            raise SystemExit(f"{section}: profile ownership/mode is unsafe")
    seen_names.add(name)
    seen_paths.add(path)
    records.append((name, path, relative, default))

for record in records:
    print("\t".join(record))
PROFILE_LIST_PYEOF
}

# Output a safe path below firefox_root, or return 1 if absent/invalid.
profile_dir_for() {
    local name="$1" records record_name path is_relative match=""
    records=$(list_registered_profiles) || return 1
    while IFS=$'\t' read -r record_name path is_relative _; do
        [ "$record_name" = "$name" ] || continue
        [ -z "$match" ] || return 1
        [ "$is_relative" = "1" ] || return 1
        match="$(firefox_root)/$path"
    done <<< "$records"
    [ -n "$match" ] || return 1
    printf '%s\n' "$match"
}

# Build the exact argv used by the owned Firefox launcher.
#
# Ordinary invocations are bound to the registered, hardened default-release
# path. A named -P/-p profile is converted only when the same safe XDG registry
# resolves it; this preserves the user's profile choice while avoiding the
# legacy-directory shadowing tracked as Mozilla Bug 2003137. Explicit path/profile-manager,
# profile-creation and diagnostic requests retain Firefox's own semantics.
#
# Result: global array NOID_FF_LAUNCH_ARGS. An unresolved ordinary default is
# a hard failure; an unresolved explicit named profile remains user-owned and
# is passed through unchanged.
prepare_firefox_launch_args() {
    local -a original=("$@") normalized=()
    local arg arg_lower named_name="" profile_path
    local i named_index=-1 named_width=0 named_count=0 bypass=0
    declare -ga NOID_FF_LAUNCH_ARGS=()

    for ((i = 0; i < ${#original[@]}; i++)); do
        arg=${original[$i]}
        arg_lower=${arg,,}
        # Firefox accepts these ordinary long options with one or two dashes.
        # Without this closed exception, -p?* mistakes them for a concatenated
        # -pNAME selector and skips the hardened default-profile binding.
        case "$arg_lower" in
            -profilemanager)
                bypass=1
                continue
                ;;
            -private|-private-window|-preferences|-purgecaches)
                continue
                ;;
        esac
        case "$arg" in
            -ProfileManager|--ProfileManager|-CreateProfile|--CreateProfile|\
            -CreateProfile=*|--CreateProfile=*|--help|-h|--version|-v|--full-version)
                bypass=1
                ;;
            -profile|--profile|-profile=*|--profile=*)
                bypass=1
                ;;
            -P|-p)
                if ((i + 1 >= ${#original[@]})); then
                    bypass=1
                    continue
                fi
                ((named_count += 1))
                if ((named_count == 1)); then
                    named_name=${original[$((i + 1))]}
                    named_index=$i
                    named_width=2
                fi
                ((i += 1))
                ;;
            -P?*|-p?*)
                ((named_count += 1))
                if ((named_count == 1)); then
                    named_name=${arg:2}
                    named_index=$i
                    named_width=1
                fi
                ;;
        esac
    done

    if ((bypass || named_count > 1)); then
        NOID_FF_LAUNCH_ARGS=("${original[@]}")
        return 0
    fi

    if ((named_count == 1)); then
        if ! profile_path=$(profile_dir_for "$named_name" 2>/dev/null) || \
           [ ! -d "$profile_path" ] || [ -L "$profile_path" ]; then
            NOID_FF_LAUNCH_ARGS=("${original[@]}")
            return 0
        fi
        for ((i = 0; i < ${#original[@]}; i++)); do
            if ((i == named_index)); then
                normalized+=(--profile "$profile_path")
                i=$((i + named_width - 1))
            else
                normalized+=("${original[$i]}")
            fi
        done
        NOID_FF_LAUNCH_ARGS=("${normalized[@]}")
        return 0
    fi

    profile_path=$(profile_dir_for default-release) || return 1
    [ -d "$profile_path" ] && [ ! -L "$profile_path" ] || return 1
    NOID_FF_LAUNCH_ARGS=(--profile "$profile_path" "${original[@]}")
}

# Create a profile via firefox -CreateProfile if not already registered.
# Returns 0 on success; 1 on failure.
ensure_profile() {
    local name="$1" existing
    noid_require_desktop_user || return 1
    [ -n "$name" ] && [ "${#name}" -le 32 ] || return 1
    case "$name" in *[!a-zA-Z0-9_-]*) return 1 ;; esac
    if existing=$(profile_dir_for "$name" 2>/dev/null); then
        [ -d "$existing" ] && [ ! -L "$existing" ]
        return
    fi
    if ! command -v firefox >/dev/null 2>&1; then
        return 1
    fi
    MOZ_HEADLESS=1 firefox --headless -no-remote -CreateProfile "$name" >/dev/null 2>&1 || return 1
    sleep 1  # allow profiles.ini commit
    profile_dir_for "$name" >/dev/null
}

# Report whether the exact profile-local DRM consent sentinel is absent or
# enabled. Any malformed/symlinked state is an error, never a silent opt-out.
profile_drm_opt_in_state() {
    local pdir="$1" sentinel mode owner
    sentinel="$pdir/$NOID_FF_DRM_SENTINEL_BASENAME"
    if [ ! -e "$sentinel" ] && [ ! -L "$sentinel" ]; then
        printf '%s\n' disabled
        return 0
    fi
    [ -f "$sentinel" ] && [ ! -L "$sentinel" ] || return 1
    mode=$(stat -c '%a' "$sentinel") || return 1
    owner=$(stat -c '%u' "$sentinel") || return 1
    [ "$mode" = 600 ] && [ "$owner" -eq "$(id -u)" ] || return 1
    grep -qx 'NOID_FIREFOX_DRM_OPT_IN_V1' "$sentinel" || return 1
    printf '%s\n' enabled
}

# The two supported compatibility choices are emitted from this shared source
# so the opt-in CLIs, Update All and completeness checks cannot drift apart.
noid_fpp_relaxation_block() {
    cat <<'NOID_FPP_RELAXATION_EOF'
// NOID-RELAX-FPP-BEGIN
// Created by noid-firefox-relax-fpp. Remove with:
//   noid-firefox-relax-fpp --restore
// This ONLY relaxes fingerprinting protection. DNS policy, HTTPS-Only, password
// manager off, Mozilla AI off, Nimbus off, telemetry off — all stay active.
user_pref("privacy.fingerprintingProtection", false);
user_pref("privacy.fingerprintingProtection.pbmode", false);
user_pref("privacy.resistFingerprinting", false);
// NOID-RELAX-FPP-END
NOID_FPP_RELAXATION_EOF
}

noid_webrtc_relaxation_block() {
    cat <<'NOID_WEBRTC_RELAXATION_EOF'
// NOID-RELAX-WEBRTC-BEGIN
// Created by noid-firefox-relax-webrtc. Remove with:
//   noid-firefox-relax-webrtc --restore
// This ONLY re-enables WebRTC. DNS policy, HTTPS-Only, password manager off,
// Mozilla AI off, Nimbus off, telemetry off, FPP on — all stay active.
// ICE candidate-reduction prefs stay on; they are not an IP-leak guarantee.
user_pref("media.peerconnection.enabled", true);
// NOID-RELAX-WEBRTC-END
NOID_WEBRTC_RELAXATION_EOF
}

# Print disabled/enabled only when a marker pair is absent or byte-exactly one
# of the supported blocks above. Malformed or altered blocks are never silently
# carried into a regenerated security configuration.
noid_supported_relaxation_state() {
    local path="$1" begin="$2" end="$3" emitter="$4"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        printf '%s\n' disabled
        return 0
    fi
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    validate_noid_marker_pair "$path" "$begin" "$end" || return 1
    if ! grep -Fxq -- "$begin" "$path"; then
        printf '%s\n' disabled
        return 0
    fi
    cmp -s \
        <(awk -v B="$begin" -v E="$end" '
            $0 == B { capture=1 }
            capture { print }
            capture && $0 == E { exit }
        ' "$path") \
        <("$emitter") || return 1
    printf '%s\n' enabled
}

# Re-emit the two supported compatibility blocks in their one canonical
# FPP-then-WebRTC order while preserving every unrelated user.js line. Each
# choice is enabled, disabled, or preserve. The current blocks must be exact
# even when the caller is changing only the other choice.
compose_userjs_relaxation_choice() {
    local path="$1" fpp_choice="$2" webrtc_choice="$3"
    local current_fpp current_webrtc fpp_state webrtc_state
    current_fpp=$(noid_supported_relaxation_state "$path" \
        "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END" \
        noid_fpp_relaxation_block) || return 1
    current_webrtc=$(noid_supported_relaxation_state "$path" \
        "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END" \
        noid_webrtc_relaxation_block) || return 1
    case "$fpp_choice" in
        preserve) fpp_state=$current_fpp ;;
        enabled|disabled) fpp_state=$fpp_choice ;;
        *) return 1 ;;
    esac
    case "$webrtc_choice" in
        preserve) webrtc_state=$current_webrtc ;;
        enabled|disabled) webrtc_state=$webrtc_choice ;;
        *) return 1 ;;
    esac
    awk -v FB="$NOID_FF_RELAX_FPP_BEGIN" \
        -v FE="$NOID_FF_RELAX_FPP_END" \
        -v WB="$NOID_FF_RELAX_WEBRTC_BEGIN" \
        -v WE="$NOID_FF_RELAX_WEBRTC_END" '
        $0 == FB || $0 == WB { skip=1; next }
        skip && ($0 == FE || $0 == WE) { skip=0; next }
        !skip { print }
    ' "$path" || return 1
    if [ "$fpp_state" = enabled ]; then
        noid_fpp_relaxation_block || return 1
    fi
    if [ "$webrtc_state" = enabled ]; then
        noid_webrtc_relaxation_block || return 1
    fi
}

# Emit the complete supported user.js state without publishing it.
# preserve-supported keeps only exact NoID Privacy compatibility blocks.
# reset-relaxations is reserved for an explicit harden-profile --force action.
compose_supported_userjs() {
    local name="$1" pdir="$2" mode="${3:-preserve-supported}"
    local userjs="$pdir/user.js" drm_state fpp_state webrtc_state
    [ -f "$NOID_FF_USERJS_BASE" ] && [ ! -L "$NOID_FF_USERJS_BASE" ] || return 1
    case "$mode" in
        preserve-supported)
            fpp_state=$(noid_supported_relaxation_state "$userjs" \
                "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END" \
                noid_fpp_relaxation_block) || return 1
            webrtc_state=$(noid_supported_relaxation_state "$userjs" \
                "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END" \
                noid_webrtc_relaxation_block) || return 1
            ;;
        reset-relaxations)
            fpp_state=disabled
            webrtc_state=disabled
            ;;
        *)
            return 1
            ;;
    esac
    drm_state=$(profile_drm_opt_in_state "$pdir") || return 1

    cat -- "$NOID_FF_USERJS_BASE" || return 1
    if [ "$name" = playground ]; then
        [ -f "$NOID_FF_USERJS_PLAYGROUND_OVERRIDES" ] && \
            [ ! -L "$NOID_FF_USERJS_PLAYGROUND_OVERRIDES" ] || return 1
        cat -- "$NOID_FF_USERJS_PLAYGROUND_OVERRIDES" || return 1
    fi
    if [ "$drm_state" = enabled ]; then
        [ -f "$NOID_FF_USERJS_DRM_OVERRIDES" ] && \
            [ ! -L "$NOID_FF_USERJS_DRM_OVERRIDES" ] || return 1
        cat -- "$NOID_FF_USERJS_DRM_OVERRIDES" || return 1
    fi
    if [ "$fpp_state" = enabled ]; then
        noid_fpp_relaxation_block || return 1
    fi
    if [ "$webrtc_state" = enabled ]; then
        noid_webrtc_relaxation_block || return 1
    fi
}

# Apply the exact supported composition to a registered profile. Regular
# Update/repair paths preserve reviewed compatibility opt-ins; only an explicit
# force operation may request reset-relaxations.
apply_userjs() {
    local name="$1" mode="${2:-preserve-supported}" pdir temporary
    [ "$#" -le 2 ] || return 1
    pdir=$(profile_dir_for "$name") || return 1
    [ -d "$pdir" ] && [ ! -L "$pdir" ] || return 1
    temporary=$(mktemp "$pdir/.user.js.combined.XXXXXXXX") || return 1
    if ! compose_supported_userjs "$name" "$pdir" "$mode" > "$temporary" || \
       ! chmod 600 "$temporary" || \
       ! sync -- "$temporary" || \
       ! noid_atomic_install_file "$temporary" "$pdir/user.js" 600 || \
       ! cmp -s "$temporary" "$pdir/user.js"; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary"
}

profile_userjs_supported() {
    local name="$1" pdir="$2" userjs state
    userjs="$pdir/user.js"
    [ -f "$userjs" ] && [ ! -L "$userjs" ] || return 1
    state=$(stat -c '%u:%a:%h' -- "$userjs") || return 1
    [ "$state" = "$(id -u):600:1" ] || return 1
    cmp -s "$userjs" <(compose_supported_userjs "$name" "$pdir")
}

# A managed signature is deliberately weaker than byte-exact completeness:
# Update All must recognize an older NoID Privacy base so it can converge it.
# Requiring both stable boundary records, safe ownership and exact cardinality
# avoids treating an unrelated user.js that merely mentions NoID Privacy as managed.
profile_userjs_noid_managed() {
    local pdir="$1" userjs state
    userjs="$pdir/user.js"
    [ -f "$userjs" ] && [ ! -L "$userjs" ] || return 1
    state=$(stat -c '%u:%a:%h' -- "$userjs") || return 1
    [ "$state" = "$(id -u):600:1" ] || return 1
    python3 - "$userjs" <<'NOID_USERJS_MANAGED_PYEOF'
import sys

start = "*    name: NoID Privacy Workstation — Firefox Hardening"
end = 'user_pref("_user.js.parrot", "NOID-COMPLETE: full hardening applied");'
with open(sys.argv[1], encoding="utf-8") as handle:
    lines = [line.rstrip("\n") for line in handle]
starts = [index for index, line in enumerate(lines) if line == start]
ends = [index for index, line in enumerate(lines) if line == end]
if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
    raise SystemExit(1)
NOID_USERJS_MANAGED_PYEOF
}

# Copy the uBO XPI into a named profile's extensions/ directory.
# This is the verified profile-local mechanism, restored after the
# distribution-bundled approach was confirmed non-functional
# under FF150 (XPI never registered in extensions.json across all tested
# launch modes). Used by Module 33 (isolated profiles) + Module 34
# (playground) for non-default-release profiles. Module 16 setup-script
# does the same install for the default-release profile inline.
#
# Requires user.js extensions.autoDisableScopes=10 (Profile bit 1 NOT in the
# disable mask) so Firefox auto-
# enables the Profile-scope XPI on next launch.
install_ubo_profile_local() {
    local name="$1" mode="${2:-preserve-valid}" pdir extension_dir target
    local actual_sha actual_size
    case "$mode" in
        preserve-valid|repair-invalid) ;;
        *) return 2 ;;
    esac
    pdir=$(profile_dir_for "$name") || return 1
    [ -d "$pdir" ] && [ ! -L "$pdir" ] || return 1
    [ -f "$NOID_FF_UBO_XPI" ] && [ ! -L "$NOID_FF_UBO_XPI" ] || return 1
    actual_size=$(stat -c '%s' "$NOID_FF_UBO_XPI") || return 1
    actual_sha=$(sha256sum "$NOID_FF_UBO_XPI" | awk '{print $1}') || return 1
    [ "$actual_size" -eq "$NOID_FF_UBO_SIZE" ] || return 1
    [ "$actual_sha" = "$NOID_FF_UBO_SHA256" ] || return 1

    extension_dir="$pdir/extensions"
    if [ -L "$extension_dir" ] || { [ -e "$extension_dir" ] && [ ! -d "$extension_dir" ]; }; then
        return 1
    fi
    install -d -m 700 "$extension_dir" || return 1
    target="$extension_dir/uBlock0@raymondhill.net.xpi"
    if [ -f "$target" ] && [ ! -L "$target" ]; then
        # A validated profile copy is user-owned current state. Preserve it:
        # M25 may have advanced it beyond the reviewed image seed.
        if validate_ubo_profile_xpi "$target"; then
            return 0
        fi
        [ "$mode" = repair-invalid ] || return 1
    else
        [ ! -e "$target" ] && [ ! -L "$target" ] || return 1
    fi
    noid_atomic_install_file "$NOID_FF_UBO_XPI" "$target" 644 || return 1
    [ "$(stat -c '%s' "$target")" -eq "$NOID_FF_UBO_SIZE" ] || return 1
    [ "$(sha256sum "$target" | awk '{print $1}')" = "$NOID_FF_UBO_SHA256" ] || return 1
    validate_ubo_profile_xpi "$target"
}

# Explicit hardening may repair an invalid regular uBO profile payload from
# the reviewed seed. A valid newer payload is always preserved.
repair_ubo_profile_local() {
    local name="$1" pdir target
    pdir=$(profile_dir_for "$name") || return 1
    target="$pdir/extensions/uBlock0@raymondhill.net.xpi"
    if [ -f "$target" ] && [ ! -L "$target" ] && validate_ubo_profile_xpi "$target"; then
        return 0
    fi
    [ ! -L "$target" ] || return 1
    if [ -e "$target" ] && [ ! -f "$target" ]; then return 1; fi
    install_ubo_profile_local "$name" repair-invalid
}

# Pre-seed extension-preferences.json with PB-allowed permission for uBO.
# Profile-local install activates uBO in normal windows, but private-
# browsing access requires an explicit per-extension permission grant.
patch_ubo_pb_permission() {
    local name="$1" pdir prefs
    pdir=$(profile_dir_for "$name") || return 1
    [ -d "$pdir" ] && [ ! -L "$pdir" ] || return 1
    prefs="$pdir/extension-preferences.json"
    [ ! -L "$prefs" ] || return 1
    if [ -e "$prefs" ] && [ ! -f "$prefs" ]; then return 1; fi
    python3 - "$prefs" <<'PYEOF' || return 1
import json, os, sys, tempfile
path = sys.argv[1]
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"refusing to overwrite invalid {path}: {exc}", file=sys.stderr)
        sys.exit(1)
else:
    d = {}
if not isinstance(d, dict):
    print(f"refusing to overwrite non-object JSON in {path}", file=sys.stderr)
    sys.exit(1)
d["uBlock0@raymondhill.net"] = {
    "permissions": ["internal:privateBrowsingAllowed"],
    "origins": [],
    "data_collection": []
}
parent = os.path.dirname(path)
fd, temporary = tempfile.mkstemp(prefix=".extension-preferences.json.tmp.", dir=parent)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(d, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYEOF
[ "$(stat -c '%a' "$prefs")" = 600 ] || return 1
}

# Firefox owns extension-preferences.json after the initial seed and rewrites
# its legacy JSONFile with the browser's native 0644 mode. Accept that form
# only when the containing profile remains private; NoID Privacy writers still publish
# 0600. Group/other-writable state is never accepted.
profile_mutable_file_safe() {
    local pdir="$1" path="$2" uid pdir_uid path_uid pdir_mode path_mode
    [ -d "$pdir" ] && [ ! -L "$pdir" ] || return 1
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    uid=$(id -u) || return 1
    pdir_uid=$(stat -c '%u' -- "$pdir") || return 1
    path_uid=$(stat -c '%u' -- "$path") || return 1
    pdir_mode=$(stat -c '%a' -- "$pdir") || return 1
    path_mode=$(stat -c '%a' -- "$path") || return 1
    [ "$pdir_uid" = "$uid" ] && [ "$path_uid" = "$uid" ] || return 1
    case "$path_mode" in
        600) return 0 ;;
        640|644) [ "$pdir_mode" = 700 ] ;;
        *) return 1 ;;
    esac
}

validate_noid_marker_pair() {
    local path="$1" begin="$2" end="$3"
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    python3 - "$path" "$begin" "$end" <<'MARKER_VALIDATE_PYEOF'
import sys
path, begin, end = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    lines = [line.rstrip("\n") for line in handle]
begins = [i for i, line in enumerate(lines) if line == begin]
ends = [i for i, line in enumerate(lines) if line == end]
if len(begins) != len(ends) or len(begins) > 1:
    raise SystemExit("invalid marker cardinality")
if begins and begins[0] >= ends[0]:
    raise SystemExit("reversed marker pair")
MARKER_VALIDATE_PYEOF
}

backup_noid_userjs() {
    local path="$1" backup
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    backup=$(mktemp "$(dirname "$path")/user.js.bak-noid-$(date -u +%Y%m%dT%H%M%S)-XXXXXXXX") || return 1
    if ! cp --preserve=mode,timestamps -- "$path" "$backup" || \
       ! sync -- "$backup"; then
        rm -f -- "$backup"
        return 1
    fi
    printf '%s\n' "$backup"
}

# A profile is complete only when all three required profile-local outputs are
# valid. This prevents a partial earlier run from becoming an idempotent skip.
profile_hardening_complete() {
    local name="$1" pdir userjs ubo prefs
    pdir=$(profile_dir_for "$name") || return 1
    userjs="$pdir/user.js"
    ubo="$pdir/extensions/uBlock0@raymondhill.net.xpi"
    prefs="$pdir/extension-preferences.json"
    profile_userjs_supported "$name" "$pdir" || return 1
    validate_ubo_profile_xpi "$ubo" || return 1
    profile_mutable_file_safe "$pdir" "$prefs" || return 1
    python3 - "$prefs" <<'PROFILE_COMPLETE_PYEOF'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
record = data["uBlock0@raymondhill.net"]
assert record["permissions"] == ["internal:privateBrowsingAllowed"]
assert record["origins"] == []
assert record["data_collection"] == []
PROFILE_COMPLETE_PYEOF
}
FF_PROFILES_EOF

chmod 644 /usr/local/lib/noid-privacy/firefox-profiles.sh
chown root:root /usr/local/lib/noid-privacy/firefox-profiles.sh
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/lib/noid-privacy/firefox-profiles.sh 2>/dev/null || true
fi

if ! bash -n /usr/local/lib/noid-privacy/firefox-profiles.sh; then
    log "FAIL: firefox-profiles.sh has syntax errors"
    exit 1
fi
log "  Installed /usr/local/lib/noid-privacy/firefox-profiles.sh"

#------------------------------------------------------------------------------
# Step 5c: /etc/firefox/policies/policies.json (minimal, search only)
#------------------------------------------------------------------------------
# EXACTLY ONE policy ships (SearchEngines.Default=DuckDuckGo): prefs cannot
# set the default engine on Rapid Release (search.json.mozlz4 + Remote
# Settings architecture), and a single minimal policy keeps the "managed by
# your organization" hint out of all main UI (verified). A wider
# policies.json (ExtensionSettings) was rejected for exactly that UI hint.
# SearchEngines works on Rapid Release despite ESR-only forum claims
# (official admin-docs + live test).

install -d -m 755 /etc/firefox/policies
cat > /etc/firefox/policies/policies.json <<'POLICIES_JSON_EOF'
{
  "policies": {
    "SearchEngines": {
      "Default": "DuckDuckGo"
    }
  }
}
POLICIES_JSON_EOF
chmod 644 /etc/firefox/policies/policies.json
chown root:root /etc/firefox/policies/policies.json
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /etc/firefox/policies/policies.json 2>/dev/null || true
fi

# Sanity: verify JSON parseable
if ! python3 -c "import json; json.load(open('/etc/firefox/policies/policies.json'))" 2>/dev/null; then
    log "  FAIL: /etc/firefox/policies/policies.json invalid JSON"
    exit 1
fi
log "  Installed /etc/firefox/policies/policies.json (DuckDuckGo as default search)"

#------------------------------------------------------------------------------
# Step 5d: Empty Fedora default bookmarks without patching Firefox omni.ja
#------------------------------------------------------------------------------
# omni.ja is NEVER patched (zip --update corrupted Firefox chrome/content —
# definitively rejected; tests/16 guards the regression). Instead: M26
# excludes fedora-bookmarks, this step ships an empty /usr/share/bookmarks
# fallback, and Step 5e seeds a valid empty bookmark backup before the first
# profile start. No synthetic distributor processed preference is involved.

mkdir -p /usr/share/bookmarks
cat > /usr/share/bookmarks/default-bookmarks.html <<'EMPTY_BOOKMARKS_EOF'
<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!-- NoID Privacy: empty bookmarks template. Firefox omni.ja is not modified. -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks Menu</H1>

<DL><p>
    <DT><H3 PERSONAL_TOOLBAR_FOLDER="true">Bookmarks Toolbar</H3>
    <DL><p>
    </DL><p>
</DL><p>
EMPTY_BOOKMARKS_EOF
chmod 644 /usr/share/bookmarks/default-bookmarks.html
chown root:root /usr/share/bookmarks/default-bookmarks.html
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/share/bookmarks/default-bookmarks.html 2>/dev/null || true
fi
log "  Installed empty /usr/share/bookmarks/default-bookmarks.html (omni.ja untouched)"

# The signed Firefox RPM's distribution.ini stays byte-pristine. The package
# exclusion, empty fallback and empty initial backup are all NoID Privacy-owned
# surfaces; no recurring Firefox-package mutation is required.
if ! rpm -Vf /usr/lib64/firefox/distribution/distribution.ini >/dev/null 2>&1; then
    log "  FAIL: Firefox distribution.ini differs from its signed RPM payload"
    exit 1
fi
log "  Firefox distribution.ini remains pristine"

#------------------------------------------------------------------------------
# Step 5e: /etc/skel pre-bake — eliminate the first-launch race
#------------------------------------------------------------------------------
# Pre-bake the seeded profile (profiles.ini + user.js + uBO XPI + empty
# bookmarks backup) into /etc/skel so the FIRST launch is already hardened —
# the xdg-autostart setup script races the user's dock-click otherwise.
# The setup script stays for warmup/refresh/drift but is out of the
# 1st-launch critical path. (NO installs.ini — see the comment below.)
log "Step 5e/8: Pre-bake Firefox profile into /etc/skel (1st-launch race fix)"

SKEL_FF_BASE="/etc/skel/.config/mozilla/firefox"
SKEL_FF_PROFILE="$SKEL_FF_BASE/default-release"

mkdir -p "$SKEL_FF_PROFILE/extensions"
mkdir -p "$SKEL_FF_PROFILE/bookmarkbackups"

# user.js — copy from /usr/share/noid-firefox/user.js (already written by Step 3)
cp "$SHARE_DIR/user.js" "$SKEL_FF_PROFILE/user.js"
chmod 600 "$SKEL_FF_PROFILE/user.js"

# uBO XPI — copy from /usr/lib64/mozilla/extensions/{ec8030f7-...}/ (Step 4 fetch)
cp "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" "$SKEL_FF_PROFILE/extensions/uBlock0@raymondhill.net.xpi"
chmod 644 "$SKEL_FF_PROFILE/extensions/uBlock0@raymondhill.net.xpi"

# uBO private-window permission — the profile-local XPI is active in ordinary
# windows without this file, but Firefox requires the explicit per-extension
# record for private windows. This belongs in the same first-launch seed as
# user.js and the XPI; relying on the later XDG setup job left Live sessions
# permanently incomplete because their pre-baked profile otherwise looked
# usable before the job ran.
cat > "$SKEL_FF_PROFILE/extension-preferences.json" <<'SKEL_EXTENSION_PREFS_EOF'
{
  "uBlock0@raymondhill.net": {
    "permissions": [
      "internal:privateBrowsingAllowed"
    ],
    "origins": [],
    "data_collection": []
  }
}
SKEL_EXTENSION_PREFS_EOF
chmod 600 "$SKEL_FF_PROFILE/extension-preferences.json"

# Empty bookmarks JSON backup — Mozilla initPlaces() restores from this on
# first profile launch (places.sqlite missing → DATABASE_STATUS_CREATE → look
# for backup → restore empty tree → 0 Fedora bookmarks).
# Filename must match Mozilla regex: bookmarks-YYYY-MM-DD.json (no hash, simplest valid form).
SKEL_BM_TS=$(date +%s%6N)
SKEL_BM_DATE=$(date +%Y-%m-%d)
cat > "$SKEL_FF_PROFILE/bookmarkbackups/bookmarks-${SKEL_BM_DATE}.json" <<SKEL_BACKUP_EOF
{
  "guid": "root________",
  "title": "",
  "index": 0,
  "dateAdded": ${SKEL_BM_TS},
  "lastModified": ${SKEL_BM_TS},
  "id": 1,
  "typeCode": 2,
  "type": "text/x-moz-place-container",
  "root": "placesRoot",
  "children": [
    {"guid": "menu________", "title": "menu", "index": 0, "dateAdded": ${SKEL_BM_TS}, "lastModified": ${SKEL_BM_TS}, "id": 2, "typeCode": 2, "type": "text/x-moz-place-container", "root": "bookmarksMenuFolder", "children": []},
    {"guid": "toolbar_____", "title": "toolbar", "index": 1, "dateAdded": ${SKEL_BM_TS}, "lastModified": ${SKEL_BM_TS}, "id": 3, "typeCode": 2, "type": "text/x-moz-place-container", "root": "toolbarFolder", "children": []},
    {"guid": "tags________", "title": "tags", "index": 2, "dateAdded": ${SKEL_BM_TS}, "lastModified": ${SKEL_BM_TS}, "id": 4, "typeCode": 2, "type": "text/x-moz-place-container", "root": "tagsFolder", "children": []},
    {"guid": "unfiled_____", "title": "unfiled", "index": 3, "dateAdded": ${SKEL_BM_TS}, "lastModified": ${SKEL_BM_TS}, "id": 5, "typeCode": 2, "type": "text/x-moz-place-container", "root": "unfiledBookmarksFolder", "children": []},
    {"guid": "mobile______", "title": "mobile", "index": 4, "dateAdded": ${SKEL_BM_TS}, "lastModified": ${SKEL_BM_TS}, "id": 6, "typeCode": 2, "type": "text/x-moz-place-container", "root": "mobileFolder", "children": []}
  ]
}
SKEL_BACKUP_EOF
chmod 644 "$SKEL_FF_PROFILE/bookmarkbackups/bookmarks-${SKEL_BM_DATE}.json"

# profiles.ini — point to our pre-baked profile
cat > "$SKEL_FF_BASE/profiles.ini" <<'SKEL_PROFILES_EOF'
[Profile0]
Name=default-release
IsRelative=1
Path=default-release
Default=1

[General]
StartWithLastProfile=1
Version=2
SKEL_PROFILES_EOF
chmod 644 "$SKEL_FF_BASE/profiles.ini"

# Do not ship installs.ini. Firefox 67+ computes its install-
# hash from the canonical firefox executable path. Pre-baking installs.ini
# with a hand-rolled hash like [NoID000000000000] does NOT match the real
# computed hash — Firefox treats it as foreign and either falls back to
# profiles.ini Default=1 (good) OR creates a new profile and writes its OWN
# [REAL_HASH] entry to installs.ini (bad). We let Firefox auto-write on first
# launch: it reads our profiles.ini Default=1, uses default-release, and
# generates installs.ini with the real install-hash + Locked=1 itself. From
# the second launch onwards, installs.ini correctly pins our profile.

# Tree perms: parent dirs stay traversable (755), but the profile directory
# itself is 700 — once the user runs Firefox it holds cookies.sqlite /
# key4.db / cert9.db / places.sqlite / session state, which must not be
# world-readable. Matches the Module 34 playground-profile convention.
chown -R root:root "$SKEL_FF_BASE"
chmod -R go-w "$SKEL_FF_BASE"
find "$SKEL_FF_BASE" -type d -exec chmod 755 {} \;
chmod 700 "$SKEL_FF_PROFILE"

log "  Pre-baked /etc/skel/.config/mozilla/firefox/default-release/ (user.js + uBO XPI + PB permission + empty bookmarks)"

# /etc/skel is consulted only at USER-CREATION time — liveuser already
# exists before %post, so mirror the pre-bake directly into any existing
# real user home (uid >= 1000). New users created later get it via skel.
log "  Mirroring pre-bake to existing real users (Live-mode liveuser + similar)"
for user_home in /home/*; do
    [ -d "$user_home" ] || continue
    user_name=$(basename "$user_home")
    # Skip system home dirs that aren't real users (uid < 1000)
    user_uid=$(id -u "$user_name" 2>/dev/null) || continue
    [ "$user_uid" -ge 1000 ] || continue
    user_gid=$(id -g "$user_name" 2>/dev/null) || continue

    target_base="$user_home/.config/mozilla/firefox"
    for user_path in \
        "$user_home/.config" \
        "$user_home/.config/mozilla" \
        "$target_base"; do
        if [ -L "$user_path" ] || { [ -e "$user_path" ] && [ ! -d "$user_path" ]; }; then
            log "  FAIL: unsafe existing Firefox seed path: $user_path"
            exit 1
        fi
    done
    install -d -m 0700 -o "$user_uid" -g "$user_gid" "$user_home/.config"
    install -d -m 0700 -o "$user_uid" -g "$user_gid" "$user_home/.config/mozilla"
    install -d -m 0700 -o "$user_uid" -g "$user_gid" "$target_base"
    install -d -m 0700 -o "$user_uid" -g "$user_gid" \
        "$target_base/default-release/extensions" \
        "$target_base/default-release/bookmarkbackups"
    # Use cp -a to preserve mode + timestamps. The trailing /. on source
    # copies CONTENTS of the dir (including dotfiles) into existing target,
    # which avoids the "subdir nesting" that plain `cp -r src dst` would do
    # if dst already exists.
    cp -a "$SKEL_FF_BASE/profiles.ini" "$target_base/profiles.ini"
    cp -a "$SKEL_FF_BASE/default-release/user.js" "$target_base/default-release/user.js"
    cp -a "$SKEL_FF_BASE/default-release/extensions/uBlock0@raymondhill.net.xpi" \
          "$target_base/default-release/extensions/uBlock0@raymondhill.net.xpi"
    cp -a "$SKEL_FF_BASE/default-release/extension-preferences.json" \
          "$target_base/default-release/extension-preferences.json"
    cp -a "$SKEL_FF_BASE/default-release/bookmarkbackups/." \
          "$target_base/default-release/bookmarkbackups/"
    chown -R "$user_uid:$user_gid" "$user_home/.config/mozilla/firefox"
    # Profile dir 700 — the mkdir -p above created it under the %post umask;
    # force owner-only so the profile (future cookies/keys/history) is private.
    chmod 700 "$target_base/default-release"
    log "    Mirrored to $user_home (uid=$user_uid)"
done

log "  1st-launch race eliminated: liveuser + future installed users get seeded profile"

#------------------------------------------------------------------------------
# Step 6: Install first-run setup script + XDG autostart entry
#------------------------------------------------------------------------------
log "Step 6/8: Install first-run setup script + XDG autostart entry"

cat > "$LOCAL_BIN_DIR/noid-firefox-setup.sh" <<'SETUPSCRIPT_EOF'
#!/bin/bash
# NoID Privacy Workstation 44 - Firefox Hardening First-Run Setup v2
# Module 16 — silent-launch + per-profile deployment.
#
# Root cause of the former first-launch bug: the setup script created a stub profile
# at .config/mozilla/firefox/default-release/ + minimal profiles.ini. Firefox 150
# *ignored* that on first launch (no [Install<HASH>] section in installs.ini)
# and created its OWN hash-based profile (e.g. tn0ohv56.default-release-1) +
# wrote installs.ini pointing to its hash-profile. Our user.js + XPI landed in
# the orphaned default-release/ dir → never used.
#
# v2 fix: let Firefox create its profile FIRST (silent --headless launch),
# detect the active profile from installs.ini, THEN drop user.js + uBO
# Private-Browsing permission in.
#
# Flow:
#   1. Self-detach via setsid and take a per-user, non-blocking lock
#   2. Validate the exact canonical base/consent-overlay + uBO source bytes
#   3. Detect active profile via installs.ini Default= (or profiles.ini fallback).
#      If none, run `firefox --headless --no-remote --new-instance` for ~6s to
#      force profile creation, then re-detect.
#   4. Refuse to race Firefox or overwrite noncanonical user configuration
#   5. Atomically install required files without deleting history, bookmarks,
#      favicons, backups, window state, or any profile directory
#   6. Validate every required postcondition and atomically publish an exact,
#      content-bound state record; an interrupted run is safely retryable

set -euo pipefail

case "$#" in
    0) ;;
    1) [ "$1" = --detached ] || {
        printf '%s\n' 'ERROR: noid-firefox-setup accepts only zero arguments or --detached' >&2
        exit 2
    } ;;
    *)
        printf '%s\n' 'ERROR: noid-firefox-setup accepts only zero arguments or --detached' >&2
        exit 2
        ;;
esac

CMDLINE_FILE=/proc/cmdline
if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
    CMDLINE_FILE=${NOID_TEST_CMDLINE_FILE:?NOID_TEST_CMDLINE_FILE is required in test mode}
fi

# Skip in live-ISO mode. Per-user Firefox profile setup
# in live overlay-fs is wasted work — overlay doesn't persist to installed
# system, plus Firefox setup running during Anaconda install confuses UX.
# Installed system has no `rd.live.image` cmdline, so script runs normally.
if grep -q "rd.live.image" "$CMDLINE_FILE" 2>/dev/null; then
    logger -t "noid-firefox-setup" "skip: rd.live.image (live-ISO mode)" 2>/dev/null || true
    exit 0
fi

if [[ "${1:-}" != "--detached" ]]; then
    exec setsid "$0" --detached &>/dev/null &
    exit 0
fi

FIREFOX_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/mozilla/firefox"
INSTALLS_INI="$FIREFOX_CONFIG/installs.ini"
PROFILES_INI="$FIREFOX_CONFIG/profiles.ini"
SOURCE_DIR="/usr/share/noid-firefox"
UBO_XPI="/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/uBlock0@raymondhill.net.xpi"
STATE_FILE="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy/firefox-setup.done"
STATE_DIR="$(dirname "$STATE_FILE")"
LOCK_FILE="$STATE_DIR/firefox-profile-operations.lock"
UBO_SHA256="bccc51a773150af4af6e1fd62c7bfdeb7238b79ff2381b998fa9f2e38f64786a"
UBO_SIZE_EXPECTED=4679419
WEBEXT_VALIDATOR="/usr/local/lib/noid-privacy/validate-webextension.py"
PROFILE_HELPER="/usr/local/lib/noid-privacy/firefox-profiles.sh"
LOG_TAG="noid-firefox-setup"

log() { logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "[$LOG_TAG] $*" >&2; }
notify() {
    notify-send --urgency="$1" --icon="$2" "$3" "$4" 2>/dev/null || true
}

if [[ ! -f "$PROFILE_HELPER" ]] || [[ -L "$PROFILE_HELPER" ]]; then
    log "FATAL: shared Firefox profile helper is missing or unsafe"
    exit 1
fi
# The FF_PROFILES_EOF library is extracted and linted independently; its
# installed absolute path does not exist in the temporary lint workspace.
# shellcheck source=/dev/null
. "$PROFILE_HELPER"

# XDG paths are valid only when absolute. Reject malformed input before a
# headless Firefox launch can create state at a path different from the one
# this setup transaction will later validate.
if ! python3 - "$FIREFOX_CONFIG" <<'FIREFOX_ROOT_PATH_PYEOF'
import os
import sys

path = sys.argv[1]
if not os.path.isabs(path) or os.path.normpath(path) != path:
    raise SystemExit("Firefox root is not an absolute normalized XDG path")
FIREFOX_ROOT_PATH_PYEOF
then
    log "FATAL: invalid XDG Firefox configuration root"
    exit 1
fi

# Resolve one detected active profile only when it remains inside the canonical
# current-user Firefox root. Firefox supports external absolute profiles, but
# profiles.ini/installs.ini is user-controlled metadata and is not authority
# for this automatic setup job to write an arbitrary filesystem path.
validate_active_profile_boundary() {
    python3 - "$FIREFOX_CONFIG" "$1" <<'ACTIVE_PROFILE_BOUNDARY_PYEOF'
import os
import stat
import sys

raw_root, raw_profile = sys.argv[1:]
uid = os.geteuid()

def reject(message):
    print(f"unsafe active Firefox profile: {message}", file=sys.stderr)
    raise SystemExit(1)

for label, path in (("Firefox root", raw_root), ("profile", raw_profile)):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        reject(f"{label} is not an absolute normalized path")

if raw_profile == raw_root:
    reject("profile resolves to the Firefox root itself")
try:
    if os.path.commonpath((raw_root, raw_profile)) != raw_root:
        reject("profile is outside the Firefox root")
except ValueError:
    reject("profile and Firefox root do not share a path domain")

root_stat = os.lstat(raw_root)
if (not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode)
        or root_stat.st_uid != uid or root_stat.st_mode & 0o022):
    reject("Firefox root ownership, mode or type is unsafe")

relative = os.path.relpath(raw_profile, raw_root)
current = raw_root
for component in relative.split(os.sep):
    if component in {"", ".", ".."}:
        reject("profile has an unsafe path component")
    current = os.path.join(current, component)
    component_stat = os.lstat(current)
    if stat.S_ISLNK(component_stat.st_mode):
        reject("profile path contains a symbolic link")

profile_stat = os.lstat(raw_profile)
if (not stat.S_ISDIR(profile_stat.st_mode)
        or profile_stat.st_uid != uid or profile_stat.st_mode & 0o022):
    reject("profile ownership, mode or type is unsafe")

root_real = os.path.realpath(raw_root)
profile_real = os.path.realpath(raw_profile)
try:
    if os.path.commonpath((root_real, profile_real)) != root_real:
        reject("canonical profile escapes the canonical Firefox root")
except ValueError:
    reject("canonical profile and root do not share a path domain")
print(profile_real)
ACTIVE_PROFILE_BOUNDARY_PYEOF
}

# Install one reviewed regular file through a same-directory temporary file.
# Same-filesystem rename prevents a crash from publishing partial bytes.
atomic_install() {
    local source="$1" destination="$2" mode="$3" parent temporary
    parent="$(dirname "$destination")"
    [[ -f "$source" ]] && [[ ! -L "$source" ]] || return 1
    [[ -d "$parent" ]] && [[ ! -L "$parent" ]] || return 1
    [[ ! -L "$destination" ]] || return 1
    if [[ -e "$destination" ]] && [[ ! -f "$destination" ]]; then
        return 1
    fi
    temporary=$(mktemp "$parent/.$(basename "$destination").tmp.XXXXXXXX") || return 1
    if ! install -m "$mode" -- "$source" "$temporary" || \
       ! sync -- "$temporary" || \
       ! mv -fT -- "$temporary" "$destination" || \
       ! sync -- "$parent"; then
        rm -f -- "$temporary"
        return 1
    fi
}

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
[ ! -L "$LOCK_FILE" ] || { log "FATAL: setup lock is symlinked"; exit 1; }
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log "another setup instance holds the per-user lock; retry on next login"
    exit 75
fi

if [[ ! -f "$SOURCE_DIR/user.js" ]] || [[ -L "$SOURCE_DIR/user.js" ]]; then
    log "FATAL: $SOURCE_DIR/user.js not found"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "Source $SOURCE_DIR/user.js not found. Setup aborted."
    exit 1
fi
if [[ ! -f "$UBO_XPI" ]] || [[ -L "$UBO_XPI" ]]; then
    log "FATAL: required regular uBlock Origin XPI is unavailable"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "Required uBlock Origin package is unavailable. Setup aborted without a success state."
    exit 1
fi
if [[ "$(stat -c '%s' "$UBO_XPI")" -ne "$UBO_SIZE_EXPECTED" ]] || \
   [[ "$(sha256sum "$UBO_XPI" | awk '{print $1}')" != "$UBO_SHA256" ]]; then
    log "FATAL: required uBlock Origin XPI differs from the reviewed bytes"
    exit 1
fi
if [[ ! -x "$WEBEXT_VALIDATOR" ]] || \
   ! "$WEBEXT_VALIDATOR" "$UBO_XPI" uBlock0@raymondhill.net \
        - 1 - >/dev/null; then
    log "FATAL: required uBlock Origin XPI fails structure/identity/signature validation"
    exit 1
fi

# ---------------------------------------------------------------------------
# Detect active profile (NoID Privacy v2: post-Firefox-launch detection)
# Section in installs.ini is bare hex hash like [11457493C5A56847], NOT
# [Install<HASH>]. Match any [<hex>] section with a Default= line.
# ---------------------------------------------------------------------------
detect_active_profile() {
    local active=""

    # Method A: installs.ini per-Install Default=
    if [[ -f "$INSTALLS_INI" ]]; then
        active=$(awk '
            /^\[[0-9A-Fa-f]+\]/ { in_install=1; next }
            /^\[/                { in_install=0; next }
            /^Default=/ {
                if (in_install) { sub("^Default=", ""); print; exit }
            }
        ' "$INSTALLS_INI")
        if [[ -n "$active" ]]; then
            [[ "$active" == /* ]] || active="$FIREFOX_CONFIG/$active"
            if [[ -d "$active" ]]; then
                echo "$active"
                return 0
            fi
        fi
    fi

    # Method B: profiles.ini Default=1 fallback. Per-section state flushes at
    # every section header (and at END), so an earlier [ProfileN] carrying
    # Default=1 wins even when later sections follow it; awk `exit` would
    # still run END, hence the printed-once flag.
    if [[ -f "$PROFILES_INI" ]]; then
        active=$(awk '
            /^\[/ { if (!done && is_default && path) { print path; done=1 }
                    is_default=0; path="" }
            /^Path=/      { sub("^Path=", ""); path=$0 }
            /^Default=1/  { is_default=1 }
            END { if (!done && is_default && path) print path }
        ' "$PROFILES_INI")
        if [[ -n "$active" ]]; then
            [[ "$active" == /* ]] || active="$FIREFOX_CONFIG/$active"
            if [[ -d "$active" ]]; then
                echo "$active"
                return 0
            fi
        fi
    fi

    # Method C: scan for hash-named or plain default-release profile dir
    for active in "$FIREFOX_CONFIG"/*.default-release "$FIREFOX_CONFIG"/*.default \
                  "$FIREFOX_CONFIG/default-release" "$FIREFOX_CONFIG/default"; do
        if [[ -d "$active" ]]; then
            echo "$active"
            return 0
        fi
    done

    return 1
}

ACTIVE_PROFILE=""
ACTIVE_PROFILE=$(detect_active_profile 2>/dev/null) || true

if [[ -n "$ACTIVE_PROFILE" ]]; then
    log "active profile detected without launch: $ACTIVE_PROFILE"
fi

# If no profile yet, force Firefox to create one via headless launch
if [[ -z "$ACTIVE_PROFILE" ]]; then
    log "no profile yet → silent-launch firefox to force creation"

    if firefox_process_active; then
        log "firefox already running, defer + retry"
        sleep 3
        ACTIVE_PROFILE=$(detect_active_profile 2>/dev/null) || true
    else
        FF_PID=""
        # Silent-launch on about:newtab (NOT about:blank) so
        # Activity Stream React app warm-starts + caches its initial state.
        # Otherwise user's first real launch shows blank page (no logo, no
        # search box, no tile grid) and requires a 2nd launch to render.
        # This resolves the observed first-launch blank-page symptom.
        timeout 8 env MOZ_HEADLESS=1 firefox --headless --no-remote --new-instance about:newtab \
            >/dev/null 2>&1 &
        FF_PID=$!
        sleep 6
        kill "$FF_PID" 2>/dev/null || true
        wait "$FF_PID" 2>/dev/null || true
        sleep 2  # allow flush

        ACTIVE_PROFILE=$(detect_active_profile 2>/dev/null) || true
    fi
fi

if [[ -z "$ACTIVE_PROFILE" ]]; then
    log "FATAL: could not detect Firefox profile after silent-launch"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "Could not detect Firefox profile. Setup aborted — please open Firefox manually once, then re-run noid-firefox-setup.sh."
    exit 1
fi

if ! ACTIVE_PROFILE=$(validate_active_profile_boundary "$ACTIVE_PROFILE"); then
    log "FATAL: active profile is outside the safe automatic-write boundary"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "The detected Firefox profile is unsafe for automatic setup. No profile bytes were changed."
    exit 1
fi

if [[ ! -w "$ACTIVE_PROFILE" ]]; then
    log "FATAL: profile $ACTIVE_PROFILE not writable"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "Firefox profile $ACTIVE_PROFILE not writable. Setup aborted."
    exit 1
fi

SOURCE_USERJS_SHA256=$(sha256sum "$SOURCE_DIR/user.js" | awk '{print $1}')
DRM_OVERLAY="$SOURCE_DIR/user-drm-overrides.js"
DRM_SENTINEL="$ACTIVE_PROFILE/.noid-drm-enabled"
expected_state() {
    printf '%s\n' \
        NOID_FIREFOX_SETUP_V1 \
        "profile=$ACTIVE_PROFILE" \
        "userjs_sha256=$SOURCE_USERJS_SHA256" \
        "ubo_sha256=$UBO_SHA256"
}

# Return disabled/enabled only for the two exact supported consent states.
# Malformed/symlinked state is an error and never causes a silent overwrite.
supported_drm_state() {
    local mode owner
    if [[ ! -e "$DRM_SENTINEL" ]] && [[ ! -L "$DRM_SENTINEL" ]]; then
        printf '%s\n' disabled
        return 0
    fi
    [[ -f "$DRM_SENTINEL" ]] && [[ ! -L "$DRM_SENTINEL" ]] || return 1
    mode=$(stat -c '%a' "$DRM_SENTINEL") || return 1
    owner=$(stat -c '%u' "$DRM_SENTINEL") || return 1
    [[ "$mode" == 600 ]] && [[ "$owner" -eq "$(id -u)" ]] || return 1
    grep -qx 'NOID_FIREFOX_DRM_OPT_IN_V1' "$DRM_SENTINEL" || return 1
    [[ -f "$DRM_OVERLAY" ]] && [[ ! -L "$DRM_OVERLAY" ]] || return 1
    printf '%s\n' enabled
}

supported_userjs_matches() {
    [[ -f "$ACTIVE_PROFILE/user.js" ]] && \
        [[ ! -L "$ACTIVE_PROFILE/user.js" ]] || return 1
    profile_userjs_supported default-release "$ACTIVE_PROFILE"
}

install_supported_userjs() {
    local state temporary
    # A byte-exact shared-library composition may include either supported
    # compatibility opt-in. Preserve it instead of rewriting it on login.
    if supported_userjs_matches; then
        return 0
    fi
    state=$(supported_drm_state) || return 1
    if [[ "$state" == disabled ]]; then
        atomic_install "$SOURCE_DIR/user.js" "$ACTIVE_PROFILE/user.js" 600
        return
    fi
    temporary=$(mktemp "$ACTIVE_PROFILE/.user.js.setup-drm.XXXXXXXX") || return 1
    if ! cat -- "$SOURCE_DIR/user.js" "$DRM_OVERLAY" > "$temporary" || \
       ! chmod 600 "$temporary" || \
       ! atomic_install "$temporary" "$ACTIVE_PROFILE/user.js" 600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary"
}

required_outputs_valid() {
    local installed_ubo="$ACTIVE_PROFILE/extensions/uBlock0@raymondhill.net.xpi"
    local extension_preferences="$ACTIVE_PROFILE/extension-preferences.json"
    # The installed uBO XPI is validated for archive structure, exact identity
    # and Mozilla signature-container presence. After the reviewed seed, the
    # profile copy is user-owned state: the
    # privacy defaults disable automatic add-on update checks
    # (extensions.update.enabled=false — no background calls to Mozilla),
    # so a newer uBO lands only through the user-started M25 Update All
    # workflow. Re-pinning the profile bytes here would downgrade any such
    # update at the next login. The seed SOURCE below
    # /usr/lib64/mozilla remains byte-pinned.
    supported_userjs_matches && \
    [[ -d "$ACTIVE_PROFILE/extensions" ]] && [[ ! -L "$ACTIVE_PROFILE/extensions" ]] && \
    [[ -f "$installed_ubo" ]] && [[ ! -L "$installed_ubo" ]] && \
    "$WEBEXT_VALIDATOR" "$installed_ubo" uBlock0@raymondhill.net \
        - 1 - >/dev/null && \
    [[ -f "$extension_preferences" ]] && [[ ! -L "$extension_preferences" ]] && \
    python3 - "$extension_preferences" <<'OUTPUT_VALIDATION_PYEOF'
import json, os, stat, sys
path = sys.argv[1]
file_stat = os.lstat(path)
profile_stat = os.lstat(os.path.dirname(path))
mode = stat.S_IMODE(file_stat.st_mode)
profile_mode = stat.S_IMODE(profile_stat.st_mode)
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)
assert file_stat.st_uid == os.geteuid()
assert profile_stat.st_uid == os.geteuid()
assert mode == 0o600 or (mode in {0o640, 0o644} and profile_mode == 0o700)
assert data["uBlock0@raymondhill.net"]["permissions"] == ["internal:privateBrowsingAllowed"]
assert data["uBlock0@raymondhill.net"]["origins"] == []
assert data["uBlock0@raymondhill.net"]["data_collection"] == []
OUTPUT_VALIDATION_PYEOF
}
if [[ -e "$STATE_FILE" ]] || [[ -L "$STATE_FILE" ]]; then
    if [[ -f "$STATE_FILE" ]] && [[ ! -L "$STATE_FILE" ]] && \
       cmp -s "$STATE_FILE" <(expected_state) && required_outputs_valid; then
        log "exact setup state and required outputs are valid, skip"
        exit 0
    fi
    [[ ! -L "$STATE_FILE" ]] || { log "FATAL: setup state is symlinked"; exit 1; }
    log "stale/incomplete setup state found; rechecking safely without deleting profile data"
fi

# Do not race a user's running browser. The setup-owned headless process, when
# needed, has already been terminated and waited above.
if firefox_process_active; then
    log "Firefox is running; no profile bytes changed, retry on next login"
    exit 75
fi

# An existing noncanonical user.js is user-owned configuration. Automatic
# first-login setup never overwrites it; the explicit harden-profile --force
# workflow is the reviewable replacement path.
if [[ -e "$ACTIVE_PROFILE/user.js" ]] || [[ -L "$ACTIVE_PROFILE/user.js" ]]; then
    [[ -f "$ACTIVE_PROFILE/user.js" ]] && [[ ! -L "$ACTIVE_PROFILE/user.js" ]] || {
        log "FATAL: active profile user.js is non-regular or symlinked"
        exit 1
    }
    if ! supported_userjs_matches; then
        log "FATAL: existing noncanonical user.js preserved; explicit --force review required"
        notify critical dialog-error "NoID Privacy Firefox Setup Needs Review" \
            "Existing Firefox user.js was preserved. Run noid-firefox-harden-profile --force only after review."
        exit 1
    fi
fi

# Never move or delete a profile directory automatically. Filename/sentinel
# heuristics cannot prove that a restored or partially initialized directory is
# disposable. Reconcile registration metadata only; every directory and every
# user data file remains byte-addressable at its original path. Firefox stores
# paths relative to its configuration root, so preserve every nested component.
if ! ACTIVE_RELATIVE=$(python3 - "$FIREFOX_CONFIG" "$ACTIVE_PROFILE" <<'ACTIVE_RELATIVE_PYEOF'
import os
import sys

root, profile = map(os.path.realpath, sys.argv[1:])
try:
    if os.path.commonpath((root, profile)) != root:
        raise SystemExit("active profile is outside the Firefox root")
except ValueError as exc:
    raise SystemExit("active profile and Firefox root have incompatible paths") from exc
relative = os.path.relpath(profile, root)
if relative in {"", ".", ".."} or relative.startswith(f"..{os.sep}"):
    raise SystemExit("active profile has no safe relative registration path")
print(relative)
ACTIVE_RELATIVE_PYEOF
); then
    log "FATAL: active profile registration path is unsafe"
    exit 1
fi
log "profile-data preservation active — no orphan directory mutation"

# Reconcile profiles.ini without deleting unrelated registrations.
if [[ -L "$PROFILES_INI" ]] || \
   { [[ -e "$PROFILES_INI" ]] && [[ ! -f "$PROFILES_INI" ]]; }; then
    log "FATAL: profiles.ini is non-regular or symlinked"
    exit 1
fi
if ! python3 - "$PROFILES_INI" "$FIREFOX_CONFIG" "$ACTIVE_RELATIVE" <<'PROFILE_RECONCILE_PYEOF'
import configparser
import os
import stat
import sys
import tempfile

ini_path, config_dir, active_relative = sys.argv[1], sys.argv[2], sys.argv[3]

cp = configparser.ConfigParser(strict=False, interpolation=None)
cp.optionxform = str  # preserve key case
cp.read(ini_path)

profile_sections = [s for s in cp.sections() if s.startswith("Profile")]
active_section = None

for sec in list(profile_sections):
    path = cp.get(sec, "Path", fallback="")
    is_relative = cp.get(sec, "IsRelative", fallback="1") != "0"
    full_path = os.path.join(config_dir, path) if is_relative else path
    full_path = os.path.normpath(full_path)
    if is_relative and os.path.normpath(path) == active_relative:
        active_section = sec
        continue

    # Remove only a proven Firefox-generated default registration whose path
    # is already absent. No directory is moved or deleted here. Custom names
    # and every existing profile remain registered, including absolute paths.
    leaf = os.path.basename(os.path.normpath(path))
    name = cp.get(sec, "Name", fallback="")
    generated_default = (
        name in {"default", "default-release"}
        and (leaf in {"default", "default-release"}
             or leaf.endswith(".default")
             or leaf.endswith(".default-release"))
    )
    if generated_default and not os.path.isdir(full_path):
        cp.remove_section(sec)

if active_section is None:
    used = {
        int(s[7:]) for s in cp.sections()
        if s.startswith("Profile") and s[7:].isdigit()
    }
    index = 0
    while index in used:
        index += 1
    active_section = f"Profile{index}"
    cp.add_section(active_section)

for sec in [s for s in cp.sections() if s.startswith("Profile")]:
    if sec != active_section:
        cp.remove_option(sec, "Default")
        if cp.get(sec, "Name", fallback="") == "default-release":
            raise SystemExit(
                f"conflicting non-orphan default-release registration: {sec}"
            )

cp.set(active_section, "Name", "default-release")
cp.set(active_section, "IsRelative", "1")
cp.set(active_section, "Path", active_relative)
cp.set(active_section, "Default", "1")

old_mode = stat.S_IMODE(os.stat(ini_path).st_mode) if os.path.exists(ini_path) else 0o600
fd, tmp_path = tempfile.mkstemp(prefix=".profiles.ini.", dir=config_dir, text=True)
try:
    with os.fdopen(fd, "w") as f:
        # Mozilla profiles.ini uses key=value without added spaces.
        cp.write(f, space_around_delimiters=False)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_path, old_mode)
    os.replace(tmp_path, ini_path)
finally:
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)

print(
    f"profiles.ini reconciled: {active_section} -> {active_relative}; "
    "unrelated registrations preserved"
)
PROFILE_RECONCILE_PYEOF
then
    log "FAIL: profiles.ini reconciliation failed"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "profiles.ini could not be reconciled safely. No unrelated profile registration was deleted."
    exit 1
fi

# Post-rewrite hard-validation: locate the named launcher profile by section;
# the first [Profile*] entry may legitimately be an unrelated custom profile.
if ! PROFILE_CONTRACT=$(python3 - "$PROFILES_INI" "$ACTIVE_RELATIVE" <<'PROFILE_VALIDATE_PYEOF'
import configparser, sys
path, active_relative = sys.argv[1], sys.argv[2]
cp = configparser.ConfigParser(strict=False, interpolation=None)
cp.optionxform = str
with open(path, encoding="utf-8") as handle:
    cp.read_file(handle)
matches = [
    section for section in cp.sections()
    if section.startswith("Profile")
    and cp.get(section, "Name", fallback="") == "default-release"
]
if len(matches) != 1:
    raise SystemExit(f"expected one default-release registration, found {len(matches)}")
section = matches[0]
actual_path = cp.get(section, "Path", fallback="")
is_relative = cp.get(section, "IsRelative", fallback="")
is_default = cp.get(section, "Default", fallback="")
if (actual_path, is_relative, is_default) != (active_relative, "1", "1"):
    raise SystemExit(
        f"{section}: Path={actual_path!r}, IsRelative={is_relative!r}, "
        f"Default={is_default!r}"
    )
print(f"{section}: Name=default-release, Path={actual_path}, Default=1")
PROFILE_VALIDATE_PYEOF
); then
    log "FAIL: profiles.ini validation failed"
    log "      launcher 'firefox -P default-release' would not resolve to active profile"
    notify critical dialog-error "NoID Privacy Firefox Setup Error" \
        "profiles.ini validation failed. Setup aborted without changing profile data."
    exit 1
fi
log "profiles.ini validated: $PROFILE_CONTRACT"

log "registration reconciliation complete; profile directories untouched"

# ---------------------------------------------------------------------------
# Install the reviewed configuration and extension without mutating user data
# ---------------------------------------------------------------------------
if ! install_supported_userjs; then
    log "FATAL: atomic user.js install failed"
    exit 1
fi
log "installed supported user.js state → $ACTIVE_PROFILE/user.js"

# xulstore.json is user-owned window state. Seed it only when absent, using a
# non-replacing hard-link publication so a concurrent creator is preserved.
# Established window geometry is never overwritten.
XULSTORE="$ACTIVE_PROFILE/xulstore.json"
if [[ -e "$XULSTORE" ]] || [[ -L "$XULSTORE" ]]; then
    if [[ ! -f "$XULSTORE" ]] || [[ -L "$XULSTORE" ]]; then
        log "FATAL: xulstore.json is non-regular or symlinked"
        exit 1
    fi
    log "preserved existing xulstore.json byte-for-byte"
else
    XULSTORE_TMP=$(mktemp "$ACTIVE_PROFILE/.xulstore.json.tmp.XXXXXXXX")
    printf '%s\n' '{"chrome://browser/content/browser.xhtml":{"main-window":{"sizemode":"maximized","screenX":"0","screenY":"0","width":"1366","height":"768"}}}' > "$XULSTORE_TMP"
    chmod 600 "$XULSTORE_TMP"
    sync -- "$XULSTORE_TMP"
    if ln -- "$XULSTORE_TMP" "$XULSTORE"; then
        rm -f -- "$XULSTORE_TMP"
        sync -- "$ACTIVE_PROFILE"
        log "seeded xulstore.json for a previously uninitialized profile"
    else
        rm -f -- "$XULSTORE_TMP"
        if [[ -f "$XULSTORE" ]] && [[ ! -L "$XULSTORE" ]]; then
            log "preserved concurrently created xulstore.json"
        else
            log "FATAL: could not safely seed xulstore.json"
            exit 1
        fi
    fi
fi

# Install uBlock Origin XPI profile-local using the verified mechanism.
# Mozilla's
# distribution-bundled auto-install does NOT register the XPI in
# extensions.json under FF150 — extensions.json stayed empty across
# all tested launch modes. Profile-local copy + extensions.autoDisableScopes=10
# (Profile bit 1 NOT in the disable-list) is
# the verified working path.
#
# When the user clicks Firefox next, ExtensionManager scans
# profile/extensions/ at full-init startup, registers uBO (Profile-scope
# = bit 1, NOT in autoDisableScopes=10 disable mask), and PB permission
# is already granted via extension-preferences.json.
EXTENSIONS_DIR_PROFILE="$ACTIVE_PROFILE/extensions"
if [[ -L "$EXTENSIONS_DIR_PROFILE" ]] || \
   { [[ -e "$EXTENSIONS_DIR_PROFILE" ]] && [[ ! -d "$EXTENSIONS_DIR_PROFILE" ]]; }; then
    log "FATAL: profile extensions path is non-directory or symlinked"
    exit 1
fi
install -d -m 700 "$EXTENSIONS_DIR_PROFILE"
UBO_TARGET="$EXTENSIONS_DIR_PROFILE/uBlock0@raymondhill.net.xpi"
if [[ -L "$UBO_TARGET" ]]; then
    log "FATAL: profile uBO XPI is symlinked"
    exit 1
fi
if [[ -f "$UBO_TARGET" ]]; then
    # Seed-once contract: an existing profile XPI is user-owned state
    # (M25's user-triggered signed add-on updates land at this exact path).
    # Preserve only a structurally valid, correctly identified, Mozilla-signed
    # payload; never bless an arbitrary pre-positioned file as setup-complete.
    if ! "$WEBEXT_VALIDATOR" "$UBO_TARGET" uBlock0@raymondhill.net \
            - 1 - >/dev/null; then
        log "FATAL: existing profile uBO XPI fails identity/signature validation"
        exit 1
    fi
    log "preserved existing validated uBO XPI → $UBO_TARGET"
elif ! atomic_install "$UBO_XPI" "$UBO_TARGET" 644; then
    log "FATAL: atomic uBlock Origin install failed"
    exit 1
else
    log "installed reviewed uBO XPI → $UBO_TARGET"
fi
if ! "$WEBEXT_VALIDATOR" "$UBO_TARGET" uBlock0@raymondhill.net \
        - 1 - >/dev/null; then
    log "FATAL: installed profile uBO XPI fails final validation"
    exit 1
fi

# Fresh accounts already receive the empty initial bookmark backup from
# /etc/skel before Firefox starts; M26 excludes the Fedora bookmark package
# and the system fallback is empty. An established profile's places/favicons
# databases and every bookmark backup are user data: this automatic refresh
# never touches them.
log "preserved places, favicons, bookmark backups, and all other profile data"

EXT_PREFS="$ACTIVE_PROFILE/extension-preferences.json"
if [[ -L "$EXT_PREFS" ]] || { [[ -e "$EXT_PREFS" ]] && [[ ! -f "$EXT_PREFS" ]]; }; then
    log "FATAL: extension-preferences.json is non-regular or symlinked"
    exit 1
fi
if ! python3 - "$EXT_PREFS" <<'PYEOF'
import json, os, stat, sys, tempfile
path = sys.argv[1]
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"refusing to overwrite invalid {path}: {exc}", file=sys.stderr)
        sys.exit(1)
else:
    d = {}
if not isinstance(d, dict):
    print(f"refusing to overwrite non-object JSON in {path}", file=sys.stderr)
    sys.exit(1)
d["uBlock0@raymondhill.net"] = {
    "permissions": ["internal:privateBrowsingAllowed"],
    "origins": [],
    "data_collection": []
}
parent = os.path.dirname(path)
fd, temporary = tempfile.mkstemp(prefix=".extension-preferences.json.tmp.", dir=parent)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYEOF
then
    log "FATAL: extension-preferences.json could not be updated atomically"
    exit 1
fi
log "extension-preferences.json → uBlock0 PB-allowed (grants private-window access)"

# Publish success only after every required postcondition is true. The state
# binds the exact profile and both reviewed inputs, so drift triggers a safe
# recheck instead of a blind skip.
if ! required_outputs_valid; then
    log "FATAL: required setup postcondition failed; success state not written"
    exit 1
fi

STATE_TMP=$(mktemp "$STATE_DIR/.firefox-setup.done.tmp.XXXXXXXX")
expected_state > "$STATE_TMP"
chmod 600 "$STATE_TMP"
sync -- "$STATE_TMP"
mv -fT -- "$STATE_TMP" "$STATE_FILE"
sync -- "$STATE_DIR"

# Notification consolidation:
# and DDG is already the default anyway): notification
# moved out of M16. M34 (firefox-playground) runs immediately after M16
# during first-login autostart and sends ONE combined notification
# covering both profiles. DDG hint removed because DuckDuckGo is already
# the default search engine (set via the search-only policies.json,
# Step 5c) — the "switch to DDG" tip was misleading.
#
# Orphan-stamp removal.
# A prior version attempted to create /var/lib/noid-privacy/firefox-default-
# release.ready as a "stamp file" supposedly read by M34. Reality check:
#   1. M34 source (973 LOC) has ZERO references to this path. It uses
#      its own stamp /var/lib/noid-privacy/stamp-34-firefox-playground.ok
#      for health-checking, not the M16-suspected stamp.
#   2. M16→M34 sequencing happens via direct chaining at script-end
#      (line ~2080 invokes /usr/local/bin/noid-firefox-playground-init.sh
#      synchronously to enforce this ordering).
#   3. The creation itself was broken: setup-script runs as user, but
#      /var/lib/noid-privacy is root:root 700 at first-boot timing →
#      mkdir + touch fail silently due to `|| true`.
# A prior stamp-based handoff only implemented the M16
# side; M34 implementation never landed. Removed as dead code.

log "setup complete"

# Profile-local work is complete. Release the shared lock before chaining the
# independent playground transaction, which acquires the same lock itself.
flock -u 9
exec 9>&-

# Do not clean up arbitrary user Firefox
# processes here. Earlier builds used broad pkill/pkill -f cleanup to remove
# headless-launch leftovers before chaining playground-init. That was unsafe:
# if the user opened Firefox during first-login setup, the visible browser
# could be terminated. The setup path already kills/waits its own $FF_PID, and
# Module 34 no longer defers on arbitrary Firefox subprocesses.

# Chain to playground-init for deterministic
# sequencing. Both XDG autostart hooks (firefox-setup + firefox-playground-init)
# fire in PARALLEL at GNOME login. Chaining from setup-script end guarantees:
# setup-script done → marker written → firefox cleanup → THEN playground-init.
if [[ -x /usr/local/bin/noid-firefox-playground-init.sh ]]; then
    log "chaining to noid-firefox-playground-init.sh (sequential, no race)"
    /usr/local/bin/noid-firefox-playground-init.sh || \
        log "WARN: playground-init returned non-zero (non-fatal)"
fi

exit 0
SETUPSCRIPT_EOF
chmod 755 "$LOCAL_BIN_DIR/noid-firefox-setup.sh"
chown root:root "$LOCAL_BIN_DIR/noid-firefox-setup.sh"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$LOCAL_BIN_DIR/noid-firefox-setup.sh" 2>/dev/null || true
fi

cat > "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop" <<'AUTOSTART_EOF'
[Desktop Entry]
Type=Application
Name=NoID Privacy Firefox Setup
Comment=First-run Firefox hardening setup (NoID Privacy Firefox Hardening v1.0 + uBlock Origin)
Exec=/usr/local/bin/noid-firefox-setup.sh
NoDisplay=true
Terminal=false
X-GNOME-Autostart-enabled=true
# NOTE: X-GNOME-Autostart-Phase REMOVED.
# GNOME 49+ (Fedora 44 ships GNOME 50) rejects .desktop files that use
# this key and logs an error in journalctl. gnome-session no longer
# manages session services via this key — only user-level app autostart
# via XDG. Removing the key reverts to the default "Application" phase,
# which is handled by the generic XDG autostart mechanism (fires after
# login + shell-ready).
AUTOSTART_EOF
chmod 644 "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop"

log "  Installed setup script + autostart entry"

#------------------------------------------------------------------------------
# Step 6b: Install /usr/local/bin/noid-firefox-relax-fpp escape-hatch
#------------------------------------------------------------------------------
# Some sites break under FPP Canvas/WebGL randomization or font restriction.
# Rather than teaching users to manually edit user.js, ship a
# script that creates a per-profile relaxation overlay. Preserves DNS choice,
# HTTPS-Only, Nimbus block, AI block, Mozilla VPN block, password manager
# block — ONLY relaxes the fingerprinting protection layer.

log "Step 6b/8: Install noid-firefox-relax-fpp escape-hatch"

cat > /usr/local/bin/noid-firefox-relax-fpp <<'RELAX_FPP_EOF'
#!/bin/bash
# noid-firefox-relax-fpp — relax Firefox Fingerprinting Protection for compat.
#
# Firefox does NOT load arbitrary *.js files from a profile — only
# `prefs.js` (engine-managed) and `user.js` (user overrides). This script
# patches user.js itself with markers so the prefs ARE loaded; --restore
# removes only that exact block and preserves every unrelated user line.
#
# Markers:
#   // NOID-RELAX-FPP-BEGIN — start of relaxation block
#   // NOID-RELAX-FPP-END   — end of relaxation block
#
# Profile discovery: registered profiles only (parsed from profiles.ini
# via the shared helper) — never scans non-profile dirs (Crash Reports,
# Pending Pings, Profile Groups, firefox-mpris).
#
# Usage:
#   noid-firefox-relax-fpp           # relax all registered profiles
#   noid-firefox-relax-fpp --restore # remove only the exact marked block
#   noid-firefox-relax-fpp --help

set -euo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox FPP" \
    NOID_FMT_AUTO_SUBTITLE="Per-profile compatibility override" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

# Source shared profile helper.
if [ -r /usr/local/lib/noid-privacy/firefox-profiles.sh ]; then
    . /usr/local/lib/noid-privacy/firefox-profiles.sh
else
    echo "ERROR: missing /usr/local/lib/noid-privacy/firefox-profiles.sh" >&2
    echo "       Module 16 install may be incomplete." >&2
    exit 2
fi

MARK_BEGIN="$NOID_FF_RELAX_FPP_BEGIN"
MARK_END="$NOID_FF_RELAX_FPP_END"

if [ "$(id -u)" -eq 0 ]; then
    echo "Run as your normal user (not root) — Firefox profiles live in your home." >&2
    echo "If you ran this via sudo, retry without sudo:" >&2
    echo "  noid-firefox-relax-fpp" >&2
    exit 1
fi

if [ "$#" -gt 1 ]; then
    echo "ERROR: expected zero arguments or one action (try --help)" >&2
    exit 2
fi
ACTION="${1:-apply}"

case "$ACTION" in
    --help|-h)
        cat <<HELP
noid-firefox-relax-fpp — relax Firefox fingerprinting protection for site
compatibility. Keeps the DNS policy, HTTPS-Only, password manager disabled, telemetry
off, Mozilla AI off, uBlock Origin active.

Patches user.js in each registered Firefox profile with a marked block.
Close Firefox before running. Restart Firefox to apply.

Usage:
  noid-firefox-relax-fpp           # apply relaxation
  noid-firefox-relax-fpp --restore # remove only the exact marked block
HELP
        exit 0
        ;;
    --restore|restore)
        ACTION_MODE=restore
        ;;
    apply|"")
        ACTION_MODE=apply
        ;;
    *)
        echo "Unknown action: $ACTION (try --help)" >&2
        exit 1
        ;;
esac

if ! acquire_firefox_profile_lock; then
    echo "Another Firefox profile operation is active; retry later." >&2
    exit 75
fi

if firefox_process_active; then
    echo "Firefox is running. Close all Firefox windows and retry." >&2
    exit 1
fi

FF_ROOT="$(firefox_root)"
if [ ! -d "$FF_ROOT" ]; then
    echo "No Firefox config dir found at $FF_ROOT." >&2
    echo "Start Firefox once to create a profile, then retry." >&2
    exit 1
fi

# Iterate REGISTERED and path-validated profiles only.
if ! PROFILE_RECORDS=$(list_registered_profiles); then
    echo "Firefox profiles.ini failed the safe record contract." >&2
    exit 1
fi
COUNT=0
FAILED=0
while IFS=$'\t' read -r name _; do
    [ -n "$name" ] || continue
    pdir=$(profile_dir_for "$name") || continue
    [ -d "$pdir" ] || continue
    if [ ! -f "$pdir/user.js" ] || [ -L "$pdir/user.js" ]; then
        echo "ERROR: $name has no safe regular user.js" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    if ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END"; then
        echo "ERROR: $name has missing/duplicate/reversed FPP markers; file preserved" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    case "$ACTION_MODE" in
        apply)
            tmpf=$(mktemp "$pdir/.user.js.relax-fpp.XXXXXXXX")
            if ! compose_userjs_relaxation_choice \
                    "$pdir/user.js" enabled preserve > "$tmpf" || \
               ! backup=$(backup_noid_userjs "$pdir/user.js") || \
               ! noid_atomic_install_file "$tmpf" "$pdir/user.js" 600 || \
               ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END"; then
                rm -f -- "$tmpf"
                echo "ERROR: atomic FPP update failed for $name" >&2
                FAILED=$((FAILED + 1))
                continue
            fi
            rm -f -- "$tmpf"
            echo "Relaxed: $name → $pdir/user.js (backup: $(basename "$backup"))"
            COUNT=$((COUNT + 1))
            ;;
        restore)
            if ! grep -Fxq -- "$MARK_BEGIN" "$pdir/user.js"; then
                echo "Already restored: $name (no FPP block)"
                COUNT=$((COUNT + 1))
                continue
            fi
            tmpf=$(mktemp "$pdir/.user.js.restore-fpp.XXXXXXXX")
            if ! compose_userjs_relaxation_choice \
                    "$pdir/user.js" disabled preserve > "$tmpf" || \
               ! backup=$(backup_noid_userjs "$pdir/user.js") || \
               ! noid_atomic_install_file "$tmpf" "$pdir/user.js" 600 || \
               ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_WEBRTC_BEGIN" "$NOID_FF_RELAX_WEBRTC_END"; then
                rm -f -- "$tmpf"
                echo "ERROR: atomic FPP restore failed for $name" >&2
                FAILED=$((FAILED + 1))
                continue
            fi
            rm -f -- "$tmpf"
            echo "Restored: $name → preserved unrelated user.js lines (backup: $(basename "$backup"))"
            COUNT=$((COUNT + 1))
            ;;
    esac
done <<< "$PROFILE_RECORDS"

if [ "$FAILED" -gt 0 ]; then
    echo "Failed safely for $FAILED profile(s); affected files were preserved." >&2
    exit 1
fi

if [ "$COUNT" -eq 0 ]; then
    case "$ACTION_MODE" in
        apply)   echo "No registered Firefox profile found. Nothing to relax." >&2 ;;
        restore) echo "No registered Firefox profile found. Nothing to restore." >&2 ;;
    esac
    exit 1
fi

echo ""
case "$ACTION_MODE" in
    apply)
        echo "Done. Relaxed $COUNT profile(s)."
        echo "Restart Firefox for change to apply."
        echo ""
        echo "To restore full fingerprinting protection:"
        echo "  noid-firefox-relax-fpp --restore"
        ;;
    restore)
        echo "Done. Removed the exact FPP block from $COUNT profile(s); unrelated lines preserved."
        echo "Restart Firefox for change to apply."
        ;;
esac
RELAX_FPP_EOF

chmod 755 /usr/local/bin/noid-firefox-relax-fpp
chown root:root /usr/local/bin/noid-firefox-relax-fpp
log "  Installed /usr/local/bin/noid-firefox-relax-fpp (755)"

#------------------------------------------------------------------------------
# Step 6b2: Install /usr/local/bin/noid-firefox-relax-webrtc escape-hatch
#------------------------------------------------------------------------------
# WebRTC ships OFF (media.peerconnection.enabled=false), so Firefox does not
# generate ICE/STUN candidates. That also breaks browser-based video calls
# (Meet / Jitsi / Discord-web). Rather than teaching users to edit user.js,
# ship a script that re-enables WebRTC per-profile while keeping the ICE
# candidate-reduction prefs (proxy-only / default-route-only) active. Those
# prefs are useful defense in depth, not a guarantee across split routes,
# proxies or VPN configurations. --restore reverts to the canonical
# WebRTC-off state. Mirrors noid-firefox-relax-fpp.

log "Step 6b2/8: Install noid-firefox-relax-webrtc escape-hatch"

cat > /usr/local/bin/noid-firefox-relax-webrtc <<'RELAX_WEBRTC_EOF'
#!/bin/bash
# noid-firefox-relax-webrtc — re-enable Firefox WebRTC for video calls.
#
# Firefox does NOT load arbitrary *.js files from a profile — only
# `prefs.js` (engine-managed) and `user.js` (user overrides). This script
# patches user.js itself with markers so the pref IS loaded; --restore removes
# only that exact block, preserving every unrelated user line and exposing the
# earlier canonical WebRTC-off preference again.
#
# Markers:
#   // NOID-RELAX-WEBRTC-BEGIN — start of relaxation block
#   // NOID-RELAX-WEBRTC-END   — end of relaxation block
#
# Profile discovery: registered profiles only (parsed from profiles.ini
# via the shared helper) — never scans non-profile dirs.
#
# Usage:
#   noid-firefox-relax-webrtc           # enable WebRTC in all registered profiles
#   noid-firefox-relax-webrtc --restore # remove only the exact marked block
#   noid-firefox-relax-webrtc --help

set -euo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox WebRTC" \
    NOID_FMT_AUTO_SUBTITLE="Per-profile leak trade-off" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

# Source shared profile helper.
if [ -r /usr/local/lib/noid-privacy/firefox-profiles.sh ]; then
    . /usr/local/lib/noid-privacy/firefox-profiles.sh
else
    echo "ERROR: missing /usr/local/lib/noid-privacy/firefox-profiles.sh" >&2
    echo "       Module 16 install may be incomplete." >&2
    exit 2
fi

MARK_BEGIN="$NOID_FF_RELAX_WEBRTC_BEGIN"
MARK_END="$NOID_FF_RELAX_WEBRTC_END"

if [ "$(id -u)" -eq 0 ]; then
    echo "Run as your normal user (not root) — Firefox profiles live in your home." >&2
    echo "If you ran this via sudo, retry without sudo:" >&2
    echo "  noid-firefox-relax-webrtc" >&2
    exit 1
fi

if [ "$#" -gt 1 ]; then
    echo "ERROR: expected zero arguments or one action (try --help)" >&2
    exit 2
fi
ACTION="${1:-apply}"

case "$ACTION" in
    --help|-h)
        cat <<HELP
noid-firefox-relax-webrtc — re-enable Firefox WebRTC for browser video calls
(Meet / Jitsi / Discord-web). Keeps DNS policy, HTTPS-Only, password manager disabled,
telemetry off, Mozilla AI off, FPP + uBlock Origin active. The ICE privacy
prefs (proxy-only when a proxy is configured and default-route-only candidate
selection) stay on. They reduce candidate exposure but cannot guarantee that a
local or non-VPN address is hidden under every split-route, proxy or VPN setup.
Use the WebRTC-off default when address disclosure must be prevented.

Patches user.js in each registered Firefox profile with a marked block.
Close Firefox before running. Restart Firefox to apply.

Usage:
  noid-firefox-relax-webrtc           # enable WebRTC
  noid-firefox-relax-webrtc --restore # remove only the exact marked block
HELP
        exit 0
        ;;
    --restore|restore)
        ACTION_MODE=restore
        ;;
    apply|"")
        ACTION_MODE=apply
        ;;
    *)
        echo "Unknown action: $ACTION (try --help)" >&2
        exit 1
        ;;
esac

if ! acquire_firefox_profile_lock; then
    echo "Another Firefox profile operation is active; retry later." >&2
    exit 75
fi

if firefox_process_active; then
    echo "Firefox is running. Close all Firefox windows and retry." >&2
    exit 1
fi

FF_ROOT="$(firefox_root)"
if [ ! -d "$FF_ROOT" ]; then
    echo "No Firefox config dir found at $FF_ROOT." >&2
    echo "Start Firefox once to create a profile, then retry." >&2
    exit 1
fi

# Iterate REGISTERED and path-validated profiles only.
if ! PROFILE_RECORDS=$(list_registered_profiles); then
    echo "Firefox profiles.ini failed the safe record contract." >&2
    exit 1
fi
COUNT=0
FAILED=0
while IFS=$'\t' read -r name _; do
    [ -n "$name" ] || continue
    pdir=$(profile_dir_for "$name") || continue
    [ -d "$pdir" ] || continue
    if [ ! -f "$pdir/user.js" ] || [ -L "$pdir/user.js" ]; then
        echo "ERROR: $name has no safe regular user.js" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    if ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END"; then
        echo "ERROR: $name has missing/duplicate/reversed WebRTC markers; file preserved" >&2
        FAILED=$((FAILED + 1))
        continue
    fi

    case "$ACTION_MODE" in
        apply)
            tmpf=$(mktemp "$pdir/.user.js.relax-webrtc.XXXXXXXX")
            if ! compose_userjs_relaxation_choice \
                    "$pdir/user.js" preserve enabled > "$tmpf" || \
               ! backup=$(backup_noid_userjs "$pdir/user.js") || \
               ! noid_atomic_install_file "$tmpf" "$pdir/user.js" 600 || \
               ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END"; then
                rm -f -- "$tmpf"
                echo "ERROR: atomic WebRTC update failed for $name" >&2
                FAILED=$((FAILED + 1))
                continue
            fi
            rm -f -- "$tmpf"
            echo "WebRTC enabled: $name → $pdir/user.js (backup: $(basename "$backup"))"
            COUNT=$((COUNT + 1))
            ;;
        restore)
            if ! grep -Fxq -- "$MARK_BEGIN" "$pdir/user.js"; then
                echo "Already restored: $name (no WebRTC block)"
                COUNT=$((COUNT + 1))
                continue
            fi
            tmpf=$(mktemp "$pdir/.user.js.restore-webrtc.XXXXXXXX")
            if ! compose_userjs_relaxation_choice \
                    "$pdir/user.js" preserve disabled > "$tmpf" || \
               ! backup=$(backup_noid_userjs "$pdir/user.js") || \
               ! noid_atomic_install_file "$tmpf" "$pdir/user.js" 600 || \
               ! validate_noid_marker_pair "$pdir/user.js" "$MARK_BEGIN" "$MARK_END" || \
               ! validate_noid_marker_pair "$pdir/user.js" \
                    "$NOID_FF_RELAX_FPP_BEGIN" "$NOID_FF_RELAX_FPP_END"; then
                rm -f -- "$tmpf"
                echo "ERROR: atomic WebRTC restore failed for $name" >&2
                FAILED=$((FAILED + 1))
                continue
            fi
            rm -f -- "$tmpf"
            echo "Restored WebRTC-off: $name → preserved unrelated user.js lines (backup: $(basename "$backup"))"
            COUNT=$((COUNT + 1))
            ;;
    esac
done <<< "$PROFILE_RECORDS"

if [ "$FAILED" -gt 0 ]; then
    echo "Failed safely for $FAILED profile(s); affected files were preserved." >&2
    exit 1
fi

if [ "$COUNT" -eq 0 ]; then
    case "$ACTION_MODE" in
        apply)   echo "No registered Firefox profile found. Nothing to change." >&2 ;;
        restore) echo "No registered Firefox profile found. Nothing to restore." >&2 ;;
    esac
    exit 1
fi

echo ""
case "$ACTION_MODE" in
    apply)
        echo "Done. WebRTC enabled in $COUNT profile(s)."
        echo "Restart Firefox for change to apply."
        echo ""
        echo "To restore WebRTC-off (privacy default):"
        echo "  noid-firefox-relax-webrtc --restore"
        ;;
    restore)
        echo "Done. Removed the exact WebRTC block from $COUNT profile(s); unrelated lines preserved."
        echo "Restart Firefox for change to apply."
        ;;
esac
RELAX_WEBRTC_EOF

chmod 755 /usr/local/bin/noid-firefox-relax-webrtc
chown root:root /usr/local/bin/noid-firefox-relax-webrtc
log "  Installed /usr/local/bin/noid-firefox-relax-webrtc (755)"

#------------------------------------------------------------------------------
# Step 6b3: explicit Firefox DRM/Widevine consent helper
#------------------------------------------------------------------------------
log "Step 6b3/8: Install noid-firefox-drm consent helper"

cat > /usr/local/bin/noid-firefox-drm <<'FIREFOX_DRM_EOF'
#!/bin/bash
# Explicit, profile-local opt-in/out for proprietary Widevine and its network
# updater. The versioned sentinel makes the choice survive the supported
# Update-All user.js re-application path.
set -euo pipefail

FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
# shellcheck source=/dev/null
if [ -r "$FMT_LIB" ]; then . "$FMT_LIB"; else
    fmt_banner(){ echo "== $1 =="; [ -n "${2:-}" ] && echo "   $2"; }
    fmt_step(){ echo "[$1/$2] $3"; }; fmt_ok(){ echo "  OK: $1"; }
    fmt_info(){ echo "  - $1"; }; fmt_warn(){ echo "  ! $1" >&2; }
    fmt_err(){ echo "  ERROR: $1" >&2; }; fmt_note(){ echo "$1"; }
    fmt_done(){ echo "$1"; }
fi
fail() { fmt_err "$*"; exit 1; }

usage() {
    cat <<'USAGE_EOF'
Usage: noid-firefox-drm {enable|disable|status} [profile-name]

Without a profile, status/disable target "default-release"; enable is the
interactive two-profile consent flow described below. Close Firefox before
enable/disable.
Enabling permits Firefox to contact Mozilla/Google update infrastructure and
download Google's proprietary Widevine CDM. Disabling prevents future GMP
checks after restart; Firefox also removes installed Widevine when EME is off.

An interactive `enable` without a profile asks separately for default-release
and Firefox Playground before changing either profile. Both answers default to
No. Non-interactive callers must name the intended profile explicitly.
USAGE_EOF
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { usage >&2; exit 2; }
action=$1
profile_name=${2:-default-release}
case "$action" in enable|disable|status) ;; *) usage >&2; exit 2 ;; esac

if [ ! -r /usr/local/lib/noid-privacy/firefox-profiles.sh ]; then
    fail "Firefox profile helper is missing"
fi
# shellcheck source=/dev/null
. /usr/local/lib/noid-privacy/firefox-profiles.sh
noid_require_desktop_user || fail "Run as the desktop user, not root."

answer_is_yes() {
    case "$1" in
        [yY]|[yY][eE][sS]|[jJ]|[jJ][aA]) return 0 ;;
        *) return 1 ;;
    esac
}

# The Setup entry point intentionally omits a profile. Collect both independent
# consents before invoking either profile-local transaction, so default-release
# is never enabled merely by opening the helper. Automation has no terminal in
# which to obtain consent and must use an explicit profile argument.
if [ "$action" = enable ] && [ "$#" -eq 1 ]; then
    [ -t 0 ] || {
        fail "Interactive profile consent requires a terminal. Name default-release or playground explicitly."
    }
    fmt_banner "NoID Privacy — Firefox DRM" "independent profile-local Widevine consent"
    fmt_warn "Enabling permits Mozilla/Google network access and a proprietary Widevine download."
    fmt_note "Each profile stays DRM-free unless you answer Yes for that profile."
    default_selected=0
    playground_selected=0
    read -r -p "Enable DRM for Firefox default-release? [y/N] " answer || answer=
    if answer_is_yes "$answer"; then
        default_selected=1
    fi
    read -r -p "Enable DRM for Firefox Playground? [y/N] " answer || answer=
    if answer_is_yes "$answer"; then
        playground_selected=1
    fi

    if [ "$default_selected" -eq 0 ] && [ "$playground_selected" -eq 0 ]; then
        fmt_done "No Firefox profile changed; DRM remains disabled."
        exit 0
    fi
    # Validate every selected profile before the first write. The explicit
    # transactions repeat these fail-closed checks immediately before mutation.
    if [ "$default_selected" -eq 1 ]; then
        /usr/bin/bash "$0" status default-release >/dev/null || {
            fail "default-release is not in a supported DRM consent state; no profile changed."
        }
    fi
    if [ "$playground_selected" -eq 1 ]; then
        /usr/bin/bash "$0" status playground >/dev/null || {
            fail "Firefox Playground is not in a supported DRM consent state; no profile changed."
        }
    fi
    if firefox_process_active; then
        fail "Close Firefox before changing DRM state; no profile changed."
    fi
    if [ "$default_selected" -eq 1 ]; then
        fmt_info "Starting the approved default-release transaction."
        /usr/bin/bash "$0" enable default-release || {
            fail "default-release DRM opt-in failed; Playground was not changed."
        }
    fi
    if [ "$playground_selected" -eq 1 ]; then
        fmt_info "Starting the approved Firefox Playground transaction."
        /usr/bin/bash "$0" enable playground || {
            if [ "$default_selected" -eq 1 ]; then
                fail "Playground opt-in failed after default-release completed; default-release remains enabled."
            fi
            fail "Firefox Playground DRM opt-in failed; default-release was not changed."
        }
    fi
    fmt_done "Selected Firefox DRM opt-ins complete"
    exit 0
fi

fmt_banner "NoID Privacy — Firefox DRM" "profile-local Widevine consent"
fmt_info "Action: $action"
fmt_info "Target profile: $profile_name"
if [ "$profile_name" = default-release ]; then
    fmt_note "This run targets only default-release; Firefox Playground is unchanged."
    fmt_note "Manual Playground opt-in: noid-firefox-drm enable playground"
else
    fmt_note "This run targets only '$profile_name'; default-release is unchanged."
fi
if [ "$action" = status ]; then
    fmt_step 1 1 "Validate profile and read consent state"
else
    fmt_step 1 2 "Validate target profile and consent state"
fi

pdir=$(profile_dir_for "$profile_name") || {
    fail "Registered profile not found or unsafe: $profile_name"
}
userjs="$pdir/user.js"
sentinel="$pdir/$NOID_FF_DRM_SENTINEL_BASENAME"
mark_begin='// NOID-DRM-OPT-IN-BEGIN'
mark_end='// NOID-DRM-OPT-IN-END'
[ -f "$userjs" ] && [ ! -L "$userjs" ] && \
    grep -q 'NoID Privacy Workstation' "$userjs" || {
        fail "Profile is not safely NoID Privacy-hardened: $profile_name"
    }
[ -f "$NOID_FF_USERJS_DRM_OVERRIDES" ] && \
    [ ! -L "$NOID_FF_USERJS_DRM_OVERRIDES" ] || {
        fail "Reviewed DRM overlay is missing."
    }
validate_noid_marker_pair "$NOID_FF_USERJS_DRM_OVERRIDES" \
    "$mark_begin" "$mark_end" || {
        fail "Reviewed DRM overlay markers are invalid."
    }
validate_noid_marker_pair "$userjs" "$mark_begin" "$mark_end" || {
    fail "Profile DRM marker state is malformed; no change made."
}
drm_state=$(profile_drm_opt_in_state "$pdir") || {
    fail "Profile DRM consent sentinel is malformed; no change made."
}
has_block=0
grep -Fxq -- "$mark_begin" "$userjs" && has_block=1

# Sentinel and marker are one consent record. Never infer intent or silently
# repair only half of it; all actions require one of the two exact states.
if { [ "$drm_state" = enabled ] && [ "$has_block" -ne 1 ]; } || \
   { [ "$drm_state" = disabled ] && [ "$has_block" -ne 0 ]; }; then
    fail "DRM consent sentinel and user.js disagree; no change made."
fi
fmt_ok "Profile registration and consent record are consistent"

if [ "$action" = status ]; then
    if [ "$drm_state" = enabled ] && [ "$has_block" -eq 1 ]; then
        fmt_done "DRM enabled for profile: $profile_name"
        exit 0
    fi
    if [ "$drm_state" = disabled ] && [ "$has_block" -eq 0 ]; then
        fmt_done "DRM disabled for profile: $profile_name"
        exit 0
    fi
    fail "Unreachable DRM consent state."
fi

if firefox_process_active; then
    fail "Close Firefox before changing DRM state."
fi
acquire_firefox_profile_lock || {
    fmt_err "Another Firefox profile operation is active."
    exit 75
}

# Exact already-requested states are read-only successes. Do this after taking
# the shared lock so another profile transaction cannot change the consent
# record between validation and return.
if [ "$action" = enable ] && [ "$drm_state" = enabled ] && [ "$has_block" -eq 1 ]; then
    fmt_info "DRM was already enabled for profile: $profile_name"
    fmt_done "Firefox DRM opt-in is active"
    exit 0
fi
if [ "$action" = disable ] && [ "$drm_state" = disabled ] && [ "$has_block" -eq 0 ]; then
    fmt_info "DRM was already disabled for profile: $profile_name"
    fmt_done "Firefox DRM privacy default is active"
    exit 0
fi

temporary=$(mktemp "$pdir/.user.js.drm.XXXXXXXX") || exit 1
trap 'rm -f -- "$temporary" "${sentinel_tmp:-}"' EXIT
backup=$(backup_noid_userjs "$userjs") || exit 1
rollback_userjs_or_fail() {
    local context=$1
    if noid_atomic_install_file "$backup" "$userjs" 600; then
        return 0
    fi
    fmt_err "CRITICAL: $context and the automatic user.js rollback also failed."
    fmt_err "Consent state may be inconsistent; recover from retained backup: $backup"
    return 1
}

case "$action" in
    enable)
        fmt_step 2 2 "Enable EME and Widevine updates for $profile_name"
        if [ "$drm_state" = disabled ] && [ "$has_block" -eq 1 ]; then
            fail "user.js contains DRM opt-in without the consent sentinel."
        fi
        if [ "$has_block" -eq 0 ]; then
            cat -- "$userjs" "$NOID_FF_USERJS_DRM_OVERRIDES" > "$temporary"
            noid_atomic_install_file "$temporary" "$userjs" 600 || exit 1
        fi
        if [ "$drm_state" = disabled ]; then
            sentinel_tmp=$(mktemp "$pdir/.noid-drm-enabled.XXXXXXXX") || {
                rollback_userjs_or_fail "DRM sentinel staging failed" || exit 1
                exit 1
            }
            printf '%s\n' 'NOID_FIREFOX_DRM_OPT_IN_V1' > "$sentinel_tmp"
            chmod 600 "$sentinel_tmp"
            if ! noid_atomic_install_file "$sentinel_tmp" "$sentinel" 600; then
                rollback_userjs_or_fail "DRM sentinel publication failed" || exit 1
                exit 1
            fi
        fi
        fmt_ok "Consent record enabled for profile: $profile_name"
        fmt_info "Backup: $(basename "$backup")"
        fmt_info "Restart Firefox; Widevine may now download from Mozilla/Google."
        fmt_done "Firefox DRM opt-in complete"
        ;;
    disable)
        fmt_step 2 2 "Restore the DRM-off privacy default for $profile_name"
        [ "$drm_state" = enabled ] && [ "$has_block" -eq 1 ] || {
            fail "Inconsistent DRM state; no change made."
        }
        awk -v begin="$mark_begin" -v end="$mark_end" '
            $0 == begin { skip=1; next }
            $0 == end { skip=0; next }
            !skip { print }
            END { if (skip) exit 1 }
        ' "$userjs" > "$temporary"
        noid_atomic_install_file "$temporary" "$userjs" 600 || exit 1
        if ! rm -f -- "$sentinel"; then
            rollback_userjs_or_fail "DRM sentinel removal failed" || exit 1
            exit 1
        fi
        fmt_ok "Consent record disabled for profile: $profile_name"
        fmt_info "Backup: $(basename "$backup")"
        fmt_info "Restart Firefox; future GMP/Widevine checks are blocked."
        fmt_done "Firefox DRM privacy default restored"
        ;;
esac

# Remove this action's scratch files and release the cross-helper profile lock
# before returning to a coordinator or another profile operation.
rm -f -- "$temporary" "${sentinel_tmp:-}"
trap - EXIT
exec {NOID_FF_PROFILE_LOCK_FD}>&-
FIREFOX_DRM_EOF

chmod 755 /usr/local/bin/noid-firefox-drm
chown root:root /usr/local/bin/noid-firefox-drm
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/bin/noid-firefox-drm 2>/dev/null || true
fi
log "  Installed /usr/local/bin/noid-firefox-drm (755)"

#------------------------------------------------------------------------------
# Step 6c: Install /usr/share/doc/noid-privacy/16-firefox-hardening.md
#------------------------------------------------------------------------------
# User-facing doc for Module 16 (Firefox hardening overview + FPP escape-hatch).
# Matches the pattern used by other Modules (15 Intel ME, 18 Flatpak, 19 NVIDIA,
# 20 Rollback, 21 Kernel Modules, 22 LUKS, 24 fwupd, ssh-server-opt-in).
log "Step 6c/8: Install /usr/share/doc/noid-privacy/16-firefox-hardening.md"

mkdir -p /usr/share/doc/noid-privacy

cat > /usr/share/doc/noid-privacy/16-firefox-hardening.md <<'FIREFOX_DOC_EOF'
# Firefox Hardening (Module 16)

The NoID Privacy Workstation image ships Firefox with two layers of pre-configured
protection: **NoID Privacy Firefox Hardening v1.0** (derived from arkenfox v144.0, MIT;
hundreds of consolidated user_pref directives in a single file, including NoID Privacy
image-scope overrides: provider-compatible DNS, FPP, Mozilla AI block, Nimbus clear, PPA + LNA, etc.;
Firefox 153's native QWAC verification/display remains enabled on desktop because
`@IS_NOT_ANDROID@` resolves to true there and false on Android), and
**uBlock Origin** (reviewed pinned release as first-install seed) pre-configured
via Managed Storage Manifest. After that seed, the extension is yours: the image
never downgrades your profile copy. The privacy defaults disable automatic
add-on update checks (no background executable-extension refresh). The current
Mozilla-signed stable release is fetched only when you explicitly start
`noid-update-all.sh`; the workflow verifies the fixed upstream repository,
GitHub asset digest, archive identity/version/compatibility, Firefox's native
signature state and the no-downgrade postcondition, then records SHA-256
evidence. The same run enumerates every profile-owned extension in every
registered Firefox profile and advances all additional AMO extensions through
AMO's compatibility-filtered official API with the same native signature,
atomic-publication and evidence gates. Filter-list content continues to refresh
inside uBO; that content feed is separate from executable XPI updates.

### Defaults versus user-owned choices

The profile `user.js` continues to enforce the privacy/security baseline.
Settings whose own contract permits a later user choice are deliberately absent
from that file and supplied only as AutoConfig `defaultPref()` values:
startup/homepage, Firefox Home content, private-search selection, Sync
Passwords/Open Tabs, AI Controls, Firefox IP Protection, GPC, the ETP
convenience allowlist, hardware video decoding, WebRender and smooth scrolling.
A value stored by Firefox in `prefs.js` after the user changes a visible control
or an advanced `about:config` feature gate therefore wins across restarts and
Update All. Weather, wallpaper and Mozilla IP Protection have upstream rollout
or system gates, so their normal UI may be absent until those related gates are
also enabled. This does not turn off any NoID Privacy default; it prevents the
default layer from masquerading as a lock.

## What's active out of the box

### Privacy / Telemetry
- Mozilla telemetry, Studies, Normandy, crash reports → **off** (arkenfox)
- Mozilla's four Firefox 153 Messaging System providers → **off**. This keeps
  onboarding, CFR, message-group and messaging-experiment work silent and avoids
  ASRouter querying an intentionally uninitialized telemetry session at launch.
  Unified base telemetry remains off rather than being enabled as a workaround.
- Firefox generative AI Controls → **blocked**, including Firefox-provided AI
  for extensions. The former NoID Privacy catch-all `browser.ml.enable=false` override
  is deliberately absent: Firefox's native AI Controls do not reverse it,
  and Mozilla documents that the panel does not govern traditional ML. Remote
  suggestions, personalization and telemetry remain disabled separately.
- Mozilla VPN "IP Protection" (`browser.ipProtection.enabled`) → **off**
- Nimbus A/B experiments → profile cleared, UUIDs rotate on every start
- Captcha detection telemetry → **off**
- Firefox Sync pre-configured: **no** (user opt-in, passwords + tabs excluded when enabled)

### Network / DNS
- **System/VPN DNS by default** (`network.trr.mode=5`, user-overridable)
- Direct WAN uses NoID Privacy's strict authenticated global/physical Quad9
  DoT; an active VPN/private `~.` DNS scope takes precedence
- IPv6 answers remain usable inside a VPN tunnel; the NoID Privacy system
  boundary, rather than Firefox, blocks unqualified physical-WAN IPv6
- **WebRTC disabled** (`media.peerconnection.enabled=false`) — prevents Firefox
  from generating WebRTC ICE/STUN candidates.
  Browser video calls (Meet / Jitsi / Discord-web) break with WebRTC off. If you
  need them, run `noid-firefox-relax-webrtc` (close Firefox first, then restart) —
  its ICE candidate-reduction prefs stay on, but they are not an IP-leak
  guarantee for every split-route, proxy or VPN configuration.
  `noid-firefox-relax-webrtc --restore` puts WebRTC back off.
- Encrypted Client Hello (ECH) on (DNS + HTTP/3)
- HTTPS-Only Mode **on**

### Cookies / Sessions
- Total Cookie Protection (isolated per-domain cookie jars)
- Bounce Tracking Protection on
- Cookies persist across restarts (login comfort — `clearOnShutdown_v2.cookiesAndStorage=false`)

### Passwords / Autofill
- Password manager **off** (external manager / airgap strategy)
- Payment autofill **off**
- Address autofill **off**
- Form-history autocomplete **off** (Firefox does not store and re-suggest
  previously entered form values)

### Fingerprinting Protection (FPP)
- **FPP active** rather than RFP; letterboxing stays off for UX
- `+AllTargets` with minus-excludes for breakage:
  - `-CSSPrefersColorScheme` (real dark/light theme)
  - `-JSDateTimeUTC` (real timezone)
  - `-RoundWindowSize` (real window size)
  - `-Navigator*` (real browser identity — Linux counterproductive to spoof)
  - `-KeyboardEvents` (real layout)
  - `-SiteSpecificZoom` (site zoom allowed)
- **Canvas + WebGL randomization ACTIVE**
- Font-visibility reduction follows Firefox's current FPP platform support;
  coverage is not identical on every Linux/font configuration
- Remote FPP overrides **off** (Mozilla cannot relax FPP via remote)

### Certificates
- CRLite mode 2 (Firefox 142+ production on-device revocation checking)
- OCSP hard-fail **off**; this does not disable Firefox's maintained revocation
  flow, but avoids failing a connection solely because a fallback responder is
  unavailable
- TLS 0-RTT **off**, Safe Negotiation enforced, Cert Pinning strict

### Safe Browsing
- Local phishing, malware, blocked-URI and download-list protection stays
  enabled, including Mozilla's maintained list-update mechanism
- The separate full per-download application-reputation request is **off**.
  This avoids submitting executable-file metadata such as name, origin, size
  and hash to the reputation service, but gives up its additional server-side
  verdicts for uncommon or potentially unwanted downloads. That is an explicit
  privacy-versus-security trade-off, not a claim of equivalent coverage

### Extensions
- **uBlock Origin** (shipped via `/usr/lib64/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/` + a managed-storage manifest)
- The current `toOverwrite.filterLists` schema enforces uBO's upstream default
  core plus three narrow additions: URL-tracking protection, phishing defence
  and outsider-to-LAN request blocking. Broad regional, cookie-notice and
  annoyance bundles are not forced: upstream warns that adding more lists
  increases breakage, and a locale-neutral image must not enable unrelated
  language lists for every user
- uBO retains its own supported defaults for startup snapshots, automatic
  filter-content updates and Firefox launch-time request suspension; NoID Privacy
  does not pin an experimental advanced setting or create an early
  request bypass
- Only the selected filter-list set is administrator-managed and re-applied at
  uBO launch. Trusted sites, dynamic/URL rules, My filters and other UI choices
  remain user-owned. The baseline is global rather than country-specific:
  manually selected regional/extra lists and uBO's locale-selected additions
  do not persist while `toOverwrite.filterLists` is active. This avoids forcing
  every language list on every user, but users who prioritize regional rules
  can opt the whole system out after closing Firefox:
  `sudo rm -f /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json`.
  Restore the exact reviewed baseline with
  `sudo install -o root -g root -m 0644 /usr/share/noid-firefox/uBlock0@raymondhill.net.json /usr/lib64/mozilla/managed-storage/uBlock0@raymondhill.net.json`.
  The opt-out relinquishes the three NoID Privacy-enforced additions and lets uBO own
  default/locale/manual list selection; executable XPI updates remain the
  separate, explicit Update All path

### New Tab Page Cleanup
- Sponsored content and Pocket Stories → **off**
- Eight curated Top Sites remain visible with embedded local monogram icons.
  The global page-thumbnail kill-switch covers shipped, user-added, pinned and
  history-derived tiles alike, so Firefox cannot pre-load their pages for a
  screenshot before a click. User-added tiles may still reuse favicons already
  collected during a normal visit or Firefox's local Top-Sites icon catalog
- Weather (classic + Nova/widget feeds), unsolicited country lookup and
  AccuWeather/Merino traffic → **off**
- Remote wallpaper feed and `newtab-wallpapers-v2` attachments → **off**
- Urlbar weather suggestions → **off**
- Highlights, CFR (Contextual Feature Recommendations) → **off**
- New Tab telemetry → **off**

### DRM / Widevine
- Encrypted Media Extensions and Widevine → **off** on a pristine profile
- GMP metadata checks → **off**, including Firefox's browser-idle update task
- Opt in only after closing Firefox with `noid-firefox-drm enable`. It asks
  independently for `default-release` and Firefox Playground before changing
  either profile; both answers default to No.
- Non-interactive callers must explicitly name one target profile, for example
  `noid-firefox-drm enable default-release`.
- Without a profile, `status` and `disable` target `default-release`; inspect
  or disable Playground separately with `noid-firefox-drm status playground`
  or `noid-firefox-drm disable playground`. The versioned profile consent
  survives the supported Update-All hardening re-application.
- Enabling permits Firefox to contact Mozilla/Google infrastructure and install
  Google's proprietary Widevine CDM; that privacy/provenance cost is explicit

### Sidebar
- AI Chat (`sidebar.main.tools`) **removed** — keeps synced tabs + history + bookmarks

## Escape-hatch: `noid-firefox-relax-fpp`

Some sites break under FPP Canvas/WebGL randomization or font restriction:
- Online image editors (Canva, Photopea, Figma image-work) — randomized canvas export
- WebGL configurators (car/furniture 3D viewers, online games) — distorted textures
- Sites that use browser fingerprint for DRM validation
- Draw/3D tools that read back Canvas/WebGL pixels

### Usage

```bash
# Close Firefox first (script will check), then:
noid-firefox-relax-fpp              # apply: disable FPP in all detected profiles
noid-firefox-relax-fpp --restore    # undo: remove only the exact marked block
noid-firefox-relax-fpp --help
```

### How it works

The script patches each registered Firefox profile's `user.js` with a marked
block at the end of the file:

```
// NOID-RELAX-FPP-BEGIN
// Created by noid-firefox-relax-fpp. Remove with:
//   noid-firefox-relax-fpp --restore
// This ONLY relaxes fingerprinting protection. DNS policy, HTTPS-Only, password
// manager off, Mozilla AI off, Nimbus off, telemetry off — all stay active.
user_pref("privacy.fingerprintingProtection", false);
user_pref("privacy.fingerprintingProtection.pbmode", false);
user_pref("privacy.resistFingerprinting", false);
// NOID-RELAX-FPP-END
```

Because Firefox processes `user.js` top-to-bottom and last-write-wins, the
marked block overrides the three FPP prefs that the canonical NoID Privacy `user.js`
sets earlier.

> **Why marked-block-in-user.js, not a separate overlay file**:
> Firefox does NOT load arbitrary `*.js` files from a profile's
> root — only `prefs.js` (engine-managed) and `user.js` (user overrides).
> A previous version of this script wrote a separate `noid-relax-fpp.js`
> next to `user.js`, which Firefox silently ignored. The script reported
> success but FPP stayed active. Patching `user.js` itself with a marked
> block makes the relaxation actually take effect. `--restore` strips only
> that validated block, preserving all unrelated profile-owned lines.

### What stays active after applying the relaxation

**Only FPP is relaxed** — every other layer remains intact:

- System/VPN DNS default, HTTPS-Only Mode, ECH
- WebRTC remains off (no WebRTC ICE/STUN candidate generation)
- Password manager off, form autofill off
- uBlock Origin + the managed filter-list baseline
- Telemetry off, Mozilla AI off, Nimbus off, IP Protection off
- Total Cookie Protection, Bounce Tracking Protection
- CRLite mode 2, cert pinning strict
- Captcha detection telemetry off

### Restore full protection

```bash
noid-firefox-relax-fpp --restore
```

Strips the `// NOID-RELAX-FPP-BEGIN ... // NOID-RELAX-FPP-END` block from
each registered profile's `user.js` after requiring exactly zero or one
correctly ordered marker pair. It retains a collision-safe backup, publishes
the rewrite atomically and preserves every line outside the block. Restart
Firefox — the earlier canonical FPP preference is active again.

### Safety

- **User-mode** (runs without sudo — profiles live in `$HOME`)
- **Iterates registered profiles only** via the shared helper
  (`list_registered_profiles` parses `profiles.ini`) — never scans
  non-profile dirs like `Crash Reports`, `Pending Pings`, `Profile
  Groups`, `firefox-mpris`
- **Refuses to run while Firefox is open** (pgrep check)
- **Idempotent**: reapplying the no-argument command first strips any existing
  marked block before appending a fresh one
- **Update-stable**: `noid-update-all.sh` preserves only byte-exact supported
  FPP/WebRTC compatibility blocks while refreshing the canonical base
- **`--restore` is complete rollback** in a single command: it strips only
  the validated marker block and preserves every unrelated `user.js` line
  (playground overrides included)

## Profile creation

NoID Privacy seeds and registers the active profile under the maintained
`~/.config/mozilla/firefox/` XDG path. Mozilla Bug 2003137 tracks an upstream
edge case where a stray, otherwise empty `~/.mozilla/firefox/` can shadow that
valid XDG registry. The owned launcher therefore resolves registered profiles through
the path-bounded shared helper and invokes Firefox with its documented
`--profile <path>` selector. Explicit profile-manager, profile-creation and
external-path requests retain Firefox's own semantics. The image ships
`/usr/share/noid-firefox/user.js` (the canonical consolidated NoID Privacy
Firefox Hardening base), which is copied into the default profile by the
first-run setup script (XDG autostart). An explicit DRM opt-in adds only the
reviewed root-owned consent overlay. Mozilla AutoConfig also applies the base
prefs as global `defaultPref()` values before any profile starts.

Closed tabs remain available to Firefox's normal Undo Closed Tab action during
the current run. They are not carried into the next browser run by default:
this avoids retaining old page state indefinitely and avoids parsing that
unneeded state on the next startup. The setting is a user-overridable
`defaultPref`, not a lock; changing
`browser.sessionstore.persist_closed_tabs_between_sessions` in `about:config`
survives restarts. NoID Privacy deliberately does not set
`browser.sessionstore.max_tabs_undo=0`, so Ctrl+Shift+T remains available
during the current run.

Upstream references: [Mozilla Bug 2003137](https://bugzilla.mozilla.org/show_bug.cgi?id=2003137)
and the documented Firefox [`--profile <path>` command-line selector](https://firefox-source-docs.mozilla.org/browser/CommandLineParameters.html).

### Multiple profiles (about:profiles / `firefox -P`)

The first-run setup script writes profile-local state for **exactly one
profile** — the default (profiles.ini `Default=1` entry or `default-release`
dir). If you later create additional profiles via `about:profiles` or
`firefox -P`, they inherit AutoConfig defaults immediately. A user-started
`noid-update-all.sh` then initializes every safely registered profile whose
`user.js` is absent, unless the exact explicit exclusion below exists. The
helper applies the same state immediately without waiting for an update.

**What a new profile still has** (global mechanisms, profile-independent):

- NoID Privacy Firefox prefs via Mozilla AutoConfig `defaultPref()`
- uBO managed-storage configuration is system-present but remains inert until
  the helper installs the profile-local extension
- Firefox's internal sandbox (Fission + seccomp + namespaces)
- Wayland session isolation

**What a new profile is MISSING** (profile-local files in `<profile>/`):

- NoID Privacy Firefox Hardening `user.js` v1.0 (single consolidated file, derived
  from arkenfox v144.0, MIT; its profile-enforced set includes WebRTC off,
  provider-compatible DNS, FPP,
  telemetry off, Pocket off, Normandy off, remote per-download Safe Browsing
  reputation off while local-list protection and updates remain on, HTTPS-Only
  mode, Encrypted Client Hello, plus NoID Privacy-specific overrides +
  ETP-tighten — baked in at image build)
- exact reviewed uBlock Origin XPI copied into `<profile>/extensions/`
- `extension-preferences.json` entry granting uBO access to private windows

**Result before the next Update All or an explicit helper run**: a new profile
still receives NoID Privacy's global hardened defaults, but temporarily lacks
the canonical profile-local `user.js`, uBO XPI and Private-Browsing grant.

### Harden a new profile

Use the bundled CLI helper:

```bash
# list all profiles + hardening status
noid-firefox-harden-profile

# harden a specific profile (matches by short name, e.g. "work" matches
# "<random-id>.work" profile directory)
noid-firefox-harden-profile work

# harden all safely repairable profiles; existing noncanonical user.js is skipped
noid-firefox-harden-profile --all

# keep one new/unhardened profile outside automatic enrollment
noid-firefox-harden-profile --exclude dev

# after review: replace user.js and reset FPP/WebRTC compatibility opt-ins
noid-firefox-harden-profile --force work
```

After running, **restart Firefox** to activate NoID Privacy Firefox Hardening
and the profile-local uBlock Origin extension in the hardened profile.
Subsequent `noid-update-all.sh` runs also initialize new safely registered
profiles with no `user.js`, then rebuild the canonical base plus any reviewed
DRM consent and byte-exact FPP/WebRTC compatibility opt-ins for all profiles
managed by NoID Privacy. Unsupported manual lines in a managed `user.js` are
not an update-stable customization surface; use the documented helpers for
supported exceptions.

### Intentionally-unhardened profiles

Some users keep a "dev" or "test" profile without NoID Privacy hardening for
DevTools access or WebExtension testing that FPP would break. Before the next
Update All, run `noid-firefox-harden-profile --exclude <profile-name>`. This
publishes one private, exact profile-local exclusion marker; `--all` and Update
All leave the profile untouched. A later named
`noid-firefox-harden-profile <profile-name>` is the explicit opt-in and removes
the marker after the full postcondition succeeds.

An existing foreign, stale or manually modified `user.js` is also never
overwritten implicitly; Update All reports and skips it. `--force` explicitly
replaces that file and resets the supported FPP/WebRTC compatibility opt-ins to
the secure defaults. `--exclude` does not remove an already applied hardening
state; use the documented removal workflow first if that is the intent.

## Updates

- **NoID Privacy Firefox Hardening**: `noid-update-all.sh` (Module 25) Step 5
  initializes every safely registered new profile with no `user.js` unless it
  carries the explicit exclusion, and rebuilds every profile managed
  by NoID Privacy from `/usr/share/noid-firefox/user.js`, retaining only the exact
  reviewed DRM consent and FPP/WebRTC compatibility opt-ins (no external
  fetch, no arkenfox dependency — post-absorption)
- **uBlock Origin**: `noid-update-all.sh` updates every hardened profile from
  the current Mozilla-signed stable upstream XPI; Firefox background add-on
  checks remain disabled
- **Other profile extensions**: `noid-update-all.sh` updates every AMO extension
  in every registered profile through the compatibility-filtered official API;
  built-in/system add-ons remain owned by the Firefox RPM transaction
- **Firefox itself**: updates via `dnf upgrade` (system package, not Mozilla's
  auto-updater)

## Troubleshooting

### Site says "Canvas check failed" / "WebGL renderer check failed"
→ `noid-firefox-relax-fpp` (temporary) + restart Firefox. After work,
`noid-firefox-relax-fpp --restore` + restart.

### Site says "Cookies disabled" / login doesn't persist

First use uBlock Origin's Logger and reload the page to determine whether a
network filter actually blocked a required request. Cosmetic-filtering
controls only hide page elements and cannot repair a blocked network request.
For diagnosis, Ctrl-click uBO's large power button to trust only the current
page; a normal click persists a whole-site Trusted-sites exception and exposes
that site to all traffic uBO would otherwise block. Prefer a narrow exception
filter or report a faulty list rule once the Logger identifies it.

"Block Outsider Intrusion into LAN" deliberately stops public pages from
reaching loopback or private-network services. If a trusted web application
really must reach a local device, review that exact destination before adding
a narrow uBO exception; do not disable the LAN list merely to fix an unrelated
login problem.

### Site embeds (Disqus comments / YouTube / Twitter / Codepen) don't load

NoID Privacy disables Mozilla's "convenience" ETP allowlist by default (`privacy.trackingprotection.allow_list.convenience.enabled=false`).
Rationale: defense-in-depth (uBlock Origin's filter lists already block most
convenience-trackers) + privacy-distro positioning (don't trust Mozilla's
curated allowlist with tracker exceptions).

If a specific embed fails AND uBO doesn't block it for separate privacy
reasons, two ways to re-enable:

**Per-site (preferred — minimal exposure):**
- Settings → Privacy & Security → Enhanced Tracking Protection
- "Manage Exceptions" → add the site

**Globally (if many sites affected):**
- about:config → search `privacy.trackingprotection.allow_list.convenience.enabled`
- toggle to `true`

The pref ships as `defaultPref` (NOT `lockPref`) — your override sticks across
restarts. Other tightening (uBO filter lists, FPP, DNS policy) remains active.

Mozilla's allowlist URL: https://etp-exceptions.mozilla.org/ (curated by Mozilla)

### Video playback breaks (DRM error)
→ DRM is intentionally off until explicit consent. Close Firefox, run:

```bash
noid-firefox-drm enable              # asks independently for both shipped profiles
noid-firefox-drm enable default-release
noid-firefox-drm enable playground
noid-firefox-drm enable work         # any other named registered profile
noid-firefox-drm status
noid-firefox-drm status playground
```

Without an explicit profile, the interactive helper asks separate `[y/N]`
questions for `default-release` and Firefox Playground before changing either
profile; both answers default to No. A non-interactive `enable` must name
exactly one registered profile. Restart Firefox afterward. The helper enables
EME and the GMP/Widevine updater together, so Firefox may contact
Mozilla/Google and download the proprietary CDM. To return to the
no-metadata/no-CDM default, close Firefox and run `noid-firefox-drm disable`
for `default-release`, plus `noid-firefox-drm disable playground` if that
profile was enabled, then restart.

### Firefox Sync wanted
→ about:preferences#sync → sign in with Mozilla account. Tabs + Passwords are
set to NOT sync by default — flip via about:preferences#sync → "Choose what
to sync" if you want them.

### Secure DNS, VPN DNS and slow first lookups

Firefox defaults to the operating-system resolver (`network.trr.mode=5`).
This lets `systemd-resolved` use an active VPN/private `~.` DNS scope; without
one, NoID Privacy's global Quad9 resolver is used. Direct-WAN Quad9 uses
strict authenticated DoT and fails closed when TLS is unavailable. The
explicit VPN/captive-portal compatibility mode permits DNS/53 fallback.

Firefox's country lookup remains disabled. A narrow
`doh-rollout.home-region=global` default initializes only the built-in Secure
DNS provider catalogue, so the chooser remains available without discovering
or publishing a location. It does not activate DoH or preselect a provider.

The setting is deliberately a user-overridable AutoConfig `defaultPref` and
is absent from the profile `user.js`. A choice made under Settings → Privacy
& Security → DNS over HTTPS therefore survives browser restarts and Update
All. Enabling browser Secure DNS creates a separate resolver path: that may be
desirable for fail-closed encrypted DNS on direct WAN, but it bypasses the DNS
selection and filtering of an active desktop VPN. Proton VPN and Mullvad both
recommend Secure DNS off while their desktop VPN is active.

For a slow first lookup, compare the effective paths:

```bash
resolvectl query example.com
curl -sS -o /dev/null -w 'dns=%{time_namelookup} total=%{time_total}\n' \
  https://example.com
```

Then inspect Firefox Settings → Privacy & Security → DNS over HTTPS. Do not
assume that a browser-selected provider and the active VPN resolver are the
same trust boundary.

## Spotify / other dedicated profiles

No dedicated media/Spotify profile is shipped. The complete image manages
`default-release` plus Firefox Playground; power users can create additional
registered profiles:

1. Create additional profile: Firefox → `about:profiles`
2. Run `noid-firefox-harden-profile <profile-name>` (installs NoID Privacy
   `user.js`, the reviewed uBO XPI and its private-window permission)

## References

- NoID Privacy Firefox Hardening (this project): `firefox/noid-firefox-hardening.js`
  in the NoID Privacy Workstation repository
- arkenfox user.js (upstream, our v1.0 basis): https://github.com/arkenfox/user.js
  (MIT license, attribution retained in user.js header — our hardening is
  derived from arkenfox v144.0)
- uBlock Origin: https://github.com/gorhill/uBlock
- uBlock Origin filter-list guidance:
  https://github.com/gorhill/uBlock/wiki/Dashboard:-Filter-lists
- uBlock Origin popup/trusted-site behavior:
  https://github.com/gorhill/uBlock/wiki/Quick-guide:-popup-user-interface
- Mozilla Firefox privacy guide: https://support.mozilla.org/en-US/products/firefox/privacy-and-security

## Hardware Video Acceleration (HW-decode)

Firefox uses its native Fedora/Mozilla GPU qualification. NoID Privacy does
not force `media.hardware-video-decoding.force-enabled` or
`gfx.webrender.all`: both settings override Firefox's blocklist rather than
normally enabling a supported device. Fedora Firefox enables qualified
Intel/AMD VA-API decoding by default, while Firefox retains its driver probe,
blocklist and failed-sanity-test fallback on every GPU.

### Codec drivers + per-GPU support

Codec drivers (Intel/AMD VA-API, OpenH264, full ffmpeg, AV1 via dav1d) are an
explicit user opt-in through `noid-complete-setup.sh` (or an explicit start of
`noid-firstboot-setup.service`). **Module 08 does not enable that service at first boot**:
Fedora's patent-stripped defaults remain in place until the user
chooses the RPM Fusion swap. See `noid-help 26-optional-packages`, section
"RPM Fusion codec stack", for the package and network/repository trade-off.

**NVIDIA**: NoID Privacy does not install a VA-driver package merely because an
NVIDIA PCI device exists. Nouveau video profiles depend on the GPU generation
and available firmware; it may use profiles exposed by Fedora Mesa, otherwise
Firefox falls back to software decode. The proprietary path also keeps software
decode by design — the unsupported NVDEC bridge would require disabling
Firefox's media-decoder sandbox (`MOZ_DISABLE_RDD_SANDBOX=1`, which Mozilla
calls a major security risk). Hybrid Intel/NVIDIA systems retain the Intel
VA-API backend. See Module 19 (`19-nvidia-drivers.md`).

**DRM streaming (Netflix / Prime / Disney+)**: hardware decode of DRM content
is not achievable on standard Linux — the Widevine CDM runs its own internal
software decoder and bypasses VA-API (Mozilla Bug 1700815, open since 2021).
Linux gets only Widevine L3 (software), so streaming services cap resolution
regardless of GPU. Not a NoID Privacy limitation; it affects every Linux browser.

### Native defaults — no user.js editing needed

Do not add force-enable preferences for normal operation. After the explicit
codec opt-in, Firefox can use a vendor-specific VA-API path that passes its
native qualification. NVIDIA uses only supported profiles exposed by the
selected driver (or an iGPU on a hybrid system) and otherwise falls back to
software decode. NoID Privacy never disables the RDD media sandbox to force an
unsupported proprietary-driver bridge.

### Rollback if video artifacts appear

If a qualified driver nevertheless shows artifacts, set
`media.hardware-video-decoding.enabled=false` in `about:config`, then restart
Firefox. The browser-owned value survives Update All and video falls back to
software decoding.

### Verification

Check if HW-decode is active:

1. Open `about:support` in Firefox
2. Scroll to **Graphics** section
3. Look for `HARDWARE_VIDEO_DECODING` row
4. Value `available by default` means the native supported path is active.
   `force enabled by user` indicates a local override and should be reset
   before diagnosing driver or playback failures.

Live monitoring while playing a video:

- Intel: `sudo intel_gpu_top` — watch Video bar above 0 %
- AMD: `radeontop` (overall GPU usage)
- NVIDIA: `nvidia-smi pmon` or `nvtop` — firefox process with `C` in Type column
FIREFOX_DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/16-firefox-hardening.md
chown root:root /usr/share/doc/noid-privacy/16-firefox-hardening.md
log "  Installed /usr/share/doc/noid-privacy/16-firefox-hardening.md"

#------------------------------------------------------------------------------
# Step 6d: Install noid-firefox-harden-profile CLI helper
#------------------------------------------------------------------------------
# Profiles created later via about:profiles / `firefox -P` keep the global
# mechanisms (AutoConfig defaults, managed-storage, sandbox) but initially lack
# the profile-local user.js + validated uBO XPI + PB-permission grant. M25
# automatically initializes safely registered profiles with no user.js and
# re-applies managed profiles. A foreign user.js or this helper's exact
# `--exclude` marker preserves an explicit opt-out.
# Usage + exit codes in the HARDEN_EOF heredoc.

log "Step 6d/8: Install noid-firefox-harden-profile CLI helper"

cat > "$LOCAL_BIN_DIR/noid-firefox-harden-profile" <<'HARDEN_EOF'
#!/bin/bash
# noid-firefox-harden-profile — apply NoID Privacy Firefox user.js to Firefox profile(s)
#
# Ships the consolidated NoID Privacy Firefox Hardening user.js (derived from arkenfox
# v144.0, MIT) into Firefox profiles that the XDG-autostart
# first-run setup missed (typically: profiles created via about:profiles or
# `firefox -P` after first boot).
#
# Profile discovery via shared helper (registered profiles only — never
# `find -type d`, which would match non-profile dirs: Crash Reports,
# Pending Pings, Profile Groups, firefox-mpris). apply_userjs handles
# base + playground correctly. The helper then installs the exact reviewed
# uBO XPI profile-local and grants its Private-Browsing permission. The wider ExtensionSettings
# policies.json was removed because Firefox displayed "managed by
# your organization" on every profile; only Step 5c's search-only policy ships.
#
# Idempotent: a profile is complete only when its user.js, validated uBO identity and
# Private-Browsing permission all validate. Partial runs with an absent or exact
# supported user.js are repaired. Existing noncanonical user.js files are
# preserved unless --force explicitly replaces them.
#
# Usage:
#   noid-firefox-harden-profile                  List profiles + status
#   noid-firefox-harden-profile <name>           Harden a specific profile
#                                                (by exact Name from profiles.ini)
#   noid-firefox-harden-profile --all            Harden every registered
#                                                safely repairable profile
#   noid-firefox-harden-profile --exclude <name> Exclude an unhardened profile
#                                                from automatic enrollment
#   noid-firefox-harden-profile --force <name>   Overwrite existing user.js
#                                                and reset FPP/WebRTC opt-ins
#   noid-firefox-harden-profile --help           This help
#
# Exit codes:
#   0  success (or idempotent no-op)
#   1  invalid input, missing profile, or profile-specific hardening failure
#   2  shared helper, source bundle, or profile registry missing or invalid
#   75 another profile operation holds the lock / Firefox still running

set -uo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox Hardening" \
    NOID_FMT_AUTO_SUBTITLE="Managed profile state" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

# Help is deliberately state-independent: it must not require the installed
# helper library, a Firefox profile, the source bundle, or an available lock.
case "${1:-}" in
    -h|--help|help)
        if [ "$#" -ne 1 ]; then
            echo "ERROR: surplus/conflicting arguments. Try --help." >&2
            exit 1
        fi
        sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
        exit 0
        ;;
esac

SOURCE_DIR=/usr/share/noid-firefox

# Source shared profile helper.
if [ -r /usr/local/lib/noid-privacy/firefox-profiles.sh ]; then
    . /usr/local/lib/noid-privacy/firefox-profiles.sh
else
    echo "ERROR: missing /usr/local/lib/noid-privacy/firefox-profiles.sh" >&2
    echo "       Module 16 install may be incomplete." >&2
    exit 2
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: run as the normal desktop user, never through sudo." >&2
    exit 1
fi

case "$#" in
    0|1) ;;
    2) [[ "$1" =~ ^--(force|exclude)$ ]] || {
           echo "ERROR: surplus/conflicting arguments. Try --help." >&2
           exit 1
       } ;;
    *) echo "ERROR: surplus/conflicting arguments. Try --help." >&2; exit 1 ;;
esac

READ_ONLY=0
case "${1:-}" in
    ""|list|--list) READ_ONLY=1 ;;
esac
if [ "$READ_ONLY" -eq 0 ]; then
    if ! acquire_firefox_profile_lock; then
        echo "ERROR: another Firefox profile operation is active; retry later." >&2
        exit 75
    fi
    if firefox_process_active; then
        echo "ERROR: close Firefox before changing profile files." >&2
        exit 75
    fi
fi

# --- Preflight --------------------------------------------------------------
if [ ! -f "$SOURCE_DIR/user.js" ] || [ -L "$SOURCE_DIR/user.js" ]; then
    echo "ERROR: source file $SOURCE_DIR/user.js missing." >&2
    echo "       The NoID Privacy Firefox bundle (Module 16) may be incomplete." >&2
    exit 2
fi
ubo_source_size=$(stat -c '%s' "$NOID_FF_UBO_XPI" 2>/dev/null || true)
ubo_source_size=${ubo_source_size:-0}
if [ ! -f "$NOID_FF_UBO_XPI" ] || [ -L "$NOID_FF_UBO_XPI" ] || \
   [ "$ubo_source_size" -ne "$NOID_FF_UBO_SIZE" ] || \
   [ "$(sha256sum "$NOID_FF_UBO_XPI" 2>/dev/null | awk '{print $1}')" != "$NOID_FF_UBO_SHA256" ]; then
    echo "ERROR: reviewed uBlock Origin XPI is missing or differs from its exact pin." >&2
    exit 2
fi

FIREFOX_CONFIG="$(firefox_root)"
if [ ! -d "$FIREFOX_CONFIG" ]; then
    echo "ERROR: $FIREFOX_CONFIG does not exist." >&2
    echo "       Launch Firefox once to create the default profile, then re-run." >&2
    exit 2
fi

# --- Profile discovery (registered only) ----------------------
HARDENED_NAMES=()
REPAIRABLE_NAMES=()
PROTECTED_NAMES=()
EXCLUDED_NAMES=()
HARDENED_PATHS=()
REPAIRABLE_PATHS=()
PROTECTED_PATHS=()
EXCLUDED_PATHS=()

if ! PROFILE_RECORDS=$(list_registered_profiles); then
    echo "ERROR: profiles.ini failed the safe path/ownership record contract." >&2
    exit 2
fi
while IFS=$'\t' read -r name _; do
    [ -n "$name" ] || continue
    pdir=$(profile_dir_for "$name") || continue
    [ -d "$pdir" ] || continue
    if profile_auto_hardening_excluded "$pdir"; then
        EXCLUDED_NAMES+=("$name")
        EXCLUDED_PATHS+=("$pdir")
    else
        exclusion_rc=$?
        if [ "$exclusion_rc" -ne 1 ]; then
            PROTECTED_NAMES+=("$name")
            PROTECTED_PATHS+=("$pdir")
        elif profile_hardening_complete "$name"; then
            HARDENED_NAMES+=("$name")
            HARDENED_PATHS+=("$pdir")
        elif { [ ! -e "$pdir/user.js" ] && [ ! -L "$pdir/user.js" ]; } || \
             profile_userjs_supported "$name" "$pdir"; then
            REPAIRABLE_NAMES+=("$name")
            REPAIRABLE_PATHS+=("$pdir")
        else
            PROTECTED_NAMES+=("$name")
            PROTECTED_PATHS+=("$pdir")
        fi
    fi
done <<< "$PROFILE_RECORDS"

# --- Harden function --------------------------------------------------------
# Uses apply_userjs from the helper which handles base vs playground correctly.
harden_profile() {
    local target_name="$1" reset_relaxations="${2:-0}" pdir apply_mode=preserve-supported
    pdir=$(profile_dir_for "$target_name") || {
        echo "ERROR: profile not registered: $target_name" >&2
        return 1
    }
    [ -d "$pdir" ] || {
        echo "ERROR: profile dir missing: $pdir" >&2
        return 1
    }
    [ -w "$pdir" ] || {
        echo "ERROR: profile dir not writable: $pdir" >&2
        return 1
    }
    if [ "$reset_relaxations" -eq 1 ]; then
        apply_mode=reset-relaxations
        echo "  [INFO] --force resets supported FPP/WebRTC compatibility opt-ins for $target_name"
    fi
    apply_userjs "$target_name" "$apply_mode" || {
        echo "ERROR: apply_userjs failed for $target_name" >&2
        return 1
    }
    repair_ubo_profile_local "$target_name" || {
        echo "ERROR: validated uBO profile-local repair failed for $target_name" >&2
        return 1
    }
    patch_ubo_pb_permission "$target_name" || {
        echo "ERROR: could not grant uBO Private-Browsing permission for $target_name" >&2
        return 1
    }
    profile_hardening_complete "$target_name" || {
        echo "ERROR: postcondition failed for $target_name" >&2
        return 1
    }
    clear_profile_auto_hardening_exclusion "$pdir" || {
        echo "ERROR: could not clear the automatic-hardening exclusion for $target_name" >&2
        return 1
    }
    echo "  [OK] hardened: $target_name → $pdir (user.js + validated uBO + private-window permission)"
    return 0
}

print_list() {
    echo "Firefox profiles at: $FIREFOX_CONFIG (registered in profiles.ini)"
    echo
    if [ "${#HARDENED_NAMES[@]}" -gt 0 ]; then
        echo "Already hardened (user.js + validated uBO + private-window permission):"
        for n in "${HARDENED_NAMES[@]}"; do echo "  [hardened]    $n"; done
    fi
    if [ "${#REPAIRABLE_NAMES[@]}" -gt 0 ]; then
        echo "Safely repairable (no user.js or exact supported composition):"
        for n in "${REPAIRABLE_NAMES[@]}"; do echo "  [repairable]  $n"; done
        echo
        echo "To harden safely repairable profiles:"
        echo "  noid-firefox-harden-profile <profile-name>"
        echo "  noid-firefox-harden-profile --all"
    fi
    if [ "${#PROTECTED_NAMES[@]}" -gt 0 ]; then
        echo "Protected from implicit overwrite (foreign/stale/modified user.js):"
        for n in "${PROTECTED_NAMES[@]}"; do echo "  [review]      $n"; done
        echo "  Review first; only an explicit --force replaces these files."
    fi
    if [ "${#EXCLUDED_NAMES[@]}" -gt 0 ]; then
        echo "Explicitly excluded from automatic hardening:"
        for n in "${EXCLUDED_NAMES[@]}"; do echo "  [excluded]    $n"; done
        echo "  Harden one by name to opt in and remove its exclusion."
    fi
    if [ "${#HARDENED_NAMES[@]}" -eq 0 ] && \
       [ "${#REPAIRABLE_NAMES[@]}" -eq 0 ] && \
       [ "${#PROTECTED_NAMES[@]}" -eq 0 ] && \
       [ "${#EXCLUDED_NAMES[@]}" -eq 0 ]; then
        echo "No registered Firefox profiles found. Launch Firefox once to create the default."
    fi
}

# --- Argument dispatch ------------------------------------------------------
FORCE=0
EXCLUDE=0
case "${1:-}" in
    ""|list|--list)
        print_list
        exit 0
        ;;
    --all)
        if [ "${#REPAIRABLE_NAMES[@]}" -eq 0 ]; then
            echo "No safely repairable Firefox profiles. Nothing changed."
            if [ "${#PROTECTED_NAMES[@]}" -gt 0 ]; then
                echo "Review protected profile(s) individually; --all never overwrites their user.js."
            fi
            if [ "${#EXCLUDED_NAMES[@]}" -gt 0 ]; then
                echo "Explicitly excluded profile(s) remain untouched."
            fi
            exit 0
        fi
        echo "Hardening ${#REPAIRABLE_NAMES[@]} safely repairable profile(s)..."
        failed=0
        for n in "${REPAIRABLE_NAMES[@]}"; do
            harden_profile "$n" || failed=$((failed + 1))
        done
        if [ "${#PROTECTED_NAMES[@]}" -gt 0 ]; then
            echo "Skipped ${#PROTECTED_NAMES[@]} protected profile(s) with noncanonical user.js."
        fi
        if [ "${#EXCLUDED_NAMES[@]}" -gt 0 ]; then
            echo "Skipped ${#EXCLUDED_NAMES[@]} explicitly excluded profile(s)."
        fi
        echo
        if [ "$failed" -gt 0 ]; then
            echo "DONE with $failed errors."
            exit 1
        else
            echo "DONE. Restart Firefox to activate NoID Privacy hardening in the hardened profile(s)."
            echo "Tip: next run of 'noid-update-all.sh' will keep them updated."
            exit 0
        fi
        ;;
    --force)
        FORCE=1
        shift
        NAME="${1:-}"
        if [ -z "$NAME" ]; then
            echo "ERROR: --force requires a profile name." >&2
            exit 1
        fi
        ;;
    --exclude)
        EXCLUDE=1
        shift
        NAME="${1:-}"
        if [ -z "$NAME" ]; then
            echo "ERROR: --exclude requires a profile name." >&2
            exit 1
        fi
        ;;
    --*)
        echo "ERROR: unknown flag '$1'. Try --help." >&2
        exit 1
        ;;
    *)
        NAME="$1"
        ;;
esac

# --- Single-profile harden path ---------------------------------------------
PROFILE_DIR=$(profile_dir_for "$NAME") || {
    echo "ERROR: profile '$NAME' not registered in profiles.ini." >&2
    echo
    print_list
    exit 1
}

if [ "$EXCLUDE" -eq 1 ]; then
    if profile_hardening_complete "$NAME" || \
       profile_userjs_noid_managed "$PROFILE_DIR"; then
        echo "ERROR: profile '$NAME' is already NoID Privacy-managed; --exclude does not remove hardening." >&2
        echo "       Use the documented removal workflow first if that is your intent." >&2
        exit 1
    fi
    publish_profile_auto_hardening_exclusion "$PROFILE_DIR" || {
        echo "ERROR: could not publish a safe automatic-hardening exclusion for '$NAME'." >&2
        exit 1
    }
    echo "Profile '$NAME' is excluded from automatic NoID Privacy hardening."
    echo "Run 'noid-firefox-harden-profile $NAME' to opt in explicitly."
    exit 0
fi

# Idempotent check (all three profile-local outputs valid)
if profile_hardening_complete "$NAME" && [ "$FORCE" -eq 0 ]; then
    echo "Profile '$NAME' already hardened (user.js + validated uBO + private-window permission)."
    echo "After review, --force replaces user.js and resets FPP/WebRTC opt-ins:"
    echo "  noid-firefox-harden-profile --force $NAME"
    exit 0
fi

if [ "$FORCE" -eq 0 ] && \
   { [ -e "$PROFILE_DIR/user.js" ] || [ -L "$PROFILE_DIR/user.js" ]; } && \
   ! profile_userjs_supported "$NAME" "$PROFILE_DIR"; then
    echo "ERROR: profile '$NAME' has a foreign, stale or manually modified user.js." >&2
    echo "       It was preserved. Review it before an explicit --force replacement." >&2
    exit 1
fi

echo "Hardening profile: $NAME → $PROFILE_DIR"
harden_profile "$NAME" "$FORCE" || exit 1
echo
echo "DONE. Restart Firefox to activate NoID Privacy Firefox Hardening in profile '$NAME'."
echo "Tip: 'noid-update-all.sh' reapplies the supported user.js composition weekly."
exit 0
HARDEN_EOF

chmod 755 "$LOCAL_BIN_DIR/noid-firefox-harden-profile"
chown root:root "$LOCAL_BIN_DIR/noid-firefox-harden-profile"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$LOCAL_BIN_DIR/noid-firefox-harden-profile" 2>/dev/null || true
fi
log "  Installed /usr/local/bin/noid-firefox-harden-profile"

#------------------------------------------------------------------------------
# Step 6e: Firefox launcher/desktop ownership boundary
#------------------------------------------------------------------------------
log "Step 6e/8: Preserve signed Fedora launcher and desktop payloads"
FF_VENDOR_DESKTOP=/usr/share/applications/org.mozilla.firefox.desktop
[ -f "$FF_VENDOR_DESKTOP" ] && [ ! -L "$FF_VENDOR_DESKTOP" ] \
    || { log "  [FAIL] pristine Fedora Firefox desktop entry missing"; exit 1; }
if ! rpm -Vf "$FF_VENDOR_DESKTOP" >/dev/null 2>&1; then
    log "  [FAIL] Fedora Firefox desktop entry differs from its RPM payload"
    exit 1
fi
log "  Signed Fedora launcher and desktop entry remain byte-pristine"

#------------------------------------------------------------------------------
# Step 6f: derive NoID Privacy-owned launcher and XDG desktop overlays
#------------------------------------------------------------------------------
# The generator accepts only the exact signed RPM payload, stages both derived
# files on their destination filesystems, validates them, and atomically
# publishes them under /usr/local. XDG/PATH precedence selects these owned
# overlays while /usr/bin and /usr/share/applications remain pristine.
log "Step 6f/8: Generate owned launcher + XDG overlay and install update hook"

# Cache the final AutoConfig payload for runtime re-assertion. The three
# files below live inside the firefox package tree as unowned files: plain
# RPM upgrades keep them in place, but reinstall/obsoletes/tree-restructure
# paths drop them silently. The reassert helper re-installs them from this
# cache on every firefox transaction (mirrors the M35 Thunderbird cache).
install -d -m 0755 /usr/share/noid-firefox
for ff_autoconfig in \
    "/usr/lib64/firefox/mozilla.cfg::mozilla.cfg" \
    "/usr/lib64/firefox/defaults/pref/autoconfig.js::autoconfig.js" \
    "/usr/lib64/firefox/defaults/pref/noid-locale.js::noid-locale.js"; do
    ff_src="${ff_autoconfig%%::*}"
    ff_dst="/usr/share/noid-firefox/${ff_autoconfig##*::}"
    if [ ! -f "$ff_src" ]; then
        log "  FAIL: AutoConfig cache source missing: $ff_src"
        exit 1
    fi
    install -m 0644 "$ff_src" "$ff_dst"
done
log "  Cached Firefox AutoConfig payload in /usr/share/noid-firefox (runtime re-assert source)"

cat > /usr/local/sbin/noid-firefox-reassert <<'NOID_FF_REASSERT_EOF'
#!/usr/bin/bash
# Regenerate NoID Privacy-owned Firefox launcher/XDG overlays after an RPM
# update. Never write a file owned by the Firefox RPM.
set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'ERROR: noid-firefox-reassert accepts no arguments' >&2
    exit 2
fi

fail() {
    logger -t noid-firefox-reassert "FAILED: $*"
    printf 'noid-firefox-reassert: %s\n' "$*" >&2
    exit 1
}

vendor_digest() {
    local path=$1 digest actual
    [ "$(rpm -q --qf '%{FILEDIGESTALGO}' firefox 2>/dev/null)" = 8 ] \
        || fail "Firefox RPM does not declare SHA-256 file digests"
    # The reader must consume rpm's complete file list: an early-exit awk can
    # close the pipe while rpm is still writing, and under pipefail the
    # resulting SIGPIPE (exit 141) would abort this script without reaching
    # fail().
    digest=$(rpm -q --qf '[%{FILENAMES}\t%{FILEDIGESTS}\n]' firefox 2>/dev/null \
        | awk -F '\t' -v p="$path" '
            $1 == p { count++; digest=$2 }
            END { if (count != 1 || digest == "") exit 1; print digest }
        ') || fail "cannot obtain RPM digest for $path"
    [ "${#digest}" -eq 64 ] || fail "cannot obtain RPM digest for $path"
    actual=$(sha256sum "$path" | awk '{print $1}')
    [ "$actual" = "$digest" ] || fail "$path differs from its signed RPM payload"
}

vendor_launcher=/usr/bin/firefox
owned_launcher=/usr/local/bin/firefox
vendor_desktop=/usr/share/applications/org.mozilla.firefox.desktop
owned_desktop=/usr/local/share/applications/org.mozilla.firefox.desktop
install -d -m 0755 /usr/local/bin /usr/local/share/applications
exec 9>/run/noid-firefox-overlay.lock
flock -w 300 9 || fail "timed out waiting for Firefox overlay regeneration"
vendor_digest "$vendor_launcher"
vendor_digest "$vendor_desktop"
widevine_anchor_count=$(grep -cF \
    '    (restorecon -vr $MOZ_CONFIG_DIR/firefox/*/gmp-widevinecdm/* &)' \
    "$vendor_launcher" 2>/dev/null || true)
widevine_anchor_count=${widevine_anchor_count:-0}
legacy_root_anchor_count=$(grep -cF 'if [ -d "$HOME/.mozilla" ]; then' \
    "$vendor_launcher" 2>/dev/null || true)
legacy_root_anchor_count=${legacy_root_anchor_count:-0}
exec_anchor_count=$(grep -cF 'exec $MOZ_PROGRAM "$@"' \
    "$vendor_launcher" 2>/dev/null || true)
exec_anchor_count=${exec_anchor_count:-0}
relaunch_anchor_count=$(grep -Fxc "export MOZ_APP_LAUNCHER=\"$vendor_launcher\"" \
    "$vendor_launcher" 2>/dev/null || true)
relaunch_anchor_count=${relaunch_anchor_count:-0}
[ "$widevine_anchor_count" -eq 1 ] \
    || fail "reviewed Widevine relabel anchor changed"
[ "$legacy_root_anchor_count" -eq 1 ] \
    || fail "reviewed Fedora profile-root anchor changed"
[ "$exec_anchor_count" -eq 1 ] \
    || fail "reviewed Firefox exec anchor changed"
[ "$relaunch_anchor_count" -eq 1 ] \
    || fail "reviewed Firefox relaunch anchor changed"

launcher_tmp=
desktop_stage_dir=
desktop_tmp=
langpack_tmp=
cleanup() {
    [ -z "${launcher_tmp:-}" ] || rm -f -- "$launcher_tmp"
    [ -z "${desktop_tmp:-}" ] || rm -f -- "$desktop_tmp" "${desktop_tmp}.filtered"
    if [ -n "${desktop_stage_dir:-}" ]; then
        rmdir -- "$desktop_stage_dir" 2>/dev/null || true
    fi
    [ -z "${langpack_tmp:-}" ] || rm -f -- "$langpack_tmp"
}
trap cleanup EXIT
launcher_tmp=$(mktemp /usr/local/bin/.firefox.XXXXXX)
desktop_stage_dir=$(mktemp -d /usr/local/share/applications/.noid-firefox-overlay.XXXXXXXX)
desktop_tmp="$desktop_stage_dir/org.mozilla.firefox.desktop"
cp -- "$vendor_launcher" "$launcher_tmp"
sed -i 's|^if \[ -d "$HOME/\.mozilla" \]; then$|if [ -f "$HOME/.mozilla/firefox/profiles.ini" ]; then|' \
    "$launcher_tmp"
sed -i '\|    (restorecon -vr $MOZ_CONFIG_DIR/firefox/\*/gmp-widevinecdm/\* &)|c\    (\n      shopt -s nullglob\n      widevine_paths=("$MOZ_CONFIG_DIR"/firefox/*/gmp-widevinecdm/*)\n      if [ "${#widevine_paths[@]}" -gt 0 ]; then\n        restorecon -vr -- "${widevine_paths[@]}"\n      fi\n    ) \&' "$launcher_tmp"
command -v python3 >/dev/null 2>&1 \
    || fail "python3 is unavailable for the reviewed Firefox launcher transform"
python3 - "$launcher_tmp" <<'NOID_FF_LAUNCHER_PATCH_PYEOF'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = path.read_text(encoding="utf-8")
anchor = 'exec $MOZ_PROGRAM "$@"'
if data.count(anchor) != 1:
    raise SystemExit("reviewed Firefox exec anchor changed during transform")
launch_block = '''\
# NoID Privacy: resolve registered XDG profiles to an explicit, validated path.
# This avoids the legacy-profile shadowing tracked as Mozilla Bug 2003137.
# Explicit path/manager/creation requests remain native.
NOID_FF_PROFILE_HELPER=/usr/local/lib/noid-privacy/firefox-profiles.sh
if [ ! -f "$NOID_FF_PROFILE_HELPER" ] || [ -L "$NOID_FF_PROFILE_HELPER" ]; then
  echo "NoID Privacy: Firefox profile helper is missing or unsafe." >&2
  exit 1
fi
. "$NOID_FF_PROFILE_HELPER"
if ! prepare_firefox_launch_args "$@"; then
  echo "NoID Privacy: the hardened default-release profile is unavailable." >&2
  echo "Run noid-firefox-harden-profile or use --ProfileManager explicitly." >&2
  exit 1
fi
set -- "${NOID_FF_LAUNCH_ARGS[@]}"
unset NOID_FF_LAUNCH_ARGS
'''
path.write_text(data.replace(anchor, launch_block + anchor), encoding="utf-8")
NOID_FF_LAUNCHER_PATCH_PYEOF
sed -i "s|^export MOZ_APP_LAUNCHER=\"$vendor_launcher\"$|export MOZ_APP_LAUNCHER=\"$owned_launcher\"|" \
    "$launcher_tmp"
bash -n "$launcher_tmp" || fail "derived Firefox launcher is not valid Bash"
chmod 0755 "$launcher_tmp"; chown root:root "$launcher_tmp"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$launcher_tmp" || fail "cannot label derived Firefox launcher"
fi
sync -- "$launcher_tmp"
mv -fT -- "$launcher_tmp" "$owned_launcher"
launcher_tmp=
sync -- "$owned_launcher"; sync -- /usr/local/bin

cp -- "$vendor_desktop" "$desktop_tmp"
sed -i 's|^Exec=firefox %u$|Exec=/usr/local/bin/firefox %u|' "$desktop_tmp"
sed -i 's|^Exec=firefox --new-window %u$|Exec=/usr/local/bin/firefox --new-window %u|' "$desktop_tmp"
sed -i 's|^Exec=firefox --private-window %u$|Exec=/usr/local/bin/firefox --private-window %u|' "$desktop_tmp"
if grep -q '^\[Desktop Action profile-manager-window\]' "$desktop_tmp"; then
    sed -i 's|^\(Actions=.*\);profile-manager-window\(;\?\)|\1\2|' "$desktop_tmp"
    sed -i 's|^\(Actions=\)profile-manager-window;|\1|' "$desktop_tmp"
    awk '/^\[Desktop Action profile-manager-window\]$/ { skip=1; next }
         skip && /^\[/ { skip=0 }
         !skip' "$desktop_tmp" > "${desktop_tmp}.filtered"
    mv -f -- "${desktop_tmp}.filtered" "$desktop_tmp"
fi
grep -qx 'Exec=/usr/local/bin/firefox %u' "$desktop_tmp" \
    || fail "derived Firefox desktop main Exec is not canonical"
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$desktop_tmp" || fail "derived Firefox desktop entry is invalid"
fi
chmod 0644 "$desktop_tmp"; chown root:root "$desktop_tmp"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$desktop_tmp" || fail "cannot label derived Firefox desktop entry"
fi
sync -- "$desktop_tmp"
mv -fT -- "$desktop_tmp" "$owned_desktop"
desktop_tmp=
rmdir -- "$desktop_stage_dir" \
    || fail "cannot remove private Firefox desktop staging directory"
desktop_stage_dir=
sync -- "$owned_desktop"; sync -- /usr/local/share/applications

# Converge distribution/extensions/ to the exact current firefox-langpacks
# name/byte set. The Step-3d copies are not RPM-owned, so an update can
# otherwise leave stale entries, omit newly packaged locales, or retain old
# bytes that Firefox marks appDisabled after a browser major upgrade.
#
# Fedora marks regional XPIs with RPM language tags and also ships a small set
# of generic-locale aliases as relative symlinks. RPM may install an alias while
# omitting its regional target under the transaction's install-lang selection.
# Accept only aliases whose state and link text exactly match the signed RPM
# header. A missing target in RPM state 2 is an intentionally unavailable alias;
# skip it. A present target must itself be a state-0, SHA-256-verified regular
# firefox-langpacks payload. No filesystem-discovered or cross-directory link is
# ever followed, and every published destination remains a regular file.
LPSRC=/usr/lib64/firefox/langpacks
LPDST=/usr/lib64/firefox/distribution/extensions
if [ ! -d "$LPSRC" ] || [ -L "$LPSRC" ]; then
    fail "Firefox langpack source directory is missing or symlinked"
fi
if [ -L "$LPDST" ] || { [ -e "$LPDST" ] && [ ! -d "$LPDST" ]; }; then
    fail "Firefox distribution extension directory is unsafe"
fi
install -d -m 0755 -o root -g root "$LPDST"
shopt -s nullglob
langpack_candidates=("$LPSRC"/langpack-*.xpi)
[ "${#langpack_candidates[@]}" -gt 0 ] \
    || fail "Firefox langpack source directory has no candidates"
[ "$(rpm -q --qf '%{FILEDIGESTALGO}' firefox-langpacks 2>/dev/null)" = 8 ] \
    || fail "firefox-langpacks RPM does not declare SHA-256 file digests"
langpack_rpm_manifest=$(rpm -q --qf \
    '[%{FILENAMES}\t%{FILESTATES}\t%{FILELINKTOS}\t%{FILEDIGESTS}\n]' \
    firefox-langpacks 2>/dev/null) \
    || fail "cannot read firefox-langpacks RPM file metadata"

langpack_rpm_field() {
    local path=$1 column=$2
    printf '%s\n' "$langpack_rpm_manifest" \
        | awk -F '\t' -v p="$path" -v c="$column" '
            $1 == p { print $c; found=1; exit }
            END { if (!found) exit 1 }
        '
}

verify_regular_langpack() {
    local path=$1 state link digest actual
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    state=$(langpack_rpm_field "$path" 2) || return 1
    link=$(langpack_rpm_field "$path" 3) || return 1
    digest=$(langpack_rpm_field "$path" 4) || return 1
    [ "$state" = 0 ] && [ -z "$link" ] && [ "${#digest}" -eq 64 ] \
        || return 1
    actual=$(sha256sum "$path" | awk '{print $1}') || return 1
    [ "$actual" = "$digest" ]
}

declare -A source_langpack_paths=()
for _lp in "${langpack_candidates[@]}"; do
    _n=${_lp##*/}
    if [ -L "$_lp" ]; then
        _state=$(langpack_rpm_field "$_lp" 2) \
            || fail "Firefox langpack alias is absent from RPM metadata: $_n"
        _expected_link=$(langpack_rpm_field "$_lp" 3) \
            || fail "Firefox langpack alias metadata is incomplete: $_n"
        _actual_link=$(readlink -- "$_lp") \
            || fail "cannot read Firefox langpack alias: $_n"
        case "$_expected_link" in
            ''|*/*|.|..|*[!A-Za-z0-9._@+-]*)
                fail "Firefox RPM declares an unsafe langpack alias: $_n"
                ;;
        esac
        case "$_expected_link" in
            langpack-*.xpi) ;;
            *) fail "Firefox RPM langpack alias target has an unexpected name: $_n" ;;
        esac
        [ "$_state" = 0 ] && [ "$_actual_link" = "$_expected_link" ] \
            || fail "Firefox langpack alias differs from its RPM payload: $_n"
        _target="$LPSRC/$_expected_link"
        if [ ! -e "$_target" ] && [ ! -L "$_target" ]; then
            _target_state=$(langpack_rpm_field "$_target" 2) \
                || fail "Firefox langpack alias target is absent from RPM metadata: $_n"
            [ "$_target_state" = 2 ] \
                || fail "Firefox langpack alias target is unexpectedly missing: $_n"
            continue
        fi
        verify_regular_langpack "$_target" \
            || fail "Firefox langpack alias target is not a pristine RPM payload: $_n"
        source_langpack_paths["$_n"]="$_target"
    elif [ -f "$_lp" ]; then
        verify_regular_langpack "$_lp" \
            || fail "Firefox langpack is not a pristine RPM payload: $_n"
        source_langpack_paths["$_n"]="$_lp"
    else
        fail "Firefox langpack source has an unsupported file type: $_n"
    fi
done
[ "${#source_langpack_paths[@]}" -gt 0 ] \
    || fail "Firefox langpack source set has no installed regular payloads"
mapfile -t source_langpack_names < <(
    printf '%s\n' "${!source_langpack_paths[@]}" | LC_ALL=C sort
)
for _lp in "$LPDST"/langpack-*.xpi; do
    [ -f "$_lp" ] && [ ! -L "$_lp" ] \
        || fail "Firefox langpack destination is non-regular or symlinked: $_lp"
done
for _n in "${source_langpack_names[@]}"; do
    _lp=${source_langpack_paths[$_n]}
    _dst="$LPDST/$_n"
    langpack_tmp=$(mktemp "$LPDST/.noid-firefox-langpack.XXXXXX") \
        || fail "cannot stage Firefox langpack: $_n"
    if ! install -m 0644 -o root -g root "$_lp" "$langpack_tmp"; then
        rm -f -- "$langpack_tmp"
        langpack_tmp=
        fail "cannot stage Firefox langpack: $_n"
    fi
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -F "$langpack_tmp" \
            || { rm -f -- "$langpack_tmp"; langpack_tmp=; fail "cannot label Firefox langpack: $_n"; }
    fi
    sync -- "$langpack_tmp"
    mv -fT -- "$langpack_tmp" "$_dst" \
        || { rm -f -- "$langpack_tmp"; langpack_tmp=; fail "cannot publish Firefox langpack: $_n"; }
    langpack_tmp=
done
for _lp in "$LPDST"/langpack-*.xpi; do
    _n=${_lp##*/}
    if [ -z "${source_langpack_paths[$_n]+present}" ]; then
        rm -f -- "$_lp" || fail "cannot remove stale Firefox langpack: $_n"
    fi
done
if command -v restorecon >/dev/null 2>&1; then
    restorecon -R "$LPDST" || fail "cannot label Firefox distribution extensions"
fi
source_langpack_set=$(printf '%s\n' "${source_langpack_names[@]}")
installed_langpack_set=$(find "$LPDST" -maxdepth 1 -type f -name 'langpack-*.xpi' \
    -printf '%f\n' | LC_ALL=C sort)
[ "$source_langpack_set" = "$installed_langpack_set" ] \
    || fail "final Firefox langpack name set differs from RPM source"
while IFS= read -r _n; do
    [ -n "$_n" ] || continue
    cmp -s "${source_langpack_paths[$_n]}" "$LPDST/$_n" \
        || fail "final Firefox langpack bytes differ: $_n"
done <<< "$source_langpack_set"
sync -- "$LPDST"

# Re-assert the AutoConfig payload inside the firefox package tree from the
# canonical cache. Preflight the complete source set before any publication:
# a partial/missing cache must make the DNF action fail visibly, not leave a
# silently incomplete policy. Publish beside each destination then rename so a
# concurrently starting browser never observes a truncated configuration.
autoconfig_changed=0
autoconfig_pairs=(
    "/usr/share/noid-firefox/mozilla.cfg::/usr/lib64/firefox/mozilla.cfg" \
    "/usr/share/noid-firefox/autoconfig.js::/usr/lib64/firefox/defaults/pref/autoconfig.js" \
    "/usr/share/noid-firefox/noid-locale.js::/usr/lib64/firefox/defaults/pref/noid-locale.js"
)
for src_dst in "${autoconfig_pairs[@]}"; do
    src="${src_dst%%::*}"
    if [ ! -f "$src" ] || [ -L "$src" ]; then
        fail "canonical AutoConfig source missing, non-regular or symlinked: $src"
    fi
done

publish_autoconfig() {
    local src=$1 dst=$2 parent tmp
    parent=${dst%/*}
    install -d -m 0755 -o root -g root "$parent"
    if [ -f "$dst" ] && [ ! -L "$dst" ] && cmp -s "$src" "$dst" \
            && [ "$(stat -c %a "$dst" 2>/dev/null || true)" = 644 ]; then
        return 0
    fi
    tmp=$(mktemp "$parent/.noid-firefox-autoconfig.XXXXXX") \
        || fail "cannot stage $dst"
    if ! install -m 0644 -o root -g root "$src" "$tmp"; then
        rm -f -- "$tmp"
        fail "cannot stage canonical AutoConfig for $dst"
    fi
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -F "$tmp" || { rm -f -- "$tmp"; fail "cannot label staged $dst"; }
    fi
    sync -- "$tmp"
    mv -fT -- "$tmp" "$dst" || { rm -f -- "$tmp"; fail "cannot publish $dst"; }
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -F "$dst" || fail "cannot label published $dst"
    fi
    [ -f "$dst" ] && [ ! -L "$dst" ] && cmp -s "$src" "$dst" \
        && [ "$(stat -c %a "$dst" 2>/dev/null || true)" = 644 ] \
        || fail "AutoConfig postcondition failed for $dst"
    sync -- "$dst"
    sync -- "$parent"
    autoconfig_changed=1
}

for src_dst in "${autoconfig_pairs[@]}"; do
    src="${src_dst%%::*}"
    dst="${src_dst#*::}"
    publish_autoconfig "$src" "$dst"
done
if [ "$autoconfig_changed" -eq 1 ]; then
    logger -t noid-firefox-reassert "re-asserted AutoConfig payload inside the firefox package tree"
fi
logger -t noid-firefox-reassert "regenerated owned Firefox launcher/XDG overlays and langpacks"
NOID_FF_REASSERT_EOF
chmod 755 /usr/local/sbin/noid-firefox-reassert
chown root:root /usr/local/sbin/noid-firefox-reassert

mkdir -p /etc/dnf/libdnf5-plugins/actions.d
cat > /etc/dnf/libdnf5-plugins/actions.d/noid-firefox.actions <<'NOID_FF_ACTIONS_EOF'
# Regenerate NoID Privacy-owned launcher/XDG overlays from the newly installed,
# signed Firefox RPM payload. Vendor-owned files remain pristine.
# Format: callback:package_filter:direction:options:command
post_transaction:firefox:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-firefox-reassert\ >/dev/null
post_transaction:firefox-langpacks:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-firefox-reassert\ >/dev/null
NOID_FF_ACTIONS_EOF
chmod 644 /etc/dnf/libdnf5-plugins/actions.d/noid-firefox.actions
/usr/local/sbin/noid-firefox-reassert
log "  Installed Firefox overlay generator + post-transaction action"

#------------------------------------------------------------------------------
# Step 7: Verification
#------------------------------------------------------------------------------
log "Step 7/8: Verification"
fail=0

# File existence checks
# Post arkenfox absorption, one consolidated base plus the reviewed DRM consent
# overlay ship (not user-overrides.js/updater.sh/prefsCleaner.sh).
for path in \
    "$SHARE_DIR/user.js" \
    "$SHARE_DIR/user-drm-overrides.js" \
    "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" \
    "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json" \
    "$LOCAL_BIN_DIR/noid-firefox-setup.sh" \
    /usr/local/bin/noid-firefox-drm \
    "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop"
do
    if [ ! -f "$path" ]; then
        log "  FAIL: $path missing"
        fail=$((fail + 1))
    fi
done

# Verify consolidated user.js integrity (v2 post arkenfox absorption)
if ! grep -q '_user.js.parrot' "$SHARE_DIR/user.js"; then
    log "  FAIL: arkenfox-derived parrot markers missing in user.js"
    fail=$((fail + 1))
fi
if ! grep -q 'NOID-COMPLETE' "$SHARE_DIR/user.js"; then
    log "  FAIL: NoID Privacy end-parrot marker missing in user.js (decode failed?)"
    fail=$((fail + 1))
fi
if ! grep -q 'SECTION: MOZILLA AI / CLOUD-VPN / NIMBUS BLOCK' "$SHARE_DIR/user.js"; then
    log "  FAIL: NoID Privacy image overrides MOZILLA AI BLOCK section missing in user.js"
    fail=$((fail + 1))
fi

# Verify the exact current managed-storage schema. Only the filter-list set is
# managed; legacy backup-format adminSettings would also wipe user-owned rules,
# trusted sites, imported lists and My filters on every uBO launch.
if ! python3 - "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json" \
        "$EXPECTED_FILTER_LIST_COUNT" <<'UBO_POLICY_PYEOF'
import json
import sys

expected = [
    "user-filters",
    "ublock-filters",
    "ublock-badware",
    "ublock-privacy",
    "ublock-quick-fixes",
    "ublock-unbreak",
    "easylist",
    "easyprivacy",
    "urlhaus-1",
    "plowe-0",
    "adguard-spyware-url",
    "block-lan",
    "curben-phishing",
]
with open(sys.argv[1], encoding="utf-8") as handle:
    managed = json.load(handle)
assert managed == {
    "name": "uBlock0@raymondhill.net",
    "description": (
        "NoID Privacy Workstation 44 - uBlock Origin managed "
        "filter-list baseline (Module 16)"
    ),
    "type": "storage",
    "data": {"toOverwrite": {"filterLists": expected}},
}
assert len(expected) == int(sys.argv[2])
UBO_POLICY_PYEOF
then
    log "  FAIL: managed uBO filter-list policy differs from the exact current schema"
    fail=$((fail + 1))
else
    log "  OK: exact $EXPECTED_FILTER_LIST_COUNT-list uBO policy preserves user-owned settings"
fi
if ! "$UBO_POLICY_VALIDATOR" \
        "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" \
        "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json"; then
    log "  FAIL: managed uBO filter-list policy is incompatible with the pinned XPI"
    fail=$((fail + 1))
else
    log "  OK: every managed filter-list token is supported by the pinned uBO XPI"
fi

# Verify setup script bash syntax
if ! bash -n "$LOCAL_BIN_DIR/noid-firefox-setup.sh" 2>/dev/null; then
    log "  FAIL: noid-firefox-setup.sh bash syntax error"
    fail=$((fail + 1))
fi

# Verify autostart desktop file is parseable (basic key-value format)
if ! grep -q '^Exec=/usr/local/bin/noid-firefox-setup.sh$' "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop"; then
    log "  FAIL: autostart desktop file Exec line malformed"
    fail=$((fail + 1))
fi

if [ "$fail" -gt 0 ]; then
    log "=== Module 16 FAILED with $fail errors ==="
    exit 1
fi

log "  Core Firefox artifacts passed the pre-Anaconda verification"

#------------------------------------------------------------------------------
# Step 8: Anaconda WebUI Firefox profile hardening
#------------------------------------------------------------------------------
# Anaconda WebUI renders the install UI in a Firefox profile built from
# /usr/share/anaconda/firefox-theme/{live,default,extlink}/user.js. The
# upstream templates set only 6 privacy prefs — Normandy/Nimbus/Push/Safe-
# Browsing/region beacons stay active during the ~10-15-min install window
# (observed Mozilla-GCP traffic with a unique nimbus.profileId).
# Fix: APPEND comprehensive overrides to all three templates (later wins in
# user.js semantics; upstream UI-behavior prefs preserved — NOT replace).
# The exact suffix is staged separately, published atomically and skipped only
# when a byte-identical completed block is already present.

log "Step 8/8: Anaconda WebUI Firefox profile hardening"

ANACONDA_FF_THEME_DIR=/usr/share/anaconda/firefox-theme
NOID_ANACONDA_FF_MARKER="// === NoID Privacy — Anaconda WebUI Firefox profile hardening ==="
ANACONDA_FF_BLOCK_TMP=
ANACONDA_FF_TARGET_TMP=
cleanup_anaconda_ff_temps() {
    [ -z "${ANACONDA_FF_TARGET_TMP:-}" ] \
        || rm -f -- "$ANACONDA_FF_TARGET_TMP"
    [ -z "${ANACONDA_FF_BLOCK_TMP:-}" ] \
        || rm -f -- "$ANACONDA_FF_BLOCK_TMP"
}
trap cleanup_anaconda_ff_temps EXIT

ANACONDA_FF_BLOCK_TMP=$(mktemp /var/tmp/noid-anaconda-firefox.XXXXXXXX)
cat > "$ANACONDA_FF_BLOCK_TMP" <<'NOID_ANACONDA_FF_EOF'

// === NoID Privacy — Anaconda WebUI Firefox profile hardening ===
// Disable all Mozilla-cloud / Google-safe-browsing / Push / Region / Update
// outbound traffic. Anaconda WebUI is local-only (cockpit-ws on 127.0.0.1:80);
// no external network needed during install. Preserves Anaconda UI functionality
// (extlink protocol handler, custom toolbar, etc. defined above).

// 1. Connectivity / captive-portal detection
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("captivedetect.canonicalURL", "");

// 2. Normandy (studies / A-B testing) — full disable
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("app.normandy.first_run", false);
user_pref("app.shield.optoutstudies.enabled", false);

// 3. Nimbus remote-configuration rollouts
user_pref("nimbus.rollouts.enabled", false);

// 4. Mozilla Settings Sync (services.settings.*) — disable
user_pref("services.settings.server", "data:,");
user_pref("services.settings.poll_interval", 0);

// 5. Telemetry — full disable (extends upstream's partial config)
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.coverage.opt-out", true);
user_pref("datareporting.healthreport.service.enabled", false);

// 6. Safe Browsing (Google + Mozilla list updates)
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.mozilla.gethashURL", "");
user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");

// 7. Push notifications (Mozilla Push Service)
user_pref("dom.push.enabled", false);
user_pref("dom.push.connection.enabled", false);
user_pref("dom.push.serverURL", "");
user_pref("dom.webnotifications.enabled", false);

// 8. Region / Geolocation
user_pref("browser.region.network.url", "");
user_pref("browser.region.update.enabled", false);
user_pref("geo.enabled", false);
user_pref("geo.provider.network.url", "");

// 9. Crash reports
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);

// 10. Update mechanisms (Live-ISO is read-only; updates are inapplicable)
user_pref("app.update.auto", false);
user_pref("extensions.update.enabled", false);
user_pref("extensions.systemAddon.update.enabled", false);

// 11. GMP / DRM updaters (Widevine, OpenH264)
user_pref("media.gmp-gmpopenh264.enabled", false);
user_pref("media.gmp-widevinecdm.enabled", false);

// 12. Search suggestions / sync (no external search needed)
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.search.update", false);

// 13. TRR (Mozilla DoH) — use system DNS in the isolated installer context
user_pref("network.trr.mode", 5);

// 14. Recommendations
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);

// 15. Firefox Account / Sync
user_pref("identity.fxaccounts.enabled", false);
user_pref("services.sync.engine.addons", false);

// 16. WebRTC (no peer-to-peer in install context)
user_pref("media.peerconnection.enabled", false);

// 17. Firefox 153 Messaging System / ASRouter providers
// The installer UI uses none of these message sources. Disabling the complete
// built-in provider set also avoids ASRouter querying uninitialized telemetry
// session dates while the install profile keeps telemetry disabled.
user_pref("browser.newtabpage.activity-stream.asrouter.providers.message-groups", "null");
user_pref("browser.newtabpage.activity-stream.asrouter.providers.onboarding", "null");
user_pref("browser.newtabpage.activity-stream.asrouter.providers.cfr", "null");
user_pref("browser.newtabpage.activity-stream.asrouter.providers.messaging-experiments", "null");

// === END NoID Privacy hardening ===
NOID_ANACONDA_FF_EOF
chmod 0600 "$ANACONDA_FF_BLOCK_TMP"
ANACONDA_FF_BLOCK_SIZE=$(stat -c '%s' "$ANACONDA_FF_BLOCK_TMP")

anaconda_ff_block_is_exact_suffix() {
    local target="$1" target_size
    [ -f "$target" ] && [ ! -L "$target" ] || return 1
    [ "$(grep -Fxc "$NOID_ANACONDA_FF_MARKER" "$target" 2>/dev/null || true)" -eq 1 ] \
        || return 1
    [ "$(grep -Fxc '// === END NoID Privacy hardening ===' \
        "$target" 2>/dev/null || true)" -eq 1 ] || return 1
    target_size=$(stat -c '%s' "$target") || return 1
    [ "$target_size" -ge "$ANACONDA_FF_BLOCK_SIZE" ] || return 1
    tail -c "$ANACONDA_FF_BLOCK_SIZE" "$target" \
        | cmp -s - "$ANACONDA_FF_BLOCK_TMP"
}

if [ ! -d "$ANACONDA_FF_THEME_DIR" ] || [ -L "$ANACONDA_FF_THEME_DIR" ]; then
    log "  [FAIL] $ANACONDA_FF_THEME_DIR not found — required Anaconda WebUI profile tree absent"
    exit 1
else
    for profile in live default extlink; do
        profile_dir="$ANACONDA_FF_THEME_DIR/$profile"
        target="$profile_dir/user.js"
        if [ ! -d "$profile_dir" ] || [ -L "$profile_dir" ] || \
           [ ! -f "$target" ] || [ -L "$target" ]; then
            log "  [FAIL] $target missing — required installer-browser profile contract absent"
            exit 1
        fi

        marker_count=$(grep -Fxc "$NOID_ANACONDA_FF_MARKER" \
            "$target" 2>/dev/null || true)
        if [ "$marker_count" -ne 0 ]; then
            if ! anaconda_ff_block_is_exact_suffix "$target"; then
                log "  [FAIL] $target contains a partial or modified NoID Privacy block"
                exit 1
            fi
            chmod 0644 "$target"
            chown root:root "$target"
            command -v restorecon >/dev/null 2>&1 \
                && restorecon -F "$target" 2>/dev/null || true
            log "  [SKIP] $target already ends in the exact hardening block"
            continue
        fi

        # Publish the complete suffix atomically. A failed copy, sync or rename
        # leaves the package-owned input intact and no misleading marker behind.
        ANACONDA_FF_TARGET_TMP=$(mktemp "$profile_dir/.user.js.noid.XXXXXXXX")
        if ! cp -- "$target" "$ANACONDA_FF_TARGET_TMP" || \
           ! cat "$ANACONDA_FF_BLOCK_TMP" >> "$ANACONDA_FF_TARGET_TMP" || \
           ! anaconda_ff_block_is_exact_suffix "$ANACONDA_FF_TARGET_TMP" || \
           ! chmod 0644 "$ANACONDA_FF_TARGET_TMP" || \
           ! chown root:root "$ANACONDA_FF_TARGET_TMP" || \
           ! sync -- "$ANACONDA_FF_TARGET_TMP" || \
           ! mv -fT -- "$ANACONDA_FF_TARGET_TMP" "$target" || \
           ! sync -- "$profile_dir"; then
            log "  [FAIL] atomic Anaconda Firefox hardening publication failed: $target"
            exit 1
        fi
        ANACONDA_FF_TARGET_TMP=
        command -v restorecon >/dev/null 2>&1 \
            && restorecon -F "$target" 2>/dev/null || true
        log "  [OK] $target — exact NoID Privacy hardening block published atomically"
    done
fi

# Verification of Step 8
ff_theme_fail=0
for profile in live default extlink; do
    target="$ANACONDA_FF_THEME_DIR/$profile/user.js"
    if [ ! -f "$target" ] || [ -L "$target" ]; then
        log "  [FAIL] required Anaconda profile disappeared before final verification: $target"
        ff_theme_fail=$((ff_theme_fail + 1))
        continue
    fi
    if ! anaconda_ff_block_is_exact_suffix "$target" || \
       [ "$(stat -c '%u:%g:%a:%h' "$target")" != "0:0:644:1" ]; then
        log "  [FAIL] $target differs from the exact hardening suffix/metadata"
        ff_theme_fail=$((ff_theme_fail + 1))
    fi
done

if [ "$ff_theme_fail" -gt 0 ]; then
    log "=== Module 16: Anaconda firefox-theme hardening FAILED ($ff_theme_fail errors) ==="
    exit 1
fi

log "    Anaconda Firefox-theme hardened (live + default + extlink — Bug #61 fix)"

#------------------------------------------------------------------------------
# Final closed deployment gate + health stamp
#------------------------------------------------------------------------------
log "Final gate: exact Firefox deployment contracts"
final_fail=0

require_regular() {
    local path="$1"
    if [ ! -f "$path" ] || [ -L "$path" ] || [ ! -s "$path" ]; then
        log "  [FAIL] missing, empty, non-regular or symlinked: $path"
        final_fail=$((final_fail + 1))
    fi
}

for path in \
    "$SHARE_DIR/user.js" \
    "$SHARE_DIR/user-drm-overrides.js" \
    "$ARKENFOX_LICENSE" \
    "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" \
    "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json" \
    "$FIREFOX_LIB_DIR/mozilla.cfg" \
    "$AUTOCONFIG_PREF_DIR/autoconfig.js" \
    "$AUTOCONFIG_PREF_DIR/noid-locale.js" \
    /etc/firefox/policies/policies.json \
    /usr/lib64/firefox/distribution/distribution.ini \
    /usr/share/applications/org.mozilla.firefox.desktop \
    /usr/local/bin/firefox \
    /usr/local/share/applications/org.mozilla.firefox.desktop \
    "$UBO_POLICY_SOURCE" \
    "$UBO_POLICY_VALIDATOR" \
    /usr/local/lib/noid-privacy/validate-webextension.py \
    /usr/local/lib/noid-privacy/verify-firefox-xpi-signature \
    /usr/local/lib/noid-privacy/firefox-profiles.sh \
    "$LOCAL_BIN_DIR/noid-firefox-setup.sh" \
    "$LOCAL_BIN_DIR/noid-firefox-harden-profile" \
    /usr/local/bin/noid-firefox-relax-fpp \
    /usr/local/bin/noid-firefox-relax-webrtc \
    /usr/local/bin/noid-firefox-drm \
    /usr/local/sbin/noid-firefox-reassert \
    /etc/dnf/libdnf5-plugins/actions.d/noid-firefox.actions \
    "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop" \
    "$SKEL_FF_BASE/profiles.ini" \
    "$SKEL_FF_PROFILE/user.js" \
    "$SKEL_FF_PROFILE/extension-preferences.json" \
    "$SKEL_FF_PROFILE/extensions/uBlock0@raymondhill.net.xpi"; do
    require_regular "$path"
done

for helper_path in \
    "$UBO_POLICY_VALIDATOR" \
    /usr/local/lib/noid-privacy/validate-webextension.py \
    /usr/local/lib/noid-privacy/verify-firefox-xpi-signature \
    /usr/local/lib/noid-privacy/firefox-profiles.sh; do
    if ! matchpathcon -V "$helper_path" >/dev/null; then
        log "  [FAIL] installed Firefox helper SELinux context differs: $helper_path"
        final_fail=$((final_fail + 1))
    fi
done

if ! cmp -s -- "$UBO_POLICY_SOURCE" \
        "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json"; then
    log "  [FAIL] active uBO policy differs from its canonical source"
    final_fail=$((final_fail + 1))
fi

for python_path in \
    "$UBO_POLICY_VALIDATOR" \
    /usr/local/lib/noid-privacy/validate-webextension.py; do
    if ! python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_text(), str(p), "exec")' \
            "$python_path" 2>/dev/null; then
        log "  [FAIL] installed Python validator does not parse: $python_path"
        final_fail=$((final_fail + 1))
    fi
    if [ "$(stat -c '%U:%G:%a' "$python_path" 2>/dev/null || true)" != \
            "root:root:755" ]; then
        log "  [FAIL] installed Python validator metadata differs: $python_path"
        final_fail=$((final_fail + 1))
    fi
done

for shell_path in \
    /usr/local/lib/noid-privacy/verify-firefox-xpi-signature \
    /usr/local/lib/noid-privacy/firefox-profiles.sh \
    "$LOCAL_BIN_DIR/noid-firefox-setup.sh" \
    "$LOCAL_BIN_DIR/noid-firefox-harden-profile" \
    /usr/local/bin/noid-firefox-relax-fpp \
    /usr/local/bin/noid-firefox-relax-webrtc \
    /usr/local/bin/noid-firefox-drm \
    /usr/local/bin/firefox \
    /usr/local/sbin/noid-firefox-reassert; do
    if ! bash -n "$shell_path" 2>/dev/null; then
        log "  [FAIL] installed shell payload does not parse: $shell_path"
        final_fail=$((final_fail + 1))
    fi
done

if [ "$(grep -Fxc '// NOID-DRM-OPT-IN-BEGIN' "$SHARE_DIR/user-drm-overrides.js" 2>/dev/null || true)" -ne 1 ] || \
   [ "$(grep -Fxc '// NOID-DRM-OPT-IN-END' "$SHARE_DIR/user-drm-overrides.js" 2>/dev/null || true)" -ne 1 ] || \
   ! grep -qx 'user_pref("media.gmp-manager.updateEnabled", true);' \
       "$SHARE_DIR/user-drm-overrides.js"; then
    log "  [FAIL] exact Firefox DRM consent overlay differs"
    final_fail=$((final_fail + 1))
fi

if ! cmp -s "$SHARE_DIR/user.js" "$SKEL_FF_PROFILE/user.js"; then
    log "  [FAIL] canonical and skel Firefox user.js differ"
    final_fail=$((final_fail + 1))
fi
if grep -Eq '^[[:space:]]*user_pref\("browser\.uiCustomization\.state"' \
        "$SHARE_DIR/user.js" || \
   [ "$(grep -Fxc -- "$TOOLBAR_DEFAULT_PREF" \
        "$FIREFOX_LIB_DIR/mozilla.cfg" 2>/dev/null || true)" -ne 1 ]; then
    log "  [FAIL] Firefox toolbar state is not one user-overridable AutoConfig default"
    final_fail=$((final_fail + 1))
fi
if ! cmp -s "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" \
        "$SKEL_FF_PROFILE/extensions/uBlock0@raymondhill.net.xpi"; then
    log "  [FAIL] staged and skel uBO XPI differ"
    final_fail=$((final_fail + 1))
fi
final_ubo_size=$(stat -c '%s' \
    "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" 2>/dev/null || true)
final_ubo_size=${final_ubo_size:-0}
if [ "$final_ubo_size" -ne "$UBO_SIZE_EXPECTED" ] || \
   [ "$(sha256sum "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" 2>/dev/null | awk '{print $1}')" != "$UBO_SHA256" ]; then
    log "  [FAIL] final uBO XPI differs from exact source pin"
    final_fail=$((final_fail + 1))
fi
if ! "$UBO_POLICY_VALIDATOR" \
        "$EXTENSIONS_DIR/uBlock0@raymondhill.net.xpi" \
        "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json"; then
    log "  [FAIL] final managed uBO policy is incompatible with the pinned XPI"
    final_fail=$((final_fail + 1))
fi

if ! python3 - "$EXPECTED_FILTER_LIST_COUNT" \
        /etc/firefox/policies/policies.json \
        "$MANAGED_STORAGE_DIR/uBlock0@raymondhill.net.json" \
        "$SKEL_FF_PROFILE/extension-preferences.json" <<'FINAL_JSON_PYEOF'
import json, sys
expected_filter_list_count = int(sys.argv[1])
expected_filter_lists = [
    "user-filters",
    "ublock-filters",
    "ublock-badware",
    "ublock-privacy",
    "ublock-quick-fixes",
    "ublock-unbreak",
    "easylist",
    "easyprivacy",
    "urlhaus-1",
    "plowe-0",
    "adguard-spyware-url",
    "block-lan",
    "curben-phishing",
]
assert len(expected_filter_lists) == expected_filter_list_count
with open(sys.argv[2], encoding="utf-8") as handle:
    policies = json.load(handle)
assert policies == {"policies": {"SearchEngines": {"Default": "DuckDuckGo"}}}
with open(sys.argv[3], encoding="utf-8") as handle:
    managed = json.load(handle)
assert managed == {
    "name": "uBlock0@raymondhill.net",
    "description": (
        "NoID Privacy Workstation 44 - uBlock Origin managed "
        "filter-list baseline (Module 16)"
    ),
    "type": "storage",
    "data": {"toOverwrite": {"filterLists": expected_filter_lists}},
}
with open(sys.argv[4], encoding="utf-8") as handle:
    seed_preferences = json.load(handle)
assert seed_preferences == {
    "uBlock0@raymondhill.net": {
        "permissions": ["internal:privateBrowsingAllowed"],
        "origins": [],
        "data_collection": [],
    }
}
FINAL_JSON_PYEOF
then
    log "  [FAIL] final Firefox policy/managed-storage/skel-permission schema differs"
    final_fail=$((final_fail + 1))
fi

if ! grep -qx 'pref("general.config.filename", "mozilla.cfg");' "$AUTOCONFIG_PREF_DIR/autoconfig.js" || \
   ! grep -qx 'pref("general.config.obscure_value", 0);' "$AUTOCONFIG_PREF_DIR/autoconfig.js" || \
   ! grep -qx 'pref("general.config.sandbox_enabled", true);' "$AUTOCONFIG_PREF_DIR/autoconfig.js" || \
   ! grep -qx 'lockPref("browser.profiles.enabled", false);' "$FIREFOX_LIB_DIR/mozilla.cfg" || \
   ! grep -qx 'lockPref("browser.newtabpage.activity-stream.default.sites", "");' "$FIREFOX_LIB_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("network.trr.mode", 5);' "$FIREFOX_LIB_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("doh-rollout.home-region", "global");' "$FIREFOX_LIB_DIR/mozilla.cfg" || \
   ! grep -qx 'defaultPref("browser.sessionstore.persist_closed_tabs_between_sessions", false);' \
       "$FIREFOX_LIB_DIR/mozilla.cfg" || \
   grep -Eq '^defaultPref\("network\.trr\.(uri|custom_uri|bootstrapAddr)"' \
       "$FIREFOX_LIB_DIR/mozilla.cfg"; then
    log "  [FAIL] final Firefox AutoConfig pointer/lock contract differs"
    final_fail=$((final_fail + 1))
fi

if ! grep -qF 'prepare_firefox_launch_args "$@"' /usr/local/bin/firefox || \
   ! grep -qF 'if [ -f "$HOME/.mozilla/firefox/profiles.ini" ]; then' \
       /usr/local/bin/firefox || \
   ! grep -qx 'Exec=/usr/local/bin/firefox %u' \
       /usr/local/share/applications/org.mozilla.firefox.desktop || \
   ! rpm -Vf /usr/bin/firefox >/dev/null 2>&1 || \
   ! rpm -Vf /usr/share/applications/org.mozilla.firefox.desktop >/dev/null 2>&1 || \
   ! rpm -Vf /usr/lib64/firefox/distribution/distribution.ini >/dev/null 2>&1 || \
   ! grep -qx 'Exec=/usr/local/bin/noid-firefox-setup.sh' \
       "$XDG_AUTOSTART_DIR/noid-firefox-setup.desktop"; then
    log "  [FAIL] final owned-overlay/vendor-pristine/autostart contract differs"
    final_fail=$((final_fail + 1))
fi

# Follow non-dangling RPM alias symlinks just as the publication path does;
# keep each alias basename in the expected set even though its destination is
# materialized as a regular file below FIREFOX_DIST_EXT.
source_langpacks=$(find -L "$FIREFOX_LANGPACK_SRC" -maxdepth 1 -type f \
    -name 'langpack-*.xpi' -printf '%f\n' | LC_ALL=C sort)
installed_langpacks=$(find "$FIREFOX_DIST_EXT" -maxdepth 1 -type f \
    -name 'langpack-*.xpi' -printf '%f\n' | LC_ALL=C sort)
if [ -z "$source_langpacks" ] || [ "$source_langpacks" != "$installed_langpacks" ]; then
    log "  [FAIL] final Firefox langpack name set differs from RPM source"
    final_fail=$((final_fail + 1))
else
    while IFS= read -r langpack; do
        cmp -s "$FIREFOX_LANGPACK_SRC/$langpack" "$FIREFOX_DIST_EXT/$langpack" || {
            log "  [FAIL] Firefox langpack bytes differ: $langpack"
            final_fail=$((final_fail + 1))
        }
    done <<< "$source_langpacks"
fi

for profile in live default extlink; do
    target="$ANACONDA_FF_THEME_DIR/$profile/user.js"
    if ! anaconda_ff_block_is_exact_suffix "$target" || \
       [ "$(stat -c '%u:%g:%a:%h' "$target" 2>/dev/null || true)" != "0:0:644:1" ]; then
        log "  [FAIL] Anaconda Firefox profile lacks one exact hardening block: $profile"
        final_fail=$((final_fail + 1))
    fi
done

if [ "$final_fail" -gt 0 ]; then
    log "=== Module 16 FINAL GATE FAILED with $final_fail errors ==="
    exit 1
fi

rm -f -- "$ANACONDA_FF_BLOCK_TMP"
ANACONDA_FF_BLOCK_TMP=
trap - EXIT

# M16_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        "0:0:755" ] \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    log "  FAIL: shared health-stamp directory drifted before publication"
    exit 1
fi

STAMP_TMP=
STAMP_PUBLISHED=0
cleanup_firefox_health_stamp() {
    if [ -n "${STAMP_TMP:-}" ]; then
        rm -f -- "$STAMP_TMP" || true
    fi
    if [ "${STAMP_PUBLISHED:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "  FAIL: could not retire incomplete Module 16 health stamp"
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
}
firefox_stamp_fail() {
    log "  FAIL: $*"
    exit 1
}
verify_firefox_health_stamp() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
            "0:0:644:1" ] \
        && [ "$(wc -l < "$path")" -eq 6 ] \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && grep -qxF 'module=16' "$path" \
        && grep -qxF 'name=firefox' "$path" \
        && grep -qxF 'version=1' "$path" \
        && grep -qxF 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path"
}
trap cleanup_firefox_health_stamp EXIT

STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-16-firefox.ok.XXXXXXXX") \
    || firefox_stamp_fail "cannot create Module 16 health-stamp candidate"
cat > "$STAMP_TMP" <<STAMP_EOF || \
    firefox_stamp_fail "cannot write Module 16 health-stamp candidate"
# NoID Privacy — Module 16 Health Stamp
module=16
name=firefox
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
STAMP_EOF
chmod 0644 "$STAMP_TMP" \
    || firefox_stamp_fail "cannot set Module 16 health-stamp mode"
chown root:root "$STAMP_TMP" \
    || firefox_stamp_fail "cannot set Module 16 health-stamp ownership"
restorecon -F -- "$STAMP_TMP" \
    || firefox_stamp_fail "cannot label Module 16 health-stamp candidate"
matchpathcon -V "$STAMP_TMP" >/dev/null \
    || firefox_stamp_fail "Module 16 health-stamp candidate label differs"
if ! verify_firefox_health_stamp "$STAMP_TMP"; then
    firefox_stamp_fail "staged Module 16 health-stamp contract is invalid"
fi
sync -- "$STAMP_TMP" \
    || firefox_stamp_fail "cannot sync Module 16 health-stamp candidate"
if ! mv -fT -- "$STAMP_TMP" "$STAMP"; then
    rm -f -- "$STAMP" || true
    firefox_stamp_fail "cannot publish Module 16 health stamp"
fi
STAMP_TMP=
STAMP_PUBLISHED=1
restorecon -F -- "$STAMP" \
    || firefox_stamp_fail "cannot label published Module 16 health stamp"
matchpathcon -V "$STAMP" >/dev/null \
    || firefox_stamp_fail "published Module 16 health-stamp label differs"
sync -- "$STAMP" \
    || firefox_stamp_fail "cannot sync published Module 16 health stamp"
sync -- "$STAMP_DIR" \
    || firefox_stamp_fail "cannot sync Module 16 health-stamp directory"
if ! verify_firefox_health_stamp "$STAMP"; then
    firefox_stamp_fail "published Module 16 health-stamp contract is invalid"
fi
STAMP_PUBLISHED=0
trap - EXIT
log "  Exact Module 16 health stamp published atomically"
# M16_HEALTH_PUBLICATION_END

log "=== Module 16: Firefox Hardening COMPLETE ==="
log "    NoID Privacy Firefox Hardening v${NOID_FIREFOX_HARDENING_VERSION} installed (${USERJS_SIZE:-unknown} bytes)"
log "    uBlock Origin XPI verified (${UBO_SIZE:-unknown} bytes) + managed storage manifest"
log "    Core, Anaconda WebUI and final deployment gates passed; health stamp written"

%end

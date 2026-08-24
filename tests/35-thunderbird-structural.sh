#!/usr/bin/env bash
# Module 35 Thunderbird Hardening — Structural Tests (run on build host pre-commit)
# Verifies source-of-truth files exist, are syntactically valid, and contain
# the expected NoID Privacy override structure + privacy/tracking baseline corrections.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0

log() { echo "[35-tb-structural] $*"; }
ok()  { log "  [OK] $*"; }
err() { log "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

log "=== Module 35 Thunderbird Hardening — Structural Tests ==="
HORLOGESKYNET_LICENSE="$REPO_ROOT/licenses/horlogeskynet-thunderbird-user.js-MIT.txt"

# 1. Source files exist
for f in thunderbird/noid-thunderbird-hardening.js \
         thunderbird/mozilla.cfg \
         thunderbird/autoconfig.js \
         thunderbird/local-settings.js \
         kickstart/snippets/35-thunderbird.ks \
         scripts/regen-thunderbird-embed.sh \
         scripts/regen-thunderbird-mozilla-cfg.sh \
         scripts/regen-thunderbird-smartcard-doc.sh \
         docs/35-thunderbird-smartcard.md; do
    if [ -s "$REPO_ROOT/$f" ]; then ok "$f present"
    else err "$f missing"; fi
done
if grep -qF 'protonmail-bridge-<exact-verified-version>.rpm' \
        "$REPO_ROOT/docs/35-thunderbird-proton-bridge.md" && \
   ! grep -qF 'protonmail-bridge-*.rpm' \
        "$REPO_ROOT/docs/35-thunderbird-proton-bridge.md"; then
    ok "Proton Bridge guide installs one exact verified RPM"
else
    err "Proton Bridge guide retains a wildcard RPM install"
fi

# 2. user.js has a NoID Privacy header + HorlogeSkynet body + NoID Privacy overrides section
if [ -f "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" ]; then
    if head -3 "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" | grep -q 'NoID Privacy Thunderbird Hardening'; then
        ok "user.js has NoID Privacy header"
    else err "user.js missing NoID Privacy header"; fi

    if grep -q 'thunderbird user.js' "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
        ok "user.js has HorlogeSkynet base"
    else err "user.js missing HorlogeSkynet base"; fi

    if grep -q '\[NoID Privacy OVERRIDES' "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
        ok "user.js has NoID Privacy OVERRIDES section"
    else err "user.js missing NoID Privacy OVERRIDES section"; fi

    # Verify NO finding-ID markers leak into deployed user.js (regression-guard)
    if grep -qE 'NoID Privacy-[0-9]{3}|Audit 2026-|#[0-9]+ NoID Privacy' "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
        err "user.js contains audit or numbered finding markers — should be functional labels only"
    else
        ok "user.js: NO finding-ID markers (regression-guard)"
    fi

    # Sanity: profile-marker version pref exists (private marker, used by harden-profile CLI detection)
    if grep -q '_noid\.thunderbird\.hardening\.version' "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
        ok "user.js has _noid.thunderbird.hardening.version marker"
    else err "user.js missing _noid.thunderbird.hardening.version marker"; fi

    m35_declared_version=$(sed -n \
        's/^NOID_TB_HARDENING_VERSION="\([^"]*\)"$/\1/p' \
        "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" | head -n 1 || true)
    m35_version_marker="user_pref(\"_noid.thunderbird.hardening.version\", \"$m35_declared_version\");"
    if [ -n "$m35_declared_version" ] && \
       [ "$(grep -Fxc "$m35_version_marker" \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js")" -eq 1 ] && \
       grep -qF 'grep -Fxc "$EXPECTED_USERJS_VERSION_MARKER" "$USERJS_CANDIDATE"' \
            "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks"; then
        ok "declared Thunderbird hardening version is gated against the embedded payload"
    else
        err "declared Thunderbird hardening version can drift from the embedded payload"
    fi
fi

# The pinned HorlogeSkynet base is followed by a NoID Privacy override layer. Repeating
# the same value in both layers adds last-write ambiguity without changing
# behavior. Only reviewed, intentionally different NoID Privacy values may repeat.
if python3 - "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" <<'PY'
import collections
import re
import sys

pref_re = re.compile(r'^user_pref\("([^"]+)",\s*(.*?)\);')
assignments = collections.defaultdict(list)
with open(sys.argv[1], encoding='utf-8') as source:
    for line_number, line in enumerate(source, 1):
        match = pref_re.match(line)
        if match:
            assignments[match.group(1)].append(
                (line_number, match.group(2)))

expected_changed_overrides = {
    'browser.download.useDownloadDir',
    'browser.formfill.enable',
    'calendar.timezone.useSystemTimezone',
    'mail.identity.default.compose_html',
    'mail.inline_attachments',
    'mailnews.auto_config.fetchFromISP.enabled',
    'mailnews.auto_config.guess.enabled',
    'mailnews.display.disallow_mime_handlers',
    'mailnews.display.html_as',
    'permissions.memory_only',
    'places.history.enabled',
    'security.OCSP.require',
    'spellchecker.dictionary',
}
identical = {}
changed = set()
for key, values in assignments.items():
    if key == '_user.js.parrot' or len(values) == 1:
        continue
    if len(values) != 2:
        print(f'{key}: expected at most two active assignments, got {values}',
              file=sys.stderr)
        raise SystemExit(1)
    if len({value for _line, value in values}) == 1:
        identical[key] = values
    else:
        changed.add(key)

if identical:
    print(f'identical duplicate preferences: {identical}', file=sys.stderr)
    raise SystemExit(1)
if changed != expected_changed_overrides:
    print('changed override set drifted:', file=sys.stderr)
    print(f'  missing: {sorted(expected_changed_overrides - changed)}',
          file=sys.stderr)
    print(f'  extra: {sorted(changed - expected_changed_overrides)}',
          file=sys.stderr)
    raise SystemExit(1)
PY
then
    ok "user.js has no identical duplicates and exactly 13 reviewed overrides"
else
    err "user.js preference assignment graph is ambiguous or unreviewed"
fi

# Firefox and Thunderbird share Gecko, but not every preference has the same
# product semantics. Keep every active common preference aligned except for
# this small, reviewed set of product-specific differences.
if python3 - \
        "$REPO_ROOT/firefox/noid-firefox-hardening.js" \
        "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" <<'PY'
import re
import sys

pref_re = re.compile(r'^\s*user_pref\("([^"]+)",\s*(.*?)\);(?:\s|$)')

def effective(path):
    result = {}
    with open(path, encoding='utf-8') as source:
        for line_number, line in enumerate(source, 1):
            match = pref_re.match(line)
            if match and match.group(1) != '_user.js.parrot':
                result[match.group(1)] = (match.group(2), line_number)
    return result

firefox = effective(sys.argv[1])
thunderbird = effective(sys.argv[2])
common = firefox.keys() & thunderbird.keys()
if len(common) < 110:
    print(f'common Gecko preference coverage unexpectedly low: {len(common)}',
          file=sys.stderr)
    raise SystemExit(1)

expected_differences = {
    # Firefox asks where to save; Thunderbird keeps its attachment workflow.
    'browser.download.useDownloadDir': ('false', 'true'),
    # Thunderbird retains its product-default form-history/autocomplete actor.
    'browser.formfill.enable': ('false', 'true'),
    # Firefox permits reviewed profile XPIs; Thunderbird permits only app scope.
    'extensions.autoDisableScopes': ('10', '11'),
    # Thunderbird clears web-content cookies; Firefox preserves explicit state.
    'privacy.clearOnShutdown.cookies': ('false', 'true'),
    # WebGL is useful in Firefox with FPP; mail content does not require it.
    'webgl.disabled': ('false', 'true'),
}

actual_differences = {
    key: (firefox[key][0], thunderbird[key][0])
    for key in common
    if firefox[key][0] != thunderbird[key][0]
}
if actual_differences != expected_differences:
    print('Firefox/Thunderbird common-pref parity drifted:', file=sys.stderr)
    print(f'  expected: {expected_differences}', file=sys.stderr)
    print(f'  actual:   {actual_differences}', file=sys.stderr)
    raise SystemExit(1)
PY
then
    ok "Firefox/Thunderbird share all common Gecko prefs except 5 reviewed product differences"
else
    err "Firefox/Thunderbird common Gecko preferences drifted without review"
fi

if [ -f "$HORLOGESKYNET_LICENSE" ] && \
   [ "$(sha256sum "$HORLOGESKYNET_LICENSE" | awk '{print $1}')" \
        = e0bfbe5467925aa73c30bb5d7e9e23fef1a2f6285b0c5dd62a5c7ab091fc5331 ]; then
    ok "exact HorlogeSkynet v140.2 MIT notice retained in repository"
else
    err "HorlogeSkynet v140.2 MIT notice missing or hash-drifted"
fi
if cmp -s \
    <(awk '/^\/\* HORLOGESKYNET MIT NOTICE BEGIN$/ { copy=1; next }
           /^HORLOGESKYNET MIT NOTICE END \*\/$/ { copy=0; found_end=1; next }
           copy { print }
           END { if (!found_end) exit 1 }' \
        "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js") \
    "$HORLOGESKYNET_LICENSE"; then
    ok "Thunderbird source retains the exact complete HorlogeSkynet MIT notice"
else
    err "Thunderbird source does not retain the exact HorlogeSkynet MIT notice"
fi
if grep -qF 'LICENSE_DIR=/usr/share/licenses/noid-privacy' \
        "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" && \
   grep -qF 'HORLOGESKYNET_LICENSE="$LICENSE_DIR/horlogeskynet-thunderbird-user.js-MIT.txt"' \
        "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" && \
   grep -qF 'e0bfbe5467925aa73c30bb5d7e9e23fef1a2f6285b0c5dd62a5c7ab091fc5331' \
        "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks"; then
    ok "M35 installs and hash-binds the HorlogeSkynet notice in the image inventory"
else
    err "M35 lacks installed HorlogeSkynet notice/hash binding"
fi

# 3. mozilla.cfg starts with comment line (Mozilla MCD parses skipping line 1)
if [ -f "$REPO_ROOT/thunderbird/mozilla.cfg" ]; then
    if head -1 "$REPO_ROOT/thunderbird/mozilla.cfg" | grep -qE '^//'; then
        ok "mozilla.cfg line 1 is comment (Mozilla parses skipping line 1)"
    else err "mozilla.cfg line 1 is not a comment — Mozilla MCD parse will skip first directive"; fi

    # NO lockPref (User-Empowerment hard constraint)
    if grep -q '^lockPref' "$REPO_ROOT/thunderbird/mozilla.cfg"; then
        err "mozilla.cfg contains lockPref — must be defaultPref-only"
    else ok "mozilla.cfg has NO lockPref (defaultPref-only)"; fi

    for pref in signon.autofillForms signon.formlessCapture.enabled; do
        if grep -qF "defaultPref(\"$pref\", false);" \
                "$REPO_ROOT/thunderbird/mozilla.cfg"; then
            ok "mozilla.cfg disables $pref"
        else
            err "mozilla.cfg missing password-manager hardening: $pref"
        fi
    done
    for update_key in \
        app.update.auto \
        extensions.update.enabled \
        extensions.update.autoUpdateDefault \
        extensions.systemAddon.update.enabled; do
        default_line="defaultPref(\"${update_key}\", false);"
        profile_line="user_pref(\"${update_key}\", false);"
        if [ "$(grep -Fxc "$default_line" \
                "$REPO_ROOT/thunderbird/mozilla.cfg")" -eq 1 ] && \
           [ "$(grep -Fxc "$profile_line" \
                "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js")" -eq 1 ] && \
           [ "$(grep -Fc "$default_line" \
                "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks")" -eq 1 ]; then
            ok "Thunderbird background updater is disabled in policy/profile sources: $update_key"
        else
            err "Thunderbird background update pref is missing or duplicated: $update_key"
        fi
    done

    for local_region_pref in \
        'doh-rollout.home-region", "global"' \
        'browser.region.network.url", ""' \
        'browser.region.network.scan", false' \
        'browser.region.update.enabled", false'; do
        if [ "$(grep -Fc "user_pref(\"$local_region_pref);" \
                "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js")" -eq 1 ] && \
           [ "$(grep -Fc "defaultPref(\"$local_region_pref);" \
                "$REPO_ROOT/thunderbird/mozilla.cfg")" -eq 1 ]; then
            ok "Thunderbird region-independent UI initialization is present: $local_region_pref"
        else
            err "Thunderbird region-independent UI initialization is missing/duplicated: $local_region_pref"
        fi
    done
    tb_keyservers='mail.openpgp.keyserver_list", "vks://keys.openpgp.org, hkps://keys.mailvelope.com"'
    if [ "$(grep -Fc "defaultPref(\"$tb_keyservers);" \
            "$REPO_ROOT/thunderbird/mozilla.cfg")" -eq 1 ] && \
       ! grep -qF 'user_pref("mail.openpgp.keyserver_list"' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
        ok "OpenPGP keyservers are an explicit user-editable default, not a restart reset"
    else
        err "OpenPGP keyserver default is missing, duplicated or forced through user.js"
    fi
    if grep -qF 'user_pref("dom.private-attribution.submission.enabled", false);' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       grep -qF 'defaultPref("dom.private-attribution.submission.enabled", false);' \
            "$REPO_ROOT/thunderbird/mozilla.cfg" && \
       ! grep -qF 'user_pref("dom.private-attribution.enabled"' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       ! grep -qF 'defaultPref("dom.private-attribution.enabled"' \
            "$REPO_ROOT/thunderbird/mozilla.cfg"; then
        ok "Thunderbird uses the active PPA submission gate without the retired cosmetic key"
    else
        err "Thunderbird PPA gate is missing or retains the retired cosmetic key"
    fi
    if [ "$(grep -Fxc 'user_pref("network.lna.websocket.enabled", true);' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js")" -eq 1 ] && \
       [ "$(grep -Fxc 'defaultPref("network.lna.websocket.enabled", true);' \
            "$REPO_ROOT/thunderbird/mozilla.cfg")" -eq 1 ] && \
       [ "$(grep -Fxc 'defaultPref("network.lna.websocket.enabled", true);' \
            "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks")" -eq 1 ] && \
       grep -qF 'Bug 2042339' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       grep -qF 'Bug 2042339' "$REPO_ROOT/thunderbird/mozilla.cfg"; then
        ok "Thunderbird enables the correctly sourced LNA WebSocket arm in both preference layers"
    else
        err "Thunderbird LNA WebSocket preference or upstream provenance is missing/duplicated"
    fi

    for sanitize_pref in \
        'privacy.sanitize.sanitizeOnShutdown", true' \
        'privacy.clearOnShutdown.cache", true' \
        'privacy.clearOnShutdown.cookies", true' \
        'privacy.clearOnShutdown.history", false' \
        'privacy.sanitize.timeSpan", 0'; do
        if grep -qF "user_pref(\"$sanitize_pref);" \
                "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
           [ "$(grep -Fxc "defaultPref(\"$sanitize_pref);" \
                "$REPO_ROOT/thunderbird/mozilla.cfg")" -eq 1 ]; then
            ok "Thunderbird 152 shutdown sanitizer uses its active namespace: $sanitize_pref"
        else
            err "Thunderbird 152 shutdown sanitizer contract is missing: $sanitize_pref"
        fi
    done
    if grep -qF 'user_pref("mail.external_protocol_requires_permission", true);' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       [ "$(grep -Fxc 'defaultPref("mail.external_protocol_requires_permission", true);' \
            "$REPO_ROOT/thunderbird/mozilla.cfg")" -eq 1 ]; then
        ok "Thunderbird uses its active external-protocol permission gate"
    else
        err "Thunderbird active external-protocol permission gate is missing"
    fi

    if grep -qF 'user_pref("browser.safebrowsing.downloads.remote.enabled", false);' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       grep -qF 'user_pref("browser.safebrowsing.malware.enabled", true);' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       grep -qF 'user_pref("browser.safebrowsing.phishing.enabled", true);' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       grep -qF 'user_pref("browser.safebrowsing.downloads.enabled", true);' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       grep -qF 'user_pref("browser.safebrowsing.blockedURIs.enabled", true);' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       grep -qF 'defaultPref("browser.safebrowsing.downloads.remote.enabled", false);' \
            "$REPO_ROOT/thunderbird/mozilla.cfg" && \
       grep -qF 'defaultPref("browser.safebrowsing.malware.enabled", true);' \
            "$REPO_ROOT/thunderbird/mozilla.cfg" && \
       grep -qF 'defaultPref("browser.safebrowsing.phishing.enabled", true);' \
            "$REPO_ROOT/thunderbird/mozilla.cfg" && \
       grep -qF 'defaultPref("browser.safebrowsing.downloads.enabled", true);' \
            "$REPO_ROOT/thunderbird/mozilla.cfg" && \
       grep -qF 'defaultPref("browser.safebrowsing.blockedURIs.enabled", true);' \
            "$REPO_ROOT/thunderbird/mozilla.cfg" && \
       grep -qF "does not initialize Gecko's SafeBrowsing list service" \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       grep -qF "does not initialize Gecko's SafeBrowsing list service" \
            "$REPO_ROOT/thunderbird/mozilla.cfg" && \
       grep -qF 'defaultPref("mail.phishing.detection.enabled", true);' \
            "$REPO_ROOT/thunderbird/mozilla.cfg" && \
       ! grep -qE '^[[:space:]]*(user_pref|defaultPref)\("browser\.safebrowsing\.(update\.enabled|malware\.enabled|phishing\.enabled)", false\)' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" \
            "$REPO_ROOT/thunderbird/mozilla.cfg"; then
        ok "Safe Browsing forward-compat values stay true while remote per-download reputation stays off"
    else
        err "Safe Browsing compatibility versus remote-reputation contract is incomplete"
    fi

    if ! grep -qF 'mail.cloud_files.accounts' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" \
            "$REPO_ROOT/thunderbird/mozilla.cfg"; then
        ok "Thunderbird does not assign a scalar preference to the CloudFiles account branch"
    else
        err "Thunderbird retains the inert mail.cloud_files.accounts scalar"
    fi
    if grep -qF '/* 8502: disable telemetry' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       ! grep -qF '/* 0802: disable telemetry' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
        ok "Thunderbird telemetry numbering matches SECTION 8500"
    else
        err "Thunderbird telemetry numbering still conflicts with its index"
    fi
    if ! grep -qF 'STARTTLS enforcement' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       grep -qF 'per-account Connection Security remains selected' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
        ok "Thunderbird TLS documentation preserves the per-account transport boundary"
    else
        err "Thunderbird TLS documentation overclaims transport enforcement"
    fi
    if ! grep -qF 'Allow auto-config lookup' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" \
            "$REPO_ROOT/thunderbird/mozilla.cfg" && \
       grep -qF 'mailnews.auto_config_url, is deliberately left' \
            "$REPO_ROOT/thunderbird/mozilla.cfg"; then
        ok "Thunderbird AutoConfig documentation separates ISPDB and own-domain controls"
    else
        err "Thunderbird AutoConfig documentation retains a false UI or control claim"
    fi
    if grep -qF 'blocklist, Remote Settings and CRLite refreshes cannot update' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
       grep -qF 'other app-directory sideloads are not auto-disabled' \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
        ok "Thunderbird proxy and extension-scope trade-offs are explicit"
    else
        err "Thunderbird proxy or extension-scope trade-off is undocumented"
    fi

    # These names are Firefox-only, foreign-platform or retired Thunderbird
    # preferences on the Fedora 44 Thunderbird 152 engine. Keeping them would
    # create cosmetic hardening that the shipped application never reads.
    retired_tb_prefs=(
        toolkit.telemetry.coverage.opt-out
        app.normandy.enabled
        browser.tabs.crashReporting.sendReport
        mail.instrumentation.postUrl
        mail.instrumentation.askUser
        mail.instrumentation.userOptedIn
        app.donation.eoy.version.viewed
        browser.ml.chat.enabled
        browser.ml.chat.shortcuts
        browser.ml.chat.sidebar
        browser.ml.chat.nimbus
        network.predictor.enabled
        network.predictor.enable-prefetch
        network.gio.supported-protocols
        security.external_protocol_requires_permission
        browser.safebrowsing.passwords.enabled
        mail.phishing.detection.ipaddresses
        mail.phishing.detection.mismatched_hosts
        mailnews.auto_config.account_constraints
        mail.provider.enabled
        mailnews.account_central_page.url
        mailnews.display.original_date
        extensions.cardbook.localizeEngine
        purple.logging.log_system
        calendar.network.timeout
        calendar.useragent.extra
        rss.message.loadWebPageOnSelect
        mail.send_message_warning.unencrypted
        app.update.enabled
        app.update.background.scheduling.enabled
        browser.cache.offline.enable
        browser.download.manager.scanWhenDone
        mailnews.send_default_charset
        mailnews.view_default_charset
        mailnews.compress_local_folder_summaries_on_quit
        geo.provider.ms-windows-location
        geo.provider.use_corelocation
        toolkit.winRegisterApplicationRestart
        browser.shell.shortcutFavicons
        browser.uitour.enabled
        browser.uitour.url
        middlemouse.contentLoadURL
        browser.eme.ui.enabled
    )
    for retired_pref in "${retired_tb_prefs[@]}"; do
        if grep -F "user_pref(\"$retired_pref\"," \
                "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" | \
                grep -q '^user_pref' || \
           grep -F "defaultPref(\"$retired_pref\"," \
                "$REPO_ROOT/thunderbird/mozilla.cfg" | \
                grep -q '^defaultPref'; then
            err "retired/inert Thunderbird preference remains active: $retired_pref"
        else
            ok "retired/inert Thunderbird preference stays inactive: $retired_pref"
        fi
    done
    if grep -qE "^\\| \`calendar\\.(network\\.timeout|useragent\\.extra)\`" \
            "$REPO_ROOT/docs/35-thunderbird-calendar-tz.md"; then
        err "calendar guide presents a retired/inert Thunderbird preference as an active default"
    elif grep -qF "The retired \`calendar.network.timeout\` and \`calendar.useragent.extra\` names are" \
            "$REPO_ROOT/docs/35-thunderbird-calendar-tz.md"; then
        ok "calendar guide distinguishes retired/inert names from active defaults"
    else
        err "calendar guide does not explain the retired/inert preference contract"
    fi
    if grep -q 'NIDP-00[24]' \
            "$REPO_ROOT/docs/35-thunderbird-calendar-tz.md" \
            "$REPO_ROOT/docs/35-thunderbird-self-hosted-mail.md"; then
        err "Thunderbird guides retain retired NIDP rationale identifiers"
    else
        ok "Thunderbird guides point at maintained rationale sources"
    fi
    for retired_namespace in \
        browser.urlbar. \
        browser.taskbar. \
        privacy.clearOnShutdown_v2. \
        privacy.clearSiteData. \
        privacy.clearHistory.; do
        if grep -F "user_pref(\"$retired_namespace" \
                "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" | \
                grep -q '^user_pref' || \
           grep -F "defaultPref(\"$retired_namespace" \
                "$REPO_ROOT/thunderbird/mozilla.cfg" | \
                grep -q '^defaultPref'; then
            err "Firefox-only Thunderbird preference namespace remains active: $retired_namespace"
        else
            ok "Firefox-only Thunderbird preference namespace stays inactive: $retired_namespace"
        fi
    done
fi

# 4. NO policies.json file in tree (Section 5 decision)
if [ -f "$REPO_ROOT/thunderbird/policies.json" ] || [ -d "$REPO_ROOT/thunderbird/policies" ]; then
    err "thunderbird/policies.json or policies/ should NOT exist (Section 5 decision)"
else
    ok "NO policies.json in thunderbird/ (Section 5 decision)"
fi

# 5. Privacy/tracking baseline corrections present in user.js
if grep -qE 'privacy.firstparty.isolate.*false|privacy/[Tt]racking' "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
    ok "user.js: privacy/tracking baseline present"
else err "user.js: privacy/tracking baseline missing"; fi
for pref in signon.autofillForms signon.formlessCapture.enabled; do
    if grep -qF "user_pref(\"$pref\", false);" \
            "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
        ok "user.js restores upstream password-manager hardening: $pref"
    else
        err "user.js missing upstream password-manager hardening: $pref"
    fi
done
for pref_file in \
        "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" \
        "$REPO_ROOT/thunderbird/mozilla.cfg"; do
    if grep -qE '^(user_pref|defaultPref)\("services\.settings\.server"' "$pref_file"; then
        err "$(basename "$pref_file") overrides Thunderbird's compiled Remote Settings endpoint"
    else
        ok "$(basename "$pref_file") inherits Thunderbird's compiled Remote Settings endpoint"
    fi
    if grep -qF 'security.remote_settings.crlite_filters.enabled", true);' "$pref_file" && \
       grep -qF 'security.pki.crlite_mode", 2);' "$pref_file" && \
       grep -qF 'security-state/cert-revocations' "$pref_file"; then
        ok "$(basename "$pref_file") enables the maintained CRLite refresh path"
    else
        err "$(basename "$pref_file") weakens or misdocuments the CRLite refresh path"
    fi
    if grep -qF 'extensions.blocklist.enabled", true);' "$pref_file"; then
        ok "$(basename "$pref_file") retains the add-on blocklist"
    else
        err "$(basename "$pref_file") disables the add-on blocklist"
    fi
    if grep -qF "Keep Mozilla's soft-fail default." "$pref_file" && \
       grep -qF 'turns responder outages into TLS/S/MIME failures' "$pref_file" && \
       grep -qF 'https://letsencrypt.org/2024/12/05/ending-ocsp.html' "$pref_file"; then
        ok "$(basename "$pref_file") documents the reviewed OCSP availability trade-off"
    else
        err "$(basename "$pref_file") lacks the reviewed OCSP soft-fail rationale"
    fi
done
if grep -Rqs 'MOZ_REMOTE_SETTINGS_DEVTOOLS' \
        "$REPO_ROOT/thunderbird" "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks"; then
    err "Thunderbird hardening bypasses the release endpoint allowlist"
else
    ok "Thunderbird hardening does not bypass the release endpoint allowlist"
fi
if grep -qF 'user_pref("network.http.microsoft-entra-sso.enabled", false);' \
        "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" && \
   ! grep -qF 'user_pref("network.http.microsoft-entra-sso.enabled", true);' \
        "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
    ok "user.js keeps Microsoft Entra automatic SSO disabled"
else
    err "user.js enables or fails to disable Microsoft Entra automatic SSO"
fi
if grep -qF 'only value 0 prompts' "$REPO_ROOT/thunderbird/mozilla.cfg" && \
   ! grep -qF 'NOT "prompt off"' "$REPO_ROOT/thunderbird/mozilla.cfg"; then
    ok "mozilla.cfg documents privacy.spoof_english values accurately"
else
    err "mozilla.cfg has stale privacy.spoof_english semantics"
fi
for stale_claim in \
    'SINGLE SOURCE OF TRUTH' \
    'TB ignores skel `default-release`' \
    'Flatpak `org.mozilla.Thunderbird` ESR-branch'; do
    if grep -qF "$stale_claim" "$REPO_ROOT/thunderbird/mozilla.cfg"; then
        err "mozilla.cfg retains stale architecture/channel claim: $stale_claim"
    else
        ok "mozilla.cfg rejects stale architecture/channel claim: $stale_claim"
    fi
done
if grep -qF 'MCD documentation recommends both' \
        "$REPO_ROOT/thunderbird/local-settings.js"; then
    err "local-settings.js overstates Mozilla AutoConfig guidance"
else
    ok "local-settings.js describes its compatibility alias without a false recommendation"
fi
if grep -qF 'every NoID Privacy preference is user-overridable via about:config' \
        "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
    err "user.js overstates the persistence of an about:config override"
elif grep -qF 'or edited/removed for a durable override' \
        "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
    ok "user.js distinguishes session changes from durable profile overrides"
else
    err "user.js lacks the durable override boundary"
fi

# The final profile values must honor the native network/permission contracts.
# HorlogeSkynet base entries may appear earlier; last-write-wins is the
# effective user.js behavior, so test the final active occurrence.
last_user_pref() {
    awk -v key="$1" '
        index($0, "user_pref(\"" key "\",") == 1 { line=$0 }
        END {
            sub(/[[:space:]]*\/\/.*/, "", line)
            print line
        }
    ' "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"
}
for native_pref_contract in \
    'network.dns.disableIPv6|user_pref("network.dns.disableIPv6", false);|defaultPref("network.dns.disableIPv6", false);' \
    'permissions.memory_only|user_pref("permissions.memory_only", false);|defaultPref("permissions.memory_only", false);'; do
    IFS='|' read -r native_key profile_line default_line \
        <<< "$native_pref_contract"
    if [ "$(last_user_pref "$native_key")" = "$profile_line" ] && \
       [ "$(grep -Fxc "$default_line" \
            "$REPO_ROOT/thunderbird/mozilla.cfg")" -eq 1 ]; then
        ok "Thunderbird native compatibility contract is effective: $native_key"
    else
        err "Thunderbird native compatibility contract is missing: $native_key"
    fi
done
if [ "$(last_user_pref 'mail.smtpserver.default.hello_argument')" \
        = 'user_pref("mail.smtpserver.default.hello_argument", "[127.0.0.1]");' ] && \
   [ "$(grep -Fxc \
        'defaultPref("mail.smtpserver.default.hello_argument", "[127.0.0.1]");' \
        "$REPO_ROOT/thunderbird/mozilla.cfg")" -eq 1 ]; then
    ok "Thunderbird SMTP default minimizes local-address disclosure"
else
    err "Thunderbird SMTP local-address minimization contract is missing"
fi
if grep -qF 'persists across' \
        "$REPO_ROOT/docs/35-thunderbird-mail-setup.md" && \
   grep -qF 'keeps dual-stack resolution enabled' \
        "$REPO_ROOT/docs/35-thunderbird-mail-setup.md" && \
   grep -qF 'provider-neutral JSDNS mode reads the OS resolver' \
        "$REPO_ROOT/docs/35-thunderbird-mail-setup.md" && \
   ! grep -qF 'managed default remains Quad9 DoH' \
        "$REPO_ROOT/docs/35-thunderbird-mail-setup.md"; then
    ok "Thunderbird user guide documents durable exceptions and provider-neutral DNS"
else
    err "Thunderbird user guide omits durable exceptions or provider-neutral DNS"
fi

# 6. NO Europe/Berlin literal in user.js (hardcoded-TZ regression-guard)
if grep -q '"Europe/Berlin"' "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
    err "user.js still contains 'Europe/Berlin' (hardcoded-TZ regression — should use useSystemTimezone)"
else
    ok "user.js: NO Europe/Berlin (system-locale TZ active)"
fi

# 7. NO active privacy.firstparty.isolate=true (16b-bug must not regress).
# Anchor at start of line — HorlogeSkynet's commented-out form starts with whitespace+//.
if grep -qE '^user_pref\("privacy\.firstparty\.isolate", true' "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
    err "user.js: ACTIVE privacy.firstparty.isolate=true (16b-bug — Mozilla deprecated)"
else
    ok "user.js: privacy.firstparty.isolate=false confirmed (no active true)"
fi

# 8. NO active privacy.donottrackheader.enabled=true (16b-bug — FP-Vector).
# HorlogeSkynet has commented form `   // user_pref(...)` — anchor excludes that.
if grep -qE '^user_pref\("privacy\.donottrackheader\.enabled", true' "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
    err "user.js: ACTIVE privacy.donottrackheader.enabled=true (16b-bug — FP-Vector)"
else
    ok "user.js: privacy.donottrackheader.enabled=false confirmed (no active true)"
fi

# 9. 35-thunderbird.ks has gzip+base64 markers + bash -n clean
if [ -f "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" ]; then
    if grep -q "TB_HARDENING_GZ_B64_EOF" "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks"; then
        ok "35-thunderbird.ks has TB_HARDENING_GZ_B64_EOF markers"
    else err "35-thunderbird.ks missing TB_HARDENING_GZ_B64_EOF markers"; fi

    if bash -n "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" 2>/dev/null; then
        ok "35-thunderbird.ks bash -n clean"
    else err "35-thunderbird.ks bash -n FAILED"; fi
fi
TB_KS="$REPO_ROOT/kickstart/snippets/35-thunderbird.ks"
for exact_gate in \
    'Exact copy graph: every maintained source copy must remain byte-identical.' \
    '$SHARE_DIR/user.js|$TB_SKEL_PROFILE_DIR/user.js' \
    '$SHARE_DIR/mozilla.cfg|$TB_INSTALL_DIR/mozilla.cfg' \
    '$SHARE_DIR/dkim_verifier.xpi|$XPI_TARGET' \
    'Thunderbird owned-overlay/vendor-pristine profile contract differs' \
    'final DKIM Verifier XPI differs from its exact pin' \
    'Thunderbird skel profiles.ini differs from canonical contract' \
    'publish_root_file "$STAMP_TMP" "$STAMP" 0644'; do
    if grep -qF "$exact_gate" "$TB_KS"; then
        ok "M35 exact final gate contains $exact_gate"
    else
        err "M35 exact final gate missing $exact_gate"
    fi
done
if [ -x "$REPO_ROOT/tests/pre-ship/19-browser-runtime-parity.sh" ]; then
    ok "non-skippable browser runtime/parity gate is executable"
else
    err "non-skippable browser runtime/parity gate missing"
fi
if grep -qF '[[ -f $IMAGE_PARITY_GATE && ! -L $IMAGE_PARITY_GATE ]]' \
        "$REPO_ROOT/tests/pre-ship/19-browser-runtime-parity.sh" \
   && grep -qF 'stat -c '\''%a'\'' -- "$IMAGE_PARITY_GATE"' \
        "$REPO_ROOT/tests/pre-ship/19-browser-runtime-parity.sh" \
   && grep -qF '555|755) ;;' \
        "$REPO_ROOT/tests/pre-ship/19-browser-runtime-parity.sh" \
   && ! grep -qF '[[ -x $IMAGE_PARITY_GATE' \
        "$REPO_ROOT/tests/pre-ship/19-browser-runtime-parity.sh"; then
    ok "browser runtime validates closed checkout/ISO modes without conflating noexec mounts"
else
    err "browser runtime paired-gate check is not safe for the noexec support medium"
fi

# 9b. Canonical profile authority for first and later ordinary launches.
for expected in \
    'TB_LAUNCHER_SOURCE_SHA256=12fd44963992a2cfafeaa5bca5f33b0c22c7ec9d1e0f1cc71a38d5bd5019e76e' \
    'owned_launcher=/usr/local/bin/thunderbird' \
    'owned_desktop=/usr/local/share/applications/net.thunderbird.Thunderbird.desktop' \
    'set -- -P default-release "$@"' \
    'Mirroring canonical Thunderbird profile to pre-existing real users'; do
    if grep -qF "$expected" "$TB_KS"; then
        ok "M35 canonical-profile control contains $expected"
    else
        err "M35 canonical-profile control missing $expected"
    fi
done
if grep -q '^\[Install\]$' "$TB_KS"; then
    err "M35 seeds an invalid hashless Thunderbird [Install] section"
else
    ok "M35 does not seed a hashless Thunderbird [Install] section"
fi
if grep -qF 'runuser -u "$user_name"' "$TB_KS" && \
   grep -qF 'env HOME="$user_home" TB_PROFILE_SOURCE_DIR="$SHARE_DIR"' "$TB_KS" && \
   grep -qF 'unsafe existing-user profile source: $profile_source' "$TB_KS" && \
   ! grep -qF 'env HOME="$user_home" TB_SKEL_DIR="$TB_SKEL_DIR"' "$TB_KS" && \
   grep -qF 'Mirrored canonical profile to $user_home as $user_name' "$TB_KS" && \
   ! grep -qF 'chown -R "$user_name:$user_name" "$target_tmp"' "$TB_KS"; then
    ok "existing-user profile seed reads public canonical bytes and writes only with target-user authority"
else
    err "existing-user profile seed crosses the user-home boundary as root"
fi
if grep -qF 'mv -T --update=none-fail -- "$temporary" "$target"' "$TB_KS" && \
   ! grep -qF 'mv -Tn -- "$temporary" "$target"' "$TB_KS"; then
    ok "existing-user profile seed receives a failing status on rename collision"
else
    err "existing-user profile seed retains mv -n success-on-skip semantics"
fi

TB_REASSERT_TMP=$(mktemp)
TB_TEST_TMP=$(mktemp -d /var/tmp/noid-tb35-test.XXXXXXXX)
TB_OVERLAY_FIXTURE=''
trap 'chmod 0700 "$TB_TEST_TMP/private-skel" 2>/dev/null || true; rm -f "$TB_REASSERT_TMP"; rm -rf "$TB_TEST_TMP"; [ -z "${TB_OVERLAY_FIXTURE:-}" ] || rm -rf "$TB_OVERLAY_FIXTURE"' EXIT

# Execute the exact unprivileged seed body against a disposable home. This
# proves initial publication, metadata and repeat-run preservation without
# granting the fixture root authority.
awk '
    /^set -euo pipefail$/ && previous ~ /NOID_TB_USER_SEED_EOF/ { copy=1 }
    copy && /^NOID_TB_USER_SEED_EOF$/ { exit }
    copy { print }
    { previous=$0 }
' "$TB_KS" > "$TB_TEST_TMP/user-seed.sh"
mkdir -p "$TB_TEST_TMP/seed-home" \
    "$TB_TEST_TMP/seed-source" \
    "$TB_TEST_TMP/private-skel/default-release"
printf '%s\n' '[General]' > "$TB_TEST_TMP/seed-source/profiles.ini"
printf '%s\n' 'user_pref("_noid.thunderbird.hardening.version", "fixture");' \
    > "$TB_TEST_TMP/seed-source/user.js"
chmod 000 "$TB_TEST_TMP/private-skel"
if HOME="$TB_TEST_TMP/seed-home" \
        TB_PROFILE_SOURCE_DIR="$TB_TEST_TMP/seed-source" \
        TB_SKEL_DIR="$TB_TEST_TMP/private-skel" \
        bash "$TB_TEST_TMP/user-seed.sh" && \
   [ "$(stat -c '%a' "$TB_TEST_TMP/seed-home/.thunderbird")" = 700 ] && \
   [ "$(stat -c '%a' \
        "$TB_TEST_TMP/seed-home/.thunderbird/profiles.ini")" = 644 ] && \
   [ "$(stat -c '%a' \
        "$TB_TEST_TMP/seed-home/.thunderbird/default-release/user.js")" = 600 ] && \
   cmp -s "$TB_TEST_TMP/seed-source/user.js" \
       "$TB_TEST_TMP/seed-home/.thunderbird/default-release/user.js"; then
    ok "unprivileged seed publishes exact canonical bytes without reading private skel"
else
    err "unprivileged existing-user seed publication failed"
fi
TB_SEED_BEFORE=$(sha256sum \
    "$TB_TEST_TMP/seed-home/.thunderbird/default-release/user.js")
set +e
HOME="$TB_TEST_TMP/seed-home" \
    TB_PROFILE_SOURCE_DIR="$TB_TEST_TMP/seed-source" \
    TB_SKEL_DIR="$TB_TEST_TMP/private-skel" \
    bash "$TB_TEST_TMP/user-seed.sh" >/dev/null 2>&1
TB_SEED_REPEAT_RC=$?
set -e
if [ "$TB_SEED_REPEAT_RC" -eq 3 ] && \
   [ "$TB_SEED_BEFORE" = "$(sha256sum \
        "$TB_TEST_TMP/seed-home/.thunderbird/default-release/user.js")" ] && \
   ! find "$TB_TEST_TMP/seed-home" -maxdepth 1 \
        -name '.noid-thunderbird-seed.*' -print -quit | grep -q .; then
    ok "existing-user seed preserves an initialized profile without temp leakage"
else
    err "existing-user seed repeat-run preservation failed"
fi

mkdir -p "$TB_TEST_TMP/seed-race-home" "$TB_TEST_TMP/seed-bin"
cat > "$TB_TEST_TMP/seed-bin/mv" <<'TB_SEED_RACE_MV_EOF'
#!/usr/bin/bash
set -euo pipefail
target="${!#}"
mkdir -p -- "$target"
printf '%s\n' 'concurrent profile sentinel' > "$target/concurrent"
case " $* " in
    *' --update=none-fail '*) exit 1 ;;
    *' -Tn '*) exit 0 ;;
    *) exit 2 ;;
esac
TB_SEED_RACE_MV_EOF
chmod 0700 "$TB_TEST_TMP/seed-bin/mv"
set +e
HOME="$TB_TEST_TMP/seed-race-home" \
    TB_PROFILE_SOURCE_DIR="$TB_TEST_TMP/seed-source" \
    PATH="$TB_TEST_TMP/seed-bin:$PATH" \
    bash "$TB_TEST_TMP/user-seed.sh" >/dev/null 2>&1
TB_SEED_RACE_RC=$?
set -e
if [ "$TB_SEED_RACE_RC" -eq 3 ] \
   && grep -qFx 'concurrent profile sentinel' \
        "$TB_TEST_TMP/seed-race-home/.thunderbird/concurrent" \
   && ! find "$TB_TEST_TMP/seed-race-home" -maxdepth 1 \
        -name '.noid-thunderbird-seed.*' -print -quit | grep -q .; then
    ok "existing-user seed preserves a profile created in the final rename race"
else
    err "existing-user seed mishandled the final rename race"
fi

# Execute the root-publication trust boundary as namespace-root when user
# namespaces are available. The fixture proves atomic symlink replacement,
# exact metadata/bytes, unsafe-parent rejection and pre-rename failure safety.
awk '
    /^log\(\) \{/ { copy=1 }
    /^verify_sha256\(\) \{/ { exit }
    copy { print }
' "$TB_KS" > "$TB_TEST_TMP/root-publish-helpers.sh"
cat > "$TB_TEST_TMP/root-publish-fixture.sh" <<'TB_ROOT_PUBLISH_FIXTURE_EOF'
#!/usr/bin/bash
set -euo pipefail
. /mnt/root-publish-helpers.sh
restorecon() { return 0; }
matchpathcon() { return 0; }

ensure_root_dir /mnt/managed 0750
[ "$(stat -Lc '%u:%g:%a' /mnt/managed)" = 0:0:750 ]

printf '%s\n' candidate > /mnt/source
printf '%s\n' victim > /mnt/victim
ln -s /mnt/victim /mnt/managed/target
publish_root_file /mnt/source /mnt/managed/target 0600
[ -f /mnt/managed/target ] && [ ! -L /mnt/managed/target ]
cmp -s /mnt/source /mnt/managed/target
[ "$(stat -Lc '%u:%g:%a:%h' /mnt/managed/target)" = 0:0:600:1 ]
[ "$(cat /mnt/victim)" = victim ]

ln -s /mnt/managed /mnt/unsafe-parent
if ( ensure_root_dir /mnt/unsafe-parent/child 0755 ); then
    exit 10
fi
[ ! -e /mnt/managed/child ]

mkdir /mnt/managed/directory-target
if ( publish_root_file /mnt/source /mnt/managed/directory-target 0644 ); then
    exit 11
fi
[ -d /mnt/managed/directory-target ]

printf '%s\n' previous > /mnt/managed/mode-failure-target
chmod 0770 /mnt/managed
if ( publish_root_file /mnt/source /mnt/managed/mode-failure-target 0644 ); then
    exit 12
fi
[ "$(cat /mnt/managed/mode-failure-target)" = previous ]
chmod 0750 /mnt/managed

chmod 0666 /mnt/source
if ( publish_root_file /mnt/source /mnt/managed/source-failure-target 0644 ); then
    exit 13
fi
[ ! -e /mnt/managed/source-failure-target ]
chmod 0644 /mnt/source

printf '%s\n' previous > /mnt/managed/failure-target
if (
    restorecon() { return 1; }
    publish_root_file /mnt/source /mnt/managed/failure-target 0644
); then
    exit 14
fi
[ "$(cat /mnt/managed/failure-target)" = previous ]
! find /mnt/managed -maxdepth 1 -name '.noid-thunderbird-publish.*' \
    -print -quit | grep -q .
TB_ROOT_PUBLISH_FIXTURE_EOF
chmod 0700 "$TB_TEST_TMP/root-publish-fixture.sh"
if command -v bwrap >/dev/null 2>&1 && \
   bwrap --unshare-user --uid 0 --gid 0 --die-with-parent \
       --ro-bind / / --dev-bind /dev /dev --proc /proc /bin/true \
       >/dev/null 2>&1; then
    if bwrap --unshare-user --uid 0 --gid 0 --die-with-parent \
            --ro-bind / / --dev-bind /dev /dev --proc /proc \
            --bind "$TB_TEST_TMP" /mnt \
            /mnt/root-publish-fixture.sh; then
        ok "root publication is atomic, path-bounded and failure-safe"
    else
        err "root publication behavioral trust-boundary fixture failed"
    fi
else
    log "  [SKIP] root publication namespace fixture unavailable; structural gates retained"
fi

# Exercise the exact module-level EXIT/signal cleanup independently of
# namespace availability. A TERM before publication must retire the active
# sibling candidate and preserve the signal-derived status.
TB_ROOT_SIGNAL_SCRIPT="$TB_TEST_TMP/root-signal-cleanup.sh"
TB_ROOT_SIGNAL_READY="$TB_TEST_TMP/root-signal.ready"
TB_ROOT_SIGNAL_CANDIDATE="$TB_TEST_TMP/root-signal.candidate"
{
    printf '%s\n' '#!/usr/bin/bash' 'set -euo pipefail' \
        'log() { :; }' \
        "STAMP_DIR=$TB_TEST_TMP" \
        'STAMP="$STAMP_DIR/stamp-35-thunderbird.ok"' \
        'STAMP_PUBLICATION_ACTIVE=0' \
        "ROOT_PUBLICATION_TMP=$TB_ROOT_SIGNAL_CANDIDATE"
    sed -n '/^cleanup_m35_publication() {$/,/^}$/p' "$TB_KS"
    printf '%s\n' \
        'trap cleanup_m35_publication EXIT' \
        "trap 'exit 129' HUP" \
        "trap 'exit 130' INT" \
        "trap 'exit 143' TERM" \
        "printf '%s\\n' candidate > \"$TB_ROOT_SIGNAL_CANDIDATE\"" \
        "printf '%s\\n' ready > \"$TB_ROOT_SIGNAL_READY\"" \
        'while :; do :; done'
} > "$TB_ROOT_SIGNAL_SCRIPT"
chmod 0700 "$TB_ROOT_SIGNAL_SCRIPT"
"$TB_ROOT_SIGNAL_SCRIPT" &
TB_ROOT_SIGNAL_PID=$!
for _ in $(seq 1 500); do
    [ -e "$TB_ROOT_SIGNAL_READY" ] && break
    sleep 0.01
done
set +e
kill -TERM "$TB_ROOT_SIGNAL_PID" 2>/dev/null
wait "$TB_ROOT_SIGNAL_PID"
TB_ROOT_SIGNAL_RC=$?
set -e
if [ "$TB_ROOT_SIGNAL_RC" -eq 143 ] \
   && [ ! -e "$TB_ROOT_SIGNAL_CANDIDATE" ]; then
    ok "module-level TERM cleanup retires an unpublished root candidate"
else
    err "module-level TERM cleanup left a candidate or wrong status ($TB_ROOT_SIGNAL_RC)"
fi

awk '
    /^cat > "\$NOID_TB_REASSERT_CANDIDATE" <<.NOID_TB_REASSERT_EOF./ { copy=1; next }
    copy && /^NOID_TB_REASSERT_EOF$/ { exit }
    copy { print }
' "$TB_KS" > "$TB_REASSERT_TMP"
if bash -n "$TB_REASSERT_TMP"; then
    ok "Thunderbird package-update launcher reassert is valid bash"
else
    err "Thunderbird package-update launcher reassert has bash syntax errors"
fi
for expected in \
    "rpm -q --qf '%{FILEDIGESTALGO}' thunderbird" \
    'if [ "$#" -ne 0 ]; then' \
    "printf 'Usage: noid-thunderbird-reassert\\n' >&2" \
    'actual=$(sha256sum "$path"' \
    'publish_staged_file "$launcher_tmp" "$owned_launcher" 0755' \
    'publish_staged_file "$desktop_tmp" "$owned_desktop" 0644' \
    'trap cleanup_reassert EXIT' \
    'ensure_managed_dir /usr/local/bin' \
    'ensure_managed_dir /usr/local/share/applications' \
    'publish_managed_file "$src" "$dst" autoconfig' \
    'publish_managed_file "$dkim_src" "$dkim_dst" dkim' \
    're-asserted DKIM Verifier payload inside the thunderbird package tree' \
    'ensure_root_dir /usr/local/bin 0755' \
    '/usr/local/bin/noid-thunderbird-reassert 0755' \
    'post_transaction:thunderbird:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-thunderbird-reassert\ >/dev/null'; do
    if grep -qF "$expected" "$TB_KS"; then
        ok "Thunderbird update durability contains $expected"
    else
        err "Thunderbird update durability missing $expected"
    fi
done
if grep -qF 'ensure_root_dir /usr/local/sbin 0755' "$TB_KS"; then
    err "Thunderbird update helper publishes through Fedora's symlinked local-sbin path"
else
    ok "Thunderbird update helper publishes through Fedora's canonical local-bin path"
fi
for expected in \
    '"/usr/local/bin/noid-thunderbird-reassert|755"' \
    '[ "$(readlink -- /usr/local/sbin 2>/dev/null)" = bin ]' \
    '[ /usr/local/sbin/noid-thunderbird-reassert -ef' \
    'Fedora unified-sbin alias resolves to the canonical Thunderbird helper'; do
    if grep -qF "$expected" "$TB_KS"; then
        ok "Thunderbird final verifier contains: $expected"
    else
        err "Thunderbird final verifier missing: $expected"
    fi
done
if grep -qF 'desktop_tmp=$(mktemp --suffix=.desktop /usr/local/share/applications/.net.thunderbird.Thunderbird.XXXXXX)' \
        "$TB_REASSERT_TMP"; then
    ok "temporary Thunderbird desktop overlay retains the validator-required suffix"
else
    err "temporary Thunderbird desktop overlay lacks the validator-required suffix"
fi
if grep -qE 'rpm-verify-allowlist|sed -i.*[[:space:]]"\$vendor_(launcher|desktop)"$' \
        "$TB_REASSERT_TMP"; then
    err "Thunderbird generator edits or normalizes vendor RPM payloads"
else
    ok "Thunderbird generator publishes only owned overlays"
fi

TB_OVERLAY_FIXTURE=$(mktemp -d "$REPO_ROOT/.test-thunderbird-overlay.XXXXXXXX")
mkdir -p "$TB_OVERLAY_FIXTURE/vendor/applications" \
    "$TB_OVERLAY_FIXTURE/owned/bin" "$TB_OVERLAY_FIXTURE/owned/applications" \
    "$TB_OVERLAY_FIXTURE/mock-bin" "$TB_OVERLAY_FIXTURE/cache" \
    "$TB_OVERLAY_FIXTURE/thunderbird/defaults/pref" \
    "$TB_OVERLAY_FIXTURE/thunderbird/distribution/extensions"
for cache_file in mozilla.cfg autoconfig.js local-settings.js noid-locale.js policies.json; do
    printf '// canonical %s fixture\n' "$cache_file" \
        > "$TB_OVERLAY_FIXTURE/cache/$cache_file"
done
printf '%s\n' 'version=6.3.0' > "$TB_OVERLAY_FIXTURE/cache/dkim_verifier.xpi"
cat > "$TB_OVERLAY_FIXTURE/vendor/thunderbird" <<'TB_VENDOR_LAUNCHER_EOF'
#!/usr/bin/bash
MOZ_PROGRAM=/bin/true
export MOZ_APP_LAUNCHER="/usr/bin/thunderbird"
exec $MOZ_PROGRAM "$@"
TB_VENDOR_LAUNCHER_EOF
cat > "$TB_OVERLAY_FIXTURE/vendor/applications/net.thunderbird.Thunderbird.desktop" <<'TB_VENDOR_DESKTOP_EOF'
[Desktop Entry]
Type=Application
Name=Thunderbird
Exec=thunderbird %u
TryExec=thunderbird
TB_VENDOR_DESKTOP_EOF
chmod 0755 "$TB_OVERLAY_FIXTURE/vendor/thunderbird"
sed -i "s#/usr/bin/thunderbird#$TB_OVERLAY_FIXTURE/vendor/thunderbird#" \
    "$TB_OVERLAY_FIXTURE/vendor/thunderbird"
cat > "$TB_OVERLAY_FIXTURE/mock-bin/rpm" <<'TB_MOCK_RPM_EOF'
#!/usr/bin/bash
case "$*" in
    *FILEDIGESTALGO*) printf '8' ;;
    *FILEDIGESTS*)
        case "${TB_MOCK_RPM_DIGEST_MODE:-}" in
            duplicate)
                printf '%s\t%s\n' "$TB_VENDOR_LAUNCHER" "$TB_VENDOR_LAUNCHER_DIGEST"
                printf '%s\t%s\n' "$TB_VENDOR_LAUNCHER" "$TB_VENDOR_LAUNCHER_DIGEST"
                printf '%s\t%s\n' "$TB_VENDOR_DESKTOP" "$TB_VENDOR_DESKTOP_DIGEST"
                ;;
            empty)
                printf '%s\t%s\n' "$TB_VENDOR_LAUNCHER" ""
                printf '%s\t%s\n' "$TB_VENDOR_DESKTOP" "$TB_VENDOR_DESKTOP_DIGEST"
                ;;
            *)
                printf '%s\t%s\n' "$TB_VENDOR_LAUNCHER" "$TB_VENDOR_LAUNCHER_DIGEST"
                printf '%s\t%s\n' "$TB_VENDOR_DESKTOP" "$TB_VENDOR_DESKTOP_DIGEST"
                ;;
        esac
        ;;
    *'%{VERSION}'*) printf '152.0' ;;
    *) exit 2 ;;
esac
TB_MOCK_RPM_EOF
chmod 0755 "$TB_OVERLAY_FIXTURE/mock-bin/rpm"
cat > "$TB_OVERLAY_FIXTURE/mock-bin/validate-webextension.py" <<'TB_VALIDATOR_EOF'
#!/usr/bin/python3
import pathlib, sys
payload, identity, expected, require_signature, browser = sys.argv[1:]
if identity != "dkim_verifier@pl" or require_signature != "0":
    raise SystemExit(1)
line = pathlib.Path(payload).read_text(encoding="utf-8").strip()
if not line.startswith("version="):
    raise SystemExit(1)
version = line.split("=", 1)[1]
if expected != "-" and version != expected:
    raise SystemExit(1)
print(version)
TB_VALIDATOR_EOF
chmod 0755 "$TB_OVERLAY_FIXTURE/mock-bin/validate-webextension.py"
for mock in restorecon matchpathcon chown; do
    ln -s /usr/bin/true "$TB_OVERLAY_FIXTURE/mock-bin/$mock"
done
cat > "$TB_OVERLAY_FIXTURE/mock-bin/logger" <<'TB_REASSERT_LOGGER_EOF'
#!/usr/bin/bash
printf '%s\n' "$*" >> "$(dirname "$0")/../reassert.log"
TB_REASSERT_LOGGER_EOF
chmod 0755 "$TB_OVERLAY_FIXTURE/mock-bin/logger"
TB_OVERLAY_OWNER=$(stat -c '%u:%g' "$TB_OVERLAY_FIXTURE")
sed \
    -e 's/-o root -g root //g' \
    -e "s#^PATH=.*#PATH=$TB_OVERLAY_FIXTURE/mock-bin:/usr/sbin:/usr/bin:/sbin:/bin#" \
    -e "s/0:0:/$TB_OVERLAY_OWNER:/g" \
    -e "s#/usr/share/noid-thunderbird#$TB_OVERLAY_FIXTURE/cache#g" \
    -e "s#/usr/lib64/thunderbird/defaults/pref#$TB_OVERLAY_FIXTURE/thunderbird/defaults/pref#g" \
    -e "s#/usr/lib64/thunderbird/distribution/extensions#$TB_OVERLAY_FIXTURE/thunderbird/distribution/extensions#g" \
    -e "s#/usr/lib64/thunderbird/distribution/policies.json#$TB_OVERLAY_FIXTURE/thunderbird/distribution/policies.json#g" \
    -e "s#/usr/lib64/thunderbird/mozilla.cfg#$TB_OVERLAY_FIXTURE/thunderbird/mozilla.cfg#g" \
    -e "s#/var/lib/noid-privacy/managed-extensions/dkim_verifier@pl.xpi#$TB_OVERLAY_FIXTURE/dkim-current.xpi#g" \
    -e "s#/usr/local/lib/noid-privacy/validate-webextension.py#$TB_OVERLAY_FIXTURE/mock-bin/validate-webextension.py#g" \
    -e "s#/usr/local/share/applications#$TB_OVERLAY_FIXTURE/owned/applications#g" \
    -e "s#/usr/local/bin#$TB_OVERLAY_FIXTURE/owned/bin#g" \
    -e "s#/usr/share/applications/net.thunderbird.Thunderbird.desktop#$TB_OVERLAY_FIXTURE/vendor/applications/net.thunderbird.Thunderbird.desktop#g" \
    -e "s#/usr/bin/thunderbird#$TB_OVERLAY_FIXTURE/vendor/thunderbird#g" \
    -e "s#/run/noid-thunderbird-overlay.lock#$TB_OVERLAY_FIXTURE/overlay.lock#g" \
    "$TB_REASSERT_TMP" > "$TB_OVERLAY_FIXTURE/reassert.sh"
TB_DKIM_SEED_SHA=$(sha256sum "$TB_OVERLAY_FIXTURE/cache/dkim_verifier.xpi" | awk '{print $1}')
sed -i "s/^dkim_seed_sha256=.*/dkim_seed_sha256=$TB_DKIM_SEED_SHA/" \
    "$TB_OVERLAY_FIXTURE/reassert.sh"
TB_VENDOR_LAUNCHER="$TB_OVERLAY_FIXTURE/vendor/thunderbird"
TB_VENDOR_DESKTOP="$TB_OVERLAY_FIXTURE/vendor/applications/net.thunderbird.Thunderbird.desktop"
TB_VENDOR_LAUNCHER_DIGEST=$(sha256sum "$TB_VENDOR_LAUNCHER" | awk '{print $1}')
TB_VENDOR_DESKTOP_DIGEST=$(sha256sum "$TB_VENDOR_DESKTOP" | awk '{print $1}')
export TB_VENDOR_LAUNCHER TB_VENDOR_DESKTOP \
    TB_VENDOR_LAUNCHER_DIGEST TB_VENDOR_DESKTOP_DIGEST
tb_vendor_before=$(sha256sum "$TB_VENDOR_LAUNCHER" "$TB_VENDOR_DESKTOP")
if PATH="$TB_OVERLAY_FIXTURE/mock-bin:$PATH" bash "$TB_OVERLAY_FIXTURE/reassert.sh"; then
    ok "Thunderbird overlay generator executes against pristine signed-payload fixture"
else
    err "Thunderbird overlay generator executes against pristine signed-payload fixture"
fi

tb_reassert_arg_snapshot() {
    find "$TB_OVERLAY_FIXTURE/owned" "$TB_OVERLAY_FIXTURE/thunderbird" \
        -type f -printf '%p\t%s\t%T@\t%m\n' | sort
    find "$TB_OVERLAY_FIXTURE/owned" "$TB_OVERLAY_FIXTURE/thunderbird" \
        -type f -print0 | sort -z | xargs -0 sha256sum
}
tb_reassert_arg_before=$(tb_reassert_arg_snapshot)
set +e
tb_reassert_arg_output=$(
    PATH="$TB_OVERLAY_FIXTURE/mock-bin:$PATH" \
        bash "$TB_OVERLAY_FIXTURE/reassert.sh" --unexpected 2>&1
)
tb_reassert_arg_rc=$?
set -e
tb_reassert_arg_after=$(tb_reassert_arg_snapshot)
if [ "$tb_reassert_arg_rc" -eq 2 ] \
   && [ "$tb_reassert_arg_output" = 'Usage: noid-thunderbird-reassert' ] \
   && [ "$tb_reassert_arg_before" = "$tb_reassert_arg_after" ]; then
    ok "Thunderbird reassert rejects unexpected arguments before mutation"
else
    err "Thunderbird reassert accepted or acted on unexpected arguments"
fi

for tb_digest_mode in duplicate empty; do
    tb_digest_before=$(tb_reassert_arg_snapshot)
    set +e
    tb_digest_output=$(
        TB_MOCK_RPM_DIGEST_MODE="$tb_digest_mode" \
        PATH="$TB_OVERLAY_FIXTURE/mock-bin:$PATH" \
            bash "$TB_OVERLAY_FIXTURE/reassert.sh" 2>&1
    )
    tb_digest_rc=$?
    set -e
    tb_digest_after=$(tb_reassert_arg_snapshot)
    if [ "$tb_digest_rc" -eq 1 ] \
       && printf '%s\n' "$tb_digest_output" \
            | grep -qF 'cannot obtain RPM digest' \
       && [ "$tb_digest_before" = "$tb_digest_after" ]; then
        ok "a $tb_digest_mode RPM digest line fails closed before any overlay mutation"
    else
        err "a $tb_digest_mode RPM digest line was accepted or mutated overlays (rc=$tb_digest_rc)"
    fi
done

cat > "$TB_OVERLAY_FIXTURE/mock-bin/sed" <<'TB_REASSERT_SIGNAL_SED_EOF'
#!/usr/bin/bash
set -euo pipefail
if [ "${TB_REASSERT_SIGNAL_TEST:-0}" -eq 1 ]; then
    printf '%s\n' "$$" > "$TB_REASSERT_SIGNAL_PID_FILE"
    printf '%s\n' ready > "$TB_REASSERT_SIGNAL_READY"
    trap 'exit 143' TERM
    while :; do :; done
fi
exec /usr/bin/sed "$@"
TB_REASSERT_SIGNAL_SED_EOF
chmod 0700 "$TB_OVERLAY_FIXTURE/mock-bin/sed"
TB_REASSERT_SIGNAL_READY="$TB_OVERLAY_FIXTURE/reassert-signal.ready"
TB_REASSERT_SIGNAL_PID_FILE="$TB_OVERLAY_FIXTURE/reassert-signal.pid"
env TB_REASSERT_SIGNAL_TEST=1 \
    TB_REASSERT_SIGNAL_READY="$TB_REASSERT_SIGNAL_READY" \
    TB_REASSERT_SIGNAL_PID_FILE="$TB_REASSERT_SIGNAL_PID_FILE" \
    /usr/bin/bash "$TB_OVERLAY_FIXTURE/reassert.sh" >/dev/null 2>&1 &
TB_REASSERT_SIGNAL_SHELL_PID=$!
for _ in $(seq 1 500); do
    [ -s "$TB_REASSERT_SIGNAL_PID_FILE" ] && break
    sleep 0.01
done
set +e
kill -TERM "$TB_REASSERT_SIGNAL_SHELL_PID" 2>/dev/null
if [ -s "$TB_REASSERT_SIGNAL_PID_FILE" ]; then
    kill -TERM "$(cat "$TB_REASSERT_SIGNAL_PID_FILE")" 2>/dev/null
fi
wait "$TB_REASSERT_SIGNAL_SHELL_PID"
TB_REASSERT_SIGNAL_RC=$?
set -e
if [ "$TB_REASSERT_SIGNAL_RC" -eq 143 ] \
   && ! find "$TB_OVERLAY_FIXTURE/owned/bin" -maxdepth 1 \
        -name '.thunderbird.*' -print -quit | grep -q . \
   && ! find "$TB_OVERLAY_FIXTURE/owned/applications" -maxdepth 1 \
        -name '.net.thunderbird.Thunderbird.*' -print -quit | grep -q .; then
    ok "Thunderbird reassert TERM cleanup retires both derived-overlay candidates"
else
    err "Thunderbird reassert TERM cleanup leaked a candidate or wrong status ($TB_REASSERT_SIGNAL_RC)"
fi

mv "$TB_OVERLAY_FIXTURE/owned/bin" "$TB_OVERLAY_FIXTURE/owned/bin.real"
mkdir -m 0700 "$TB_OVERLAY_FIXTURE/symlink-victim"
printf '%s\n' 'must not be normalized through a symlink' \
    > "$TB_OVERLAY_FIXTURE/symlink-victim/sentinel"
ln -s "$TB_OVERLAY_FIXTURE/symlink-victim" \
    "$TB_OVERLAY_FIXTURE/owned/bin"
if /usr/bin/bash "$TB_OVERLAY_FIXTURE/reassert.sh" >/dev/null 2>&1; then
    err "Thunderbird reassert accepted a symlinked managed directory"
else
    ok "Thunderbird reassert rejects a symlinked managed directory before mutation"
fi
if [ "$(stat -c '%a' "$TB_OVERLAY_FIXTURE/symlink-victim")" = 700 ] \
   && grep -qFx 'must not be normalized through a symlink' \
        "$TB_OVERLAY_FIXTURE/symlink-victim/sentinel"; then
    ok "Thunderbird reassert does not chmod or modify a managed-directory symlink target"
else
    err "Thunderbird reassert mutated a managed-directory symlink target"
fi
rm -f "$TB_OVERLAY_FIXTURE/owned/bin"
mv "$TB_OVERLAY_FIXTURE/owned/bin.real" "$TB_OVERLAY_FIXTURE/owned/bin"

for managed_file in mozilla.cfg autoconfig.js local-settings.js noid-locale.js policies.json; do
    case "$managed_file" in
        mozilla.cfg) managed_dst="$TB_OVERLAY_FIXTURE/thunderbird/mozilla.cfg" ;;
        policies.json) managed_dst="$TB_OVERLAY_FIXTURE/thunderbird/distribution/policies.json" ;;
        *) managed_dst="$TB_OVERLAY_FIXTURE/thunderbird/defaults/pref/$managed_file" ;;
    esac
    if cmp -s "$TB_OVERLAY_FIXTURE/cache/$managed_file" "$managed_dst"; then
        ok "$managed_file is restored byte-exactly"
    else
        err "$managed_file is not restored byte-exactly"
    fi
done
if cmp -s "$TB_OVERLAY_FIXTURE/cache/dkim_verifier.xpi" \
        "$TB_OVERLAY_FIXTURE/thunderbird/distribution/extensions/dkim_verifier@pl.xpi"; then
    ok "missing DKIM XPI is restored from the exact validated seed"
else
    err "missing DKIM XPI is not restored from the exact validated seed"
fi
: > "$TB_OVERLAY_FIXTURE/reassert.log"
printf '%s' 'version=6.3.0 ' \
    > "$TB_OVERLAY_FIXTURE/thunderbird/distribution/extensions/dkim_verifier@pl.xpi"
if PATH="$TB_OVERLAY_FIXTURE/mock-bin:$PATH" \
        bash "$TB_OVERLAY_FIXTURE/reassert.sh" && \
   grep -qF 're-asserted DKIM Verifier payload inside the thunderbird package tree' \
        "$TB_OVERLAY_FIXTURE/reassert.log" && \
   ! grep -qF 're-asserted AutoConfig payload inside the thunderbird package tree' \
        "$TB_OVERLAY_FIXTURE/reassert.log"; then
    ok "DKIM-only repair is logged separately from AutoConfig repair"
else
    err "DKIM-only repair is mislabeled as an AutoConfig repair"
fi
printf '%s\n' 'version=6.4.0' > "$TB_OVERLAY_FIXTURE/dkim-current.xpi"
if PATH="$TB_OVERLAY_FIXTURE/mock-bin:$PATH" bash "$TB_OVERLAY_FIXTURE/reassert.sh"; then
    ok "validated durable DKIM state supersedes the older reviewed seed"
else
    err "validated durable DKIM state could not be reasserted"
fi
if cmp -s "$TB_OVERLAY_FIXTURE/dkim-current.xpi" \
        "$TB_OVERLAY_FIXTURE/thunderbird/distribution/extensions/dkim_verifier@pl.xpi"; then
    ok "DKIM destination advances to the validated durable version"
else
    err "DKIM destination did not advance to the validated durable version"
fi
printf '%s\n' 'version=6.5.0' \
    > "$TB_OVERLAY_FIXTURE/thunderbird/distribution/extensions/dkim_verifier@pl.xpi"
if PATH="$TB_OVERLAY_FIXTURE/mock-bin:$PATH" bash "$TB_OVERLAY_FIXTURE/reassert.sh"; then
    ok "newer validated DKIM destination is accepted"
else
    err "newer validated DKIM destination was rejected"
fi
if grep -qxF 'version=6.5.0' \
        "$TB_OVERLAY_FIXTURE/thunderbird/distribution/extensions/dkim_verifier@pl.xpi"; then
    ok "DKIM recovery never downgrades a newer validated destination"
else
    err "DKIM recovery downgraded a newer validated destination"
fi
printf '%s\n' '// stock overwrite' > "$TB_OVERLAY_FIXTURE/thunderbird/mozilla.cfg"
if PATH="$TB_OVERLAY_FIXTURE/mock-bin:$PATH" bash "$TB_OVERLAY_FIXTURE/reassert.sh"; then
    ok "Thunderbird reassert repairs an AutoConfig package stomp"
else
    err "Thunderbird reassert repairs an AutoConfig package stomp"
fi
if cmp -s "$TB_OVERLAY_FIXTURE/cache/mozilla.cfg" \
        "$TB_OVERLAY_FIXTURE/thunderbird/mozilla.cfg"; then
    ok "repaired Thunderbird AutoConfig matches its canonical cache"
else
    err "repaired Thunderbird AutoConfig differs from its canonical cache"
fi
mv "$TB_OVERLAY_FIXTURE/cache/autoconfig.js" \
    "$TB_OVERLAY_FIXTURE/cache/autoconfig.js.missing"
tb_autoconfig_before=$(sha256sum "$TB_OVERLAY_FIXTURE/thunderbird/mozilla.cfg" \
    "$TB_OVERLAY_FIXTURE/thunderbird/defaults/pref/noid-locale.js")
if PATH="$TB_OVERLAY_FIXTURE/mock-bin:$PATH" bash "$TB_OVERLAY_FIXTURE/reassert.sh" \
        >/dev/null 2>&1; then
    err "Thunderbird reassert accepted a partial canonical cache"
else
    ok "Thunderbird reassert fails closed on a partial canonical cache"
fi
if [ "$tb_autoconfig_before" = "$(sha256sum "$TB_OVERLAY_FIXTURE/thunderbird/mozilla.cfg" \
        "$TB_OVERLAY_FIXTURE/thunderbird/defaults/pref/noid-locale.js")" ]; then
    ok "failed Thunderbird cache preflight preserves other managed destinations"
else
    err "failed Thunderbird cache preflight changed another managed destination"
fi
mv "$TB_OVERLAY_FIXTURE/cache/autoconfig.js.missing" \
    "$TB_OVERLAY_FIXTURE/cache/autoconfig.js"
if grep -qF 'set -- -P default-release "$@"' \
        "$TB_OVERLAY_FIXTURE/owned/bin/thunderbird"; then
    ok "derived Thunderbird launcher selects the canonical profile"
else
    err "derived Thunderbird launcher does not select the canonical profile"
fi
if grep -qF -- '-p|-profile|--profile|' \
        "$TB_OVERLAY_FIXTURE/owned/bin/thunderbird" && \
   grep -qF -- 'case "${arg,,}" in' \
        "$TB_OVERLAY_FIXTURE/owned/bin/thunderbird" && \
   ! grep -qF -- '-P*' "$TB_OVERLAY_FIXTURE/owned/bin/thunderbird"; then
    ok "derived Thunderbird launcher recognizes exact profile flags case-insensitively"
else
    err "derived Thunderbird launcher accepts an attached or ambiguous -P argument"
fi
cp -- "$TB_OVERLAY_FIXTURE/owned/bin/thunderbird" \
    "$TB_OVERLAY_FIXTURE/launcher-argv-test"
cat > "$TB_OVERLAY_FIXTURE/mock-bin/record-argv" <<'TB_RECORD_ARGV_EOF'
#!/usr/bin/bash
printf '<%s>\n' "$@"
TB_RECORD_ARGV_EOF
chmod 0700 "$TB_OVERLAY_FIXTURE/mock-bin/record-argv"
sed -i "s#^MOZ_PROGRAM=/bin/true\$#MOZ_PROGRAM=$TB_OVERLAY_FIXTURE/mock-bin/record-argv#" \
    "$TB_OVERLAY_FIXTURE/launcher-argv-test"
tb_attached_profile_output=$(
    bash "$TB_OVERLAY_FIXTURE/launcher-argv-test" -Pfoo
)
tb_explicit_profile_output=$(
    bash "$TB_OVERLAY_FIXTURE/launcher-argv-test" -P alternate
)
tb_lowercase_profile_output=$(
    bash "$TB_OVERLAY_FIXTURE/launcher-argv-test" -p alternate
)
tb_uppercase_profile_output=$(
    bash "$TB_OVERLAY_FIXTURE/launcher-argv-test" --PROFILE /tmp/alternate
)
tb_attached_long_profile_output=$(
    bash "$TB_OVERLAY_FIXTURE/launcher-argv-test" --profile=/tmp/alternate
)
tb_ordinary_output=$(
    bash "$TB_OVERLAY_FIXTURE/launcher-argv-test" https://example.invalid/
)
tb_full_version_output=$(
    bash "$TB_OVERLAY_FIXTURE/launcher-argv-test" --FULL-VERSION
)
if [ "$tb_attached_profile_output" = $'<-P>\n<default-release>\n<-Pfoo>' ] \
   && [ "$tb_explicit_profile_output" = $'<-P>\n<alternate>' ] \
   && [ "$tb_lowercase_profile_output" = $'<-p>\n<alternate>' ] \
   && [ "$tb_uppercase_profile_output" = $'<--PROFILE>\n</tmp/alternate>' ] \
   && [ "$tb_attached_long_profile_output" = \
        $'<-P>\n<default-release>\n<--profile=/tmp/alternate>' ] \
   && [ "$tb_ordinary_output" = \
        $'<-P>\n<default-release>\n<https://example.invalid/>' ] \
   && [ "$tb_full_version_output" = $'<--FULL-VERSION>' ]; then
    ok "Thunderbird launcher argv contract resists attached-profile bypasses"
else
    err "Thunderbird launcher argv contract can bypass the canonical profile"
fi
if grep -qF "export MOZ_APP_LAUNCHER=\"$TB_OVERLAY_FIXTURE/owned/bin/thunderbird\"" \
        "$TB_OVERLAY_FIXTURE/owned/bin/thunderbird"; then
    ok "Thunderbird self-relaunch stays on the owned canonical-profile launcher"
else
    err "Thunderbird self-relaunch bypasses the owned launcher"
fi
if grep -qx "Exec=$TB_OVERLAY_FIXTURE/owned/bin/thunderbird %u" \
        "$TB_OVERLAY_FIXTURE/owned/applications/net.thunderbird.Thunderbird.desktop"; then
    ok "derived Thunderbird desktop selects the owned launcher"
else
    err "derived Thunderbird desktop does not select the owned launcher"
fi
if [ "$tb_vendor_before" = "$(sha256sum "$TB_VENDOR_LAUNCHER" "$TB_VENDOR_DESKTOP")" ]; then
    ok "Thunderbird overlay generation preserves vendor bytes"
else
    err "Thunderbird overlay generation changed vendor bytes"
fi
tb_owned_before=$(sha256sum "$TB_OVERLAY_FIXTURE/owned/bin/thunderbird" \
    "$TB_OVERLAY_FIXTURE/owned/applications/net.thunderbird.Thunderbird.desktop")
printf '\n# unexpected vendor drift\n' >> "$TB_VENDOR_LAUNCHER"
if PATH="$TB_OVERLAY_FIXTURE/mock-bin:$PATH" bash "$TB_OVERLAY_FIXTURE/reassert.sh" \
        >/dev/null 2>&1; then
    err "Thunderbird overlay generator accepted vendor drift"
else
    ok "Thunderbird overlay generator rejects vendor drift"
fi
if [ "$tb_owned_before" = "$(sha256sum "$TB_OVERLAY_FIXTURE/owned/bin/thunderbird" \
        "$TB_OVERLAY_FIXTURE/owned/applications/net.thunderbird.Thunderbird.desktop")" ]; then
    ok "failed Thunderbird regeneration preserves last known-good overlays"
else
    err "failed Thunderbird regeneration changed owned overlays"
fi
if grep -qF 'sudo /usr/local/sbin/noid-thunderbird-reassert' \
    "$REPO_ROOT/kickstart/snippets/25-update-process.ks"; then
    ok "guided update explicitly regenerates the Thunderbird owned overlays"
else
    err "guided update does not regenerate the Thunderbird owned overlays"
fi

# 10. regen-thunderbird-embed.sh --check passes (embed in sync with source).
# Invoke through Bash so a lost executable bit cannot silently remove the gate.
if bash "$REPO_ROOT/scripts/regen-thunderbird-embed.sh" --check \
        >/dev/null 2>&1; then
    ok "regen-thunderbird-embed.sh --check: embed in sync"
else
    err "regen-thunderbird-embed.sh --check: DRIFT or generator unavailable"
fi

# 11. 35-thunderbird.ks writes a health stamp
if [ -f "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" ]; then
    if grep -q 'stamp-35-thunderbird\.ok' "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" \
       && grep -q '^module=35$' "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" \
       && grep -q '^status=ok$' "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" \
       && grep -qF 'Prior Module 35 health stamp is absent' \
            "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" \
       && grep -qF 'cleanup_m35_publication()' \
            "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" \
       && grep -qF 'matchpathcon -V "$STAMP"' \
            "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks"; then
        ok "35-thunderbird.ks writes health stamp (module=35, status=ok)"
    else err "35-thunderbird.ks missing health stamp block"; fi
fi

m35_invalidate_line=$(grep -nF \
    '# M35_HEALTH_INVALIDATION_BEGIN' "$TB_KS" | cut -d: -f1 || true)
m35_first_payload_line=$(grep -nF \
    'NOID_TB_REASSERT_CANDIDATE=$(mktemp' "$TB_KS" | cut -d: -f1 || true)
m35_publish_line=$(grep -nF \
    'Exact Module 35 health stamp published atomically' "$TB_KS" | \
    cut -d: -f1 || true)
m35_complete_line=$(grep -nF \
    'log "=== Module 35: Thunderbird hardening COMPLETE ==="' \
    "$TB_KS" | cut -d: -f1 || true)
if [ -n "$m35_invalidate_line" ] && [ -n "$m35_first_payload_line" ] \
   && [ -n "$m35_publish_line" ] && [ -n "$m35_complete_line" ] \
   && [ "$m35_invalidate_line" -lt "$m35_first_payload_line" ] \
   && [ "$m35_publish_line" -lt "$m35_complete_line" ]; then
    ok "M35 retires old health before mutation and completes after publication"
else
    err "M35 retires old health before mutation and completes after publication"
fi

# Execute the exact invalidation/publication blocks with the production atomic
# publisher. Injected label and rename failures must never leave green health.
M35_STAMP_ROOT="$TB_TEST_TMP/health-stamp"
M35_STAMP_STATE="$M35_STAMP_ROOT/state"
M35_STAMP_BIN="$M35_STAMP_ROOT/bin"
M35_STAMP_INVALIDATE="$M35_STAMP_ROOT/invalidate.sh"
M35_STAMP_PUBLISH="$M35_STAMP_ROOT/publish.sh"
M35_STAMP_UID=$(id -u)
M35_STAMP_GID=$(id -g)
mkdir -p "$M35_STAMP_BIN"

cat > "$M35_STAMP_BIN/restorecon" <<'M35_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-35-thunderbird.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M35_STAMP_RESTORECON_EOF
cat > "$M35_STAMP_BIN/matchpathcon" <<'M35_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M35_STAMP_MATCHPATHCON_EOF
cat > "$M35_STAMP_BIN/mv" <<'M35_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M35_STAMP_MV_EOF
chmod 0700 "$M35_STAMP_BIN/restorecon" \
    "$M35_STAMP_BIN/matchpathcon" "$M35_STAMP_BIN/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' 'fail() { exit 1; }' \
        "STAMP_DIR=$M35_STAMP_STATE" \
        'STAMP="$STAMP_DIR/stamp-35-thunderbird.ok"'
    sed -n \
        '/^# M35_HEALTH_INVALIDATION_BEGIN$/,/^# M35_HEALTH_INVALIDATION_END$/p' \
        "$TB_KS" |
        sed -e "s|/var/lib/noid-privacy|$M35_STAMP_STATE|g" \
            -e "s/-o root -g root/-o $M35_STAMP_UID -g $M35_STAMP_GID/" \
            -e "s/0:0:755/$M35_STAMP_UID:$M35_STAMP_GID:755/"
} > "$M35_STAMP_INVALIDATE"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' 'fail() { exit 1; }' \
        "STAMP_DIR=$M35_STAMP_STATE" \
        'STAMP="$STAMP_DIR/stamp-35-thunderbird.ok"' \
        'STAMP_PUBLICATION_ACTIVE=0' 'ROOT_PUBLICATION_TMP='
    sed -n '/^cleanup_m35_publication() {$/,/^}$/p' "$TB_KS"
    printf '%s\n' 'trap cleanup_m35_publication EXIT'
    sed -n '/^publish_root_file() {$/,/^}$/p' "$TB_KS" |
        sed -e "s/-o root -g root/-o $M35_STAMP_UID -g $M35_STAMP_GID/" \
            -e "s/0:0:/$M35_STAMP_UID:$M35_STAMP_GID:/g"
    sed -n \
        '/M35_HEALTH_PUBLICATION_BEGIN$/,/M35_HEALTH_PUBLICATION_END$/p' \
        "$TB_KS" |
        sed -e "s/chown root:root/chown $M35_STAMP_UID:$M35_STAMP_GID/" \
            -e "s/0:0:755/$M35_STAMP_UID:$M35_STAMP_GID:755/" \
            -e "s/0:0:644:1/$M35_STAMP_UID:$M35_STAMP_GID:644:1/"
} > "$M35_STAMP_PUBLISH"
chmod 0700 "$M35_STAMP_INVALIDATE" "$M35_STAMP_PUBLISH"

mkdir -m 0755 "$M35_STAMP_STATE"
printf '%s\n' 'module=35' 'name=thunderbird' 'status=ok' \
    > "$M35_STAMP_STATE/stamp-35-thunderbird.ok"
if env PATH="$M35_STAMP_BIN:$PATH" "$M35_STAMP_INVALIDATE"; then
    ok "M35 rerun invalidates its prior build-success stamp"
else
    err "M35 rerun invalidates its prior build-success stamp"
fi
if [ ! -e "$M35_STAMP_STATE/stamp-35-thunderbird.ok" ]; then
    ok "M35 old success evidence is absent before payload publication"
else
    err "M35 old success evidence is absent before payload publication"
fi

chmod 0777 "$M35_STAMP_STATE"
printf '%s\n' 'must-survive' \
    > "$M35_STAMP_STATE/stamp-35-thunderbird.ok"
if env PATH="$M35_STAMP_BIN:$PATH" "$M35_STAMP_INVALIDATE"; then
    err "M35 rejects shared state-directory metadata drift"
else
    ok "M35 rejects shared state-directory metadata drift"
fi
if [ "$(stat -c '%u:%g:%a' "$M35_STAMP_STATE")" = \
        "$M35_STAMP_UID:$M35_STAMP_GID:777" ] \
   && grep -qFx 'must-survive' \
        "$M35_STAMP_STATE/stamp-35-thunderbird.ok"; then
    ok "M35 does not normalize or traverse a drifted state boundary"
else
    err "M35 does not normalize or traverse a drifted state boundary"
fi
rm "$M35_STAMP_STATE/stamp-35-thunderbird.ok"
chmod 0755 "$M35_STAMP_STATE"

if env PATH="$M35_STAMP_BIN:$PATH" FAKE_RESTORECON_FAIL=all \
        "$M35_STAMP_PUBLISH"; then
    err "M35 rejects a health-stamp candidate label failure"
else
    ok "M35 rejects a health-stamp candidate label failure"
fi
if [ ! -e "$M35_STAMP_STATE/stamp-35-thunderbird.ok" ] \
   && [ -z "$(find "$M35_STAMP_STATE" -maxdepth 1 \
        -name '.stamp-35-thunderbird.ok.*' -print -quit)" ]; then
    ok "M35 candidate-label failure leaves no plausible health evidence"
else
    err "M35 candidate-label failure leaves no plausible health evidence"
fi

if env PATH="$M35_STAMP_BIN:$PATH" FAKE_RESTORECON_FAIL=final \
        "$M35_STAMP_PUBLISH"; then
    err "M35 rejects a final health-stamp label failure"
else
    ok "M35 rejects a final health-stamp label failure"
fi
if [ ! -e "$M35_STAMP_STATE/stamp-35-thunderbird.ok" ]; then
    ok "M35 final-label failure removes the published success stamp"
else
    err "M35 final-label failure removes the published success stamp"
fi

if env PATH="$M35_STAMP_BIN:$PATH" FAKE_MV_FAIL=1 \
        "$M35_STAMP_PUBLISH"; then
    err "M35 rejects an atomic health-stamp rename failure"
else
    ok "M35 rejects an atomic health-stamp rename failure"
fi
if [ ! -e "$M35_STAMP_STATE/stamp-35-thunderbird.ok" ]; then
    ok "M35 rename failure leaves no success stamp"
else
    err "M35 rename failure leaves no success stamp"
fi

if env PATH="$M35_STAMP_BIN:$PATH" "$M35_STAMP_PUBLISH"; then
    ok "M35 publishes exact health evidence after all gates"
else
    err "M35 publishes exact health evidence after all gates"
fi
if [ "$(stat -c '%u:%g:%a:%h' \
        "$M35_STAMP_STATE/stamp-35-thunderbird.ok" 2>/dev/null || true)" = \
        "$M35_STAMP_UID:$M35_STAMP_GID:644:1" ] \
   && [ "$(wc -l < \
        "$M35_STAMP_STATE/stamp-35-thunderbird.ok")" -eq 6 ] \
   && grep -qFx 'module=35' \
        "$M35_STAMP_STATE/stamp-35-thunderbird.ok" \
   && grep -qFx 'name=thunderbird' \
        "$M35_STAMP_STATE/stamp-35-thunderbird.ok" \
   && grep -qFx 'status=ok' \
        "$M35_STAMP_STATE/stamp-35-thunderbird.ok"; then
    ok "M35 published health stamp has exact metadata and six-line schema"
else
    err "M35 published health stamp has exact metadata and six-line schema"
fi

# 12. TB mozilla.cfg: M35 heredoc <-> standalone byte-identical (parity gate).
# Layer 2 mozilla.cfg has a standalone source and generated M35 copy;
# regen-thunderbird-mozilla-cfg.sh --check gates their parity. Invoke through
# Bash so the gate remains visible even if its executable bit drifts.
if bash "$REPO_ROOT/scripts/regen-thunderbird-mozilla-cfg.sh" --check \
        >/dev/null 2>&1; then
    ok "regen-thunderbird-mozilla-cfg.sh --check: heredoc <-> standalone in sync"
else
    err "regen-thunderbird-mozilla-cfg.sh --check: DRIFT or generator unavailable"
fi

# 12b. Execute the embedded strict AutoConfig validator. A malformed line
# must fail even when the expected preference text remains grep-visible.
TB_CFG_VALIDATOR="$TB_TEST_TMP/validate-mozilla-cfg.py"
awk '
    /^if ! python3 - "\$TB_INSTALL_DIR\/mozilla.cfg" <<.MOZILLA_SYNTAX_PY_EOF./ { copy=1; next }
    copy && /^MOZILLA_SYNTAX_PY_EOF$/ { exit }
    copy { print }
' "$TB_KS" > "$TB_CFG_VALIDATOR"
if python3 "$TB_CFG_VALIDATOR" "$REPO_ROOT/thunderbird/mozilla.cfg"; then
    ok "mozilla.cfg strict grammar validator accepts canonical source"
else
    err "mozilla.cfg strict grammar validator rejects canonical source"
fi
cp "$REPO_ROOT/thunderbird/mozilla.cfg" "$TB_TEST_TMP/mozilla-broken.cfg"
printf '%s\n' 'defaultPref("syntactically.broken", );' >> "$TB_TEST_TMP/mozilla-broken.cfg"
if python3 "$TB_CFG_VALIDATOR" "$TB_TEST_TMP/mozilla-broken.cfg" >/dev/null 2>&1; then
    err "mozilla.cfg strict grammar validator accepted malformed JavaScript"
else
    ok "mozilla.cfg strict grammar validator rejects malformed JavaScript"
fi

# 12c. Exercise the registered-profile, path, backup, atomic-publication and
# exact-CLI contracts of the migration/multi-profile helper.
TB_HARDEN_TMP="$TB_TEST_TMP/noid-thunderbird-harden-profile"
awk '
    /^cat > "\$HARDEN_PROFILE_CANDIDATE" <<.HARDEN_PROFILE_SH_EOF./ { copy=1; next }
    copy && /^HARDEN_PROFILE_SH_EOF$/ { exit }
    copy { print }
' "$TB_KS" > "$TB_HARDEN_TMP"
chmod 0755 "$TB_HARDEN_TMP"
printf '%s\n' 'user_pref("_noid.thunderbird.hardening.version", "fixture");' \
    > "$TB_TEST_TMP/canonical-user.js"
chmod 0644 "$TB_TEST_TMP/canonical-user.js"
sed -i "s|^NOID_USERJS=.*|NOID_USERJS=\"$TB_TEST_TMP/canonical-user.js\"|" \
    "$TB_HARDEN_TMP"
TB_FIXTURE_SOURCE_OWNER=$(stat -c '%u:%g' "$TB_TEST_TMP/canonical-user.js")
sed -i "s/0:0:644:1/$TB_FIXTURE_SOURCE_OWNER:644:1/" "$TB_HARDEN_TMP"
mkdir -p "$TB_TEST_TMP/home/.thunderbird/relative.default" \
         "$TB_TEST_TMP/home/.thunderbird/second.default" \
         "$TB_TEST_TMP/state" "$TB_TEST_TMP/bin"
sed -i "s|^PATH=.*|PATH=$TB_TEST_TMP/bin:/usr/sbin:/usr/bin:/sbin:/bin|" \
    "$TB_HARDEN_TMP"
cat > "$TB_TEST_TMP/bin/pgrep" <<'TB_PGREP_EOF'
#!/bin/sh
mode=$(cat "$(dirname "$0")/process-mode" 2>/dev/null || printf '%s' none)
case "$mode" in
    active|zombie) printf '%s\n' 4242 ;;
    *) exit 1 ;;
esac
TB_PGREP_EOF
cat > "$TB_TEST_TMP/bin/ps" <<'TB_PS_EOF'
#!/bin/sh
mode=$(cat "$(dirname "$0")/process-mode" 2>/dev/null || printf '%s' none)
case "$mode" in
    active) printf '%s\n' S ;;
    zombie) printf '%s\n' Z ;;
    *) exit 1 ;;
esac
TB_PS_EOF
chmod 0700 "$TB_TEST_TMP/bin/pgrep"
chmod 0700 "$TB_TEST_TMP/bin/ps"
ln -s /usr/bin/true "$TB_TEST_TMP/bin/matchpathcon"
cat > "$TB_TEST_TMP/home/.thunderbird/profiles.ini" <<'PROFILE_FIXTURE'
[Profile0]
Name=relative
IsRelative=1
Path=relative.default

[Profile1]
Name=second
IsRelative=1
Path=second.default
PROFILE_FIXTURE
printf '%s\n' \
    'pre-existing Thunderbird user.js sentinel' \
    '// user_pref("_noid.thunderbird.hardening.version", "comment-only");' \
    > "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js"
run_tb_harden() {
    sed -i "s|^PASSWD_HOME=.*|PASSWD_HOME=\"$TB_TEST_TMP/home\"|" \
        "$TB_HARDEN_TMP"
    HOME="$TB_TEST_TMP/home" XDG_STATE_HOME="$TB_TEST_TMP/state" \
        PATH="$TB_TEST_TMP/bin:$PATH" bash "$TB_HARDEN_TMP" "$@"
}

# The updater-safe mode must initialize an absent user.js, refresh a profile
# carrying the exact NoID Privacy marker and preserve every foreign user.js. It must
# also publish exact machine-readable eligible/change/protected counts.
mv "$TB_TEST_TMP/home/.thunderbird" \
    "$TB_TEST_TMP/home/.thunderbird.fixture"
tb_absent_output=$(run_tb_harden --automatic)
if [ ! -e "$TB_TEST_TMP/home/.thunderbird" ] && \
   grep -qFx 'NOID_RESULT eligible=0 changed=0 protected=0' <<< "$tb_absent_output"; then
    ok "automatic reconciliation leaves an absent Thunderbird tree absent"
else
    err "automatic reconciliation adopted an absent Thunderbird tree"
fi
mv "$TB_TEST_TMP/home/.thunderbird.fixture" \
    "$TB_TEST_TMP/home/.thunderbird"
tb_foreign_before=$(sha256sum \
    "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")
tb_managed_empty_output=$(run_tb_harden --automatic)
if [ "$tb_foreign_before" = "$(sha256sum \
        "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")" ] && \
   cmp -s "$TB_TEST_TMP/canonical-user.js" \
        "$TB_TEST_TMP/home/.thunderbird/second.default/user.js" && \
   grep -qFx 'NOID_RESULT eligible=1 changed=1 protected=1' \
        <<< "$tb_managed_empty_output"; then
    ok "automatic reconciliation initializes new profiles and preserves foreign user.js"
else
    err "automatic reconciliation crossed the new-versus-foreign profile boundary"
fi
printf '%s\n' \
    'user_pref("_noid.thunderbird.hardening.version", "old-fixture");' \
    'user_pref("noid.fixture.old", true);' \
    > "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js"
printf '%s\n' 'foreign second-profile user.js' \
    > "$TB_TEST_TMP/home/.thunderbird/second.default/user.js"
tb_second_foreign_before=$(sha256sum \
    "$TB_TEST_TMP/home/.thunderbird/second.default/user.js")
tb_managed_refresh_output=$(run_tb_harden --automatic)
if cmp -s "$TB_TEST_TMP/canonical-user.js" \
        "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js" && \
   [ "$tb_second_foreign_before" = "$(sha256sum \
        "$TB_TEST_TMP/home/.thunderbird/second.default/user.js")" ] && \
   grep -qFx 'NOID_RESULT eligible=1 changed=1 protected=1' \
        <<< "$tb_managed_refresh_output"; then
    ok "automatic reconciliation refreshes marker-owned bytes and preserves foreign bytes"
else
    err "automatic reconciliation crossed its ownership boundary"
fi

if run_tb_harden --all >/dev/null && \
   cmp -s "$TB_TEST_TMP/canonical-user.js" \
       "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js" && \
   cmp -s "$TB_TEST_TMP/canonical-user.js" \
       "$TB_TEST_TMP/home/.thunderbird/second.default/user.js" && \
   [ "$(stat -c '%a' "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")" = 600 ]; then
    ok "harden-profile atomically applies canonical bytes to registered relative profiles"
else
    err "harden-profile failed registered relative-profile fixture"
fi
if [ "$(find "$TB_TEST_TMP/home/.thunderbird/relative.default" -maxdepth 1 \
        -type f -name 'user.js.bak-noid-*' | wc -l)" -eq 1 ] && \
   [ "$(stat -c '%a' "$(find \
        "$TB_TEST_TMP/home/.thunderbird/relative.default" -maxdepth 1 \
        -type f -name 'user.js.bak-noid-*' -print -quit)")" = 600 ]; then
    ok "harden-profile preserves one private collision-safe backup before replacement"
else
    err "harden-profile did not preserve exactly one private initial backup"
fi

cat > "$TB_TEST_TMP/bin/install" <<'TB_PROFILE_SIGNAL_INSTALL_EOF'
#!/usr/bin/bash
set -euo pipefail
if [ "${TB_PROFILE_SIGNAL_TEST:-0}" -eq 1 ]; then
    printf '%s\n' "$$" > "$TB_PROFILE_SIGNAL_PID_FILE"
    printf '%s\n' ready > "$TB_PROFILE_SIGNAL_READY"
    trap 'exit 143' TERM
    while :; do :; done
fi
exec /usr/bin/install "$@"
TB_PROFILE_SIGNAL_INSTALL_EOF
chmod 0700 "$TB_TEST_TMP/bin/install"
TB_PROFILE_SIGNAL_READY="$TB_TEST_TMP/profile-signal.ready"
TB_PROFILE_SIGNAL_PID_FILE="$TB_TEST_TMP/profile-signal.pid"
printf '%s\n' 'must survive interrupted profile publication' \
    > "$TB_TEST_TMP/home/.thunderbird/second.default/user.js"
env HOME="$TB_TEST_TMP/home" XDG_STATE_HOME="$TB_TEST_TMP/state" \
    TB_PROFILE_SIGNAL_TEST=1 \
    TB_PROFILE_SIGNAL_READY="$TB_PROFILE_SIGNAL_READY" \
    TB_PROFILE_SIGNAL_PID_FILE="$TB_PROFILE_SIGNAL_PID_FILE" \
    /usr/bin/bash "$TB_HARDEN_TMP" second >/dev/null 2>&1 &
TB_PROFILE_SIGNAL_SHELL_PID=$!
for _ in $(seq 1 500); do
    [ -s "$TB_PROFILE_SIGNAL_PID_FILE" ] && break
    sleep 0.01
done
set +e
kill -TERM "$TB_PROFILE_SIGNAL_SHELL_PID" 2>/dev/null
if [ -s "$TB_PROFILE_SIGNAL_PID_FILE" ]; then
    kill -TERM "$(cat "$TB_PROFILE_SIGNAL_PID_FILE")" 2>/dev/null
fi
wait "$TB_PROFILE_SIGNAL_SHELL_PID"
TB_PROFILE_SIGNAL_RC=$?
set -e
if [ "$TB_PROFILE_SIGNAL_RC" -eq 143 ] \
   && grep -qFx 'must survive interrupted profile publication' \
        "$TB_TEST_TMP/home/.thunderbird/second.default/user.js" \
   && ! find "$TB_TEST_TMP/home/.thunderbird/second.default" -maxdepth 1 \
        -name '.user.js.tmp.*' -print -quit | grep -q .; then
    ok "profile-helper TERM cleanup preserves old bytes and retires its atomic candidate"
else
    err "profile-helper TERM cleanup crossed the publication boundary ($TB_PROFILE_SIGNAL_RC)"
fi
if ! run_tb_harden second >/dev/null; then
    err "profile helper did not recover after the TERM cleanup fixture"
fi

tb_idempotent_before=$(sha256sum \
    "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")
if run_tb_harden relative >/dev/null && run_tb_harden relative >/dev/null && \
   [ "$(find "$TB_TEST_TMP/home/.thunderbird/relative.default" -maxdepth 1 \
        -type f -name 'user.js.bak-noid-*' | wc -l)" -eq 1 ] && \
   [ "$tb_idempotent_before" = "$(sha256sum \
        "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")" ]; then
    ok "reapplying canonical profile bytes is idempotent and creates no backup churn"
else
    err "reapplying canonical profile bytes changed state or created backup churn"
fi
printf '%s' 'must survive active process guard' \
    > "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js"
printf '%s\n' active > "$TB_TEST_TMP/bin/process-mode"
set +e
run_tb_harden relative >/dev/null 2>&1
TB_ACTIVE_RC=$?
set -e
if [ "$TB_ACTIVE_RC" -eq 75 ] && \
   [ "$(cat "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")" = \
       'must survive active process guard' ]; then
    ok "live Thunderbird process guard returns 75 before profile mutation"
else
    err "live Thunderbird process guard did not fail closed before mutation"
fi
printf '%s\n' zombie > "$TB_TEST_TMP/bin/process-mode"
if run_tb_harden relative >/dev/null && \
   cmp -s "$TB_TEST_TMP/canonical-user.js" \
       "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js"; then
    ok "zombie-only Thunderbird process records do not block profile maintenance"
else
    err "zombie-only Thunderbird process records incorrectly block maintenance"
fi
printf '%s\n' none > "$TB_TEST_TMP/bin/process-mode"
if run_tb_harden relative surplus >/dev/null 2>&1; then
    err "harden-profile accepted surplus arguments"
else
    ok "harden-profile rejects surplus arguments"
fi

mkdir -p "$TB_TEST_TMP/absolute-profile"
cat > "$TB_TEST_TMP/home/.thunderbird/profiles.ini" <<PROFILE_ABSOLUTE_FIXTURE
[Profile0]
Name=absolute
IsRelative=0
Path=$TB_TEST_TMP/absolute-profile
PROFILE_ABSOLUTE_FIXTURE
if run_tb_harden --all >/dev/null 2>&1 || \
   [ -e "$TB_TEST_TMP/absolute-profile/user.js" ]; then
    err "harden-profile followed an absolute profiles.ini destination"
else
    ok "harden-profile rejects absolute profiles.ini destinations without mutation"
fi
tb_external_managed_output=$(run_tb_harden --automatic)
if [ ! -e "$TB_TEST_TMP/absolute-profile/user.js" ] && \
   grep -qFx 'NOID_RESULT eligible=0 changed=0 protected=0' \
        <<< "$tb_external_managed_output"; then
    ok "automatic reconciliation safely skips external profiles outside its authority"
else
    err "automatic reconciliation touched or failed on an external profile"
fi

cat > "$TB_TEST_TMP/home/.thunderbird/profiles.ini" <<'PROFILE_TRAVERSAL_FIXTURE'
[Profile0]
Name=traversal
IsRelative=1
Path=../outside-profile
PROFILE_TRAVERSAL_FIXTURE
if run_tb_harden --all >/dev/null 2>&1; then
    err "harden-profile accepted profile traversal"
else
    ok "harden-profile rejects profile traversal"
fi

ln -s "$TB_TEST_TMP/absolute-profile" \
    "$TB_TEST_TMP/home/.thunderbird/symlink.profile"
cat > "$TB_TEST_TMP/home/.thunderbird/profiles.ini" <<'PROFILE_SYMLINK_FIXTURE'
[Profile0]
Name=symlinked
IsRelative=1
Path=symlink.profile
PROFILE_SYMLINK_FIXTURE
if run_tb_harden --all >/dev/null 2>&1; then
    err "harden-profile accepted a symlinked profile path"
else
    ok "harden-profile rejects symlinked profile paths"
fi
rm -f "$TB_TEST_TMP/home/.thunderbird/symlink.profile"

cat > "$TB_TEST_TMP/home/.thunderbird/profiles.ini" <<'PROFILE_VALID_AGAIN_FIXTURE'
[Profile0]
Name=relative
IsRelative=1
Path=relative.default

[Profile1]
Name=second
IsRelative=1
Path=second.default
PROFILE_VALID_AGAIN_FIXTURE
printf '%s' 'symlink victim sentinel' > "$TB_TEST_TMP/victim"
rm -f "$TB_TEST_TMP/home/.thunderbird/second.default/user.js"
ln -s "$TB_TEST_TMP/victim" \
    "$TB_TEST_TMP/home/.thunderbird/second.default/user.js"
if run_tb_harden second >/dev/null 2>&1 || \
   [ "$(cat "$TB_TEST_TMP/victim")" != 'symlink victim sentinel' ]; then
    err "harden-profile followed a symlinked user.js destination"
else
    ok "harden-profile rejects symlinked user.js and preserves its target"
fi
rm -f "$TB_TEST_TMP/home/.thunderbird/second.default/user.js"

mkdir -m 0700 "$TB_TEST_TMP/home/.thunderbird/all.named" \
    "$TB_TEST_TMP/home/.thunderbird/automatic.named"
cat > "$TB_TEST_TMP/home/.thunderbird/profiles.ini" <<'PROFILE_RESERVED_NAMES_FIXTURE'
[Profile0]
Name=relative
IsRelative=1
Path=relative.default

[Profile1]
Name=second
IsRelative=1
Path=second.default

[Profile2]
Name=all
IsRelative=1
Path=all.named

[Profile3]
Name=automatic
IsRelative=1
Path=automatic.named
PROFILE_RESERVED_NAMES_FIXTURE
printf '%s\n' 'reserved-name neighbor sentinel' \
    > "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js"
printf '%s\n' 'automatic named-profile sentinel' \
    > "$TB_TEST_TMP/home/.thunderbird/automatic.named/user.js"
tb_reserved_neighbor_before=$(sha256sum \
    "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")
if run_tb_harden all >/dev/null && \
   cmp -s "$TB_TEST_TMP/canonical-user.js" \
        "$TB_TEST_TMP/home/.thunderbird/all.named/user.js" && \
   [ "$tb_reserved_neighbor_before" = "$(sha256sum \
        "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")" ] && \
   grep -qFx 'automatic named-profile sentinel' \
        "$TB_TEST_TMP/home/.thunderbird/automatic.named/user.js"; then
    ok "bare profile name all selects one profile instead of bulk scope"
else
    err "bare profile name all escalated to bulk scope"
fi
if run_tb_harden automatic >/dev/null && \
   cmp -s "$TB_TEST_TMP/canonical-user.js" \
        "$TB_TEST_TMP/home/.thunderbird/automatic.named/user.js" && \
   [ "$tb_reserved_neighbor_before" = "$(sha256sum \
        "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")" ]; then
    ok "bare profile name automatic selects one profile instead of updater scope"
else
    err "bare profile name automatic escalated to updater scope"
fi
if run_tb_harden --remove all >/dev/null && \
   [ ! -e "$TB_TEST_TMP/home/.thunderbird/all.named/user.js" ] && \
   cmp -s "$TB_TEST_TMP/canonical-user.js" \
        "$TB_TEST_TMP/home/.thunderbird/automatic.named/user.js" && \
   [ "$tb_reserved_neighbor_before" = "$(sha256sum \
        "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")" ]; then
    ok "--remove with profile name all remains single-profile scope"
else
    err "--remove with profile name all escalated to bulk removal"
fi
rm -rf "$TB_TEST_TMP/home/.thunderbird/all.named" \
    "$TB_TEST_TMP/home/.thunderbird/automatic.named"
cat > "$TB_TEST_TMP/home/.thunderbird/profiles.ini" <<'PROFILE_VALID_AFTER_RESERVED_FIXTURE'
[Profile0]
Name=relative
IsRelative=1
Path=relative.default

[Profile1]
Name=second
IsRelative=1
Path=second.default
PROFILE_VALID_AFTER_RESERVED_FIXTURE

printf '%s\n' 'foreign remove sentinel' \
    > "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js"
tb_foreign_remove_before=$(sha256sum \
    "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")
tb_foreign_remove_output=$(run_tb_harden --remove relative)
if [ "$tb_foreign_remove_before" = "$(sha256sum \
        "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js")" ] && \
   grep -qF 'Preserved foreign user.js and disabled automatic NoID Privacy hardening' \
        <<< "$tb_foreign_remove_output" && \
   grep -qFx NOID_THUNDERBIRD_HARDENING_DISABLED_V1 \
        "$TB_TEST_TMP/home/.thunderbird/relative.default/.noid-thunderbird-hardening-disabled"; then
    ok "removing a foreign user.js preserves it and records the opt-out explicitly"
else
    err "removing a foreign user.js succeeds without an explicit preserved opt-out"
fi
if ! run_tb_harden relative >/dev/null; then
    err "explicit profile apply did not recover after foreign remove fixture"
fi

if run_tb_harden --remove relative >/dev/null && \
   [ ! -e "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js" ] && \
   grep -qFx NOID_THUNDERBIRD_HARDENING_DISABLED_V1 \
       "$TB_TEST_TMP/home/.thunderbird/relative.default/.noid-thunderbird-hardening-disabled"; then
    ok "registered-name remove backs up, removes NoID Privacy user.js and records automatic opt-out"
else
    err "registered-name remove failed"
fi
tb_removed_output=$(run_tb_harden --automatic)
if [ ! -e "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js" ] && \
   grep -qFx 'NOID_RESULT eligible=1 changed=1 protected=1' \
       <<< "$tb_removed_output"; then
    ok "automatic reconciliation preserves explicit opt-out while initializing another new profile"
else
    err "automatic reconciliation ignored an explicit profile opt-out"
fi
if run_tb_harden relative >/dev/null && \
   cmp -s "$TB_TEST_TMP/canonical-user.js" \
       "$TB_TEST_TMP/home/.thunderbird/relative.default/user.js" && \
   [ ! -e "$TB_TEST_TMP/home/.thunderbird/relative.default/.noid-thunderbird-hardening-disabled" ]; then
    ok "explicit profile application clears the automatic opt-out"
else
    err "explicit profile application did not clear the automatic opt-out"
fi

TB_LOCK="$TB_TEST_TMP/state/noid-privacy/thunderbird-profile-operations.lock"
exec 8>"$TB_LOCK"
flock -n 8
set +e
run_tb_harden --all >/dev/null 2>&1
TB_LOCK_RC=$?
set -e
flock -u 8
exec 8>&-
if [ "$TB_LOCK_RC" -eq 75 ]; then
    ok "concurrent Thunderbird profile operation returns retry code 75"
else
    err "concurrent Thunderbird profile operation returned $TB_LOCK_RC instead of 75"
fi

# 13. Hybrid TLS must be explicit in both profile and system-wide layers.
if grep -qF 'user_pref("security.tls.enable_kyber", true);' \
    "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
    ok "user.js explicitly enables hybrid TLS client capability"
else
    err "user.js missing explicit hybrid TLS client capability"
fi
if grep -qF 'defaultPref("security.tls.enable_kyber", true);' \
    "$REPO_ROOT/thunderbird/mozilla.cfg"; then
    ok "mozilla.cfg explicitly enables hybrid TLS client capability"
else
    err "mozilla.cfg missing explicit hybrid TLS client capability"
fi
if grep -qF 'defaultPref("network.trr.mode", 5);' \
        "$REPO_ROOT/thunderbird/mozilla.cfg" && \
   ! grep -qE '^[[:space:]]*defaultPref\("network\.trr\.(uri|custom_uri|bootstrapAddr)"' \
        "$REPO_ROOT/thunderbird/mozilla.cfg" && \
   ! grep -qE '^[[:space:]]*user_pref\("network\.trr\.' \
        "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js"; then
    ok "Thunderbird defaults to provider-neutral OS/VPN DNS without resetting user choice"
else
    err "Thunderbird profile or AutoConfig still forces a browser DoH provider"
fi

# 14. The experimental smartcard path must not be documented as delegating
# public-key operations, and the stale GPGME filename-suffix override must stay
# absent from both deployed preference layers.
if "$REPO_ROOT/scripts/regen-thunderbird-smartcard-doc.sh" --check \
        >/dev/null 2>&1; then
    ok "M35 installed smartcard guide matches its canonical source"
else
    err "M35 installed smartcard guide drifted from its canonical source"
fi
awk '
    /^cat > "\$SMARTCARD_DOC_CANDIDATE" <<.NOID_TB_SMARTCARD_DOC_EOF./ {
        body = 1
        next
    }
    body && $0 == "NOID_TB_SMARTCARD_DOC_EOF" { exit }
    body { print }
' "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks" \
    > "$TB_TEST_TMP/35-thunderbird-smartcard-installed.md"
if cmp -s "$TB_TEST_TMP/35-thunderbird-smartcard-installed.md" \
        "$REPO_ROOT/docs/35-thunderbird-smartcard.md"; then
    ok "M35 smartcard heredoc is byte-identical to the source guide"
else
    err "M35 smartcard heredoc differs from the source guide"
fi
if grep -qF '`docs/35-thunderbird-mail-setup.md` (source tree)' \
        "$REPO_ROOT/docs/35-thunderbird-smartcard.md"; then
    ok "smartcard guide labels its repository-only setup reference"
else
    err "smartcard guide presents a repository-only setup reference as installed"
fi
for expected in \
    'publish_root_file "$SMARTCARD_DOC_CANDIDATE"' \
    '/usr/share/doc/noid-privacy/35-thunderbird-smartcard.md 0644' \
    'stat -Lc '\''%u:%g:%a:%h'\''' \
    '](35-thunderbird-smartcard.md)' \
    'PAGER=true /usr/local/bin/noid-help 35-thunderbird-smartcard'; do
    if grep -qF "$expected" \
            "$REPO_ROOT/kickstart/snippets/35-thunderbird.ks"; then
        ok "M35 smartcard deployment contains: $expected"
    else
        err "M35 smartcard deployment missing: $expected"
    fi
done
if grep -q 'mail\.openpgp\.load_untested_gpgme_version' \
    "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" \
    "$REPO_ROOT/thunderbird/mozilla.cfg"; then
    err "Thunderbird prefs contain stale load_untested_gpgme_version override"
else
    ok "Thunderbird prefs leave GPGME filename-suffix escape hatch unset"
fi
if grep -qE 'delegates OpenPGP operations|Encrypt.*card.s encryption subkey|Paste the \*\*fingerprint' \
    "$REPO_ROOT/docs/35-thunderbird-smartcard.md"; then
    err "smartcard guide overstates external-GnuPG operation coverage"
else
    ok "smartcard guide preserves Thunderbird/RNP versus GnuPG boundary"
fi

# 15. DKIM Verifier v6 uses WebExtension storage. Gecko prefs with the old
# extension prefix are inert and must not reappear. Its default resolver must
# remain provider-neutral instead of bypassing active OS/VPN DNS with policy.
if grep -q '^[[:space:]]*\(defaultPref\|user_pref\)("extensions\.dkim_verifier\.' \
    "$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js" \
    "$REPO_ROOT/thunderbird/mozilla.cfg"; then
    err "inert DKIM-Verifier Gecko preferences found"
else
    ok "DKIM Verifier configuration uses WebExtension storage boundary"
fi
if grep -qF '"SearchEngines": {' "$TB_KS" && \
   grep -qF '"Default": "DuckDuckGo"' "$TB_KS" && \
   ! grep -qF '"dns.resolver": 3' "$TB_KS" && \
   ! grep -qF '"dns.doh.server": "https://dns.quad9.net/dns-query"' "$TB_KS"; then
    ok "M35 policy keeps DuckDuckGo without forcing DKIM DNS around the OS/VPN resolver"
else
    err "M35 policy is missing DuckDuckGo or still forces DKIM DNS"
fi

# 16. CI must re-fetch and byte-verify the exact reviewed DKIM seed from the
# same official release channel used by M35.
CI_WORKFLOW="$REPO_ROOT/.github/workflows/ci.yml"
for expected in \
    'DKIM_VERSION=$(grep -oE '\''DKIM_VERIFIER_VERSION="[0-9.]+"'\''' \
    'DKIM_SHA=$(grep -oE '\''DKIM_VERIFIER_SHA256="[a-f0-9]+"'\''' \
    'Verify pinned DKIM Verifier XPI bytes' \
    'https://github.com/lieser/dkim_verifier/releases/download/v$DKIM_VERSION/dkim_verifier-$DKIM_VERSION.xpi' \
    'printf '\''%s  %s\n'\'' "$DKIM_SHA" "$tmp/dkim-verifier.xpi" | sha256sum -c -'; do
    if grep -qF "$expected" "$CI_WORKFLOW"; then
        ok "CI DKIM byte-verification contract contains: $expected"
    else
        err "CI DKIM byte-verification contract missing: $expected"
    fi
done

# ---------------------------------------------------------------------------
# Remote Settings is NOT a content-signature boundary in Thunderbird.
# Thunderbird ships REMOTE_SETTINGS_VERIFY_SIGNATURE=false, and
# RemoteSettingsClient copies that constant into this.verifySignature, which
# gates every signature check it performs. A source comment promising a signed
# blocklist, signed Remote Settings or a signed CRLite refresh invites a
# reviewer to trust a boundary that does not exist, so the claim is banned and
# the real contract must be recorded next to it.
# ---------------------------------------------------------------------------
for f in thunderbird/noid-thunderbird-hardening.js \
         thunderbird/mozilla.cfg \
         kickstart/snippets/35-thunderbird.ks; do
    if python3 - "$REPO_ROOT/$f" <<'PY'
import re
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    words = re.findall(r"[A-Za-z]+(?:-[A-Za-z]+)*", source.read().lower())
normalized = " ".join(words)
claims = (
    "signed remote settings",
    "signed blocklist",
    "signed add-on blocklist",
    "signed security-state",
    "signed dumps",
    "signed crlite",
)
raise SystemExit(1 if any(claim in normalized for claim in claims) else 0)
PY
    then
        ok "$f makes no unearned Remote Settings signature claim"
    else
        err "$f claims a Remote Settings content-signature boundary Thunderbird does not enforce"
    fi
done

for f in thunderbird/noid-thunderbird-hardening.js \
         thunderbird/mozilla.cfg \
         kickstart/snippets/35-thunderbird.ks; do
    if grep -qF 'REMOTE_SETTINGS_VERIFY_SIGNATURE = false' "$REPO_ROOT/$f"; then
        ok "$f records the actual Thunderbird Remote Settings contract"
    else
        err "$f must state REMOTE_SETTINGS_VERIFY_SIGNATURE = false where it discusses Remote Settings"
    fi
done

# Cross-check the documented constant against an installed Thunderbird when one
# is readable. This is a guard, not evidence for the image: it fires when a
# future Thunderbird flips the constant, which is exactly the moment the
# comments above stop being true and must be revisited.
TB_OMNI=/usr/lib64/thunderbird/omni.ja
if [ -r "$TB_OMNI" ] && command -v unzip >/dev/null 2>&1; then
    tb_tmp=$(mktemp -d)
    if unzip -o -q "$TB_OMNI" 'modules/AppConstants.sys.mjs' -d "$tb_tmp" 2>/dev/null; then
        tb_value=$(grep -A6 'REMOTE_SETTINGS_VERIFY_SIGNATURE:' \
            "$tb_tmp/modules/AppConstants.sys.mjs" \
            | grep -oE '^[[:space:]]*(true|false),' | head -1 | tr -d '[:space:],')
        case "$tb_value" in
            false)
                ok "installed Thunderbird confirms REMOTE_SETTINGS_VERIFY_SIGNATURE=false"
                ;;
            true)
                err "installed Thunderbird now verifies Remote Settings signatures — revisit the CRLite/blocklist comments"
                ;;
            *)
                err "could not read REMOTE_SETTINGS_VERIFY_SIGNATURE from $TB_OMNI"
                ;;
        esac
    else
        err "could not extract AppConstants.sys.mjs from $TB_OMNI"
    fi
    rm -rf "$tb_tmp"
else
    log "  [SKIP] M35: no readable installed Thunderbird omni.ja; signature contract checked structurally only"
fi

if [ "$FAIL" -eq 0 ]; then
    log "=== ALL STRUCTURAL TESTS PASS ==="
    exit 0
else
    log "=== $FAIL STRUCTURAL TESTS FAILED ==="
    exit 1
fi

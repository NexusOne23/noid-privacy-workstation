# ============================================================================
# Module 33 — Operational Hygiene
# Status: LOCKED 2026-08-05 (v39) — document protected System.map RPM evidence and its native kmod contract.
#
# Ships (doc + CLI only, %packages empty):
#   - 33-oauth-audit-checklist.md           external-account access review
#   - 33-firefox-profile-isolation.md       profile-isolation guide
#   - 33-integrity-check-guide.md           noid-integrity-check usage guide
#   - /usr/local/bin/noid-integrity-check                    5-section hygiene CLI
#   - /usr/local/bin/noid-firefox-create-isolated-profile    isolated-profile CLI
#   - /etc/cron.allow + /etc/at.allow       root-only scheduler allowlists (Phase 6b)
#   - health stamp
#
# Threat-model inputs:
#   - OAuth 2.0 Security Best Current Practice (RFC 9700)
#   - Live RPM/systemd/cron/Flatpak evidence from the installed host
#   - Mozilla's profile data model. Profiles separate browser data; they are
#     not an OS sandbox and do not stop same-user malware from reading them.
# No control or verdict below depends on a vendor threat-report claim.
#
# Design invariants (tests/33 asserts these):
#   - User-invoked only. Zero timers, zero services, zero autostart.
#   - No network calls from any shipped script. Silent-Machine aligned.
#   - %packages stays empty (doc + CLI only).
#   - noid-help picks up new docs dynamically (M30 iterates the doc dir).
#
# Constraint notes (keep on future edits):
#   - uBO install is profile-local through the shared, postcondition-checked
#     install_ubo_profile_local helper.
#   - noid-integrity-check _section_rpm is root-gated: unprivileged RPM 6
#     verification reports protected paths as unreadable/missing, so it cannot
#     provide complete package-file evidence.
#   - Stamp `version=1` is the shared health-stamp format version, not this
#     module's content revision.
#
# Dependencies: none at build. Runtime: rpm, systemctl, flatpak and find
# (@workstation defaults or M26 deps); firefox (M26/M16). crontab is queried
# only when a user has separately installed Cronie, which is absent by default.
# ============================================================================

%packages --exclude-weakdeps
# No packages. Doc + CLI only.
%end

%post --log=/var/log/ks-33-operational-hygiene.log --erroronfail
set -euo pipefail

PHASE=""
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [M33] ${PHASE}: $*"; }
die() { log "FAIL: $*"; exit 1; }
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-33-operational-hygiene.ok"
STAMP_TMP=""
STAMP_PUBLICATION_ACTIVE=0
cleanup_m33_health_stamp() {
    local saved_rc=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [ -n "${STAMP_TMP:-}" ]; then
        rm -f -- "$STAMP_TMP" || true
    fi
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "FAIL: could not retire incomplete Module 33 health stamp"
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
    return "$saved_rc"
}
trap cleanup_m33_health_stamp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ensure_root_dir() {
    local path="$1" mode="$2" state
    case "$path" in
        /*) ;;
        *) die "managed directory is not absolute: $path" ;;
    esac
    if [ -L "$path" ] || { [ -e "$path" ] && [ ! -d "$path" ]; }; then
        die "unsafe managed directory: $path"
    fi
    if [ ! -e "$path" ]; then
        install -d -o root -g root -m "$mode" -- "$path" ||
            die "cannot create managed directory: $path"
    else
        chown root:root -- "$path" ||
            die "cannot set managed-directory owner: $path"
        chmod "$mode" -- "$path" ||
            die "cannot set managed-directory mode: $path"
    fi
    [ "$(readlink -f -- "$path" 2>/dev/null)" = "$path" ] ||
        die "managed-directory path contains a symlink: $path"
    state=$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null || echo "")
    [ "$state" = "0:0:$mode" ] ||
        die "managed-directory postcondition failed: $path ($state)"
    /usr/sbin/restorecon -F -- "$path" ||
        die "cannot label managed directory: $path"
    /usr/sbin/matchpathcon -V "$path" >/dev/null ||
        die "managed-directory label differs: $path"
    sync -- "$path" ||
        die "cannot sync managed directory: $path"
}

publish_root_file() {
    local tmp="$1" target="$2" mode="$3" parent parent_state parent_mode state
    case "$target" in
        /*) ;;
        *) die "payload target is not absolute: $target" ;;
    esac
    parent=$(dirname -- "$target")
    [ "$(dirname -- "$tmp")" = "$parent" ] ||
        die "temporary payload is not in target directory: $target"
    [ -d "$parent" ] && [ ! -L "$parent" ] ||
        die "unsafe payload parent: $parent"
    [ "$(readlink -f -- "$parent" 2>/dev/null)" = "$parent" ] ||
        die "payload parent path contains a symlink: $parent"
    parent_state=$(stat -Lc '%u:%g:%a' -- "$parent" 2>/dev/null || echo "")
    case "$parent_state" in
        0:0:*) parent_mode=${parent_state##*:} ;;
        *) die "payload parent is not root-owned: $parent ($parent_state)" ;;
    esac
    [[ "$parent_mode" =~ ^[0-7]{3,4}$ ]] ||
        die "payload parent has an invalid mode: $parent ($parent_mode)"
    (( (8#$parent_mode & 0022) == 0 )) ||
        die "payload parent is group/other-writable: $parent ($parent_mode)"
    [ -f "$tmp" ] && [ ! -L "$tmp" ] &&
        [ "$(stat -Lc '%h' -- "$tmp" 2>/dev/null)" = 1 ] ||
        die "unsafe temporary payload: $tmp"
    chown root:root -- "$tmp" || die "cannot set payload owner: $target"
    chmod "$mode" -- "$tmp" || die "cannot set payload mode: $target"
    sync -- "$tmp" || die "cannot sync staged payload: $target"
    mv -fT -- "$tmp" "$target" || die "cannot publish payload: $target"
    /usr/sbin/restorecon -F -- "$target" ||
        die "cannot label published payload: $target"
    /usr/sbin/matchpathcon -V "$target" >/dev/null ||
        die "published payload label differs: $target"
    sync -- "$target" || die "cannot sync published payload: $target"
    sync -- "$parent" || die "cannot sync payload directory: $parent"
    state=$(stat -Lc '%u:%g:%a:%h' -- "$target" 2>/dev/null || echo "")
    [ -f "$target" ] && [ ! -L "$target" ] &&
        [ "$state" = "0:0:$mode:1" ] ||
        die "payload postcondition failed: $target ($state)"
}

log "=== Module 33 Operational Hygiene start ==="

# M33_HEALTH_INVALIDATION_BEGIN
# This stamp covers all documents, CLIs and defensive scheduler policy below.
# Validate shared state without normalizing drift, then retire any earlier
# success before the first owned payload mutation.
PHASE="P0-health-invalidation"
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    die "$STAMP_DIR exists but is not a real directory"
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ]; then
    die "$STAMP_DIR metadata is not root:root 0755"
fi
if [ ! -x /usr/sbin/restorecon ] || [ ! -x /usr/sbin/matchpathcon ] \
   || ! /usr/sbin/restorecon -F -- "$STAMP_DIR" \
   || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "$STAMP_DIR SELinux context is not canonical"
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        die "health-stamp target is not a file or symlink: $STAMP"
    fi
    rm -f -- "$STAMP" \
        || die "cannot invalidate stale Module 33 health stamp"
    sync -- "$STAMP_DIR"
fi
log "  [OK] prior Module 33 health stamp is absent"
# M33_HEALTH_INVALIDATION_END

# ----------------------------------------------------------------------------
# Phase 1 — ensure doc + var directories
# ----------------------------------------------------------------------------
PHASE="P1-setup"
log "Creating directories"
ensure_root_dir /usr/share/doc/noid-privacy 755

# ----------------------------------------------------------------------------
# Phase 2 — Write 33-oauth-audit-checklist.md
# ----------------------------------------------------------------------------
PHASE="P2-oauth-doc"
log "Writing 33-oauth-audit-checklist.md"

# Shipped Markdown target: /usr/share/doc/noid-privacy/33-oauth-audit-checklist.md
OAUTH_TARGET=/usr/share/doc/noid-privacy/33-oauth-audit-checklist.md
OAUTH_TMP=$(mktemp /usr/share/doc/noid-privacy/.33-oauth-audit-checklist.XXXXXX) ||
    die "cannot create OAuth-document temporary file"
cat > "$OAUTH_TMP" <<'OAUTH_EOF'
# External Account Access Audit — OAuth, Apps, Tokens and Sessions

OAuth grants let an application act within scopes you approved. Access-token,
refresh-token and revocation behavior varies by provider. A valid bearer token
can authorize in-scope requests without a fresh MFA prompt, but it is inaccurate
to say that every grant is permanent, survives every password change or
"bypasses MFA". RFC 9700 permits providers to revoke refresh tokens after
security events such as logout or a password change and recommends expiry after
inactivity.

This checklist deliberately includes adjacent credentials that are **not
OAuth**: API keys, personal access tokens, SSH keys, app passwords, browser
sessions and linked devices. Review each in its own provider UI.

**Cadence**: monthly is a NoID Privacy recommendation, not a provider
requirement. Also review after a lost device, a suspected phishing event, an
account/security alert, a role or organization change, or unexpected API
activity.

---

## The checklist

Open providers by typing the known domain or using a saved bookmark; do not sign
in through an unsolicited message. Provider routes and labels change, so use
the named account-settings area if a direct route moves.

For every app, token, key, session or linked device ask:

1. **Do I recognize and still need it?** If not, revoke it.
2. **Are its scopes and resources minimal?** Check mail, files, messages,
   repositories, organizations and administrative permissions separately.
3. **Is its lifetime appropriate?** Prefer the shortest practical expiry for
   manually managed tokens. Do not replace short-lived, provider-rotated tokens
   with long-lived static credentials.
4. **Does the provider show recent use, source or owner information?** An
   unexpected value is incident evidence; record it before revoking.
5. **What will revocation break?** Confirm the dependency, then revoke. A
   legitimate application can usually be authorized again if needed.

---

### Google / Workspace

**Connections**: https://myaccount.google.com/connections

**What to look for**:
- Third-party access to Gmail, Drive, Calendar, Photos or Contacts
- "Sign in with Google" connections you no longer use
- Any ability to edit, upload, create or delete data that the app does not need

Google's connection page shows more than OAuth data access, so review every
connection type it presents.

---

### GitHub

**OAuth apps**: https://github.com/settings/applications
**Authorized GitHub Apps**: https://github.com/settings/applications (same URL, tab)
**Personal access tokens**: https://github.com/settings/tokens
**SSH + deploy keys**: https://github.com/settings/keys

**What to look for**:
- Classic OAuth/PAT `repo` access when repository-specific access would suffice
- Fine-grained tokens covering more repositories or permissions than required
- Tokens without a practical expiration
- SSH/deploy keys and GitHub Apps for retired devices, CI jobs or repositories

GitHub recommends setting an expiration on personal access tokens and revokes
some unused or exposed tokens automatically. That does not replace review.

---

### Proton (sessions; not an OAuth-grant page)

**Account**: https://account.proton.me/

Navigate to Settings → All settings → Security and privacy → Session
management.

**What to look for**:
- Sessions that do not match a current browser or device
- App passwords or client credentials for retired mail clients

Revoke an unexpected session. Preserve the provider's displayed evidence first
if compromise is suspected.

---

### Microsoft personal and work/school accounts

**Work/school app portal**: https://myapps.microsoft.com/
**Personal account**: https://account.microsoft.com/ → Privacy / app access

**What to look for**:
- Delegated access to mail, calendar, OneDrive, contacts or directory data
- Whether consent was granted by you or by an organization administrator

For work/school accounts, user-granted permissions can be revoked in My Apps;
administrator-granted access may require the organization administrator.

---

### Apple ID

**Account**: https://account.apple.com/account/manage → Sign-In and Security
→ Sign in with Apple

**What to look for**:
- "Sign in with Apple" apps you no longer use
- Whether an app still needs its relay address

Apple labels revocation "Stop Using Sign in with Apple". It can require a new
account/login flow the next time the app is used.

---

### Dropbox

**URL**: https://www.dropbox.com/account/connected_apps

**What to look for**:
- Third-party apps with full-Dropbox-access scope
- Old mobile apps / backup tools

---

### Discord

**User Settings**: Authorized Apps
**Developer applications you own**: https://discord.com/developers/applications

**What to look for**:
- Authorized applications you no longer use
- Bots and integrations installed in servers you administer

---

### Signal

**Location**: Signal mobile app → Settings → Linked devices (no web
dashboard)

**What to look for**:
- Linked desktop devices (laptops, desktops) — should match exactly
  what you use

---

### Anthropic (Claude)

**API keys**: https://platform.claude.com/settings/keys
**Claude app**: https://claude.ai/settings/account

**What to look for**:
- API keys you generated for experiments and forgot to delete
- Organization invitations to orgs you don't recognize

---

### OpenAI

**Organization API keys**:
https://platform.openai.com/settings/organization/api-keys

Also open each active project's settings and review its project-scoped keys,
service accounts, members and roles.

**What to look for**:
- Unused organization or project API keys
- Projects, service accounts, members and organization memberships you no
  longer need
- Broad roles where a narrower project role is sufficient

Treat every API key as a secret. For unattended workloads that support it,
prefer OpenAI's short-lived workload-identity tokens over a long-lived static
key; do not expose either credential in browser or other client-side code.

---

### Slack

Open the workspace's Apps / Manage apps page. Availability depends on your
workspace role.

**What to look for**:
- Installed apps you don't use (incident trackers, note-takers)
- Apps that can read channel history, files or direct messages beyond their
  actual purpose

---

### LinkedIn

**URL**: https://www.linkedin.com/psettings/permitted-services

**What to look for**:
- Services you no longer use
- Publishing, recruiting or profile-sync access that exceeds the service's
  current purpose

---

### Atlassian (Jira / Confluence / Bitbucket)

**URL**: https://id.atlassian.com/manage-profile/apps

**What to look for**:
- Connected apps and API tokens you no longer need
- Access covering more sites or products than the integration currently uses

---

### VPN providers

Do not assume the provider uses OAuth. If its account page exposes device
slots, API tokens, sessions or WireGuard keys, review those exact objects.
Mullvad's device list is available from https://mullvad.net/en/account.

---

### Developer services

If you use these:

- **GitLab**: https://gitlab.com/-/profile/applications → Authorized apps
- **npm**: https://www.npmjs.com/settings/USERNAME/tokens
- **Cloudflare**: https://dash.cloudflare.com/profile/api-tokens

Prefer resource-scoped, expiring tokens. Review CI/CD secrets at the same time:
revoking a provider token without removing its stale secret from a runner leaves
confusing dead credentials behind.

---

## After the review

1. Record the provider, object, time and reason for each change without copying
   token values or other secrets into the log.
2. Test the workflows that should remain functional.
3. If anything was unexpected, review provider security/activity logs and
   preserve relevant evidence before changing more state.
4. Set the next reminder if a monthly cadence fits your use.

## Integration with `noid-integrity-check`

Run `noid-integrity-check oauth` — this prints a short provider summary and
references this document. It performs no network access and cannot inspect
remote accounts.

## False-positive patterns

- **Desktop apps that use OAuth for login**: mail and calendar clients may need
  an authorization while in use.
- **CI/CD integrations**: GitHub Apps installed on your repos (e.g.
  Dependabot or CodeQL) can be legitimate. Verify ownership and permissions.
- **Browser-extension OAuth**: some extensions request OAuth for sync.
  Continued use alone does not prove its current scopes are minimal.
- **Sessions and app passwords**: these are not OAuth grants even though they
  belong in the same human review.

## References

- OAuth 2.0 Security Best Current Practice — RFC 9700 (BCP 240):
  https://www.rfc-editor.org/rfc/rfc9700.html
- Google Account Help — third-party connections:
  https://support.google.com/accounts/answer/14012355
- GitHub Docs — token expiration and revocation:
  https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation
- Microsoft Support — edit or revoke application permissions in My Apps:
  https://support.microsoft.com/en-US/accounts-billing/work-school/edit-or-revoke-application-permissions-in-the-my-apps-portal
- Proton Support — logging out of sessions:
  https://proton.me/support/log-out-all-other-sessions
- Apple Support — manage Sign in with Apple:
  https://support.apple.com/102571
- OpenAI API authentication — API keys and short-lived workload identity:
  https://developers.openai.com/api/reference/overview#authentication
OAUTH_EOF

publish_root_file "$OAUTH_TMP" "$OAUTH_TARGET" 644
log "  [OK] 33-oauth-audit-checklist.md written"

# ----------------------------------------------------------------------------
# Phase 3 — Write 33-firefox-profile-isolation.md
# ----------------------------------------------------------------------------
PHASE="P3-ffprofile-doc"
log "Writing 33-firefox-profile-isolation.md"

# Shipped Markdown target: /usr/share/doc/noid-privacy/33-firefox-profile-isolation.md
FFPROFILE_TARGET=/usr/share/doc/noid-privacy/33-firefox-profile-isolation.md
FFPROFILE_TMP=$(mktemp /usr/share/doc/noid-privacy/.33-firefox-profile-isolation.XXXXXX) ||
    die "cannot create Firefox-profile-document temporary file"
cat > "$FFPROFILE_TMP" <<'FFPROFILE_EOF'
# Firefox Profile Isolation

Firefox profiles keep bookmarks, passwords, settings, extensions, history and
site data in separate profile directories. That is useful for avoiding
accidental account mixing, keeping unrelated browsing histories apart and
applying a dedicated workflow to high-value accounts.

## Security boundary — read this first

A separate profile is **browser-data separation, not an OS sandbox**. Every
profile belongs to the same Linux user. Malware or another process that gains
that user's filesystem access can attempt to read every user-readable profile.
Profile separation therefore does not replace:

- timely Firefox and extension updates
- SELinux, application sandboxing and least privilege
- phishing-resistant authentication where the provider supports it
- session revocation after suspected cookie/token theft
- signing out of high-value accounts when persistent sessions are unnecessary

A stolen, still-valid session cookie may let an attacker reuse that session
without a new MFA challenge, depending on the provider's session controls. It
does not follow that every cookie is decryptable, reusable or equivalent to
complete account access.

Firefox Multi-Account Containers separates selected cookies, logins and site
data inside one profile. Separate profiles additionally separate bookmarks,
passwords, settings, extensions and history. Neither mechanism protects all
profile files from a process already running as the same OS user.

## Quick start

```bash
# Close Firefox, then create a persistent profile:
noid-firefox-create-isolated-profile banking

# Launch it as a new Firefox instance:
firefox -P banking --new-instance

# List registered profiles:
noid-firefox-create-isolated-profile --list
```

The helper creates and registers the profile through Firefox, then applies the
shared NoID Privacy profile contract:

- the canonical NoID Privacy `user.js` composition
- system/VPN DNS by default, FPP/TCP and the other M16 privacy controls
- the exact validated uBlock Origin XPI, installed profile-local
- uBlock Origin private-window permission and managed filter-list seed
- an empty initial bookmark backup and maximized initial window state

The new profile keeps these Firefox-managed data sets separate from the default
profile:

- Cookies / session storage / IndexedDB
- Saved logins / passwords
- Browsing history / download history
- Bookmarks / pinned tabs
- Extensions added manually
- Themes / customizations

Data can be combined again if you deliberately connect profiles to the same
Mozilla Sync account and enable synchronization. Review Sync separately for
each profile.

## Choosing profile boundaries

Use as few profiles as you can operate consistently. More profiles add
maintenance and memory cost; they are useful when the data or account context
really differs.

| Profile | Use | Rationale |
|---------|-----|-----------|
| `default-release` | ordinary signed-in browsing | Canonical M16 profile and default external-link target. |
| `banking` | a small set of financial sites | Reduces accidental navigation and account-context mixing. |
| `work` | employer identity and work SaaS | Keeps work history, extensions and logins apart from personal use. |
| `shopping` | commerce accounts | Keeps persistent commerce state out of other browsing contexts. |
| `research` | persistent investigative setup | Separate extensions and history; still not a malware boundary. |
| `playground` | disposable/private untrusted browsing | Use the M34 amnesic workflow rather than creating another persistent profile. |

Do not create a dedicated profile and then use it for unrelated browsing; that
removes most of the operational benefit.

## Profile manager UI

```bash
# Close Firefox first, then open the upstream manager:
firefox -P
```

Use the upstream manager to inspect or remove a profile. Before deletion,
confirm the exact profile name and decide whether Firefox should retain or
delete its files. Do not remove a directory and hand-edit `profiles.ini`; that
can leave stale registrations or delete the wrong data.

## Application launchers

Pinning a running window can pin the generic Firefox launcher rather than its
profile arguments. For a persistent Dash item, create a dedicated desktop entry
whose command is `firefox -P banking --new-instance`, launch that entry from
Activities, and then pin that application entry. Profile names accepted by the
NoID Privacy helper contain only letters, digits, `_` and `-`.

## Operating each profile

### Banking profile hygiene

- Use a saved, verified origin rather than a link from an unsolicited message.
- Sign out after use when the provider and workflow make that practical.
- Keep unrelated email, search and general browsing out of the profile.
- Use `firefox -P banking --safe-mode --new-instance` only for
  troubleshooting. Safe Mode disables extensions and themes; it is not a
  stronger browsing-security mode.

### Research profile hygiene

- A private window limits persistence after close but does not anonymize
  traffic, hide it from the network or create an OS security boundary.
- Use the M34 Playground for disposable browsing. Use a persistent research
  profile only when its separate extensions, bookmarks or history are useful.
- Close every window for the profile when its private-browsing session should
  end.

## Interaction with NoID Privacy Firefox Hardening updates

The supported Update workflow discovers registered profiles through the shared
`list_registered_profiles` helper. It reconciles profiles already recognized
as NoID Privacy-managed, including those created by this CLI, while preserving the
reviewed DRM/FPP/WebRTC compatibility opt-ins. Arbitrary user-created profiles
are not silently claimed or overwritten.

## Caveats

### Instance selection

Firefox resolves a registered `-P <name>` through its profile registry under
the configured XDG profile root. `--new-instance` is Firefox's current
documented option for starting a new instance instead of opening a window in
an existing one. Keep it in dedicated launcher commands.

### Extensions

Extensions added manually to one profile do not carry over. Minimize extension
count and review permissions in every profile where an extension is installed.
The NoID Privacy helper installs only the exact validated uBlock Origin payload required
by the shared hardening contract.

### Keychain / keyring

Firefox-saved passwords are profile data. A system password manager can serve
multiple profiles, but its browser extension and permissions remain
profile-specific. Do not enable Sync merely to copy an extension or password
unless cross-profile synchronization is intended.

### Updates

Profile separation does not compensate for an outdated browser. Use the
user-operated NoID Privacy Update workflow and verify the installed Firefox build after
an update. Do not freeze a profile on an old Firefox version.

## References

- Mozilla Support — Manage Firefox profiles:
  https://support.mozilla.org/en-US/kb/profile-management
- Mozilla Support — Where Firefox stores user data:
  https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data
- Mozilla Support — original Profile Manager:
  https://support.mozilla.org/en-US/kb/profile-manager-create-remove-switch-firefox-profiles
- Module 16 (NoID Privacy Firefox Hardening) source:
  /usr/share/noid-firefox/user.js

FFPROFILE_EOF

publish_root_file "$FFPROFILE_TMP" "$FFPROFILE_TARGET" 644
log "  [OK] 33-firefox-profile-isolation.md written"

# ----------------------------------------------------------------------------
# Phase 4 — Write 33-integrity-check-guide.md
# ----------------------------------------------------------------------------
PHASE="P4-icguide-doc"
log "Writing 33-integrity-check-guide.md"

# Shipped Markdown target: /usr/share/doc/noid-privacy/33-integrity-check-guide.md
ICGUIDE_TARGET=/usr/share/doc/noid-privacy/33-integrity-check-guide.md
ICGUIDE_TMP=$(mktemp /usr/share/doc/noid-privacy/.33-integrity-check-guide.XXXXXX) ||
    die "cannot create integrity-guide temporary file"
cat > "$ICGUIDE_TMP" <<'ICGUIDE_EOF'
# noid-integrity-check — On-Demand Operational Hygiene Scan

**What**: A single CLI that consolidates five hygiene checks into one
readable output. Runs on-demand (not as a timer). Complements the
auditd evidence from Module 12 and, only after the user accepts a baseline,
Module 13 AIDE checks.

**Why**: package verification, scheduled-execution inventories, Flatpak
history and external-account access are different evidence sources. This tool
puts their current state in one human-readable, local-only report without
adding a timer, service, network request or new trust database.

This is a diagnostic snapshot, not compromise detection and not an integrity
attestation. A clean-looking report cannot prove that the machine is clean.

## Quick start

```bash
noid-integrity-check           # default scan (5 sections)
noid-integrity-check --all     # + SUID + enabled services
noid-integrity-check --brief   # summary only (default or selected sections)
noid-integrity-check --help    # full usage

# Run a specific section:
noid-integrity-check --section rpm
noid-integrity-check --section "timers cron"
```

## Sections

### `rpm` — RPM package file integrity

Runs `rpm -Va --nodeps`, validates RPM's structured package-file output, counts
the complete stream and prints its first 20 drift records without suppressing
any file-record category. Dependency verification is deliberately excluded
from this file-integrity section so dependency diagnostics cannot be mislabeled
as malformed file records; review package-manager dependency health separately.
Config-file drift below `/etc` or `/var` and NoID Privacy configuration drift
therefore remain classified as drift; neither familiarity nor a local
reconstruction record makes package divergence disappear. Run `rpm -Va --nodeps`
directly when the report says that more records exist. Browser launcher
customizations use owned `/usr/local` overlays, not RPM-file rewrites.

This section is root-only. RPM 6 can read much of the database as a normal
user, but protected files then appear unreadable or missing, so the evidence is
not complete enough for this report.

**Possible causes**:
- You or another admin manually edited the file (legitimate, but worth
  remembering)
- A tool (e.g. `update-alternatives`) swapped a file by design
- The file was tampered with

**What to do**:
- Compare diff: `rpm -V <package>` shows which files + which attributes
  changed (S=size, 5=digest, T=mtime, M=mode, U=owner, G=group, L=symlink,
  D=device, P=capability)
- Attribute first: `rpm -qf -- /path/from/the/report`
- Investigate relevant audit events: `sudo ausearch -f /path/from/the/report -i`
- After understanding the cause, use `sudo dnf reinstall <package>` when a
  Fedora package restore is actually required. Report the expected AIDE drift;
  never rebaseline merely to silence it.

### `timers` — systemd timers

Lists every installed system timer unit file, including enabled, disabled,
static and masked states, and labels each by source:

| Label | Meaning |
|-------|---------|
| `NoID Privacy` | Exact known NoID Privacy timer name at its expected root-owned `/etc/systemd/system/` path |
| `NoID Privacy mask` | Exact known NoID Privacy-suppressed vendor timer at its root-owned `/etc/systemd/system/` symlink to `/dev/null` |
| `vendor` | Fedora-packaged vendor default (e.g. `fstrim.timer`) |
| `admin` | User/admin/runtime-installed under `/etc`, `/run` or `/usr/local/lib/systemd/` |
| `admin override` | A timer with one or more local or runtime `.timer.d` drop-ins under `/etc`, `/run` or `/usr/local` |
| `generator output` | Runtime `.timer.d` output from a systemd generator under `/run/systemd/generator*` |
| `vendor override` | A known NoID Privacy timer changed by a package-owned `/usr/lib` drop-in |
| `unknown` | Could not determine source — investigate |

Package-owned `/usr/lib/systemd/system/*.d` drop-ins remain `vendor` when their
main fragment is also vendor-owned; a drop-in is not automatically a local
override. The label describes origin, not file integrity. RPM/AIDE/audit
evidence remains separate. User-manager timers are outside this system-manager
inventory.
For an installed template such as `name@.timer`, the CLI asks systemd for an
inert synthetic instance so its FragmentPath and drop-ins resolve without
starting or enabling anything.

**What to do for `unknown` / `admin` / `admin override` unexpected timers**:
- `systemctl cat <timer-name>.timer` — see the unit definition
- `systemctl list-timers <timer-name>` — when it runs
- `systemctl status <timer-name>` — last run + status
- Inspect ownership and dependencies before changing state. If it is confirmed
  unwanted, disable it explicitly; do not disable an unfamiliar unit merely
  because this source classifier cannot identify it.

### `cron` — cron entries

Scans:
- `/etc/crontab` and `/etc/anacrontab` when present
- regular files and symlinks in `/etc/cron.d/*` + `/etc/cron.daily/*` +
  `.hourly` + `.weekly` + `.monthly`
- Current user's crontab (`crontab -l`) when Cronie has been installed
  separately. Cronie is not installed by default on NoID Privacy.

Lists each entry + the RPM package that owns it (or `<unowned>`).

**Unowned** cron entries are not necessarily suspicious — manually installed
scripts under `/etc/cron.*` don't belong to any RPM. But every such entry
should be accounted for. Active user-crontab lines, unowned system entries and
symlinked system sources contribute a yellow review item to the summary. A
valid symlink is supported by Cronie, but its printed target is a separate
pathname trust boundary that must be reviewed.

**What to do**:
- Inspect the owning package and file contents.
- For a package-owned entry, change it through the package's supported
  configuration.
- For a manually managed entry, archive its content and remove or edit it only
  after confirming the exact target and owner.
- If Cronie was installed separately, edit the current user's crontab with
  `crontab -e`.

### `flatpak` — Flatpak history

Queries `flatpak history --system --since=30days` and, when the current
account already has a user repository, the matching `--user` history. It never
initializes a user repository merely to audit it. Both scopes are labelled in
the output.

Shows recorded app/repository changes in the last 30 days, including installs,
updates, removals, pulls and remote changes when Flatpak records them. Any
displayed event is a yellow review item. A failed history query is red because
the evidence is unknown; absence of events is green only when every requested
history query succeeded.

**What to do**:
- Legitimate update? Good.
- Install you don't remember? Run `flatpak info <app>` for metadata;
  `flatpak permission-show <app>` for permissions.
- Remove you don't remember? Possibly another admin, possibly a flatpak
  issue. Preserve the displayed history row, then inspect the installation
  metadata and relevant system/user journal evidence for that time.

### `oauth` — external-account access review reminder

Prints a short set of provider account-access URLs and a pointer to the full
checklist at
`/usr/share/doc/noid-privacy/33-oauth-audit-checklist.md`.

This is a yellow *manual action*, not an automated scan. Remote grants, keys,
sessions and linked devices are visible only after the user signs in to each
provider. The CLI performs no network request.

## Optional sections (with `--all` or `--section`)

### `suid` — SUID + SGID binaries

Scans each relevant local filesystem tree (`/`, `/home`, `/var`, `/var/tmp`,
`/tmp`, `/dev/shm`, `/boot`, `/boot/efi`) with `find -xdev` and lists every
regular file carrying a setuid or setgid bit. Scanning each candidate
separately is load-bearing:
NoID Privacy mounts several of these paths independently, so one `find / -xdev`
would silently skip them.

NoID Privacy M10 uses a declarative systemd-tmpfiles policy, reapplied at boot,
by package-scoped dnf5 actions and by the supported post-DNF update
reconciliation. It removes SUID from `chfn`, `chsh`, `gpasswd`, `newgrp` and
`fusermount-glusterfs`; account/group changes use sudo plus a new login, and
unprivileged Gluster FUSE mounts are not a base-image workflow. It deliberately retains Fedora's SUID modes for `chage`,
`pam_timestamp_check`, `userhelper` and `libgtop_server2`, because those back
the self expiry query, consolehelper and GNOME process inspection. These local
mode differences remain visible to RPM verification. AIDE reports only later
drift from a user-accepted baseline, if that baseline has been activated.

The exact set on YOUR system depends on what is installed. This guide
deliberately does not carry a static allowlist: optional hardware, virtualization,
desktop and compatibility packages add legitimate paths, while a fixed list
silently becomes incomplete as Fedora packages change. Attribute every reported
path to the live package set instead:

```
path=/path/from/the/report
rpm -qf -- "$path"
rpm -V "$(rpm -qf --qf '%{NAME}\n' -- "$path")"
```

An unowned path, an unexpected owner package or unexplained verification drift
needs investigation. M10's documented mode changes remain expected RPM
verification evidence; do not absorb any other result into an expected list
merely because the binary name looks familiar.

### `services` — enabled systemd unit files

Lists every system unit file in persistent `enabled` or transient
`enabled-runtime` state and prints the reported state. This is an inventory,
not source or integrity classification. Verbose output — only needed when
auditing after a suspected compromise.

## Running as root vs user

Without sudo:
- the RPM section is skipped because protected paths make its evidence
  incomplete
- M10's mode-0700 policy protects the five `/etc/cron.*` directories; their
  system-entry walk is reported as one expected yellow incomplete-evidence item
- when Cronie was installed separately, `crontab -l` shows the CURRENT user's
  crontab only
- `flatpak history` shows system scope plus the CURRENT user's existing scope
- the system timer-unit inventory works
- The SUID scan cannot read every selected local tree

With sudo:
- Full `rpm -Va --nodeps` package-file output
- the protected system cron directories, plus root's crontab rather than the
  invoking desktop user's crontab when Cronie was installed separately
- Flatpak history covers system scope plus root's user scope, not the invoking
  desktop user's repository; run the Flatpak section once without sudo for that
- All selected local filesystem trees readable for the SUID scan

Recommendation: run both modes. A plain `noid-integrity-check` as user
for user Flatpak/crontab evidence, then `sudo noid-integrity-check --all` for
complete RPM and filesystem evidence. Cadence is the user's choice; the tool
does not schedule itself.

## False positives you will see

- **First run after install**: `rpm -Va` shows many `.M.......` mode
  and content records for deliberate image policy. They remain evidence:
  attribute each record to its owning module or package and keep unexplained
  drift open. Do not baseline it away in your head or hide it in an allowlist.
- **Protected kernel symbol maps**: M01 retains both package-native
  `/boot/System.map-<version>` and
  `/usr/lib/modules/<version>/System.map`, but changes them from the RPM's 0644
  to root-only 0600. `rpm -Va` therefore reports an intentional mode difference
  on those exact `kernel-core` paths. Their presence is required by the native
  target-kernel kmod/depmod transaction; investigate a missing file, content
  difference or any other kernel-file record normally.
- **Vendor timers**: `fstrim.timer` and `systemd-tmpfiles-clean.timer` are
  ordinary Fedora/systemd units. The M08 DNF/plocate and M24 fwupd refresh
  timers appear as `NoID Privacy mask` only when their exact expected
  root-owned symlink still points directly to `/dev/null`; every changed target,
  unexpected mask name or override remains visible for review. The inventory
  therefore shows the actual state instead of assuming a vendor default is
  active.
- **Snapper cleanup override**: M20 intentionally ships
  `/etc/systemd/system/snapper-cleanup.timer.d/99-noid-frequency.conf` on the
  vendor timer. It therefore appears as one `admin override` yellow on a stock
  image; verify that exact drop-in and investigate any additional override.
- **Non-root cron inventory**: M10 protects all five `/etc/cron.*` directories
  with mode 0700. A user run therefore reports one consolidated yellow for
  incomplete system-cron evidence; the sudo run supplies that evidence.
- **User-created Flatpaks during setup**: intentionally installed apps appear
  under the labelled system or current-user scope.
- **Package-owned SUID/SGID files**: presence alone is not a verdict. Attribute
  each live path to its package and verify that package before deciding it is
  expected.

## Interpretation — green light vs escalation

> **Reading-order note**: review the **False
> positives** section *above* before applying this interpretation table. On
> first-install runs you may see deliberate `.M.......` or content drift from
> `rpm -Va`. Those records are yellow evidence, not green: explain each against
> the owning NoID Privacy module and investigate every unowned or unexpected
> record. A known path never becomes invisible merely because it looks familiar.

| Output | Action |
|--------|--------|
| No red/yellow automated findings | Review the printed evidence and manual actions; this is not an integrity all-clear. |
| One yellow (NOTICE) | Investigate the specific item. Usually explainable. |
| One red | Evidence collection or source classification failed. Preserve output and investigate with auditd and, if activated, the existing AIDE evidence. |
| Multiple red | Treat as an incident until explained. Avoid changing trust state; preserve evidence before repair or recovery decisions. |

Exit 0 means the requested evidence sources completed without an automated red
collection/source-classification failure; yellow review items can coexist with
exit 0. Exit 1 means at least one red failure, and exit 2 is a usage error.
No exit status is an integrity attestation: automation must still retain and
review the printed summary and evidence.

## Module 33 health stamp

This CLI is shipped by Module 33 "Operational Hygiene". Its presence
is verified at image build time by the stamp file
`/var/lib/noid-privacy/stamp-33-operational-hygiene.ok`. If the stamp
is missing, treat Module 33 as incomplete: inspect its three documents, two
CLIs, two scheduler allow-files and the installation log. Do not create
replacement evidence merely to make the status green.

## References

- RPM 6 `rpm(8)` — verify output and exit status:
  https://rpm.org/docs/6.0.x/man/rpm.8
- systemd `systemctl(1)` — list-unit-files:
  https://www.freedesktop.org/software/systemd/man/latest/systemctl.html
- Cronie `cron(8)` — system/user sources and accepted symlinked crontabs:
  https://man7.org/linux/man-pages/man8/cron.8.html
- Flatpak command reference — history subcommand:
  https://docs.flatpak.org/en/latest/flatpak-command-reference.html
- GNU Findutils manual — mode-bit matching:
  https://www.gnu.org/software/findutils/manual/html_mono/find.html
ICGUIDE_EOF

publish_root_file "$ICGUIDE_TMP" "$ICGUIDE_TARGET" 644
log "  [OK] 33-integrity-check-guide.md written"

# ----------------------------------------------------------------------------
# Phase 5 — Install /usr/local/bin/noid-integrity-check
# ----------------------------------------------------------------------------
PHASE="P5-integrity-cli"
log "Writing /usr/local/bin/noid-integrity-check"

NIC_TARGET=/usr/local/bin/noid-integrity-check
NIC_TMP=$(mktemp /usr/local/bin/.noid-integrity-check.XXXXXX) ||
    die "cannot create integrity-CLI temporary file"
cat > "$NIC_TMP" <<'NIC_EOF'
#!/bin/bash
# noid-integrity-check — unified on-demand operational hygiene diagnostic
# Part of NoID Privacy Workstation, Module 33 Operational Hygiene.
# Full guide: /usr/share/doc/noid-privacy/33-integrity-check-guide.md

set -euo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Integrity" \
    NOID_FMT_AUTO_SUBTITLE="Read-only system spot-check" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

SCRIPT="$(basename "$0")"
DOC_GUIDE="/usr/share/doc/noid-privacy/33-integrity-check-guide.md"
DOC_OAUTH="/usr/share/doc/noid-privacy/33-oauth-audit-checklist.md"
DEFAULT_SECTIONS="rpm timers cron flatpak oauth"
EXTRA_SECTIONS="suid services"

usage() {
    cat <<USAGE_END
$SCRIPT — on-demand operational hygiene scan

USAGE
  $SCRIPT                      default scan: $DEFAULT_SECTIONS
  $SCRIPT --all                include optional: $EXTRA_SECTIONS
  $SCRIPT --section <name(s)>  run only the listed sections
  $SCRIPT --brief              summary output (default or selected sections)
  $SCRIPT --help               this message

SECTIONS
  rpm       rpm -Va --nodeps  package-file integrity (count + first 20 records)
  timers    systemctl   installed system timer-unit inventory + source labels
  cron      cron scan   system cron/anacron sources + user crontab
  flatpak   flatpak     last 30 days of app/repository history
  oauth     reminder    manual external-account review; link to $DOC_OAUTH
  suid      find        files carrying SUID/SGID bits (slow, --all only)
  services  systemctl   enabled/enabled-runtime unit files (verbose, --all only)

INTERPRETATION
  Green (OK)       evaluated check produced no review item
  Yellow (NOTICE)  manual review, skipped evidence or explainable finding
  Red (FAIL)       collection/source-classification failure; investigate

This is human-readable evidence, not an integrity attestation. See
$DOC_GUIDE for per-section detail and interpretation.
USAGE_END
}

# Colors (disabled on non-tty)
if [ -t 1 ]; then
    C_RED=$'\033[31m'
    C_YELLOW=$'\033[33m'
    C_GREEN=$'\033[32m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
else
    C_RED=""; C_YELLOW=""; C_GREEN=""; C_BOLD=""; C_RESET=""
fi

# Counters for summary
hits_red=0
hits_yellow=0
hits_green=0
declare -a noid_cleanup_dirs=()

cleanup_cli_tempdirs() {
    local saved_rc=$? path
    trap - EXIT
    trap '' HUP INT TERM
    for path in "${noid_cleanup_dirs[@]}"; do
        [ -n "$path" ] || continue
        if ! rm -rf -- "$path"; then
            printf '%s: cannot remove private audit workspace: %s\n' \
                "$SCRIPT" "$path" >&2
        fi
    done
    return "$saved_rc"
}

remove_cli_tempdir() {
    local target="$1" index
    if ! rm -rf -- "$target"; then
        return 1
    fi
    # Do not retain a successfully removed pathname in the EXIT list: a local
    # user must not be able to recreate that name in /var/tmp and have a later
    # cleanup remove someone else's replacement directory.
    for index in "${!noid_cleanup_dirs[@]}"; do
        if [ "${noid_cleanup_dirs[$index]}" = "$target" ]; then
            unset 'noid_cleanup_dirs[index]'
            break
        fi
    done
    return 0
}

trap cleanup_cli_tempdirs EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

_header() {
    printf '\n%b=== %s ===%b\n' "$C_BOLD" "$1" "$C_RESET"
}

_ok() {
    printf '  %bOK%b %s\n' "$C_GREEN" "$C_RESET" "$1"
    hits_green=$((hits_green + 1))
}

_notice() {
    printf '  %bNOTICE%b %s\n' "$C_YELLOW" "$C_RESET" "$1"
    hits_yellow=$((hits_yellow + 1))
}

_fail_line() {
    printf '  %bFAIL%b %s\n' "$C_RED" "$C_RESET" "$1"
    hits_red=$((hits_red + 1))
}

_skip() {
    printf '  %bSKIP%b %s\n' "$C_YELLOW" "$C_RESET" "$1"
    hits_yellow=$((hits_yellow + 1))
}

validate_rpm_verify_output() {
    # Accept only RPM's structured verification records. A non-empty malformed
    # stream is an execution/parser failure, not integrity drift. Paths may
    # contain spaces, so validation deliberately anchors only their leading /.
    awk '
        /^[[:space:]]*$/ { next }
        /^[.SM5DLUGTPE?]{9}[[:space:]]+([[:alpha:]?][[:space:]]+)?\// {
            valid=1; next
        }
        /^missing[[:space:]]+([[:alpha:]?][[:space:]]+)?\// {
            valid=1; next
        }
        { bad=1 }
        END { exit (bad || !valid) }
    '
}

_section_rpm() {
    _header "rpm -Va (package file integrity)"
    if ! command -v rpm >/dev/null 2>&1; then
        _skip "rpm not available"
        return
    fi
    # RPM 6 can read the database as a normal user, but protected paths then
    # appear unreadable or missing. Root-gate this evidence instead of turning
    # an incomplete run into hundreds of misleading drift records.
    if [ "$(id -u)" -ne 0 ]; then
        _skip "needs root to verify protected package paths — run: sudo ${SCRIPT} --all"
        return
    fi
    local rpm_tmp rpm_rc count
    if ! rpm_tmp=$(mktemp -d "${TMPDIR:-/var/tmp}/noid-rpm-verify.XXXXXX"); then
        _fail_line "cannot create a private rpm verification workspace"
        return
    fi
    noid_cleanup_dirs+=("$rpm_tmp")
    rpm_rc=0
    rpm -Va --nodeps >"$rpm_tmp/stdout" 2>"$rpm_tmp/stderr" || rpm_rc=$?

    if [ -s "$rpm_tmp/stderr" ]; then
        _fail_line "rpm -Va --nodeps wrote diagnostics; integrity state is unknown (rc=$rpm_rc)"
        sed -n '1,20{s/^/      /;p;}' "$rpm_tmp/stderr"
        remove_cli_tempdir "$rpm_tmp" || \
            _notice "cannot remove private rpm verification workspace: $rpm_tmp"
        return
    fi
    if [ -s "$rpm_tmp/stdout" ] && \
       ! validate_rpm_verify_output < "$rpm_tmp/stdout"; then
        _fail_line "rpm -Va --nodeps returned malformed output; integrity state is unknown (rc=$rpm_rc)"
        sed -n '1,20{s/^/      /;p;}' "$rpm_tmp/stdout"
        remove_cli_tempdir "$rpm_tmp" || \
            _notice "cannot remove private rpm verification workspace: $rpm_tmp"
        return
    fi
    if [ "$rpm_rc" -eq 1 ] && [ -s "$rpm_tmp/stdout" ]; then
        : # RPM 6 reports verified file drift with rc=1 and structured stdout.
    elif [ "$rpm_rc" -ne 0 ]; then
        _fail_line "rpm -Va --nodeps failed (rc=$rpm_rc); integrity state is unknown"
        sed -n '1,20{s/^/      /;p;}' "$rpm_tmp/stdout"
        remove_cli_tempdir "$rpm_tmp" || \
            _notice "cannot remove private rpm verification workspace: $rpm_tmp"
        return
    fi
    # Classify every structured drift record without a suppression oracle.
    # M16/M35 keep vendor payloads byte-pristine and derive owned /usr/local
    # overlays instead. Print a bounded preview and retain the full count.
    if [ ! -s "$rpm_tmp/stdout" ]; then
        _ok "no RPM package-file drift"
    else
        count=$(grep -c . "$rpm_tmp/stdout" || true)
        _notice "$count RPM package-file record(s) differ from the package baseline"
        sed -n '1,20{s/^/      /;p;}' "$rpm_tmp/stdout"
        if [ "$count" -gt 20 ]; then
            printf '      ... (run "rpm -Va --nodeps" for full list)\n'
        fi
    fi
    if ! remove_cli_tempdir "$rpm_tmp"; then
        _notice "cannot remove private rpm verification workspace: $rpm_tmp"
    fi
}

_known_noid_system_timer() {
    case "$1" in
        aide-check.timer|\
        btrfs-scrub.timer|\
        noid-audit-prune.timer|\
        noid-auditd-rotate.timer|\
        noid-dracut-hostonly-firstboot.timer|\
        noid-install-logs-prune.timer|\
        noid-lan-expiry-reconcile.timer|\
        noid-misc-logs-prune.timer|\
        noid-nm-privacy-prune.timer|\
        noid-nm-scope-physical-profiles.timer|\
        noid-snapper-prune.timer|\
        noid-wan-strict-endpoint-expiry.timer)
            return 0
            ;;
    esac
    return 1
}

_known_noid_masked_system_timer() {
    case "$1" in
        dnf-makecache.timer|\
        dnf5-makecache.timer|\
        fwupd-refresh.timer|\
        plocate-updatedb.timer)
            return 0
            ;;
    esac
    return 1
}

_noid_timer_mask_is_exact() {
    local unit="$1" path="$2" expected_state="${3:-0:0:1}"
    local target state
    _known_noid_masked_system_timer "$unit" || return 1
    [ -L "$path" ] || return 1
    target=$(readlink -- "$path" 2>/dev/null) || return 1
    [ "$target" = /dev/null ] || return 1
    state=$(stat -c '%u:%g:%h' -- "$path" 2>/dev/null) || return 1
    [ "$state" = "$expected_state" ]
}

_rpm_owns_path() {
    command -v rpm >/dev/null 2>&1 &&
        LC_ALL=C rpm -qf -- "$1" >/dev/null 2>&1
}

_section_timers() {
    _header "installed systemd timer unit files"
    if ! command -v systemctl >/dev/null 2>&1; then
        _skip "systemctl not available"
        return
    fi
    local listing timers total=0 noid_count=0 unknown_count=0 admin_count=0
    local noid_mask_count=0 vendor_override_count=0 generator_count=0
    local t inspect_t unit_state src_line dropins marker col expected_path metadata
    local src_rc dropins_rc dropin dropin_class
    if ! listing=$(LC_ALL=C systemctl list-unit-files --type=timer \
                   --no-pager --no-legend 2>/dev/null); then
        _fail_line "cannot enumerate installed system timer unit files"
        return
    fi
    timers=$(awk '$1 ~ /\.timer$/ { print $1 "\t" $2 }' <<< "$listing" | sort -u)
    if [ -z "$timers" ]; then
        _notice "no installed system timer unit files reported"
        return
    fi
    while IFS=$'\t' read -r t unit_state; do
        [ -z "$t" ] && continue
        total=$((total + 1))
        inspect_t=$t
        case "$t" in
            *@.timer) inspect_t=${t/@.timer/@noid-audit.timer} ;;
        esac
        src_rc=0
        dropins_rc=0
        src_line=$(systemctl show -p FragmentPath --value "$inspect_t" \
                   2>/dev/null) || src_rc=$?
        dropins=$(systemctl show -p DropInPaths --value "$inspect_t" \
                  2>/dev/null) || dropins_rc=$?
        dropin_class='none'
        for dropin in $dropins; do
            case "$dropin" in
                /usr/lib/systemd/system/*)
                    if _rpm_owns_path "$dropin"; then
                        [ "$dropin_class" = none ] && dropin_class='vendor'
                    else
                        dropin_class='unknown'
                        break
                    fi
                    ;;
                /etc/systemd/system/*|/run/systemd/system/*|\
                /usr/local/lib/systemd/system/*)
                    dropin_class='admin'
                    ;;
                /run/systemd/generator*/*)
                    dropin_class='generator'
                    ;;
                *)
                    dropin_class='unknown'
                    break
                    ;;
            esac
        done
        expected_path="/etc/systemd/system/$t"
        metadata=$(stat -Lc '%u:%g:%a:%h' -- "$expected_path" 2>/dev/null || echo "")
        if [ "$src_rc" -ne 0 ] || [ "$dropins_rc" -ne 0 ] || \
           [ -z "$src_line" ] || [ "$dropin_class" = unknown ]; then
            marker='unknown'
            col="$C_RED"
            unknown_count=$((unknown_count + 1))
        elif [ "$dropin_class" = generator ]; then
            marker='generator output'
            col="$C_YELLOW"
            generator_count=$((generator_count + 1))
        elif [ "$dropin_class" = admin ]; then
            # FragmentPath alone stays /usr/lib for a vendor timer when a
            # local/runtime drop-in changes it. Surface that override.
            marker='admin override'
            col="$C_YELLOW"
            admin_count=$((admin_count + 1))
        elif [ "$src_line" = "$expected_path" ] && \
             _noid_timer_mask_is_exact "$t" "$expected_path"; then
            if [ "$dropin_class" = vendor ]; then
                marker='vendor override'
                col="$C_YELLOW"
                vendor_override_count=$((vendor_override_count + 1))
            else
                marker='NoID Privacy mask'
                col="$C_GREEN"
                noid_mask_count=$((noid_mask_count + 1))
            fi
        elif _known_noid_system_timer "$t" && \
           [ "$src_line" = "$expected_path" ] && \
           [ -f "$expected_path" ] && [ ! -L "$expected_path" ] && \
           [ "$metadata" = "0:0:644:1" ]; then
            if [ "$dropin_class" = vendor ]; then
                marker='vendor override'
                col="$C_YELLOW"
                vendor_override_count=$((vendor_override_count + 1))
            else
                marker='NoID Privacy'
                col="$C_GREEN"
                noid_count=$((noid_count + 1))
            fi
        elif [[ "$src_line" == /usr/lib/systemd/* ]] && \
             _rpm_owns_path "$src_line"; then
            # Package-owned /usr/lib drop-ins do not turn a package-owned
            # fragment into an administrator override.
            marker='vendor'
            col="$C_GREEN"
        elif [[ "$src_line" == /etc/systemd/* ]] || \
             [[ "$src_line" == /run/systemd/* ]] || \
             [[ "$src_line" == /usr/local/lib/systemd/* ]]; then
            marker='admin'
            col="$C_YELLOW"
            admin_count=$((admin_count + 1))
        else
            marker='unknown'
            col="$C_RED"
            unknown_count=$((unknown_count + 1))
        fi
        printf '  [%b%-19s%b] %-46s state=%s\n' \
            "$col" "$marker" "$C_RESET" "$t" "${unit_state:-unknown}"
    done <<< "$timers"
    printf '  (total: %d, NoID Privacy: %d, NoID Privacy masks: %d, admin/override: %d, generator: %d, vendor override: %d, unknown: %d)\n' \
        "$total" "$noid_count" "$noid_mask_count" "$admin_count" \
        "$generator_count" "$vendor_override_count" "$unknown_count"
    if [ "$admin_count" -gt 0 ]; then
        hits_yellow=$((hits_yellow + admin_count))
    fi
    if [ "$vendor_override_count" -gt 0 ]; then
        hits_yellow=$((hits_yellow + vendor_override_count))
    fi
    if [ "$generator_count" -gt 0 ]; then
        hits_yellow=$((hits_yellow + generator_count))
    fi
    if [ "$unknown_count" -gt 0 ]; then
        hits_red=$((hits_red + unknown_count))
    fi
    if [ "$admin_count" -eq 0 ] && [ "$generator_count" -eq 0 ] && \
       [ "$vendor_override_count" -eq 0 ] && \
       [ "$unknown_count" -eq 0 ]; then
        _ok "all $total installed system timer unit files have classified sources"
    fi
}

_section_cron() {
    _header "cron entries (system + user)"
    local any=0 partial=0 dir entries find_rc cron_dirs cron_files pkg e noun
    local link_note
    local system_count=0 unowned_count=0 symlink_count=0 user_count=0
    local protected_cron_dirs=0
    local user_cron="" active_user_cron=""
    local cron_tmp="" crontab_rc=0
    cron_dirs="/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly"
    cron_files="/etc/crontab /etc/anacrontab"
    for e in $cron_files; do
        [ -e "$e" ] || [ -L "$e" ] || continue
        # Cronie accepts regular sources and symlinks that resolve to regular
        # files. A broken link or link to another object is not valid evidence.
        if [ ! -f "$e" ]; then
            partial=1
            _fail_line "system scheduler source is not a regular file or valid symlink: $e"
            continue
        fi
        any=1
        system_count=$((system_count + 1))
        pkg=$(LC_ALL=C rpm -qf "$e" 2>/dev/null | sed -n '1p' || true)
        case "$pkg" in
            *"not owned"*|"")
                pkg="<unowned>"
                unowned_count=$((unowned_count + 1))
                ;;
        esac
        link_note=""
        if [ -L "$e" ]; then
            symlink_count=$((symlink_count + 1))
            link_note=" -> $(readlink -- "$e" 2>/dev/null || printf '?')"
        fi
        printf '  %-45s  (%s)%s\n' "$e" "$pkg" "$link_note"
    done
    for dir in $cron_dirs; do
        [ -d "$dir" ] || continue
        find_rc=0
        entries=$(find "$dir" -maxdepth 1 \( -type f -o -type l \) \
                  ! -name 'README*' ! -name '.*' 2>/dev/null) || find_rc=$?
        entries=$(printf '%s\n' "$entries" | sed '/^$/d' | sort)
        if [ "$find_rc" -ne 0 ]; then
            partial=1
            case "$dir" in
                /etc/cron.d|/etc/cron.daily|/etc/cron.hourly|\
                /etc/cron.weekly|/etc/cron.monthly)
                    if [ "$(id -u)" -ne 0 ]; then
                        protected_cron_dirs=$((protected_cron_dirs + 1))
                    else
                        _notice "cron scan incomplete for $dir (find rc=$find_rc); retaining discovered entries"
                    fi
                    ;;
                *)
                    _notice "cron scan incomplete for $dir (find rc=$find_rc); retaining discovered entries"
                    ;;
            esac
        fi
        [ -z "$entries" ] && continue
        any=1
        printf '  %s/\n' "$dir"
        while IFS= read -r e; do
            [ -z "$e" ] && continue
            if [ ! -f "$e" ]; then
                partial=1
                _fail_line "cron directory source is not a regular file or valid symlink: $e"
                continue
            fi
            system_count=$((system_count + 1))
            # LC_ALL=C: the "not owned" diagnostic is matched below and rpm
            # localizes it — without the pin a German session would print the
            # localized sentence as the owning package name.
            pkg=$(LC_ALL=C rpm -qf "$e" 2>/dev/null | sed -n '1p' || true)
            case "$pkg" in
                *"not owned"*|"")
                    pkg="<unowned>"
                    unowned_count=$((unowned_count + 1))
                    ;;
            esac
            link_note=""
            if [ -L "$e" ]; then
                symlink_count=$((symlink_count + 1))
                link_note=" -> $(readlink -- "$e" 2>/dev/null || printf '?')"
            fi
            printf '    %-40s  (%s)%s\n' "$(basename "$e")" "$pkg" "$link_note"
        done <<< "$entries"
    done
    if [ "$protected_cron_dirs" -gt 0 ]; then
        _notice "$protected_cron_dirs protected system cron directories were unreadable under M10's mode-0700 policy; retry this section with sudo"
    fi
    if command -v crontab >/dev/null 2>&1; then
        if ! cron_tmp=$(mktemp -d "${TMPDIR:-/var/tmp}/noid-crontab-audit.XXXXXX"); then
            partial=1
            _notice "cannot create a private current-user crontab workspace"
        else
            noid_cleanup_dirs+=("$cron_tmp")
            LC_ALL=C crontab -l >"$cron_tmp/stdout" 2>"$cron_tmp/stderr" ||
                crontab_rc=$?
            if [ "$crontab_rc" -eq 0 ]; then
                user_cron=$(<"$cron_tmp/stdout")
                active_user_cron=$(printf '%s\n' "$user_cron" |
                    grep -vE '^[[:space:]]*#|^[[:space:]]*$' || true)
                if [ -n "$active_user_cron" ]; then
                    any=1
                    user_count=$(printf '%s\n' "$active_user_cron" |
                        grep -c . || true)
                    printf '  user crontab (%s):\n' "$(id -un)"
                    printf '%s\n' "$active_user_cron" | sed 's/^/    /'
                fi
            elif [ "$crontab_rc" -eq 1 ] &&
                 [ ! -s "$cron_tmp/stdout" ] &&
                 grep -qE '^no crontab for ' "$cron_tmp/stderr"; then
                : # cronie's explicit no-crontab result
            else
                partial=1
                _notice "cannot read current-user crontab (exit $crontab_rc)"
                sed -n '1,5{s/^/      /;p;}' "$cron_tmp/stderr"
            fi
            if ! remove_cli_tempdir "$cron_tmp"; then
                _notice "cannot remove private crontab workspace: $cron_tmp"
            fi
        fi
    fi
    if [ "$unowned_count" -gt 0 ]; then
        noun=entries
        [ "$unowned_count" -eq 1 ] && noun=entry
        _notice "$unowned_count unowned system cron $noun require attribution"
    fi
    if [ "$symlink_count" -eq 1 ]; then
        _notice "1 symlinked system cron source requires target review"
    elif [ "$symlink_count" -gt 1 ]; then
        _notice "$symlink_count symlinked system cron sources require target review"
    fi
    if [ "$user_count" -gt 0 ]; then
        noun=entries
        [ "$user_count" -eq 1 ] && noun=entry
        _notice "$user_count active current-user crontab $noun require review"
    fi
    if [ "$any" -eq 0 ] && [ "$partial" -eq 0 ]; then
        _ok "no cron entries"
    elif [ "$partial" -eq 0 ] && [ "$unowned_count" -eq 0 ] && \
         [ "$symlink_count" -eq 0 ] && \
         [ "$user_count" -eq 0 ]; then
        if [ "$system_count" -eq 1 ]; then
            _ok "1 system cron entry is package-owned"
        else
            _ok "$system_count system cron entries are package-owned"
        fi
    fi
}

_section_flatpak() {
    _header "flatpak history (last 30 days)"
    if ! command -v flatpak >/dev/null 2>&1; then
        _skip "flatpak not installed"
        return
    fi
    # `flatpak history` without an explicit scope initializes an otherwise
    # unused per-user repository, even though Flatpak documents the system
    # installation as the default.  An explicit system query can still create
    # $HOME/.cache/flatpak/system-cache.  Keep both side effects out of the
    # caller's home: this audit must not manufacture AIDE drift.
    local flatpak_cache system_hist="" user_hist="" system_content="" user_content=""
    local system_stdout system_stderr user_stdout user_stderr
    local event_count=0
    local system_rc=0 user_rc=0
    local home_dir=${HOME:-}
    local user_data_home="" user_repo=""
    if [ -n "${XDG_DATA_HOME:-}" ]; then
        user_data_home=$XDG_DATA_HOME
    elif [ -n "$home_dir" ]; then
        user_data_home="$home_dir/.local/share"
    else
        _skip "HOME and XDG_DATA_HOME are unset; cannot locate the current-user Flatpak repository"
    fi
    [ -z "$user_data_home" ] || user_repo="$user_data_home/flatpak/repo"
    if ! flatpak_cache=$(mktemp -d "${TMPDIR:-/var/tmp}/noid-integrity-flatpak.XXXXXX"); then
        _fail_line "cannot create an isolated Flatpak audit cache"
        return
    fi
    noid_cleanup_dirs+=("$flatpak_cache")
    system_stdout="$flatpak_cache/system.stdout"
    system_stderr="$flatpak_cache/system.stderr"
    user_stdout="$flatpak_cache/user.stdout"
    user_stderr="$flatpak_cache/user.stderr"
    LC_ALL=C XDG_CACHE_HOME="$flatpak_cache" \
        flatpak history --system --since=30days \
        --columns=time,change,application \
        >"$system_stdout" 2>"$system_stderr" || system_rc=$?
    if [ -n "$user_repo" ] && [ -f "$user_repo/config" ]; then
        LC_ALL=C XDG_CACHE_HOME="$flatpak_cache" \
            flatpak history --user --since=30days \
            --columns=time,change,application \
            >"$user_stdout" 2>"$user_stderr" || user_rc=$?
    fi

    if [ "$system_rc" -ne 0 ]; then
        _fail_line "cannot read system Flatpak history (exit $system_rc)"
        sed -n '1,5{s/^/      /;p;}' "$system_stderr" 2>/dev/null || true
    else
        system_hist=$(<"$system_stdout")
        system_content=$(printf '%s\n' "$system_hist" |
            grep -vE '^[[:space:]]*$|^Time[[:space:]]' || true)
    fi
    if [ "$user_rc" -ne 0 ]; then
        _fail_line "cannot read current-user Flatpak history (exit $user_rc)"
        sed -n '1,5{s/^/      /;p;}' "$user_stderr" 2>/dev/null || true
    else
        [ ! -f "$user_stdout" ] || user_hist=$(<"$user_stdout")
        user_content=$(printf '%s\n' "$user_hist" |
            grep -vE '^[[:space:]]*$|^Time[[:space:]]' || true)
    fi

    if [ -n "$system_content" ]; then
        printf '  [system]\n'
        printf '%s\n' "$system_hist" | sed -n '1,25{s/^/    /;p;}'
    fi
    if [ -n "$user_content" ]; then
        printf '  [user:%s]\n' "$(id -un)"
        printf '%s\n' "$user_hist" | sed -n '1,25{s/^/    /;p;}'
    fi
    if [ "$system_rc" -eq 0 ] && [ "$user_rc" -eq 0 ] \
       && [ -z "$system_content" ] && [ -z "$user_content" ]; then
        _ok "no system or current-user flatpak events in last 30 days"
    elif [ "$system_rc" -eq 0 ] && [ "$user_rc" -eq 0 ]; then
        event_count=$(printf '%s\n%s\n' "$system_content" "$user_content" |
            grep -c . || true)
        _notice "$event_count Flatpak history event(s) require review"
    fi
    if ! remove_cli_tempdir "$flatpak_cache"; then
        _notice "cannot remove isolated Flatpak audit cache: $flatpak_cache"
    fi
}

_section_oauth() {
    _header "external account access audit"
    _notice "manual provider review required; this CLI performs no network request"
    printf '    Google    https://myaccount.google.com/connections\n'
    printf '    GitHub    https://github.com/settings/applications\n'
    printf '    Proton    https://account.proton.me/\n'
    printf '    Microsoft https://myapps.microsoft.com/ (work/school)\n'
    printf '    Apple     https://account.apple.com/account/manage\n'
    printf '  Full checklist (OAuth, tokens, sessions, linked devices):\n'
    printf '    less %s\n' "$DOC_OAUTH"
}

_section_suid() {
    _header "files carrying SUID / SGID bits"
    if ! command -v find >/dev/null 2>&1; then
        _skip "find not available"
        return
    fi
    local roots=() root find_rc=0 scan_advice suid="" count=0
    for root in / /home /var /var/tmp /tmp /dev/shm /boot /boot/efi; do
        [ -d "$root" ] || continue
        roots+=("$root")
    done
    # Capture find's status instead of letting a non-zero pipeline kill the
    # whole run under errexit. Permission denials are common for an
    # unprivileged scan, but transient pathname and I/O errors can also make
    # find non-zero; report the exact rc without claiming one universal cause.
    if [ "$(id -u)" -eq 0 ]; then
        scan_advice="investigate the walker error before trusting this section"
    else
        scan_advice="retry: sudo $SCRIPT --all"
    fi
    suid=$(find "${roots[@]}" -xdev -type f \
               \( -perm -4000 -o -perm -2000 \) \
               -printf '%m %u %g %p\n' 2>/dev/null | sort -u) || find_rc=$?
    if [ -z "$suid" ]; then
        if [ "$find_rc" -ne 0 ]; then
            _notice "SUID scan incomplete (find rc=$find_rc) and returned nothing — $scan_advice"
        else
            _ok "no regular files carrying SUID/SGID bits found in the selected trees"
        fi
        return
    fi
    count=$(printf '%s\n' "$suid" | grep -c . || true)
    if [ "$find_rc" -ne 0 ]; then
        _notice "$count SUID/SGID files (PARTIAL — find rc=$find_rc; paths were unreadable or changed; $scan_advice)"
    else
        _notice "$count SUID/SGID files; attribute every path to its live package"
    fi
    printf '%s\n' "$suid" | sed 's/^/      /'
}

_section_services() {
    _header "enabled systemd unit files"
    if ! command -v systemctl >/dev/null 2>&1; then
        _skip "systemctl not available"
        return
    fi
    local listing enabled count
    if ! listing=$(LC_ALL=C systemctl list-unit-files \
                   --state=enabled,enabled-runtime \
                   --no-pager --no-legend 2>/dev/null); then
        _fail_line "cannot enumerate enabled systemd unit files"
        return
    fi
    enabled=$(awk 'NF >= 2 {print $1 "\t" $2}' <<< "$listing" | sort -u)
    if [ -z "$enabled" ]; then
        _notice "no enabled unit files (unusual — expected at least some vendor defaults)"
        return
    fi
    count=$(printf '%s\n' "$enabled" | grep -c . || true)
    printf '  %d enabled/enabled-runtime unit files:\n' "$count"
    printf '%s\n' "$enabled" | awk -F'\t' \
        '{ printf "    %-52s state=%s\n", $1, $2 }'
    _notice "enabled-unit inventory printed for human review"
}

_print_summary() {
    printf '\n%b=== Summary ===%b\n' "$C_BOLD" "$C_RESET"
    printf '  %bgreen%b  %d\n' "$C_GREEN" "$C_RESET" "$hits_green"
    printf '  %byellow%b %d\n' "$C_YELLOW" "$C_RESET" "$hits_yellow"
    printf '  %bred%b    %d\n' "$C_RED" "$C_RESET" "$hits_red"
    if [ "$hits_red" -gt 0 ]; then
        printf '\n  %bAction%b: investigate red items (see %s)\n' \
               "$C_BOLD" "$C_RESET" "$DOC_GUIDE"
    elif [ "$hits_yellow" -gt 0 ]; then
        printf '\n  %bAction%b: review yellow items, usually explainable\n' \
               "$C_BOLD" "$C_RESET"
    else
        printf '\n  %bAction%b: review the printed evidence; no automated red/yellow finding is not an integrity attestation.\n' \
               "$C_BOLD" "$C_RESET"
    fi
}

# --- arg parse ---
SECTIONS=""
BRIEF=0
explicit_sections=0
include_all=0

while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --all)
            include_all=1
            shift
            ;;
        --brief)
            BRIEF=1
            shift
            ;;
        --section)
            shift
            [ $# -lt 1 ] && { echo "--section needs an argument" >&2; exit 2; }
            case "$1" in
                '') echo "--section needs a non-empty section name" >&2; exit 2 ;;
                -*) echo "--section needs a section name" >&2; exit 2 ;;
            esac
            SECTIONS="${SECTIONS:+$SECTIONS }$1"
            explicit_sections=1
            shift
            ;;
        --*)
            echo "unknown option: $1 (see --help)" >&2
            exit 2
            ;;
        *)
            [ -n "$1" ] || { echo "section name must not be empty" >&2; exit 2; }
            SECTIONS="${SECTIONS:+$SECTIONS }$1"
            explicit_sections=1
            shift
            ;;
    esac
done

if [ "$include_all" -eq 1 ]; then
    SECTIONS="$DEFAULT_SECTIONS $EXTRA_SECTIONS${SECTIONS:+ $SECTIONS}"
elif [ "$explicit_sections" -eq 0 ]; then
    SECTIONS="$DEFAULT_SECTIONS"
fi

# Validate before executing anything and de-duplicate while preserving order.
# An argument error must not run a partial scan and then append a green-looking
# summary.
normalized_sections=""
for sec in $SECTIONS; do
    case "$sec" in
        rpm|timers|cron|flatpak|oauth|suid|services) ;;
        *)
            printf 'unknown section: %s (see --help)\n' "$sec" >&2
            exit 2
            ;;
    esac
    case " $normalized_sections " in
        *" $sec "*) ;;
        *) normalized_sections="${normalized_sections:+$normalized_sections }$sec" ;;
    esac
done
SECTIONS=$normalized_sections

# Note only about requested sections whose evidence boundary actually changes.
if [ "$(id -u)" -ne 0 ] && [ "$BRIEF" -eq 0 ]; then
    note_printed=0
    case " $SECTIONS " in
        *" rpm "*)
            printf '%bNOTE%b RPM verification is skipped without root.\n' \
                "$C_YELLOW" "$C_RESET"
            note_printed=1
            ;;
    esac
    case " $SECTIONS " in
        *" suid "*)
            printf '%bNOTE%b The filesystem scan may be incomplete without root.\n' \
                "$C_YELLOW" "$C_RESET"
            note_printed=1
            ;;
    esac
    case " $SECTIONS " in
        *" cron "*|*" flatpak "*)
            printf '%bNOTE%b sudo changes crontab/Flatpak user scope; retain this user run too.\n' \
                "$C_YELLOW" "$C_RESET"
            note_printed=1
            ;;
    esac
    [ "$note_printed" -eq 0 ] || printf '\n'
fi

# Brief mode: in --brief, redirect
# stdout to /dev/null during section execution. Counters (hits_green/yellow/
# red) increment regardless of stdout because they're shell vars not output.
# _print_summary then prints to the saved stdout (fd 3) at end. Implements
# the help-text contract "summary output (default sections)" — previously
# only the sudo NOTE banner was suppressed, full section detail still
# printed.
if [ "$BRIEF" -eq 1 ]; then
    exec 3>&1 1>/dev/null
fi

# Execute validated sections
for sec in $SECTIONS; do
    case "$sec" in
        rpm)      _section_rpm ;;
        timers)   _section_timers ;;
        cron)     _section_cron ;;
        flatpak)  _section_flatpak ;;
        oauth)    _section_oauth ;;
        suid)     _section_suid ;;
        services) _section_services ;;
    esac
done

# Restore stdout for summary (always visible)
if [ "$BRIEF" -eq 1 ]; then
    exec 1>&3 3>&-
fi

_print_summary
if [ "$hits_red" -gt 0 ]; then
    exit 1
fi
exit 0
NIC_EOF

publish_root_file "$NIC_TMP" "$NIC_TARGET" 755
log "  [OK] /usr/local/bin/noid-integrity-check installed"

# Syntax check the shipped script
if ! bash -n /usr/local/bin/noid-integrity-check; then
    die "noid-integrity-check has syntax errors"
fi
log "  [OK] bash -n passed on noid-integrity-check"

# ----------------------------------------------------------------------------
# Phase 6 — Install /usr/local/bin/noid-firefox-create-isolated-profile
# ----------------------------------------------------------------------------
PHASE="P6-ffprofile-cli"
log "Writing /usr/local/bin/noid-firefox-create-isolated-profile"

FFCP_TARGET=/usr/local/bin/noid-firefox-create-isolated-profile
FFCP_TMP=$(mktemp /usr/local/bin/.noid-firefox-create-isolated-profile.XXXXXX) ||
    die "cannot create Firefox-profile-CLI temporary file"
cat > "$FFCP_TMP" <<'FFCP_EOF'
#!/bin/bash
# noid-firefox-create-isolated-profile — Create a separate, NoID Privacy-hardened
# Firefox profile. Profile separation is a browser-data boundary, not an OS
# sandbox against processes running as the same user.
# Part of NoID Privacy Workstation, Module 33 Operational Hygiene.
# Full guide: /usr/share/doc/noid-privacy/33-firefox-profile-isolation.md
#
set -uo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox Profile" \
    NOID_FMT_AUTO_SUBTITLE="Isolated profile creation" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

SCRIPT="$(basename "$0")"
DOC_GUIDE="/usr/share/doc/noid-privacy/33-firefox-profile-isolation.md"
PROFILE_HELPER="/usr/local/lib/noid-privacy/firefox-profiles.sh"
PROFILE_CREATION_STARTED=0
PROFILE_CREATION_COMPLETE=0

profile_creation_exit_notice() {
    local saved_rc=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [ "${PROFILE_CREATION_STARTED:-0}" -eq 1 ] && \
       [ "${PROFILE_CREATION_COMPLETE:-0}" -eq 0 ] && \
       [ "$saved_rc" -ne 0 ]; then
        printf '%s\n' \
            "$SCRIPT: profile creation stopped before every hardening postcondition passed." \
            "         Firefox may already have registered '$NAME' in profiles.ini." \
            "         Keep Firefox closed, run '$SCRIPT --list', and if that exact" \
            "         profile exists remove it with 'firefox -P' before retrying." >&2
    fi
    return "$saved_rc"
}

# Source shared profile helper.
if [ -f "$PROFILE_HELPER" ] && [ ! -L "$PROFILE_HELPER" ] && \
   [ "$(stat -Lc '%u:%g:%a:%h' -- "$PROFILE_HELPER" 2>/dev/null)" = \
       "0:0:644:1" ]; then
    # shellcheck source=/dev/null
    . "$PROFILE_HELPER"
else
    echo "$SCRIPT: missing or unsafe profile helper: $PROFILE_HELPER" >&2
    echo "         Module 16 installation may be incomplete." >&2
    exit 2
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "$SCRIPT: run as the normal desktop user, never through sudo" >&2
    exit 1
fi
if [ "$#" -gt 1 ]; then
    echo "$SCRIPT: surplus/conflicting arguments (try --help)" >&2
    exit 2
fi

usage() {
    cat <<USAGE_END
$SCRIPT — create an isolated Firefox profile with NoID Privacy Firefox Hardening

USAGE
  $SCRIPT <profile-name>       create profile + apply hardening
  $SCRIPT --list               list existing Firefox profiles
  $SCRIPT --help               this message

NAME CONSTRAINTS
  - 1-32 characters
  - Allowed: A-Z a-z 0-9 _ -
  - "playground" is reserved (managed by Module 34)
  - Firefox itself enforces more, but this CLI is strict.

EFFECT
  - Creates a profile through Firefox under
    \$XDG_CONFIG_HOME/mozilla/firefox/ (default: ~/.config/mozilla/firefox/)
  - Applies the supported NoID Privacy user.js composition
  - Registers the profile in profiles.ini
  - Installs validated profile-local uBlock Origin state
  - Prints launch and upstream profile-removal guidance

ISOLATION
  Firefox stores these separately:
    - cookies, session storage, IndexedDB
    - saved logins + passwords
    - browsing + download history
    - bookmarks, pinned tabs, themes

  This is NOT an OS sandbox. Same-user malware may read every profile.

USE CASES
  banking     online banking only
  work        work email / Slack / Notion / corporate SaaS
  shopping    Amazon / eBay / tracking-heavy sites
  crypto      exchanges + hot wallet web UIs
  research    OSINT / investigative browsing
  daily       your primary default

LAUNCH
  firefox -P <name> --new-instance

See $DOC_GUIDE for the exact boundary, launcher and removal guidance.
USAGE_END
}

_list_profiles() {
    local root records
    root=$(firefox_root)
    local ini="$root/profiles.ini"
    if [ ! -f "$ini" ]; then
        echo "$SCRIPT: no profiles.ini yet — run Firefox once to initialize" >&2
        return 1
    fi
    if ! records=$(list_registered_profiles); then
        echo "$SCRIPT: profiles.ini failed the safe profile-record contract" >&2
        return 1
    fi
    printf 'Firefox profiles (from %s):\n\n' "$ini"
    printf '%s\n' "$records" | awk -F'\t' '
        { printf "  %s%-24s %s\n", ($4 == "1" ? "* " : "  "), $1, $2 }
    '
    printf '\n  (* = default)\n'
    printf '\nLaunch:  firefox -P <name> --new-instance\n'
}

# --- arg parse ---
if [ $# -eq 0 ]; then
    usage
    exit 0
fi

case "$1" in
    --help|-h)
        usage
        exit 0
        ;;
    --list|-l)
        _list_profiles
        exit $?
        ;;
    -*)
        echo "$SCRIPT: unknown flag: $1" >&2
        echo "       run '$SCRIPT --help' for usage" >&2
        exit 2
        ;;
esac

NAME="$1"

if ! acquire_firefox_profile_lock; then
    echo "$SCRIPT: another Firefox profile operation is active; retry later" >&2
    exit 75
fi
if firefox_process_active; then
    echo "$SCRIPT: close Firefox before creating or changing a profile" >&2
    exit 75
fi

# validate name
case "$NAME" in
    '')
        echo "$SCRIPT: profile name required" >&2; exit 2 ;;
    *[!a-zA-Z0-9_-]*)
        echo "$SCRIPT: name contains invalid characters (allowed: A-Z a-z 0-9 _ -)" >&2; exit 2 ;;
    playground)
        echo "$SCRIPT: 'playground' is reserved — managed by Module 34 (auto-pinned amnesic profile)" >&2
        exit 2 ;;
esac
if [ "${#NAME}" -gt 32 ]; then
    echo "$SCRIPT: name too long (max 32 chars)" >&2
    exit 2
fi

# prerequisite: firefox
if ! command -v firefox >/dev/null 2>&1; then
    echo "$SCRIPT: firefox is not installed" >&2
    echo "         this image ships Firefox — did M26 fail?" >&2
    exit 1
fi

# prerequisite: embedded user.js
if [ ! -f "$NOID_FF_USERJS_BASE" ] || [ -L "$NOID_FF_USERJS_BASE" ]; then
    echo "$SCRIPT: embedded user.js missing at $NOID_FF_USERJS_BASE" >&2
    echo "         Module 16 (NoID Privacy Firefox Hardening) not installed?" >&2
    exit 1
fi

PROFILE_ROOT="$(firefox_root)"
case "$PROFILE_ROOT" in
    /*) ;;
    *)
        echo "$SCRIPT: Firefox profile root is not absolute: $PROFILE_ROOT" >&2
        exit 1
        ;;
esac
if [ -L "$PROFILE_ROOT" ]; then
    echo "$SCRIPT: Firefox profile root must not be a symlink: $PROFILE_ROOT" >&2
    exit 1
fi
if [ ! -e "$PROFILE_ROOT" ]; then
    if ! install -d -m 700 -- "$PROFILE_ROOT"; then
        echo "$SCRIPT: cannot create Firefox profile root: $PROFILE_ROOT" >&2
        exit 1
    fi
fi
PROFILE_ROOT_STATE=$(stat -Lc '%u:%a' -- "$PROFILE_ROOT" 2>/dev/null || echo "")
PROFILE_ROOT_OWNER=${PROFILE_ROOT_STATE%%:*}
PROFILE_ROOT_MODE=${PROFILE_ROOT_STATE#*:}
if [ ! -d "$PROFILE_ROOT" ] || [ -L "$PROFILE_ROOT" ] || \
   [ "$PROFILE_ROOT_OWNER" != "$(id -u)" ] || \
   ! [[ "$PROFILE_ROOT_MODE" =~ ^[0-7]{3,4}$ ]] || \
   (( (8#$PROFILE_ROOT_MODE & 0022) != 0 )); then
    echo "$SCRIPT: unsafe Firefox profile root ownership/mode: $PROFILE_ROOT" >&2
    exit 1
fi

# Refuse to overwrite an existing profile with the same name.
if profile_dir_for "$NAME" >/dev/null 2>&1; then
    echo "$SCRIPT: a Firefox profile named '$NAME' already exists" >&2
    echo "         run '$SCRIPT --list' to see all profiles" >&2
    exit 1
fi

echo "Creating Firefox profile: $NAME"
echo "  embedded user.js: $NOID_FF_USERJS_BASE"
echo "  XDG profile root: $PROFILE_ROOT"
echo ""

# Create the profile via the helper, which uses Firefox's headless
# -CreateProfile interface
# and validates that profiles.ini registered the profile afterwards.
PROFILE_CREATION_STARTED=1
trap profile_creation_exit_notice EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if ! ensure_profile "$NAME"; then
    echo "$SCRIPT: ensure_profile failed (firefox -CreateProfile did not register profile)" >&2
    exit 1
fi

PROFILE_DIR=$(profile_dir_for "$NAME") || {
    echo "$SCRIPT: profile_dir_for returned nothing for '$NAME'" >&2
    exit 1
}

if [ ! -d "$PROFILE_DIR" ]; then
    # Keep the helper usable if Firefox registered the path before materializing
    # the directory.
    if ! install -d -m 700 -- "$PROFILE_DIR"; then
        echo "$SCRIPT: cannot create registered profile directory" >&2
        exit 1
    fi
fi
if [ -L "$PROFILE_DIR" ] || \
   [ "$(stat -Lc '%u:%a' -- "$PROFILE_DIR" 2>/dev/null)" != "$(id -u):700" ]; then
    echo "$SCRIPT: registered profile directory ownership/mode is unsafe" >&2
    exit 1
fi

# Apply user.js via the helper. Falls into the "default" branch (not
# playground) because M33 doesn't create playground profiles.
if ! apply_userjs "$NAME"; then
    echo "$SCRIPT: apply_userjs failed for '$NAME'" >&2
    exit 1
fi

# Install the exact profile-local XPI and permissions through the shared helper;
# profile_hardening_complete is the final byte/metadata/content postcondition.
if ! install_ubo_profile_local "$NAME"; then
    echo "$SCRIPT: exact uBO profile-local install failed for '$NAME'" >&2
    exit 1
fi
if ! patch_ubo_pb_permission "$NAME"; then
    echo "$SCRIPT: uBO Private-Browsing permission failed for '$NAME'" >&2
    exit 1
fi
if ! profile_hardening_complete "$NAME"; then
    echo "$SCRIPT: complete profile postcondition failed for '$NAME'" >&2
    exit 1
fi

# Pre-create xulstore.json so first launch opens maximized. Write through a
# same-directory temporary file so a short write never replaces valid state.
XULSTORE_FILE="$PROFILE_DIR/xulstore.json"
XULSTORE_TMP=$(mktemp "$PROFILE_DIR/.xulstore.json.XXXXXX") || {
    echo "$SCRIPT: cannot create temporary xulstore.json" >&2
    exit 1
}
if ! cat > "$XULSTORE_TMP" <<XULSTORE_JSON_EOF
{"chrome://browser/content/browser.xhtml":{"main-window":{"sizemode":"maximized","screenX":"0","screenY":"0","width":"1366","height":"768"}}}
XULSTORE_JSON_EOF
then
    rm -f -- "$XULSTORE_TMP"
    echo "$SCRIPT: cannot write xulstore.json" >&2
    exit 1
fi
if ! chmod 600 "$XULSTORE_TMP" || ! mv -nT -- "$XULSTORE_TMP" "$XULSTORE_FILE"; then
    rm -f -- "$XULSTORE_TMP"
    echo "$SCRIPT: cannot install xulstore.json" >&2
    exit 1
fi
rm -f -- "$XULSTORE_TMP"
if [ ! -f "$XULSTORE_FILE" ] || [ -L "$XULSTORE_FILE" ] || \
   [ "$(stat -Lc '%u:%a:%h' -- "$XULSTORE_FILE" 2>/dev/null)" != \
       "$(id -u):600:1" ] || \
   ! grep -qF '"sizemode":"maximized"' "$XULSTORE_FILE"; then
    echo "$SCRIPT: xulstore.json postcondition failed" >&2
    exit 1
fi

# Pre-place an empty bookmarks JSON backup so
# Mozilla's PlacesBrowserStartup.initPlaces() restores from it, skipping
# the chrome://browser/content/default-bookmarks.html import path that
# would otherwise inject Fedora-customized default bookmarks.
# Filename matches Mozilla regex /^bookmarks-([0-9-]+)(?:_[0-9]+)?(?:_[a-z0-9=_+-]{24,})?\.(json|jsonlz4)$/i
NOID_BM_TS=$(date +%s%6N)
NOID_BM_DATE=$(date +%Y-%m-%d)
NOID_BM_DIR="$PROFILE_DIR/bookmarkbackups"
NOID_BM_FILE="$NOID_BM_DIR/bookmarks-${NOID_BM_DATE}.json"
if [ -L "$NOID_BM_DIR" ] || ! install -d -m 700 "$NOID_BM_DIR" || \
   [ ! -d "$NOID_BM_DIR" ] || \
   [ "$(stat -Lc '%u:%a' -- "$NOID_BM_DIR" 2>/dev/null)" != \
       "$(id -u):700" ]; then
    echo "$SCRIPT: bookmark backup directory postcondition failed" >&2
    exit 1
fi
NOID_BM_TMP=$(mktemp "$NOID_BM_DIR/.bookmarks.json.XXXXXX") || {
    echo "$SCRIPT: cannot create temporary bookmarks backup" >&2
    exit 1
}
if ! cat > "$NOID_BM_TMP" <<BOOKMARKS_BACKUP_JSON_EOF
{
  "guid": "root________",
  "title": "",
  "index": 0,
  "dateAdded": ${NOID_BM_TS},
  "lastModified": ${NOID_BM_TS},
  "id": 1,
  "typeCode": 2,
  "type": "text/x-moz-place-container",
  "root": "placesRoot",
  "children": [
    {"guid": "menu________", "title": "menu", "index": 0, "dateAdded": ${NOID_BM_TS}, "lastModified": ${NOID_BM_TS}, "id": 2, "typeCode": 2, "type": "text/x-moz-place-container", "root": "bookmarksMenuFolder", "children": []},
    {"guid": "toolbar_____", "title": "toolbar", "index": 1, "dateAdded": ${NOID_BM_TS}, "lastModified": ${NOID_BM_TS}, "id": 3, "typeCode": 2, "type": "text/x-moz-place-container", "root": "toolbarFolder", "children": []},
    {"guid": "tags________", "title": "tags", "index": 2, "dateAdded": ${NOID_BM_TS}, "lastModified": ${NOID_BM_TS}, "id": 4, "typeCode": 2, "type": "text/x-moz-place-container", "root": "tagsFolder", "children": []},
    {"guid": "unfiled_____", "title": "unfiled", "index": 3, "dateAdded": ${NOID_BM_TS}, "lastModified": ${NOID_BM_TS}, "id": 5, "typeCode": 2, "type": "text/x-moz-place-container", "root": "unfiledBookmarksFolder", "children": []},
    {"guid": "mobile______", "title": "mobile", "index": 4, "dateAdded": ${NOID_BM_TS}, "lastModified": ${NOID_BM_TS}, "id": 6, "typeCode": 2, "type": "text/x-moz-place-container", "root": "mobileFolder", "children": []}
  ]
}
BOOKMARKS_BACKUP_JSON_EOF
then
    rm -f -- "$NOID_BM_TMP"
    echo "$SCRIPT: cannot write bookmarks backup" >&2
    exit 1
fi
if ! chmod 600 "$NOID_BM_TMP" || ! mv -nT -- "$NOID_BM_TMP" "$NOID_BM_FILE"; then
    rm -f -- "$NOID_BM_TMP"
    echo "$SCRIPT: cannot install bookmarks backup" >&2
    exit 1
fi
rm -f -- "$NOID_BM_TMP"
if [ ! -f "$NOID_BM_FILE" ] || [ -L "$NOID_BM_FILE" ] || \
   [ "$(stat -Lc '%u:%a:%h' -- "$NOID_BM_FILE" 2>/dev/null)" != \
       "$(id -u):600:1" ] || \
   ! grep -qF '"root": "placesRoot"' "$NOID_BM_FILE" || \
   [ "$(grep -Fc '"children": []' "$NOID_BM_FILE")" -ne 5 ]; then
    echo "$SCRIPT: bookmarks backup postcondition failed" >&2
    exit 1
fi
PROFILE_CREATION_COMPLETE=1
trap - EXIT HUP INT TERM

echo "  [OK] profile directory: $PROFILE_DIR"
echo "  [OK] user.js installed (600)"
echo "  [OK] xulstore.json (sizemode=maximized)"
echo "  [OK] empty bookmarks backup installed (600)"
echo ""

cat <<POST_END
Profile "$NAME" ready.

Launch:
  firefox -P "$NAME" --new-instance

Behavior:
  - NoID Privacy Firefox Hardening active (FPP, system/VPN DNS by default,
    TCP, no telemetry)
  - Exact validated uBlock Origin payload installed profile-local
  - uBlock Origin allowed in private windows for this profile
  - Firefox keeps cookies/history/logins separate from other profiles
  - This is browser-data separation, not a same-user malware sandbox
  - Empty bookmarks (no Fedora defaults) — add your own via Ctrl+D

Dedicated GNOME launcher:
  Create a desktop entry whose command is:
    firefox -P "$NAME" --new-instance
  Launch that Activities entry before pinning it; pinning the generic Firefox
  window can lose the profile arguments.

See: $DOC_GUIDE

Remove later:
  Close Firefox, run 'firefox -P', select the exact profile, and use the
  upstream Remove Profile action. Decide there whether to retain its files.
POST_END

exit 0
FFCP_EOF

publish_root_file "$FFCP_TMP" "$FFCP_TARGET" 755
log "  [OK] /usr/local/bin/noid-firefox-create-isolated-profile installed"

# Syntax check the shipped script
if ! bash -n /usr/local/bin/noid-firefox-create-isolated-profile; then
    die "noid-firefox-create-isolated-profile has syntax errors"
fi
log "  [OK] bash -n passed on noid-firefox-create-isolated-profile"

# ----------------------------------------------------------------------------
# Phase 6b — cron.allow + at.allow defensive root-only policy
# ----------------------------------------------------------------------------
# cronie + at are absent from the validated base image (no crond/atd), and M33
# installs neither package. The allow-files are defensive future-proofing:
# if a user later installs cronie/at, only root may submit new jobs through
# crontab/at. Semantics per crontab(1)/at(1): the matching allow-file takes
# precedence over Fedora's empty, world-readable deny-file and admits only
# listed users. cron.allow is intentionally 0644: it contains no secret, and
# Cronie documents an allow-file unreadable by the invoking user as
# nonexistent. A 0600 cron.allow followed by Fedora's empty cron.deny would
# therefore allow every local user instead of enforcing this policy.
# Fedora's at(1) is setuid-root and upstream opens at.allow inside its explicit
# privileged section, so at.allow retains the tighter 0600 mode. Existing jobs
# and root-managed system scheduler sources remain separate review surfaces.
PHASE="P6b-cron-at-deny"
log "Phase 6b — cron.allow + at.allow root-only (defensive future-proof)"

CRON_ALLOW_TARGET=/etc/cron.allow
CRON_ALLOW_TMP=$(mktemp /etc/.cron.allow.noid.XXXXXX) ||
    die "cannot create cron.allow temporary file"
cat > "$CRON_ALLOW_TMP" <<'CRON_ALLOW_EOF'
# NoID Privacy — restricted cron access
# cronie is NOT installed by default on NoID Privacy. This file is defensive:
# if cronie is later installed manually, only root may use crontab.
root
CRON_ALLOW_EOF
publish_root_file "$CRON_ALLOW_TMP" "$CRON_ALLOW_TARGET" 644
log "  [OK] /etc/cron.allow written (readable root-only allowlist, mode 0644)"

AT_ALLOW_TARGET=/etc/at.allow
AT_ALLOW_TMP=$(mktemp /etc/.at.allow.noid.XXXXXX) ||
    die "cannot create at.allow temporary file"
cat > "$AT_ALLOW_TMP" <<'AT_ALLOW_EOF'
# NoID Privacy — restricted at access
# at is NOT installed by default on NoID Privacy. This file is defensive:
# if at is later installed manually, only root may submit at jobs.
root
AT_ALLOW_EOF
publish_root_file "$AT_ALLOW_TMP" "$AT_ALLOW_TARGET" 600
log "  [OK] /etc/at.allow written (root-only allowlist, mode 0600)"

# ----------------------------------------------------------------------------
# Phase 7 — SELinux context restore on all new files
# ----------------------------------------------------------------------------
PHASE="P7-selinux"
log "Restoring SELinux contexts"
for payload in \
    /usr/share/doc/noid-privacy \
    /usr/share/doc/noid-privacy/33-oauth-audit-checklist.md \
    /usr/share/doc/noid-privacy/33-firefox-profile-isolation.md \
    /usr/share/doc/noid-privacy/33-integrity-check-guide.md \
    /usr/local/bin/noid-integrity-check \
    /usr/local/bin/noid-firefox-create-isolated-profile \
    /etc/cron.allow /etc/at.allow; do
    /usr/sbin/restorecon -F -- "$payload" ||
        die "restorecon failed for Module 33 payload: $payload"
    /usr/sbin/matchpathcon -V "$payload" >/dev/null ||
        die "SELinux context differs for Module 33 payload: $payload"
done
log "  [OK] every Module 33 payload has its canonical SELinux context"

# ----------------------------------------------------------------------------
# Phase 8 — Verification
# ----------------------------------------------------------------------------
PHASE="P8-verify"
log "Running verification"

checks=0
fails=0

check() {
    local desc="$1"
    shift
    checks=$((checks + 1))
    if "$@"; then
        log "  [OK] $desc"
    else
        fails=$((fails + 1))
        log "  [FAIL] $desc"
    fi
}

verify_owned_regular() {
    local path="$1" expected_mode="$2"
    [ -f "$path" ] &&
        [ ! -L "$path" ] &&
        [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null)" = \
            "0:0:${expected_mode}:1" ] &&
        /usr/sbin/matchpathcon -V "$path" >/dev/null
}

# ---- docs exist + min size + exact file metadata ----
oauth_size=$(stat -c %s /usr/share/doc/noid-privacy/33-oauth-audit-checklist.md 2>/dev/null || echo 0)
oauth_size=${oauth_size:-0}
check "33-oauth-audit-checklist.md > 4KB (actual: ${oauth_size} bytes)" \
    test "$oauth_size" -gt 4096

ff_size=$(stat -c %s /usr/share/doc/noid-privacy/33-firefox-profile-isolation.md 2>/dev/null || echo 0)
ff_size=${ff_size:-0}
check "33-firefox-profile-isolation.md > 4KB (actual: ${ff_size} bytes)" \
    test "$ff_size" -gt 4096

ic_size=$(stat -c %s /usr/share/doc/noid-privacy/33-integrity-check-guide.md 2>/dev/null || echo 0)
ic_size=${ic_size:-0}
check "33-integrity-check-guide.md > 3KB (actual: ${ic_size} bytes)" \
    test "$ic_size" -gt 3072

for doc in 33-oauth-audit-checklist.md 33-firefox-profile-isolation.md 33-integrity-check-guide.md; do
    check "$doc regular root:root 0644 link-count=1" \
        verify_owned_regular "/usr/share/doc/noid-privacy/$doc" 644
done

# ---- doc structural markers ----
for kw in "External Account Access Audit" "myaccount.google.com/connections" "github.com/settings/applications" "account.proton.me" "RFC 9700" "monthly"; do
    if grep -qF -- "$kw" /usr/share/doc/noid-privacy/33-oauth-audit-checklist.md 2>/dev/null; then
        checks=$((checks + 1))
        log "  [OK] oauth-checklist references: $kw"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] oauth-checklist missing: $kw"
    fi
done

for kw in "browser-data separation, not an OS sandbox" "noid-firefox-create-isolated-profile" "--new-instance" "Multi-Account Containers" "banking"; do
    if grep -qF -- "$kw" /usr/share/doc/noid-privacy/33-firefox-profile-isolation.md 2>/dev/null; then
        checks=$((checks + 1))
        log "  [OK] firefox-isolation references: $kw"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] firefox-isolation missing: $kw"
    fi
done

for kw in "rpm -Va" "systemd timers" "external-account access review" "False positives" "Module 33"; do
    if grep -qF -- "$kw" /usr/share/doc/noid-privacy/33-integrity-check-guide.md 2>/dev/null; then
        checks=$((checks + 1))
        log "  [OK] integrity-guide references: $kw"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] integrity-guide missing: $kw"
    fi
done

# ---- CLI scripts: exact metadata + bash -n + structural functions ----
for cli in /usr/local/bin/noid-integrity-check /usr/local/bin/noid-firefox-create-isolated-profile; do
    check "$cli regular root:root 0755 link-count=1" \
        verify_owned_regular "$cli" 755
    check "$cli bash -n clean" bash -n "$cli"
done

# noid-integrity-check must have the 5 default section functions + arg parse
for func in _section_rpm _section_timers _section_cron _section_flatpak _section_oauth; do
    if grep -qF "$func()" /usr/local/bin/noid-integrity-check; then
        checks=$((checks + 1))
        log "  [OK] noid-integrity-check defines: $func"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] noid-integrity-check missing function: $func"
    fi
done

# noid-integrity-check help + all flags. grep -qF with unescaped flag
# strings — ERE-escaped `\-\-help` forms emit "stray \ before -" warnings
# (fixed-string match is the correct intent here).
for flag in "--help" "--all" "--section" "--brief"; do
    if grep -qF -- "$flag" /usr/local/bin/noid-integrity-check; then
        checks=$((checks + 1))
        log "  [OK] noid-integrity-check flag present: $flag"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] noid-integrity-check flag missing: $flag"
    fi
done

# noid-firefox-create-isolated-profile must source the firefox-profiles helper
# (single source of truth for profile management)
if grep -qF "/usr/local/lib/noid-privacy/firefox-profiles.sh" /usr/local/bin/noid-firefox-create-isolated-profile; then
    checks=$((checks + 1))
    log "  [OK] noid-firefox-create-isolated-profile sources firefox-profiles helper"
else
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] noid-firefox-create-isolated-profile not sourcing firefox-profiles helper"
fi

# noid-firefox-create-isolated-profile must invoke helper functions
# ensure_profile() runs Firefox's headless -CreateProfile interface;
# apply_userjs() installs the embedded user.js (NOID_FF_USERJS_BASE) into the profile.
if grep -q "ensure_profile " /usr/local/bin/noid-firefox-create-isolated-profile && \
   grep -q "apply_userjs " /usr/local/bin/noid-firefox-create-isolated-profile; then
    checks=$((checks + 1))
    log "  [OK] noid-firefox-create-isolated-profile uses ensure_profile + apply_userjs"
else
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] noid-firefox-create-isolated-profile missing helper function calls"
fi

# ---- Phase 6b: cron.allow + at.allow defensive root-only ----
if verify_owned_regular /etc/cron.allow 644 && grep -qx root /etc/cron.allow; then
    checks=$((checks + 1))
    log "  [OK] /etc/cron.allow exists, mode 0644, contains root"
else
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] /etc/cron.allow missing/wrong mode/missing root entry"
fi
if verify_owned_regular /etc/at.allow 600 && grep -qx root /etc/at.allow; then
    checks=$((checks + 1))
    log "  [OK] /etc/at.allow exists, mode 0600, contains root"
else
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] /etc/at.allow missing/wrong mode/missing root entry"
fi

# ---- Module 33 is DOC + CLI only: no background artifacts ----
unit_hits=""
unit_find_rc=0
for unit_kind in timer service path socket; do
    unit_find_rc=0
    unit_hits=$(find /etc/systemd /usr/lib/systemd \
        \( -type f -o -type l \) \
        \( -name "noid-integrity-check.${unit_kind}" -o \
           -name "noid-firefox-create-isolated-profile.${unit_kind}" \) \
        -print 2>/dev/null) || unit_find_rc=$?
    if [ "$unit_find_rc" -ne 0 ]; then
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] cannot prove absence of Module 33 ${unit_kind} artifacts (find rc=$unit_find_rc)"
    elif [ -n "$unit_hits" ]; then
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] Module 33 CLI has an unexpected ${unit_kind}"
    else
        checks=$((checks + 1))
        log "  [OK] no Module 33 CLI ${unit_kind} exists"
    fi
done

# ---- No autostart entries ----
autostart_hits=""
autostart_find_rc=0
if [ -L /etc/xdg/autostart ]; then
    autostart_find_rc=1
elif [ -d /etc/xdg/autostart ]; then
    autostart_hits=$(find /etc/xdg/autostart -maxdepth 1 \
        \( -type f -o -type l \) \
        \( -name "noid-integrity-check*.desktop" -o \
           -name "noid-firefox-create-isolated-profile*.desktop" \) \
        -print 2>/dev/null) || autostart_find_rc=$?
fi
if [ "$autostart_find_rc" -ne 0 ]; then
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] cannot prove absence of Module 33 autostart artifacts (find rc=$autostart_find_rc)"
elif [ -n "$autostart_hits" ]; then
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] Module 33 ships an autostart (should be user-invoked only)"
else
    checks=$((checks + 1))
    log "  [OK] no XDG autostart entries (Module 33 is user-invoked only)"
fi

log "Verification: $((checks - fails))/$checks passed"
if [ "$fails" -gt 0 ]; then
    die "$fails verification check(s) FAILED"
fi

# ----------------------------------------------------------------------------
# Phase 9 — Write health stamp
# ----------------------------------------------------------------------------
PHASE="P9-stamp"
# M33_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "shared health-stamp directory drifted before Module 33 publication"
fi

verify_m33_health_stamp() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
            0:0:644:1 ] \
        && [ "$(wc -l < "$path")" -eq 10 ] \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_passed=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_total=' "$path" || true)" -eq 1 ] \
        && grep -qFx '# NoID Privacy — Module 33 Health Stamp' "$path" \
        && grep -qFx \
            '# Written at end of %post verification when all checks pass.' \
            "$path" \
        && grep -qFx \
            '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
            "$path" \
        && grep -qFx 'module=33' "$path" \
        && grep -qFx 'name=operational-hygiene' "$path" \
        && grep -qFx 'version=1' "$path" \
        && grep -qFx 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path" \
        && grep -qFx "checks_passed=$((checks - fails))" "$path" \
        && grep -qFx "checks_total=$checks" "$path"
}

STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-33-operational-hygiene.ok.XXXXXXXX") ||
    die "cannot create Module 33 stamp temporary file"
cat > "$STAMP_TMP" <<STAMP_EOF
# NoID Privacy — Module 33 Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.
module=33
name=operational-hygiene
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=$((checks - fails))
checks_total=$checks
STAMP_EOF

chown root:root -- "$STAMP_TMP"
chmod 0644 -- "$STAMP_TMP"
/usr/sbin/restorecon -F -- "$STAMP_TMP" \
    || die "cannot label Module 33 health-stamp candidate"
/usr/sbin/matchpathcon -V "$STAMP_TMP" >/dev/null \
    || die "Module 33 health-stamp candidate label differs"
verify_m33_health_stamp "$STAMP_TMP" \
    || die "staged Module 33 health-stamp contract is invalid"
sync -- "$STAMP_TMP" \
    || die "cannot sync Module 33 health-stamp candidate"

STAMP_PUBLICATION_ACTIVE=1
publish_root_file "$STAMP_TMP" "$STAMP" 644
STAMP_TMP=""
/usr/sbin/restorecon -F -- "$STAMP" \
    || die "cannot label published Module 33 health stamp"
/usr/sbin/matchpathcon -V "$STAMP" >/dev/null \
    || die "published Module 33 health-stamp label differs"
sync -- "$STAMP" \
    || die "cannot sync published Module 33 health stamp"
sync -- "$STAMP_DIR" \
    || die "cannot sync Module 33 health-stamp directory"
verify_m33_health_stamp "$STAMP" \
    || die "published Module 33 health-stamp contract is invalid"
STAMP_PUBLICATION_ACTIVE=0
log "  [OK] exact Module 33 health stamp published atomically"
# M33_HEALTH_PUBLICATION_END

trap - EXIT HUP INT TERM
log "=== Module 33 Operational Hygiene complete ==="
%end

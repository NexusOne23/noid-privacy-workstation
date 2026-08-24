#!/usr/bin/env bash
# M18 structural regression: exact remote trust, native unit suppression,
# embedded-source parity, sandbox overrides and Silent-Machine behavior.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT=$(find_project_root)
KS="$ROOT/kickstart/snippets/18-flatpak-sandboxing.ks"
POLICY="$ROOT/scripts/noid-flatpak-remote-policy.sh"
DESCRIPTOR="$ROOT/manifests/flathub.flatpakrepo"
POLICY_REGEN="$ROOT/scripts/regen-flatpak-remote-policy-embed.sh"
DESCRIPTOR_REGEN="$ROOT/scripts/regen-flathub-descriptor-embed.sh"
RUNTIME="$ROOT/tests/pre-ship/18-flatpak-remote-runtime.sh"

test_start "18-flatpak-sandboxing-structural"

assert_file_exists "$KS"
assert_file_executable "$POLICY"
assert_file_exists "$DESCRIPTOR"
assert_file_executable "$POLICY_REGEN"
assert_file_executable "$DESCRIPTOR_REGEN"
assert_file_executable "$RUNTIME" "three-pass Flatpak runtime gate is executable"
assert_cmd_success "M18 parses as Bash" bash -n "$KS"
assert_grep_fixed 'Fedora'\''s flatpak RPM Recommends p11-kit-server as a weak dependency.' \
    "$KS" "M18 records Fedora's actual p11-kit-server dependency strength"
assert_grep_fixed 'Do not add it solely to silence the session' "$KS" \
    "M18 keeps the optional PKCS#11 server an explicit compatibility choice"
assert_grep_fixed 'It is unrelated to X11 and' "$KS" \
    "M18 does not conflate PKCS#11 trust export with display access"
assert_cmd_success "Flatpak policy controller parses" bash -n "$POLICY"
assert_cmd_success "three-pass Flatpak runtime gate parses" bash -n "$RUNTIME"
assert_cmd_success "Flatpak policy embed is byte-identical" "$POLICY_REGEN" --check
assert_cmd_success "Flathub descriptor embed is byte-identical" "$DESCRIPTOR_REGEN" --check
assert_grep_fixed 'M26 separately adds jq for M25 + documented M29/M30 JSON checks' \
    "$KS" "M18 attributes jq to its actual package owner and consumers"
assert_not_grep 'Module 25 + image build steps' "$KS" \
    "M18 does not invent a jq build-step dependency"
assert_grep_fixed 'MIN_VER="1.18.1"' "$KS" \
    "Flatpak floor includes the August 2026 security release"
assert_grep_fixed 'XDP_MIN_VER="1.22.1"' "$KS" \
    "portal floor includes the June 2026 host-file security fixes"
assert_grep_fixed '| Portal CVE-2026-55888 | Arbitrary write access to nonexistent host files | 1.22.1 |' \
    "$KS" "SaveFiles advisory impact matches the upstream 1.22.1 release"
assert_grep_fixed '| Portal CVE-2026-55889 | Drag-and-drop/copy-paste theft via predictable transfer key | 1.22.1 |' \
    "$KS" "FileTransfer advisory impact matches the upstream 1.22.1 release"
assert_grep_fixed 'if [ -u /usr/bin/bwrap ]; then' "$KS" \
    "deprecated setuid bubblewrap mode is rejected"
assert_grep_fixed '| Flatpak CVE-2024-42472 | Symlink following in `--persist` | 1.14.10 / 1.15.10 |' \
    "$KS" "CVE-2024-42472 uses the upstream patched-version floor"
assert_grep_fixed '| Flatpak GHSA-2fxp-43j9-pwvc | OCI system-helper symlink following permits arbitrary file reads | 1.16.4 |' \
    "$KS" "CVE-less Flatpak system-helper advisory is identified accurately"
for advisory in \
    GHSA-8688-9x26-hhxj GHSA-qrwq-7qwx-q9rp GHSA-fqx6-vh4p-42cg \
    GHSA-8qxj-x646-phcm GHSA-9rww-v4mm-x4jg GHSA-v2gw-v9h5-9q4x \
    GHSA-jr92-2v97-wgvc GHSA-99wv-m8rp-g58x GHSA-w69g-9x8j-7p8f \
    GHSA-q4gr-vc25-57m5; do
    assert_grep_fixed "$advisory" "$KS" \
        "Flatpak 1.18.1 advisory is retained: $advisory"
done
assert_not_grep 'CVE-2025-4870\|1\.14\.8 / 1\.15\.10' "$KS" \
    "unrelated CVE and vulnerable Flatpak version cannot return"
assert_grep_fixed 'All ${#REQUIRED_PACKAGES[@]} required packages present' "$KS" \
    "package summary follows the verified package array"
assert_not_grep 'All 7 required packages\|Setting 5 global overrides\|5 global overrides applied' \
    "$KS" "maintenance prose cannot carry stale package or override counts"
assert_grep_fixed 'six defaults. Prove the native no-APP reset does not erase per-app state.' \
    "$RUNTIME" "runtime reset-boundary comment follows the exact six-rule policy"
assert_grep_fixed 'exact six global denies' \
    "$RUNTIME" "runtime success summary follows the exact six-rule policy"
assert_not_grep 'five defaults\|exact five global denies' \
    "$RUNTIME" "runtime prose cannot carry the stale five-rule count"

assert_eq 4040 "$(stat -c '%s' "$DESCRIPTOR")" \
    "reviewed Flathub descriptor has the pinned byte count"
assert_eq 3371dd250e61d9e1633630073fefda153cd4426f72f4afa0c3373ae2e8fea03a \
    "$(sha256sum "$DESCRIPTOR" | awk '{print $1}')" \
    "reviewed Flathub descriptor has the pinned SHA-256"
assert_grep_fixed 'TRUSTED_KEY_EXPORT_SHA256=8bdc20abc4e19c0796460beb5bfe0e7aa4138716999e19c6f2dbdd78cc41aeaa' \
    "$POLICY" "canonical Flathub public-key export bytes are pinned"
assert_grep_fixed 'TRUSTED_KEY_FINGERPRINT=6E5C05D979C76DAF93C081354184DD4D907A7CAE' \
    "$POLICY" "full Flathub signing-key fingerprint is pinned"
assert_grep_fixed 'gpg-verify-summary' "$POLICY" \
    "summary-signature enforcement is a hard config postcondition"
assert_not_grep_extended 'http2|HTTP/2|multiplex' "$POLICY" \
    "controller no longer pins the removed Flathub transport workaround"
assert_not_grep 'configure_flathub_transport' "$POLICY" \
    "removed transport configurator cannot return"
assert_grep_fixed 'set(remote_sections) != expected_names' "$POLICY" \
    "default remote set is exact, not a name-presence check"
assert_grep_fixed 'actual_keys != expected_keys[name]' "$POLICY" \
    "every Flathub remote key is allowlisted exactly"
assert_grep_fixed 'Export the complete public' "$POLICY" \
    "trusted-key proof rejects additional signing keys"
assert_grep_fixed 'cannot enumerate installed system Flatpak refs' "$POLICY" \
    "failed installed-ref inventory aborts before reconciliation"
assert_grep_fixed 'cannot enumerate system Flatpak remotes' "$POLICY" \
    "failed remote inventory is distinct from an empty inventory"
assert_grep_fixed 'cannot enumerate installed system Flatpak origins' "$POLICY" \
    "Fedora opt-out cannot remove an update source after an origin-query failure"
assert_not_grep '--if-not-exists' "$POLICY" \
    "NoID Privacy remote reconciliation cannot accept a hostile pre-existing name"
assert_not_grep 'remote-delete --system --force' "$POLICY" \
    "remote reconciliation retains Flatpak's installed-ref protection"

assert_grep_fixed 'systemctl disable flatpak-add-fedora-repos.service' "$KS"
assert_grep_fixed 'systemctl mask flatpak-add-fedora-repos.service' "$KS"
assert_grep_fixed 'readlink -f /etc/systemd/system/flatpak-add-fedora-repos.service' "$KS"
assert_grep_fixed 'rm -f -- /var/lib/flatpak/.fedora-initialized' "$KS"
assert_not_grep 'touch /var/lib/flatpak/.fedora-initialized' "$KS" \
    "Fedora's private initialization sentinel is never forged"
assert_grep_fixed 'noid-toggle-fedora-flatpaks on' "$KS"
assert_grep_fixed 'fedora-testing is outside the explicit stable Fedora opt-in' "$POLICY"
assert_grep_fixed 'DRIFT (fedora-testing is present)' "$POLICY" \
    "Fedora status exposes the forbidden testing remote"
assert_grep_fixed 'new Fedora remote failed verification and was rolled back' "$POLICY" \
    "a newly added Fedora remote cannot survive failed identity verification"
assert_grep_fixed 'Fedora remote config metadata is not root:root 0644' "$POLICY" \
    "Fedora opt-in verifies root ownership and mode of the shared remote config"
assert_grep_fixed 'fails by design while' "$POLICY" \
    "controller help explains exact-default behavior during Fedora opt-in"
assert_grep_fixed 'The Fedora source is an OCI registry remote, not an OSTree repository.' \
    "$KS" "trust guide distinguishes Fedora OCI from pinned OSTree remotes"
assert_grep_fixed 'NoID Privacy does not pin an HTTP protocol for these remotes.' \
    "$KS" "trust guide delegates transport negotiation to maintained OSTree defaults"
assert_not_grep 'http2=false' "$KS" \
    "removed HTTP/2-disable workaround cannot return"
assert_grep_fixed 'expected to fail while the Fedora opt-in adds a third remote.' \
    "$KS" "trust guide documents verify-default semantics during opt-in"
assert_grep_fixed '## Fedora RPMs in GNOME Software' "$KS" \
    "trust guide documents the first-class native package view"
assert_grep_fixed 'The DNF5 plugin reads **all currently enabled DNF repositories**' \
    "$KS" "RPM view does not misrepresent enabled repository scope"
assert_grep_fixed '## AppImage: per-application opt-in only' "$KS" \
    "trust guide documents AppImage as an explicit exception"
assert_grep_fixed 'does not install `appimaged`' "$KS" \
    "AppImage guidance preserves the silent-machine default"
assert_grep_fixed 'observes that teardown every 250 ms for' "$KS" \
    "RPM guidance documents the visible graceful-shutdown interval"
assert_grep_fixed 'at most 90 seconds' "$KS" \
    "RPM guidance documents the bounded complete-quit wait"
assert_grep_fixed "trap '[ -z \"\$work\" ] || rm -rf -- \"\$work\"' EXIT" "$POLICY" \
    "trusted-key scratch cleanup covers every helper exit"
assert_grep_fixed 'chmod 0750 /usr/local/libexec/noid-flatpak-remote-policy' "$KS" \
    "internal Flatpak controller stays root-executable only"
assert_grep_fixed 'install -o root -g root -m 0755' "$KS" \
    "user-facing Flatpak toggle retains unprivileged status access"
assert_grep_fixed 'echo "$program: $*" >&2' "$POLICY" \
    "controller diagnostics name the actual public or internal entry point"
assert_not_grep 'echo "noid-flatpak-remote-policy: $*"' "$POLICY" \
    "public toggle errors do not name the root-only helper"

assert_grep_fixed 'flatpak override --system --system-no-talk-name=org.freedesktop.systemd1' "$KS"
assert_grep_fixed 'flatpak override --system --system-no-talk-name=org.freedesktop.PackageKit' "$KS"
assert_grep_fixed 'flatpak override --system --no-talk-name=org.freedesktop.Flatpak' "$KS"
# org.freedesktop.systemd1 is owned on BOTH buses: by PID 1 on the system bus
# and by the per-user manager on the session bus. --system-no-talk-name writes
# only into [System Bus Policy], so the session-bus twin is what actually
# closes StartTransientUnit against the user manager -- the same total-escape
# class already closed for org.freedesktop.Flatpak one line above.
assert_grep_fixed 'flatpak override --system --no-talk-name=org.freedesktop.systemd1' "$KS" \
    "the per-user systemd manager is denied on the session bus as well"
assert_grep_fixed "flatpak override --system --nofilesystem='~/.ssh'" "$KS"
assert_grep_fixed "flatpak override --system --nofilesystem='~/.gnupg'" "$KS"
assert_grep_fixed 'flatpak override --system --reset' "$KS" \
    "M18 clears only the compose-owned global override before exact publication"
assert_grep_fixed 'verify_exact_global_overrides' "$KS" \
    "M18 final verification rejects extra global grants or denials"
assert_grep_fixed '"Context": {"filesystems": "!~/.ssh;!~/.gnupg;"},' "$KS" \
    "M18 exact override verifier retains both sensitive-directory denies"

assert_grep_fixed '/usr/share/doc/noid-privacy/18-flatpak-trust-model.md' "$KS"
assert_grep_fixed '## The effective sandbox is per app' "$KS" \
    "trust guide distinguishes the empty default from effective app permissions"
assert_grep_fixed "the app's signed Flatpak metadata" "$KS"
assert_grep_fixed 'system-wide global and per-app overrides' "$KS"
assert_grep_fixed 'dynamic portal grants' "$KS"
assert_grep_fixed 'Such user-mediated grants are separate from static' "$KS" \
    "trust guide distinguishes document-portal access from static overrides"
assert_grep_fixed 'explicit one-run `flatpak run` arguments' "$KS"
assert_grep_fixed 'not, by itself, a sandbox escape' "$KS" \
    "declared authority is not mislabeled as an implementation escape"
assert_not_grep 'Flatpak provides no security boundary that protects the OS' "$KS" \
    "fabricated upstream quotation cannot return"
assert_grep_fixed 'This is a deliberate reduction of an upstream interface' "$KS"
assert_grep_fixed 'interface is an implementation vulnerability.' "$KS"
assert_grep_fixed '## Why we block host service-management interfaces globally' \
    "$KS" "trust guide discloses systemd and PackageKit compatibility costs"
assert_grep_fixed 'flatpak override --user --talk-name=org.freedesktop.systemd1 "$APP_ID"' \
    "$KS" "trust guide documents a per-app user-manager exception"
assert_grep_fixed 'flatpak override --user --system-talk-name=org.freedesktop.systemd1 "$APP_ID"' \
    "$KS" "trust guide documents a per-app PID 1 exception"
assert_grep_fixed 'flatpak override --user --system-talk-name=org.freedesktop.PackageKit "$APP_ID"' \
    "$KS" "trust guide documents a per-app PackageKit exception"
assert_grep_fixed 'flatpak override --user --system-no-talk-name=org.freedesktop.PackageKit "$APP_ID"' \
    "$KS" "trust guide documents precise PackageKit exception revocation"
assert_grep_fixed 'Bash does not currently tilde-expand it after' "$KS" \
    "nofilesystem quoting rationale describes Bash accurately"
assert_not_grep 'shell does NOT expand' "$KS" \
    "nofilesystem rationale does not claim quoting is the sole expansion guard"
assert_grep_fixed 'flatpak remote-info --system --show-commit flathub-verified' "$KS"
assert_grep_fixed 'flatpak remote-info --system --show-metadata flathub-verified' "$KS"
assert_grep_fixed 'flatpak install --system flathub-verified com.github.tchx84.Flatseal' "$KS"
assert_grep_fixed 'Flatpak, not a NoID Privacy trust anchor.' "$KS"
assert_not_grep 'currently needs no network permission' "$KS" \
    "mutable Flatseal permissions are not frozen into a timeless verdict"
assert_grep_fixed 'Per-app user overrides can deliberately relax' "$KS" \
    "Flatseal authority is not misrepresented as an extra sandbox"
assert_not_grep 'manifest-audited and trust-clean' "$KS"
assert_not_grep 'unverified publisher on' "$KS"
assert_not_grep 'Flatseal is the only GUI' "$KS"
assert_grep_fixed 'flatpak override --user --socket=ssh-auth "$APP_ID"' "$KS"
assert_grep_fixed 'flatpak override --user --socket=gpg-agent "$APP_ID"' "$KS"
assert_grep_fixed 'They still delegate cryptographic authority' "$KS" \
    "agent sockets are not misrepresented as authority-free"
assert_grep_fixed "flatpak override --user --filesystem='~/.ssh:ro'" "$KS"
assert_grep_fixed "flatpak override --user --filesystem='~/.gnupg:ro'" "$KS"
assert_grep_fixed 'flatpak override --user --nosocket=ssh-auth "$APP_ID"' "$KS"
assert_grep_fixed "flatpak override --user --nofilesystem='~/.ssh'" "$KS"
assert_grep_fixed 'Manifest and system-wide overrides still apply.' "$KS" \
    "reset semantics do not erase lower-precedence policy"
assert_not_grep 'no GUI/Flatpak app legitimately needs' "$KS"
assert_not_grep 'Near-zero-breakage' "$KS"
assert_grep_fixed '! -x /usr/local/bin/noid-flatseal-install.sh' "$KS"
assert_grep_fixed '! -f /etc/systemd/system/noid-flatseal-install.service' "$KS"
assert_grep_fixed '! -L /etc/systemd/system/multi-user.target.wants/noid-flatseal-install.service' "$KS"
assert_not_grep 'tee -a /var/log/ks-18-flatpak-sandboxing.log' "$KS" \
    "%post output is not duplicated into its own anaconda log"
assert_grep_fixed 'live|fresh-install|reboot) ;;' "$RUNTIME" \
    "Flatpak runtime gate accepts the exact three lifecycle identities"
assert_grep_fixed 'policy=/usr/local/libexec/noid-flatpak-remote-policy' "$RUNTIME"
assert_grep_fixed 'verify_root_file "$policy" 750' "$RUNTIME" \
    "runtime gate checks the internal controller mode"
assert_grep_fixed 'verify_root_file "$toggle" 755' "$RUNTIME" \
    "runtime gate checks the user-facing helper mode"
assert_grep_fixed 'cmp -s -- "$repo_policy" "$policy"' "$RUNTIME" \
    "runtime gate binds the installed controller to canonical repository bytes"
assert_grep_fixed 'cmp -s -- "$expected_trust_doc" "$trust_doc"' "$RUNTIME" \
    "runtime gate binds the installed trust guide to its canonical M18 heredoc"
assert_grep_fixed 'rpm -V "${platform_packages[@]}"' "$RUNTIME" \
    "runtime gate verifies every Flatpak platform RPM payload"
assert_grep_fixed 'key id $fedora_key' "$RUNTIME" \
    "runtime gate authenticates Fedora 44 package signatures"
assert_grep_fixed 'matchpathcon -V "$path"' "$RUNTIME" \
    "runtime gate verifies SELinux labels on owned and trust-state files"
assert_grep_fixed '"$policy" verify-default --online' "$RUNTIME" \
    "runtime gate verifies current signed catalogs instead of optional cache state"
assert_not_grep 'cached-catalog policy failed' "$RUNTIME" \
    "runtime gate cannot treat an evictable summary cache as durable trust state"
assert_grep_fixed 'legacy per-remote HTTP transport override remains' \
    "$RUNTIME" "runtime gate independently rejects legacy transport overrides"
assert_grep_fixed 'flatpak-add-fedora-repos.service' "$RUNTIME"
assert_grep_fixed '/var/lib/flatpak/.fedora-initialized' "$RUNTIME"
assert_grep_fixed 'remote_inventory=$(flatpak remotes' "$RUNTIME" \
    "runtime remote inventory failure cannot be hidden by process substitution"
assert_grep_fixed 'global Flatpak overrides are not the exact six-rule policy' "$RUNTIME" \
    "runtime gate rejects every extra or missing global override"
assert_grep_fixed 'global reset removed per-app state or retained global state' "$RUNTIME" \
    "runtime gate proves global reset preserves isolated per-app state"

test_finish

# ============================================================================
# Module 26 — Package Set Consolidation
# Status: LOCKED 2026-08-02 (v61) — ship dormant WireGuard tooling so kernel tunnels can be pinned.
#
# Covers:
#   - Explicit declaration of implicit @workstation deps used by other
#     modules (libnotify, python3-audit, zenity,
#     python3-gobject, GTK4, libadwaita, vte291-gtk4, curl, jq, unzip, git,
#     cryptsetup, NetworkManager OpenVPN integration,
#     libdnf5-plugin-actions, GNOME 50 compatibility retentions)
#   - Productivity Tier-1 (Fedora-main only): thunderbird, keepassxc, git,
#     btop, 7zip, unar, nmap, tmux, btrfs-assistant
#   - Audit/forensics tier: hdparm, vim-common (xxd), tpm2-tools, sqlite
#   - Media codec baseline (gstreamer1-plugin-libav/dav1d +
#     libva-intel-media-driver + libva-utils); Live-ISO support trio; Plymouth theme
#     plugin + fonts; trademark rebrand (generic-logos/-release-notes)
#   - @workstation exclusions (network/account-integrating GNOME apps, SMB,
#     printing, Exchange,
#     classic-session, cockpit meta, guest-tools, fedora-bookmarks, ...)
#   - BlueZ MPRIS user proxy remains preset-disabled until a separate explicit
#     media-control opt-in; Btrfs Assistant's authenticated root UI and tmux's
#     dormant system-service template are verified and documented
#   - %post verification CHECK 1-6 (MUST_PRESENT / MUST_ABSENT arrays) +
#     OPTDOC user doc; Anaconda consumes canonical locale codes independently
#     of glibc's normalized `.utf8` display spelling
#
# Tier-1 selection criteria: Fedora main · native RPM · DNF update path · no
# default-enabled background service/listener/autostart · no redundant default.
# Dormant package-owned activation surfaces must remain disabled and be
# disclosed rather than being mislabeled as absent.
#
# Deliberate deviations (do NOT re-litigate):
#   - The Fedora release package split is RETAINED deliberately. Fedora's
#     documented Remix recipe instead replaces it with generic-release, and
#     the Fedora 44 solver permits that swap. However, the current
#     generic-release-common preset payload is not equivalent to the current
#     fedora-release-common payload. NoID Privacy therefore retains the
#     Fedora release split for its validated presets/runtime while M32
#     overlays public product identity and dnf5 actions re-assert that
#     overlay. fedora-logos is replaced by generic-logos; Fedora 44 has no
#     fedora-release-notes binary package, so generic-release-notes is added
#     rather than presented as a package replacement.
#     This is a documented deviation, not a claim of following the complete
#     Fedora Remix package recipe.
#   - cockpit: exclude the META package only — sub-packages are hard-
#     required by anaconda-webui (Live-ISO needs it); the sockets/services
#     are masked in M08 (ghost-binary state). Excluding sub-packages breaks
#     the Anaconda solver.
#   - avahi is PRESENT for the GNOME 50 dependency chain. Its main package
#     includes both the core library and daemon/activation payload; M05 masks
#     avahi-daemon.service + .socket. Discovery-facing Avahi sub-packages and
#     PipeWire's optional RAOP/AirPlay discovery config stay excluded.
#   - Bluetooth pivot: bluez + gnome-bluetooth +
#     NetworkManager-bluetooth are INSTALLED but default-disabled +
#     rfkill-blocked (M08) — without the panel package the GNOME-Settings
#     BT toggle cannot exist. BlueZ's optional per-user MPRIS proxy is
#     separately preset-disabled here; bluez-cups stays excluded.
#   - gnome-tweaks REMOVED (optional UI already covered by NoID Privacy Welcome);
#     filezilla REMOVED (FTP not pre-installed on a privacy image — user directive);
#     unrar/p7zip-plugins replaced by FOSS unar/7zip (Fedora main).
#   - openh264 family is OPT-IN only (Cisco license bars redistribution);
#     -gstreamer1-plugin-openh264 excluded pre-opt-in (Silent-Machine
#     pure-state; explicitly requested by the Module 08 opt-in transaction).
#   - fedora-workstation-repositories dropped: shipped third-party
#     repo definitions without user opt-in; the only one NoID Privacy uses
#     (rpmfusion-nonfree-nvidia-driver) is NoID Privacy-owned in M08 Step 7a.
#   - GNOME 50 hard-dep retentions (samba-common, avahi, libreport-
#     filesystem, mdadm, iscsi-initiator-utils, libsmbclient,
#     libavformat-free, PackageKit-glib) are mixed compatibility payloads,
#     not a library-only set. Network activation is separately masked where
#     applicable; Fedora-conditioned local mdraid recovery/scrub units remain.
#     Explicit includes guard against weak-dep flips.
#   - yelp is deliberately KEPT for local GNOME help and accessibility. That
#     supported use needs no network; the viewer is not claimed network-incapable.
#
# Constraint notes (keep when editing):
#   - DRIFT-PROOF COMPLETENESS: every explicit %packages include/exclude
#     MUST be propagated to MUST_PRESENT / MUST_ABSENT (and CHECK 5 for
#     Tier-1) in the SAME commit — multiple incidents came from skipping
#     this. Arrays use dynamic ${#ARRAY[@]} counts (no static counter to drift).
#   - tests/26 pins: `-glibc-utils` line + the libc_malloc_debug.so.0
#     rationale comment in %packages (keep that comment) + vte291-gtk4 +
#     glibc-utils in MUST_ABSENT + OPTDOC path + noid-update-reminder.timer.
#   - livesys-scripts / anaconda-live / anaconda-install-env-deps are
#     removed post-install by M41 anaconda-cleanup — MUST_PRESENT is a
#     build-time-only assertion for those three.
#   - Do not try to create duplicate `.UTF-8` locale aliases with localedef:
#     glibc normalizes archive display names to `.utf8`, while Fedora 44
#     Anaconda's locale backend already accepts the canonical selections.
#
# Cross-reference:
#   - M05 (samba/avahi masks), M08 (BT engagement + repos + firstboot codec
#     tasks + service masks), M09 (openssh-server MUST_ABSENT), M16
#     (fedora-bookmarks/distribution.ini), M17 (extension enablement), M19
#     (NVIDIA absent at build, CHECK 4), M20 (snapper plugins absent), M22
#     (LUKS recovery CLI), M25
#     (vte291-gtk4 + orchestrator), M32 (identity restore + branding), M41
#     (live-pkg cleanup), M99 (cross-mod verify).
# ============================================================================

# ---------------------------------------------------------------------------
# Explicit dependencies used by other Modules but implicit via @workstation
# + Tier-1 productivity packages (9 Fedora-main-only)
# ---------------------------------------------------------------------------
%packages --exclude-weakdeps
# Module 12 (audit-notify), 13 (aide-notify), 25 (update-reminder)
libnotify

# Module 12 — maintained auparse feed binding for the opt-in auditd desktop
# notification plugin. Explicit because no installed package requires this
# Python binding and --exclude-weakdeps must not make event assembly optional.
python3-audit

# Module 10 — local AccountsService/useradd paths create homes through
# login.defs CREATE_HOME=yes + HOME_MODE=0700. Keep the unused privileged
# oddjobd D-Bus service and its PAM loader out of the Silent-Machine image;
# external-identity deployments must opt into their own provisioning path.
-oddjob
-oddjob-mkhomedir

# Module 20 (rollback prompt zenity dialog); also Module 25 noid-askpass
zenity

# Modules 13/25/36/37 — all four first-party apps require the Python GI, GTK4
# and libadwaita runtime; Update additionally embeds a GTK4 Vte terminal.
# Keep the complete GUI contract explicit instead of inheriting it accidentally
# from the current Workstation package group.
python3-gobject
gtk4
libadwaita
vte291-gtk4

# Module 16 (firefox-setup downloads uBlock Origin XPI — NoID Privacy user.js is
# embedded in the image, no runtime fetch needed post-absorption)
curl

# jq: required by M25's user-started GNOME-extension reconciliation and by
# documented M29/M30 JSON inspection commands. Keep it explicit so
# --exclude-weakdeps cannot remove those supported paths.
jq

# unzip: M13's pinned Claude/Codex VSIX installers; same weak-dep guard as jq.
unzip

# Git is used by VSCodium/agent development, source inspection and the
# documented offline/recovery workflows. Keep the ordinary Fedora `git`
# package explicit instead of inheriting it accidentally from @workstation.
# Do not install git-all: its CVS/SVN/Perforce/web/daemon integrations are not
# part of the base-image contract.
git

# Module 29 — provider-neutral native OpenVPN import. Fedora Workstation
# currently supplies the plugin and its GNOME authentication dialog through
# the product group; keep both explicit so the documented stock support path
# cannot disappear when comps membership changes. These packages configure no
# provider, profile, credential, listener or autostart. The post gate below
# rejects a future systemd/XDG activation or special-privilege surface.
NetworkManager-openvpn
NetworkManager-openvpn-gnome

# Module 06 — WAN-egress-strict discovers an unmanaged kernel WireGuard tunnel
# by reading `wg show all endpoints`. That discovery ships in the image; its
# only tool did not. A provider daemon driving the kernel through netlink
# (Mullvad and similar), wg-quick or systemd-networkd therefore brought up a
# tunnel this host could not enumerate: the endpoint was never pinned and an
# armed boundary dropped every handshake. Measured on the installed image --
# the peer's handshake timestamp stayed frozen until the package was present,
# and resumed immediately once it was. Two CLI binaries plus completions, no
# daemon, no autostart, no D-Bus, no SUID or file capabilities; the post gate
# below keeps the two shipped wg-quick units dormant.
wireguard-tools

# --- Module 08 — Bluetooth stack ----------------------
# Installed but default-disabled + rfkill-blocked at install time (M08
# Step 1f.5). Allows GNOME-Settings → Bluetooth panel + gsd-rfkill to toggle
# natively while keeping default OFF (UX-parity with mic/cam toggle pattern).
# noid-toggle-bluetooth CLI controls service-state + rfkill atomic.
# Reason for installing despite default-OFF: without gnome-bluetooth the
# GNOME-Settings BT-panel doesn't exist → no native toggle path.
bluez
gnome-bluetooth
NetworkManager-bluetooth

# --- Productivity Tier-1 (Fedora main, NoID Privacy policy-covered) ---
# Email + PGP. NoID Privacy's Thunderbird enterprise/AutoConfig policy disables
# background telemetry; this is an image policy, not an upstream default claim.
thunderbird
# Password manager (audited, offline-first)
keepassxc
# M17 selects native Wayland as the strict Qt application default. Fedora 44's
# KeePassXC 2.7.12 is Qt5, while @workstation otherwise supplies only its xcb
# platform plugin and Qt6 Wayland support. Without this Fedora-main package,
# KeePassXC aborts before opening. This is a load-bearing runtime dependency of
# NoID Privacy's selected default, not an optional weak dependency.
qt5-qtwayland
# filezilla removed — FTP/SFTP not pre-install on privacy-
# image per user directive. Users wanting FTP can `sudo dnf install filezilla`
# manually. SFTP available via `sftp` from openssh-clients (already installed).
# Modern CLI process monitor
btop
# gnome-tweaks deliberately NOT installed: NoID Privacy Welcome already provides the
# required app-autostart UI, so the broader optional preferences package is
# omitted from the base surface. GNOME dconf locks still take precedence over
# user-db writes if a user deliberately installs Tweaks later.
# Archive support (Fedora main, FOSS): 7zip = native 7z reader/writer
# (replaces p7zip in F44+); unar = RAR reader (RARv5 + encryption +
# multi-volume). No RAR-creation tool is selected for the base image.
7zip
unar
# Network scanner (security audit tool)
nmap
# Terminal multiplexer. Fedora's RPM also ships the manually enableable
# tmux@.service system template. It remains disabled by default; an ordinary
# interactive `tmux` invocation does not enable that boot-persistent unit.
tmux
# BTRFS snapshot/subvolume GUI (complements snapper CLI from M20).
# The audited Fedora 44 2.2-6 RPM has no packaged daemon, listener or autostart
# entry, but PolicyKit launches the COMPLETE Qt6 UI as root after administrator
# authentication. It exposes destructive subvolume/snapshot and service
# operations. M26 verifies that exact privilege/activation surface; M20's
# checked noid-snap-rollback remains the only supported NoID Privacy root
# rollback path. Re-audit this version-specific surface on update.
btrfs-assistant

# --- Audit/Forensics tier (manual CLIs: no daemons/listeners/autostart) ---
# - hdparm:     ATA identity/security/HPA/DCO/power queries; mutating and
#               destructive options also exist. SMART logs belong to smartctl.
# - vim-common: provides /usr/bin/xxd (vim-minimal does NOT ship it) — EFI
#               variable hex-dumps, TPM event log, binary inspection.
#               vim-enhanced deliberately not chosen.
# - tpm2-tools: tpm2_pcrread/quote/getcap/eventlog through the selected TCTI;
#               no daemon. Inspects TPM evidence but does not calculate fwupd HSI.
hdparm
vim-common
tpm2-tools
# - sqlite:     sqlite3 CLI — Firefox profile DB inspection (places/cookies/
#               formhistory content audits). It can write unless opened with
#               an explicit read-only mode; no daemon/listener/autostart.
sqlite

# --- GNOME Shell legacy tray-icon support (broader app-compat) ---
# Apps still expect tray icons (Thunderbird, KeePassXC, Element/Signal,
# Spotify) — without this their tray-only features silently disappear.
# D-Bus StatusNotifierItem bridge. The shipped Fedora build has no intended
# network role or telemetry feature; future versions remain an audit target.
# M17 enables the UUID
# (appindicatorsupport@rgcjonas.gmail.com) via dconf; install path
# /usr/share/gnome-shell/extensions/<UUID>/ is RPM-owned.
gnome-shell-extension-appindicator

# --- dnf5 actions plugin (identity persistence + nvidia hook) ---
# dnf5 does NOT load the dnf4 python post-transaction-actions plugin; NoID Privacy's
# action-files live under /etc/dnf/libdnf5-plugins/actions.d/. Two consumers:
# M32 noid-identity.actions (restores the NoID Privacy identity files on every
# fedora-release-* transaction) + M19 noid-nvidia-initramfs.actions
# (driver-only initramfs rebuild). This is the canonical native mechanism for
# the kickstart-delivered image.
libdnf5-plugin-actions

# --- Media codec stack (Fedora main + fedora-cisco-openh264 baseline) ---
# Build-time coverage: VP8/VP9 (ffmpeg-free + ffvpx), AV1 SW-decode (dav1d),
# Intel free-codec HW-decode (libva-intel-media-driver, stripped variant).
# First-boot opt-in via M08 firstboot Tasks 1-3 completes the stack: full
# ffmpeg plus the GStreamer Freeworld H.265 software decoder (RPM Fusion),
# Fedora-built/signed and Cisco-distributed OpenH264 RPMs, and the
# GPU-vendor-conditional driver swap (Intel → intel-media-driver, AMD →
# mesa-va-drivers-freeworld, every NVIDIA driver state = log-only with the
# active driver/iGPU profiles or sandboxed software fallback).
# Protected-media acceleration and resolution are not package-set
# postconditions: they depend on the browser, CDM and streaming service.
# Mozilla Bug 1700815 tracks Firefox/libva protected-content integration.

# H.264 (mozilla-openh264 + openh264) is OPT-IN only. Fedora builds and signs
# the RPMs; Cisco distributes them because its patent grant requires that
# distribution boundary. Derivative distros may not bundle the binaries.
# M08 ships the repo file (text only) + the firstboot install task; the user
# triggers it via Welcome → codecs.

# FFmpeg → GStreamer bridge (uses ffmpeg-free backing library from Fedora main)
gstreamer1-plugin-libav

# GStreamer AV1 decoder (patent-free, modern streaming sites use AV1)
gstreamer1-plugin-dav1d

# Fedora's service-free VA-API diagnostics, including vainfo. The mandatory
# codec release gate uses it in every lifecycle pass to enumerate only the
# profiles that the current Intel/AMD device actually advertises.
libva-utils

# Silent-Machine consent state: none of the three OpenH264 opt-in RPMs is
# present before consent (@workstation would otherwise pull this plugin).
# M25's upgrade exclusion covers the update path; this covers install time.
# Module 08 requests the plugin explicitly in the opt-in transaction.
-gstreamer1-plugin-openh264

# Intel VA-API driver (free codecs only — Fedora main; VP8/VP9/AV1 HW-decode
# on Intel iGPU). For H.264/H.265 HW-decode the RPM Fusion intel-media-driver
# is needed; covered by noid-complete-setup.sh for Intel users who want it.
libva-intel-media-driver

# --- Live-ISO support (Modernized Live Media pattern) ---
# Aligned with Fedora 44 upstream "ModernizeLiveMedia" change. Without these,
# the live ISO boots to tty1 with locked liveuser → no auto-login → no GDM.
# M41 anaconda-cleanup removes these packages and the liveuser/live-session
# configuration from a successfully installed target.
livesys-scripts          # Auto-config live env (creates liveuser GDM autologin
                         # at boot, configures graphical.target default for live)
anaconda-live            # Live install button + "Install to Hard Drive" icon
                         # on GNOME desktop (anaconda runs from live image)
anaconda-install-env-deps  # Deps for anaconda when running from live image

# --- Fedora Workstation / optional-stack EXCLUSIONS (matches Doc 26) ---
# These arrive through Fedora Workstation groups, weak dependencies or optional
# integrations, but are unneeded on a privacy-hardened image. Users can
# re-install them with `sudo dnf install <pkg>` — see the inventory in
# /usr/share/doc/noid-privacy/26-optional-packages.md.

# Network/account-integrating GNOME apps. Maps and Weather use online services
# when invoked; Calendar and Contacts integrate accounts the user configures.
# Exclusion minimizes optional network/account surface without claiming that
# every package phones home merely because it is installed.
-gnome-calendar
-gnome-clocks
-gnome-contacts
-gnome-maps
-gnome-weather

# GNOME first-run welcome slideshow (no value on hardened image)
-gnome-tour

# Cockpit: exclude the META package ONLY (loopback HTTP listener = needless
# attack surface). Excluding the sub-packages breaks the Anaconda solver;
# they stay installed via the anaconda-webui hard-dep (Live-ISO needs it)
# with cockpit.socket + cockpit.service masked in M08 — ghost-binary state.
-cockpit

# fedora-bookmarks: the template ships ~70 places.sqlite entries that
# Firefox imports into EVERY new profile via the distribution import path —
# the importBookmarksHTML/restoreDefaultBookmarks prefs do NOT block that
# code path. No source package = no template = no import.
-fedora-bookmarks

# GNOME-Classic mode + its extensions: legacy task-bar workflow, unused on
# modern GNOME-Wayland; the session hard-requires 4 of the 5 extensions.
# background-logo independently excluded (NoID Privacy ships own branding, M32).
-gnome-classic-session
-gnome-shell-extension-apps-menu
-gnome-shell-extension-places-menu
-gnome-shell-extension-window-list
-gnome-shell-extension-launch-new-instance
-gnome-shell-extension-background-logo

# SMB integration (conflicts with M05 LAN isolation — samba also excluded there)
-gvfs-smb
-cifs-utils

# PipeWire's optional RAOP config unconditionally loads its Zeroconf discovery
# module. That module links libavahi-client and requests org.freedesktop.Avahi
# whenever PipeWire starts, even though M05 deliberately masks the daemon.
# Base audio does not require this 35-byte configuration sub-package. Keep it
# out of the Silent-Machine baseline; the explicit opt-in and undo are
# documented in 26-optional-packages.md and M30's LAN-isolation guide.
-pipewire-config-raop

# Bluetooth GUI exclusion dropped (design pivot):
# gnome-bluetooth + NetworkManager-bluetooth are now INSTALLED (see
# Module 08 section in include block + MUST_PRESENT array). Default-
# state: bluetooth.service disabled + rfkill-blocked at install (M08).
# GNOME-Settings BT-toggle + noid-toggle-bluetooth CLI both work natively.
# bluez-cups stays excluded (CUPS-BT-printing is a separate concern below).

# Printing drivers (HP + gutenprint + BT-print). The CUPS activation units are
# separately masked by default; the user-facing doc gives an explicit package/
# service opt-in, privacy trade-off and complete undo.
-hplip
-gutenprint-cups
-bluez-cups

# Evolution Exchange Web Services plugin (only useful if user configures
# Microsoft Exchange in Evolution — irrelevant default bloat)
-evolution-ews-core

# `unar` is the selected Fedora-main RAR reader. Fedora also offers the
# separately named `unrar-free`; RPM Fusion nonfree offers `unrar`. Neither is
# needed beside the explicitly shipped `unar`, so keep `unrar` out explicitly.
-unrar

# NOTE: yelp (GNOME help viewer) is DELIBERATELY kept for accessibility.
# Reading installed GNOME Help needs no network. This supported local use does
# not imply that the general-purpose viewer is technically network-incapable.

# --- glibc debug-surface minimization (defense in depth) ---
# glibc-utils ships debug tools (mtrace, xtrace, memusage) + the libc_malloc_debug.so.0
# library. Current MALLOC_CHECK_ behavior requires that debug library to be
# preloaded. glibc 2.43 already disables MALLOC_CHECK_ for SUID/SGID programs.
# Excluding glibc-utils removes unused debug tooling/library as minimalism and
# defense in depth, not as the primary SUID safety boundary.
# Primary reference:
# sourceware.org/glibc/manual/2.43/html_node/Heap-Consistency-Checking.html
# Zero dependency impact: `dnf repoquery --whatrequires glibc-utils` returns
# empty — no package needs it.
-glibc-utils

# VMware guest tools: 1 SUID-root binary + 3 services, only useful as a
# VMware guest — not a supported environment (bare-metal + libvirt/qemu
# only). The M08 Q10 service masks become ghost-masks by design.
-open-vm-tools
-open-vm-tools-desktop

# VirtualBox guest additions: VBoxClient* + an xdg autostart entry, only
# useful as a VirtualBox guest — not a supported environment.
-virtualbox-guest-additions

# ============================================================================
# Fedora trademark assets — retained Fedora release runtime deviation
# ============================================================================
# Fedora's documented Remix package recipe removes Fedora-branded release and
# logo packages in favor of generic counterparts. On Fedora 44, fedora-logos
# is a real binary package while fedora-release-notes is not; this image
# replaces the logo package and adds generic-release-notes. It deliberately
# retains the Fedora release package split because generic-release is a real
# Fedora-provided replacement and the solver permits that swap, but
# generic-release-common's current system/user presets are not equivalent to
# the validated fedora-release-common payload. M32 overlays public identity
# files and the dnf5 actions plugin re-asserts them after release transactions.
# Audit basis: Fedora-signed generic-release-common-44-0.2 versus
# fedora-release-common-44-18; revalidate preset parity before migration.
# Primary references: fedoraproject.org/wiki/Remix and
# packages.fedoraproject.org/pkgs/generic-release/generic-release/
# A future own release RPM or generic-release migration requires preset-parity
# validation; this package block does not claim the complete Fedora Remix recipe.
-fedora-logos
generic-logos
generic-release-notes

# Privacy: drop fedora-workstation-repositories. It is a
# @workstation-product-environment DEFAULT member (not mandatory; nothing
# hard-requires it) that ships pre-configured third-party repo definitions
# (Google Chrome / PyCharm-COPR / Steam / rpmfusion-nonfree-nvidia-driver) —
# all disabled-by-default but present without any explicit user opt-in, which
# conflicts with the "no third-party repo unless the user asks for it" posture.
# The ONLY one NoID Privacy actually uses, rpmfusion-nonfree-nvidia-driver, is shipped
# NoID Privacy-owned in Module 08 Step 7a (enabled=0; Module 19 opt-in flips it on).
# A user who wants Chrome/Steam adds the repo explicitly (Chrome's own .rpm
# re-creates google-chrome.repo on install). Verified absent in MUST_ABSENT.
-fedora-workstation-repositories

# ============================================================================
# Plymouth theme plugin (M32 boot splash)
# ============================================================================
# M32 uses the stock bgrt theme (two-step plugin). plymouth-plugin-label
# provides the freetype text renderer the two-step password dialog uses to
# draw the LUKS prompt; plymouth-plugin-two-step pulls it in transitively, the
# explicit include guards against a weak-dep flip.
plymouth-plugin-label

# Plymouth font deps: upstream switched Cantarell → Adwaita Sans and the
# transitive font pull became unreliable — without a matching font in the
# initramfs, the theme's Image.Text returns a null sprite = INVISIBLE LUKS
# password prompt. Ship BOTH legacy + new fonts (M32's dracut drop-in
# additionally install_items+= them).
abattis-cantarell-fonts
abattis-cantarell-vf-fonts
adwaita-sans-fonts

# Emoji fonts: the welcome dialog's priority column uses emoji prefixes —
# defensive explicit add against weak-dep misclassification (tofu boxes).
google-noto-emoji-fonts

# GNOME 50 compatibility retentions. This is a mixed payload set: some are
# libraries/config only, while avahi, mdadm and iscsi-initiator-utils also
# contain service/socket/timer integration. Network activation is masked where
# applicable; Fedora-conditioned local mdraid recovery/scrub behavior remains
# for storage safety. Explicit includes override --exclude-weakdeps and
# transitive-exclusion paths.
#
# samba-common: config skeleton + /etc/samba/smb.conf (deleted in M05 STEP 6).
#   No daemon. Retained as the packaging companion of libsmbclient; current
#   verified hard-dependency anchors for libsmbclient are gnome-control-center
#   and libavformat-free. Do not infer consumers from desktop membership.
samba-common
# avahi: spice-webdavd requires this package; libsane-hpaio requires its
#   libraries. The package also owns daemon/D-Bus activation payload. M05
#   masks avahi-daemon.service + .socket, so the retained payload cannot start
#   the LAN-discovery daemon through those native activation paths.
avahi
# libreport-filesystem: paths only (/var/spool/abrt etc.), no daemon. Required
#   transitively by mdadm via udisks2 → libblockdev-mdraid chain.
libreport-filesystem
# mdadm: RAID utilities plus Fedora-conditioned local assembly/monitoring and
#   scrub units. M08 deliberately preserves those local safety paths for
#   detected mdraid instead of masking them; no network service is introduced.
#   Required by libblockdev-mdraid → udisks2 → gvfs → nautilus.
mdadm
# iscsi-initiator-utils: iSCSI initiator with service/socket/dispatcher
#   integration. M08 masks its native services/sockets and shadows the
#   NetworkManager dispatcher because no iSCSI targets are configured.
#   Required transitively by libvirt-daemon-driver-storage-iscsi →
#   libvirt-daemon-kvm → gnome-boxes.
iscsi-initiator-utils
# libsmbclient: SMB client library. No daemon. NEW hard-dep of gnome-control-
#   center 50.0-1 + libavformat-free 8.0.1-6 (Fedora F44 update).
libsmbclient
# libavformat-free: codec library required by gstreamer1-plugin-libav and
#   localsearch through its soname. Nautilus is not a direct consumer.
libavformat-free
# PackageKit-glib: GLib bindings for PackageKit (not the daemon!). Current
#   verified consumers are simple-scan and PackageKit-gstreamer-plugin; GNOME
#   Control Center is not used as a fabricated transitive justification.
#   PackageKit daemon itself remains excluded by Module 08 (-PackageKit +
#   -PackageKit-command-not-found) — only the .so library installs, no service
#   runs.
PackageKit-glib
%end

# ---------------------------------------------------------------------------
# %post — Module 26 post-install package verification
# ---------------------------------------------------------------------------
%post --erroronfail --log=/var/log/ks-26-package-set.log
set -euo pipefail

log() { echo "[noid-26-packages] $*"; }
log "=== Module 26 post-install: package verification ==="

verify_ok=0
verify_fail=0

# BlueZ ships mpris-proxy.service and Fedora's vendor user preset enables it.
# It bridges session MPRIS state to the Bluetooth system bus and is not needed
# for the default-off radio or for ordinary Bluetooth pairing and audio.
# Keep it dormant by default without masking it: a user who has already opted
# into Bluetooth may still explicitly enable the media-control bridge.
MPRIS_PRESET=/etc/systemd/user-preset/40-noid-bluetooth-media.preset
install -d -m 0755 -o root -g root /etc/systemd/user-preset
cat > "$MPRIS_PRESET" <<'MPRIS_PRESET_EOF'
# NoID Privacy — Bluetooth media controls are a separate explicit opt-in.
disable mpris-proxy.service
MPRIS_PRESET_EOF
chmod 0644 "$MPRIS_PRESET"
chown root:root "$MPRIS_PRESET"
systemctl --global disable mpris-proxy.service >/dev/null

# ====================================================================
# CHECK 1: Critical packages MUST be present
# ====================================================================
log "CHECK 1: critical packages present"

MUST_PRESENT=(
    # Module 01 — bootloader
    kernel kernel-core kernel-modules kernel-modules-core kernel-modules-extra
    dracut-live dracut-config-generic
    fwupd efibootmgr grubby mokutil shim-x64 grub2-efi-x64 crypto-policies
    # Module 03 — firewall
    firewalld libnftnl nftables bpftool iproute iproute-tc util-linux-core
    # Module 09 — SSH
    openssh-clients
    # Module 08 — Bluetooth stack installed but default-disabled
    # + rfkill-blocked. GNOME-Settings BT-panel works via gsd-rfkill while
    # default-state stays OFF. noid-toggle-bluetooth CLI + GNOME-Settings BT-
    # toggle both functional. Design pivot from MUST_ABSENT
    # to MUST_PRESENT. bluez-cups stays MUST_ABSENT (cups-BT-print
    # separate concern).
    bluez
    gnome-bluetooth
    NetworkManager-bluetooth
    # Module 14 — USBGuard (usbguard-dbus added to support
    # for GNOME gsd-usb-protection D-Bus integration / lock-popup parity with host)
    usbguard
    usbguard-dbus
    # Module 20 — Snapper
    snapper
    # Module 22 — user-facing LUKS header backup and verification CLI
    cryptsetup
    # Module 26 — explicit deps (python3-audit owns M12's auparse binding)
    libnotify python3-audit zenity curl
    # Modules 13/25/36 — complete first-party GTK application runtime
    python3-gobject gtk4 libadwaita vte291-gtk4
    # Explicit weak-dep guards (see %packages comments)
    jq
    unzip
    git
    # Module 29 — provider-neutral native OpenVPN import/authentication path
    NetworkManager-openvpn
    NetworkManager-openvpn-gnome
    # Module 06 — kernel-tunnel endpoint discovery for WAN-egress-strict
    wireguard-tools
    # Module 19 + M32 — dnf5 actions plugin. The nvidia-initramfs re-assert
    # (M19) + identity-restore (M32) action-files are inert without it; it is
    # an explicit %packages include, so verify presence (drift-proof guard).
    libdnf5-plugin-actions
    # Productivity Tier-1 (optional gnome-tweaks deliberately absent — see %packages)
    thunderbird keepassxc btop 7zip nmap tmux btrfs-assistant
    # Current Fedora Workstation GNOME application set documented below.
    # Keep this as a compose-time truth gate so a future group change cannot
    # silently leave the shipped inventory stale.
    papers showtime decibels snapshot loupe
    # M17 strict Qt Wayland default requires this for Qt5 KeePassXC.
    qt5-qtwayland
    unar
    # Audit/forensics tier
    hdparm
    vim-common
    tpm2-tools
    sqlite
    # Codec stack baseline
    gstreamer1-plugin-libav
    gstreamer1-plugin-dav1d
    libva-utils
    libva-intel-media-driver
    # Plymouth theme plugin (M32 bgrt = two-step + label)
    plymouth-plugin-label
    # Live-ISO support (build-time-only assertion — M41 removes these post-install)
    livesys-scripts
    anaconda-live
    anaconda-install-env-deps
    # Trademark rebrand replacements
    generic-logos
    generic-release-notes
    # Welcome-dialog emoji rendering
    google-noto-emoji-fonts
    # Plymouth font deps (invisible-LUKS-prompt guard)
    abattis-cantarell-fonts
    abattis-cantarell-vf-fonts
    adwaita-sans-fonts
    # GNOME 50 mixed compatibility retentions (see %packages comments)
    samba-common
    avahi
    libreport-filesystem
    mdadm
    iscsi-initiator-utils
    libsmbclient
    libavformat-free
    PackageKit-glib
    # GNOME Shell tray-icon bridge (M17 enables via dconf)
    gnome-shell-extension-appindicator
)

for pkg in "${MUST_PRESENT[@]}"; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
        verify_ok=$((verify_ok + 1))
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] package missing: $pkg"
    fi
done
log "  MUST_PRESENT: ${#MUST_PRESENT[@]} checked"

# ====================================================================
# CHECK 1b: Dormant/privileged package surfaces match the reviewed contract
# ====================================================================
log "CHECK 1b: package activation and privilege surfaces"

mpris_state=$(systemctl --global is-enabled mpris-proxy.service 2>/dev/null || true)
if [ -f "$MPRIS_PRESET" ] && [ ! -L "$MPRIS_PRESET" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$MPRIS_PRESET" 2>/dev/null || true)" = \
             0:0:644:1 ] \
        && [ "$(sha256sum "$MPRIS_PRESET" 2>/dev/null | awk '{ print $1 }')" = \
             aa2550c4376d482c1372bca0c3a3a4653d4b541e6e6cd25081875721fc09664c ] \
        && [ "$mpris_state" = disabled ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] BlueZ MPRIS proxy is preset-disabled and globally disabled"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] BlueZ MPRIS proxy default-off policy is incomplete (state=${mpris_state:-unknown})"
fi

tmux_service_state=$(systemctl is-enabled tmux@.service 2>/dev/null || true)
if [ "$tmux_service_state" = disabled ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] optional tmux@.service template remains disabled"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] optional tmux@.service template is not dormant (state=${tmux_service_state:-unknown})"
fi

openvpn_activation_paths=$(rpm -ql NetworkManager-openvpn \
        NetworkManager-openvpn-gnome 2>/dev/null \
    | grep -E '/systemd/(system|user)/|/xdg/autostart/|/dbus-1/(services|system-services)/' \
    || true)
openvpn_special_privileges=$(rpm -q --qf \
    '[%{FILEMODES:perms} %{FILECAPS} %{FILENAMES}\n]' \
    NetworkManager-openvpn NetworkManager-openvpn-gnome 2>/dev/null \
    | awk '$1 ~ /[sS]/ || $2 != "(none)" { print }' \
    || true)
if [ -z "$openvpn_activation_paths" ] \
        && [ -z "$openvpn_special_privileges" ] \
        && rpm -V NetworkManager-openvpn NetworkManager-openvpn-gnome \
            >/dev/null 2>&1; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] native OpenVPN integration is passive until a profile is selected"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] native OpenVPN integration gained an unreviewed activation or privilege surface"
fi

# wireguard-tools ships two units, unlike the OpenVPN plugin: wg-quick.target
# and the wg-quick@.service template. Both are inert by construction -- the
# target carries no [Install] and the template needs an explicit instance name
# to enable -- so they are allowed by exact name and their dormancy is asserted
# rather than assumed. Any third activation path, an XDG autostart entry, a
# D-Bus service or a special-privilege file is a contract change and fails.
wireguard_activation_paths=$(rpm -ql wireguard-tools 2>/dev/null \
    | grep -E '/systemd/(system|user)/|/xdg/autostart/|/dbus-1/(services|system-services)/' \
    | grep -vxE '/usr/lib/systemd/system/wg-quick(\.target|@\.service)' \
    || true)
wireguard_special_privileges=$(rpm -q --qf \
    '[%{FILEMODES:perms} %{FILECAPS} %{FILENAMES}\n]' \
    wireguard-tools 2>/dev/null \
    | awk '$1 ~ /[sS]/ || $2 != "(none)" { print }' \
    || true)
wg_target_state=$(systemctl is-enabled wg-quick.target 2>/dev/null || true)
wg_template_state=$(systemctl is-enabled wg-quick@.service 2>/dev/null || true)
if [ -z "$wireguard_activation_paths" ] \
        && [ -z "$wireguard_special_privileges" ] \
        && [ "$wg_target_state" = static ] \
        && [ "$wg_template_state" = disabled ] \
        && rpm -V wireguard-tools >/dev/null 2>&1; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] WireGuard tooling is present and its wg-quick units stay dormant"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] WireGuard tooling is not dormant (target=${wg_target_state:-unknown} template=${wg_template_state:-unknown})"
fi

BTRFS_ASSISTANT_POLICY=/usr/share/polkit-1/actions/org.btrfs-assistant.pkexec.policy
btrfs_surface_paths=$(rpm -ql btrfs-assistant 2>/dev/null \
    | grep -E '/systemd/(system|user)/|/xdg/autostart/|/dbus-1/(services|system-services)/|^/etc/(anacrontab|cron)' \
    || true)
btrfs_polkit_paths=$(rpm -ql btrfs-assistant 2>/dev/null \
    | grep -E '^/usr/share/polkit-1/(actions/.*\.policy|rules\.d/)' \
    || true)
btrfs_special_privileges=$(rpm -q --qf \
    '[%{FILEMODES:perms} %{FILECAPS} %{FILENAMES}\n]' \
    btrfs-assistant 2>/dev/null \
    | awk '$1 ~ /[sS]/ || $2 != "(none)" { print }' \
    || true)
BTRFS_ASSISTANT_OWNED_PATHS=(
    "$BTRFS_ASSISTANT_POLICY"
    /usr/bin/btrfs-assistant
    /usr/bin/btrfs-assistant-bin
    /usr/bin/btrfs-assistant-launcher
)
btrfs_owned_paths_ok=1
for path in "${BTRFS_ASSISTANT_OWNED_PATHS[@]}"; do
    if [ ! -f "$path" ] || [ -L "$path" ] \
            || [ "$(rpm -qf --qf '%{NAME}' "$path" 2>/dev/null || true)" != \
                 btrfs-assistant ]; then
        btrfs_owned_paths_ok=0
        break
    fi
done

if [ -n "$btrfs_surface_paths" ]; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Btrfs Assistant gained an unreviewed packaged activation surface"
elif [ "$btrfs_polkit_paths" != "$BTRFS_ASSISTANT_POLICY" ] \
        || [ -n "$btrfs_special_privileges" ]; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Btrfs Assistant gained an unreviewed privilege surface"
elif [ "$btrfs_owned_paths_ok" -ne 1 ] \
        || ! rpm -V btrfs-assistant >/dev/null 2>&1; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Btrfs Assistant Fedora RPM payload is missing or modified"
elif [ "$(stat -Lc '%u:%g:%a:%h' "$BTRFS_ASSISTANT_POLICY" \
          2>/dev/null || true)" != 0:0:644:1 ]; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Btrfs Assistant PolicyKit metadata is unsafe"
elif python3 - "$BTRFS_ASSISTANT_POLICY" <<'BTRFS_POLKIT_EOF'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
actions = root.findall("action")
if len(actions) != 1:
    raise SystemExit(1)
action = actions[0]
defaults = action.find("defaults")
if defaults is None:
    raise SystemExit(1)
expected_defaults = {
    "allow_any": "no",
    "allow_inactive": "no",
    "allow_active": "auth_admin",
}
for name, expected in expected_defaults.items():
    node = defaults.find(name)
    if node is None or (node.text or "").strip() != expected:
        raise SystemExit(1)
annotations = {
    node.attrib.get("key"): (node.text or "").strip()
    for node in action.findall("annotate")
}
if annotations.get("org.freedesktop.policykit.exec.path") != \
        "/usr/bin/btrfs-assistant":
    raise SystemExit(1)
if annotations.get("org.freedesktop.policykit.exec.allow_gui") != "true":
    raise SystemExit(1)
BTRFS_POLKIT_EOF
then
    verify_ok=$((verify_ok + 1))
    log "  [OK] Btrfs Assistant has no background activation and retains its authenticated root-UI boundary"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Btrfs Assistant PolicyKit root-UI contract changed"
fi

# ====================================================================
# CHECK 2: Unwanted packages MUST be absent
# ====================================================================
log "CHECK 2: unwanted packages absent"

MUST_ABSENT=(
    # Module 05 — LAN isolation
    # `avahi` (service-bearing main package) removed from MUST_ABSENT.
    # F44 GNOME 50 hard-deps avahi via gnome-control-center → spice-webdavd
    # → libsane-hpaio chain — cannot be excluded without breaking GNOME stack.
    # Sub-packages (autoipd + nss-mdns + tools) stay excluded — those are
    # the optional discovery additions. Module 05 masks the main package's
    # avahi-daemon.service and .socket activation paths.
    avahi-autoipd avahi-tools avahi-ui avahi-ui-tools nss-mdns
    # PipeWire AirPlay/Zeroconf discovery is an explicit opt-in. Without this
    # config sub-package, PipeWire does not request the masked Avahi daemon.
    pipewire-config-raop
    # Module 08 — service minimization
    abrt abrt-cli abrt-desktop abrt-dbus
    plocate gnome-software-rpm-ostree
    sssd sssd-common
    # Module 09 — SSH server (excluded in M09 %packages, must NOT be installed)
    openssh-server
    # Module 10 — native local home creation; no privileged oddjobd D-Bus
    # helper or PAM loader is shipped in the Silent-Machine baseline.
    oddjob oddjob-mkhomedir
    # Module 20 — real Fedora dnf4-only Snapper plugin exclusion. M20 and M99
    # separately enforce that no grub-btrfs RPM is installed; grub-btrfs is not
    # available in the audited Fedora 44 repositories, so counting its absent
    # package name here would provide vacuous green evidence.
    python3-dnf-plugin-snapper
    # Module 01 — BIOS legacy install path blocker
    # grub2-pc binary stays MUST_ABSENT (no active BIOS install).
    # grub2-pc-modules is REQUIRED for lorax Live-ISO build (hybrid El Torito).
    grub2-pc
    # Module 26 — @workstation-default exclusions (
    # gnome-bluetooth + NetworkManager-bluetooth REMOVED from MUST_ABSENT and
    # moved to MUST_PRESENT above — see Module 08 BT-stack section.
    # bluez-cups stays excluded as CUPS-BT-printing is separate concern.)
    gnome-calendar gnome-clocks gnome-contacts gnome-maps gnome-weather
    gnome-tour
    gvfs-smb cifs-utils
    hplip gutenprint-cups bluez-cups
    evolution-ews-core
    # Module 26 — glibc hardening
    glibc-utils
    # Fedora trademark rebrand: fedora-logos is a real replaced package and
    # generic-logos + additive generic-release-notes are in MUST_PRESENT.
    fedora-logos
    # fedora-workstation-repositories dropped in %packages
    # (Fedora-Workstation default-member shipping pre-configured Chrome/PyCharm/
    # Steam/nvidia-driver repo defs; nothing hard-requires it). The nvidia-driver
    # repo is now NoID Privacy-owned in Module 08 Step 7a. Verify the package is absent.
    fedora-workstation-repositories
    # Module 26 — replaced archive implementation
    unrar
    # Cockpit web-management exclusion
    # meta package only, sub-packages stay installed via
    # anaconda-webui hard-dep but cockpit.socket+cockpit.service masked in M08
    cockpit
    # VMware-guest-tools attack-surface trim
    # 1 SUID-root binary + 3 services removed
    open-vm-tools
    open-vm-tools-desktop
    # VirtualBox-guest-tools attack-surface trim: VBoxClient* autostart
    virtualbox-guest-additions
    # GNOME-Classic mode + 5 extensions
    # excluded — modern GNOME-Wayland-only, classic
    # task-bar workflow not used on hardened privacy image
    gnome-classic-session
    gnome-shell-extension-apps-menu
    gnome-shell-extension-places-menu
    gnome-shell-extension-window-list
    gnome-shell-extension-launch-new-instance
    gnome-shell-extension-background-logo
    # GStreamer OpenH264 plugin
    # Silent-Machine consent state requires all three OpenH264 opt-in RPMs to
    # remain absent pre-opt-in. Module 08 requests this plugin explicitly after
    # opt-in instead of depending on DNF weak-dependency policy.
    gstreamer1-plugin-openh264
    # Fedora bookmarks template
    # eliminates 70 places.sqlite entries Firefox imports
    # via distribution-defined bookmark-import path. Cross-ref M16 distribution.ini.
    fedora-bookmarks
)

for pkg in "${MUST_ABSENT[@]}"; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] unwanted package present: $pkg"
    else
        verify_ok=$((verify_ok + 1))
    fi
done
log "  MUST_ABSENT: ${#MUST_ABSENT[@]} checked"

# ====================================================================
# CHECK 3: Persistent weak-dependency policy (/etc/dnf/dnf.conf)
# ====================================================================
# The source test verifies every %packages header. Runtime cannot infer why a
# package is absent (python3-dnf-plugin-snapper is explicitly excluded), so do
# not present that confounded package as proof. Verify the persistent DNF policy
# that applies to later transactions instead.
log "CHECK 3: persistent weak-dependency policy"
if ! grep -qiE '^[[:space:]]*install_weak_deps[[:space:]]*=[[:space:]]*(0|false)[[:space:]]*$' \
        /etc/dnf/dnf.conf; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] /etc/dnf/dnf.conf does not disable weak dependencies"
else
    verify_ok=$((verify_ok + 1))
    log "  [OK] persistent install_weak_deps policy is disabled"
fi

# ====================================================================
# CHECK 4: No NVIDIA RPMs at build time (Module 19 doc-only)
# ====================================================================
log "CHECK 4: NVIDIA RPMs absent at build time"
nvidia_count=$(rpm -qa 2>/dev/null | grep -ciE '^(akmod-nvidia|kmod-nvidia|nvidia-settings|nvidia-persistenced|xorg-x11-drv-nvidia)' || true)
nvidia_count=${nvidia_count:-0}
if [ "$nvidia_count" -gt 0 ]; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] ${nvidia_count} NVIDIA RPM(s) found (Module 19 is doc-only)"
else
    verify_ok=$((verify_ok + 1))
    log "  [OK] no NVIDIA RPMs at build time"
fi

# ====================================================================
# CHECK 5: Productivity Tier-1 packages installed
# ====================================================================
log "CHECK 5: Productivity Tier-1 packages (v2)"
# p7zip → 7zip (matches NoID Privacy %packages migration)
# gnome-tweaks was removed from the nonessential base package surface.
# unar and btrfs-assistant are covered here, in MUST_PRESENT and in OPTDOC.
# qt5-qtwayland is verified immediately after this nine-package loop as a
# load-bearing KeePassXC runtime dependency, not as a tenth Tier-1 product.
for pkg in thunderbird keepassxc git btop 7zip unar nmap tmux btrfs-assistant; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
        verify_ok=$((verify_ok + 1))
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] Tier-1 package missing: $pkg"
    fi
done
if [ "$(rpm -qf --qf '%{NAME}' /usr/lib64/qt5/plugins/platforms/libqwayland-generic.so 2>/dev/null || true)" != qt5-qtwayland ]; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Qt5 Wayland platform plugin missing or not owned by qt5-qtwayland"
else
    verify_ok=$((verify_ok + 1))
fi

# ====================================================================
# CHECK 6: Optional-packages documentation shipped
# ====================================================================
# MOVED to AFTER the doc-write block — verification
# was firing BEFORE the doc was written, always reporting "missing".
# Verification now lives post-OPTDOC_EOF.

# ====================================================================
# Install /usr/share/doc/noid-privacy/26-optional-packages.md
# ====================================================================
# User-facing doc listing optional packages that were deliberately NOT
# shipped in the image (legal + Silent-Machine policy), with install commands.

mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/26-optional-packages.md <<'OPTDOC_EOF'
# Optional Packages (Not Pre-Installed)

The NoID Privacy Workstation image ships a minimal, privacy-focused baseline of
productivity packages (Module 26 Tier-1). Additional packages were
**deliberately excluded** to keep the image small and avoid redistributing
those third-party payloads.

RPM Fusion free + nonfree repos are already enabled in this image, so
installing these packages takes one command each — `dnf` handles the rest.

## Installed only after explicit codec opt-in

The codec packages are handled by the deliberately disabled
`noid-firstboot-setup.service` (Module 08 Step 9). Nothing is fetched at first
boot automatically. Run `noid-complete-setup.sh` only if you want the listed
RPM Fusion / Cisco payloads installed on your system. The wrapper presents
four explicit phases and streams only the current invocation's DNF/task output;
the complete retained log remains `/var/log/noid-firstboot-setup.log`.

### `ffmpeg` (full codecs, replaces `ffmpeg-free`)
**Repo**: RPM Fusion FREE (patent-encumbered H.264 High / H.265 / AC-3 / DTS codecs)
**What happens**: `dnf swap ffmpeg-free ffmpeg --allowerasing` on first boot
**Result**: broader local and non-DRM media codec coverage. DRM services retain
their browser/Widevine and service-specific Linux limits.

### `gstreamer1-plugins-bad-freeworld` (GStreamer H.265 software decode)
**Repo**: RPM Fusion FREE
**What happens**: Task 1 installs the plugin together with the FFmpeg
completion.
**Result**: Showtime and other GStreamer applications keep a software H.265
decoder on systems where no usable VA-API/Vulkan hardware decoder exists.
The package is loaded on demand and adds no service, autostart or network
listener.

### OpenH264 + Mozilla/GStreamer bridges
**Repo**: fedora-cisco-openh264 (Fedora-built and Fedora-signed; Cisco
distributes the codec RPMs under its paid patent-grant arrangement);
`gstreamer1-plugin-openh264` comes from Fedora
**What happens**: Task 2 explicitly installs `openh264`, `mozilla-openh264`
and `gstreamer1-plugin-openh264` after opt-in
**Result**: Firefox WebRTC video calls (Element / Jitsi / Discord) with H.264
fallback plus GStreamer H.264 playback. Generic Firefox `<video>` H.264
playback remains covered by ffmpeg from the swap above.

### Distribution boundary

The image excludes these RPM Fusion/Cisco package payloads. They are downloaded
only after the user explicitly starts the codec-completion workflow. Patent
coverage varies by jurisdiction; this package boundary is not legal advice or
a universal claim that every remaining codec is patent-free.

### What's NOT in firstboot anymore

Earlier v3-v5 firstboot also installed `unrar` (RPM Fusion nonfree, RARLAB
payload) and `p7zip-plugins` (RPM Fusion free). Both were dropped in v6
because Fedora-main replacements cover the selected extraction/archive
use-cases without those RPM Fusion packages:

- `unar` (Fedora main) — handles RARv5 + encryption + multi-volume RAR
  extraction. NoID Privacy does not ship a RAR-creation tool.
- `7zip` (Fedora main, modern, replaces legacy `p7zip` in F44+) — native
  7z reader/writer and general archive utility.

Both are pre-installed at build time (M26 Tier-1) — no firstboot fetch
required.

### Re-run / troubleshooting

If the opt-in codec setup fails (no network, RPM Fusion temporarily
unreachable), the disabled service does not schedule itself for a later boot.
Resolve the reported cause and rerun the explicit command below.

Manual trigger if needed:

```bash
sudo systemctl start noid-firstboot-setup.service
journalctl -u noid-firstboot-setup.service
# Or run the script directly:
sudo /usr/local/bin/noid-firstboot-setup.sh
```

Status check:

```bash
ls -la /var/lib/noid-privacy/firstboot-setup-done.flag   # exists = all 3 tasks completed
cat /var/log/noid-firstboot-setup.log                    # full task log
```

---

## Manual install (if firstboot setup fails permanently)

```bash
sudo dnf swap ffmpeg-free ffmpeg --allowerasing
sudo dnf install gstreamer1-plugins-bad-freeworld
sudo dnf install openh264 mozilla-openh264 gstreamer1-plugin-openh264
```

## Excluded from default image (install if needed)

The packages below can arrive through Fedora Workstation default groups,
GNOME weak dependencies or optional integration stacks. NoID Privacy
**deliberately excludes** them for privacy, minimalism or an unnecessary
default integration surface. Each is a one-command fix if you need it.

### Network/account-integrating GNOME apps

Maps and Weather use online services when you invoke their online features;
Calendar and Contacts integrate accounts that you deliberately configure.
Clocks is grouped here as optional desktop functionality, not because merely
installing every listed package proves background communication. They are
excluded to minimize unused network/account integration in the default image.

```bash
# Install any subset you actually want
sudo dnf install gnome-calendar gnome-clocks gnome-contacts gnome-maps gnome-weather
```

### GNOME first-run welcome slideshow

```bash
# gnome-tour: first-boot slideshow introducing GNOME. Useless on hardened image.
sudo dnf install gnome-tour     # if you really want to see it
```

### SMB (Windows file sharing)

`gvfs-smb` and `cifs-utils` are excluded here; Module 05 also excludes the
`samba` server and `samba-client` CLI. `samba-common` stays installed as a
packaging companion of `libsmbclient`, while Module 05 removes its orphan
configuration files. Install these clients if you need to access a
Windows/NAS share:

```bash
sudo dnf install gvfs-smb cifs-utils
```

### AirPlay / RAOP output discovery

`pipewire-config-raop` is a small Fedora configuration sub-package that makes
every PipeWire start load the RAOP discovery module and request Avahi
Zeroconf. It is excluded so the default audio stack performs no dormant
AirPlay discovery and does not generate D-Bus activation attempts for the
masked Avahi daemon.

Install it only if you deliberately want PipeWire to participate in AirPlay
discovery:

```bash
sudo dnf install pipewire-config-raop
systemctl --user restart pipewire.service pipewire-pulse.service wireplumber.service
```

This changes the local PipeWire/Avahi client surface; it does **not** by itself
open NoID Privacy's XDP/TC, topology or firewalld LAN boundary. The stock
complete-LAN-isolation policy still blocks unsolicited multicast discovery,
and the exact-peer Network helper is not a global mDNS switch. Do not weaken
that boundary merely to silence an Avahi error.

Undo the package-side opt-in:

```bash
sudo dnf remove pipewire-config-raop
systemctl --user restart pipewire.service pipewire-pulse.service wireplumber.service
```

### Bluetooth

The Bluetooth stack and GNOME/NetworkManager control panels are installed so
the supported opt-in works without fetching packages. Radio/service state ships
**OFF by default** (rfkill soft-block + flag-file + udev enforcer, Module 08;
not a systemd mask). BlueZ also ships an optional per-user `mpris-proxy`
media-control bridge; NoID Privacy keeps that user service preset-disabled so
it cannot become a session background process merely because the package is
installed. To opt into the radio/audio stack:

```bash
sudo noid-toggle-bluetooth on
```

Basic pairing and Bluetooth audio do not require a boot-enabled MPRIS proxy.
If you deliberately want Bluetooth headset/device media controls bridged to
desktop MPRIS players, enable it separately after the Bluetooth opt-in:

```bash
systemctl --user enable --now mpris-proxy.service
```

Undo that extra background service before restoring the default-off stack:

```bash
systemctl --user disable --now mpris-proxy.service
sudo noid-toggle-bluetooth off
```

### Printing drivers

NoID Privacy excludes optional HP, Gutenprint and Bluetooth printer drivers
and masks CUPS activation by default. Opting in starts a local print daemon
and socket; cupsd may also use localhost IPP and DNS-SD client discovery
according to its active configuration. This increases local attack surface and
may generate printer-discovery traffic, while NoID Privacy's firewall and LAN
isolation remain in force. Install only the drivers you need, then activate
CUPS:

```bash
# Install the local authorization helper and only the needed driver set.
sudo dnf install cups-pk-helper

# HP printers (most common)
sudo dnf install hplip hplip-gui

# Gutenprint (many Canon/Epson/Brother)
sudo dnf install gutenprint-cups

# Bluetooth printers (rare)
sudo dnf install bluez-cups

# CUPS and all activation units are deliberately masked by default.
sudo systemctl unmask cups.service cups.socket cups.path
sudo systemctl enable --now cups.socket cups.path
```

Undo the persistent CUPS activation after removing any drivers you no longer
want:

```bash
sudo systemctl disable --now cups.path cups.socket cups.service
sudo systemctl mask cups.service cups.socket cups.path
```

### Exchange email

`evolution-ews-core` is the Microsoft Exchange Web Services plugin for the
Evolution email client. Only useful if you actually use Exchange:

```bash
sudo dnf install evolution-ews
```

### What stays in the image

For accessibility, `yelp` (GNOME help viewer) is **kept**. Reading installed
GNOME and application help needs no network. This supported local use is not a
claim that the viewer is technically unable to open external content.

## Graphics editors

### `gimp` — Raster image editor

**Status**: Fedora main (free software)
**Why not pre-installed**: Large optional application with a narrow use case.
Most users don't edit raster images on a privacy-hardened workstation.

```bash
sudo dnf install gimp
```

### `inkscape` — Vector graphics editor

**Status**: Fedora main
**Why not pre-installed**: Large package, narrow use case.

```bash
sudo dnf install inkscape
```

## Network auditing

### `wireshark` — GUI packet analyzer

**Status**: Fedora main
**Why not pre-installed**: Requires user-group setup + setcap for non-root
capture. Narrow security-audit use case, not baseline.

```bash
sudo dnf install wireshark
sudo usermod -aG wireshark $USER
# Log out + back in for group change to take effect
```

## Development / Power-user tools

### `neovim` — Modern vim fork

**Status**: Fedora main
**Why not pre-installed**: `vim-minimal` is base Fedora default. Power
users install their preferred editor.

```bash
sudo dnf install neovim
```

### `ripgrep` (rg), `fd-find` (fd), `bat`, `eza`, `tldr`

**Status**: All Fedora main.
**Why not pre-installed**: Optional power-user CLI bonus, not universal.

```bash
sudo dnf install ripgrep fd-find bat eza tldr
```

## Media

### `vlc` — Universal media player

**Status**: Fedora main/updates on Fedora 44
**Why not pre-installed**: `showtime` (GNOME Video Player) is already installed.
VLC remains optional when you prefer its interface or need additional
format/workflow support.

```bash
sudo dnf install vlc
```

### `obs-studio` — Screen recording / streaming

**Status**: Fedora main (also RPM Fusion)
**Why not pre-installed**: Large package, narrow use case (streamers).

```bash
sudo dnf install obs-studio
```

### `audacity` — Audio editor

**Status**: Fedora main on Fedora 44. The package is named `audacity`;
`audacity-free` is not a Fedora 44 package.
**Why not pre-installed**: Narrow use case.

```bash
sudo dnf install audacity
```

## What's already installed (Tier-1 shipped in image)

For reference, these Fedora-main packages ARE pre-installed:

- `thunderbird` — Email + PGP (Mozilla)
- `keepassxc` — Password manager
- `git` — Version control for VSCodium, agent, source-review and recovery workflows
- `btop` — Modern CLI process monitor
- `7zip` — 7z archive reader/writer (Fedora main, modern; replaces legacy `p7zip` in F44+)
- `unar` — RARv5 reader (Fedora main, FOSS alternative to RPM Fusion `unrar`)
- `nmap` — Network scanner
- `tmux` — Terminal multiplexer
- `btrfs-assistant` — BTRFS snapshot/subvolume GUI (complements snapper CLI)

Fedora's `tmux` RPM also contains a manually enableable `tmux@.service`
template. NoID Privacy leaves it disabled; invoking `tmux` normally starts only
the user's deliberate terminal session and does not create a boot service.

### Btrfs Assistant privilege and recovery boundary

The Fedora 44 `btrfs-assistant` package starts its complete Qt interface as
root through PolicyKit after administrator authentication. It has no packaged
daemon, listener or autostart entry in the audited 2.2-6 build, but the GUI
itself can delete/restore snapshots and subvolumes and can change Snapper or
Btrfs-maintenance service settings. Treat every Apply/Delete/Restore action as
a privileged system mutation, not as a read-only viewer.

For a NoID Privacy root rollback, do **not** use Btrfs Assistant's restore
button or raw `snapper rollback`. Use the checked platform workflow:

```bash
sudo snapper -c root list
SNAPSHOT_NUMBER=REPLACE_WITH_REVIEWED_NUMBER
sudo noid-snap-rollback "$SNAPSHOT_NUMBER"
```

That workflow validates the NoID Privacy default-subvolume, fstab, BLS and
boot-image contract. Snapper root snapshots do not include the separate
`/home` or `/var/lib/libvirt` top-level subvolumes, and snapshots are not
backups.

**GNOME Shell Extensions** (pre-installed system-wide, M17 enabled via dconf):

- **Just-Perfection** (`just-perfection-desktop@just-perfection`, v36) —
  GNOME Shell UI customization. NoID Privacy uses it to hide the empty
  events-button in the clock-menu (clean look when no calendars are
  configured). Build-time SHA-pinned download from extensions.gnome.org.
  Upstream: gitlab.gnome.org/jrahmatzadeh/just-perfection (GPL-3.0).
  M25's user-started Update workflow checks its fixed EGO identity, GNOME
  compatibility, archive structure, version and digest evidence, then can
  atomically advance it to a newer compatible EGO stable release. EGO does not
  provide an artifact signature, so this explicit HTTPS/validation boundary is
  weaker than an RPM signature and is never a background update.
- **AppIndicator + KStatusNotifierItem Support**
  (`appindicatorsupport@rgcjonas.gmail.com`) — legacy tray-icon support
  for apps that minimize-to-tray (Thunderbird, KeePassXC, Element,
  Signal, Spotify). GNOME Shell dropped native tray years ago; this
  bridges D-Bus tray-events to the shell panel. Official Fedora RPM,
  upstream github.com/ubuntu/gnome-shell-extension-appindicator (GPL-2.0).
  Updated in user-started DNF transactions.

Both extensions are local UI components. The pinned Just-Perfection source and
the shipped AppIndicator build have no intended network/telemetry feature in
this audit; that is a version-specific observation, not a promise about future
updates.
Full rationale + opt-in extensions for power-users:
[gnome-extensions-autostart.md](gnome-extensions-autostart.md).

**Audit / Forensics tools** (pre-installed for hardware audit):

- `hdparm` — ATA identity, security, HPA/DCO and power-state queries. SMART
  health/log inspection belongs to `smartctl`, not `hdparm`. Use case:
  post-refurb-purchase audit of pre-owner ATA-password state and supported
  drive-capability inspection.
  Some flags can change or erase drive state; the shipped audit workflow uses
  query operations only.
- `vim-common` — provides `/usr/bin/xxd`. Hex/binary dump for EFI variable
  forensics, TPM event log analysis, general binary inspection. `vim-minimal`
  (Fedora base) does NOT ship `xxd`. `vim-enhanced` deliberately NOT chosen —
  user installs full vim per choice.
- `tpm2-tools` — `tpm2_pcrread`, `tpm2_quote`, `tpm2_getcap`, `tpm2_eventlog`.
  Uses a selected TPM Command Transmission Interface (commonly the kernel
  resource-manager device) and adds no service. These commands inspect TPM
  capabilities, PCRs, quotes and event logs; fwupd, not `tpm2-tools`, computes
  the holistic Host Security ID (HSI) attributes.
  Reference: [fwupd HSI documentation](https://fwupd.github.io/libfwupdplugin/hsi.html).
- `sqlite` — `sqlite3` CLI. Firefox profile DB inspection
  (`places.sqlite`/`cookies.sqlite`/`formhistory.sqlite` content audit),
  general SQLite-format diagnostics. The CLI can write databases unless you
  explicitly open them read-only; it adds no daemon, listener or autostart.

All four are manually invoked CLIs with no enabled daemon, network listener or
autostart. They are not globally read-only: `hdparm` and some TPM commands can
mutate device state when explicitly given destructive options. Total disk
impact in the currently audited Fedora 44 package builds is approximately
42 MiB (mostly `vim-common`); future RPM sizes may change.

Plus base Fedora Workstation stack:
- Firefox (NoID Privacy Firefox Hardening v1.0 derived from arkenfox v144.0, M16) + uBlock Origin
- LibreOffice (Writer/Calc/Impress/Draw/Base/Math)
- Papers, Showtime, Decibels, Snapshot, Loupe
- VSCodium (codium, via paulcarroty upstream repo, M08)
- @virtualization (libvirt + qemu-kvm + virt-manager)

**After explicit codec opt-in** (via `noid-complete-setup.sh`):
- `ffmpeg` (full codecs, RPM Fusion free) — replaces `ffmpeg-free`
- `gstreamer1-plugins-bad-freeworld` (RPM Fusion free) — software H.265
  coverage for GStreamer applications
- `openh264` + `mozilla-openh264` + `gstreamer1-plugin-openh264`
  (Fedora-built/signed; codec Cisco-distributed) — Firefox WebRTC and
  GStreamer H.264 coverage

## Compliance profile measurement

No profile-specific OpenSCAP result is bundled, and component-name overlap is
not evidence of compliance. Profile availability, rule content and status are
defined by the exact installed `scap-security-guide` build. Inventory that
version and its profile IDs first, then select the exact profile required by
your organization:

```bash
sudo dnf install scap-security-guide openscap-scanner
DATASTREAM=/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml
EVIDENCE_STAGE="$(sudo mktemp -d /var/tmp/openscap-noid.XXXXXX)"
EVIDENCE_DEST="$(mktemp -d "$HOME/openscap-noid-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"
sudo chmod 0700 "$EVIDENCE_STAGE"
sudo rpm -q scap-security-guide openscap-scanner \
    | sudo tee "$EVIDENCE_STAGE/package-versions.txt" >/dev/null
sudo oscap --version | sudo tee "$EVIDENCE_STAGE/oscap-version.txt" >/dev/null
sudo oscap info "$DATASTREAM" \
    | sudo tee "$EVIDENCE_STAGE/profile-inventory.txt" >/dev/null

# Copy one exact Profile ID from profile-inventory.txt after review.
PROFILE_ID='xccdf_org.ssgproject.content_profile_REPLACE_ME'
sudo oscap xccdf eval --profile "$PROFILE_ID" \
    --results "$EVIDENCE_STAGE/results.xml" \
    --report "$EVIDENCE_STAGE/report.html" \
    "$DATASTREAM"
sudo chown -R -- "$(id -u):$(id -g)" "$EVIDENCE_STAGE"
find "$EVIDENCE_STAGE" -mindepth 1 -maxdepth 1 \
    -exec mv -t "$EVIDENCE_DEST" -- {} +
rmdir -- "$EVIDENCE_STAGE"
printf 'Evidence: %s\n' "$EVIDENCE_DEST"
```

Review every failed, not-applicable and not-checked rule against the selected
profile and retain the package versions, profile inventory, XML and HTML
outputs together. An OpenSCAP result measures only that versioned profile and
its evaluated rules; it does not certify NoID Privacy, guarantee a security level or
support a general ranking against another baseline.

Reference: [ComplianceAsCode Fedora profile guide](https://complianceascode.github.io/content-pages/guides/ssg-fedora-guide-index.html)

## Updates

All optional RPM installs go through `dnf`, so:

1. `/usr/local/bin/noid-update-all.sh` (Module 25) Step 2 runs the DNF upgrade
   with `--refresh`, `-y` and a command-priority
   `--setopt=*.pkg_gpgcheck=True` guard. Before OpenH264 opt-in it also excludes
   the three codec packages so an Obsoletes relation cannot cross the consent
   boundary.
2. Installed RPM updates arrive through the enabled Fedora `updates` and
   RPM Fusion updates repositories, subject to that signature policy.
3. Optional RPMs need no separate updater; non-RPM components retain their
   explicitly documented update mechanisms.

## Security updates

Run `/usr/local/bin/noid-update-all.sh` weekly. The Module 25 user timer starts
its Monday schedule at 10:00 with up to one hour of randomized delay
(`/etc/systemd/user/noid-update-reminder.timer`).
Manual update anytime:

```bash
/usr/local/bin/noid-update-all.sh
```

This handles the documented DNF, Flatpak and firmware steps, takes a Snapper
pre-snapshot when available, and checks against an existing user-owned AIDE
baseline. It does not accept AIDE drift or claim to cover every maintenance
task.
OPTDOC_EOF

chmod 644 /usr/share/doc/noid-privacy/26-optional-packages.md
chown root:root /usr/share/doc/noid-privacy/26-optional-packages.md

# ====================================================================
# CHECK 6 (relocated post-write)
# ====================================================================
log "CHECK 6: /usr/share/doc/noid-privacy/26-optional-packages.md shipped"
if [ -f /usr/share/doc/noid-privacy/26-optional-packages.md ]; then
    verify_ok=$((verify_ok + 1))
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] 26-optional-packages.md missing"
fi

# glibc intentionally displays archive names in normalized `.utf8` spelling;
# generating a second `.UTF-8` display alias is neither representable nor
# required by the Fedora 44 Anaconda locale backend. The live-runtime release
# gate verifies all 13 canonical installer selections instead.
log "Locale policy: use glibc normalized locales; no ineffective alias generation"

# ====================================================================
# Summary
# ====================================================================
log "Verification: ${verify_ok} OK, ${verify_fail} FAIL"

if [ "$verify_fail" -gt 0 ]; then
    log "=== Module 26 FAILED (${verify_fail} package verification failures) ==="
    exit 1
fi

log "=== Module 26 complete ==="
%end

# ============================================================================
# NoID Privacy Workstation 44 — Master Kickstart
# Source of truth: kickstart/snippets/*.ks (this file is the assembler)
# Status: LOCKED 2026-08-01 (v34) — record the Firefox profile and locale contract in module provenance.
#
# Purpose: Top-level kickstart file for livemedia-creator. Assembles all
# module snippets in dependency order, sets system-wide defaults, and
# declares the package environment (@^workstation + @virtualization +
# explicit libvirt-daemon-config-network for the Module 03 firewalld
# libvirt zone dependency).
#
# Build usage:
#   sudo -v
#   ./scripts/build-iso.sh
#
# The wrapper is the sole supported release path: it validates and flattens
# this assembler, stages pinned payloads, applies the live-compose-only
# storage/bootloader transformation, and runs the post-compose evidence gates.
#
# BUILD-TIME NETWORK REQUIREMENT:
#   The %post blocks in Module 08 (RPM Fusion + VSCodium), Module 16 (uBlock
#   Origin from GitHub), Module 17 (Just Perfection from EGO), Module 18
#   (flathub remote-add), and Module 35 (DKIM Verifier from GitHub) require
#   working HTTPS connectivity during the Anaconda %post chroot. External
#   origins include download1.rpmfusion.org, mirrors.rpmfusion.org, gitlab.com,
#   download.vscodium.com, github.com, extensions.gnome.org and dl.flathub.org.
#   Provider-neutral Module 29 imports no third-party VPN trust root.
#   Module 40 consumes only the build wrapper's locally staged, SHA-256-pinned
#   audit payload and has no runtime self-update. The Firefox hardening user.js
#   is EMBEDDED into the image — no build-time download.
#
# Snippet order (functional summary; detail lives in each module header):
#   01  bootloader + kernel cmdline + GRUB + Secure Boot
#   02  sysctl hardening (3 files; M07 adds its own privacy-network file)
#   03  firewalld + always-active block-lan-out + allow-host-ipv6 override
#   04  Native-ACD-safe permanent gateway/peer pinning + pre-up learner
#   05  LAN isolation (L5-L7) + resolved + NM
#   06  VPN zone enforcement dispatcher + WAN-egress-strict
#   07  IPv6 privacy + gai.conf + per-WAN disable
#   08  Service minimization + systemd unit hardening + dconf gnome-software
#   09  SSH hardening (client-only)
#   10  PAM + login security
#   11  chrony NTS-only (closed EU institutional set + minimum-source threshold)
#   11b Manual, evidence-first DNS diagnostics (no timer or auto-recovery)
#   12  SELinux + auditd (immutable -e 2)
#   13  AIDE + welcome notification (reads status files from later modules)
#   14  USBGuard + firstboot service + notifier
#   15  Intel ME / MEI mitigation (writes mei-status.txt)
#   16  Firefox hardening (embedded user.js + uBlock Origin XPI)
#   17  GNOME privacy + dconf lockdown + D-Bus overrides
#   18  Flatpak sandboxing (remote trust docs + D-Bus overrides; Flatseal optional)
#   19  NVIDIA + Secure Boot MOK documentation (manual opt-in)
#   20  Snapper snapshots + CLI rollback
#   21  Kernel module blacklisting (dual CIS: blacklist + install /bin/false)
#   22  LUKS/partitioning docs + header backup + mount/discard hardening
#   23  NetworkManager privacy (ethernet MAC rand + IPv6 off on ethernet/wifi)
#   24  Firmware / fwupd telemetry lockdown + documentation
#   25  Update process orchestrator + weekly reminder
#   26  Package set consolidation (explicit deps + verification sweep)
#   27  Hardware abstraction (I/O scheduler, earlyoom, zram)
#   28  Local AI stack documentation (doc-only, user opt-in)
#   29  Tier-A user docs
#   30  Tier-B user docs + noid-help CLI
#   31  Tier-C user docs
#   32  Branding (os-release + issue + trademark disclaimer + assets)
#   33  Operational hygiene docs + CLIs (user-invoked only, no timers)
#   34  Firefox Playground profile (amnesic second profile, after 16)
#   35  Thunderbird hardening (AutoConfig + DKIM Verifier + skel template)
#   36  NoID Privacy Network App (GTK4 front-end over audited network CLIs)
#   40  noid-audit bundle (SHA256-pinned, offline-first, no self-update)
#   37  NoID Privacy Tools App (after 40: verifies every curated helper)
#   41  Anaconda Live-ISO → HDD cleanup safety-net
#   42  Forensic retention (30-day caps on persistent forensic sources)
#   99  Finalize: cross-module sanity; AIDE trust remains user-owned/uninitialized
#
# Snippet order CRITICAL CONSTRAINTS:
#   - 99 must be LAST (final cross-module state verification)
#   - 13 must run BEFORE 14, 15 (their status files are read by the welcome
#     script, which tolerates missing files — order matters for verification)
#   - 01 must run before 99 (M99 verifies final bootloader artifacts/state)
#   - 11b must run AFTER 11 (imports DNS baseline + helper cross-refs)
#   - 34 must run AFTER 16 (depends on /usr/share/noid-firefox/user.js)
#   - 41 must run BEFORE 99 (liveuser/GDM/sudoers cleanup must precede the
#     final cross-module verification)
#   - 40 any position before 99 (independent supply-chain payload)
#   - 37 must run AFTER 40 (its build-time curated-helper verification
#     requires noid-audit, which Module 40 installs)
#   - 42 must run BEFORE 99 (M99 verifies its stamp via EXPECTED_STAMPS).
#     Its daily retention units are otherwise independent of M41's one-shot
#     installed-system cleanup; the adjacent numbering is organizational.
# ============================================================================

# ----------------------------------------------------------------------------
# System locale + keyboard + timezone (build-time defaults)
# ----------------------------------------------------------------------------
# End-users can change these via GNOME Settings after install. Build-time
# values are only for the live ISO boot session. Generic image ships with
# neutral us layout + UTC; end users re-select their region in
# gnome-initial-setup at first boot.
lang en_US.UTF-8
keyboard --vckeymap=us --xlayouts='us'
timezone UTC --utc

# ----------------------------------------------------------------------------
# Network (live session only)
# ----------------------------------------------------------------------------
# Module 03/04/05 configure runtime network behavior. This line only
# applies to the live boot session — NM profiles are created by end-user
# during install + first-boot.
# --noipv6: sets ipv6.method=disabled on the profile from the start.
# Without it the auto-generated profile defaults to ipv6.method=auto and
# races Module 02's default.disable_ipv6=1 (~50 NM "Read-only file system"
# journal errors before the Module 23 dispatcher flips the profile).
network --bootproto=dhcp --device=link --activate --onboot=on --hostname=noid-privacy --noipv6

# ----------------------------------------------------------------------------
# Authentication
# ----------------------------------------------------------------------------
# yescrypt is the hardened password hash since Fedora 35+ (Anaconda default).
# The legacy `auth` directive was removed in the Fedora 35 command set; no
# replacement is needed since yescrypt is the system default.
# Module 10 configures faillock + pwquality on top of this.

# Root account: LOCKED. Administration via wheel group + sudo (Module 10).
rootpw --lock


# Live user for the ISO boot session only. Kickstart creates it explicitly
# locked; Module 17 deliberately removes that lock for live-mode GDM auto-login
# and passwordless sudo. Module 41 removes the account and every privilege
# path from the installed system. The end-user account is created through
# GNOME Initial Setup on first boot of the installed system.
user --name=liveuser --groups=wheel --lock

# ----------------------------------------------------------------------------
# Services
# ----------------------------------------------------------------------------
# Individual Modules enable/disable their own services via systemctl in %post.
# This line only enables NetworkManager (required for boot) and Fedora's two
# live-media units. `firstboot` is a separate Kickstart command, not an F44
# system service; GNOME Initial Setup uses user units and must remain available
# to create the installed system's end-user account.
services --enabled=NetworkManager,livesys,livesys-late

# ----------------------------------------------------------------------------
# Selinux + firewall (baseline, Module 12 + 03 harden further)
# ----------------------------------------------------------------------------
selinux --enforcing
# --remove-service=ssh: Anaconda's Network-Configure-Task adds ssh to the
# default zone AFTER all %post stages; this directive makes pykickstart
# generate the offline-cmd without --service=ssh. M03 STEP 3b stays as
# idempotent defense-in-depth (it also strips ssh from the libvirt-to-host
# policy, which ships in the libvirt-daemon-config-network RPM
# independently of this directive). See the M03 header for the 3-layer
# ssh-strip architecture.
firewall --enabled --remove-service=ssh

# ----------------------------------------------------------------------------
# Storage (build-time live ISO)
# ----------------------------------------------------------------------------
# Source layout only (end-user installs partition interactively). The supported
# build wrapper always transforms this block before compose: the KVM path uses
# lorax's deterministic q35 IDE/AHCI `/dev/sda`, so the collapse program injects
# `--drives=sda`/`--ondisk=sda`; `--no-virt` uses dirinstall and performs no
# partitioning. Do not hardcode `vda` here. The wrapper also prepends
# `bootloader --location=none` for the disposable Live image.
zerombr
clearpart --all --initlabel
# The ESP and /boot directives keep the assembler valid as a standalone
# kickstart for source validation; no supported compose consumes them. The
# wrapper's collapse program removes them and keeps only the root anchor.
part /boot/efi --size=600 --fstype=efi
part /boot --size=1024 --fstype=ext4
# 12000 MiB: 10000 left only ~50 MiB free with RPM Fusion + codium and was
# too tight for the codium install scriptlets. Monitor: if `df -h /`
# post-install reports < 1 GiB free, update this anchor plus
# scripts/collapse-live-partition-layout.awk and scripts/build-iso.sh in one
# reviewed change (Anaconda surfaces a full disk only as a cryptic
# "transaction failed" error).
part / --size=12000 --fstype=ext4

# Live ISO doesn't install a bootloader to a final disk (the end-user
# installer does that). M01 owns the sole bootloader policy directive;
# scripts/build-iso.sh rewrites its first flattened occurrence to add
# `--location=none` for the disposable live-ISO compose only.

# ----------------------------------------------------------------------------
# Installation source
# ----------------------------------------------------------------------------
# Fedora 44 everything repo via metalink (adjust for local mirror if needed).
# NOTE: fedora-cisco-openh264 is intentionally NOT declared here — H.264 codec
# install is deferred to user opt-in via noid-complete-setup.sh (Module 08).
# Fedora builds and signs the OpenH264 RPMs; Cisco distributes those binaries
# because its paid patent grant requires Cisco to be the distributor.
# Derivative distros are not covered to bundle them. Shipping the .repo file
# (text config, no binaries) is fine; bundling the binaries in the ISO
# squashfs is not.
# These endpoints return Metalink XML, not a plain mirrorlist. Declaring the
# correct source type is required for Anaconda/DNF to consume repomd hashes and
# current update metadata. Restrict selected payload mirrors to HTTPS so an
# on-path peer cannot replay older, still-validly-signed repository content via
# a plaintext mirror during the compose transaction.
url --metalink="https://mirrors.fedoraproject.org/metalink?repo=fedora-44&arch=x86_64&protocol=https"
repo --name=fedora-updates --metalink="https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64&protocol=https"

# ----------------------------------------------------------------------------
# Package environment
# ----------------------------------------------------------------------------
# --exclude-weakdeps: prevent Recommends/Suggests from pulling back excluded
#   packages (critical for Module 05 samba/avahi, 08 PackageKit, 09
#   openssh-server exclusions).
# --inst-langs: extract locale data for 13 widely-used language families plus
#   the regional Firefox payloads behind Fedora's generic es/pt/zh aliases.
#   Fedora Workstation's comps defaults still request the complete glibc locale
#   catalog, so the explicit `-glibc-all-langpacks` below is load-bearing;
#   users can add more with `sudo dnf install glibc-langpack-<code>`.
#
# CRITICAL — the separator MUST be COLON (`:`), NOT comma: Anaconda passes
#   the list AS-IS to the RPM macro `%_install_langs`, whose parser splits
#   on colons. With commas only `en` matches (substring at position 0) and
#   every other language's locale files are silently skipped at RPM
#   extraction. Verify on the composed image with a retained core package:
#   compare `rpm -ql gnome-shell | grep -c '^/usr/share/locale/.*\.mo$'`
#   with `find /usr/share/locale -path '*/LC_MESSAGES/gnome-shell.mo' -type f
#   | wc -l`. The current F44 image retains 16 of 93 and their
#   locale bases are exactly ar,de,en,es,fr,it,ja,ko,nl,pl,pt,ru,zh. A
#   near-equal count means the filter did not apply; only English means the
#   separator regressed. Neither `rpm --eval "%_install_langs"` nor
#   `anaconda.mo` is valid: the macro reads `all` after the transaction,
#   Anaconda is installed after the filtered compose payload and M41 removes
#   it from the ordinary installed target.
#
# Core environment: @^workstation-product-environment = Fedora Workstation
#   full stack (GNOME, Nautilus, Firefox, LibreOffice, etc.)
#
# @virtualization: libvirt + qemu-kvm + virt-manager (Module 26 pre-lock
#   decision). Provides libvirt-daemon-config-network which ships the
#   firewalld libvirt zone REQUIRED by Module 03's block-lan-out policy
#   (<ingress-zone name="libvirt"/>). If @virtualization is removed, Module 03
#   conditionally removes the libvirt ingress-zone line at install time.
#
# Explicit adds: libvirt-daemon-config-network as hard ref to avoid any
#   weak-dep situation where @virtualization loses it.
%packages --exclude-weakdeps --inst-langs=en:de:fr:es:es_AR:es_CL:es_ES:es_MX:it:pt:pt_BR:pt_PT:nl:pl:ru:zh:zh_CN:zh_TW:ja:ko:ar
@^workstation-product-environment
@virtualization
libvirt-daemon-config-network
# M99's early-boot live-payload ACL repair uses getfacl/setfacl as a
# release-critical transport replacement, so do not rely on an incidental
# Workstation package dependency to retain the `acl` tools.
acl
# M22's user-facing LUKS header backup/verification workflow calls the
# cryptsetup CLI directly. The boot path can use systemd-cryptsetup instead,
# so do not rely on Workstation group membership to retain this user tool.
cryptsetup
# Explicit langpacks-* adds: --exclude-weakdeps strips the Recommends chain
# that normally pulls them from --inst-langs, leaving an English-only
# Welcome dropdown. langpacks-XX is an umbrella that Requires ONLY
# langpacks-core-XX + langpacks-fonts-XX; the per-app translation packs
# attach via weak `Supplements:` and need their own explicit block below.
# anaconda-l10n does not exist as an F44 package (installer translations
# are embedded in the anaconda RPM) — do not add it.
langpacks-en
langpacks-de
langpacks-fr
langpacks-es
langpacks-it
langpacks-pt
langpacks-nl
langpacks-pl
langpacks-ru
langpacks-zh_CN
langpacks-ja
langpacks-ko
langpacks-ar

# Fedora's workstation-product group includes glibc-all-langpacks as a default
# package. `--exclude-weakdeps` does not suppress group defaults, so exclude
# the complete catalog before retaining the reviewed 13-language set.
-glibc-all-langpacks

# Explicit glibc-langpack-XX: langpacks-core-XX pulls these only as
# Recommends, which --exclude-weakdeps blocks. Without them langtable
# returns no locales and the Anaconda Welcome screen shows ONLY English
# variants. List matches langpacks-XX above (13 language families).
# BEGIN GENERATED REQUIRED_GLIBC_LANGPACKS (from manifests/required-glibc-langpacks.tsv)
glibc-langpack-en
glibc-langpack-de
glibc-langpack-fr
glibc-langpack-es
glibc-langpack-it
glibc-langpack-pt
glibc-langpack-nl
glibc-langpack-pl
glibc-langpack-ru
glibc-langpack-zh
glibc-langpack-ja
glibc-langpack-ko
glibc-langpack-ar
# END GENERATED REQUIRED_GLIBC_LANGPACKS

# Explicit per-app language packs (attach via weak `Supplements:`, stripped
# by --exclude-weakdeps): without them Firefox / LibreOffice / spellcheck
# stay English-only on non-English installs. firefox-langpacks ships ALL
# locales in one package (M16 activates them via distribution/extensions/;
# the /usr/lib64/firefox/langpacks/ path is inert since FF 91, RH bug
# #2030190). pt → pt-BR + pt-PT, zh → zh-Hans + zh-Hant. Spell/hyphen/thesaurus
# packs are listed only where Fedora ships them (zh/ja: none; ko/ar: hunspell only).
firefox-langpacks
libreoffice-langpack-en
libreoffice-langpack-de
libreoffice-langpack-fr
libreoffice-langpack-es
libreoffice-langpack-it
libreoffice-langpack-pt-BR
libreoffice-langpack-pt-PT
libreoffice-langpack-nl
libreoffice-langpack-pl
libreoffice-langpack-ru
libreoffice-langpack-zh-Hans
libreoffice-langpack-zh-Hant
libreoffice-langpack-ja
libreoffice-langpack-ko
libreoffice-langpack-ar
hunspell-en
hunspell-de
hunspell-fr
hunspell-es
hunspell-it
hunspell-pt
hunspell-pt-BR
hunspell-nl
hunspell-pl
hunspell-ru
hunspell-ko
hunspell-ar
hyphen-en
hyphen-de
hyphen-fr
hyphen-es
hyphen-it
hyphen-pt
hyphen-pt-BR
hyphen-nl
hyphen-pl
hyphen-ru
mythes-en
mythes-de
mythes-fr
mythes-es
mythes-it
mythes-pt
mythes-nl
mythes-pl
mythes-ru

# Do NOT add `langtable-data` — the package does not exist on F44 (only
# langtable + python3-langtable); adding it fails the dnf transaction and
# aborts the build. The glibc-langpack-XX list above is the only fix needed
# for multi-language Anaconda Welcome support.

# gnome-user-share excluded (WebDAV file-sharing server — antithetical to
# the LAN-isolated posture) along with its whole httpd backend family
# (explicit, so dnf5 SRPM-family-expand cannot relink them).
# Do NOT attempt glusterfs excludes: they break @virtualization hard-deps
# (libvirt-daemon-driver-storage-gluster → glusterfs-fuse; qemu-kvm →
# libgfapi.so.0) and abort the build. 9.6 MB of inert libraries is the
# accepted cost — no glusterfs daemon runs by default.
-gnome-user-share
-httpd
-httpd-core
-httpd-tools
-httpd-filesystem
%end

# ============================================================================
# %post — Included snippets in dependency order
# ============================================================================
# Each snippet is self-contained with its own %post block + verification.
# Snippets are processed in %include order by Anaconda.
#
# IMPORTANT: 99-finalize.ks MUST be the last %include.

%include snippets/01-bootloader.ks
%include snippets/02-sysctl.ks
%include snippets/03-firewalld.ks
%include snippets/04-arp-hardening.ks
%include snippets/05-lan-isolation.ks
%include snippets/06-vpn-killswitch.ks
%include snippets/07-ipv6-privacy.ks
%include snippets/08-service-minimization.ks
%include snippets/09-ssh.ks
%include snippets/10-pam-login.ks
%include snippets/11-dns-ntp.ks
%include snippets/11b-dns-health.ks
%include snippets/12-selinux-auditd.ks
%include snippets/13-aide-welcome.ks
%include snippets/14-usbguard.ks
%include snippets/15-intel-me-mitigation.ks
%include snippets/16-firefox.ks
%include snippets/17-gnome-hardening.ks
%include snippets/18-flatpak-sandboxing.ks
%include snippets/19-nvidia-mok-docs.ks
%include snippets/20-snapper.ks
%include snippets/21-kernel-module-blacklist.ks
%include snippets/22-luks-partitioning.ks
%include snippets/23-networkmanager.ks
%include snippets/24-firmware-fwupd.ks
%include snippets/25-update-process.ks
%include snippets/26-package-set.ks
%include snippets/27-hardware-tuning.ks
%include snippets/28-local-ai-docs.ks
%include snippets/29-user-docs.ks
%include snippets/30-user-docs-tier-b.ks
%include snippets/31-user-docs-tier-c.ks
%include snippets/32-branding.ks
%include snippets/33-operational-hygiene.ks
%include snippets/34-firefox-playground.ks
%include snippets/35-thunderbird.ks
%include snippets/36-noid-network-app.ks
%include snippets/40-audit-bundle.ks
%include snippets/37-noid-tools-app.ks
%include snippets/41-anaconda-cleanup.ks
%include snippets/42-forensic-retention.ks

# Finalize MUST be last — runs cross-module verification and rejects any
# compose-created AIDE trust database
%include snippets/99-finalize.ks

# ----------------------------------------------------------------------------
# Reboot after install
# ----------------------------------------------------------------------------
reboot

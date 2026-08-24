# tests/ — NoID Privacy Workstation semantic test suite

Mandatory gate before marking a Module `LOCKED`. See `../CONTRIBUTING.md`
for the full policy.

## Run everything

The complete release gate requires `aide`, `bwrap`, `checkmodule`, `clang`,
GNU `base64`, `sha256sum` and `strip`, the libbpf and Linux UAPI development
headers, `dconf`, `desktop-file-validate`, `git`, `gsettings` with the GVfs
discovery schemas, `jq`, `ksvalidator`, `patch`, `python3` with the `auparse`
module, `semodule_package`, `setfacl`, `shellcheck`, `systemd-analyze`,
`systemd-tmpfiles`, `udevadm`, `usbguard`, `usbguard-notifier`, and `visudo`.
On Fedora 44:

```bash
sudo dnf install ShellCheck aide acl binutils bubblewrap checkpolicy clang dconf desktop-file-utils git glib2 gvfs jq kernel-headers libbpf-devel patch policycoreutils pykickstart python3 python3-audit sudo systemd systemd-udev usbguard usbguard-notifier
```

```bash
./tests/run-all.sh
```

Expected: all tests pass, exit 0. A missing full-suite prerequisite is a
test-harness error (exit 2), reported before any partial pass/fail summary.

## Run a subset

```bash
./tests/run-all.sh 22            # only M22-related tests
./tests/run-all.sh 29 welcome    # M29 + welcome-script tests
./tests/run-all.sh --verbose     # show per-check output even on pass
```

## Current tests

Full suite: **84 tests** via `run-all.sh` + **4 bwrap smoke tests** under
`tests/smoke/` = **88 test scripts total** (plus `lib.sh` + `run-all.sh`
helpers in both directories and the one-time `tests/smoke/prep-rootfs.sh`).
The table below is the complete structural list; discovery uses the same
`tests/[0-9][0-9]*-*.sh` shape as `run-all.sh`.

| Test | What it covers | Would catch |
|------|----------------|-------------|
| `00-anaconda-patch-structured.sh` | Retired RPM-error bypass + authenticated deterministic profile/mask updates image | reintroduced scriptlet suppression, unauthenticated base, archive drift or output replacement |
| `00-archive-signing-structural.sh` | Release-signed candidate/sign-off authentication plus fsynced atomic complete-tree archive | unsigned/tampered candidate, incomplete VM approval, partial copy or destination replacement |
| `00-rootfs-hygiene.sh` | Final Live-root machine identity, random seed, compose log and network/runtime-state absence contract plus real ISO extraction wrapper | build-host identity reuse, compose evidence leakage or a hygiene gate that never reaches the final SquashFS |
| `00-compose-sources.sh` | Fedora source type, compose identity/log policy and installed-VM freshness/AVC gate wiring | Metalink drift, unclassified installer errors, missing success markers or runtime release gates |
| `00-dnf-actions-structural.sh` | DNF5 action-file syntax and updater integration | malformed post-transaction hooks or missing redeploy action |
| `00-fedora-base-iso-trust.sh` | Fedora base-ISO signer/digest pin and canonical verifier call | unreviewed base media or verifier bypass |
| `00-pii-sweep.sh` | Public-tree Python-cache, PNG metadata, binary home-path, machine-id and MAC sweep plus fixtures | ignored bytecode, image author/time metadata or accidental host identity/path outside the synthetic allowlist |
| `00-source-generators.sh` | Shared strict CLI/marker/metadata/validate-before-publish contract for every generator | malformed input mutation, delimiter ambiguity, mode loss, symlink inclusion or non-atomic writes |
| `00-status-metadata.sh` | Module lock provenance + published repo-count parity | stale LOCKED dates, incomplete test inventory or README count drift |
| `00-syntax-sweep.sh` | `bash -n` on every .ks file | Syntax errors (typos, missing `fi`/quotes) |
| `01-shellcheck.sh` | Blocking ShellCheck pass over standalone test/build scripts when ShellCheck is installed | Unquoted vars, `[` vs `[[`, subshell traps |
| `02-shellcheck-heredocs.sh` | shellcheck on bash heredocs extracted from .ks | Heredoc body shellcheck warnings (audit) |
| `01-bootloader-structural.sh` | M01 manifest-backed exact cmdline surfaces + Secure Boot | comment-only false green, duplicate/conflicting family or source-surface drift |
| `02-sysctl-structural.sh` | M02 99-hardening.conf + 99-audit-fixes + 99-userns | sysctl param count drift, wildcard expansion |
| `03-firewalld-structural.sh` | M03 strict-wan + block-lan-out policy, including the host-only cross-layer DHCPv4 selector | ingress-zone regression, rule count drift, DHCP widening, peer/global grant shadowing or VM inheritance |
| `03b-lan-xdp-controller-state.sh` | Closed LAN-XDP state/map schemas, exact live identities and multi-NIC rollback | corrupt/cross-root state, name-only TC match, unsafe map reuse or wrong-mode rollback |
| `03c-firewalld-firstboot-runtime.sh` | Isolated all-physical firstboot zone/SSH/exact-IPv6-policy transaction | first-NIC-only enforcement, reload churn, false completion or hidden policy widening |
| `03d-lan-xdp-policy-digest.sh` | LAN-XDP fast path: identical enforced input plus live attachment skips the rebuild | stale enforcement after a skipped sync, forged/foreign digest sidecar or a fast path that never engages |
| `03e-lan-topology-coalescing.sh` | Topology-refresh coalescing decides on the boot clock, never the steppable wall clock | a chrony backward step discarding an unseen event, a stale pre-monotonic stamp skipping every refresh, or a targeted invocation being coalesced |
| `04-arp-hardening-structural.sh` | M04 closed state guard + permanent pin + awaited/no-wait dispatcher pair + native ACD contract | fail-open state/marker metadata, serialized post-activation regression, shadow-table regression, sandbox, neighbour-parser or dispatcher drift |
| `04-arp-transaction-fixture.sh` | M04 staged refresh/retained-identity pin opt-out, paired dispatcher publication, post-DHCP retry and exact rollback behaviour | stale/cross-interface cache reuse, unsafe lock/state, split awaited/no-wait copies, partial publication, signal/pre-up/up failure or unpinned active link |
| `05-lan-isolation-structural.sh` | M05 strict global/physical DNS policy, transactional physical-uplink DoT selector, the M23 tunnel-default boundary, masks, exception-state and boot/timer unit contracts | DNS scope/rollback drift, tunnel transport misattribution, service drift or reboot-volatile temporary grants |
| `05-lan-direction-fixture.sh` | M05 outbound/inbound/both CLI, state/export, exact firewalld and add/edit/revoke ordering | selector widening, schema drift or stale-permit transaction gaps |
| `05-lan-temp-expiry-fixture.sh` | M05 durable temporary-exception deadline/reconciliation behavior | reboot promotion, clock extension, invalid state or hidden revoke failure |
| `05-printing-toggle-fixture.sh` | M05 print-stack opt-in: which units it unmasks, activation entry points, failed-activation rollback and discovery-drift reporting | enabling printing re-opening mDNS/WSD discovery, an outright-enabled cupsd, a half-open state after a failed activation or a silent firewall change |
| `06-vpn-killswitch-structural.sh` | M06 dispatcher/WAN-strict publication, live-only WireGuard MTU source parity and inbound-DROP `noid-vpn` zone | ifcfg-less NM, NM-2.0 rename, profile mutation or MTU dispatcher drift |
| `06-wireguard-mtu-fixture.sh` | Lower-only active WireGuard MTU reconciliation across IPv4/IPv6, route ceilings, multiple/unresolved peers, IPv6 floor, lock trust and all-interface events | hard-coded MTU, profile ownership races, unsafe raise, partial-evidence mutation or IPv6 breakage |
| `07-ipv6-privacy-structural.sh` | M07 gai.conf + per-WAN sysctl | ra=0 removal, gai.conf drift |
| `07-ipv6-policy-transaction-fixture.sh` | M07 locked sysctl/status publication and fail-closed NM pre-up | hidden logger failure, unsafe metadata, concurrent hotplug, interruption or split durable state |
| `08-mask-list-structural.sh` | M08 mask-list, exact privileged helper bridge and dconf gnome-software | service-count drift, privilege widening or packagekit rename |
| `08-udisks2-mount-propagation-structural.sh` | M08 udisks2 mount propagation and sandbox exception | removable-media mounts hidden by an over-tight service sandbox |
| `09-ssh-structural.sh` | M09 sshd mask + client defaults | accidental un-mask, client config rot |
| `10-pam-structural.sh` | M10 faillock, pwquality, native yescrypt, login privacy, libvirt system-QEMU core ceiling, declarative permission policy, interactive umask, command-scoped DNF state umask and locked/atomic Bash-history compaction | PAM/hash/mode drift, privileged QEMU core-limit bypass, unreadable DNF state, obsolete chmod timer, global umask mutation, destructive prompt hooks or false history bounds |
| `11-chrony-nts-structural.sh` | M11 dated 6-source production/public NTS manifest + readiness-gated restricted client | source/status/config drift, pre-production dependency, pre-readiness traffic, minsources change |
| `11b-dns-diagnostics-structural.sh` | M11b manual evidence-first DNS diagnostics | background probe/recovery regression, fixed target or mutating default action |
| `12-auditd-structural.sh` | M12 SELinux + 132 dual-ABI audit rules including AIDE evidence + durable storage alert | ABI/time/login-session/AIDE-rule drift, suppression, immutable or failure-policy regression |
| `13-welcome-script.sh` | M13 Setup app plus shared GTK4/libadwaita identity, accessibility, AIDE and desktop contracts | split autostart/app-grid identity, duplicate windows, missing feedback, syntax or shared-contract drift |
| `13b-noid-status-structural.sh` | M13 noid-status diagnostic CLI — auditd/HSI/snapper/user-timer control-flow + JSON mode | HSI ANSI/colon truncation, inherited-session false unknown, auditd non-root or JSON field drift |
| `13c-autostart-netwait.sh` | M13 autostart network gate — physical-carrier classification and fail-open contract | a tunnel/dummy device opening the gate, or the wrapper preventing an app from starting |
| `14-usbguard-structural.sh` | M14 state machine, notifier and least-privilege named IPC contract | policy GC, broad group/parameter access, false permanent-notification claims or user-service rot |
| `15-intel-me-structural.sh` | M15 MEI blacklist + KT/SOL PCI IDs + AMD PSP docs | new PCI ID missing, mei_me regression |
| `16-firefox-structural.sh` | M16 NoID Privacy Firefox Hardening embed + uBO XPI + managed-storage | arkenfox absorption regression, XPI SHA256 drift |
| `17-gnome-hardening-structural.sh` | M17 dconf lockdown, transactional SW_LID/logind lid CLI, and split GNOME Software D-Bus-denial/explicit-launch overlays | desktop/laptop misclassification, partial lid apply, telemetry channel re-open or deliberate Software launch blocked |
| `17-lid-action-fixture.sh` | Isolated desktop/laptop lid-action lifecycle with native logind stubs | false SW_LID detection, unconfirmed suspend, failed-reload residue, lower-policy deletion or independent-file overwrite |
| `17-microphone-policy-fixture.sh` | Isolated PipeWire/WirePlumber microphone-policy lifecycle, helper and restart persistence | one-shot muting, unmute drift, new-source bypass, split GNOME/WirePlumber state or volatile settings |
| `17-privacy-cleanup-fixture.sh` | Custom-XDG GNOME tracking/thumbnail cleanup with Mozilla, symlink and mount substitutions | live-profile lock deletion, hidden-cache residue, symlink traversal, bind-mount deletion or preflight partial mutation |
| `17-user-firstrun-fixture.sh` | Isolated transactional per-user first-login task lifecycle including libvirt session compatibility | premature global completion, conflicting/symlinked QEMU config overwrite, swallowed task failure or non-retryable partial setup |
| `18-flatpak-remote-policy-fixture.sh` | Exact Flathub descriptor/config/key/catalog reconciliation and Fedora stable opt-in state machine | hostile existing names, key/config drift, empty catalogs, destructive ref migration or fedora-testing mutation |
| `18-flatpak-sandboxing-structural.sh` | M18 native Fedora-unit mask, source parity, 3 D-Bus + 2 filesystem overrides and three-pass gate wiring | private-sentinel workaround, Flatseal autoinstall or remote-trust regression |
| `19-gsk-renderer-toggle.sh` | M19 portable NVIDIA-offload matcher, post-Shell systemd activation environment, administrator precedence and reversible auto/on/off policy | AMD-only or NVIDIA-primary false match, Shell-wide renderer override, ineffective network sandbox, deprecated `ngl` or unsafe rollback |
| `19-nvidia-install.sh` | M19 helper/queue — GPU and branch policy, MOK identity, NVIDIA sleep default, shared-lock deferral and M21 image delegation | wrong package branch, stale MOK/module identity, independent Dracut writer, M21 reboot inhibitor race or incomplete all-kernel rollback |
| `19-nvidia-mok-docs-structural.sh` | M19 NVIDIA + Secure Boot MOK docs | doc heredoc truncation |
| `20-snapper-structural.sh` | M20 native default-subvolume model + checked create/status/rollback + measured retention fixture | unsafe fstab/BLS state, non-root mutation, interrupted-resume drift, clock/default mis-deletion |
| `21-kernel-modules-structural.sh` | M21 normalized module policy, Generic/host-only recovery transaction and canonical later Root/LUKS/Plymouth/MEI/Intel-GSC/NVIDIA validator | State/count drift, fake enforcement, storage/crypto/controller/GSC omission, unsafe publication, stale candidate or uncoordinated writer claim |
| `22-luks-backup-wrapper.sh` | M22 noid-luks-backup.sh helper — LUKS2 auto-detect, removable-media detect, SHA256 verify, --verify/--list-existing | helper deleted, refuse-root stripped, detection regex broken, filename convention changed |
| `22-luks-partitioning-mount.sh` | M22 `ensure_mount_options` helper against mock fstab | **The M22 sed-delimiter silent-fail bug.** Canonical E2E test. |
| `23-networkmanager-structural.sh` | M23 MAC privacy, physical IPv6 policy and native NetworkManager defaults: strict physical DoT plus best-effort opportunistic unset non-physical/VPN/private transport | hostname-mode regression, physical fail-open DNS, forced tunnel plaintext or a value rejected by NetworkManager's parser |
| `24-fwupd-structural.sh` | M24 telemetry/P2P off + exact refresh masks + boot-dormant on-demand daemon + Flatpak-only Software/three-pass Silent Machine gate | background update traffic, persistent fwupd, native-backend wakeup or broken manual firmware path |
| `25-update-process-structural.sh` | M25 update orchestrator/GUI, exact VTE ABI, honest completion state, user-owned AIDE check and locked canonical post-DNF boot-image validation | spawn/step/pin drift, false completion, AIDE trust mutation, uncoordinated kernel transaction or direct Dracut writer |
| `26-package-set-structural.sh` | M26 exclusions, Tier-1 apps, rebrand swap and explicit three-app Python-GI/GTK4/libadwaita/VTE runtime | exclusion or GUI-runtime dependency regression |
| `27-hardware-tuning-structural.sh` | M27 Fedora/kernel performance and EEE ownership, native udev/.link parsers, WoL + USB/SD noexec/external-NTFS policy and exact runtime-gate contract | returned scheduler/HWP/zram/EEE/sync/BDI bet, parser/WoL rule rot, removable-media execution or missing behavior gate |
| `28-local-ai-structural.sh` | M28 Option ordering (A=RamaLama, B=Ollama) | Regression of RamaLama-primary decision, llama-vscode/WebUI editor section or preserved CVE notes |
| `29-user-docs-heredoc.sh` | All 4 M29 Tier-A docs extract correctly + cross-module semantics and DNS CLI discoverability | Heredoc truncation; broken cross-links; VPN/GNOME/dconf/DNS claim drift |
| `30-live-payload-acl-parity-fixture.sh` | Rootless raw/SquashFS/installed offline-root fixture with absolute systemd enablement links | Host-root resolution of an image-root symlink and false ACL release-gate failure |
| `30-user-docs-tier-b.sh` | M30 6 Tier-B docs + noid-help CLI, including global DNS mode/recovery | doc or DNS-scope drift, CLI alias rot |
| `31-user-docs-tier-c.sh` | M31 operational docs + canonical threat/scope/PQ/performance/license sources | heredoc truncation, source parity, DNS/performance ownership or cross-ref drift |
| `32-avatar-face.sh` | M32 avatar + face-gallery — /etc/skel/.face{,.icon}, AccountsService backfill service + path-unit | missing avatar install lines, dconf override wrong path, accidental locks file |
| `32-include-count.sh` | master.ks %include references resolve + every snippet wired in (no orphans) | missing/orphan snippet, include-vs-snippet count mismatch |
| `32-plymouth-theme.sh` | M32 Plymouth bgrt theme — M26 label plugin, M21 sole transactional target-kernel Dracut writer + exact Plymouth candidate artifacts | label plugin/theme missing, competing M32 Dracut writer, candidate lacks branding |
| `33-config-validation.sh` | Fedora 44 pykickstart validation of flattened master.ks plus JSON/systemd/NM/desktop structure | Invalid Kickstart grammar or malformed generated configuration |
| `33-operational-hygiene-structural.sh` | M33 standards/live-evidence hygiene: 3 docs + 2 CLI + stamp + user-invoked-only invariant | doc truncation, unsupported security claims, CLI regression, unsafe payload publication, accidental service/timer ship or stamp-order violation |
| `34-amd-psp-doc-structural.sh` | M15 companion — AMD PSP hardware-layer doc | heredoc truncation, CVE notes removed |
| `34-firefox-playground-structural.sh` | M34 dual-profile: amnesic overrides + .desktop + dconf auto-pin + init script + packaged Firefox icon lookup + stamp | missing amnesic pref, dconf lock regression, init-script idempotency break, duplicate icon/rendering pipeline |
| `35-thunderbird-runtime.sh` | Static contract for the paired root-image and normal-user three-pass browser pre-ship gates | missing real launches, pass IDs, byte/extension/effective-pref checks |
| `35-thunderbird-structural.sh` | M35 Thunderbird embed + AutoConfig + DKIM Verifier XPI + skel | DKIM XPI SHA drift, AutoConfig regression |
| `36-branding-structural.sh` | M32 os-release + issue + trademark disclaimer | trademark rot |
| `36-mtu-audit-fixture.sh` | M36 tunnel-MTU audit behaviour: full-tunnel self-routing, unevaluable and multi-route peers, ordinary/locked route MTUs, the RFC 8200 1280 IPv6 floor, and owner-specific persistent guidance | measuring the inner link as the outer one, a green verdict from an unevaluable peer, hiding the strictest local MTU, printing a correction that breaks configured IPv6, or persisting a provider-owned runtime profile |
| `36-noid-network-structural.sh` | M36 Network app — persistent suite header, adaptive navigation, global DNS transport truth/control, formatted WAN/firewalld/nft audits, synchronized WAN/LAN truth and serialized privilege lifecycle | stale controls, shell injection/truncation, false DNS/VPN scope, false parity, overlapping mutation, unsupported grant or identity drift |
| `37-noid-tools-structural.sh` | M37 Tools app — curated helper catalog including Laptop Lid Close and Global DNS Transport, repo-deploy coverage gate, read-only drop-down defaults, unique emoji prefixes, single-hold terminal wrapper and icon/stamp wiring | dead catalog rows, uncurated new helpers, mutating defaults, duplicate emojis, wrapper or wiring drift |
| `37b-noid-cli-presentation-structural.sh` | Complete Tools CLI presentation inventory derived from M37's catalog | an exposed first-party helper retaining an unreviewed or inconsistent terminal presentation |
| `40-audit-bundle-structural.sh` | M40 exact commit/size/SHA-pinned auditor + offline wrapper default + disabled self-update | source mutation, active-network default, TLS-only root-script replacement, or pin drift |
| `41-anaconda-cleanup-structural.sh` | M41 installed-system Anaconda/live-user cleanup plus Live/install host-identity lifecycle | live-only accounts, sudoers, installer evidence or reused machine-local identities surviving installation |
| `42-forensic-retention-structural.sh` | M42 exact log/AIDE-report/archive scopes, native UPower/audit/NM lifecycle behavior, durable privileged publication and excluded AIDE trust state | overbroad deletion, live-daemon fake clearing, profile rollback loss, trust-state deletion, partial publication, swallowed failure or boundary drift |
| `99-finalize-structural.sh` | M99 cross-module sanity, complete four-app release gate and rejection of compose-created AIDE trust state | app/runtime/desktop contract, stamp-read loop or trust-boundary drift |

Plus `tests/smoke/` (4 bwrap-based smoke tests: M02 sysctl, M17 GNOME, M23 NetworkManager, M27 hardware abstraction).

## Pre-ship gates

The scripts under `tests/pre-ship/` are deliberately not part of
`run-all.sh`: some are source-release checks; the ACL gate compares the mounted
raw-compose, extracted SquashFS and installed roots; and the browser, LAN-XDP,
package-freshness and enforcing-AVC gates require the actual candidate VM
(freshness with controlled WAN access).

```bash
sudo bash tests/pre-ship/03-lan-xdp-runtime.sh             # in installed VM
sudo bash tests/pre-ship/03-lan-direction-nft-runtime.sh   # disposable nft netns
sudo bash tests/pre-ship/01-kernel-cmdline-runtime.sh live
sudo bash tests/pre-ship/01-kernel-cmdline-runtime.sh fresh-install
sudo bash tests/pre-ship/01-kernel-cmdline-runtime.sh reboot
sudo bash tests/pre-ship/01-timezone-runtime.sh live       # before deliberate timezone changes
sudo bash tests/pre-ship/01-timezone-runtime.sh fresh-install Europe/Berlin  # use the consciously selected IANA zone
sudo bash tests/pre-ship/01-timezone-runtime.sh reboot Europe/Berlin         # same selected zone
sudo bash tests/pre-ship/02-unprivileged-bpf-runtime.sh live
sudo bash tests/pre-ship/02-unprivileged-bpf-runtime.sh fresh-install
sudo bash tests/pre-ship/02-unprivileged-bpf-runtime.sh reboot
sudo bash tests/pre-ship/02-sysctl-runtime.sh live
sudo bash tests/pre-ship/02-sysctl-runtime.sh fresh-install
sudo bash tests/pre-ship/02-sysctl-runtime.sh reboot
sudo bash tests/pre-ship/04-ipv4-acd-runtime.sh live
sudo bash tests/pre-ship/04-ipv4-acd-runtime.sh fresh-install
sudo bash tests/pre-ship/04-ipv4-acd-runtime.sh reboot
sudo bash tests/pre-ship/14-usbguard-runtime.sh live
sudo bash tests/pre-ship/14-usbguard-runtime.sh fresh-install
sudo bash tests/pre-ship/14-usbguard-runtime.sh reboot
# The M41 gate may be started immediately after graphical login; it waits up
# to 620 seconds for the intentionally post-GDM maintenance unit and marker.
sudo bash tests/pre-ship/41-installed-firstboot-runtime.sh fresh-install
sudo bash tests/pre-ship/41-installed-firstboot-runtime.sh reboot
# Run record once in each of two independent installations into a root-owned
# 0700 /var/tmp evidence directory, transfer only the digest records to one
# controlled guest, then compare them there:
sudo install -d -o root -g root -m 0700 /var/tmp/noid-host-id-gate
sudo bash tests/pre-ship/41-host-identity-uniqueness.sh record /var/tmp/noid-host-id-gate/install-a
sudo bash tests/pre-ship/41-host-identity-uniqueness.sh record /var/tmp/noid-host-id-gate/install-b
sudo bash tests/pre-ship/41-host-identity-uniqueness.sh compare /var/tmp/noid-host-id-gate/install-a /var/tmp/noid-host-id-gate/install-b
sudo bash tests/pre-ship/07-tcp-timestamps-runtime.sh live
sudo bash tests/pre-ship/07-tcp-timestamps-runtime.sh fresh-install
sudo bash tests/pre-ship/07-tcp-timestamps-runtime.sh reboot
bash tests/pre-ship/08-agent-policy-adapters-runtime.sh live       # normal GNOME VM user
bash tests/pre-ship/08-agent-policy-adapters-runtime.sh fresh-install
bash tests/pre-ship/08-agent-policy-adapters-runtime.sh reboot
bash tests/pre-ship/19-gsk-session-runtime.sh live                # normal GNOME VM user
bash tests/pre-ship/19-gsk-session-runtime.sh fresh-install
bash tests/pre-ship/19-gsk-session-runtime.sh reboot
sudo bash tests/pre-ship/08-codec-runtime.sh live pristine
sudo bash tests/pre-ship/08-codec-runtime.sh fresh-install pristine
# Run noid-complete-setup.sh explicitly, then:
sudo bash tests/pre-ship/08-codec-runtime.sh fresh-install complete
sudo bash tests/pre-ship/08-codec-runtime.sh reboot complete
sudo bash tests/pre-ship/10-logind-inhibitors-runtime.sh live
sudo bash tests/pre-ship/10-logind-inhibitors-runtime.sh fresh-install
sudo bash tests/pre-ship/10-logind-inhibitors-runtime.sh reboot
sudo bash tests/pre-ship/10-login-privacy-runtime.sh live
sudo bash tests/pre-ship/10-login-privacy-runtime.sh fresh-install
sudo bash tests/pre-ship/10-login-privacy-runtime.sh reboot
bash tests/pre-ship/10-bash-history-runtime.sh live            # normal VM user
bash tests/pre-ship/10-bash-history-runtime.sh fresh-install
bash tests/pre-ship/10-bash-history-runtime.sh reboot
sudo -v && bash tests/pre-ship/10-libvirt-core-runtime.sh live  # normal VM user; probes system + session
sudo -v && bash tests/pre-ship/10-libvirt-core-runtime.sh fresh-install
sudo -v && bash tests/pre-ship/10-libvirt-core-runtime.sh reboot
sudo bash tests/pre-ship/10-permission-policy-runtime.sh live
sudo bash tests/pre-ship/10-permission-policy-runtime.sh fresh-install
sudo bash tests/pre-ship/10-permission-policy-runtime.sh reboot
sudo bash tests/pre-ship/11-chrony-runtime.sh live offline
sudo bash tests/pre-ship/11-chrony-runtime.sh live online
sudo bash tests/pre-ship/11-chrony-runtime.sh live cookie-restart
sudo bash tests/pre-ship/11-chrony-runtime.sh live post-resume
sudo bash tests/pre-ship/11-chrony-runtime.sh fresh-install offline
sudo bash tests/pre-ship/11-chrony-runtime.sh fresh-install online
sudo bash tests/pre-ship/11-chrony-runtime.sh fresh-install rtc-bootstrap  # first installed boot with libvirt RTC +7200s
sudo bash tests/pre-ship/11-chrony-runtime.sh fresh-install fresh-ke
sudo bash tests/pre-ship/11-chrony-runtime.sh fresh-install cookie-restart
sudo bash tests/pre-ship/11-chrony-runtime.sh fresh-install post-resume
sudo bash tests/pre-ship/11-chrony-runtime.sh reboot offline
sudo bash tests/pre-ship/11-chrony-runtime.sh reboot online
sudo bash tests/pre-ship/11-chrony-runtime.sh reboot cookie-restart
sudo bash tests/pre-ship/11-chrony-runtime.sh reboot post-resume
bash tests/pre-ship/13-first-party-app-accessibility-runtime.sh live  # normal GNOME VM user
bash tests/pre-ship/13-first-party-app-accessibility-runtime.sh fresh-install
bash tests/pre-ship/13-first-party-app-accessibility-runtime.sh reboot
bash tests/pre-ship/10-umask-runtime.sh live                    # normal VM user
bash tests/pre-ship/10-umask-runtime.sh fresh-install
bash tests/pre-ship/10-umask-runtime.sh reboot
bash tests/pre-ship/17-display-power-runtime.sh live              # normal GNOME VM user
bash tests/pre-ship/17-display-power-runtime.sh fresh-install
bash tests/pre-ship/17-display-power-runtime.sh reboot
bash tests/pre-ship/17-jit-runtime.sh live                      # normal GNOME VM user
bash tests/pre-ship/17-jit-runtime.sh fresh-install
bash tests/pre-ship/17-jit-runtime.sh reboot
bash tests/pre-ship/17-wayland-default-runtime.sh live            # normal GNOME VM user
bash tests/pre-ship/17-wayland-default-runtime.sh fresh-install
bash tests/pre-ship/17-wayland-default-runtime.sh reboot
# Run before manually opening GNOME Software or invoking Update All in each pass.
sudo -v && bash tests/pre-ship/24-silent-update-runtime.sh live   # normal GNOME VM user
sudo -v && bash tests/pre-ship/24-silent-update-runtime.sh fresh-install
sudo -v && bash tests/pre-ship/24-silent-update-runtime.sh reboot
bash tests/pre-ship/17-privacy-cleanup-runtime.sh live prepare     # log out/in between phases
bash tests/pre-ship/17-privacy-cleanup-runtime.sh live verify
bash tests/pre-ship/17-privacy-cleanup-runtime.sh fresh-install prepare
bash tests/pre-ship/17-privacy-cleanup-runtime.sh fresh-install verify
bash tests/pre-ship/17-privacy-cleanup-runtime.sh reboot prepare
bash tests/pre-ship/17-privacy-cleanup-runtime.sh reboot verify
bash tests/pre-ship/17-user-firstrun-runtime.sh fresh-install     # normal GNOME VM user, after first login
bash tests/pre-ship/17-user-firstrun-runtime.sh reboot
bash tests/pre-ship/17-session-lifecycle-runtime.sh live initial # Live logout/re-login recovery; notifier active
bash tests/pre-ship/17-session-lifecycle-runtime.sh fresh-install initial
sudo bash tests/pre-ship/17-gnome-shell-logout-runtime.sh fresh-install 1 prepare
# Keep the session unlocked and log out immediately from inside the session:
# GNOME's Log Out entry, or gnome-session-quit --logout --no-prompt where
# GNOME 50 hides that entry (single account, always-show-log-out unset).
# Do not substitute loginctl or a delayed automation.
# Log in again before both verification commands.
bash tests/pre-ship/17-session-lifecycle-runtime.sh fresh-install second-login
sudo bash tests/pre-ship/17-gnome-shell-logout-runtime.sh fresh-install 1 verify
# Repeat a second independent fresh-install logout/re-login cycle.
sudo bash tests/pre-ship/17-gnome-shell-logout-runtime.sh fresh-install 2 prepare
# Repeat the same unlocked visible-dialog logout, log in again, then verify:
sudo bash tests/pre-ship/17-gnome-shell-logout-runtime.sh fresh-install 2 verify
bash tests/pre-ship/17-session-lifecycle-runtime.sh reboot initial
sudo bash tests/pre-ship/17-gnome-shell-logout-runtime.sh reboot 1 prepare
# Repeat the same unlocked visible-dialog logout and log in again before both
# verification commands.
bash tests/pre-ship/17-session-lifecycle-runtime.sh reboot second-login
sudo bash tests/pre-ship/17-gnome-shell-logout-runtime.sh reboot 1 verify
# Start each command from serial/SSH, then bring GDM to the foreground within
# its 30-second wait; the gate snapshots the active greeter before normal login:
sudo bash tests/pre-ship/17-greeter-identity-runtime.sh live
sudo bash tests/pre-ship/17-greeter-identity-runtime.sh fresh-install
sudo bash tests/pre-ship/17-greeter-identity-runtime.sh reboot
# After the normal graphical login in each pass; Live accepts only the exact
# native automatic-login path when it has no pre-user Shell, fresh-install
# accepts Fedora's exact Initial Setup Shell, and reboot requires GDM in the
# current boot while auditing both installed boots:
sudo bash tests/pre-ship/17-greeter-retirement-runtime.sh live
sudo bash tests/pre-ship/17-greeter-retirement-runtime.sh fresh-install
sudo bash tests/pre-ship/17-greeter-retirement-runtime.sh reboot
sudo bash tests/pre-ship/17-liveinst-webui-runtime.sh live baseline
# Open the Fedora installer, then while its window is open:
sudo bash tests/pre-ship/17-liveinst-webui-runtime.sh live active
# Close it normally with Alt+F4, then:
sudo bash tests/pre-ship/17-liveinst-webui-runtime.sh live closed
# Open it once more, prove active again, then exercise the exact-PID error exit:
sudo bash tests/pre-ship/17-liveinst-webui-runtime.sh live active
sudo bash tests/pre-ship/17-liveinst-webui-runtime.sh live error-exit
sudo bash tests/pre-ship/17-liveinst-webui-runtime.sh fresh-install absent
sudo bash tests/pre-ship/17-liveinst-webui-runtime.sh reboot absent
bash tests/pre-ship/09-ssh-fix-phase-disabled.sh
sudo bash tests/pre-ship/05-resolved-dot-runtime.sh live config
sudo bash tests/pre-ship/05-resolved-dot-runtime.sh fresh-install config
# With no VPN/private ~. DNS active; performs one explicit Quad9 TXT query:
sudo bash tests/pre-ship/05-resolved-dot-runtime.sh fresh-install quad9-query
# With one provider-neutral VPN/private ~. DNS scope active whose profile keeps
# connection.dns-over-tls at default (-1). Global and physical DNS must remain
# strict; this proves the tunnel inherits M23's generic opportunistic default:
sudo bash tests/pre-ship/05-resolved-dot-runtime.sh fresh-install vpn-query
# Optional stronger positive control: use a disposable test tunnel whose
# complete DNS server set is Quad9-only and whose DoT property remains unset.
# Do not rewrite or `resolvectl revert` a provider-owned mixed resolver scope;
# its client owns republishing that runtime state. The gate explicitly resets
# resolved's feature cache and requires Quad9 to report DoT for the probe:
sudo bash tests/pre-ship/05-resolved-dot-runtime.sh fresh-install vpn-dot-query
sudo bash tests/pre-ship/05-resolved-dot-runtime.sh reboot config
# With the same unset-profile tunnel scope active after reboot, repeat both the
# compatibility proof and, with the same disposable Quad9-only test tunnel,
# the explicit best-effort TLS positive control:
sudo bash tests/pre-ship/05-resolved-dot-runtime.sh reboot vpn-query
sudo bash tests/pre-ship/05-resolved-dot-runtime.sh reboot vpn-dot-query
sudo bash tests/pre-ship/17-mutter-fedora-runtime.sh /
sudo bash tests/pre-ship/18-flatpak-remote-runtime.sh live
sudo bash tests/pre-ship/18-flatpak-remote-runtime.sh fresh-install
sudo bash tests/pre-ship/18-flatpak-remote-runtime.sh reboot
bash tests/pre-ship/18-browser-license-notices.sh /          # candidate root
sudo bash tests/pre-ship/19-browser-image-parity.sh live
sudo bash tests/pre-ship/19-browser-image-parity.sh fresh-install
sudo bash tests/pre-ship/19-browser-image-parity.sh reboot
bash tests/pre-ship/19-browser-runtime-parity.sh live        # normal VM user
bash tests/pre-ship/19-browser-runtime-parity.sh fresh-install
bash tests/pre-ship/19-browser-runtime-parity.sh reboot
# In QEMU/KVM, attach unmounted, distinct-UUID 128 MiB ext4 fixtures:
# One 768-MiB USB matrix disk (NOID_VFAT/EXFAT/NTFS/EXT4), NOID_FIXED over
# USB removable=0 and NOID_SD over native SD; see docs/release-process.md.
sudo bash tests/pre-ship/20-hardware-tuning-runtime.sh live
sudo bash tests/pre-ship/20-hardware-tuning-runtime.sh fresh-install
sudo bash tests/pre-ship/20-hardware-tuning-runtime.sh reboot
sudo bash tests/pre-ship/21-dracut-hostonly-runtime.sh live
sudo bash tests/pre-ship/20-snapper-rollback-runtime.sh live
# First boot transaction: stage M21, then reboot into its one-shot candidate.
sudo bash tests/pre-ship/21-dracut-hostonly-runtime.sh fresh-install
# Reboot #1, then prove M21 reached the terminal host-only basis:
sudo bash tests/pre-ship/21-dracut-hostonly-runtime.sh reboot
# Second boot transaction in the same disposable QEMU/KVM VM: only now may
# Snapper select a new default root. Rerun this same pass if it is interrupted.
sudo bash tests/pre-ship/20-snapper-rollback-runtime.sh fresh-install  # last before reboot #2
# Reboot #2 into the selected rollback root, then:
sudo bash tests/pre-ship/20-snapper-rollback-runtime.sh reboot
# Separate disposable clone: each recover runs in the temporary fallback boot;
# each following arm/verify runs after another normal reboot into restored Generic.
sudo bash tests/pre-ship/21-dracut-powerloss-runtime.sh select-recovery
sudo bash tests/pre-ship/21-dracut-powerloss-runtime.sh recover
sudo bash tests/pre-ship/21-dracut-powerloss-runtime.sh arm  # then host: virsh destroy
sudo bash tests/pre-ship/21-dracut-powerloss-runtime.sh recover
sudo bash tests/pre-ship/21-dracut-powerloss-runtime.sh verify
sudo bash tests/pre-ship/21-wan-threat-boundary-runtime.sh live
sudo bash tests/pre-ship/21-wan-threat-boundary-runtime.sh fresh-install
sudo bash tests/pre-ship/21-wan-threat-boundary-runtime.sh reboot
sudo bash tests/pre-ship/29-installed-package-freshness.sh  # in installed VM
bash tests/pre-ship/30-live-payload-acl-parity.sh \
  /mnt/raw-compose /mnt/squashfs /mnt/installed
sudo bash tests/pre-ship/31-installed-enforcing-avc.sh      # in installed VM
```

The LAN-XDP gate loads the exact installed object, verifies native mode where
requested plus generic XDP and TC, and injects a deterministic matrix of 36
malformed and seven valid raw Ethernet/IPv4/UDP/TCP/ICMP/EAPOL/ARP/DHCP frames.
Every malformed reachable frame must increment the exact drop class and remain
invisible to a concurrent AF_PACKET capture; every valid exceptional branch
must increment its exact pass class.

The freshness command must report zero Fedora upgrades and zero
Critical/Important/Moderate security advisories. The ACL gate must report
`raw=exact` and `installed=exact` (with either exact preservation or the
explicit known-loss/reconstruction contract at SquashFS), and the enforcing
gate must report zero current-boot AVC/USER_AVC records before the ISO checksum
is signed.

The M01 runtime gate must pass all three exact lifecycle identities. The live
run checks the effective bootloader manifest; fresh-install and reboot also
require a successful firstboot decision plus the native Fedora split: every
normal BLS `options` line equals the semantic `/etc/kernel/cmdline` plus one
trailing `$tuned_params` macro. During the M21 pending phase, exactly one
Generic recovery entry may append only its exact recovery marker after that
macro.
The M02 BPF gate must likewise pass all three identities with effective value
1, an unprivileged syscall `EPERM` and a rejected administrator reset to 0.
The complete M02 sysctl gate must also pass all three identities: its three
installed files must be root-owned regular mode-0640 single-link files,
byte-identical to their source heredocs, and all 105 directives must match
every concrete procfs node selected by their interface wildcards.
The M04/M23 ACD gate must pass all three identities with no ARP packet hook,
an exact permanent gateway pin, effective DAD=200 and both isolated
duplicate-rejected/unused-accepted outcomes. Its veth peer lives in a bounded
process namespace, avoiding named-netns bind mounts against the Live overlay
without weakening SELinux. Its source fixtures also require a
gateway-less `pre-up` to defer without trusting a stale route, the following
`up` event to retry from the exact-interface default route, and any failed
post-DHCP learning attempt to disconnect only that interface.
The M07 timestamp gate must pass all three identities with effective value 1,
no installed value-0 override and exact M07 file metadata. This verifies the
maintained per-connection-randomized Linux policy rather than substituting an
unbenchmarked privacy patch that disables RTTM/PAWS.
The M18 Flatpak gate must pass all three identities with controlled WAN. It
requires the byte-pinned descriptor, exact two-remote config, canonical Flathub
public-key export, non-empty current signed full/verified catalogs, the native
`/etc` mask for Fedora's auto-add unit, no forged vendor sentinel and all six
global denies. Flatpak may legitimately evict cached summaries after ordinary
transactions, so cache presence is not treated as durable trust state. Fedora's
stable OCI remote remains an explicit helper opt-in.
The M10 Bash-history gate must pass all three identities as the normal VM user.
It verifies exact artifact metadata, string/array prompt-hook preservation,
newest-100 compaction after a successful sync, a legitimate entry larger than
10 KiB, multiline/history-expansion behavior, four simultaneous shells under
one per-user lock, literal mid-compaction `SIGKILL` recovery including stale
temporary-copy cleanup, and symlink refusal.
This is separate from the scoped 30-day system-log retention policy.
The M10 permission gate separately binds all nine reviewed paths to their RPM
owners and package-declared modes. It requires five intentionally admin-only
paths to remain non-SUID, four load-bearing Fedora paths to retain native SUID,
the six cron/sudoers directories to remain root-only, the old weekly mutator to
be absent, and unprivileged `chage -l`/PAM helper behavior to remain functional.
The M08 Agent-adapter gate proves that the normal account passes the shared
persistent-user boundary, its sealed record is not rewritten on a second unit
activation, and the unit makes no unenforceable IP-firewall claim while its
retained `RestrictAddressFamilies=AF_UNIX` sandbox still rejects an actual
AF_INET socket in each candidate identity.
The M19 GSK-session gate independently proves the automatic renderer policy
inside the real local GNOME login. On a matched portable NVIDIA-offload
topology, it requires the private marker and exact `GSK_RENDERER=gl` value in
the user manager while the systemd-owned GNOME Shell MainPID has no renderer
override. On every topology it rejects unit-specific drop-ins and
unenforceable user-manager network claims, then proves the retained
AF_UNIX-only socket filter with a transient local probe. It does not launch an
application or perform network I/O.
The M13 application gate launches Setup, Network, Update and Tools through
their exact entry points, uses the real AT-SPI tree, visits all three Network
pages and rejects every visible actionable control without an explicit name.
Semantic rows, switches, entries, combos and page tabs also require a
description. It never activates Update's `Start Update` action.
The M17 session gate proves the Live-only GNOME logout suppression and the
USBGuard notifier's real process/argv/target ownership behind an exact active,
local `Class=user` Wayland/X11 logind identity. The paired installed commands
require the same boot but a different login session ID, so a second printed
PASS cannot be obtained by rerunning the command before logout. The separate
root-run greeter gate is started before authentication through serial/SSH and
waits up to 30 seconds for GDM. It takes one complete property snapshot as soon
as an active `Class=greeter` session appears, then requires that greeter user
manager to condition-skip both user units when the manager remains available.
It queries the existing user bus as the already validated NSS identity; it
does not synthesize a PAM login through `systemctl --machine`. The Live ISO's
intentional timed auto-login may retire that manager after the snapshot; this
is accepted only when the session is no longer foreground and
`user@UID.service` reaches exact `inactive/success`. Both paths prove there is
no notifier process, adapter state, per-greeter USBGuard IPC file or
supplementary group grant.
The M17/M24 Silent Machine gate runs before any manual Software/Update action in
each pass. It proves that Fedora's pristine D-Bus descriptor routes Software
activation immediately to its masked unit, with no duplicate admin service,
and cannot spawn GNOME Software, dnf5daemon-server, fwupd refresh or passim;
that the current Fedora launcher instead resolves through the standard admin
desktop tier with `DBusActivatable=false` and its direct `Exec` intact; and that
installed fwupd stays boot-dormant, activates only on demand and settles through
its native update-aware quit request without enabling background LVFS/P2P work.
It separately binds the deployed Update All helper to unprivileged
`fwupdmgr refresh --force`, a visible install prompt, PolicyKit-mediated
`fwupdmgr update --no-reboot-check`, checked command status and fwupd's
dedicated JSON reboot-state query, so the silent default is not confused with
a disabled deliberate update path or a privileged network client.
The M11 chrony gate first proves the same restricted process/artifact boundary
without a route, then under the controlled WAN requires all 6 manifest-bound
sources to have nonzero NTS keys/cookies/reachability and a normal leap state.
The fresh-install-only `rtc-bootstrap` action additionally binds a libvirt
+7200-second UTC-basis RTC injection to a journal-measured 6900–7500-second
authenticated correction, `LocalRTC=no`, active automatic time and completed
synchronization. It catches a daemon-exit threshold which would strand normal
localtime-as-UTC firmware clocks while leaving the TLS-invalid-clock recovery
boundary intact.
It also rechecks IPv4 resolution, TLS 1.3 chain/hostname validation and distinct
negotiated timestamp backends for every dated public dependency.
It pins the RPM-owned restricted unit and `-F 2` sysconfig bytes, effective
`chrony` UID/SELinux domain/sole `CAP_SYS_TIME`, NNP/seccomp/systemd sandbox,
closed UDP 323 and exclusive enablement. Separate actions prove cookie dump and
reload, a fresh TLS-authenticated NTS-KE after removing only disposable cached
cookies, and bounded fail-closed recovery after a journal-proven suspend/resume.
Invoke each `post-resume` action immediately after wake: it allows up to 60
seconds for gateway/XDP readiness, requires chrony to remain offline before
that boundary, and records the actual wait in its PASS evidence. Run every
listed identity/action against the unchanged candidate bytes; `fresh-ke` is
deliberately limited to the fresh-install VM.
The M06 threat-boundary gate must pass all three identities with a valid
published runtime mode, the matching output/forward-hook postcondition, and
exact `EPERM` results for capability-empty UID 65534 opening IPv4-raw/
`AF_PACKET` sockets or attempting an nft mutation. It proves the ordinary
unprivileged boundary; it deliberately does not relabel privileged link-layer,
namespace/control-plane or firmware paths as covered.

## Add a new test

```bash
# File name: NN-<module-or-topic>-<what>.sh
# Example:   tests/03-firewalld-zones.sh
```

Template:

```bash
#!/bin/bash
# NN-topic-what — one-sentence purpose
# Background: why this test exists (what bug would it catch?)

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/NN-topic.ks"

test_start "NN-topic-what"

# your assertions, using:
#   assert_file_exists <path>
#   assert_file_executable <path>
#   assert_file_min_size <path> <bytes>
#   assert_grep <pattern> <path> [desc]
#   assert_grep_extended <regex> <path> [desc]
#   assert_grep_fixed <literal> <path> [desc]
#   assert_not_grep <pattern> <path> [desc]
#   assert_eq <expected> <actual> [desc]
#   assert_cmd_success <desc> <cmd> [args...]
#   assert_cmd_failure <desc> <cmd> [args...]
#   extract_heredoc <ks-file> <marker> <target>

test_finish
```

Make it executable, then:

```bash
chmod +x tests/NN-topic-what.sh
./tests/run-all.sh topic    # filter to just this test
```

## What these tests are and aren't

These are **semantic and structural tests of repository-owned build inputs and
helper logic**, not a substitute for runtime tests of an installed NoID Privacy
image. The complete `run-all.sh` contract requires Fedora 44 `pykickstart`,
ShellCheck, the clang/libbpf BPF build toolchain, GNU patch, Git, and Python 3;
it fails at preflight if any prerequisite is unavailable. Direct execution of
a filtered or individual test retains that test's documented capability
behavior. ShellCheck findings and Kickstart grammar failures are blocking, and
CI also runs dedicated capabilities as separate required jobs.
The tests catch:

- Syntax errors (via `bash -n`)
- Logic bugs in helper functions that can be extracted + exercised on
  mock data (like M22 `ensure_mount_options`)
- Heredoc integrity (doc files that would be truncated or empty at
  install time)
- Structural invariants ("RamaLama must be Option A", "welcome script
  must have --again flag")

They do NOT catch:

- Whether Anaconda completes a real compose and installation; `ksvalidator`
  checks the flattened Kickstart grammar, not installer execution
- Whether the image actually boots + passes VM-test 16-point matrix
- Whether fwupd sees the firmware after install
- SELinux AVCs that only appear at runtime

Those require the documented **candidate-VM and Pre-Ship gates** after a real
build; they are deliberately outside `run-all.sh`.

`35-thunderbird-runtime.sh` keeps historical naming compatibility while
validating the paired candidate-only browser gates' source contract. It does
not read the build host's installed browser state. The root-owned image parity
gate and the actual normal-user launches run through
`tests/pre-ship/19-browser-image-parity.sh` and
`tests/pre-ship/19-browser-runtime-parity.sh`, respectively, in the live,
fresh-install and reboot candidate passes.

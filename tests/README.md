# tests/ — NoID Privacy Workstation semantic test suite

Mandatory gate before marking a Module `LOCKED`. See `../CONTRIBUTING.md`
for the full policy.

## Run everything

The complete release gate requires `aide`, `bwrap`, `checkmodule`, `clang`, `cpio`,
GNU `base64`, `sha256sum` and `strip`, the libbpf and Linux UAPI development
headers, `dconf`, `desktop-file-validate`, `git`, `gsettings` with the GVfs
discovery schemas, `gzip`, `jq`, `ksvalidator`, `lsinitrd`, `modinfo`, `openssl`, `patch`,
`xz`, `zstd`, `python3` with the `auparse`
module, `pgrep`, `semodule_package`, `setfacl`, `shellcheck`, `systemd-analyze`,
`systemd-tmpfiles`, `udevadm`, `usbguard`, `usbguard-notifier`,
`usbguard-rule-parser`, `visudo`, `dbus-daemon`, `dbus-run-session`, `dbus-send`,
`dbus-test-tool`, `gdm`, `pipewire`,
`wireplumber`, `pw-cli`, `pw-dump`, `wpctl`, and `spa-json-dump`.
The native initramfs fixture also requires Fedora's `libseccomp.so.2` library.
On Fedora 44 (the same command `run-all.sh` prints when a prerequisite is
missing):

```bash
sudo dnf install ShellCheck aide acl audit binutils bubblewrap checkpolicy clang cpio dbus-daemon dconf desktop-file-utils dracut gdm git glib2 gvfs gzip jq kernel-headers kmod libbpf-devel libseccomp openssl patch pipewire pipewire-utils policycoreutils procps-ng pykickstart python3 python3-audit sudo systemd systemd-udev usbguard usbguard-tools usbguard-notifier wireplumber xz zstd
```

The preflight checks exactly this tool set. Individual tests additionally call
ordinary Fedora workstation tools (for example `firewall-cmd`, `nmcli`, `nft`,
`wg`, `ssh-keygen`, `lspci` and `unzip`); the CI job in
`.github/workflows/ci.yml` installs the complete package superset and is the
authoritative list for a minimal build host.

```bash
./tests/run-all.sh
```

Expected: all tests pass, exit 0. A missing prerequisite from the preflight
set above is a test-harness error (exit 2), reported before any partial
pass/fail summary.

## Run a subset

```bash
./tests/run-all.sh 22            # only M22-related tests
./tests/run-all.sh 29 welcome    # M29 + welcome-script tests
./tests/run-all.sh --verbose     # show per-check output even on pass
```

## Current tests

Full suite: **89 tests** via `run-all.sh` + **4 bwrap smoke tests** under
`tests/smoke/` = **93 test scripts total** (plus `lib.sh` + `run-all.sh`
helpers in both directories, the one-time `tests/smoke/prep-rootfs.sh`, and
14 numbered `tests/NN-*.py` contract/fixture programs plus `tests/fixtures/`
modules that run only through their owning `.sh` test).
The table below is the complete structural list; discovery uses the same
`tests/[0-9][0-9]*-*.sh` shape as `run-all.sh`.

| Test | What it covers | Would catch |
|------|----------------|-------------|
| `00-archive-signing-structural.sh` | Signed release archive authentication and atomic complete-tree copy | unsigned/tampered candidate, incomplete VM approval, partial copy or destination replacement |
| `00-compose-metalinks.sh` | Current Fedora primary metadata, unchanged HTTPS mirrors and native offline Kickstart staging | older permitted repository snapshots, malformed hashes, plaintext mirrors or unintended repository rewrites |
| `00-compose-sources.sh` | Fedora source type, Lorax inventory reads, compose identity/log policy, shutdown-event ordering and installed-VM freshness/AVC gate wiring | Incomplete staging inventories, metalink drift, unclassified or premature shutdown errors, missing success markers or runtime release gates |
| `00-dnf-actions-structural.sh` | DNF5 action-file syntax and updater integration | malformed post-transaction hooks or missing redeploy action |
| `00-fedora-base-iso-trust.sh` | Fedora base-ISO signer/digest pin and canonical verifier call | unreviewed base media or verifier bypass |
| `00-pii-sweep.sh` | Public-tree Python-cache, PNG metadata, binary home-path, machine-id and MAC sweep plus fixtures | ignored bytecode, image author/time metadata or accidental host identity/path outside the synthetic allowlist |
| `00-release-evidence-readers.sh` | Native release-gate inventory and chrony-cookie recovery error fixtures | failed reads reported clean, lost recovery evidence or false package verification |
| `00-rootfs-hygiene.sh` | Final Live-root identity/state absence, native log/SSH scan failures and ISO extraction wrapper wiring | Identity reuse, compose evidence leakage, unreadable trees reported clean or a gate that never reaches the final SquashFS |
| `00-source-generators.sh` | Copy-isolated strict CLI/marker/metadata/validate-before-publish contract for every `scripts/regen-*.sh` generator | malformed input mutation, delimiter ambiguity, mode loss, symlink inclusion or non-atomic writes |
| `00-status-metadata.sh` | Module lock provenance + published repo-count parity | stale LOCKED dates, incomplete test inventory or README count drift |
| `00-syntax-sweep.sh` | `bash -n` on every .ks file, `tests/lib.sh` self-tests (logger shim, negative/exact-status assertions, heredoc extraction, exec scratch) and the `run-all.sh` log/status fixture | Syntax errors (typos, missing `fi`/quotes), assertion helpers that pass vacuously or a runner that loses a failure or log |
| `00-updates-image-structural.sh` | Retired RPM-error bypass + authenticated deterministic profile/mask updates image | reintroduced scriptlet suppression, unauthenticated base, archive drift or output replacement |
| `01-bootloader-structural.sh` | M01 manifest-backed exact cmdline surfaces + Secure Boot | comment-only false green, duplicate/conflicting family or source-surface drift |
| `01-shellcheck.sh` | Blocking ShellCheck pass over standalone test/build scripts; fails closed when ShellCheck is missing | Unquoted vars, `[` vs `[[`, subshell traps |
| `02-shellcheck-heredocs.sh` | shellcheck on bash heredocs extracted from .ks (blocking at error/warning severity; style/info advisory) | Heredoc body shellcheck errors and warnings |
| `02-sysctl-structural.sh` | M02 99-hardening.conf + 99-audit-fixes + 99-userns | sysctl param count drift, wildcard expansion |
| `03-firewalld-structural.sh` | M03 drop-default firewalld.conf + block-lan-out/allow-host-ipv6 policies, including the host-only cross-layer DHCPv4 selector | ingress-zone regression, rule count drift, DHCP widening, peer/global grant shadowing or VM inheritance |
| `03b-lan-xdp-controller-state.sh` | Closed LAN-XDP state/map schemas, exact live identities and multi-NIC rollback | corrupt/cross-root state, name-only TC match, unsafe map reuse or wrong-mode rollback |
| `03c-firewalld-firstboot-runtime.sh` | Isolated all-physical firstboot zone/SSH/exact-IPv6-policy transaction | first-NIC-only enforcement, reload churn, false completion or hidden policy widening |
| `03d-lan-xdp-policy-digest.sh` | LAN-XDP fast path: identical enforced input plus live attachment skips the rebuild | stale enforcement after a skipped sync, forged/foreign digest sidecar or a fast path that never engages |
| `03e-lan-topology-coalescing.sh` | Topology-refresh coalescing decides on the boot clock, never the steppable wall clock | a chrony backward step discarding an unseen event, a stale pre-monotonic stamp skipping every refresh, or a targeted invocation being coalesced |
| `04-arp-hardening-structural.sh` | M04 closed state guard + permanent pin + awaited/no-wait dispatcher pair + native ACD contract | fail-open state/marker metadata, serialized post-activation regression, shadow-table regression, sandbox, neighbour-parser or dispatcher drift |
| `04-arp-failover-fixture.sh` | Remaining physical gateway after link removal, including vanished sysfs devices and queued old events | stranded readiness, tunnel/carrierless fallback, ignored pin opt-out or unconditional readiness publication |
| `04-arp-revalidate-handoff-fixture.sh` | Post-activation gateway revalidation leaves the dispatcher through a root-private per-event request; pre-up stays awaited and an unavailable hand-off revalidates in place | a long revalidation holding NetworkManager's event queue, a handed-off pre-up, a lost or replayed request, a gateway address in a unit name or journal, or a disconnect on a non-contested failure |
| `04-arp-transaction-fixture.sh` | M04 staged refresh/retained-identity pin opt-out, paired dispatcher publication, post-DHCP retry and exact rollback behaviour | stale/cross-interface cache reuse, unsafe lock/state, split awaited/no-wait copies, partial publication, signal/pre-up/up failure, or a link disconnect on a transient failure |
| `05-lan-direction-fixture.sh` | M05 outbound/inbound/both CLI, state/export, exact firewalld and add/edit/revoke ordering | selector widening, schema drift or stale-permit transaction gaps |
| `05-lan-isolation-structural.sh` | M05 strict global/physical DNS policy, transactional physical-uplink DoT selector, the M23 tunnel-default boundary, masks, exception-state and boot/timer unit contracts | DNS scope/rollback drift, tunnel transport misattribution, service drift or reboot-volatile temporary grants |
| `05-lan-temp-expiry-fixture.sh` | M05 durable temporary-exception deadline/reconciliation behavior | reboot promotion, clock extension, invalid state or hidden revoke failure |
| `05-printing-toggle-fixture.sh` | M05 print-stack opt-in: which units it unmasks, activation entry points, failed-activation rollback and discovery-drift reporting | enabling printing re-opening mDNS/WSD discovery, an outright-enabled cupsd, a half-open state after a failed activation or a silent firewall change |
| `06-vpn-killswitch-structural.sh` | M06 dispatcher/WAN-strict publication, live-only WireGuard MTU source parity and inbound-DROP `noid-vpn` zone | ifcfg-less NM, NM-2.0 rename, profile mutation or MTU dispatcher drift |
| `06-wireguard-mtu-fixture.sh` | Lower-only active WireGuard MTU reconciliation across IPv4/IPv6, route ceilings, multiple/unresolved peers, IPv6 floor, lock trust and all-interface events | hard-coded MTU, profile ownership races, unsafe raise, partial-evidence mutation or IPv6 breakage |
| `07-ipv6-policy-transaction-fixture.sh` | M07 locked sysctl/status publication and fail-closed NM pre-up | hidden logger failure, unsafe metadata, concurrent hotplug, interruption or split durable state |
| `07-ipv6-privacy-structural.sh` | M07 gai.conf + per-WAN sysctl | ra=0 removal, gai.conf drift |
| `08-mask-list-structural.sh` | M08 mask-list, exact privileged helper bridge and dconf gnome-software | service-count drift, privilege widening or packagekit rename |
| `08-udisks2-mount-propagation-structural.sh` | M08 udisks2 mount propagation, sandbox exception and the 0644 libmount mount-event tmpfiles companion of `UMask=0077` | removable-media mounts hidden by an over-tight service sandbox, or user managers that stop tracking mounts after the first UDisks mount |
| `09-ssh-structural.sh` | M09 openssh-server exclusion, PQ-hybrid client defaults and opt-in server template | openssh-server returning, client config rot or a weakened server template |
| `10-pam-structural.sh` | M10 faillock, pwquality, native yescrypt, login privacy, libvirt system-QEMU core ceiling, declarative permission policy, interactive umask, command-scoped DNF state umask and locked/atomic Bash-history compaction | PAM/hash/mode drift, privileged QEMU core-limit bypass, unreadable DNF state, obsolete chmod timer, global umask mutation, destructive prompt hooks or false history bounds |
| `11-chrony-nts-structural.sh` | M11 dated 6-source production/public NTS manifest + readiness-gated restricted client | source/status/config drift, pre-production dependency, pre-readiness traffic, minsources change |
| `11b-dns-diagnostics-structural.sh` | M11b manual evidence-first DNS diagnostics | background probe/recovery regression, fixed target or mutating default action |
| `12-auditd-structural.sh` | M12 SELinux + 132 dual-ABI audit rules including AIDE evidence + durable storage alert | ABI/time/login-session/AIDE-rule drift, suppression, immutable or failure-policy regression |
| `13-welcome-script.sh` | M13 Setup app plus shared GTK4/libadwaita identity, accessibility, native AIDE rule resolution and synthetic comparison vectors, and desktop contracts | split autostart/app-grid identity, duplicate windows, missing feedback, weakened AIDE rules, syntax or shared-contract drift; no baseline initialization or replacement |
| `13b-noid-status-structural.sh` | M13 noid-status diagnostic CLI — auditd/HSI/snapper/user-timer control-flow + JSON mode | HSI ANSI/colon truncation, inherited-session false unknown, auditd non-root or JSON field drift |
| `13c-autostart-netwait.sh` | M13 autostart network gate — physical-carrier classification and fail-open contract | a tunnel/dummy device opening the gate, or the wrapper preventing an app from starting |
| `14-usbguard-structural.sh` | M14 state machine, notifier and least-privilege named IPC contract | policy GC, broad group/parameter access, false permanent-notification claims or user-service rot |
| `15-intel-me-structural.sh` | M15 no-default MEI sub-module blacklist guard, KT/SOL PCI-ID enforcement (udev/Dracut/early boot), mei-status contract + AMD PSP docs | re-introduced default MEI blacklist, new PCI ID missing, mei_me regression |
| `15b-amd-psp-doc-structural.sh` | M15 companion — AMD PSP hardware-layer doc | heredoc truncation, CVE notes removed |
| `16-browser-gate-contract.sh` | Static contract for the paired root-image and normal-user three-pass browser pre-ship gates | missing real launches, pass IDs, byte/extension/effective-pref checks |
| `16-firefox-structural.sh` | M16 NoID Privacy Firefox Hardening embed + uBO XPI + managed-storage | arkenfox absorption regression, XPI SHA256 drift |
| `17-gnome-hardening-structural.sh` | M17 dconf lockdown, transactional SW_LID/logind lid CLI, and split GNOME Software D-Bus-denial/explicit-launch overlays | desktop/laptop misclassification, partial lid apply, telemetry channel re-open or deliberate Software launch blocked |
| `17-lid-action-fixture.sh` | Isolated desktop/laptop lid-action lifecycle with native logind stubs | false SW_LID detection, unconfirmed suspend, failed-reload residue, lower-policy deletion or independent-file overwrite |
| `17-microphone-policy-fixture.sh` | Isolated PipeWire/WirePlumber microphone-policy lifecycle, helper and restart persistence | invalid source inventories, missing runtime prerequisites, unmute drift, new-source bypass, split GNOME/WirePlumber state or volatile settings |
| `17-privacy-cleanup-fixture.sh` | Custom-XDG GNOME tracking/thumbnail cleanup with Mozilla, symlink and mount substitutions | live-profile lock deletion, hidden-cache residue, symlink traversal, bind-mount deletion or preflight partial mutation |
| `17-user-firstrun-fixture.sh` | Isolated transactional per-user first-login task lifecycle including libvirt session compatibility | premature global completion, conflicting/symlinked QEMU config overwrite, swallowed task failure or non-retryable partial setup |
| `18-flatpak-remote-policy-fixture.sh` | Exact Flathub descriptor/config/key/catalog reconciliation, native key-file grammar and Fedora stable opt-in state machine | hostile existing names, key/config drift, empty catalogs, destructive ref migration or fedora-testing mutation |
| `18-flatpak-sandboxing-structural.sh` | M18 native Fedora-unit mask, source parity, 3 D-Bus + 2 filesystem overrides and three-pass gate wiring | private-sentinel workaround, Flatseal autoinstall or remote-trust regression |
| `19-gsk-renderer-toggle.sh` | M19 portable NVIDIA-offload matcher, post-Shell activation environment, native manager/topology/process read failures, administrator precedence and reversible auto/on/off policy | incomplete GPU/connector/process evidence, malformed NUL records, AMD-only or NVIDIA-primary false match, Shell-wide renderer override, false cleanup, pipe errors or unsafe rollback |
| `19-nvidia-install.sh` | M19 helper/queue — GPU and branch policy, MOK identity, NVIDIA sleep default, native payload-signature and queue-read failures, shared-lock deferral and M21 image delegation | wrong package branch, stale or invalid module signatures, queue errors or unsafe pending objects releasing the guard, independent Dracut writer or incomplete all-kernel rollback |
| `19-nvidia-mok-docs-structural.sh` | M19 NVIDIA + Secure Boot MOK docs | doc heredoc truncation |
| `20-snapper-structural.sh` | M20 native default-subvolume model + checked create/status/rollback + measured retention fixture | unsafe fstab/BLS state, non-root mutation, interrupted-resume drift, clock/default mis-deletion |
| `21-kernel-modules-structural.sh` | M21 normalized module policy, exact BLS selection, source-derived unit dependencies, Generic/host-only recovery transaction and canonical later Root/LUKS/Plymouth/MEI/Intel-GSC/NVIDIA validator | State/count drift, fake enforcement, incomplete or incorrect BLS selection, storage/crypto/controller/GSC omission, unsafe publication, stale candidate or uncoordinated writer claim |
| `22-luks-backup-wrapper.sh` | M22 LUKS detection, removable topology, pinned staging metadata, backup/verify transactions | incomplete mixed-disk fixture, descriptor-link metadata, unsafe staging or publication |
| `22-luks-partitioning-mount.sh` | M22 effective mount-option and durable fstab transactions, exact unit/helper graph, synthetic scrub recovery | flags in wrong fields or overridden by later options, failed reads/publication, invalid unit commands or host mount-target dependencies |
| `23-networkmanager-structural.sh` | M23 MAC privacy, physical IPv6 policy and native NetworkManager defaults: strict physical DoT plus best-effort opportunistic unset non-physical/VPN/private transport | hostname-mode regression, physical fail-open DNS, forced tunnel plaintext or a value rejected by NetworkManager's parser |
| `24-fwupd-structural.sh` | M24 telemetry/P2P off + exact refresh masks + boot-dormant on-demand daemon + Flatpak-only Software/three-pass Silent Machine gate | background update traffic, persistent fwupd, native-backend wakeup or broken manual firmware path |
| `25-update-process-structural.sh` | M25 update orchestrator/GUI, exact VTE ABI, honest completion state, native reboot-reader and inventory error/schema fixtures, user-owned AIDE check and locked canonical post-DNF boot-image validation | spawn/step/pin drift, false completion or reboot readiness, AIDE trust mutation, uncoordinated kernel transaction or direct Dracut writer |
| `26-native-integrations.sh` | Native package activation, privilege and API contracts | added autostarts, special privileges, relaxed UDisks authorization or unmasked CPU-control services |
| `26-package-set-structural.sh` | M26 exclusions, Tier-1 apps, rebrand swap and explicit four-app Python-GI/GTK4/libadwaita runtime plus Update's VTE | exclusion or GUI-runtime dependency regression |
| `27-hardware-tuning-structural.sh` | M27 Fedora/kernel performance and EEE ownership, native udev/.link parsers, WoL + USB/SD noexec/external-NTFS policy and exact runtime-gate contract | returned scheduler/HWP/zram/EEE/sync/BDI bet, parser/WoL rule rot, removable-media execution or missing behavior gate |
| `28-local-ai-structural.sh` | M28 Option ordering (A=RamaLama, B=Ollama) | Regression of RamaLama-primary decision, llama-vscode/WebUI editor section or preserved CVE notes |
| `29-user-docs-heredoc.sh` | All 4 M29 Tier-A docs extract correctly + cross-module semantics and DNS CLI discoverability | Heredoc truncation; broken cross-links; VPN/GNOME/dconf/DNS claim drift |
| `30-user-docs-tier-b.sh` | M30 6 Tier-B docs + noid-help CLI, including global DNS mode/recovery | doc or DNS-scope drift, CLI alias rot |
| `31-user-docs-tier-c.sh` | M31 operational docs + canonical threat/scope/PQ/performance/license sources | heredoc truncation, source parity, DNS/performance ownership or cross-ref drift |
| `32-avatar-face.sh` | M32 avatar + face-gallery — /etc/skel/.face{,.icon}, AccountsService backfill service + path-unit | missing avatar install lines, dconf override wrong path, accidental locks file |
| `32-branding-structural.sh` | M32 os-release + issue + trademark disclaimer | trademark rot |
| `32-include-count.sh` | master.ks %include references resolve + every snippet wired in (no orphans) | missing/orphan snippet, include-vs-snippet count mismatch |
| `32-plymouth-theme.sh` | M32 Plymouth bgrt theme — M26 label plugin, M21 sole transactional target-kernel Dracut writer + exact Plymouth candidate artifacts | label plugin/theme missing, competing M32 Dracut writer, candidate lacks branding |
| `33-config-validation.sh` | Fedora 44 pykickstart validation of flattened master.ks plus JSON/systemd/NM/desktop structure | Invalid Kickstart grammar or malformed generated configuration |
| `33-operational-hygiene-structural.sh` | M33 standards/live-evidence hygiene: 3 docs + 2 CLI + stamp + user-invoked-only invariant | doc truncation, unsupported security claims, CLI regression, unsafe payload publication, accidental service/timer ship or stamp-order violation |
| `34-firefox-playground-structural.sh` | M34 dual-profile: amnesic overrides + .desktop + dconf auto-pin + init script + packaged Firefox icon lookup + stamp | missing amnesic pref, dconf lock regression, init-script idempotency break, duplicate icon/rendering pipeline |
| `35-thunderbird-structural.sh` | M35 embeds, AutoConfig, DKIM, skel and native process/CLI fixtures | pin drift, AutoConfig regression, profile changes after failed process queries |
| `36-mtu-audit-fixture.sh` | M36 tunnel-MTU audit behaviour: full-tunnel self-routing, unevaluable and multi-route peers, ordinary/locked route MTUs, the RFC 8200 1280 IPv6 floor, and owner-specific persistent guidance | measuring the inner link as the outer one, a green verdict from an unevaluable peer, hiding the strictest local MTU, printing a correction that breaks configured IPv6, or persisting a provider-owned runtime profile |
| `36-noid-network-structural.sh` | M36 Network app — persistent suite header, adaptive navigation, global DNS transport truth/control, formatted WAN/firewalld/nft audits, synchronized WAN/LAN truth and serialized privilege lifecycle | stale controls, shell injection/truncation, false DNS/VPN scope, false parity, overlapping mutation, unsupported grant or identity drift |
| `37-noid-tools-structural.sh` | M37 Tools app — curated helper catalog including Laptop Lid Close and Global DNS Transport, repo-deploy coverage gate, read-only drop-down defaults, unique emoji prefixes, single-hold terminal wrapper and icon/stamp wiring | dead catalog rows, uncurated new helpers, mutating defaults, duplicate emojis, wrapper or wiring drift |
| `37b-noid-cli-presentation-structural.sh` | Complete Tools CLI presentation inventory derived from M37's catalog | an exposed first-party helper retaining an unreviewed or inconsistent terminal presentation |
| `40-audit-bundle-structural.sh` | M40 exact commit/size/SHA-pinned auditor + offline wrapper default + disabled self-update | source mutation, active-network default, TLS-only root-script replacement, or pin drift |
| `41-anaconda-cleanup-structural.sh` | M41 installed-system Anaconda/live-user cleanup plus Live/install host-identity lifecycle | live-only accounts, sudoers, installer evidence or reused machine-local identities surviving installation |
| `42-forensic-retention-structural.sh` | M42 exact log/AIDE-report/archive scopes, invocation report creation/retention, native SWTPM rotation and failed-write preservation, native units and source helpers in a private root, UPower/audit/NM lifecycle behavior, durable publication and excluded AIDE trust state | overbroad deletion, mismatched report retention, missing unit helpers, live-daemon fake clearing, profile rollback loss, trust-state deletion, partial publication or swallowed failure |
| `99-finalize-structural.sh` | M99 cross-module sanity, native ACL unit/source-helper validation in a private root, closed system-mask and libdnf5 action inventories executed against fixtures, complete four-app release gate and rejection of compose-created AIDE trust state | app/runtime/desktop contract, missing unit helpers, stamp-read loop, unreviewed mask/action drift or trust-boundary drift |
| `99-live-payload-acl-parity-fixture.sh` | Rootless raw/SquashFS/installed offline-root fixture with absolute systemd enablement links | Host-root resolution of an image-root symlink and false ACL release-gate failure |

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
sudo bash tests/pre-ship/03-firewalld-capabilities-runtime.sh live
sudo bash tests/pre-ship/03-firewalld-capabilities-runtime.sh fresh-install
sudo bash tests/pre-ship/03-firewalld-capabilities-runtime.sh reboot
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
bash tests/pre-ship/16-browser-license-notices.sh /          # candidate root
sudo bash tests/pre-ship/16-browser-image-parity.sh live
sudo bash tests/pre-ship/16-browser-image-parity.sh fresh-install
sudo bash tests/pre-ship/16-browser-image-parity.sh reboot
bash tests/pre-ship/16-browser-runtime-parity.sh live        # normal VM user
bash tests/pre-ship/16-browser-runtime-parity.sh fresh-install
bash tests/pre-ship/16-browser-runtime-parity.sh reboot
bash tests/pre-ship/16-fpp-relaxation-runtime.sh             # normal VM user, live pass
# In QEMU/KVM, attach unmounted fixtures with six distinct filesystem UUIDs:
# one 768-MiB removable=1 USB disk with four 128-MiB partitions (NOID_VFAT,
# NOID_EXFAT, NOID_NTFS, NOID_EXT4), a 128-MiB ext4 NOID_FIXED USB disk with
# removable=0 and a 128-MiB ext4 NOID_SD native SD card.
# Use GPT for the 768-MiB USB disk and preserve all fixtures across phases.
sudo bash tests/pre-ship/27-hardware-tuning-runtime.sh live
sudo bash tests/pre-ship/27-hardware-tuning-runtime.sh fresh-install
sudo bash tests/pre-ship/27-hardware-tuning-runtime.sh reboot
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
sudo bash tests/pre-ship/20-snapper-rollback-runtime.sh crossing-prepare  # then install a newer kernel; no reboot
sudo bash tests/pre-ship/20-snapper-rollback-runtime.sh crossing-rollback  # then reboot
sudo bash tests/pre-ship/20-snapper-rollback-runtime.sh crossing-reboot
# Separate disposable clone: each recover runs in the temporary fallback boot;
# each following arm/verify runs after another normal reboot into restored Generic.
sudo bash tests/pre-ship/21-dracut-powerloss-runtime.sh select-recovery
sudo bash tests/pre-ship/21-dracut-powerloss-runtime.sh recover
sudo bash tests/pre-ship/21-dracut-powerloss-runtime.sh arm  # then host: virsh destroy
sudo bash tests/pre-ship/21-dracut-powerloss-runtime.sh recover
sudo bash tests/pre-ship/21-dracut-powerloss-runtime.sh verify
sudo bash tests/pre-ship/06-wan-threat-boundary-runtime.sh live
sudo bash tests/pre-ship/06-wan-threat-boundary-runtime.sh fresh-install
sudo bash tests/pre-ship/06-wan-threat-boundary-runtime.sh reboot
sudo bash tests/pre-ship/25-installed-package-freshness.sh  # in installed VM
bash tests/pre-ship/99-live-payload-acl-parity.sh \
  /mnt/raw-compose /mnt/squashfs /mnt/installed
sudo bash tests/pre-ship/12-installed-enforcing-avc.sh      # in installed VM
```

The scripts report their own checks and return a failing status when their
requirements are not met. Package freshness is read-only: it checks current
Fedora metadata without installing updates. Recovery and state-transition
tests require disposable VMs; hardware-dependent checks require suitable
hardware. These commands are a usage reference, not results for a particular
ISO. Completed ISO results are summarized in the release notes.

## Add a new test

```bash
# File name: NN-<module-or-topic>-<what>.sh
# Example:   tests/03-firewalld-zones.sh
```

Naming rule for `tests/` and `tests/pre-ship/`: the prefix is the number of
the Module that owns the verified behavior (two digits, plus a letter for a
companion test such as `13b`); cross-module and release gates owned by the
finalizer use `99`. Execution order is never encoded in a file name: the suite
runs in discovery order, and candidate-VM order is defined by the command
block above and the individual scripts' prerequisites.

Scratch directories: a test that executes fixture programs creates its
private directory with `make_exec_tmpdir <label>` from `tests/lib.sh`. It lives
under `/var/tmp` (exec-capable and disk-backed; `/tmp` is noexec on the
hardened host) or under `NOID_TEST_EXEC_TMPDIR` when set, and never inside the
checkout.

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
#   assert_not_grep_extended <regex> <path> [desc]
#   assert_not_grep_fixed <literal> <path> [desc]
#   assert_eq <expected> <actual> [desc]
#   assert_cmd_success <desc> <cmd> [args...]
#   assert_cmd_failure <desc> <cmd> [args...]   (a missing command fails)
#   assert_cmd_status <expected-rc> <desc> <cmd> [args...]
#   _skip <desc>                                  (explicit capability skip)
#   extract_heredoc <ks-file> <marker> <target> [occurrence]
#   dir=$(make_exec_tmpdir <label>)

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
image. `run-all.sh` fails at preflight (exit 2) if any prerequisite listed
under "Run everything" is unavailable. Direct execution of
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
- Whether the image boots and works after installation and reboot
- Whether fwupd sees the firmware after install
- SELinux AVCs that only appear at runtime

Those require the documented **candidate-VM and Pre-Ship gates** after a real
build; they are deliberately outside `run-all.sh`.

`35-thunderbird-structural.sh` also checks the compiled Remote Settings
signature flag when the test host has an installed Thunderbird `omni.ja`.
It reports that one package inspection as `[SKIP]` when the archive is absent;
this does not skip the source, process or profile-publication fixtures. This
host-package check does not establish candidate-image behavior.

`16-browser-gate-contract.sh` validates the paired candidate-only browser
gates' source contract. It does not read the build host's installed browser
state. The root-owned image parity
gate and the actual normal-user launches run through
`tests/pre-ship/16-browser-image-parity.sh` and
`tests/pre-ship/16-browser-runtime-parity.sh`, respectively, in the live,
fresh-install and reboot candidate passes.

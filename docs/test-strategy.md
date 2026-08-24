# Test Strategy

Four complementary layers of testing — each catches a different class of bug.

## Layer 1: Semantic tests (`tests/NN-*.sh`)

**What they test**: source-of-truth invariants in
`kickstart/snippets/*.ks`. This includes structural assertions such as “must
contain X”/“must not contain deprecated Y” and, where a test owns the boundary,
executed extracted-helper or fixture paths. The complete gate requires
`bwrap` so M40's root-publication boundary is exercised rather than silently
treated as a successful check.

**Shared assertion framework**: minimal custom library (`tests/lib.sh`) with
`assert_grep`, `assert_file_exists`, `assert_grep_fixed`,
`assert_not_grep`, etc. The library itself uses Bash and standard text tools;
individual tests declare or capability-check additional native tools where
their subject requires them.

**Run all**: `bash tests/run-all.sh` (host-dependent; currently tens of
seconds, with no intentional system modification). The unfiltered release gate
preflights AIDE, Bubblewrap, the clang/libbpf BPF build toolchain, SELinux
policy compilation/packaging, desktop and Kickstart validation, the Python
`auparse` binding, systemd unit/tmpfiles validation, sudoers validation, and
the USBGuard tools used by the hermetic notifier graph. On Fedora 44 install
them with `sudo dnf install ShellCheck aide acl binutils bubblewrap checkpolicy
clang dconf desktop-file-utils git glib2 gvfs jq kernel-headers libbpf-devel
patch policycoreutils pykickstart python3 python3-audit sudo systemd systemd-udev
usbguard usbguard-notifier`. A missing prerequisite exits as a harness error
before a partial result is printed.

The M13 AIDE fixture deliberately performs an unprivileged comparison against
a temporary database. Fedora's audit-enabled AIDE may write
`Failed sending audit message:added=...` to that editor/terminal scope when the
fixture detects its seeded differences but cannot submit an audit anomaly.
This is test-process evidence, not an `aide-check.service` failure: correlate
the verbose journal metadata with the fixture path and test window, and still
require `auditctl -s` to report `lost 0`. Do not run the suite as root merely to
turn that diagnostic into a privileged audit event.

**Coverage**: 84 structural tests total, with hundreds of assertions. Every Module
(M01–M37 + M11b + M40 + M41 + M42) has at least one structural test +
`99-finalize-structural.sh` for the final gate + `32-include-count.sh`
for master.ks wiring + `33-config-validation.sh` for JSON/XML/systemd
unit sanity + `36-branding-structural.sh` for M32 rebrand. 4 smoke tests
(`tests/smoke/M02-sysctl`, `M17-gnome`, `M23-nm`, `M27-hardware`)
exercise selected %post blocks in a bwrap sandbox.

**What they catch**:

- Regression: a snippet edit that drops a critical line.
- Supply-chain bypass: `verify_sha256` call removed.
- Deprecated pattern: `X-GNOME-Autostart-Phase` reintroduced after
  NF-1/2/7 fix.
- Wrong paths: `/etc/foo` typo'd as `/etc/food`.

**What they do NOT catch**:

- Semantic errors in behavior that no assertion or executed fixture covers.
- Runtime failures (a service fails to start on real hardware).
- ISO build failures (livemedia-creator rejects the kickstart).

## Layer 2: `bash -n` syntax + pykickstart validation

**What they test**: syntactic correctness of every `.ks` file and
embedded shell script.

**Run**: part of `tests/00-syntax-sweep.sh`; also `pykickstart`
validation via `ksflatten` + `ksvalidator -v F44` on the flattened
master.ks (snippets are fragments — per-file validation always fails).

**Coverage**: 43 kickstart files (master.ks + 42 snippets including 99-finalize)
+ every shebang-prefixed heredoc payload extracted by the current heredoc
test: Bash/sh payloads are syntax-checked and passed through the blocking
ShellCheck gate; non-shell payloads are classified and skipped by ShellCheck.
The test prints the current extraction and classification tallies on each run.

**What they catch**:

- Missing `fi`/`done`/`esac`.
- Unquoted string with special chars.
- Obvious syntax errors (typo `cat >foo`, missing `)` in case).

**What they do NOT catch**:

- Semantic errors (`sed -i 's/a/b'` missing trailing slash).
- Runtime command failures (`mount -o noexec` when mount doesn't exist).
- Semantic/content errors in non-shell heredocs; shell-classified heredocs are
  syntax-checked separately but still need behavioral tests.

## Layer 3: VM smoke test (manual, pre-release)

**What they test**: end-to-end build + install + boot of the ISO in a
VM. Exercised against the 16-point matrix maintained inline in
[`docs/release-process.md`](release-process.md).

**Tools**: `qemu-system-x86_64` + `virt-manager`.

**Coverage**: install path, first boot, network (with/without VPN),
LUKS unlock, SELinux, audit rules, snapper snapshot, fwupd, DNS, NTP,
Firefox firstboot setup, AIDE's initially untrusted/disabled state plus an
explicit user-reviewed candidate workflow, and noid-update-all dry-run.

**Run**: manual. Automating it (QEMU + `expect`) is future work.

After installation, the networked release candidate must also pass
`tests/pre-ship/03-lan-xdp-runtime.sh`. In disposable network namespaces it
submits the exact installed object to the running kernel verifier, forces
generic XDP, attaches TC, proves an allowed interface/IP/MAC peer works only on
its authorized NIC, and proves the same identity on a second NIC is dropped
before ordinary AF_PACKET capture. It also injects 36 invalid or explicitly
unsupported raw fixtures, seven baseline-valid frames and two additional DHCP
frames for Stable-MAC rotation, covering reachable truncation, declared
length, both unsupported PPPoE EtherTypes, IPv4/transport checksum,
Ethernet/ARP identity, standard ARP reply/request/Probe/Announcement,
DHCP/EAPOL, Stable-MAC rotation, related-ICMP and fragment cases;
drop/pass counters and a concurrent AF_PACKET capture must agree exactly. A
sub-Ethernet-header frame is source-gated because both AF_PACKET and the
kernel XDP test runner reject such an input before program execution. Set
`NOID_REQUIRE_NATIVE_XDP=1` on the native-XDP matrix target.
The direction fixture separately proves that add, edit, revoke and rollback
request exact peer-flow invalidation before a peer policy can be published.
Release qualification then repeats an outbound grant/revoke/re-grant in the
two-VM LAN lab and verifies that an old reverse tuple cannot admit a new SYN
outside the current inbound selector.

`tests/pre-ship/03-lan-direction-nft-runtime.sh` separately exercises the
ordered host-output path in a disposable network namespace. It proves that
root-owned IPv4 UDP 68-to-67 renewal, broadcast and routed DHCP requests reach
a hook after both M03 and the modeled firewalld policy. The namespace uses a
directly assigned address, proving the topology path is independent of DHCP.
An explicit peer grant retains ordinary and source-68 traffic, and global LAN
allow removes the default-only source-68 fallback together with the other LAN
drops. Outside those explicit grants, a non-root sender, adjacent ports,
arbitrary source-68 payloads, broadcast misuse and ordinary LAN application
traffic remain blocked. Its ordinary-WAN positive control prevents a
blanket-output drop from producing a false green. The structural gate
additionally proves that the derived VM policy deletes the host-only DHCP
continuation.

The candidate must then pass
`tests/pre-ship/29-installed-package-freshness.sh`. That gate refreshes only
Fedora base/stable-updates metadata, records repository revision evidence and
rejects both any available Fedora upgrade and any
Critical/Important/Moderate security advisory.

Kernel-command-line validation is a separate three-pass, non-skippable gate.
`tests/pre-ship/01-kernel-cmdline-runtime.sh` takes only `live`,
`fresh-install` or `reboot`, uses the same closed manifest/parser as the M01
source test, rejects duplicate/conflicting managed families, and requires the
effective hardware-conditional set. Installed passes additionally require a
successful firstboot result and the Fedora-native transport split: every normal
BLS entry is the semantic `/etc/kernel/cmdline` plus exactly one trailing
`$tuned_params` macro. During M21's pending phase, exactly one Generic recovery
entry may append only its exact recovery marker after that macro;
source/comment matches cannot substitute for this proof.

The separate `tests/pre-ship/01-timezone-runtime.sh` gate first runs before any
deliberate Live-session timezone change with the exact `live` pass ID. It
requires Anaconda's neutral `UTC` symlink, systemd's effective timezone and the
UTC hardware-clock mode. This catches the Live installer boundary where
Anaconda ignores the build-time master kickstart and uses
`interactive-defaults.ks`; the M01 source/compose gates independently bind the
installed-target directive to the same neutral default. GNOME Initial Setup
requires a timezone selection before the first installed account is usable,
so claiming an untouched installed runtime pass would be impossible. The
`fresh-install` and `reboot` passes instead take the consciously selected IANA
timezone as an explicit argument, require it exactly in `/etc/localtime` and
systemd, and require the hardware clock to remain UTC across the reboot.

M02's irreversible BPF choice is also checked in every lifecycle pass by
`tests/pre-ship/02-unprivileged-bpf-runtime.sh`. The gate requires effective
value 1, a minimal unprivileged `bpf()` call rejected with `EPERM`, and a
failed root write of value 0 with the value still 1. An unexpectedly accepted
write is immediately ratcheted back to 1 and blocks the candidate.
`tests/pre-ship/02-sysctl-runtime.sh` closes the rest of M02 in the same three
lifecycle passes. It checks exact type/owner/mode/link metadata and source-byte
identity for all three installed files, then expands every wildcard and
compares all 105 directives with every selected concrete `/proc/sys` node.
This detects a syntactically valid boot policy that a later network component
has drifted at runtime.

M08 codec completion has its own root-only lifecycle gate:
`tests/pre-ship/08-codec-runtime.sh`. Its explicit expected-state argument
prevents auto-detection from hiding an untested branch. The canonical sequence
is Live `pristine`, fresh-install `pristine`, explicit user codec opt-in,
fresh-install `complete`, then reboot `complete`. Pristine proves that the
service is disabled and every deferred payload remains absent. Complete
requires canonical helper/unit/wrapper bytes, private exact transaction
receipts, package payload and cached dependency integrity, then generates
H.264, HEVC, VP9 and AV1 fixtures locally. All four must decode through FFmpeg
and the dedicated GStreamer factories; each Intel/AMD profile actually
advertised by `vainfo` must also complete an explicit FFmpeg VA-API decode.
This does not turn a protected-media service, resolution or CDM result into an
image claim.

The complete pre-ship command block in `tests/README.md` is the canonical
candidate ledger. Release evidence records a sorted executable inventory and
one result for every listed command/action; the 16-point smoke summary is not a
substitute. This future-closes the release process when a new executable gate
is added: an undocumented inventory entry or a missing/non-PASS ledger entry is
a release blocker.

M07 TCP timestamps and all M10 identity/session gates are three-pass evidence,
not source-only policy claims. The M07 gate requires effective value 1 and the
exact policy-file boundary. M10 separately proves logind inhibitor behavior,
login privacy, concurrent and crash-safe Bash history, RPM-owned permission
policy, effective umask and real system/session QEMU core-limit processes.
Bash-history and umask run as the normal VM user. The libvirt gate also runs in
that user context after `sudo -v` so it can exercise both driver modes; the
other M10 gates run as root.

M11 chrony uses an action matrix rather than one generic PASS. Each lifecycle
pass proves the offline boundary, controlled-WAN NTS state, cookie restart and
journal-backed suspend/resume recovery; `fresh-install` additionally performs
the destructive disposable-cookie `fresh-ke` action. It also performs the
`rtc-bootstrap` action on the first installed boot after libvirt injected a
+7200-second UTC-basis RTC offset. That gate requires an authenticated measured
correction in the 6900–7500-second class, `LocalRTC=no`, active automatic time
and completed synchronization; this covers firmware which stores local civil
time without weakening NTS certificate validation. Every action in
`tests/README.md` is retained separately. The Live pass binds Fedora's
RPM-owned `livesys` removal of `rtcsync`, which prevents a Live environment
from writing the hardware RTC; both installed passes instead require the
directive in the exact closed configuration. Every public NTS-KE dependency
must return a valid hostname-bound chain and negotiate both exact TLS 1.3 and
ALPN `ntske/1`; merely offering that ALPN from the client is not evidence that
the server selected it.
For VM evidence, suspend means guest ACPI S3 with host-side QMP `SUSPEND` then
`WAKEUP` event evidence, or equivalent `query-status` transitions through
`suspended` and back to `running`; save, snapshot and pause operations do not
exercise that lifecycle. A black SPICE scanout by itself proves neither
suspend failure nor resume success. Serial-console kernel entry/exit, QMP
lifecycle evidence and a passing post-resume gate qualify the non-graphical
path only; if SPICE remains black, record the virtual-display harness
limitation and rerun the GUI/display portion with a maintained alternative
virtual video model or physical target.
M04's extracted resolver fixture independently delays address publication,
proves that two online sources cannot satisfy M11's `minsources 3`, and proves
that bounded exhaustion records aggregate counters before returning all
sources offline.

The normal GNOME user also runs M17 display-power, JIT and Wayland gates in all
three passes. M19's post-Shell activation environment is a separate
normal-user lifecycle gate. `tests/pre-ship/19-gsk-session-runtime.sh` binds
the real local `Class=user` graphical session, the systemd-owned GNOME Shell
MainPID, unit and marker metadata, automatic-mode status and the effective
user-manager environment. A matched portable NVIDIA-offload topology must
have exactly `GSK_RENDERER=gl` for future systemd/D-Bus activations while
GNOME Shell has no renderer override; an unmatched topology must retain the
vendor default. A transient local socket probe proves that the honest
`RestrictAddressFamilies=AF_UNIX` boundary permits AF_UNIX and rejects AF_INET
without relying on `PrivateNetwork=`.

Before manually opening GNOME Software or invoking Update All in
each pass, that user runs `sudo -v` and then
`tests/pre-ship/24-silent-update-runtime.sh`. The cached ticket supplies only a
bounded noninteractive read of root-only `fwupd.conf`; the gate remains in the
normal user's GNOME and session-D-Bus context. The gate
performs a real denied session-bus activation, rejects any resulting Software,
DNF-daemon, fwupd-refresh or passim activity, verifies boot-dormant native
fwupd activation plus update-aware settlement, resolves and launches the
effective Flatpak-only direct-execution admin launcher, then exercises the
separate named Fedora-RPM one-shot with `dnf5` active and `fwupd` absent,
completely quits it, and proves the next ordinary launch is Flatpak-only again.
It also binds the deliberate firmware refresh/prompt/update path in the
deployed Update All helper. Privacy
cleanup has two actions per pass with a real logout/login between `prepare` and
`verify`. M06's WAN
threat-boundary gate independently requires all three pass identities and exact
capability-empty `EPERM` results; firewall configuration text alone cannot
substitute for those runtime checks.

Native IPv4 conflict detection is a separate three-pass gate:
`tests/pre-ship/04-ipv4-acd-runtime.sh`. It requires M04's enabled pre-network
state guard, rejects every retired hookless nft/firewalld shadow artifact,
parses the exact root-owned gateway pin without sourcing state, checks
NetworkManager's effective 200 ms DAD default and rejects any active physical
profile that explicitly disables it. A private veth/netns pair then proves a
duplicate address is rejected and the same address is accepted after the peer
releases it. M03's crafted-XDP matrix independently proves the ARP frames reach
the earliest packet boundary. The source fixtures additionally reproduce
iproute2's exact-device neighbour output without a redundant `dev` field, a
gateway-less `pre-up`, the exact-interface route fallback at `up`,
failure-triggered disconnect, closed state/marker/lock metadata, retained XDP
identity during kernel-pin opt-out, byte-identical awaited/no-wait dispatcher
publication plus exact rollback, and the firstboot service's real
IPv4/privilege-drop sandbox requirements.

MAC-pseudonym release evidence is installation-scoped, not a configuration
text claim. The mounted candidate SquashFS must contain no
`/var/lib/NetworkManager/secret_key`; its canonical `/etc/machine-id` is an
empty root-owned regular file and systemd/Anaconda must generate the target
identity natively. The first NetworkManager seed must be a root-only `nm-v2`
key.
The associated Wi-Fi address must be locally administered, unicast and
different from the permanent address; it must remain stable across a same-SSID
reconnect and reboot. A second disposable installation identity must produce a
different same-SSID pseudonym. Record only Boolean results and timestamps in
release evidence, never the IDs, seed bytes, SSID or MAC values.

The final-SquashFS hygiene gate additionally requires BRLAPI, NVMe host IDs,
the systemd random seed, compose network state and compose/Anaconda/Kickstart
logs to be absent. At Live boot M41 creates only the missing BRLAPI/NVMe set;
before the first installed login it rotates that set again unless an active
NVMe-over-Fabrics controller makes identity changes unsafe. The mandatory
two-install `41-host-identity-uniqueness.sh` gate records private per-field
digests and proves that machine-id, random seed, BRLAPI key, NVMe host ID and
NVMe host NQN all differ. Only its Boolean verdict enters release sign-off.

Browser validation is a paired three-pass, non-skippable candidate gate. Run
`tests/pre-ship/19-browser-image-parity.sh` as root and then
`tests/pre-ship/19-browser-runtime-parity.sh` as the normal desktop user with
the exact pass identity `live`, `fresh-install` and `reboot`. The root gate
compares the canonical repository sources with every installed source and
root-owned skel/config copy, then checks module stamps, metadata and license
notices. The user gate validates active profile-local XPI and permission bytes,
launches the real Firefox and Thunderbird binaries, and requires the expected
effective preferences plus active, non-disabled uBlock Origin and DKIM Verifier
records. A source-host structural test only validates this contract; it never
substitutes an older host installation for candidate runtime evidence.

USBGuard named-IPC validation is independently mandatory in the same three
passes. Run `tests/pre-ship/14-usbguard-runtime.sh` as root with `live`,
`fresh-install` and `reboot`. It requires broad group/user daemon grants to be
absent, exact root and eligible-user ACL bytes/metadata, no legacy
supplementary `usbguard` membership, active daemon/D-Bus services, an unchanged
rules file across denied policy/parameter probes, and the idempotent
device-modify operation required by the upstream notifier. This gate tests the
runtime privilege split; the structural gate separately pins the notifier's
temporary-allow semantics and documents USBGuard's inability to distinguish
temporary from permanent device modification within `Devices=modify`.

Hardware-tuning validation is independently non-skippable in the same three
passes. Run `tests/pre-ship/20-hardware-tuning-runtime.sh` as root with the
exact `live`, `fresh-install` and `reboot` identities. Attach one 768 MiB GPT
QEMU USB disk with `removable=1` and exact 128 MiB VFAT, exFAT, NTFS and ext4
partitions labeled `NOID_VFAT`, `NOID_EXFAT`, `NOID_NTFS` and `NOID_EXT4`;
attach a separate 128 MiB ext4 QEMU USB disk labeled `NOID_FIXED` with
`removable=0`, and a 128 MiB native QEMU SD ext4 fixture labeled `NOID_SD`.
Use six distinct filesystem UUIDs, start unmounted, and preserve/re-attach the
same backing images across all passes. The gate rejects physical hosts,
ambiguous labels, wrong parents, pre-existing mounts and any other declared
size or filesystem. The source suite uses `udevadm verify` and the native
`net_setup_link` parser; the VM gate then proves the effective `.link` winner,
Fedora/kernel ownership, observed live schedulers, effective UDisks
`noexec,nodev,nosuid` mounts without blanket `sync`, retained vfat `flush`,
ntfs3 for external NTFS, direct-exec denial plus the interpreter boundary on
all filesystems/classes, and the explicit allowed `exec` override on every USB
matrix filesystem. Its `.com` probe retains execute bits under VFAT `showexec`,
so the denial cannot be falsely attributed to VFAT's emulated file mode. It
reads and compares real whole-device `queue/write_cache` and FUA values, carries
fsynced data hashes across live → fresh-install → reboot, completes safe
power-off for USB and clean unmount for SD, then verifies exact earlyoom argv,
active tuned services,
Fedora-owned effective zram state, the Fedora-owned thermald outcome and the M08 intel_lpmd mask
(single-EPP-writer policy). Lenovo DYTC is recorded as inventory rather than
used to disable thermal protection. An Intel HWP path is recorded rather than
forced. Hardware without driver-visible WoL support is reported as N/A only
after the applicable policy selection is proven. Whenever a WoL state is
exposed, the gate requires disabled; a capability without a current state
fails. EEE is not probed or mutated because it remains Fedora/driver-owned.
The external-storage threat boundary, physical measurements and primary
sources are in
[`external-storage-policy.md`](external-storage-policy.md).

M21's installed Dracut transition has a separate three-pass candidate gate:
`tests/pre-ship/21-dracut-hostonly-runtime.sh`. The live pass proves that the
portable image has no installed-transition artifacts. The fresh-install pass
requires a fully validated host-only candidate, a byte-inspectable Generic
recovery image/BLS entry, Generic as GRUB's persistent saved default and the
normal candidate as the one-shot `next_entry`. The reboot pass is the actual
bootability proof: it requires a distinct boot ID on the target kernel, the
normal entry restored as the saved default, retired recovery artifacts and no
first-shutdown mdraid-wait evidence in the persistent previous-boot journal.
The fresh pass also calls the shared guard and later atomic regenerator while
the trial is pending and hashes all three transaction objects before/after, so
fail-closed is proven non-mutating. The reboot pass requires the exact
`basis=hostonly` terminal record.
M21 `fresh-install` and `reboot` must both pass before the destructive Snapper
fresh pass. While M21 is pending, the shared guard deliberately refuses every
other boot writer, including Snapper rollback. Therefore the two candidate
transactions use separate reboots: first confirm M21's host-only basis, then
run Snapper `fresh-install` last and reboot again into its selected root.
`lsinitrd`, Dracut success or source greps cannot substitute for either real
reboot.

An additional disposable clone must pass
`tests/pre-ship/21-dracut-powerloss-runtime.sh`. Its `select-recovery` action
boots the reviewed fallback, and `recover` proves the resulting
`recovered-generic` baseline. Because the temporary fallback is never an
allowed writer basis, the operator reboots into the restored standard Generic
entry before `arm` requires the exact `basis=generic` guard record. `arm` then
runs the exact installed helper bytes with a transient Bash debug trap, stops
after the fsynchronized candidate publication but before the durable M21 state
write, and requires the KVM host to issue `virsh destroy`. After the operator
starts the VM and unlocks LUKS, a second `recover` invocation requires the
automatic Generic recovery marker, an abrupt prior journal rather than a clean
guest shutdown, the exact boot-ID-bound marker that `arm` fsynchronized before
READY, restored Generic standard image/default and
`phase=recovered-generic`, then publishes a boot-ID-bound observation
checkpoint. The operator reboots into the restored standard entry once more;
only there can final `verify` require `basis=generic` while binding the current,
recovery and interrupted journals to three distinct boot IDs. A shell signal or
normal guest reboot is not power-loss evidence.

Structural gates prove that M08, M15, M19 and M25 acquire this same contract
before their maintained boot mutations. Release evidence adds actual post-
convergence runs of the Gaming and MEI toggles plus the human-operated Update
All workflow in disposable clones. NVIDIA kernel/driver cycles require real
qualified NVIDIA hardware or PCI passthrough; a non-NVIDIA VM cannot close that
hardware-specific lane. The shared lock is not claimed to serialize arbitrary
root commands, foreign RPM scripts or third-party kernel hooks.

Snapper rollback has its own destructive three-pass candidate gate:
`tests/pre-ship/20-snapper-rollback-runtime.sh`. The live pass proves that the
overlay never becomes rollback-ready. The gate refuses non-QEMU/KVM hosts and
first binds its installed M20/M21 helpers, units, guards and destructive
Snapper/Btrfs binaries to the frozen checkout and current RPM evidence. The
fresh-install pass independently checks fstab, BLS, SELinux-labeled stable
state/mounts, every eligible desktop user's root-only boundary and the exact
argumentless Wheel sudo status path, then deliberately selects a disposable
snapshot and must run last before its own reboot. Exact
prepared/pending/ready records make the pass resumable across a shell
interruption; an already published default can be reconstructed only from the
matching durable helper record. After an abrupt reboot, the reboot pass may
finish a pending helper transaction only when its selected default is already
the running root. It cannot share M21's pending trial reboot:
M21's reboot pass must first expose the terminal `basis=hostonly` guard record.
The Snapper reboot pass then proves the selected root is actually
active/default and that a file created after the target snapshot disappeared.
Source greps or a `set-default` return code cannot substitute for that boot.

`tests/pre-ship/30-live-payload-acl-parity.sh` compares three explicitly
mounted roots: the retained raw compose disk, the ISO's extracted SquashFS and
the installed candidate. It requires the complete canonical ACL manifest in
raw and installed state, permits only exact preservation or the known
all-or-nothing SquashFS transport loss, and binds the reconstruction artifacts
byte-for-byte across installation. In the running installed VM,
`tests/pre-ship/31-installed-enforcing-avc.sh` separately requires SELinux
enforcing, audit immutable, zero lost audit events and zero AVC/USER_AVC records
for the current boot. Build-installer permissive AVC classification never acts
as an installed-system allowlist.

**What it catches**:

- Install-time failures (livemedia-creator success but anaconda error).
- First-boot service failures (a systemd unit tries to start too early).
- Runtime divergence: snippet says "mask X" but reality says X active.
- User-facing UX issues (a missing polkit rule, a broken .desktop).

**What it does NOT catch**:

- Real-hardware-specific issues (IOMMU group differences, NVIDIA GPU
  corner cases, USB 3.x XHCI quirks). Requires bare-metal testing.

## Layer 4: Reproducibility smoke test (pre-release)

**What it tests**: whether two builds of the same tag/commit and explicitly
pinned inputs, with the same `SOURCE_DATE_EPOCH`, produce identical ISO bytes.
This is an experiment with a reported result, not a guaranteed property.

**Tools**: `livemedia-creator` + `sha256sum` + manual host setup.

**Run**: manual, pre-release. See
[`docs/build-reproducibility.md`](build-reproducibility.md).

**What it catches**:

- Non-deterministic build inputs leaking into the ISO.
- Host-specific state (timestamps, random seeds) leaking.

## When to add a new test

Add a semantic test (Layer 1) for any:

- New external-content fetch (SHA256 pin verification test).
- New critical configuration file (path + key + value grep assertion).
- New systemd unit (heredoc marker + path + enable step).
- New security-critical kernel flag (grep the flag in bootloader).

Add a `bash -n` entry (Layer 2) — automatic for new .ks files via
`00-syntax-sweep.sh` globs.

Add a VM-test point (Layer 3) for any:

- New first-boot service that has user-facing effects.
- New config that impacts login / network / storage.

## Anti-patterns to avoid

### Tests that depend on live system state

Semantic tests must run on the kickstart source alone. Never reach
into `/etc/` or `/var/` on the host — that requires a VM, which
belongs to Layer 3.

### Tests that echo variables without quoting

`assert_grep $PATTERN $FILE` — if `$PATTERN` contains spaces, the
assertion silently checks the wrong thing. Always double-quote:
`assert_grep "$PATTERN" "$FILE"`.

### Tests that check for comments instead of active code

`grep -q 'X-GNOME-Autostart-Phase' file.ks` matches comments too. For
active-code checks use `grep -P '^\s*X-GNOME-Autostart-Phase\s*='`
(anchored, allows leading whitespace in heredoc).

### Tests that duplicate `bash -n`

`run bash -n` in a test body is redundant; `00-syntax-sweep` covers
the whole tree. Add semantic assertions only.

## CI integration (shipped — `.github/workflows/ci.yml`)

GitHub Actions workflow runs on every push + PR to `main`.
Six independent jobs are all required to pass:

1. **`syntax`** — `bash -n` on `master.ks` + all `kickstart/snippets/*.ks`.
2. **`tests`** — Fedora 44 job container with target-release ShellCheck,
   pykickstart, patch and Git packages; exact M40 auditor sibling checkout plus
   full `bash tests/run-all.sh` (all 84 structural).
3. **`shellcheck`** — warning/error gate over every shell script directly
   under `tests/`, `tests/smoke/`, `scripts/`, `scripts/lib/`,
   `scripts/anaconda-patch/` and `branding/icons/`, with the workflow's
   reviewed SC1091/SC2016/SC2012/SC2015 exclusions.
4. **`pykickstart`** — `ksflatten` + `ksvalidator -v F44` on the
   flattened master.ks in a `fedora:44` container (snippets are
   `%post`/`%packages` fragments, not standalone kickstarts).
5. **`pii-sweep`** — rejects Python caches, PNG time/EXIF/text metadata,
   personal home paths, MAC addresses and 32-character machine-id-like patterns
   across the project-owned docs, kickstart, scripts, tests, workflow and
   override trees; fails on an unlisted synthetic value. This is not a general
   name/e-mail detector, so human review remains required there.
6. **`supply-chain-verify`** — sync/pin checks:
   `scripts/regen-firefox-embed.sh --check` (M16 blob ↔
   `firefox/noid-firefox-hardening.js`), `regen-thunderbird-embed.sh
   --check` (M35 blob), `regen-thunderbird-mozilla-cfg.sh --check`
   (M35 heredoc ↔ standalone `thunderbird/mozilla.cfg`),
   `regen-ai-workspace-doc.sh --check`, `regen-local-ai-doc.sh --check`,
   `regen-wan-strict-doc.sh --check` and
   `regen-branding-shasums.sh --check` (branding manifest), plus complete
   HTTPS downloads and SHA-256 verification of the exact pinned uBO and DKIM
   Verifier XPIs (catches upstream tag drift, replacement or takedown).

What's **not** in CI yet:

- **bwrap helper smoke tests** (`tests/smoke/run-all.sh`, M02/M17/M23/M27) —
  the PR-template checkbox is a local-only gate: the default jobs do not
  provide the privileged user-namespace/installroot and prepared-rootfs
  boundary documented in `tests/smoke/README.md`. CI only shellchecks the
  smoke-test sources.
- **Layer 3 VM smoke test** — still manual (QEMU + 16-point matrix in
  `docs/release-process.md`). Candidate for `expect`-driven
  automation on a self-hosted runner.
- **Layer 4 reproducibility smoke test** — manual pre-release. Needs
  two controlled builds of the same revision, inputs and toolchain plus a
  digest-only `sha256sum` comparison; no GitHub-runner-native
  solution yet.
- **Actual ISO build in CI** — `livemedia-creator` needs KVM which
  GitHub default runners don't provide. Self-hosted runner or tag-only
  trigger would unblock this.

# Release Process

Covers the v1.x release process, versioning, release-notes template, ISO
signing, publishing, and tagging.

## Version scheme

The project uses a compact SemVer-inspired tag convention: a stable minor
release omits the trailing `.0` (`v1.7` corresponds to SemVer `1.7.0`), while a
hotfix adds the patch component (`v1.7.1`).

| Component | Meaning | Example bump |
|-----------|---------|--------------|
| **Major**  | Breaking public contract or compatibility change, including a removed Module | `v1.7` → `v2.0` |
| **Minor**  | Additive change — new Module, new user docs, hardening added | `v1.6` → `v1.7` |
| **Patch**  | Bug fix, doc fix, CVE mitigation within a Module | `v1.7` → `v1.7.1` |

Pre-release: use `-rc.N` (`v1.7-rc.1`, `v1.7-rc.2`, `v1.7`).

## Release cadence

- **Minor releases**: no guaranteed calendar cadence; cut only after the
  documented gates pass for a coherent additive release.
- **Patch releases**: as needed for CVE fixes or reproducibility bugs.
- **Major releases**: only for breaking product/interface contracts. A Fedora
  base migration does not by itself force a major bump unless it breaks one.

## Pre-release checklist

### 1. Code gate
- [ ] All `tests/run-all.sh` pass
- [ ] `bash -n` sweep clean on 43 kickstart files (master.ks + 42 snippets including 99-finalize)
- [ ] `pykickstart` validation clean
- [ ] `for s in scripts/regen-*.sh; do bash "$s" --check || exit 1; done` clean
      (every source generator in sync; the same sweep is enforced per script
      by `tests/00-source-generators.sh`)
- [ ] Git working tree clean

### 2. Documentation gate
- [ ] `CHANGELOG.md` updated with release section
- [ ] `docs/*.md` cross-references correct
- [ ] `INDEX.md` reflects current Module layout
- [ ] `README.md` version/feature claims accurate

### 3. Supply-chain gate
- [ ] `firefox/noid-firefox-hardening.js` reviewed (any diff vs prior
      tag needs eyes; bump its `NOID_FIREFOX_HARDENING_VERSION` + the
      comment header if refreshing from upstream arkenfox)
- [ ] M16 embedded blob regenerated via `scripts/regen-firefox-embed.sh`
      if `firefox/noid-firefox-hardening.js` changed
- [ ] `thunderbird/noid-thunderbird-hardening.js` reviewed against the latest
      tagged HorlogeSkynet release and the shipped Thunderbird engine; any
      accepted base change is manual and M35 is regenerated with
      `scripts/regen-thunderbird-embed.sh`
- [ ] uBO release tag re-verified
- [ ] DKIM Verifier release tag re-verified
- [ ] Confirmed that no build/runtime/Update All path fetches an upstream
      arkenfox or HorlogeSkynet `user.js`
- [ ] Fedora 44 base and stable-updates sources use the correct Kickstart
      `--metalink` type with HTTPS-only payload mirrors
- [ ] All `SHA256_*` constants match live upstream SHAs

### 4. VM smoke test — MANUAL BLOCKING GATE

> **This is a manual blocking gate in the current repository.**
> It requires a human with a working KVM host and focused attention
> per release. A release tag MUST NOT be pushed without a signed-off
> matrix. No exception.

**Why manual**: `livemedia-creator` needs KVM which GitHub default runners
don't provide; `expect`-driven QEMU automation is future work
(see `docs/test-strategy.md` "What's not in CI yet"). For v1.x releases
this step remains human-executed against the 16-point VM smoke matrix
maintained inline below.

**Procedure**:

- [ ] Freeze a clean proposed release commit and record its full SHA. Build an
      **unsigned candidate checksum** from that exact commit via the `Candidate
      build` section below; do not create the final release tag yet. The ISO
      checksum itself is not signed at this stage; the installed-candidate gate
      later proves that Mutter is the unmodified Fedora package.
- [ ] Boot the ISO in QEMU/virt-manager with UEFI + Secure Boot enabled
      and sufficient assigned RAM. TPM 2.0 is optional and is not a hidden
      requirement of this matrix.
- [ ] Run `sudo bash tests/pre-ship/01-kernel-cmdline-runtime.sh` with the
      exact pass IDs `live`, `fresh-install` and `reboot`. Each run must match
      the canonical managed-argument manifest without duplicate/conflicting
      values. Installed passes must also prove that every normal BLS `options`
      line equals the semantic `/etc/kernel/cmdline` plus exactly one trailing
      Fedora `$tuned_params` transport macro. While M21 is pending, its one
      exact Generic recovery entry appends only
      `noid.initramfs=generic-fallback` after that macro. Retain all three logs.
- [ ] Before making any deliberate timezone change in the Live environment,
      run `sudo bash tests/pre-ship/01-timezone-runtime.sh live`. Require
      Anaconda's exact neutral `UTC` symlink, systemd's effective `UTC` value
      and a UTC hardware clock. The M01 source/compose gates separately prove
      that the installed-target directive is also `timezone UTC --utc`.
      GNOME Initial Setup requires choosing a timezone before the first
      installed account is usable, so there is no honest post-boot,
      pre-selection shell pass. Record the consciously selected IANA timezone,
      then run `sudo bash tests/pre-ship/01-timezone-runtime.sh fresh-install
      <IANA_TIMEZONE>` after the first login and the same command with `reboot`
      after the normal reboot. Both installed passes must match that exact
      selection while keeping the hardware clock in UTC mode.
- [ ] After the first installed login and again after the normal reboot, run
      `sudo bash tests/pre-ship/41-installed-firstboot-runtime.sh` with
      `fresh-install` and `reboot`. Require compose/Anaconda/Kickstart evidence
      to be absent from the installed root, successful M41 and host-identity
      completion, Fedora-compatible AccountsService sandboxing, zero M41-scope
      mode/link/owner/group or label drift and no known
      initial-setup/initramfs regression in either lifecycle journal. Missing
      regular RPM configs and content/time drift remain outside M41's
      metadata-only authority.
- [ ] Retain the canonical builder's
      `private-build-evidence/rootfs-hygiene-audit.json` and require its final
      verdict to be `pass`; this is the blocking final-SquashFS hygiene gate,
      not an inspection of the pre-SquashFS compose root.
- [ ] Perform two independent installations from the same candidate ISO. In
      each installed guest create a separate root-owned `0700` evidence
      directory under `/var/tmp`, then run
      `sudo bash tests/pre-ship/41-host-identity-uniqueness.sh record
      ABSOLUTE-EVIDENCE-FILE`. Transfer only those private digest records to one
      controlled guest and run `sudo bash
      tests/pre-ship/41-host-identity-uniqueness.sh compare EVIDENCE-A
      EVIDENCE-B`. Require PASS for machine-id, random seed, BRLAPI key, NVMe
      host ID and NVMe host NQN; never copy or record the raw values. Remove the
      private digest records after the comparison and record only the verdict.
- [ ] Run `sudo bash tests/pre-ship/02-unprivileged-bpf-runtime.sh` with the
      same three pass IDs. Require value 1, unprivileged `bpf()` returning
      `EPERM`, and rejection of the root transition back to 0.
- [ ] Run `sudo bash tests/pre-ship/02-sysctl-runtime.sh` with the same three
      pass IDs. Require exact source bytes and metadata for all three M02 files
      plus equality for all 105 directives at every selected procfs node.
- [ ] Run `sudo bash tests/pre-ship/07-tcp-timestamps-runtime.sh` with `live`,
      `fresh-install` and `reboot`. Require effective value 1, no installed
      value-0 override and exact ownership/mode for the M07 policy file.
- [ ] Run the exact M08 codec sequence from `tests/README.md`: `live pristine`,
      `fresh-install pristine`, explicit user codec opt-in,
      `fresh-install complete`, then `reboot complete`. Require canonical
      dormant service bytes, exact private receipts, public read-only DNF5
      system-state metadata, clean RPM payload/dependencies, real
      H.264/HEVC/VP9/AV1 FFmpeg and GStreamer decode, plus every Intel/AMD
      VA-API profile the candidate actually advertises. Do not substitute
      auto-detected state, a package inventory or a protected-media service
      test.
- [ ] Run every M10 candidate gate with all three pass IDs: logind inhibitors,
      login privacy, Bash history, permission policy, umask and the libvirt
      core-limit process probe. Run Bash history and umask as the normal VM
      user. After `sudo -v`, run the libvirt gate as that same user so it can
      test both `qemu:///session` and `qemu:///system`; run the other three as
      root. Retain a separate log for every script/pass pair.
- [ ] For each `post-resume` M11 pass, invoke the gate immediately after a real
      suspend/resume. Require kernel entry/exit evidence, gateway/XDP readiness
      within the gate's 60-second recovery bound, zero online chrony sources
      before that boundary and the reported authenticated six-source state
      afterward.
      In a VM, require guest ACPI S3 plus host-side QMP `SUSPEND` followed by
      `WAKEUP` event evidence (or equivalent `query-status` transitions through
      `suspended` and back to `running`); `virsh save`, a snapshot or a paused
      VM is not a substitute. A black SPICE scanout alone proves neither
      suspend failure nor resume success. If the serial console proves kernel
      entry/exit, the QMP lifecycle and the complete post-resume gate while
      SPICE stays black, record a virtual-display harness limitation and do
      not claim GUI resume qualification; rerun the display portion with a
      maintained alternative virtual video model or physical target.
- [ ] Before the first installed boot of the disposable `fresh-install` VM,
      shut it down and set its libvirt domain clock to
      `<clock offset='variable' adjustment='7200' basis='utc'>` while retaining
      any existing timer children. Boot once, do not toggle GNOME automatic
      time, wait for controlled-WAN readiness and run the `rtc-bootstrap`
      action. Require the journal-measured 6900–7500-second correction,
      `LocalRTC=no`, active automatic time and completed synchronization. After
      the gate, shut the VM down and restore the domain clock to UTC before the
      later `reboot` pass. This is the mandatory localtime-as-UTC RTC regression
      proof, not a configuration-only substitute.
- [ ] Run every action in `tests/pre-ship/11-chrony-runtime.sh` exactly as
      listed in `tests/README.md`: `offline`, `online`, `cookie-restart` and
      `post-resume` in all three passes, plus `rtc-bootstrap` and `fresh-ke` in
      `fresh-install`.
      The online actions require controlled WAN; none may be replaced by a
      configuration-only inspection. The Live pass must verify Fedora
      `livesys` removed `rtcsync`; both installed passes must require it.
- [ ] As the normal GNOME VM user, run the M17 display-power, JIT and Wayland
      gates with all three pass IDs. Run both `prepare` and `verify` actions of
      the privacy-cleanup gate in every pass, with a real logout/login between
      those actions. Retain all action logs.
- [ ] As the normal GNOME VM user, run
      `bash tests/pre-ship/19-gsk-session-runtime.sh {live|fresh-install|reboot}`
      in each lifecycle pass. On qualified NVIDIA-offload hardware require the
      exact post-Shell user-manager renderer and marker while GNOME Shell
      remains unmodified; on unmatched hardware require GTK's vendor default.
      Every pass must reject unit-specific overrides and prove the AF_UNIX-only
      socket filter without a private-network-namespace claim. Retain all three
      logs.
- [ ] Before manually opening GNOME Software or starting Update All in each
      lifecycle pass, run
      `sudo -v && bash tests/pre-ship/24-silent-update-runtime.sh {live|fresh-install|reboot}`
      as the normal GNOME user. The cached ticket permits only the gate's
      bounded read of root-only `fwupd.conf`; it does not move the GNOME/D-Bus
      probes into a root session. Require Fedora's pristine Software service
      descriptor and its exact masked-unit route, no duplicate admin service,
      and real unsolicited D-Bus activation to fail without spawning
      Software/dnf5daemon or changing fwupd. Require all refresh/P2P units to
      remain masked/inactive and the effective GIO launcher to select the admin
      `DBusActivatable=false` copy with Fedora's direct `Exec` intact. Retain
      all three logs.
- [ ] Run `sudo bash tests/pre-ship/21-wan-threat-boundary-runtime.sh` with
      `live`, `fresh-install` and `reboot`. Require the published runtime mode,
      its matching nftables postcondition and the exact capability-empty
      `EPERM` results in every pass.
- [ ] Run `sudo bash tests/pre-ship/21-dracut-hostonly-runtime.sh` with the
      exact pass IDs `live`, `fresh-install` and `reboot`. The fresh pass must
      prove Generic is the persistent saved GRUB default and the validated
      host-only candidate is the one-shot next entry. Run it before the
      destructive Snapper fresh pass. The reboot pass must prove a distinct
      target-kernel boot, restoration of the normal saved default, retirement
      of the fallback and no mdraid-wait evidence from the first shutdown.
      The fresh pass must additionally prove that the central guard and later
      atomic regenerator refuse `pending-reboot` without changing the standard
      image, fallback image or state bytes. The reboot pass must emit exactly
      `basis=hostonly`. Retain all three logs; content inspection alone is not
      boot evidence.
- [ ] On a separate disposable clone, run
      `tests/pre-ship/21-dracut-powerloss-runtime.sh select-recovery`, reboot
      normally into the selected fallback and run `recover`. Reboot normally
      once more into the restored standard Generic entry and run `arm`. Only
      after it reports READY, issue `virsh destroy <domain>` on the KVM host
      (not guest reboot/shutdown), start the VM, unlock LUKS and run `recover`
      again. Require the automatic Generic BLS boot, an abrupt previous journal,
      the exact fsynchronized `arm` journal marker, restored Generic
      standard/default and `phase=recovered-generic`. Reboot normally once more
      and run `verify`; `arm` and final `verify` must observe
      the central guard's exact `basis=generic` terminal record. The temporary
      recovery entry is deliberately never a writer basis. Retain all five
      action logs plus the host destroy/start transcript.
- [ ] On a disposable installed clone after a confirmed M21 reboot, exercise
      the maintained manual writers rather than only their structural tests:
      run `sudo noid-toggle-gaming off`, then an informed no-op/default restore
      through `sudo noid-mei-restore-submodules --restore wdt`. After each,
      require `sudo /usr/libexec/noid-boot-mutation-guard` to emit exactly
      `basis=hostonly`, no Generic recovery entry/image, no GRUB `next_entry`,
      and a bootable reboot. The release operator—not an agent—must separately
      run the supported `noid-update-all.sh` workflow and retain its DNF,
      kernel, NVIDIA-if-present and check-only AIDE evidence.
- [ ] On dedicated NVIDIA hardware (or qualified PCI-passthrough; a generic VM
      without NVIDIA is not evidence), complete the M19 install/MOK flow, a
      kernel update and a driver-only update. Require the durable worker's
      ready hash to match the published image, reboot successfully after each,
      and retain the selected NVIDIA compatibility policy: AC and battery idle
      auto-suspend defaults are `nothing`, and laptop lid actions are `lock`.
      Confirm the queue has no `.pending`, `.deferred` or `.failed` artifacts.
- [ ] Run `sudo bash tests/pre-ship/20-snapper-rollback-runtime.sh live` in the
      live image from the exact frozen source checkout. The gate itself
      refuses non-QEMU/KVM hosts and binds every executed M20/M21 helper,
      systemd guard and destructive Snapper/Btrfs binary to current
      source/RPM evidence before activation. In the installed VM, run its
      `fresh-install` pass **last before the lifecycle reboot**: it creates a
      disposable target, writes a post-snapshot probe and deliberately
      publishes that target as the Btrfs default. If the pass is interrupted,
      rerun the same `fresh-install` command before reboot; it resumes only
      exact prepared/pending/ready evidence. After reboot, run its `reboot`
      pass and require the selected snapshot to be both active/default, the
      status to be `boot=ready` and the probe to be absent. If power loss has
      already caused a reboot, run the `reboot` pass instead; it may finish
      only an exact pending transaction whose newly selected default is
      already the running root. Retain all three logs.
- [ ] After the isolated test NIC and gateway pin are active, run
      `sudo bash tests/pre-ship/04-ipv4-acd-runtime.sh` with `live`,
      `fresh-install` and `reboot`. Require coordination-only nft state, the
      exact permanent gateway neighbour, effective NetworkManager DAD=200 and
      both duplicate-rejected/unused-accepted outcomes on its private veth pair.
- [ ] With the exact frozen source checkout available, run both non-skippable
      browser gates in every lifecycle pass. First run
      `sudo bash tests/pre-ship/19-browser-image-parity.sh live`, then as the
      normal desktop user run
      `bash tests/pre-ship/19-browser-runtime-parity.sh live`; repeat both with
      `fresh-install` after the first installed login and `reboot` after the
      lifecycle reboot. The root gate must prove repository/image/root-owned
      skel/config byte and metadata parity; the user gate must start the real
      Firefox and Thunderbird binaries and require their effective preference
      and extension state. Retain all six logs.
- [ ] As root, run `tests/pre-ship/18-flatpak-remote-runtime.sh` with `live`,
      `fresh-install` and `reboot`. Each pass must prove the exact pinned
      descriptor/config/key state and both current signed online catalogs,
      native Fedora auto-add unit
      mask, absent private sentinel, disabled-default stable Fedora remote and
      all six global denies. Controlled WAN is required for each pass; retain
      all three logs.
- [ ] Run `sudo bash tests/pre-ship/14-usbguard-runtime.sh` with `live`,
      `fresh-install` and `reboot`. Each pass must prove that named ACLs are
      the sole IPC authorization source, every eligible user has only the
      notifier-compatible profile, no legacy `usbguard` group membership
      remains, parameter/policy mutations are denied, and the durable rules
      file is byte-unchanged after the probes. Retain all three logs.
- [ ] Attach one 768 MiB GPT QEMU USB-storage disk with `removable=1` and four
      exact 128 MiB partitions formatted/labeled `NOID_VFAT` (VFAT),
      `NOID_EXFAT` (exFAT), `NOID_NTFS` (NTFS) and `NOID_EXT4` (ext4). Attach a
      separate 128 MiB ext4 QEMU USB disk labeled `NOID_FIXED` with
      `removable=0`, plus a 128 MiB ext4 native QEMU SD-card fixture labeled
      `NOID_SD`. Give all six filesystems distinct UUIDs and leave them
      unmounted. The gate refuses non-QEMU/KVM hosts, duplicate labels,
      pre-existing mounts, wrong parents, sizes, partition count or filesystem
      types. Run
      `sudo bash tests/pre-ship/20-hardware-tuning-runtime.sh` with the exact
      same `live`, `fresh-install` and `reboot` pass IDs, reattaching the same
      persistent fixture images after each USB power-off/VM transition. Each
      run must prove
      native rule parsing, Fedora/kernel ownership plus the observed live I/O
      scheduler, the effective Wake-on-LAN `.link` winner and vendor-owned EEE
      boundary, UDisks `noexec,nodev,nosuid` mounts without `sync`, retained
      VFAT `flush`, ntfs3 for external NTFS, and the direct-exec/interpreter
      boundary across all filesystems and device classes. The executable
      `.com` probe must retain execute bits under VFAT `showexec`, so its
      status-126 denial proves mount-level `noexec`. It must also prove the
      explicit allowed `exec` override on every USB matrix filesystem,
      unchanged whole-device `queue/write_cache`/FUA observations, cold hashes carried from `live` to
      `fresh-install` to `reboot`, completed UDisks power-off for USB plus
      clean SD unmount, exact earlyoom argv, active
      tuned/tuned-ppd and Fedora-owned zram state. Retain all three logs.
      The policy rationale and physical-device evidence are in
      [`external-storage-policy.md`](external-storage-policy.md).
- [ ] Walk the 16-point matrix (see sign-off template below). Record
      each point's outcome (PASS / FAIL / SKIP + why) in a per-release
      artefact.
- [ ] With the installed candidate VM on its controlled WAN, run
      `sudo bash tests/pre-ship/29-installed-package-freshness.sh`. It must
      report zero Fedora package upgrades and zero Critical/Important/Moderate
      security advisories. Record the repository revisions/timestamps printed
      by the gate in the sign-off artefact.
- [ ] Run `tests/pre-ship/30-live-payload-acl-parity.sh` against the retained
      raw-compose root, extracted SquashFS root and installed-candidate root;
      require `raw=exact` and `installed=exact`. In the running installed VM,
      run `sudo bash tests/pre-ship/31-installed-enforcing-avc.sh` and require
      SELinux enforcing, immutable audit, zero lost events and zero current-boot
      AVC/USER_AVC records.
- [ ] The browser gate invokes
      `tests/pre-ship/18-browser-license-notices.sh /`; independently retain
      its installed-candidate output if a separate license artefact is wanted.
- [ ] Run the non-lifecycle candidate gates
      `tests/pre-ship/09-ssh-fix-phase-disabled.sh` and
      `sudo bash tests/pre-ship/17-mutter-fedora-runtime.sh /`, and retain their
      output. The lifecycle ledger must additionally contain all three
      prepare/logout/re-login/verify cycles from
      `17-gnome-shell-logout-runtime.sh` with no F284 precursor, SIGSEGV,
      core-dump result or new Shell `ANOM_ABEND`, plus all three
      `17-greeter-retirement-runtime.sh` passes after normal login. The Live
      pass may have no pre-user Shell only when the exact `liveuser` automatic-
      login path and active `org.gnome.Shell@user.service` are evidenced with
      zero native-crash records. The reboot pass must prove clean pre-user
      Shell retirement in both the preceding and current boot. Fedora's first
      installed boot may use
      `org.gnome.Shell@initial-setup.service`; later boots must use
      `org.gnome.Shell@gdm.service`. Each Shell cycle starts unlocked and logs
      out immediately from inside the running session: GNOME's Log Out entry
      where the Shell renders it, otherwise `gnome-session-quit --logout
      --no-prompt` from that same session, which invokes the identical
      `org.gnome.SessionManager.Logout` path the entry itself calls. GNOME 50
      does not render that entry on a single-account installation unless
      `org.gnome.shell always-show-log-out` is set, so requiring the dialog
      alone would make this step unreachable on a normal candidate. Still
      excluded: `loginctl terminate-session`, session kills, and any delayed or
      out-of-session automation — those skip the session-manager teardown this
      test exists to prove.
- [ ] Generate a sorted executable inventory of `tests/pre-ship/`, record its
      SHA-256, and maintain a command ledger containing every command in the
      canonical `tests/README.md` pre-ship block. Every inventory entry must be
      either an invoked gate or the documented Python fixture helper invoked by
      the LAN-XDP gate. A missing, undocumented or non-PASS command blocks the
      release; the 16-point summary cannot hide a missing detailed gate.
- [ ] All 16 points must be PASS (not SKIP, not FAIL) before creating the final
      tag or publishing, and the LAN-XDP, package-freshness, three-root ACL and
      installed enforcing-AVC gates plus every command/action in the canonical
      pre-ship ledger must pass. Only then sign the already-built
      candidate's checksum. The signed tag must point to the exact commit
      recorded in the matrix; final-SquashFS hygiene and two-install identity
      uniqueness must also pass, and tagging must not change the tree.

**Sign-off artefact** (one per release; store offline with the artifacts):

```
# VM-test sign-off for noid-privacy-workstation-44-v1.7-x86_64

Tag:        v1.7
Git commit: <40-char SHA>
Candidate directory: <exact unsigned-candidate-... basename>
Candidate ISO SHA256: <64 lowercase hex>
Tester:     <NexusOne23 or signing-key fingerprint>
Date (UTC): <ISO-8601>
Guest:      <QEMU version + virt-manager version + libvirt version>
Matrix:     VM smoke matrix (16 points, listed below)

Results:
  1. Install + Anaconda reach                 [PASS|FAIL|SKIP] — <note>
  2. First boot + gnome-initial-setup          [ ]
  3. LUKS unlock + btrfs mount                 [ ]
  4. Secure Boot state (mokutil --sb-state)    [ ]
  5. systemctl --failed = 0 units              [ ]
  6. firewalld/LAN boundary                    [ ]
     - block-lan-out + topology/netdev tables active
     - noid-lan-xdp health ACTIVE; exact live XDP/TC status
     - tests/pre-ship/03-lan-xdp-runtime.sh PASS
     - tests/pre-ship/04-ipv4-acd-runtime.sh PASS in live/fresh/reboot
     - standard ARP/ACD passes XDP; gateway neighbour is exact + PERMANENT
     - native mode on a qualified driver + forced generic mode exercised
     - same peer IP/MAC rejected on a second physical interface
     - grant/revoke/re-grant cannot reactivate a stale peer reverse tuple
     - simulated XDP-only failure keeps WAN recovery + reports DEGRADED
  7. AIDE uninitialized + timer disabled       [ ]
  8. SELinux enforcing + tests/pre-ship/31-installed-enforcing-avc.sh PASS [ ]
  9. usbguard service + initial policy         [ ]
  10. sysctl 99-hardening.conf applied          [ ]
     - tests/pre-ship/01-kernel-cmdline-runtime.sh PASS in live/fresh/reboot
     - normal BLS = semantic /etc/kernel/cmdline + one `$tuned_params` macro
     - pending Generic recovery then appends only its one exact marker
     - tests/pre-ship/02-unprivileged-bpf-runtime.sh PASS in live/fresh/reboot
     - tests/pre-ship/02-sysctl-runtime.sh PASS in live/fresh/reboot
     - tests/pre-ship/04-ipv4-acd-runtime.sh PASS in live/fresh/reboot
     - tests/pre-ship/20-hardware-tuning-runtime.sh PASS in live/fresh/reboot
     - both labeled USB-storage fixtures attached in all three passes
 11. Firefox first-run profile + uBO XPI       [ ]
 12. Thunderbird user.js seeded                [ ]
 13. journald hardening drop-in applied        [ ]
     (Seal=yes present; FSS itself is inert on F44 — systemd built
     without gcrypt — config-presence check, not sealing-functional)
 14. Snapper baseline + native default model    [ ]
     - tests/pre-ship/20-snapper-rollback-runtime.sh PASS in live/fresh/reboot
     - fresh-install pass ran last before reboot in the disposable VM
     - exact fstab/BLS/mount/sudo boundary; real selected-root boot proved
     - tests/pre-ship/21-dracut-hostonly-runtime.sh PASS in live/fresh/reboot
     - Generic saved default + one-shot host-only trial + real boot confirmed
     - first installed shutdown has no mdraid wait evidence
     - separate tests/pre-ship/21-dracut-powerloss-runtime.sh hard-cut PASS
 15. dconf NoID Privacy gnome-privacy profile loaded   [ ]
 16. noid-status full report                   [ ]

Browser runtime/parity live:          [PASS|FAIL]
Browser runtime/parity fresh-install: [PASS|FAIL]
Browser runtime/parity reboot:        [PASS|FAIL]
Codec runtime live/pristine:          [PASS|FAIL]
Codec runtime fresh/pristine:         [PASS|FAIL]
Codec runtime fresh/complete:         [PASS|FAIL]
Codec runtime reboot/complete:        [PASS|FAIL]
Kernel cmdline parity live:           [PASS|FAIL]
Kernel cmdline parity fresh-install:  [PASS|FAIL]
Kernel cmdline parity reboot:         [PASS|FAIL]
Neutral timezone live:                [PASS|FAIL]
Selected timezone fresh-install:      [PASS|FAIL]
Selected timezone reboot:             [PASS|FAIL]
BPF irreversible gate live:          [PASS|FAIL]
BPF irreversible gate fresh-install: [PASS|FAIL]
BPF irreversible gate reboot:        [PASS|FAIL]
M02 complete sysctl live:            [PASS|FAIL]
M02 complete sysctl fresh-install:   [PASS|FAIL]
M02 complete sysctl reboot:          [PASS|FAIL]
TCP timestamps gate live:            [PASS|FAIL]
TCP timestamps gate fresh-install:   [PASS|FAIL]
TCP timestamps gate reboot:          [PASS|FAIL]
M10 logind-inhibitors live/fresh/reboot: [PASS|FAIL]
M10 login-privacy live/fresh/reboot:     [PASS|FAIL]
M10 Bash-history live/fresh/reboot:      [PASS|FAIL]
M10 permission-policy live/fresh/reboot: [PASS|FAIL]
M10 umask live/fresh/reboot:              [PASS|FAIL]
M10 libvirt-core live/fresh/reboot:       [PASS|FAIL]
M11 chrony complete action matrix:        [PASS|FAIL]
M17 display-power live/fresh/reboot:      [PASS|FAIL]
M17 JIT live/fresh/reboot:                [PASS|FAIL]
M17 Wayland live/fresh/reboot:            [PASS|FAIL]
M24 Silent Machine/update live/fresh/reboot: [PASS|FAIL]
M17 privacy-cleanup prepare/verify + logout/login in all passes: [PASS|FAIL]
Flatpak remote trust live:            [PASS|FAIL]
Flatpak remote trust fresh-install:   [PASS|FAIL]
Flatpak remote trust reboot:          [PASS|FAIL]
GSK session gate live:                [PASS|FAIL]
GSK session gate fresh-install:       [PASS|FAIL]
GSK session gate reboot:              [PASS|FAIL]
WAN threat boundary live:             [PASS|FAIL]
WAN threat boundary fresh-install:    [PASS|FAIL]
WAN threat boundary reboot:           [PASS|FAIL]
Dracut host-only gate live:           [PASS|FAIL]
Dracut host-only gate fresh-install:  [PASS|FAIL]
Dracut host-only gate reboot:         [PASS|FAIL]
Dracut hard-power-loss recovery:      [PASS|FAIL]
Snapper rollback gate live:           [PASS|FAIL]
Snapper rollback gate fresh-install:  [PASS|FAIL]
Snapper rollback gate reboot:         [PASS|FAIL]
SSH fix-phase-disabled gate:          [PASS|FAIL]
Fedora Mutter provenance gate:        [PASS|FAIL]
GNOME Shell clean logout ×3 gate:     [PASS|FAIL]
Browser license-notices gate:         [PASS|FAIL]
Complete pre-ship command ledger:     [PASS|FAIL]
Pre-ship executable inventory SHA256: <64 lowercase hex>

Final: 16/16 PASS + complete canonical pre-ship command ledger PASS + all three browser/kernel/BPF/Flatpak/hardware/Dracut/Snapper passes + Dracut hard-power-loss recovery + LAN-XDP + package freshness + ACL parity + enforcing AVC gates PASS — CLEAR FOR TAGGING/PUBLISHING
       or
       N/16 PASS — RELEASE BLOCKED, see per-point notes.

Detached sign-off signature: vm-test-signoff.txt.asc (release key)

Final SquashFS image-hygiene gate: [PASS|FAIL]
Two-install host-identity uniqueness gate: [PASS|FAIL]
Package freshness gate: [PASS|FAIL]
Fedora repo evidence: <revision + Updated timestamp from gate output>
Raw/SquashFS/installed ACL parity gate: [PASS|FAIL]
Installed enforcing-AVC gate: [PASS|FAIL]
```

**Storage**: keep the sign-off offline alongside the release artifacts
(ISO + SHA256SUMS + .asc). It is deliberately NOT committed to the
public repo because it is an operational sign-off artifact
(`.gitignore` excludes `vm-test-signoff.txt`). Reviewers / auditors can re-run any single point against a
fresh VM if they doubt a PASS.

**Failure path**: any FAIL on the matrix = release tag not created or pushed;
open a tracking issue, fix the regression, rerun the matrix from scratch.
No partial-pass releases.

## Candidate build

```bash
# Build the frozen proposed release commit; tag it only after the matrix passes.
TAG=v1.7
RELEASE_COMMIT=<40-char proposed release SHA>
git checkout --detach "$RELEASE_COMMIT"
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$RELEASE_COMMIT")

# Build via the canonical wrapper (handles the native Anaconda profile overlay
# + build-installer-only BRLTTY suppression + fail-closed compose-log policy + lorax
# phase 2 partition/bootloader munging + branding SHA-verified staging
# + audit-tool SHA pin + ksflatten — none of which the bare
# livemedia-creator command performs). Wrapper picks up SOURCE_DATE_EPOCH
# from the environment as one variance-reduction input.
sudo -v
# The candidate checksum intentionally remains unsigned until the installed-VM
# matrix and package-freshness gate pass.
./scripts/build-iso.sh

# The wrapper retains root-private, hash-bound livemedia/program/virt-install
# logs plus compose-log-audit.json below the exact printed candidate directory's
# private-build-evidence/.
# These contain builder-local paths and are offline evidence, not publishable
# release assets.

# Optional local toolchain record. Do not include hostnames, hardware IDs,
# machine-id, usernames, or other machine-specific identifiers.
cat > BUILD-ATTESTATION.txt <<EOF
NoID Privacy Workstation Release Build Attestation
=============================================
Tag: $TAG
Git commit: $(git rev-parse HEAD)
SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH
livemedia-creator version: $(livemedia-creator -V 2>&1)
anaconda version: $(rpm -q anaconda --qf '%{VERSION}')
EOF
```

## Signing

Generate SHA256SUMS + detached signature:

```bash
# Run only after the exact candidate has passed the complete VM matrix and
# package-freshness gate. Do not rebuild between sign-off and this operation.
# Use the exact candidate directory recorded in the VM sign-off:
CANDIDATE_DIR='build-output/candidates/unsigned-candidate-<build-id>-<random>'
cd "$CANDIDATE_DIR"
RELEASE_KEY_ID=1ACBFCE49687FEBB91010E52F8E3F11D6962256F
gpg --batch --yes --armor --detach-sign \
  --local-user "${RELEASE_KEY_ID}!" --output SHA256SUMS.asc SHA256SUMS
gpg --batch --yes --armor --detach-sign \
  --local-user "${RELEASE_KEY_ID}!" \
  --output vm-test-signoff.txt.asc vm-test-signoff.txt
gpg --batch --status-fd=1 --verify SHA256SUMS.asc SHA256SUMS \
  | awk -v fpr="$RELEASE_KEY_ID" \
      '$1=="[GNUPG:]" && ($2=="EXPKEYSIG"||$2=="REVKEYSIG"||$2=="EXPSIG") {bad=1}
       $1=="[GNUPG:]" && $2=="GOODSIG" {good=1}
       $1=="[GNUPG:]" && $2=="VALIDSIG" && $3==fpr {ok=1}
       END {exit !(ok && good && !bad)}'
gpg --batch --status-fd=1 \
  --verify vm-test-signoff.txt.asc vm-test-signoff.txt \
  | awk -v fpr="$RELEASE_KEY_ID" \
      '$1=="[GNUPG:]" && ($2=="EXPKEYSIG"||$2=="REVKEYSIG"||$2=="EXPSIG") {bad=1}
       $1=="[GNUPG:]" && $2=="GOODSIG" {good=1}
       $1=="[GNUPG:]" && $2=="VALIDSIG" && $3==fpr {ok=1}
       END {exit !(ok && good && !bad)}'

# Optional offline archive after both signatures exist. This copies the entire
# candidate/evidence tree through a verified, fsynced, atomic transaction.
cd ../../..
./scripts/archive-build.sh "$CANDIDATE_DIR"
```

The archive name is derived from the authenticated candidate identity as
`signed-release-<commit-prefix>-<source-epoch>-<random>`. There is no separate
manual build number to assign or keep synchronized.

Required:
- Sign with the exact NoID Privacy release-key fingerprint
  `1ACBFCE49687FEBB91010E52F8E3F11D6962256F`; never select by keyring order or
  a mutable UID string.
- The public key is published at
  <https://noid-privacy.com/downloads/noid-privacy-release.asc>; its fingerprint
  must be cross-checked through an independent public channel. A matching value
  in this same source tree is useful for consistency but is not independent trust.

## Publish

The release ISO is **not** attached to a GitHub Release; GitHub requires each
individual release asset to be under 2 GiB. It is published on the project's
own download host; its download page is
<https://noid-privacy.com/linux.html>:

- Upload the builder's exact `noid-privacy-workstation-44-${TAG}-x86_64.iso`,
  `SHA256SUMS`, and
  `SHA256SUMS.asc` to the website's `downloads/` area.
- The download page (`hardened-linux-privacy-os.html`) links the ISO with force-download +
  resume (`Accept-Ranges`) headers; the verification recipe (import key →
  `gpg --verify SHA256SUMS.asc SHA256SUMS` → `sha256sum -c SHA256SUMS`) is shown
  next to the download.

Optionally cut a signed source git tag for the release commit — checksums,
signature, and the build attestation only, never the ISO itself (it exceeds the
release-asset ceiling):

```bash
git tag -s "$TAG" -m "NoID Privacy Workstation $TAG"
```

## Release-notes template

Paste into the GitHub Release body:

```markdown
# NoID Privacy Workstation v1.7

## Summary

One-paragraph summary of what this release delivers. Focus on user
impact; link to the technical detail in docs.

## What's new

- **<surface>**: <user-visible additive change>.
- **<surface>**: <second user-visible additive change>.

## Bug fixes

- [#<issue>] <user-visible bug fix>.

## Breaking changes

(None — or list here.)

## Supply-chain pins

- NoID Privacy Firefox Hardening: derived from arkenfox `<reviewed-base>`, embedded
  (regenerate via `scripts/regen-firefox-embed.sh`)
- NoID Privacy Thunderbird Hardening: derived from HorlogeSkynet `<reviewed-base>`,
  embedded (regenerate via `scripts/regen-thunderbird-embed.sh`)
- uBO release: `<version>`
- DKIM Verifier release: `<version>`
- Base ISO: `<filename + SHA-256>`
- Package/repository evidence: `<manifest or archived build-log reference>`

## SHA256SUMS

\`\`\`
<PASTE SHA256SUMS CONTENTS>
\`\`\`

Signature: `SHA256SUMS.asc` (detached, GPG-signed by
`1ACBFCE49687FEBB91010E52F8E3F11D6962256F` <- release key fp).

## Verify

\`\`\`bash
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
\`\`\`

## Build-variance record

This release was built with these inputs; they do not establish reproducibility:
- `SOURCE_DATE_EPOCH=<exact integer>`
- `livemedia-creator <exact version>`
- `<exact build-host release/toolchain identity>`

See `docs/build-reproducibility.md`.

## Contributors

- @<maintainer>
- @<contributors>

## Full changelog

See `CHANGELOG.md`.
```

## Post-release

- [ ] Open milestone for next release on GitHub
- [ ] Update README badges if major version changed
- [ ] Announce only through currently operated project channels

## Hotfix workflow

For CVE mitigation requiring immediate patch-level release:

1. Branch off the release tag: `git checkout -b hotfix/1.7.1 v1.7`
2. Apply minimal fix + CVE reference in commit message
3. Bump `NOID_VERSION` in `kickstart/snippets/32-branding.ks` (this string
   is the single source of truth — it is baked into `/etc/os-release` at
   image build time; there is no separate `VERSION` file in the repo root)
4. Run `tests/run-all.sh`
5. Tag + release with hotfix build process above
6. Merge hotfix back to main: `git checkout main && git merge hotfix/1.7.1`

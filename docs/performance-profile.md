# Performance profile and measurement boundary

NoID Privacy changes kernel command-line options, sysctls, service activation,
audit rules, SELinux policy, I/O behavior and scheduled integrity work. Those
changes can improve idle behavior in one workload and reduce throughput in
another. The project has not published a controlled benchmark set comparing
stock Fedora with NoID Privacy, so this document does not invent percentages,
boot seconds or memory savings.

## Likely cost centers

- Kernel memory-initialization options `init_on_alloc` and `init_on_free`
  zero newly allocated and freed memory, adding work on allocation-heavy
  paths. `slab_nomerge` deliberately gives up some allocator cache merging
  for heap-layout isolation, so its memory/performance effect is
  workload-dependent. No global `slab_debug` option is enabled.
- Strict IOMMU behavior can reduce I/O throughput or increase CPU work on some
  devices and drivers.
- CPU-vulnerability mitigations vary substantially by CPU generation,
  microcode, kernel and workload.
- SELinux and audit rule evaluation add access/syscall-path work. Volume rises
  with build systems, package transactions and other fork/file-heavy tasks.
- AIDE is scheduled rather than continuous, but its filesystem scan consumes
  CPU and storage bandwidth while active.
- Privacy DNS/TLS layers and firewall policy evaluation can add latency, but
  WAN/provider conditions usually dominate interactive network measurements.

## Likely savings or idle reductions

- Masked or disabled background services cannot consume resources while they
  remain inactive.
- Disabled automatic package/firmware polling removes those scheduled wakeups.
- zram can avoid slower disk swap under memory pressure, with a CPU/compression
  trade-off.
- Hardware-specific I/O scheduler choices may help or hurt depending on the
  device, kernel and workload; NoID Privacy therefore leaves scheduler
  selection with Fedora, the block driver and the kernel.

Bluetooth, location, printing/discovery, smartcard, indexing and similar
features are deliberately constrained or off by default. Their absence is a
functional/privacy decision, not a performance claim.

## Module 27 ownership

Module 27 is the existing hardware/performance boundary; a second performance
module would duplicate ownership. Its default policy is deliberately small:

- Fedora's `systemd-udev` rule and the kernel select I/O schedulers. No
  `/etc/udev/rules.d/60-noid-iosched.rules` override is shipped.
- Fedora's `zram-generator-defaults` package owns zram size, compression and
  priority. No NoID Privacy zram configuration override is shipped.
- The kernel plus Fedora's `tuned`/`tuned-ppd` stack own CPU boost, EPP and
  governor behavior. No unconditional Intel HWP dynamic-boost write is shipped.
  `noid-balanced` and `noid-balanced-battery` inherit Fedora's corresponding
  profiles and disable only their invalid attempt to reload
  `cpufreq_conservative`, which Fedora 44 builds into the kernel.
- M02 remains security/privacy-only. M27 does not add BBR, a qdisc, socket
  ceilings, swappiness, swap readahead, writeback, block read-ahead or a
  command-line/initramfs performance setting.

M27 still owns explicitly documented functional or stability choices:
earlyoom as the image's process-level low-memory policy, physical-wired-NIC
Wake-on-LAN disable, UDisks `noexec` defaults for USB/SD storage, a scoped
`ntfs3,ntfs` driver order for external NTFS, and the hardware-conditional
thermald decision. EEE remains with Fedora, each driver and the link partner
because systemd 259's legacy 32-bit EEE ioctl cannot represent modern link
modes safely. The external-storage policy covers sticks and USB SSDs/HDDs
regardless of the unreliable removable bit. Blanket `sync` was removed after
VFAT/exFAT/NTFS/ext4 testing showed its large performance cost; mount(8) also
says it may shorten limited-write media life. UDisks filesystem defaults still
merge in (`flush` on vfat). Neither `noexec` nor NTFS driver selection changes
the device-cache view or replaces eject/power-off, and an explicit allowed
`exec` request can override the default. No BDI throttle or `queue/write_cache`
mutation is shipped. These choices are verified as behavior and carry their
own trade-off; they are not advertised as universal throughput improvements.

## Supported user-selected performance surface

Use GNOME Settings → Power → Power Mode. Fedora's `tuned-ppd` translates that
selection to the configured tuned profile. The public choices remain
`Balanced`, `Performance` and `Power Saver`; the internal `noid-balanced`
names only remove the inapplicable module reload and do not add a CPU-policy
writer. `Balanced` remains the normal baseline; the other two are explicit
user choices and can change throughput, responsiveness, power draw,
temperature and fan behavior.

Verify the effective selection with:

```bash
busctl get-property net.hadess.PowerProfiles /net/hadess/PowerProfiles \
  net.hadess.PowerProfiles ActiveProfile
tuned-adm active
tuned-adm verify --ignore-missing
systemctl is-active tuned.service tuned-ppd.service
```

`--ignore-missing` is TuneD's native verification mode for settings that the
current hardware or driver does not expose. It still rejects a different value
for every exposed setting. This matters, for example, on Intel `intel_pstate`
systems where TuneD can apply Fedora's `boost=1` through the global
`no_turbo=0` control even though no per-policy `boost` file exists to read
back.

NoID Privacy does not ship BBR/fq as a hidden or default optimization. Network
congestion control is route, RTT, loss, workload and VPN-transport dependent;
changing it can also change externally observable traffic behavior. Any future
network profile needs a separate explicit privacy decision and retained
no-VPN, WireGuard and OpenVPN measurements.

## Measure the installed system

Record the exact image/source revision, firmware, kernel, microcode, power
profile, thermal state and workload before comparing results. At minimum:

```bash
cat /etc/noid-build-info
uname -r
lscpu
systemd-analyze time
systemd-analyze blame
systemctl --failed
free -h
swapon --show
```

For a meaningful A/B comparison:

1. Use the same machine, firmware settings, power source and storage.
2. Compare against the Fedora 44 package/kernel versions represented by the
   compose, not an unrelated newer installation.
3. Reboot between states, warm or cold caches consistently, and repeat enough
   times to report variation rather than one favorable result.
4. Measure the actual target workload (build, database, browser, media, VM or
   ML job) and keep thermal throttling visible.
5. Change one hardening control at a time, document the security cost, and use
   the module's supported escape hatch where one exists.

Do not disable SELinux, audit, IOMMU, CPU mitigations or memory hardening based
on a generic percentage from another machine. If performance is a release
criterion, add the reproducible benchmark and raw results to the release
evidence rather than converting an expectation into a README claim.

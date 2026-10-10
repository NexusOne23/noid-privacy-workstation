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
`ntfs3,ntfs` driver order for external NTFS; thermald keeps Fedora's preset and
its own hardware probe (intel_lpmd is masked by M08 under the single-EPP-writer
policy). EEE remains with Fedora, each driver and the link partner
because systemd 259's legacy 32-bit EEE ioctl cannot represent modern link
modes safely. The external-storage policy covers sticks and USB SSDs/HDDs
regardless of the unreliable removable bit. Blanket `sync` is not used:
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

## Firefox's first page and the uBlock Origin startup cache

Firefox's web cache and uBlock Origin's filter-engine cache are separate.
The productive profile clears the web cache and form data on normal shutdown;
it retains cookies and site storage. These defaults are defined in the repository
source `firefox/noid-firefox-hardening.js`.
Normal shutdown with these defaults has been verified to preserve uBO's
filter-engine cache in the installed v1.9 candidate.

uBO can hold requests until its filtering engine is ready. Without a valid
saved engine, it builds that engine from the filter lists. Its saved startup
state is called a **selfie**. In the shipped uBO 1.75.0, creation is deferred:
the default timer is 53 seconds, with a later alarm as a second path. Filter
updates can invalidate and reschedule this state. Repeated brief sessions can
therefore end before a usable selfie is saved, repeating the startup work.
This does not mean Firefox deleted the filter cache when it closed.
See upstream's [cache storage](https://github.com/gorhill/uBlock/blob/1.75.0/src/js/cachestorage.js),
[selfie lifecycle](https://github.com/gorhill/uBlock/blob/1.75.0/src/js/storage.js)
and [startup sequence](https://github.com/gorhill/uBlock/blob/1.75.0/src/js/start.js).

To diagnose this without changing protection settings:

1. Open uBO's dashboard, then **Support**, and inspect **Troubleshooting
   Information**. Record `allReadyAfter` and whether it includes `(selfie)`.
2. Leave Firefox open for a few minutes once, quit normally, then reopen it
   and record the same fields. This gives uBO time to finish its own deferred
   work; it is not a guarantee that every future launch will reuse a selfie.
3. Compare the first and subsequent page requests separately. If uBO is
   already ready before the first request, investigate DNS, TCP/TLS and server
   response time rather than attributing that delay to filter loading.

Keep shutdown clearing, filtering during startup, the selected filter lists,
DNS validation and encrypted transport unchanged. Do not infer that an
extension was reinstalled or its storage cleared from a slow launch alone;
check the active profile, extension state and measured startup data.

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

Also record the observable milestones: power-on, disk-unlock prompt, password
submission, login screen, login submission and usable desktop. Report manual
input waits separately. `systemd-analyze` totals and `blame` entries are service
measurements, not desktop-readiness measurements: parallel work and one-time
post-install jobs can finish after the desktop is usable. Pair them with the
critical chain and journal ordering before calling a long-running service a
boot bottleneck. Keep first installed boot, later cold boots and reboots as
separate samples. When joining guest logs with host screenshots, calibrate
their clocks and reject joins affected by clock steps.

For a meaningful A/B comparison:

1. Use the same machine, firmware settings, power source and storage.
2. Compare against the Fedora 44 package/kernel versions represented by the
   compose, not an unrelated newer installation.
3. Reboot between states, warm or cold caches consistently, and repeat enough
   times to report variation rather than one favorable result.
4. Measure the actual target workload (build, database, browser, media, VM or
   ML job) and keep thermal throttling visible.
5. Preserve protection settings during the baseline comparison. Attribute
   delays with service dependencies, application readiness, cache state and
   network timings before proposing a change.

Do not disable SELinux, audit, IOMMU, CPU mitigations or memory hardening based
on a generic percentage from another machine. If performance is a release
criterion, add the reproducible benchmark and raw results to the release
evidence rather than converting an expectation into a README claim.

# Test coverage

Four complementary layers of testing cover the source, build inputs, running
image and optional build comparisons.

## 1. Source and helper tests

**Coverage**: 89 structural tests total. The programs in `tests/` check configuration invariants,
source generators, supply-chain pins and extracted helper behavior. Every
functional module (M01–M37 + M11b + M40 + M41 + M42) is covered. Four additional
smoke tests exercise selected helpers in disposable roots.

```bash
bash tests/run-all.sh
```

See [tests/README.md](../tests/README.md) for dependencies, individual tests and
filtered runs. The runner returns 1 for test failures and 2 for setup errors;
a missing prerequisite does not count as a passing test. Source tests do not
establish that an ISO installs or boots successfully.

The AIDE source fixture compares synthetic data without creating or replacing
a host baseline. Fedora's AIDE may print
`Failed sending audit message:added=...` when an unprivileged fixture detects
its deliberate differences. Do not run the suite as root merely to
suppress that diagnostic; use the fixture result to assess the test.

## 2. Syntax and build-input validation

**Coverage**: 43 kickstart files (master.ks + 42 snippets including 99-finalize)
and the scripts embedded in them. Shell payloads pass syntax and ShellCheck
validation. `ksflatten` and `ksvalidator -v F44` validate the combined
Kickstart; individual snippets are not standalone Kickstart files.

These checks detect malformed input before a build. They do not replace an
actual Anaconda installation.

## 3. Tests of the ISO in a VM

The scripts in [`tests/pre-ship/`](../tests/pre-ship/) exercise the Live image,
a fresh installation and the installed system after reboot. Their command
reference is in [tests/README.md](../tests/README.md#pre-ship-gates).

| Area | Examples |
|------|----------|
| Installation and boot | UEFI/Secure Boot, first-boot setup, LUKS unlock, kernel command line |
| Desktop | Login/logout, Wayland, display power, first-party application controls |
| Applications | Real Firefox/Thunderbird startup, extension state, Flatpak policy and codec decoding |
| Network | LAN/XDP filtering, firewall boundaries, DNS, VPN compatibility, NTS and resume |
| Security | Effective sysctls, unprivileged BPF restrictions, SELinux, audit and USBGuard permissions |
| Storage | USB/SD mount behavior, permissions, image hygiene and independent installation identities |
| Recovery | Initramfs transitions, interrupted boot changes and Snapper rollback |
| Updates and integrity | Silent defaults, package freshness, AIDE and deliberate update paths |

Runtime tests belong in disposable test systems, never on the build host or an
unrelated workstation. Some tests deliberately change state, reboot, roll back
a snapshot or simulate power loss. Follow each script's supported arguments
and prerequisites. M21 `fresh-install` and `reboot` must both pass before
the destructive Snapper test: the two boot transitions need separate reboots.

`tests/pre-ship/08-codec-runtime.sh` checks both the initial state and explicit
codec opt-in, including public read-only DNF5 state and actual
H.264/HEVC/VP9/AV1 FFmpeg and GStreamer decode. Package presence alone is not a
decode test.

The installed SELinux test checks the Fedora 44 kernel-facing schema baseline
and reports the supported partial vendor boundary for newer extensions. It
also checks enforcing mode, immutable audit and current-boot denials.

VM coverage does not establish compatibility with every physical device.
NVIDIA, Wi-Fi and other hardware-specific paths need suitable hardware.
Release notes summarize the tested ISO's results, not the execution history.

## 4. Optional build comparison

Two builds can be compared to investigate differing inputs or generated files.
Complete ISO reproducibility is not established. A matching checksum proves
only that the compared files match; see
[build reproducibility](build-reproducibility.md).

## Continuous integration

GitHub Actions workflow runs on every push + PR to `main`.
The six jobs cover shell syntax, all 89 structural tests, ShellCheck, Kickstart
validation, the public-data scan, and source-generator/supply-chain checks.
Failures stop the workflow; environment-specific skips are reported explicitly.
See [ci.yml](../.github/workflows/ci.yml) for the executable configuration.

CI does not run the complete ISO build, graphical VM installation, physical
hardware tests or the privileged smoke-test environment. A green CI run alone
is not an ISO test result.

## Adding tests

Add a regression test when changing helper behavior, configuration, first-boot
logic or security boundaries. Test the actual behavior with a positive control
where a blanket failure could otherwise look successful. Keep source tests
isolated from the host's installed configuration and use disposable fixtures
for changes to system state. The [test reference](../tests/README.md#add-a-new-test)
describes naming and the shared assertion helpers.

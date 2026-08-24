# Smoke tests (bwrap-sandboxed)

Complement to the structural tests in `tests/NN-*.sh`. Where structural
tests grep for patterns in the source kickstart, **smoke tests actually
execute a Module's %post block** inside a bubblewrap sandbox against a
prepared Fedora rootfs — catching runtime bugs that structural tests
miss.

## Layering

| Layer | What it tests | Runtime |
|-------|---------------|---------|
| `tests/00-syntax-sweep.sh` | `bash -n` per .ks | milliseconds |
| `tests/NN-*.sh` | grep patterns over kickstart source | seconds, 84 test programs |
| `tests/smoke/MNN-<name>-smoke.sh` | actual %post execution in sandbox | minutes (first run: rootfs fetch) |
| VM smoke (manual) | full install boot | hours |

Smoke tests bridge the gap between "the source looks right" and "an
ISO actually boots". They validate:
- File paths resolve correctly (no typos in `/etc/foo/bar.conf`)
- sysctl keys the kernel accepts (vs typo'd keys)
- dconf compile works (DCONF_PRIVACY_EOF body is valid)
- Offline `systemctl enable`/`mask` writes the expected unit symlinks
- No runtime errors during %post execution

## Requirements

Smoke tests require the build host to have:

- **bubblewrap** (`sudo dnf install bubblewrap`) — sandbox engine
- **dnf** (one-time, for rootfs prep via `dnf --installroot`)
- **redhat-rpm-config** (`sudo dnf install redhat-rpm-config`) — Fedora
  vendor RPM configuration used by the closed bootstrap
- **~4 GB free disk in the worst case** (~1.8 GB prepared rootfs plus one
  ephemeral snapshot when copy-on-write is unavailable)
- **sudo** (rootfs prep needs `dnf --installroot`)
- **Kernel ≥ 5.13** (bwrap user namespace + cgroup features)

CI compatibility: these privileged user-namespace/installroot tests do not run
in the project's default GitHub Actions jobs, whose sandbox and disk contract
does not provide the prepared-rootfs execution boundary. Run them locally or
on a qualified self-hosted runner.

## First-time setup

```bash
# One-time: prepare the sandbox rootfs
sudo ./tests/smoke/prep-rootfs.sh

# Output: /var/cache/noid-smoke/rootfs-f44/ (~1.8 GB)
```

The rootfs is a minimal Fedora 44 + bash + coreutils + systemd +
selected Module prerequisites (systemd-resolved for M11, glib2 + dconf
for M17, etc.). Each test creates and then removes an ephemeral snapshot;
the prepared rootfs remains cached. Its manifest records the Fedora release
and a SHA-256 of the complete preparation definition. If that definition
changes, smoke tests reject the stale cache and require `prep-rootfs.sh` to
be run again.

An advanced cache relocation may set
`NOID_SMOKE_ROOTFS=/path/to/rootfs-f44`. The release-specific final component
is mandatory, its parent must be a canonical root-owned directory without
group/other write access, and an existing target is replaced only when it has
the NoID Privacy owner marker (or the exact legacy preparation manifest).
Mounted, symlinked, unmarked, or broader targets are rejected before deletion.

## Running smoke tests

```bash
# All smoke tests
sudo ./tests/smoke/run-all.sh

# Single Module
sudo ./tests/smoke/M02-sysctl-smoke.sh

# Optional: put only the disposable snapshots on another suitable filesystem.
# The prepared rootfs path remains controlled independently.
sudo env NOID_SMOKE_SANDBOX_PARENT=/path/with/free/space \
    ./tests/smoke/run-all.sh

# tests/run-all.sh never executes smoke tests; it only prints an
# availability hint, which this variable suppresses (CI-friendly)
SKIP_SMOKE_HINT=1 bash tests/run-all.sh
```

Exit codes:
- `0` — all smoke tests passed
- `1` — assertion failed
- `2` — no smoke-test programs were discovered
- `77` — prerequisites missing (bwrap, rootfs) → skipped, not failed

The all-tests runner exits `1` before execution when an existing rootfs does
not match the current preparation definition. Rebuild the cache using the
printed command; an old package set is not valid smoke-test evidence.

## What can NOT be smoke-tested

These Module concerns need a real VM:

- **Module 01** kernel cmdline: applied at boot, not at %post
- **Module 13** AIDE baseline: needs real /usr + /etc + btrfs
- **Module 14** USBGuard initial policy: needs real USB devices
- **Module 15** IOMMU state: hardware-dependent
- **Module 19** NVIDIA driver: hardware + kernel module signing
- **Module 22** LUKS: disk layout
- **Module 24** fwupd HSI: hardware attestation

These have structural tests but rely on VM smoke for runtime
validation.

## Sandbox isolation

Each smoke test runs in a fresh bwrap invocation with:

```bash
bwrap \
    --bind ${SNAPSHOT_DIR} /         # writable rootfs snapshot
    [--ro-bind /sys /sys |           # M27 opt-in: host sysfs, read-only
     --ro-bind /sys/fs/cgroup /sys/fs/cgroup] # M17 opt-in: cgroup subtree only
    --uid 0 --gid 0                  # fake-root semantics
    --unshare-pid                    # isolated process namespace
    --unshare-net                    # no network leakage
    --unshare-uts                    # isolated hostname
    --new-session                    # block TIOCSTI (CVE-2017-5226)
    --die-with-parent                # no process orphans
    --proc /proc --dev /dev --tmpfs /run --tmpfs /tmp
    --setenv HOME /tmp
    --setenv PATH /usr/sbin:/usr/bin:/sbin:/bin
    /bin/bash /root/.noid-smoke-<extracted-script>.sh
```

The `--bind` gives the %post block write access to a copy of the
rootfs. After the test, the snapshot is discarded — no state leaks.
The optional binds are mutually exclusive and disabled by default.
`M27-hardware-smoke.sh` opts into the complete host `/sys` tree through
`SMOKE_BIND_SYS=1`; `M17-gnome-smoke.sh` exposes only
`/sys/fs/cgroup` through `SMOKE_BIND_CGROUP=1`. Both views are read-only, but
they can reveal host hardware or controller state to the tested `%post` block.

## Limitations

- **SELinux**: disabled inside the sandbox (bwrap can't transition
  contexts). Smoke tests verify non-SELinux behaviour; SELinux checks
  happen via VM smoke + `assert_selinux_context` structural assertions.
- **systemctl**: the unit-file system inside the sandbox is the same
  rootfs, but `systemctl` interacts with a host-owned systemd that
  doesn't exist. `systemctl enable` writes the correct symlink (which
  is what we check), but `systemctl start` is a no-op.
- **M02 network-namespace sysctls**: file creation, metadata and SELinux
  validation stay inside the network-isolated sandbox. The global
  `net.core.bpf_jit_harden` node is absent from a newly created network
  namespace, so the exact three generated files are subsequently checked with
  `sysctl --dry-run` in the Fedora host's initial namespace. The test neither
  writes a live value nor enables an unknown-key ignore mode.
- **dnf**: no network — the sandbox is hard-wired `--unshare-net`.
  Anything a %post needs must come from the pre-populated rootfs
  (extend `prep-rootfs.sh` rather than downloading in-sandbox).

## Contributing a new smoke test

Template (mirrors `M02-sysctl-smoke.sh`):

```bash
#!/bin/bash
# tests/smoke/MNN-<name>-smoke.sh — Module NN smoke test
set -euo pipefail
. "$(dirname "$0")/lib.sh"

smoke_start "MNN-<name>"

PROJECT_ROOT="$(project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/NN-name.ks"

TMP_POST=$(mktemp --tmpdir smoke-mNN-post-XXXXXX.sh)
smoke_register_temp_file "$TMP_POST"

extract_post "$KS_FILE" "$TMP_POST"

# Stub only one exact line that the sandbox cannot run against its isolated
# kernel/systemd. Prove uniqueness before making an anchored replacement:
stub_line='    systemctl daemon-reload'
[ "$(grep -Fxc "$stub_line" "$TMP_POST" || true)" -eq 1 ] \
    || { _fail "MNN stub contract drifted"; exit 1; }
sed -i 's|^    systemctl daemon-reload$|    true  # sandbox stub|' "$TMP_POST"

if run_in_sandbox "$TMP_POST"; then
    _pass "MNN %post executed without error"
else
    _fail "MNN %post returned non-zero"
fi

# Assertions on the post-execution rootfs state
assert_in_sandbox '[ -f /etc/foo/bar.conf ]' "/etc/foo/bar.conf was created"
assert_in_sandbox 'grep -q "^key=value" /etc/foo/bar.conf' "key=value set"

smoke_finish
```

See `M02-sysctl-smoke.sh` for a working example.

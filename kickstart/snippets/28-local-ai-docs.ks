# ============================================================================
# Module 28 — Local AI Stack Documentation (user-facing, opt-in)
# Status: LOCKED 2026-08-24 (v36) — refresh the reviewed llama.cpp Vulkan pin to b10605.
#
# Scope: ship one user-facing guide for optional local inference, exact
# loopback/network boundaries, four runtime choices, editor integration and
# full owner-authorized tools plus optional lower-trust isolation.
# NO package installs, NO service enables, NO auto-setup — local AI is a
# per-hardware user opt-in on a generic image.
#
# Covers: doc heredoc (AI_DOC_EOF) + keyword/structure verification +
# health stamp.
# Shipped Markdown target: /usr/share/doc/noid-privacy/28-local-ai.md
# Shipped Markdown heredoc: AI_DOC_EOF
#
# Deliberate constraint notes:
#   - Option order is RamaLama, Ollama, LM Studio, llama.cpp. It is navigation,
#     not a universal performance/security ranking.
#   - docs/28-local-ai.md is canonical. Regenerate this heredoc with
#     scripts/regen-local-ai-doc.sh; tests/28 gates byte identity.
#   - Upstream `ramalama run` network isolation is not generalized to
#     `ramalama serve`; every server example binds and verifies loopback.
#   - CVE claims remain version-scoped and link to the primary advisory.
#   - No user-facing M12 doc exists — never cross-reference a 12-*.md from
#     this doc (use operational commands like `getenforce` instead).
#   - Registry/model pulls and editor extension traffic remain separate from
#     the local inference path.
#   - The explicit owner profile keeps file/terminal autonomy; sandboxing is a
#     separately selected lower-trust mode, never an implicit product limit.
#   - stamp (Phase 4): doc-only modules are no exemption; M99
#     EXPECTED_STAMPS includes 28.
#
# Dependencies: none at build. Package modifications: NONE.
# ============================================================================

%packages --exclude-weakdeps
# No packages. Documentation-only module.
%end

%post --log=/var/log/ks-28-local-ai-docs.log --erroronfail
set -euo pipefail

PHASE=""
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [M28] ${PHASE}: $*"; }
die() { log "FAIL: $*"; exit 1; }
DOC_TMP=""
STAMP_TMP=""
STAMP_PUBLICATION_ACTIVE=0
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-28-local-ai-docs.ok"
cleanup() {
    if [ -n "${DOC_TMP:-}" ]; then
        rm -f -- "$DOC_TMP" || true
    fi
    if [ -n "${STAMP_TMP:-}" ]; then
        rm -f -- "$STAMP_TMP" || true
    fi
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "FAIL: could not retire incomplete Module 28 health stamp"
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

log "=== Module 28 Local AI Stack Documentation start ==="
command -v restorecon >/dev/null 2>&1 \
    || die "restorecon is required for fail-closed SELinux labeling"
command -v matchpathcon >/dev/null 2>&1 \
    || die "matchpathcon is required for fail-closed SELinux verification"

# M28_HEALTH_INVALIDATION_BEGIN
# A build-health stamp describes this complete documentation publication, not
# merely the last successful historical run. Validate the shared state boundary
# without normalizing drift, then retire old success before the first payload
# mutation so a failed rerun cannot leave plausible green evidence behind.
PHASE="P0-health-invalidation"
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    die "$STAMP_DIR exists but is not a real directory"
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ]; then
    die "$STAMP_DIR metadata is not root:root 0755"
fi
if ! restorecon -F -- "$STAMP_DIR" \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "$STAMP_DIR SELinux context is not canonical"
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        die "health-stamp target is not a file or symlink: $STAMP"
    fi
    rm -f -- "$STAMP" \
        || die "cannot invalidate stale Module 28 health stamp"
    sync -- "$STAMP_DIR"
fi
log "  [OK] prior Module 28 health stamp is absent"
# M28_HEALTH_INVALIDATION_END

# ------------------------------------------------------------------------------
# Phase 1 — Ensure doc directory
# ------------------------------------------------------------------------------
PHASE="P1-setup"
DOC_DIR=/usr/share/doc/noid-privacy
AI_DOC="$DOC_DIR/28-local-ai.md"
log "Preparing $DOC_DIR"
if { [ -e "$DOC_DIR" ] || [ -L "$DOC_DIR" ]; } \
   && { [ ! -d "$DOC_DIR" ] || [ -L "$DOC_DIR" ]; }; then
    die "$DOC_DIR exists but is not a real directory"
fi
install -d -m 0755 -o root -g root "$DOC_DIR"
[ "$(stat -c '%u:%g:%a' "$DOC_DIR")" = "0:0:755" ] \
    || die "$DOC_DIR metadata is not root:root 0755"
restorecon -F -- "$DOC_DIR" \
    || die "cannot label $DOC_DIR"
matchpathcon -V "$DOC_DIR" >/dev/null \
    || die "$DOC_DIR SELinux context differs"

# ------------------------------------------------------------------------------
# Phase 2 — Write 28-local-ai.md
# ------------------------------------------------------------------------------
PHASE="P2-doc"
log "Writing 28-local-ai.md"

DOC_TMP=$(mktemp "$DOC_DIR/.28-local-ai.md.XXXXXXXX")
cat > "$DOC_TMP" <<'AI_DOC_EOF'
# Local AI stack — optional

NoID Privacy installs no model runtime, model or editor AI extension by default.
This guide describes four opt-in paths. A local model can keep inference prompts
on the workstation only when the server is loopback-bound and the client is
actually configured to use it. Downloads, registries, update checks, editor
extensions, model tools and remote MCP servers are separate network boundaries.

## Boundary before installation

- A model file is untrusted input. Prefer a reviewed publisher, record the
  model revision/digest and read its license/model card.
- A loopback listener is reachable by local processes. It is not authentication
  or isolation from another compromised desktop application.
- `0.0.0.0`/`::` exposes a server beyond loopback when firewall/routing allows.
  This guide deliberately uses `127.0.0.1` and verifies the listener.
- Rootless containers reduce host access but are not VM or kernel boundaries.
- Agent/tool mode is materially more powerful than chat/completion because it
  can read and change files and execute commands. In NoID Privacy's explicitly enabled
  owner workflow that authority is intentional; the controls below keep the
  listener and remote boundaries narrow without turning the local agent into a
  read-only assistant.
- Local inference avoids a cloud-model request, but there can still be registry,
  marketplace and updater traffic. It also consumes local hardware and power.

## Hardware check

CPU-only inference is the compatibility baseline. GPU support depends on the exact
device, driver, runtime, model format and backend; a vendor/generation name is
not a guarantee that a particular model fits or runs correctly.

```bash
lspci -nn | grep -iE 'VGA|3D|Display'
free -h
ls -l /dev/dri 2>/dev/null || true
command -v nvidia-smi >/dev/null && nvidia-smi
```

Record the exact GPU memory rather than inferring it from the product name:

```bash
nvidia-smi --query-gpu=name,driver_version,memory.total,memory.free,compute_cap \
  --format=csv,noheader 2>/dev/null || true
```

Model memory is not just the file size. Weights, context/KV cache, compute
buffers, parallel server slots and the GPU driver all consume memory. A model
can use RAM and VRAM together when its engine supports partial offload, but
crossing the CPU/GPU boundary can reduce speed. In a Mixture-of-Experts (MoE)
model, only some experts are active per token; that lowers compute relative to
the total parameter count, but the complete quantized expert weights still have
to live in RAM, VRAM or mapped storage.

For initial load/smoke validation on a 4-GiB GPU with ample system RAM, start
with one server slot, 4096 context, automatic or conservative GPU-layer
fitting, and a small reviewed quantization. That is not enough context for the
full agent profile described later. Increase context or offload one variable at
a time while watching both:

```bash
watch -n 1 nvidia-smi
watch -n 1 'free -h; ps -C llama-server -o pid,rss,vsz,cmd --no-headers'
```

Do not promise a token rate from model size alone. Measure cold load, prompt
processing and token generation separately, then repeat a warm run. Record
engine/build, model digest, quantization, context, batch/ubatch, parallel slots,
GPU layers, KV-cache type, prompt/evaluated token counts and power mode.
Ollama's native `/api/generate` response reports nanosecond durations; for a
non-streaming benchmark its generation rate can be calculated without timing
the HTTP client:

```bash
ollama_model=${OLLAMA_MODEL:?export OLLAMA_MODEL with the exact reviewed model tag}
benchmark_prompt='Explain one concrete privacy boundary in two sentences.'
curl --fail --silent http://127.0.0.1:11434/api/generate \
  -H 'Content-Type: application/json' \
  --data-binary "$(jq -cn \
    --arg model "$ollama_model" --arg prompt "$benchmark_prompt" \
    '{model:$model,prompt:$prompt,stream:false,options:{num_ctx:4096,seed:1,num_predict:128}}')" \
  | tee /var/tmp/noid-ollama-benchmark.json \
  | jq '{load_s:(.load_duration/1e9),prompt_tps:(.prompt_eval_count*1e9/.prompt_eval_duration),generation_tps:(.eval_count*1e9/.eval_duration),prompt_tokens:.prompt_eval_count,generated_tokens:.eval_count}'
```

That file can contain generated text and timing metadata; remove or retain it
according to the workspace's disclosure policy.

## Which option should you pick?

| Option | Choose it when |
|---|---|
| **A. RamaLama** | You want the Fedora-packaged, rootless-container path and are willing to inspect the generated Podman command/network mode. |
| **B. Ollama** | You want Ollama API compatibility and accept either a security-reviewed Fedora candidate or a pinned, verified upstream release. |
| **C. LM Studio** | You want a closed-source GUI/AppImage and accept its vendor/update boundary. |
| **D. llama.cpp** | You want the direct engine (Fedora package when suitable, otherwise an exactly pinned upstream build) and will manage GGUF files and flags yourself. |

RamaLama is the recommended starting point for this image because Fedora 44
packages it and its upstream design supports rootless containers. That is a
delivery/integration preference, not a universal security or performance rank.
Do not infer that a container is active from the package name alone: RamaLama
can also select a host backend. Confirm the effective engine with
`ramalama info` and inspect `--dryrun`.

## Option A — RamaLama

Fedora 44 packages `ramalama`; current upstream documentation describes model
containers, read-only model mounts and `ramalama run` with no container network.
Always check the installed version's help/man pages because CLI, defaults and
backends evolve. The Fedora 44 `ramalama-0.21.0-1.fc44` payload audited for this
guide differs from parts of its bundled/upstream prose: `run` did not emit
`--network=none` unless requested, and its effective SELinux default was false,
which generated `--security-opt=label=disable`. Therefore make both controls
explicit and inspect the generated command.

```bash
sudo dnf install ramalama podman
rpm -q ramalama podman
ramalama version
man ramalama-run
man ramalama-serve
```

Pulling a model or inference image contacts the selected registry. The registry
can observe the source connection and requested artifact. Tags can move; use a
reviewed immutable model/OCI digest where the selected transport supports it.
Hosted API transports such as `openai://` are remote inference paths and bypass
the local container runtime; do not use them for a local-only claim.

```bash
# Example only: select a current model from a reviewed registry/model card.
model_reference=${RAMALAMA_MODEL:?export RAMALAMA_MODEL with the reviewed model reference}
ramalama pull "$model_reference"
ramalama list

# CPU-only interactive run with explicit isolation. The model must already be
# present for --pull=never.
ramalama --dryrun run --network=none --selinux=true \
  --device=none --ngl 0 --pull=never "$model_reference"
ramalama run --network=none --selinux=true \
  --device=none --ngl 0 --pull=never "$model_reference"
```

The dry run must contain `--network none`, must not contain
`--security-opt=label=disable`, and must not expose an unintended device. Do not
generalize `run` isolation to hosted API transports or `serve`: a server must
publish a host port for clients, and the audited `serve` default was the
wildcard `::`. A serving container can also retain outbound connectivity.
Bind the host socket to loopback and apply a separately verified egress policy
when the serving container must be offline.

RamaLama's browser UI and an editor-only endpoint are two deliberate modes:

```bash
model_reference=${RAMALAMA_MODEL:?export RAMALAMA_MODEL with the reviewed model reference}

# Browser chat: WebUI on, explicit loopback, SELinux labels retained.
ramalama --dryrun serve --selinux=true --host 127.0.0.1 --port 8080 \
  --webui on --pull=never "$model_reference"
ramalama serve --selinux=true --host 127.0.0.1 --port 8080 \
  --webui on --pull=never "$model_reference"

# Headless VSCodium/API mode instead:
# ramalama serve --selinux=true --host 127.0.0.1 --port 8080 \
#   --webui off --pull=never "$model_reference"

# In another terminal:
ss -ltnp | grep ':8080'
curl --fail --silent http://127.0.0.1:8080/v1/models
podman ps --format '{{.Names}} {{.Ports}}'
```

Open `http://127.0.0.1:8080/` only after the socket check. Expected: no
`0.0.0.0:8080` or `[::]:8080` listener. API paths depend on the selected
RamaLama inference backend/version; verify `/health`, `/v1/models`, `/infill`
and `/v1/chat/completions` individually before assigning editor roles.

The Fedora RPM covers the RamaLama client, not every model or runtime OCI image.
Before the first run, inspect the runtime image source and pin its digest where
the selected engine permits it. After a reviewed pull, `--pull=never` prevents a
silent refresh; confirm the exact image with:

```bash
runtime_image=${RAMALAMA_RUNTIME_IMAGE:?export RAMALAMA_RUNTIME_IMAGE with the exact image ID or digest}
podman image inspect --format '{{.Digest}} {{.RepoDigests}}' "$runtime_image"
```

### GPU boundary

Use `ramalama info`, `ramalama --dryrun`, the installed `ramalama-cuda(7)`
documentation and upstream hardware table. NVIDIA normally requires the
proprietary driver plus a reviewed container-toolkit/CDI setup. AMD paths depend
on ROCm/Vulkan support; Intel Arc and other Intel GPUs likewise depend on the
exact device, driver and backend.
Enabling `container_use_devices` widens container device
access system-wide and must be a deliberate SELinux trade-off, not an automatic
copy/paste step.

```bash
ramalama info
podman info --debug
```

Automatic detection can expose `/dev/dri`, `/dev/accel` or every configured
NVIDIA CDI device. On a CPU-only run, `--device=none --ngl 0` is the auditable
baseline. For GPU use, remove those flags only after the dry run shows the exact
intended device. If setup fails, return to CPU rather than disabling SELinux or
passing broad host devices.

### Remove RamaLama

```bash
sudo dnf remove ramalama

# Optional, recoverable data removal after inspecting the exact paths:
ramalama_data_root=${XDG_DATA_HOME:-"$HOME/.local/share"}
ramalama_config_root=${XDG_CONFIG_HOME:-"$HOME/.config"}
for ramalama_path in \
  "$ramalama_data_root/ramalama" \
  "$ramalama_config_root/ramalama"; do
    [ ! -e "$ramalama_path" ] || du -sh -- "$ramalama_path"
done
# Run only for each reviewed path that should be retired:
# gio trash -- "$ramalama_data_root/ramalama"
# gio trash -- "$ramalama_config_root/ramalama"
```

## Option B — Ollama

NoID Privacy does not install Ollama. Fedora 44 now packages it, so “Ollama is
available only through the vendor installer” is no longer true. However, the
package candidate must be security-acceptable, not merely Fedora-signed.

At the 2026-08-23 review, Fedora 44 still offered `ollama-0.12.11-4.fc44`.
CVE-2026-7482 affects Ollama before 0.17.1, and NVD lists releases through
0.13.5 as affected by CVE-2026-5757. The audited Fedora candidate is therefore
not acceptable. Do not install or run that version. Re-evaluate the current
candidate and Fedora advisories at use time:

```bash
dnf repoquery --latest-limit=1 --qf '%{name}-%{evr}.%{arch}' ollama
dnf info ollama
```

When Fedora ships a fixed/sufficiently reviewed build, DNF is preferred. Until
then, a current upstream release is a separate vendor-code boundary. The
mutable `https://ollama.com/install.sh` installer writes to system paths,
creates a user/service, enables the service, and can add a driver repository;
do not pipe it to a shell or treat `OLLAMA_VERSION` as artifact verification.

For evaluation without root or persistent autostart, pin an exact GitHub
release, verify its vendor-published checksum against a separately retained
review pin, and extract it into a version-specific user directory. At the
2026-08-23 review, the current upstream release was `v0.32.15`; its published
Linux x86-64 artifact was 1,422,416,084 bytes, and the vendor checksum plus
the retained review pin both resolved to
`50539c5fe9bf85887733355098dcdb266b433cb8c73fa180713417e9ed6e42bb`.
Re-check current advisories before installing even these pinned bytes:

```bash
(
set -euo pipefail
ollama_version=v0.32.15
ollama_expected=50539c5fe9bf85887733355098dcdb266b433cb8c73fa180713417e9ed6e42bb
if [[ ! $ollama_version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'invalid Ollama release: %s\n' "$ollama_version" >&2
  exit 2
fi

ollama_asset=ollama-linux-amd64.tar.zst
ollama_stage=$(mktemp -d /var/tmp/noid-ollama.XXXXXXXX)
cleanup_ollama_stage() {
  case "$ollama_stage" in
    /var/tmp/noid-ollama.*) ;;
    *) printf 'refusing unexpected Ollama stage: %s\n' "$ollama_stage" >&2; return 1 ;;
  esac
  if [ -e "$ollama_stage" ] || [ -L "$ollama_stage" ]; then
    [ -d "$ollama_stage" ] && [ ! -L "$ollama_stage" ] || {
      printf 'refusing non-directory Ollama stage: %s\n' "$ollama_stage" >&2
      return 1
    }
    find "$ollama_stage" -depth -delete
  fi
}
trap cleanup_ollama_stage EXIT
trap 'exit 1' HUP INT TERM
chmod 0700 "$ollama_stage"
ollama_release="https://github.com/ollama/ollama/releases/download/$ollama_version"

curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  "$ollama_release/$ollama_asset" -o "$ollama_stage/$ollama_asset"
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  "$ollama_release/sha256sum.txt" -o "$ollama_stage/sha256sum.txt"
awk -v asset="./$ollama_asset" '$2 == asset { print }' \
  "$ollama_stage/sha256sum.txt" > "$ollama_stage/selected.sha256"
test "$(wc -l < "$ollama_stage/selected.sha256")" -eq 1
test "$(cut -d' ' -f1 < "$ollama_stage/selected.sha256")" = "$ollama_expected"
(cd "$ollama_stage" && sha256sum --check selected.sha256)
tar --zstd -tf "$ollama_stage/$ollama_asset" | less

ollama_root="$HOME/.local/lib/ollama/${ollama_version#v}"
test ! -e "$ollama_root" && test ! -L "$ollama_root"
install -d -m 0700 "$ollama_root"
tar --zstd --no-same-owner --no-same-permissions \
  -xf "$ollama_stage/$ollama_asset" -C "$ollama_root"
"$ollama_root/bin/ollama" --version
cleanup_ollama_stage
trap - EXIT HUP INT TERM
)
```

For v0.32.15 the vendor checksum matched the retained pin, the archive had no
absolute/traversal paths or special device entries, and the extracted client
was executed offline in a network-unshared sandbox. Its version probe reported
0.32.15, and `ollama serve --help` retained the loopback default plus the
documented `OLLAMA_NO_CLOUD` control.

The source review also covered the two current availability advisories whose
version metadata is incomplete. ZDI-26-403 / CVE-2026-15685 describes a short
array index in `downloadBlob`, but publishes neither affected versions nor a
reproducer. Upstream commit `9239a254e054` added an empty-digest guard on
2025-05-27, release `v0.8.0` contains that commit, and the reviewed `v0.32.15`
source additionally routes the digest through `manifest.BlobsPath` before any
`[7:19]` slice. That validator accepts only a complete `sha256:`/`sha256-`
digest with 64 hexadecimal characters. This independently rules out the
described short-digest panic in the pinned source; it is not a vendor statement
of the advisory's affected range.

CVE-2026-65315 covers attacker-sized allocations in the GGUF parser. Upstream
issue 17042 links the repair to merged commit `67b6a1c2d453`; `v0.32.15`
contains it, and its reviewed parser caps strings, arrays and tensor dimensions
before allocation. These checks reduce the known parser DoS, but they do not
make untrusted model files safe. Keep the API on loopback, import models only
from reviewed sources, and re-check advisories at use time.

A separate open upstream report, issue 17041, covers an SSRF path in tensor
blob redirects. The reviewed `v0.32.15` source still returns a cross-host
redirect from `x/transfer/download.go` without rejecting loopback, private or
link-local targets. Treat that issue as unresolved: do not let untrusted clients
or model references drive `/api/pull`, retain the loopback API bind, and use
the host egress boundary where a deployment needs stronger containment.

The release checksum authenticates only what the vendor published through that
release channel; it is not an independent code audit. Inspect archive paths
before extraction when the release layout changes. Keep the version in the
path so updates are side-by-side and reversible.

Run the server in the foreground first. This preserves NoID Privacy's
no-unattended-service default and makes the selected backend visible:

```bash
ollama_version=v0.32.15
ollama_root="$HOME/.local/lib/ollama/${ollama_version#v}"
export OLLAMA_HOST=127.0.0.1:11434
export OLLAMA_NO_CLOUD=1
export OLLAMA_MODELS="$HOME/.local/share/ollama/models"
"$ollama_root/bin/ollama" serve
```

In a second terminal, use the same exact binary and verify the listener:

```bash
ollama_version=v0.32.15
ollama_root="$HOME/.local/lib/ollama/${ollama_version#v}"
ss -ltnp | grep ':11434'
curl --fail --silent http://127.0.0.1:11434/api/tags
"$ollama_root/bin/ollama" ps
```

`OLLAMA_NO_CLOUD=1` disables Ollama cloud models and web search; current
upstream documentation says the log then reports
`Ollama cloud disabled: true`. It does not stop model downloads or update
checks, and it is not a substitute for an outbound policy.

Do not expose the local API to LAN/WAN. Current Ollama documentation explicitly
says that `http://localhost:11434` requires no authentication.
CVE-2025-63389 separately records missing authentication in releases through
0.12.3; do not reinterpret that version range as proof that a current local API
is authenticated. Loopback binding and current security updates remain required.

Vulkan support and environment variables are version-specific. Current Ollama
documentation says Vulkan is experimental and must be enabled with
`OLLAMA_VULKAN=1`; `GGML_VK_VISIBLE_DEVICES` selects Vulkan devices and `-1`
disables all of them. Do not use the stale `OLLAMA_VULKAN=0` recipe or force
`OLLAMA_LLM_LIBRARY=vulkan`. NVIDIA CUDA selection is a different backend;
verify the actual backend, offload and devices in the server log and
`ollama ps`.

```bash
# Only for a deliberately selected Vulkan test:
export OLLAMA_VULKAN=1
export GGML_VK_VISIBLE_DEVICES=0

# To exclude Vulkan devices instead:
unset OLLAMA_VULKAN
export GGML_VK_VISIBLE_DEVICES=-1
```

For a system service installed separately, set both
`OLLAMA_HOST=127.0.0.1:11434` and `OLLAMA_NO_CLOUD=1` in a reviewed systemd
drop-in, then verify the effective environment, listener and service state.
Do not enable persistent background execution merely to make a one-shot test.

To remove the user-local evaluation, stop the foreground process, inspect the
version directory, model store and any generated `~/.ollama` identity, then use
`gio trash` on only the exact reviewed targets. A vendor/system installation
has a different layout and must be removed according to its recorded changes.

## Option C — LM Studio

LM Studio is closed source and distributed by its vendor. Its Linux support is
Ubuntu-oriented, so a current vendor artifact is not proof of Fedora
compatibility. Download the current Linux artifact from the official site,
verify every checksum/signature the vendor currently provides, and retain the
artifact/version record. The vendor currently distributes an AppImage; use one
resolved file, never a wildcard that can execute an unintended older download.

```bash
lmstudio_filename=${LM_STUDIO_FILENAME:?export LM_STUDIO_FILENAME with the exact reviewed AppImage filename}
lmstudio_source="/var/tmp/$lmstudio_filename"
test -f "$lmstudio_source" && test ! -L "$lmstudio_source"
sha256sum "$lmstudio_source"

install -d -m 0700 "$HOME/.local/opt/lm-studio"
install -m 0755 -- "$lmstudio_source" \
  "$HOME/.local/opt/lm-studio/LM-Studio.AppImage"
"$HOME/.local/opt/lm-studio/LM-Studio.AppImage"
```

In the application's current server UI, select the model, bind the API to
`127.0.0.1`, leave **Serve on Local Network** off, turn **Require
Authentication** on and configure the matching token in each client. Restrict
CORS to the exact local client origin where supported. Verify with `ss -ltnp`;
a GUI label is not proof of the socket. Treat MCP configuration and the optional
headless `llmster` daemon as separate tool/service boundaries.

The vendor's current privacy policy says local chats/documents stay on-device
and the app has no behavioral telemetry, but update checks send app/OS data and
an IP address, model search/download sends search/download data, and cloud
models or web search send the request for remote processing. These are
vendor claims to verify against the installed version and observed traffic;
they do not justify weakening the silent-machine or egress policy.

Remove the AppImage, desktop entry and application/model data only after
reviewing the locations shown by the installed version.

## Option D — llama.cpp

Fedora 44 packages `llama-cpp` and its `llama-cli`/`llama-server` binaries.
At the 2026-08-23 review, Fedora 44 still offered `b6153-3.fc44`, provided no newer `llama`
umbrella command, and declared a large ROCm/HIP dependency chain even for an
NVIDIA or CPU-only host. On the reference host, DNF previewed roughly 2 GiB of
downloads and 6 GiB installed. Preview the current transaction; do not install
that footprint merely because another component expects the command
`llama serve`. Fedora's build/backends may lag upstream or differ from online
examples, so the installed binary's `--help` is authoritative.

```bash
sudo dnf install --assumeno llama-cpp
# Run only after the previewed version/backend/footprint is accepted:
sudo dnf install llama-cpp
rpm -q llama-cpp
llama-cli --help | head
llama-server --help | less
llama-bench --help | less
```

At the 2026-08-24 review, the newest upstream `b*` release carrying the
documented Ubuntu x86-64 Vulkan artifact was build `b10605`. Its exact
32,911,942-byte archive and the GitHub release metadata both
resolved to SHA-256
`e19d439953b4ccc8ce8fb17963d2882658573cbbce7a753543e0791ffbeff350`.
For a reversible non-root evaluation on Intel Arc/NVIDIA, retain that review
pin rather than executing llama-vscode's mutable installer:

```bash
(
set -euo pipefail
llama_cpp_build=b10605
llama_cpp_asset=llama-b10605-bin-ubuntu-vulkan-x64.tar.gz
llama_cpp_expected=e19d439953b4ccc8ce8fb17963d2882658573cbbce7a753543e0791ffbeff350
llama_cpp_stage=$(mktemp -d /var/tmp/noid-llama-cpp.XXXXXXXX)
cleanup_llama_cpp_stage() {
  case "$llama_cpp_stage" in
    /var/tmp/noid-llama-cpp.*) ;;
    *) printf 'refusing unexpected llama.cpp stage: %s\n' "$llama_cpp_stage" >&2; return 1 ;;
  esac
  if [ -e "$llama_cpp_stage" ] || [ -L "$llama_cpp_stage" ]; then
    [ -d "$llama_cpp_stage" ] && [ ! -L "$llama_cpp_stage" ] || {
      printf 'refusing non-directory llama.cpp stage: %s\n' "$llama_cpp_stage" >&2
      return 1
    }
    find "$llama_cpp_stage" -depth -delete
  fi
}
trap cleanup_llama_cpp_stage EXIT
trap 'exit 1' HUP INT TERM
chmod 0700 "$llama_cpp_stage"
llama_cpp_release="https://github.com/ggml-org/llama.cpp/releases/download/$llama_cpp_build"

curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  "$llama_cpp_release/$llama_cpp_asset" \
  -o "$llama_cpp_stage/$llama_cpp_asset"
test "$(sha256sum "$llama_cpp_stage/$llama_cpp_asset" | cut -d' ' -f1)" = \
  "$llama_cpp_expected"
tar -tzf "$llama_cpp_stage/$llama_cpp_asset" | less

llama_cpp_root="$HOME/.local/lib/llama.cpp/$llama_cpp_build-vulkan"
test ! -e "$llama_cpp_root" && test ! -L "$llama_cpp_root"
install -d -m 0700 "$llama_cpp_root"
tar --no-same-owner --no-same-permissions --strip-components=1 \
  -xzf "$llama_cpp_stage/$llama_cpp_asset" -C "$llama_cpp_root"
"$llama_cpp_root/llama-server" --version
"$llama_cpp_root/llama-server" --list-devices
cleanup_llama_cpp_stage
trap - EXIT HUP INT TERM
)
```

The downloaded b10605 binary was also executed offline in a network-unshared
sandbox for `--version`, `--help` and `--list-devices`; the binary identified
release build 10605 at commit `a130532ae`. The documented
`--host`, `--port`, `--ctx-size`, `--parallel`, `--jinja`, `--reasoning`,
thread, device, GPU-layer and CPU-MoE flags were all present. That proves CLI
compatibility for this guide; it does not repeat the model/performance record
retained below for b10173.

This is exact vendor-release evidence, not an independent source audit or a
permanent “latest” claim. Re-review source, release metadata, dependencies and
network defaults before changing the build/digest pair. Use the Fedora package
again when its version, backend and transaction footprint meet the deployment.

Use an already downloaded, reviewed local GGUF path to avoid implicit
Hugging Face lookups:

```bash
llama-cli -m "$HOME/models/model.gguf" -p 'Hello'
llama-server -m "$HOME/models/model.gguf" \
  --host 127.0.0.1 --port 8080 \
  --ctx-size 4096 --parallel 1
```

Then verify the listener exactly as above. In current upstream builds the
browser UI is enabled by default and is available at
`http://127.0.0.1:8080/`; use explicit `--ui` or `--no-ui` only after the
installed `--help` confirms those flags. Current upstream exposes FIM at
`/infill`, chat at `/v1/chat/completions`, embeddings at `/v1/embeddings` and
health at `/health`. Test the endpoint required by the client instead of
assuming “OpenAI compatible” covers every role.

Current upstream builds support `--api-key-file`; use it even on loopback when
multiple local applications run, and set `--cors-origins localhost`. The UI
assets, health and model-list endpoints remain public in the current upstream
implementation, while inference and `/tools` require the key when one is set.
Loopback and process isolation are still required.

Building upstream source or using upstream CUDA/Vulkan binaries creates a
separate compiler/binary/dependency trust path and is outside the Fedora-package
guarantee. On a 4-GiB NVIDIA system, a reviewed current accelerator-capable
upstream runtime can be substantially more practical than Fedora's ROCm-oriented
transaction; pin its exact release/source and verify vendor-published digests.

### MoE/expert offload

Current upstream flags include `--cpu-moe`, `--n-cpu-moe`, `-ngl`/GPU layers,
`--override-tensor`/`-ot`, automatic device fitting, flash attention and
quantized K/V caches. They change and are not available or equivalent in every
Fedora build, backend or wrapper. Check the actual `llama-server --help` and
`llama-bench --help`.

For a 4-GiB GPU plus ample RAM, compare three measured states:

1. CPU baseline (`-ngl 0`);
2. automatic/maximum stable layer offload; and
3. MoE experts retained in RAM with `--cpu-moe` or a measured
   `--n-cpu-moe N`, while non-expert tensors and possibly KV cache use VRAM.

Do not blindly copy a tensor-regex `-ot` rule from another architecture. A
wrong pattern can silently place different tensors than intended after a model
or engine update. Likewise, `q8_0`/`q4_0` KV cache can save memory but changes
quality/backend compatibility and must be compared with the default `f16`.

Use a fixed local model and identical parameters:

```bash
llama-bench -m "$HOME/models/model.gguf" \
  -p 512 -n 128 -r 5 -ngl 0 -o jsonl

# In a current build where -1 means automatic GPU-layer fitting:
llama-bench -m "$HOME/models/model.gguf" \
  -p 512 -n 128 -r 5 -ngl -1 -o jsonl
```

If the installed help offers `--fit`/`--fit-target`, start with its conservative
default margin rather than filling all 4094 MiB reported by the GPU. Desktop
display allocation and transient compute buffers need headroom. There is no
universal “4 GB/6 GB/12 GB” recipe: total model state must still fit across RAM
and VRAM, and CPU-offloaded experts can become the bottleneck.

Automatic fitting is not a substitute for checking the startup log. In
reviewed `b10173`, a requested `--n-cpu-moe` creates tensor overrides; when the
initial placement does not already fit, `--fit` can report that it cannot
adjust parameters because those overrides are set. It may still start with
less reserve than requested. In that case, set `--fit off`, reduce
`--n-gpu-layers` explicitly, restart, and verify process VRAM with `nvidia-smi`.
Never claim a target reserve from the command line alone.

Start conservatively, monitor memory, and record the exact model hash, context,
batch/ubatch, slots, KV type, backend and command. An out-of-memory failure can
come from weights, KV cache, compute buffers, driver/runtime allocation or
warm-up; do not assume one cause or blindly disable warm-up/graphs. A target
such as 20 generated tokens/s is accepted only when the real model, intended
context and warm-run measurement reproduce it.

## VSCodium integration

VSCodium's core telemetry setting does not control third-party extensions.
Every client must be reviewed/configured independently, and an extension can
read more workspace context than the model prompt visibly shows.

Keep three roles separate:

1. FIM completion uses `/infill` and a code-FIM model.
2. Chat/tool calling uses `/v1/chat/completions` and a compatible instruct
   model/template.
3. Workspace RAG optionally uses `/v1/embeddings` and a dedicated embedding
   model.

One model or “OpenAI-compatible” endpoint need not implement all three. On a
4-GiB GPU, loading three GPU models concurrently is usually worse than
switching profiles or keeping a small embedding model on CPU.

### llama-vscode — preferred current local client

`ggml-org/llama.vscode` supports FIM, chat, embeddings and agent tools. Install
only an exact reviewed VSIX and record its version/hash. At the 2026-08-23
review, Open VSX's latest package was `0.0.63`; its 830,841-byte package,
registry-published SHA-256 and the independently retained review pin resolved
to `7fe75977590fe7f21ba72567bf1a99129b9fe5413f740eec4c50165afce89e65`:

```bash
(
set -euo pipefail
llama_vscode_version=0.0.63
llama_vscode_expected=7fe75977590fe7f21ba72567bf1a99129b9fe5413f740eec4c50165afce89e65
llama_vscode_stage=$(mktemp -d /var/tmp/noid-llama-vscode.XXXXXXXX)
cleanup_llama_vscode_stage() {
  case "$llama_vscode_stage" in
    /var/tmp/noid-llama-vscode.*) ;;
    *) printf 'refusing unexpected llama-vscode stage: %s\n' "$llama_vscode_stage" >&2; return 1 ;;
  esac
  if [ -e "$llama_vscode_stage" ] || [ -L "$llama_vscode_stage" ]; then
    [ -d "$llama_vscode_stage" ] && [ ! -L "$llama_vscode_stage" ] || {
      printf 'refusing non-directory llama-vscode stage: %s\n' "$llama_vscode_stage" >&2
      return 1
    }
    find "$llama_vscode_stage" -depth -delete
  fi
}
trap cleanup_llama_vscode_stage EXIT
trap 'exit 1' HUP INT TERM
chmod 0700 "$llama_vscode_stage"
llama_vscode_base="https://open-vsx.org/api/ggml-org/llama-vscode/$llama_vscode_version/file"
llama_vscode_vsix="$llama_vscode_stage/ggml-org.llama-vscode-$llama_vscode_version.vsix"

curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  "$llama_vscode_base/ggml-org.llama-vscode-$llama_vscode_version.vsix" \
  -o "$llama_vscode_vsix"
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  "$llama_vscode_base/ggml-org.llama-vscode-$llama_vscode_version.sha256" \
  -o "$llama_vscode_stage/registry.sha256"

test "$(tr -d '\r\n' < "$llama_vscode_stage/registry.sha256")" = \
  "$llama_vscode_expected"
test "$(sha256sum "$llama_vscode_vsix" | cut -d' ' -f1)" = \
  "$llama_vscode_expected"
unzip -p "$llama_vscode_vsix" extension/package.json \
  | jq -e --arg version "$llama_vscode_version" \
      '.publisher == "ggml-org" and .name == "llama-vscode"
       and .version == $version and .engines.vscode == "^1.109.0"'

codium --install-extension "$llama_vscode_vsix"
codium --list-extensions --show-versions | grep '^ggml-org\.llama-vscode@'
cleanup_llama_vscode_stage
trap - EXIT HUP INT TERM
)
```

That registry checksum is transport/registry evidence, not an independent
publisher audit. A different version or byte digest requires a fresh source,
manifest, network-default and behavior review rather than merely changing the
two variables.

The exact `0.0.63` source/package audited for this guide requires VS Code API
`^1.109.0`; the reviewed host's VSCodium 1.126 build satisfied that manifest
contract. It contains behavior not
reflected by its older Linux README:

- its Linux **Install/Upgrade llama.cpp** action offers
  `curl -LsSf https://llama.app/install.sh | sh` or Homebrew;
- runtime detection executes `llama serve --version`, while Fedora 44's
  `llama-cpp` package provides `llama-server` but no `llama` command;
- predefined environments can download models, start `llama serve` commands or
  select remote OpenRouter endpoints; and
- RAG is enabled by default and indexes up to 10,000 workspace files, while
  persistent agent auto-memory is also enabled by default.

Do not use its installer/updater or predefined environments on NoID Privacy. Manage the
runtime/model outside VSCodium and configure only explicit base URLs. The
extension appends `/infill`, `/v1/chat/completions`, `/v1/embeddings` and
`/health` itself, so do not append those paths in settings. In this repository,
point `agent_rules` at the reviewed `AGENTS.md`; use the corresponding reviewed
instruction file in another workspace. The full owner profile keeps all normal
agent tools and persistent project memory enabled, but leaves the defective
0.0.63 RAG indexer off. It also points the script loader at Fedora's
root-owned empty directory: with the upstream empty default it scans the editor
process's current directory for `.lvs` files, and a selected DSL script can run
`runTerminalCommand` without the normal agent-tool confirmation path.

```json
{
  "llama-vscode.ask_install_llamacpp": false,
  "llama-vscode.env_start_last_used": false,
  "llama-vscode.launch_completion": "",
  "llama-vscode.launch_chat": "",
  "llama-vscode.launch_tools": "",
  "llama-vscode.launch_embeddings": "",
  "llama-vscode.endpoint": "",
  "llama-vscode.endpoint_chat": "http://127.0.0.1:8011",
  "llama-vscode.endpoint_tools": "http://127.0.0.1:8011",
  "llama-vscode.endpoint_embeddings": "",
  "llama-vscode.ai_model": "",
  "llama-vscode.agent_rules": "AGENTS.md",
  "llama-vscode.scripts_folder": "/var/empty",
  "llama-vscode.only_one_local_model": false,
  "llama-vscode.auto": false,
  "llama-vscode.debounce_ms": 200,
  "llama-vscode.lm_max_input_tokens": 0,
  "llama-vscode.lm_max_output_tokens": 0,
  "llama-vscode.rag_enabled": false,
  "llama-vscode.rag_ignore_file": ".ragignore",
  "llama-vscode.auto_memory_enabled": true,
  "llama-vscode.tools_max_iterations": 100,
  "llama-vscode.tool_run_terminal_command_enabled": true,
  "llama-vscode.tool_read_file_enabled": true,
  "llama-vscode.tool_list_directory_enabled": true,
  "llama-vscode.tool_regex_search_enabled": true,
  "llama-vscode.tool_search_source_enabled": true,
  "llama-vscode.tool_edit_file_enabled": true,
  "llama-vscode.tool_multi_edit_file_enabled": true,
  "llama-vscode.reminder_edit_file_frequency": 5,
  "llama-vscode.tool_delete_file_enabled": true,
  "llama-vscode.tool_get_diff_enabled": true,
  "llama-vscode.tool_get_errors_enabled": true,
  "llama-vscode.tool_update_todo_list_enabled": true,
  "llama-vscode.tool_delegate_task_enabled": true,
  "llama-vscode.telegram_bot_enabled": false,
  "llama-vscode.tool_custom_tool_enabled": false,
  "llama-vscode.tool_custom_eval_tool_enabled": false,
  "llama-vscode.tool_permit_some_terminal_commands": true,
  "llama-vscode.tool_permit_file_changes": true,
  "llama-vscode.tool_permit_file_delete": true
}
```

An empty `ai_model` is intentional for a single local llama.cpp server; the
audited package otherwise defaults it to a remote-looking Gemini model name.
If a local router requires a model identifier, set the exact local alias
instead. If API keys are enabled, configure the extension's separate
`api_key`, `api_key_chat`, `api_key_tools` and `api_key_embeddings` settings;
store them only in VSCodium user settings, and do not commit those values.
Leaving both LM token-limit overrides at zero makes audited 0.0.63 query the
local llama.cpp runtime instead of advertising an invented context size.

The completion endpoint and automatic completion are intentionally empty/off
in this chat/tool profile. The two tested reference models below are instruct
models; FIM control tokens alone are not evidence of FIM quality. When a
separately reviewed FIM model is running on port 8012, set `endpoint` to that
loopback base URL, turn `auto` on, and test completion latency. For chat/tools,
start a tool-capable instruct model on 8011 with the correct model chat
template and current `--jinja` support. Test the configured routes before
opening VSCodium:

```bash
curl --fail --silent http://127.0.0.1:8011/health
curl --fail --silent http://127.0.0.1:8011/props \
  | jq '{chat_template,chat_template_caps}'
curl --silent --output /dev/null --write-out '%{http_code}\n' \
  http://127.0.0.1:8011/tools
# The result above must be 401 when the server uses --api-key-file.

# Only after enabling the optional FIM endpoint:
curl --fail --silent http://127.0.0.1:8012/health
```

FIM context is line-based in this extension (`n_prefix`, `n_suffix`,
`ring_n_chunks`, `ring_chunk_size`) while the server limit is token-based.
“More context” can overflow the server or slow every keystroke. Begin with the
package defaults only after confirming they fit the server context; on a
4096-token endpoint, reduce ring chunks and benchmark completion latency. A
200-ms debounce avoids a request for every keystroke on modest hardware.

For agent/chat, 4096 tokens are usually too small once tool schemas, repository
rules, conversation and an output reserve share the same slot. Audited 0.0.63
queries llama.cpp's token limits, counts the outgoing tools prompt exactly,
reserves 256 safety tokens, and bounds output to at most one quarter of the
context. The 32K reference configuration below passed that path; choose a
smaller context only after the intended repository prompt and tool set fit.

Reasoning mode is a model/quality choice, not an agent-authority restriction.
Current `llama-server` accepts `--reasoning on|off`; both tested models can
spend the entire small output budget in reasoning before producing visible
content. Use `--reasoning off` for responsive routine work or a client that
must always receive visible content. Keep reasoning on for tasks where the
measured quality gain justifies its latency and token budget. Do not use the
deprecated `--chat-template-kwargs '{"enable_thinking":false}'` form in current
`b10605`.

Do not enable RAG in audited llama-vscode 0.0.63. Its full-workspace indexing
pass applies `.gitignore` and `.ragignore`, but its save listener calls the
incremental indexer without either ignore check or a workspace-boundary check.
A subsequently saved excluded file—or even a text document opened from outside
the workspace—can therefore enter the index. File search/read tools remain
available to the agent, so this does not make the owner profile read-only.

After a later exact VSIX fixes that behavior and a save-path regression test
passes, create a reviewed `.ragignore` in every workspace before enabling RAG.
The index is still a local copy of selected workspace content. Keep secrets,
generated trees, model files and unrelated data out:

```gitignore
.git/
.env
.env.*
*.key
*.pem
*.p12
*.kdbx
node_modules/
target/
dist/
build/
models/
```

When the corrected RAG is deliberately enabled, it falls back to BM25 for chunk
selection without an embeddings endpoint and calls `/v1/embeddings` when one
is configured. Persistent `auto_memory_enabled` is separate: it creates
Markdown memory under VSCodium's per-workspace extension storage and may feed
it into later agent sessions. That improves continuity, but it is retained
workspace context: inspect and delete it when the project or trust boundary
changes. Set memory to false for a workspace that must not retain content.

The extension exposes read/search/edit/delete and terminal tools. For the
owner-authorized agent profile, `tool_permit_file_changes=true` removes file
edit confirmation, `tool_permit_file_delete=true` separately removes deletion
confirmation inside the extension's hard workspace-root boundary, and
`tool_permit_some_terminal_commands=true` auto-allows commands its heuristic
classifies as non-modifying. In audited 0.0.63, commands classified as
modifying still prompt even with that setting; stock llama-vscode therefore
cannot honestly promise the same confirmation-free autonomy as NoID Privacy's Codex or
Claude workflow. Tool availability also does not prove that a small local model
will call tools reliably—test correct selection, arguments, error recovery and
repository scope with disposable fixtures first.

Version 0.0.63 also registers an external `vscode://ggml-org.llama-vscode/...`
URI handler. A supplied project path is resolved and checked, then VSCodium
asks before opening it; an agent prompt from the URI is placed in the agent UI
but is not automatically submitted. Treat those links as untrusted input and
inspect the displayed project and prompt before accepting either action.

Keeping Telegram, remote model environments, web-reading custom tools and
user-defined JavaScript/eval tools disabled does not restrict normal local
repository work: the owner profile still has search, read, edit, delete,
diagnostics, task delegation and terminal access. Add MCP servers or other
tools when they provide a needed capability and have been individually
reviewed; a locally named environment is not a local-only guarantee. Reinspect
the exact VSIX after every explicit extension update; a past source scan is not
a permanent no-telemetry guarantee.

### Cline or other agent extensions

Agent extensions can add vendor analytics, cloud defaults, web fetches, MCP
connections and command/file tools. Do not infer privacy from the VSCodium core
switch. For a strict local deployment, review the exact extension version,
disable its vendor features, configure only loopback providers and enforce the
network/filesystem boundary outside the extension.

## Agent authority — full owner mode and optional isolation

Chat-only inference and an agent allowed to execute shell commands are different
authority modes. NoID Privacy's owner-authorized AI workflow deliberately chooses the
second one. Do not add an artificial read-only workspace, terminal denylist or
per-edit confirmation to that profile.

For VSCodium, llama-vscode executes its own tools in the editor process;
llama-server's separate built-in tools are unnecessary for that path. The
settings above grant the extension its complete useful local tool set and
unconfirmed file changes. Its unavoidable prompt for commands classified as
modifying is a limitation of audited version 0.0.63, not a NoID Privacy policy.

For a browser agent, current upstream llama-server provides `read_file`,
`file_glob_search`, `grep_search`, `exec_shell_command`, `write_file`,
`edit_file` and `get_datetime`. Its file tools accept arbitrary paths, its
shell uses `sh -c` and inherits the server environment, and its working
directory is not a filesystem boundary. Starting it as the desktop owner
therefore intentionally grants that account's normal filesystem and command
authority:

```bash
agent_workspace="$HOME/path/to/repository"
agent_model="$HOME/models/reviewed-tool-model.gguf"
agent_config="$HOME/.config/noid-local-ai"
agent_ctx=16384

test -d "$agent_workspace" && test -f "$agent_model"
install -d -m 0700 "$agent_config"
if [ ! -e "$agent_config/api-key" ]; then
  umask 077
  openssl rand -hex 32 > "$agent_config/api-key"
fi

cd "$agent_workspace"
llama-server -m "$agent_model" \
  --host 127.0.0.1 --port 8080 \
  --ctx-size "$agent_ctx" --parallel 1 --jinja \
  --api-key-file "$agent_config/api-key" \
  --cors-origins localhost \
  --tools all --ui --no-ui-mcp-proxy
```

The generic `agent_ctx` is a starting point, not a hardware promise. Increase
it only after the exact model/backend passes load, real prompt, long-chat and
VRAM/RAM checks; the two reference models below passed 32768. Add the exact
measured device, MoE, layer, load and reasoning flags for that model rather
than relying on runtime defaults.

Open `http://127.0.0.1:8080/`, enter the API key when requested, then open
**Settings → Chat → Tools**. For the owner profile, enable every required tool
and select **Always allow** for each. The audited WebUI stores those decisions
in that browser origin's local storage and thereafter bypasses individual tool
prompts. Do not use `--agent` merely as a shortcut: it also enables the
experimental MCP CORS proxy, while `--tools all` supplies the local built-ins
without that extra network bridge. The built-in shell currently caps one call
at 60 seconds and 16 KiB of output; long jobs must be started and observed in
separate calls, or handled through VSCodium, Codex or Claude.

`--api-key-file` protects inference and `/tools` from other local clients that
do not have the key. It does not reduce the authority of a client that does
have it, and it is not a filesystem sandbox. The full owner profile is suitable
only for a model and task the owner chose to delegate. It does not become root
unless the account separately grants or authenticates privileged access.

### Optional lower-trust profile

Use isolation only when the user deliberately wants to evaluate a foreign or
less trusted model with reduced authority. It is not the default owner
workflow. Example starting point (paths and device access must be adapted and
verified):

```ini
[Service]
Type=exec
DynamicUser=yes
UMask=0077
WorkingDirectory=/var/lib/noid-agent-scratch
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
StateDirectory=noid-agent-scratch
ReadOnlyPaths=/var/lib/noid-models
LoadCredential=api-key:/etc/noid-local-ai/api-key
ExecStart=/usr/bin/llama-server -m /var/lib/noid-models/model.gguf --host 127.0.0.1 --port 8080 --ctx-size 4096 --parallel 1 --api-key-file ${CREDENTIALS_DIRECTORY}/api-key
```

That inference-only unit has no repository write path. For browser tools, add
only the intended `--tools` names and expose one exact workspace through a
dedicated service identity. A read-only review may use
`BindReadOnlyPaths=/real/repository:/workspace`; an owner-authorized editing
profile requires a correspondingly narrow writable `BindPaths=` and a user that
has DAC permission. Never bind all of `/home`, the host root or credential
directories merely to make a tool call succeed.

GPU access conflicts with `PrivateDevices=yes`; add only the exact devices,
supplementary groups and SELinux policy required by the chosen backend. Do not
weaken the whole service until `systemd-analyze security "$unit"` and runtime
namespace, filesystem, tool and socket tests show which specific control fails.

```bash
unit=${NOID_LOCAL_AI_UNIT:?export NOID_LOCAL_AI_UNIT with the exact service unit}
systemd-analyze security "$unit"
systemctl show "$unit" -p MainPID -p IPAddressDeny -p IPAddressAllow
ss -ltnp
```

The model process and the editor/agent are separate subjects. Isolating the
server does not constrain an editor extension that itself executes commands.
Conversely, VSCodium workspace trust or a confirmation dialog is not a kernel
boundary for a separately tool-enabled WebUI server.

## Model selection

This repository intentionally does not maintain a “best models in 2026” table.
Model names, tags, licenses, context behavior and memory formats change faster
than an OS release. Select from current official model cards and record:

- immutable revision/hash and download source;
- license and permitted use;
- architecture/format supported by the selected engine;
- actual file size plus measured RAM/VRAM at the intended context;
- FIM/tool/function-calling compatibility required by the client; and
- prompt-template provenance.

Quantization trades memory, speed and quality in model- and task-dependent
ways; there is no defensible universal percentage loss for `Q4_K_M` or claim
that `Q8_0` is lossless. Benchmark the real task and retain the command/results.

### Current publisher candidates — reviewed metadata, not benchmarked

Ornith 1.5 is now available from the publisher. At the 2026-08-23 review, the
following Q4_K_M objects were resolved through immutable Hugging Face revisions;
the sizes and SHA-256 values came from those revisions' LFS metadata:

| Model file | Publisher revision and license | Verified size | SHA-256 |
|---|---|---:|---|
| `Ornith-1.5-9B-Q4_K_M.gguf` | ornith-ai revision `85bf2b98cdcbad4291cb4f46943526cc089f75a0`, MIT | 5,629,108,992 bytes | `7d791afcb31812acc88cd5aafc675391df28c6fc3d8eae002bb4e6cc3d8cfd8d` |
| `Ornith-1.5-35B-Q4_K_M.gguf` | ornith-ai revision `fbbaed45c2f0e200276ffa51701a24d45dc7f57e`, MIT | 21,713,462,848 bytes | `ca6ea26329c88b78ffd90a85163be2e746c2fafd1024f56db47e499f117f9a7f` |

The publisher describes the 9B model as dense and the 35B variant as a
35B-total/approximately-3B-active MoE model, both with 262144-token context,
reasoning and tool use. Those are publisher claims, not reproduced NoID Privacy
results. Neither file was downloaded or benchmarked on the reference host, so
these pins do not replace the Ornith 1.0 record below or establish RAM, VRAM,
throughput, template compatibility or agent reliability.

Meta's current official downloadable family also includes Llama 4 Scout and
Maverick. No exact official artifact from that family was reproduced for this
32-GiB-RAM/4-GiB-VRAM profile, and this guide does not turn a mutable community
quantization into a reference pin. Evaluate an exact official model card,
license, immutable source and measured footprint before adding one.

### Reproduced reference-host validation — 2026-07-28

This is a compatibility/performance record, not a shipped model set or an
automatic download policy. The reference host was Fedora 44 with an Intel Core
Ultra 7 155H, 32 GiB RAM, NVIDIA RTX 500 Ada Laptop GPU (4094 MiB), driver
610.43.03 and the then-reviewed llama.cpp `b10173` Vulkan archive.

Two user-provided files were resolved to immutable publisher revisions. The
local size and full SHA-256 matched the remote linked object in each case:

| Model file | Publisher revision and license | Verified size | SHA-256 |
|---|---|---:|---|
| `Gemma4-26B-A4B-Uncensored-HauhauCS-Balanced-Q4_K_P.gguf` | HauhauCS revision `96c11c22b1128c3c8c655b21557b409f307c557f`, Apache-2.0 | 16,916,915,296 bytes | `295121f61edeedaa8604bcaf3171831981c546c3a10a210cea87dc992eb429ae` |
| `ornith-1.0-35b-Q4_K_M.gguf` | deepreinforce-ai revision `383064f72a1ef3087b779f268d3ca117eb989aac`, MIT | 21,166,757,760 bytes | `ff25291b2599fb927a835e624d2b3540106af61761c3fa57ac4264046dbec002` |

The embedded GGUF metadata also matched the claimed architectures. Gemma4 is
25.23B total/approximately 3.8B active, 30 MoE layers, 128 experts and top-8
routing. Ornith is 34.66B total/approximately 3B active, 40 MoE layers, 256
experts and top-8 routing. Both advertise 262144 native context and an embedded
tool-capable chat template. The Gemma publisher describes creative
writing/roleplay as its main use and says a Qwen-family model was better in its
own agentic testing; Ornith is the more appropriate of these two for the
coding-agent role. Publisher benchmark claims were not reproduced here.

Use exact hashes before launching. The following b10173 profile reproduced a
single 32768-token slot on the reference host. `Vulkan1` is not portable—select
the intended device from this exact runtime's `--list-devices` output:

```bash
(
set -euo pipefail
model_id=ornith
model_dir="$HOME/models"

case "$model_id" in
  gemma4)
    model="$model_dir/Gemma4-26B-A4B-Uncensored-HauhauCS-Balanced-Q4_K_P.gguf"
    expected=295121f61edeedaa8604bcaf3171831981c546c3a10a210cea87dc992eb429ae
    cpu_moe_layers=30
    gpu_layers=27
    ;;
  ornith)
    model="$model_dir/ornith-1.0-35b-Q4_K_M.gguf"
    expected=ff25291b2599fb927a835e624d2b3540106af61761c3fa57ac4264046dbec002
    cpu_moe_layers=40
    gpu_layers=41
    ;;
  *)
    printf 'unsupported reference model: %s\n' "$model_id" >&2
    exit 2
    ;;
esac

test -f "$model" && test ! -L "$model"
test "$(sha256sum "$model" | cut -d' ' -f1)" = "$expected"

llama_cpp_root="$HOME/.local/lib/llama.cpp/b10173-vulkan"
agent_config="$HOME/.config/noid-local-ai"
test -x "$llama_cpp_root/llama-server"
test -r "$agent_config/api-key"

"$llama_cpp_root/llama-server" -m "$model" \
  --host 127.0.0.1 --port 8011 \
  --ctx-size 32768 --parallel 1 --jinja \
  --reasoning off \
  --threads 8 --threads-batch 12 \
  --device Vulkan1 \
  --n-gpu-layers "$gpu_layers" --n-cpu-moe "$cpu_moe_layers" \
  --fit off --load-mode mmap \
  --api-key-file "$agent_config/api-key" \
  --cors-origins localhost \
  --tools all --ui --no-ui-mcp-proxy
)
```

`--reasoning off` was the responsive reference mode, not a restriction on file,
terminal or browser tools. Ornith also ran with reasoning enabled, but a
128-token trivial request exhausted its entire budget in reasoning and returned
no visible answer. For reasoning-on work, increase the measured output budget
and accept the latency explicitly.

At idle after initialization, the Gemma profile used 2937 MiB process VRAM and
left 803 MiB GPU memory free; Ornith used 2485 MiB and left 1255 MiB free.
Both successfully served one 32K slot: Gemma returned an exact non-reasoning
chat answer, while Ornith returned the exact requested tool call after parsing
all seven built-in schemas. Across the disposable-agent tests, Ornith selected
the exact requested `read_file`, `write_file` and `exec_shell_command`
functions, preserved their arguments, and completed read/write/shell cycles in
a disposable Git repository. Unauthenticated `/tools` returned HTTP 401,
authenticated tool calls worked, and the WebUI returned HTTP 200 to a
gzip-capable browser client.

Fixed `llama-bench` probes (`pp512`/`tg64`, three repetitions) produced:

| Model | CPU, 8 threads | Vulkan/CPU-MoE probe |
|---|---:|---:|
| Gemma4 Q4_K_P | 28.27 prompt / 9.76 generated tok/s | 181.68 prompt / 10.47 generated tok/s |
| Ornith Q4_K_M | 33.53 prompt / 10.13 generated tok/s | 145.94 prompt / 10.68 generated tok/s |

These are synthetic warm probes, not interactive-agent speed. Real API samples
with short answers or full tool schemas ranged roughly 3.5–7.1 generated
tokens/s. The requested 20 generated tokens/s was therefore **not** achieved
with these exact Q4 files on this 4-GiB GPU, and the guide does not promise it.
GPU offload greatly accelerated large-prompt ingestion but only modestly
improved token generation because the MoE experts remained in RAM.

Although b10173 warned that tensor overrides plus `mmap` might be slower, the
measured `--load-mode none` Ornith comparison took about 44 seconds to load
instead of 8–11 seconds, prompt processing fell below 1 token/s, and the run
was stopped after more than two minutes. `mmap` is therefore the verified
choice on this reference Btrfs/zram host. Re-measure after any engine, model,
driver, power-profile or hardware change instead of generalizing that result.

## Updates and removal

| Component | Update boundary |
|---|---|
| RamaLama/Podman/llama.cpp | Fedora DNF, preferably through the user-run update orchestrator |
| Ollama | Fedora only after security review, otherwise an exact verified upstream release; re-check advisories and checksums |
| LM Studio | vendor download/update channel |
| VSCodium extensions | explicit Open VSX/current-source review; automatic extension updates are disabled by the image |
| Models | registry/model publisher; tags may move, so retain revision/hash |

After any update, re-check listeners, extension settings, container command,
model hash and tool permissions. Uninstalling a runtime does not automatically
delete models, editor indexes, chat history or service drop-ins.

## Verification checklist

```bash
# Only expected loopback listeners:
ss -ltnp

# No unexpected long-running inference service:
systemctl --type=service --state=running | grep -Ei 'ollama|ramalama|llama' || true
systemctl --user --type=service --state=running | grep -Ei 'ollama|ramalama|llama' || true

# Container network/mount/device review when RamaLama is used:
podman ps --no-trunc
container_name=${RAMALAMA_CONTAINER:?export RAMALAMA_CONTAINER with the exact container name}
podman inspect "$container_name"

# Owner WebUI: unauthenticated tool access must fail; authenticate in the UI,
# then confirm every intended tool is both Enabled and Always allow.
curl --silent --output /dev/null --write-out '%{http_code}\n' \
  http://127.0.0.1:8080/tools

# GPU/RAM placement and the actual backend during a measured run:
nvidia-smi
free -h
```

Test agent authority with a disposable, non-secret fixture inside the intended
workspace: have the agent read it, edit it, create and remove a sibling, run a
repository test and inspect `git diff`. In owner mode those operations must
work with the desktop account's normal permissions; in the llama.cpp WebUI,
tools marked **Always allow** must not produce another permission dialog. Also
test a failed command, a path containing spaces and a job longer than one shell
call so the model's recovery behavior and the 60-second server limit are
visible. Inspect the final diff and remove the fixture afterward.

For a strong offline test, use an isolated network namespace or external packet
capture while exercising chat, completion, agent tools, model load and editor
startup. A successful `curl 127.0.0.1` test proves only that one loopback path,
not that the complete editor/runtime stack made no other request.

## Primary references

- RamaLama: <https://github.com/containers/ramalama>
- Fedora RamaLama package: <https://packages.fedoraproject.org/pkgs/ramalama/ramalama/>
- Fedora llama.cpp package: <https://packages.fedoraproject.org/pkgs/llama-cpp/llama-cpp/>
- Fedora Ollama package: <https://packages.fedoraproject.org/pkgs/ollama/ollama/>
- llama.cpp releases: <https://github.com/ggml-org/llama.cpp/releases>
- llama.cpp server: <https://github.com/ggml-org/llama.cpp/tree/master/tools/server>
- llama-vscode: <https://github.com/ggml-org/llama.vscode>
- llama-vscode on Open VSX: <https://open-vsx.org/extension/ggml-org/llama-vscode>
- Gemma4 HauhauCS reference GGUF:
  <https://huggingface.co/HauhauCS/Gemma4-26B-A4B-Uncensored-HauhauCS-Balanced>
- Ornith reference GGUF:
  <https://huggingface.co/deepreinforce-ai/Ornith-1.0-35B-GGUF>
- Ornith 1.5 publisher GGUFs:
  <https://huggingface.co/ornith-ai/Ornith-1.5-9B-GGUF>
  and <https://huggingface.co/ornith-ai/Ornith-1.5-35B-A3B-GGUF>
- Meta Llama 4 official model family: <https://www.llama.com/models/llama-4/>
- Ollama releases and checksums: <https://github.com/ollama/ollama/releases>
- Ollama API: <https://github.com/ollama/ollama/blob/main/docs/api.md>
- Ollama local authentication: <https://docs.ollama.com/api/authentication>
- Ollama local-only mode: <https://docs.ollama.com/faq>
- Ollama hardware/Vulkan: <https://docs.ollama.com/gpu>
- CVE-2025-63389: <https://nvd.nist.gov/vuln/detail/CVE-2025-63389>
- CVE-2026-7482: <https://nvd.nist.gov/vuln/detail/CVE-2026-7482>
- CVE-2026-5757 / CERT VU#518910:
  <https://www.kb.cert.org/vuls/id/518910>
- ZDI-26-403 / CVE-2026-15685:
  <https://www.zerodayinitiative.com/advisories/ZDI-26-403/>
- Ollama empty-digest guard:
  <https://github.com/ollama/ollama/commit/9239a254e054d24b0de3358ba8c4bd9b50730bfd>
- CVE-2026-65315 report and upstream repair:
  <https://github.com/ollama/ollama/issues/17042>
  and <https://github.com/ollama/ollama/commit/67b6a1c2d45321e0cb3c04a18073f9818de7724b>
- Ollama tensor-redirect SSRF report:
  <https://github.com/ollama/ollama/issues/17041>
- LM Studio offline/network boundary: <https://lmstudio.ai/docs/app/offline>
- LM Studio API: <https://lmstudio.ai/docs/developer/rest>
- LM Studio app privacy: <https://lmstudio.ai/app-privacy>

Treat these as live upstream references: review their current content and the
installed versions at the time of deployment.
AI_DOC_EOF

chmod 0644 "$DOC_TMP"
chown root:root "$DOC_TMP"
sync -- "$DOC_TMP" \
    || die "cannot sync staged 28-local-ai.md"
mv -fT "$DOC_TMP" "$AI_DOC"
DOC_TMP=""
restorecon -F -- "$AI_DOC" \
    || die "cannot label published 28-local-ai.md"
matchpathcon -V "$AI_DOC" >/dev/null \
    || die "published 28-local-ai.md SELinux context differs"
sync -- "$AI_DOC" \
    || die "cannot sync published 28-local-ai.md"
sync -- "$DOC_DIR" \
    || die "cannot sync 28-local-ai.md directory entry"
log "  [OK] 28-local-ai.md written"

# ------------------------------------------------------------------------------
# Phase 3 — Verification
# ------------------------------------------------------------------------------
PHASE="P3-verify"
log "Running verification"

checks=0
fails=0

check() {
    description=$1
    shift
    checks=$((checks + 1))
    if "$@" >/dev/null 2>&1; then
        log "  [OK] $description"
    else
        fails=$((fails + 1))
        log "  [FAIL] $description"
    fi
}

# File type and metadata: a symlink or extra hard link is not an installed doc.
check "28-local-ai.md is a regular non-symlink" test -f "$AI_DOC"
check "28-local-ai.md is not a symlink" test ! -L "$AI_DOC"
ai_doc_meta=$(stat -c '%u:%g:%a:%h' "$AI_DOC" 2>/dev/null || true)
check "28-local-ai.md metadata root:root 0644, one link" \
    test "$ai_doc_meta" = "0:0:644:1"

# Content sanity — must cover all 3 GPU vendors + CPU + the inference options.
# Keyword checks: grep -F DIRECTLY on the file. The earlier $()-into-
# echo|grep pipeline produced reproducible false-negatives on multi-word
# keywords ("Intel Arc", "LM Studio") in the Anaconda chroot bash —
# direct grep -F is robust against locale/IFS/echo-builtin quirks there.
for keyword in "NVIDIA" "AMD" "Intel Arc" "CPU-only" "Ollama" "LM Studio" "llama-vscode" "Vulkan" "RamaLama" "OLLAMA_NO_CLOUD=1" "OLLAMA_VULKAN=1" "CVE-2026-7482" "n-cpu-moe" "--tools all" "Always allow" "NoNewPrivileges"; do
    if grep -qF -- "$keyword" "$AI_DOC"; then
        checks=$((checks + 1))
        log "  [OK] doc covers: $keyword"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] doc missing keyword: $keyword"
    fi
done

# Structural sanity: RamaLama must be Option A and precede Option B (Ollama)
# — locked doc ordering (see header).
option_a_line=""
option_b_line=""
if ! option_a_line=$(grep -m1 -n '^## Option A' \
        "$AI_DOC" | cut -d: -f1); then
    option_a_line=""
fi
if ! option_b_line=$(grep -m1 -n '^## Option B' \
        "$AI_DOC" | cut -d: -f1); then
    option_b_line=""
fi

checks=$((checks + 1))
if [ -n "$option_a_line" ] && [ -n "$option_b_line" ] && [ "$option_a_line" -lt "$option_b_line" ]; then
    if grep -E '^## Option A.*RamaLama' "$AI_DOC" >/dev/null 2>&1; then
        log "  [OK] v2 structure: RamaLama is Option A (primary)"
    else
        fails=$((fails + 1))
        log "  [FAIL] v2 structure: Option A header does not mention RamaLama"
    fi
else
    fails=$((fails + 1))
    log "  [FAIL] v2 structure: could not locate Option A/B headers in doc"
fi

checks=$((checks + 1))
if grep -E '^## Option B.*Ollama' "$AI_DOC" >/dev/null 2>&1; then
    log "  [OK] v2 structure: Ollama is Option B (secondary)"
else
    fails=$((fails + 1))
    log "  [FAIL] v2 structure: Option B header does not mention Ollama"
fi

# Content size (should be substantial — full guide)
ai_size=$(stat -c %s "$AI_DOC" 2>/dev/null || echo 0)
check "28-local-ai.md > 8KB (actual: ${ai_size} bytes)" \
    test "$ai_size" -gt 8192

# Module 28 is DOC-ONLY: none of its documented runtimes may be pulled in.
ai_rpm_count=0
ai_rpm_names=""
for ai_pkg in ramalama llama-cpp ollama lm-studio; do
    if rpm -q --quiet "$ai_pkg"; then
        ai_rpm_count=$((ai_rpm_count + 1))
        ai_rpm_names="${ai_rpm_names}${ai_rpm_names:+,}${ai_pkg}"
    fi
done
check "no documented AI runtime RPM installed (found: ${ai_rpm_names:-none})" \
    test "$ai_rpm_count" -eq 0

log "Verification: $((checks - fails))/$checks passed"
if [ "$fails" -gt 0 ]; then
    die "$fails verification check(s) FAILED"
fi

# ------------------------------------------------------------------------------
# Phase 4 — Health stamp (pattern)
# ------------------------------------------------------------------------------
# Doc-only modules are no exemption; M99 EXPECTED_STAMPS includes 28.
PHASE="P4-stamp"
# M28_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "shared health-stamp directory drifted before Module 28 publication"
fi

verify_m28_health_stamp() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
            0:0:644:1 ] \
        && [ "$(wc -l < "$path")" -eq 10 ] \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_passed=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_total=' "$path" || true)" -eq 1 ] \
        && grep -qFx '# NoID Privacy — Module 28 Health Stamp' "$path" \
        && grep -qFx \
            '# Written at end of %post verification when all checks pass.' \
            "$path" \
        && grep -qFx \
            '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
            "$path" \
        && grep -qFx 'module=28' "$path" \
        && grep -qFx 'name=local-ai-docs' "$path" \
        && grep -qFx 'version=1' "$path" \
        && grep -qFx 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path" \
        && grep -qFx "checks_passed=$((checks - fails))" "$path" \
        && grep -qFx "checks_total=$checks" "$path"
}

STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-28-local-ai-docs.ok.XXXXXXXX")
cat > "$STAMP_TMP" <<STAMP_EOF
# NoID Privacy — Module 28 Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.
module=28
name=local-ai-docs
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=$((checks - fails))
checks_total=$checks
STAMP_EOF

chmod 0644 "$STAMP_TMP"
chown root:root "$STAMP_TMP"
restorecon -F -- "$STAMP_TMP" \
    || die "cannot label Module 28 health-stamp candidate"
matchpathcon -V "$STAMP_TMP" >/dev/null \
    || die "Module 28 health-stamp candidate label differs"
verify_m28_health_stamp "$STAMP_TMP" \
    || die "staged Module 28 health-stamp contract is invalid"
sync -- "$STAMP_TMP" \
    || die "cannot sync Module 28 health-stamp candidate"
if ! mv -fT -- "$STAMP_TMP" "$STAMP"; then
    rm -f -- "$STAMP" || true
    die "cannot publish Module 28 health stamp"
fi
STAMP_TMP=""
STAMP_PUBLICATION_ACTIVE=1
restorecon -F -- "$STAMP" \
    || die "cannot label published Module 28 health stamp"
matchpathcon -V "$STAMP" >/dev/null \
    || die "published Module 28 health-stamp label differs"
sync -- "$STAMP" \
    || die "cannot sync published Module 28 health stamp"
sync -- "$STAMP_DIR" \
    || die "cannot sync Module 28 health-stamp directory"
verify_m28_health_stamp "$STAMP" \
    || die "published Module 28 health-stamp contract is invalid"
STAMP_PUBLICATION_ACTIVE=0
log "  [OK] exact Module 28 health stamp published atomically"
# M28_HEALTH_PUBLICATION_END

trap - EXIT
log "=== Module 28 Local AI Stack Documentation complete ==="
%end

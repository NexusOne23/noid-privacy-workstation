# AI-Agent-Ready Workspace — Threat Model & Opt-Out Paths

NoID Privacy Workstation ships an AI-ready workspace for Claude Code
(Anthropic) and OpenAI Codex plus a hardened VSCodium. Every agent component
is an explicit opt-in: the Claude and Codex CLIs and their verified Open VSX
extensions are each installed only through their own [y/N] prompt in the
Setup helpers; the image itself ships no vendor agent code.
This document covers what that means for the
privacy threat model, where the trust boundaries lie, and how to opt out
of any layer you don't want.

For the alternative — a **fully-local, no-cloud** AI stack
(RamaLama / Ollama / LM Studio / llama.cpp + a local editor extension) — see
[`28-local-ai.md`](28-local-ai.md). Both can coexist.

## What's actually shipped

| Layer | Where | Auto-active? |
|---|---|---|
| **VSCodium** (hardened) | RPM installed by Module 08 `%post` from the fingerprint-pinned VSCodium repository (pre-staged local RPM, signed remote fallback) | Yes — installed, but only runs when you launch it |
| **`claude-code` extension** (SHA-pinned) | Optional second prompt in `noid-claude-install` | Absent by default; once installed it activates at editor startup with documented nonessential telemetry/error reporting disabled while its normal first-use sign-in screen remains available |
| **Claude Code CLI binary** | Bundled INSIDE the `claude-code` extension package | Only invoked when the extension's AI panel runs an action |
| **`/etc/skel/.claude/settings.json`** | Skel-copy to `~/.claude/settings.json` for each new user | Read by Claude Code at runtime IF you invoke it |
| **`/etc/claude-code/CLAUDE.md`** | Root-owned canonical engineering doctrine | Loaded by Claude Code IF you invoke it |
| **Codex adapter** | `~/.codex/AGENTS.md` → canonical doctrine | Seeded for new users; a one-time, non-overwriting user service fills a missing adapter only for eligible persistent human accounts; read only if Codex/ChatGPT-Codex is invoked |
| **Codex CLI/IDE defaults** | `/etc/codex/config.toml` | Official lowest-precedence system layer, read only when Codex runs; shared by CLI and IDE |
| **Codex standalone CLI** | Installed by `noid-codex-install` only after consent | Not present by default; exact native package, no npm/remote installer |
| **Codex VSCodium extension** (SHA-pinned) | Optional second prompt in `noid-codex-install` | Absent by default: Open VSX marks it pre-release and it has vendor telemetry with no supported off switch |
| **Gemini adapters** | `~/.gemini/{AGENTS.md,GEMINI.md}` → canonical doctrine | Seeded for new users and conservatively backfilled once for existing users; pre-existing files or links are never overwritten |
| **Project-agent adapter** | Repo-root `AGENTS.md`, byte-checked against the canonical doctrine | Read at this repo's root by Cursor, Codex and other AGENTS.md-compatible clients; this is project scope, not a fabricated global Cursor file |
| **Claude CLI** (`claude` in `$PATH`) | Installed by `noid-claude-install` only when you run it | Exact native binary; no npm/remote installer |

**Bottom line**: the image ships the hardened workspace and configuration,
but no vendor agent code and no intentional model request. Third-party agent
code arrives only through an accepted installer prompt. An installed
extension activates at editor startup, so the defensible claim is that the
documented nonessential-traffic and error-reporting controls are disabled —
not the unprovable absolute that opaque third-party code can never make any
request. Authentication remains an explicit user action through the normal
first-use sign-in screen.

Model/API traffic and token use begin only after the user authenticates and
invokes the respective agent. For a strict zero-third-party-code editor
posture, simply decline both extension prompts.

## VSCodium folder trust

The image sets `security.workspace.trust.enabled=false`, VSCodium's documented
native global switch for disabling Restricted Mode and treating every opened
folder as trusted without a prompt. This supports unattended CLI/IDE agents
without forging VSCodium's private per-user trust database or planting
repository-specific state.

This is a real security trade-off: opening an untrusted repository immediately
enables its workspace settings, tasks, debug features and installed extensions.
`task.allowAutomaticTasks="off"` still blocks automatic task startup, but it is
not a replacement for Workspace Trust. Users who prefer selective trust can set
`security.workspace.trust.enabled=true` in their VSCodium user settings and use
the native **Manage Workspace Trust** command.

## Privacy and autonomy defaults (what `/etc/skel/.claude/settings.json` ships)

```json
{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "cleanupPeriodDays": 7,
  "skipWebFetchPreflight": true,
  "env": {
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1",
    "CLAUDE_CODE_HIDE_CWD": "1",
    "DISABLE_AUTOUPDATER": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_FEEDBACK_COMMAND": "1",
    "DISABLE_GROWTHBOOK": "1",
    "DISABLE_TELEMETRY": "1",
    "DO_NOT_TRACK": "1"
  },
  "permissions": {
    "defaultMode": "bypassPermissions"
  }
}
```

| Setting | Effect |
|---|---|
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` | Disables documented nonessential traffic as a broad baseline |
| `DISABLE_AUTOUPDATER=1` | Prevents Claude's own background updater; the opted-in CLI moves forward only inside an explicit Update All run, which drives the vendor channel and records version + SHA-256 evidence in the agent-update ledger |
| `DISABLE_ERROR_REPORTING=1` | Disables Sentry operational-error reports |
| `DISABLE_FEEDBACK_COMMAND=1`, `CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY=1` | Disables feedback upload and post-session surveys |
| `DISABLE_GROWTHBOOK=1` | Disables remote feature-flag retrieval and uses built-in defaults; trade-off: any feature upstream is still rolling out behind a flag stays off until it becomes an unconditional client default |
| `CLAUDE_CODE_HIDE_CWD=1` | Hides the current working directory from the CLI banner so it doesn't leak in screenshots / pair-programming sessions |
| `DISABLE_TELEMETRY=1`, `DO_NOT_TRACK=1` | Explicitly disables Claude telemetry in addition to the broader nonessential-traffic switch |
| `skipWebFetchPreflight=true` | Prevents Claude Code sending each WebFetch hostname to Anthropic's safety preflight; trade-off: that vendor blocklist check no longer protects WebFetch |
| `cleanupPeriodDays=7` | Session transcripts auto-purged from disk after 7 days (upstream default is 30) |
| `permissions.defaultMode="bypassPermissions"` | Starts Claude CLI sessions without tool-approval prompts; the VSCodium extension independently selects the same initial mode through `claudeCode.initialPermissionMode` and permits it with `claudeCode.allowDangerouslySkipPermissions=true` |

`DISABLE_GROWTHBOOK=1` is deliberately redundant. Claude Code already gates
remote flag retrieval behind its telemetry switch, which
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, `DISABLE_TELEMETRY` and
`DO_NOT_TRACK` each disable on their own, so the fetch is already off without
it. It is kept as an explicit second barrier: the client carries a separate
disk-cache path for flag data that is designed to work while telemetry is off
and that only this variable closes for good, and an upstream change decoupling
flag retrieval from the telemetry switch would otherwise re-enable third-party
retrieval silently on the next update.

The bypass default is deliberate: this workstation is designed for
owner-authorized autonomous agents in both the CLI and VSCodium. Anthropic
documents that bypass mode skips every permission check. A malicious repository,
prompt injection or mistaken instruction can therefore reach every file,
credential, network destination and passwordless-sudo operation available to
the invoking account. Use the mode only on a host and in repositories you are
prepared to give that authority; set `permissions.defaultMode` and
`claudeCode.initialPermissionMode` back to `default` when interactive approval
is the safer boundary. The upstream emergency circuit breakers are
defense-in-depth, not a replacement for permissions.

The schema's `disableAutoMode` and `disableBypassPermissionsMode` switches are
intentionally absent because they would disable modes rather than select one.

This is the **template** copied to every new user account. Users can
freely override in their own `~/.claude/settings.json` — the image
does NOT enforce these as a managed-settings layer.

## Codex system defaults (`/etc/codex/config.toml`)

Codex officially shares configuration layers between its CLI and IDE
extension. NoID Privacy uses the Unix system layer as an overridable baseline:

- `cli_auth_credentials_store="keyring"` avoids the default plaintext
  `~/.codex/auth.json` token store.
- `check_for_update_on_startup=false` prevents implicit update discovery.
  `noid-update-all.sh` refreshes an opted-in NoID Privacy-managed CLI from the
  newest official GitHub release tarball under the same archive validation
  as the pinned install, recording version + SHA-256 evidence.
- `web_search="indexed"` keeps Codex's web-search tool available while using
  its index-gated retrieval mode instead of forcing unrestricted live search.
  Search is model-controlled and has no per-call approval prompt, so the shared
  doctrine limits it to material current/high-stakes/version-specific facts and
  requires minimized, non-identifying queries. `codex --search` deliberately
  selects live retrieval for that session; user/project configuration can also
  override the lower-precedence system value. Power users who want permanent
  unrestricted live retrieval set `web_search = "live"` in
  `~/.codex/config.toml` — the user layer overrides this system default, and
  no `requirements.toml` in the image restricts that choice.
- Product analytics, `/feedback`, and all OTel log/trace/metrics exporters are
  off.
- `shell_environment_policy.inherit="core"` retains Codex's default
  key/secret/token filtering for spawned tools.
- `approval_policy="never"` prevents both CLI and IDE approval prompts, while
  `sandbox_mode="danger-full-access"` gives spawned tools unrestricted host
  filesystem and network access. This is the image's autonomous-agent default,
  not a security boundary.
- A malicious repository, prompt injection or mistaken instruction can
  therefore act with every privilege of the invoking account, including its
  passwordless-sudo authorization. Users who prefer containment can override
  the system layer with `approval_policy="untrusted"` and
  `sandbox_mode="workspace-write"` in `~/.codex/config.toml`; trusted project
  configuration has still higher precedence. No admin `requirements.toml`
  prevents that choice.

The Codex VSCodium package uses an exact Open VSX version/SHA pin at install
time and is not placed in `/etc/skel`. Once opted in, Update All refreshes it
from the newest Open VSX release with recorded evidence. Open VSX currently
labels `openai.chatgpt` pre-release, it activates on editor startup, and its
published `chatgpt.*` settings offer no switch for the wrapper extension's own
startup telemetry/Sentry path. The shared Codex core configuration does turn
off documented Codex analytics, feedback and OTel exporters, but NoID Privacy does not
misrepresent that as proof that every wrapper-extension request is disabled.
The installer therefore asks separately after the CLI install. NoID Privacy's
VSCodium template deliberately leaves startup focus and TODO CodeLens at the
extension's own defaults because those are UI preferences, not telemetry or
security controls.

## System-wide engineering doctrine

`/etc/claude-code/CLAUDE.md` ships system-level engineering directives.
Claude Code reads that managed path directly. Codex reads the per-user global
`~/.codex/AGENTS.md` adapter, and Gemini CLI reads `~/.gemini/GEMINI.md`; both
are absolute symlinks to the same root-owned source, so the content cannot
silently diverge. The repo-root `AGENTS.md` is additionally tested byte-for-byte
for Cursor and other project-compatible clients:

`/etc/skel` handles newly created accounts. For an eligible account that
already exists when the image is deployed, `noid-agent-policy-adapters.service`
runs once in that user's own session. The shared account gate requires a UID
inside `/etc/login.defs`, a usable login shell and the owned canonical
`/home/<name>` directory, so GDM, GNOME Initial Setup and transient/system
identities cannot receive adapter state. The service creates only missing
directories/links, preserves every pre-existing file or symlink, refuses to
traverse an unsafe adapter directory, and records the one-time decision under
`~/.local/state/noid-privacy/agent-policy-adapters.done`. It installs policy
links only—never a Claude, Codex, Gemini or other vendor executable.

- **Native > Hacky** — prefer vendor-documented native mechanisms over
  reverse-engineering, hash spoofing, undocumented API calls
- **Root-Cause First** — identify root cause before fixing, no
  symptom-patching
- **No Hype-Patches** — reject "AI-resistant" / "$YEAR-future-proof"
  framing
- **Priority hierarchy**: Correctness > Security > Privacy > Stability and
  recoverability > UX > Simplicity and auditability > Performance where it
  materially matters
- **Verification doctrine** — verify live state and files locally; use
  tool-agnostic external retrieval only for material current, high-stakes,
  version-specific, source-dependent, or genuinely uncertain facts
- **AIDE evidence boundary** — agents may inspect results but never initialize,
  update, replace, or launch a workflow that changes the user-owned baseline

The doctrine reduces variance in how compatible agents approach tasks on this
system. It shapes model behavior statistically; it is not an enforcement
boundary. After the one-time reconciliation has sealed its state, users can opt
out by replacing/removing their per-user adapter; it is not recreated on later
logins.

Instruction discovery is a **client capability**, not a model capability.
Consequently:

- Codex/ChatGPT-Codex has a documented global `~/.codex/AGENTS.md` scope.
- Gemini CLI has a documented global `~/.gemini/GEMINI.md` scope and supports
  custom context filenames.
- Cursor CLI reads both `AGENTS.md` and `CLAUDE.md` at a project root; this repo
  uses its byte-checked `AGENTS.md` adapter. Truly global User Rules live in
  Cursor settings. No portable `/etc/AGENTS.md` path exists in Cursor's
  documented interface, so NoID Privacy does not claim otherwise. Grok used *inside
  Cursor* receives the rules Cursor injects; a standalone web chat cannot read
  local files automatically.

Primary references: [OpenAI Codex `AGENTS.md`](https://learn.chatgpt.com/docs/agent-configuration/agents-md),
[Codex configuration](https://learn.chatgpt.com/docs/config-file/config-basic),
[Codex IDE extension](https://developers.openai.com/codex/ide/),
[Claude Code managed policy](https://code.claude.com/docs/en/memory),
[Gemini CLI context files](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md#context-files-hierarchical-instructional-context),
[Cursor CLI rules](https://docs.cursor.com/en/cli/using).

## What this DOES NOT protect against (the AI-workspace threat model)

Honest accounting of where the NoID Privacy hardening posture stops and the
Anthropic/OpenAI trust boundaries start:

### Conversation content goes to Anthropic

When you invoke Claude (CLI or VSCodium panel), the prompts + files +
code Claude sees go to **Anthropic's API servers**. This is the
fundamental tradeoff between a vendor cloud model and a local open-weight
model (Qwen, Llama, etc.):
the data plane is **NOT under NoID Privacy's control**:

- Anthropic's privacy policy applies, NOT NoID Privacy's (see
  https://www.anthropic.com/legal/privacy)
- Anthropic's account-specific data-retention policy applies. Commercial
  Claude Code/API use is normally 30 days; consumer use is 30 days when model
  improvement is off and may be retained for five years when it is on.
  ZDR, saved-product data, feedback, policy-enforcement and legal exceptions
  have different periods. Check the live account policy; do not infer cloud
  retention from NoID Privacy's 7-day local transcript setting.
- US-jurisdiction: Anthropic is a US company → US legal subpoena reach
- Closed-source API: you cannot audit what happens to data after it
  reaches Anthropic's servers

`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` disables **telemetry &
analytics**. It does NOT (and cannot) disable the conversation itself
from being sent — that's the entire point of cloud AI.

### Code Claude reads from your filesystem is sent over the wire

When Claude executes a tool call to read a file (e.g. `Read /home/you/secret.txt`),
the returned content becomes model context and goes to the configured model
provider. Permission controls can prevent the read; after approval there is no
NoID Privacy content-redaction layer. **Don't approve secret reads you don't want the
provider to receive.**

Practical mitigation: keep secret material in directories Claude is
not invoked against. The `CLAUDE_CODE_HIDE_CWD=1` hides directory paths
in the BANNER but the LLM still reads files when you tell it to.

### Claude is itself opaque

Even with full hardening, you cannot inspect Claude's reasoning, training
data, or model weights. The "AI doctrine" in `/etc/claude-code/CLAUDE.md`
shapes Claude's responses statistically — it does not guarantee them.
Claude can hallucinate, get facts wrong, or be manipulated by prompt
injection in files you read together. **Verify before acting**, especially
on security-relevant or destructive operations.

### Network-level exposure: traffic IS visible to ISP/VPN provider

Direct Anthropic API calls use TLS. Your
ISP / VPN / firewall sees:

- Source IP (yours, unless you tunnel via VPN)
- Destination IPs for the vendor/CDN/cloud path in use
- Connection timing + traffic volume

If you route via VPN, the destination is hidden from your ISP but the
**VPN provider** sees the destination instead. The content is encrypted,
but traffic-analysis from timing + volume is theoretically possible.

If you want zero-exposure of the fact that you use AI at all, use the
fully-local stack ([`28-local-ai.md`](28-local-ai.md)) instead.

### Codex has the same cloud-data boundary

When invoked, Codex sends prompts, selected files/context, tool results and
responses to OpenAI. The `/etc/codex/config.toml` defaults disable local
product analytics, feedback and OTel export, while making index-gated web
search available under the shared minimized-retrieval doctrine. These controls
do not and cannot disable the model request itself.

Retention and model-training use depend on the account/workspace. For personal
ChatGPT plans, Codex content may be used for model improvement unless the
ChatGPT data control is turned off. OpenAI's current Codex help states that this
ChatGPT training control applies to content processed through Codex, including
Computer Use screenshots. Business, Enterprise and Edu inputs/outputs are not
used for training by default; eligible API organizations may opt in through
their organization controls where offered. Kept Codex chats remain in the
account until deletion; deleted chats are scheduled for deletion within 30 days
subject to de-identification, security and legal exceptions. Verify the live
workspace controls before sending sensitive data.

### Cloud providers can change policy

Privacy posture today ≠ privacy posture tomorrow. Either provider could:

- Change data-retention terms
- Be acquired / restructured
- Be subject to government compulsion (US National Security Letter, etc.)
- Have a breach where API logs leak

You can mitigate by switching to local AI (see below) at any time — your
existing VSCodium + local-editor setup keeps working.

## Opt-out paths (every layer)

Pick the level that matches your threat model:

### Level 1 — Don't authenticate or invoke a cloud agent

Do not log in, run either installer, or start a model action. This avoids
intentional model/API traffic. Because the image stages no vendor extension,
declining both installer prompts already means no third-party agent
extension executes with the editor.

### Level 2 — Remove the per-user CLIs

If you previously used the NoID Privacy installers:

```bash
# Remove only the NoID Privacy-managed native binaries/packages.
rm -f ~/.local/bin/claude ~/.local/bin/codex
rm -rf ~/.local/share/claude/versions
rm -rf ~/.codex/packages/standalone

# Optional local state removal; review before running because this deletes
# sessions and user settings. Run `codex logout` first to clear keyring auth.
rm -rf ~/.claude
```

### Level 3 — Disable/uninstall the VSCodium extensions

```bash
# In VSCodium: Extensions panel → search "Claude Code" → Disable / Uninstall
# Or via CLI:
codium --uninstall-extension anthropic.claude-code
codium --uninstall-extension openai.chatgpt
```

The image stages no extension under `/etc/skel`, so a per-user uninstall is
complete; nothing re-copies for new accounts.

### Level 4 — Remove the system-wide doctrine

```bash
sudo rm -f -- /etc/claude-code/CLAUDE.md
sudo rmdir -- /etc/claude-code
# Claude loses the managed policy; Codex/Gemini adapter links become dangling
```

Or opt out only one user/client without touching the system source:

```bash
rm -f ~/.codex/AGENTS.md
rm -f ~/.gemini/AGENTS.md ~/.gemini/GEMINI.md
```

### Level 5 — Switch to local AI

Set up RamaLama / Ollama / LM Studio / llama.cpp plus llama-vscode or another
individually reviewed local client per [`28-local-ai.md`](28-local-ai.md). It
coexists with Claude Code — same VSCodium, different inference back-ends. You
can switch the model per task.

### Level 6 — Network-enforced cloud-AI opt-out

For defense in depth, use an outbound default-deny policy or a dedicated
network namespace with only an explicit non-AI allowlist. A one-time nftables
rule made from a hostname is not a hard guarantee: vendor/CDN IPs rotate,
IPv4 and IPv6 differ, and authentication/telemetry may use additional hosts.
NoID Privacy's normal WAN-only or VPN-endpoint mode does **not** selectively block
Anthropic/OpenAI while WAN is available. For the strongest practical result,
combine network default-deny with Levels 2 and 3.

## Recommended posture by use-case

| Use-case | Recommended setup |
|---|---|
| **Casual / no-AI** | Do not run either opt-in installer; nothing agent-related is present to remove. |
| **AI for non-sensitive coding only** | Keep image defaults. Don't paste secrets or customer data into a cloud agent. |
| **AI for sensitive work** | Use local AI ([`28-local-ai.md`](28-local-ai.md)) instead. |
| **Mixed** | A local editor agent for everyday work plus a cloud agent only for selected tasks. |
| **Air-gapped / strict local** | Remove both vendor extensions/CLIs, enforce network default-deny and use only local AI. |

## Summary trust boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│  Your local NoID Privacy host                                       │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Hardening surface that NoID Privacy controls:              │    │
│  │  - LUKS2 / SELinux / firewalld / AIDE / sysctl              │    │
│  │  - 134-state module policy with 53 effective denies         │    │
│  │  - VSCodium core telemetry off                              │    │
│  │  - Claude traffic controls + 7-day local transcript cap     │    │
│  │  - Codex analytics/feedback/OTel off by default             │    │
│  │  - System doctrine (Native > Hacky, etc.)                   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│                       │ (TLS over WAN)                              │
└───────────────────────┼─────────────────────────────────────────────┘
                        │
                        ▼  ← NoID Privacy hardening ends here
┌─────────────────────────────────────────────────────────────────────┐
│  Anthropic or OpenAI infrastructure                                 │
│                                                                     │
│  - Prompts, approved file/context and outputs visible to provider   │
│  - Provider/account/workspace privacy + retention terms apply       │
│  - Subject to US legal process                                      │
│  - Closed model/API boundary                                        │
└─────────────────────────────────────────────────────────────────────┘
```

## References

- Anthropic Claude Code data usage and traffic controls:
  https://code.claude.com/docs/en/data-usage
- Anthropic account-specific retention:
  https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-my-organization-s-data
- OpenAI Codex plan/data controls:
  https://help.openai.com/en/articles/11369540-using-codex-with-chatgpt
- OpenAI Codex chat deletion/retention:
  https://help.openai.com/en/articles/20001333-how-to-archive-and-delete-chats-in-codex
- OpenAI Codex configuration reference:
  https://learn.chatgpt.com/docs/config-file/config-reference
- Anthropic Claude Code permission modes:
  https://code.claude.com/docs/en/permission-modes
- Visual Studio Code Workspace Trust:
  https://code.visualstudio.com/docs/editing/workspaces/workspace-trust
- Local-AI alternative (RamaLama / Ollama / LM Studio): [`28-local-ai.md`](28-local-ai.md)
- General threat model: [`threat-model.md`](threat-model.md)
- Out-of-scope items: [`scope.md`](scope.md)

# Overview — what agt-opencode is and why it exists

## Purpose

`agt-opencode` is a **runtime governance plugin for [OpenCode](https://opencode.ai)**.
It exists to stop an AI coding agent from doing dangerous or untrusted things —
*before* they happen — instead of trusting the model to "behave" because the
prompt told it to.

Prompt-based safety ("you must never delete data…") is probabilistic: a
sufficiently clever or injected instruction can talk the model past it.
`agt-opencode` moves the guardrail **out of the prompt and into the runtime**:
every tool call, user prompt, and tool result is checked against an explicit
policy at the moment it is about to take effect. The decision is deterministic,
in-process, and recorded.

It is a personal port of Microsoft's
[Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
(AGT) to OpenCode's plugin model. **It is not an official Microsoft package.**

## What it actually does

| Concern | What the plugin does |
|---|---|
| **Dangerous commands** | Denies `rm -rf` (and PowerShell `Remove-Item -Recurse`, `find -delete`, `xargs rm`), `curl\|sh` bootstraps, cloud-metadata endpoint access, encoded/`iex` PowerShell, `certutil` downloads. |
| **Credential theft** | Denies reads of `.env`, `~/.ssh`, `~/.aws`, `~/.kube`, `.npmrc`, `id_rsa`, `$env:*TOKEN`, etc. — whether via shell command or a direct file-read tool. |
| **Risky tools** | Sends `bash`, `webfetch`, `websearch`, `task` to **review** (see the review→deny note below). |
| **Prompt injection** | Scans every user prompt for injection / context-poisoning patterns; a flagged prompt is rewritten to a neutral refusal. |
| **Tool-output poisoning** | Scans `webfetch` / `websearch` / `bash` output for injected instructions and suppresses or flags it before the model sees it. |
| **MCP tool poisoning** | Scans MCP tool names/arguments for poisoning and typosquatting cues. |
| **Auditability** | Appends every decision to a persistent, SHA-256 hash-chained audit log. |

## How it works (architecture)

OpenCode loads a plugin as an **in-process module** that exports a `Plugin`
function returning a hooks object. `agt-opencode` is that function. It maps
OpenCode's hooks onto the AGT governance engine:

| OpenCode hook | Governance behaviour |
|---|---|
| `tool.execute.before` | **Hard gate.** `deny` throws and aborts the tool call; `review` throws unless an interactive permission prompt handled it; fails **closed** on any internal error. |
| `permission.ask` | Best-effort second layer — reinforces `deny` and routes `review` to an interactive prompt *when* OpenCode supplies tool context. |
| `tool.execute.after` | Scans output; rewrites it to a sanitized warning when suppressed, appends an advisory note otherwise. |
| `chat.message` | Scans the prompt; rewrites a blocked prompt to a refusal; injects the AGT guard context once per session. |

The engine itself (`plugin/src/policy.mjs`, adapted from AGT; `poisoning.mjs`,
verbatim) plus the AGT SDK are bundled by `build.mjs` (esbuild) into a single
file, `assets/agt-governance.js` — the one artifact the installer ships.

```
prompt / tool call ──► AGT policy engine ──► allow / review / deny ──► audit log
                       (deterministic, in-process, fail-closed)
```

## Security model — read this

- **In-process guardrail, not a sandbox.** The engine runs in the same process
  as the agent it governs. It reliably gates well-behaved tool calls, but code
  that escapes the agent process can bypass it. For hard isolation, run OpenCode
  inside a container or VM.
- **`review` currently resolves to `deny`.** OpenCode's `permission.ask` hook
  does not reliably fire ([opencode#7006](https://github.com/anomalyco/opencode/issues/7006)),
  so a `review` decision has no interactive prompt to resolve it and the
  `tool.execute.before` gate fails closed (denies). That is safe but blunt —
  see [CONFIGURATION.md](CONFIGURATION.md) for how the `balanced` default and
  the `advisory` profile work around it.
- **Cross-seat note (if you also run the Claude Code seat).** The two seats
  resolve a `review` decision **differently**: this OpenCode seat **denies**
  headless (above), whereas the Claude Code companion renders `review` as an
  interactive **ask** prompt that you can approve. The same policy is therefore
  *blunter here* — a `review`-tier tool that you could approve-and-run under
  Claude Code is blocked outright under OpenCode. Use `advisory` or widen
  `allowedTools` if that is too strict for your workflow.
- **The audit log is tamper-evident, not tamper-proof.** The hash chain detects
  edits/insertions/reordering and tail-truncation, but it is keyless: anyone who
  can write the log file can recompute a valid chain. Treat it as an integrity
  tripwire; forward to a SIEM/WORM sink for true non-repudiation.

## Where to go next

- [INSTALL.md](INSTALL.md) — install it (build-from-source, installer CLI, npm).
- [USAGE.md](USAGE.md) — day-to-day use, CLI commands, what decisions look like.
- [CONFIGURATION.md](CONFIGURATION.md) — profiles, policy schema, overrides, audit.

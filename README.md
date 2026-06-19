# agt-opencode

Runtime governance for [OpenCode](https://opencode.ai) powered by Microsoft's
[Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) (AGT).

Every tool call, user prompt, and tool result is evaluated against policy
*before* it reaches the model — deterministic, in-process, and recorded to a
tamper-evident audit log.

- **Policy enforcement** — allow / review / deny for every tool call.
- **Prompt-injection scanning** — user prompts are scanned for injection and
  context-poisoning patterns.
- **Tool-output scanning** — `webfetch` / `websearch` / `bash` output is scanned
  and suppressed or flagged if it looks like injected instructions.
- **MCP tool-poisoning detection** — tool names and arguments are scanned.
- **Tamper-evident audit log** — a SHA-256 hash-chained record at
  `~/.config/opencode/agt/audit-log.json` (tamper-evident, not tamper-proof —
  see Known limitations).

This is a personal port of AGT to OpenCode, parallel to `agt-claude-code`. It is
not an official Microsoft package.

## Documentation

Detailed guides live in [`docs/`](docs/):

- [Overview](docs/OVERVIEW.md) — purpose, what it does, how it works, security model.
- [Install](docs/INSTALL.md) — build-from-source, installer CLI, npm package, verify.
- [Usage](docs/USAGE.md) — day-to-day behaviour, the management CLI, the audit log, troubleshooting.
- [Configuration](docs/CONFIGURATION.md) — profiles, policy schema, per-project overrides, env vars.
- [LLM-as-judge](docs/LLM-JUDGE.md) — whether users can add an LLM judge, its advantages vs the deterministic rules, tradeoffs, and how to wire one up.
- [Benchmark](docs/BENCHMARK.md) — adversarial settings-vs-plugin benchmark: what `opencode.json` already prevents and what the plugin adds, with reproducible per-category numbers.

## How it works

`agt-opencode` is a single-file OpenCode plugin. OpenCode loads it in-process
and the adapter maps OpenCode's hooks onto the AGT governance engine:

| OpenCode hook | Governance behavior |
|---|---|
| `tool.execute.before` | Hard gate. `deny` throws and aborts the call; `review` throws unless an interactive prompt handled it; fails closed on any error. |
| `permission.ask` | Best-effort second layer — reinforces `deny` and routes `review` to an interactive prompt when OpenCode supplies tool context. |
| `tool.execute.after` | Scans output; rewrites it to a sanitized warning when suppressed, appends an advisory note otherwise. |
| `chat.message` | Scans the prompt; a blocked prompt is rewritten to a refusal; injects the AGT guard context once per session. |

The text/poisoning helpers (`poisoning.mjs`) are copied verbatim from AGT;
`policy.mjs` is the AGT governance engine *adapted* for OpenCode (notably, its
audit log was rewritten to persist a cross-session hash chain — see `NOTICE`);
`sdk-loader.mjs` and `agt-plugin.ts` are the OpenCode-specific glue. The AGT SDK
and the default policy are bundled into `assets/agt-governance.js` by
`build.mjs` — the single artifact the installer ships.

## Install

```bash
npm install        # installs esbuild + the AGT SDK
npm run build      # produces assets/agt-governance.js
node bin/agt-opencode.mjs install
```

`install` copies the plugin into `~/.config/opencode/plugins/agt-governance.js`
and seeds a default policy at `~/.config/opencode/agt/policy.json`. No edit to
`opencode.json` is needed — OpenCode auto-loads the plugins directory. Restart
OpenCode, then check with `agt-opencode doctor`.

> **Corporate TLS note:** if `npm install` fails with
> `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, your network intercepts TLS. Point npm at
> your corporate CA (`NODE_EXTRA_CA_CERTS`) or, as a last resort, install with
> `npm install --strict-ssl=false`.

## Commands

```
agt-opencode install [--force-policy]      Install the plugin, seed a policy
agt-opencode update  [--force-policy]      Refresh the installed plugin
agt-opencode uninstall [--remove-policy]   Remove the managed plugin
agt-opencode doctor [--json]               Diagnose the install
agt-opencode policy path|show              Inspect the active policy
agt-opencode policy validate|apply --file <path> | --profile <name>
agt-opencode skills audit <dir>...         Scan skill(s): resolve the full
                                           transitive dep tree + CVE scan, then
                                           write a supply-chain attestation
```

Global options: `--opencode-home <dir>` overrides the OpenCode config home.

## Policy & configuration

A policy has two independent parts, and understanding the split is the key to
configuring the plugin:

1. **Tool tiers** (`toolPolicies`) — the **friction dial**. Each tool is
   `allowed` (runs freely), in `reviewTools` (→ `ask`, which OpenCode resolves to
   a **deny** headless — see opencode#7006), or `blockedTools` (always deny).
   `defaultEffect` covers anything unlisted. *Most day-to-day friction comes from
   here* — a broad review tier denies/asks on benign `bash`/`edit`/`webfetch`.
2. **Threat rules** (`blockedToolCalls`, `directResourcePolicies`,
   `poisoningPatterns`) + the **extensions** (below) — the **security**. These
   fire on the specific dangerous pattern (`rm -rf`, credential reads, metadata
   SSRF, `curl|sh`, prompt injection) regardless of the tier, with a near-zero
   false-positive rate. A threat-rule `deny` always wins over an allowed tier.

Because they're separable, you can have strong security **without** the
blocking: widen `allowedTools` (or pick the `secure-low-friction` profile) and
the named threat rules still block the dangerous calls.

### Profiles (`config/profiles/`)

Apply with `agt-opencode policy apply --profile <name>`. Every profile carries
the same threat rules + extensions; they differ only in the tool tiers / mode:

- **strict** — only `read`/`glob`/`grep`/`list` allowed; everything else
  reviewed (→ denied headless). Lock-down; the agent can't write/run until you
  widen `allowedTools`.
- **balanced** *(default)* — also allows `write`/`edit`/`apply_patch`; reviews
  `bash`/`webfetch`/`websearch`/`task`. Safe, but reviews (denies) benign bash.
- **secure-low-friction** — **recommended when you want security without
  blocking work.** Allows the everyday tools (`bash`/`edit`/`write`/`webfetch`/
  `websearch`/…); only subagent spawning (`task`) is reviewed. The named threat
  rules + exfil/DLP/content-safety still enforce, so dangerous calls are still
  blocked — you just lose the blanket "review everything" friction.
- **advisory** — never blocks; surfaces findings only (warnings).

### Tuning it yourself

- **Edit the active policy** at `~/.config/opencode/agt/policy.json` (or apply a
  profile, then tweak). Move a tool name between `allowedTools` and `reviewTools`
  to trade friction for default-deny coverage.
- **Per-project override:** drop `.opencode/agt-policy.json` in a repo. It is
  **untrusted by default** — it may only *tighten* (see the trust gate below).
- **Extension modes:** set each extension's `mode` to `advisory` (warn) or
  `enforce` (block) — see the table below.
- `agt-opencode policy show` prints the active policy; `policy validate` checks a
  file or profile before applying.

### Governance extensions

The policy enables six extra layers (configure each in the policy file;
`mode: "advisory"` warns, `mode: "enforce"` blocks):

| Extension | Default | What it does |
| --- | --- | --- |
| **DLP** (`dlpPolicies`) | advisory | Credential values (AWS/GitHub/private-key) + PII (SSN, credit-card via Luhn, email) in tool output / webfetch URLs; allow-snippets suppress docs placeholders. |
| **Exfiltration** (`exfilPolicies`) | enforce | Session-aware: blocks an outbound request that embeds a credential value seen earlier in tool output. |
| **Rate-limit** (`rateLimitPolicies`) | advisory | Per-session, per-tool call budgets. |
| **Content-safety** (`contentSafetyPolicies`) | advisory | Harmful-instruction / jailbreak / credential-social-engineering scan; optional external API. |
| **Dependency** (`dependencyPolicies`) | enforce | Supply-chain hygiene over a skill's / install command's deps — typosquat, unpinned, denied, non-registry/editable, untrusted index, npm install-scripts, license — across Python (PEP 723 inline, requirements, pyproject) and Node (package.json, lockfiles). |
| **Skill** (`skillPolicies`) | enforce | Governs a skill before it runs: integrity attestation, dangerous-pattern / secret / injection / capability scans, source allowlist, and the scan-once attestation that drives the transitive CVE gate. |

**Skill & dependency supply-chain governance.** Tier 1 (runtime, in-process, no
network) parses a skill's manifests (incl. PEP 723 inline) + does metadata hygiene
+ an attestation lookup. Tier 2 (`skills audit`, off the hot path) resolves the
**full transitive tree** (`uv`/`npm`) and runs an auto-detected scanner (trivy /
osv-scanner / pip-audit) for CVEs, then writes a `scanned` attestation so a later
run is a cheap cache hit. **Fail-safe guarantee:** a skill is allowed silently only
when its deps were actually resolved transitively AND scanned clean; if they can't
be (no resolver/scanner, resolver error, bare-import JS with no manifest) coverage
is `unavailable` → unverified = unsafe (review/deny), never a false-clean. The
proactive audit needs `uv`/`npm` + a scanner on `PATH`; their absence fails safe.
Methodology + measured numbers: `experiment/supplychain/BENCHMARK.md`.

OpenCode runs the plugin **resident in-process**, so the stateful extensions
(exfil, rate-limit) keep per-session state in memory (the Claude Code seat,
which spawns a process per event, persists the same state to disk instead).

**Known limitations (defense-in-depth, not guarantees):** exfil matching is a
*tripwire* — it catches a tracked secret reused verbatim, but byte transforms
(base64/hex/splitting) evade the substring match; pair it with the egress
allowlist for real containment. DLP/content-safety catalogues are not exhaustive
(extend via `customPatterns`) and heuristic content-safety is defeatable by
paraphrase/unicode. The content layers default to **advisory** because heuristic
matching has FP/FN; move a layer to `enforce` after validating it on your workload.

### Project-policy trust gate

A project-local `.opencode/agt-policy.json` is **untrusted by default**: it may
only ADD restrictions, never weaken the global/default policy (no
`enforce`→`advisory`, allow-all, extension-disable, or allow-hole over a
credential path). Grant trust explicitly with `AGT_TRUST_PROJECT_POLICY=1` or by
listing the project in `~/.config/opencode/agt/trusted-projects.json`. Clamped
downgrade attempts are recorded in the audit log.

## Known limitations

- **`review` resolves to `deny`** unless OpenCode's `permission.ask` hook fires
  with enough tool context. OpenCode's permission API is still evolving
  ([opencode#7006](https://github.com/anomalyco/opencode/issues/7006)); the
  `tool.execute.before` gate fails closed rather than silently allowing.
- **`chat.message` cannot hard-block** a prompt — a blocked prompt is rewritten
  in place, not rejected outright.
- **The audit log is tamper-evident, not tamper-proof.** Entries form a
  persistent SHA-256 hash chain that spans sessions (each run appends and links
  to the previous entry; `doctor`/`policy show` report whether the chain
  verifies). Because the chain is keyless and computed over public fields,
  anyone who can write the log file can recompute a valid chain — treat it as an
  integrity tripwire, not an unforgeable ledger. Forward entries to an
  append-only sink (SIEM/WORM) for true non-repudiation.
- **Governance runs in-process.** The engine is a cooperative OpenCode hook
  inside the same process as the agent it governs — a guardrail, not an OS-level
  sandbox. Code that can break out of the agent process can bypass it. For hard
  isolation, run OpenCode (and the agent) inside a container.

Set `AGT_OPENCODE_DEBUG=1` to log hook payloads to stderr — useful for
confirming hook order and `permission.ask` behavior against your OpenCode build.

## Layout

```
plugin/src/agt-plugin.ts   OpenCode adapter (the only OpenCode-specific runtime code)
plugin/src/policy.mjs      AGT governance engine (adapted for OpenCode)
plugin/src/poisoning.mjs   AGT text helpers (verbatim)
plugin/src/sdk-loader.mjs  Bundle-friendly SDK shim
config/default-policy.json Default (balanced) policy
config/profiles/           strict / balanced / advisory
build.mjs                  esbuild bundler -> assets/agt-governance.js
bin/ + lib/                Installer CLI
test/                      Installer + policy-engine tests
```

## License

MIT.

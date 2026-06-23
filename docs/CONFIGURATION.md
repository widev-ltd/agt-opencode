# Configuration — agt-opencode

## Profiles

Four policy profiles ship under `config/profiles/`. They share the same
dangerous-command/credential deny rules and the same scanning; they differ in
which tools are allowed vs reviewed and whether enforcement blocks at all.

| Profile | Mode | Allowed (run freely) | Reviewed → **currently denied** | Use when |
|---|---|---|---|---|
| **strict** | enforce | `read` `glob` `grep` `list` | everything else (write, edit, bash, web, task) | Maximum lock-down. Expect the agent to be unable to write/run until you widen `allowedTools`. |
| **balanced** *(default)* | enforce | `read` `glob` `grep` `list` `write` `edit` `apply_patch` `todowrite` | `bash` `webfetch` `websearch` `task` | Normal use — the agent can do the read/write/edit loop; shell/web are gated. |
| **secure-low-friction** *(recommended)* | enforce | the everyday tools — `read` `glob` `grep` `list` `todowrite` `write` `edit` `apply_patch` `bash` `webfetch` `websearch` | only `task` (subagent spawning) | You want security without the prompting/blocking: the named threat rules + exfil/DLP/content-safety still enforce, but `bash`/web aren't reviewed (so not denied), so the agent works freely. |
| **advisory** | advisory | — (never blocks) | — (only warns) | First rollout / observation. Surfaces findings without blocking anything. |

> Because of OpenCode's review→deny behaviour (see
> [USAGE.md](USAGE.md#the-reviewdeny-behaviour-important)), "reviewed" tools are
> currently **blocked**, not interactively approved. `balanced` is the default
> because it keeps the core editing loop working anyway; **`secure-low-friction`**
> is the recommended step up when review→deny is too blunt — it keeps the threat
> rules but stops sending `bash`/web to review (so they aren't denied).

Apply a profile (then restart OpenCode):

```bash
agt-opencode policy apply --profile strict
```

## Policy file shape

A policy is a JSON document (`schemaVersion: 1`). The key fields:

```jsonc
{
  "schemaVersion": 1,
  "version": 1,
  "profile": "balanced",
  "mode": "enforce",                  // "enforce" | "advisory"
  "denyOnPolicyError": true,          // fail closed if evaluation errors
  "minimumPromptDefenseGrade": "B",   // reported in status (see note below)
  "toolPolicies": {
    "allowedTools": ["read", "glob", "grep", "list", "write", "edit", "apply_patch", "todowrite"],
    "reviewTools":  ["bash", "webfetch", "websearch", "task"],
    "blockedTools": [],
    "defaultEffect": "review"         // effect for tools not listed above
  },
  "outputPolicies": {
    "suppressTools": ["webfetch", "websearch"],  // flagged output is replaced
    "advisoryTools": ["bash"]                    // flagged output is annotated
  },
  "scanOutputTools": ["webfetch", "websearch", "bash"],
  "blockedToolCalls": [ /* command-pattern rules: recursive-delete, dangerous-bootstrap, secret-read, persistence-write */ ],
  "directResourcePolicies": { "pathRules": [ /* credential paths */ ], "urlRules": [ /* metadata endpoints */ ] },
  "poisoningPatterns": [ /* prompt/output injection regexes */ ],
  "additionalContext": [ /* extra guard lines injected into the session */ ],

  // ── Governance extensions (each has its own `mode`: "advisory" | "enforce") ──
  "dlpPolicies":          { "mode": "advisory", /* credential/PII catalogues, allow-snippets */ },
  "exfilPolicies":        { "mode": "enforce",  /* session-aware secret-reuse tripwire */ },
  "rateLimitPolicies":    { "mode": "advisory", /* per-session, per-tool call budgets */ },
  "contentSafetyPolicies":{ "mode": "advisory", /* harmful-instruction / jailbreak scan */ },
  "intentJudgePolicies":  { "enabled": false,   /* OPTIONAL LLM-as-judge intent detection — off by default; see LLM-JUDGE.md */ },
  "dependencyPolicies":   { "mode": "enforce",  /* supply-chain dep hygiene — see below */ },
  "skillPolicies":        { "mode": "enforce",  /* skill gating + attestation — see below */ }
}
```

- **`mode`** — `enforce` acts on decisions; `advisory` never blocks (findings
  only).
- **`allowedTools` vs `reviewTools` vs `blockedTools`** — tool names are matched
  case-insensitively. Anything unlisted uses `defaultEffect`.
- **`blockedToolCalls`** — regex command patterns (per tool) with an effect
  (`deny`/`review`). The shipped rules cover recursive deletes, downloaded-script
  bootstraps, credential/secret reads, and persistence writes, for both POSIX and
  PowerShell syntaxes routed through the `bash` tool.
- **`directResourcePolicies`** — deny reads of credential *paths* (`.ssh`, `.env`,
  `.aws`, …) and access to cloud-metadata URLs, independent of the command text.
- **`poisoningPatterns`** — regexes that flag prompt-injection / context-poisoning
  in prompts and tool output.

Validate before applying:

```bash
agt-opencode policy validate --file ./my-policy.json
```

> **Note on `minimumPromptDefenseGrade`:** this value is reported by
> `doctor`/status but is **not currently an enforcement gate** — it grades the
> built-in guard prose, not your input. Treat it as informational.

## Governance extensions

Six extra layers run on top of the core policy. Each has its own `mode`
(`advisory` warns, `enforce` blocks); set it per extension in the policy file. The
content layers default to **advisory** (heuristic matching has FP/FN — validate on
your workload before enforcing); the structural supply-chain and exfil layers
default to **enforce**.

| Extension | Key | Default | What it does |
|---|---|---|---|
| DLP | `dlpPolicies` | advisory | Credential values (AWS/GitHub/private-key) + PII (SSN, Luhn card, email) in tool output / webfetch URLs; `allowSnippets` suppress doc placeholders. |
| Exfiltration | `exfilPolicies` | enforce | Session-aware: blocks an outbound request embedding a credential value seen earlier in tool output. |
| Rate-limit | `rateLimitPolicies` | advisory | Per-session, per-tool call budgets. |
| Content-safety | `contentSafetyPolicies` | advisory | Harmful-instruction / jailbreak / credential-social-engineering scan; optional external API. |
| Intent judge | `intentJudgePolicies` | **disabled** | Optional LLM-as-judge for tool-call *intent* (benign/suspicious/malicious). Additive-only, fail-safe to deterministic. Off by default — see [LLM-JUDGE.md](LLM-JUDGE.md). |
| Dependency | `dependencyPolicies` | enforce | Supply-chain hygiene over a skill's / install command's deps. |
| Skill | `skillPolicies` | enforce | Governs a skill before it runs: integrity attestation + scans. |

### Dependency + skill supply-chain governance

These two are the supply-chain gate (methodology + numbers in
[`experiment/supplychain/BENCHMARK.md`](../experiment/supplychain/BENCHMARK.md)).
They work in two tiers:

- **Tier 1 (runtime, in-process, no network).** `dependencyPolicies` parses a
  skill's manifests — Python `requirements.txt` / `pyproject.toml` / **PEP 723
  inline metadata**, and Node `package.json` / lockfiles — and applies deterministic
  hygiene a CVE scanner is blind to: denied package, non-registry/editable install,
  untrusted index (dependency-confusion), npm install-scripts. `skillPolicies` adds
  metadata hygiene, dangerous-pattern / secret / injection / capability scans, a
  source allowlist, and an **attestation lookup**. (Typosquat name-matching,
  unpinned, and license-deny were removed — FP-prone heuristic / lockfile's job /
  compliance, not security.)
- **Tier 2 (`skills audit`, off the hot path).** Resolves the **full transitive
  tree** (`uv` / `npm`) and runs an auto-detected CVE scanner (`trivy` /
  `osv-scanner` / `pip-audit`), then writes a `scanned` attestation so a later
  runtime gate is a cheap cache hit. See
  [USAGE.md](USAGE.md#trusting-skills--two-tiers).

Useful keys (both accept `mode` and merge over the shipped defaults):

```jsonc
"dependencyPolicies": {
  "mode": "enforce",
  "deny": ["evil-pkg"],                  // package names always denied
  "severityThreshold": "medium",         // min severity that escalates to deny
  "allowedIndexes": ["https://pypi.org/simple"]  // [] = any index OK
}
"skillPolicies": {
  "mode": "enforce",
  "allowedSources": ["https://trusted-marketplace.example/"],  // skill origin allowlist ([] = any)
  "capabilityProfile": {                 // operator budget — the HARD ceiling (false = forbid)
    "maxNetwork": true, "maxSubprocess": true,
    "maxFsWrite": false, "maxSecretRead": false
  },
  "severityThreshold": "high",           // min finding severity that escalates (default high)
  "trustedSigners": ["/etc/agt/ci-public.pem"],  // CI public key(s): PEM or file path (delivered out of band)
  // requireSignature DEFAULTS to true when trustedSigners is set (no silent fallback
  // to the forgeable local tier). Set false to keep the 1-day local scan alongside it.
  "requireSignature": true,
  "revokedKeyIds": [],                    // revoke a compromised signer by its --key-id
  "revokedAttestationKeys": [],           // surgically revoke individual attestations by integrity key
  "maxAgeMs": 604800000,                 // CI-signed stamp window (default 7 days; an embedded notAfter, if tighter, wins)
  "localGraceMs": 86400000               // unsigned local-scan stamp window (default 1 day)
}
```

> **Two trust tiers (hardened).** A **CI-signed** stamp is honored only if it
> verifies under a `trustedSigners` key, is bound to the skill's current files, is
> within its validity window (embedded `notAfter`, or `maxAgeMs`, whichever is
> tighter), and its `keyId`/integrity-key is not in the revocation lists —
> unforgeable by a local attacker (the private key lives in CI/HSM, off the agent
> box). A signature **is** the pass: CI signs only skills that scanned clean. A
> revoked/expired/unverifiable stamp is treated as untrusted (review/deny), never
> allow. **`requireSignature` defaults to true when `trustedSigners` is set** (no
> silent fallback to the forgeable local tier); set it false to keep the 1-day
> (`localGraceMs`) local scan. An **unsigned** skill (no trusted signers) is scanned
> locally and gets the 1-day stamp — forgeable but time-boxed. The CI signer is a
> separate tool (`tools/skill-signer/sign.mjs --key-id <id> --valid-days <N>`), run
> by CI; revoke by adding the id to `revokedKeyIds`. Runbook:
> `tools/skill-signer/KEY-MANAGEMENT.md`. See [USAGE.md](USAGE.md#trusting-skills--two-tiers).

> **Capability least-privilege.** A skill declares what it may do in its
> `SKILL.md` frontmatter (`allowed-capabilities: [network, subprocess, …]`). A
> capability **used but not declared** — or declared but forbidden by the operator
> `capabilityProfile` budget — is flagged. The budget is the hard ceiling: a
> self-declaration can never override a capability the operator set to `false`.

> **Fail-safe behavior (a guardrail, not a guarantee).** In `enforce`, a skill is
> silent-allowed only when its deps were actually resolved transitively **and**
> scanned clean (or carry a valid CI signature). If they can't be (no
> resolver/scanner, resolver error, bare-import JS with no manifest) coverage is
> `unavailable` → unverified = unsafe (review/deny), never a false-clean. It catches
> *known* CVEs/patterns, not novel/zero-day; only the CI-signed tier resists a local
> forger; a true boundary needs OS-level isolation, which this is not.

## Per-project override

A project can ship its own policy. The plugin uses the **first** of these that
exists, falling back to the bundled default:

1. `<project>/.opencode/agt-policy.json` (per project)
2. `<opencode-home>/agt/policy.json` (per user, seeded by the installer)
3. bundled default (`balanced`)

This lets a repo enforce a stricter (or looser) policy than your global one.

## Environment variables

| Variable | Effect |
|---|---|
| `OPENCODE_CONFIG_HOME` | Override the OpenCode config home (else `$XDG_CONFIG_HOME/opencode` → `~/.config/opencode`). |
| `XDG_CONFIG_HOME` | Standard XDG base; `…/opencode` is used. |
| `AGT_OPENCODE_DEBUG=1` | Log hook payloads/decisions to stderr. |

(The adapter also bridges internal `AGT_COPILOT_POLICY_PATH` /
`AGT_COPILOT_AUDIT_PATH` variables to the resolved OpenCode paths; you normally
do not set these yourself.)

## Audit log

- Location: `<opencode-home>/agt/audit-log.json`.
- A persistent SHA-256 hash chain that **spans sessions** (appends, never resets).
- **Tamper-evident, not tamper-proof** (keyless). Forward to a SIEM/WORM sink for
  non-repudiation. See [OVERVIEW.md](OVERVIEW.md#security-model--read-this).

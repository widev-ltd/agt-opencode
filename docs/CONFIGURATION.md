# Configuration — agt-opencode

## Profiles

Three policy profiles ship under `config/profiles/`. They share the same
dangerous-command/credential deny rules and the same scanning; they differ in
which tools are allowed vs reviewed and whether enforcement blocks at all.

| Profile | Mode | Allowed (run freely) | Reviewed → **currently denied** | Use when |
|---|---|---|---|---|
| **strict** | enforce | `read` `glob` `grep` `list` | everything else (write, edit, bash, web, task) | Maximum lock-down. Expect the agent to be unable to write/run until you widen `allowedTools`. |
| **balanced** *(default)* | enforce | `read` `glob` `grep` `list` `write` `edit` `apply_patch` `todowrite` | `bash` `webfetch` `websearch` `task` | Normal use — the agent can do the read/write/edit loop; shell/web are gated. |
| **advisory** | advisory | — (never blocks) | — (only warns) | First rollout / observation. Surfaces findings without blocking anything. |

> Because of OpenCode's review→deny behaviour (see
> [USAGE.md](USAGE.md#the-reviewdeny-behaviour-important)), "reviewed" tools are
> currently **blocked**, not interactively approved. `balanced` is the default
> because it keeps the core editing loop working anyway.

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
  "additionalContext": [ /* extra guard lines injected into the session */ ]
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

# LLM-as-judge — intention detection (built-in, optional, off by default)

The governance layer ships a built-in **LLM-as-judge** that assesses the *intent*
behind a tool call — benign / suspicious / malicious — and feeds that verdict into
the decision. It is **disabled by default** and is a *second-opinion* layer on top
of the deterministic rules, never a replacement.

## What it is

- A `tool.execute.before` / `PreToolUse` step that, when enabled, sends the action
  (tool + command + args) to an LLM and asks for a strict JSON verdict
  (`{intent, confidence, reason}`).
- The deterministic engine (command-pattern, credential-path, prompt/output
  poisoning, supply-chain) still runs first and is **authoritative**. The judge is
  **additive-only**: it can raise an `allow` to `review`, or (in `enforce` mode)
  to `deny` — it can **never** turn a deterministic `deny`/`review` into an `allow`.
  (The gate skips the judge entirely once the base decision is already `deny`.)

## Enabling it

Off by default. Configure `intentJudgePolicies` in your policy:

```jsonc
"intentJudgePolicies": {
  "enabled": true,
  "mode": "advisory",              // "advisory" = warn (a context note); "enforce" = block
  "provider": "anthropic",         // "anthropic" | "openai" | "custom"
  "apiKeyEnv": "ANTHROPIC_API_KEY",// env var holding the key — NEVER put the key in policy
  "model": "claude-haiku-4-5-20251001",
  "timeoutMs": 4000,
  "failClosed": false,             // judge error/timeout: false → degrade to deterministic; true → raise to review
  "triggerTools": ["bash", "webfetch", "websearch", "task"]  // [] = judge every call (scope to bound cost)
}
```

- **`provider`**: `anthropic` (Messages API) and `openai` (OpenAI-compatible chat
  completions) are built in. `custom` POSTs `{system, action}` to your `endpoint`
  and expects `{intent, reason, confidence}` back — use this for an in-house judge
  service or a different vendor.
- **`apiKeyEnv`**: the judge reads the key from this environment variable at call
  time. The key is never stored in the policy file and never logged. If the env var
  is unset, the judge is *unavailable* (see fail-safe below) — it does not error.
- **`triggerTools`**: scope the judge to the risky tools. An empty list judges every
  call, which is the most expensive setting.
- **Disable**: set `enabled: false` (or remove the stanza). It's also off whenever no
  `provider`/`endpoint` resolves.

## Fail-safe behavior (important)

A judge that is unreachable, times out, returns garbage, or has no API key yields
status **`unavailable`**. By default that **degrades to the deterministic decision**
(a note, no block) — a *missing* verdict never silently allows something the
deterministic layer flagged, and a *failed* judge never hard-blocks unless you opt
in. Set `failClosed: true` to instead raise `unavailable` calls to **review**.

Either way the judge **never throws into the decision** and **never downgrades** the
deterministic verdict.

## Deterministic rules vs. the judge

| | **Deterministic rules** (always on) | **LLM judge** (opt-in) |
|---|---|---|
| **Catches** | Known-bad **patterns** you enumerate | **Novel / semantic** intent ("looks like exfiltration" with no matching pattern) |
| **Speed** | **Sub-millisecond**, in-process | A network round-trip: **hundreds of ms–seconds** per judged call |
| **Cost** | Free | An **API call** per judged call |
| **Determinism** | **Reproducible**; clean audit trail | **Non-deterministic** — verdicts vary run to run |
| **Trust surface** | Local code only | Adds a **model + provider + network** to the path |
| **Fooled by** | Obfuscation (degrades to *review*, not *allow*) | **Prompt injection of the judge itself** — poisoned args can argue "this is safe" |
| **Role** | The fast, reliable **first line** | A **second opinion** for semantic/novel risk |

## Honest limits (do not oversell)

- **Data egress — read this before enabling.** When on, the judge sends the action
  it's judging (tool name, command, and args) to the configured LLM endpoint. Those
  args can contain file contents, paths, or secrets. Enabling the judge therefore
  **ships potentially sensitive data to a third party** (whoever runs `endpoint`).
  Use a provider/endpoint you trust (or a self-hosted `custom` one), scope it with
  `triggerTools`, and don't enable it where that egress is unacceptable. The
  deterministic layer sends nothing off-box.
- **Non-deterministic.** The same call can get different verdicts. This undercuts
  reproducibility and the audit story — that's why it's off by default.
- **Defeatable.** A crafted action can read as benign, and the judge's *input* is
  attacker-influenced (poisoned tool args/output can try to prompt-inject the judge).
  The judge prompt instructs the model to treat the action as data, not commands —
  but that mitigation is not a guarantee. Treat the judge as defense-in-depth.
- **Not an isolation boundary.** Like the rest of the plugin it runs in-process — a
  smarter guardrail, not a sandbox. Real isolation is a container/VM.
- **Latency & cost** on every judged call — scope with `triggerTools`.
- Behind a TLS-intercepting proxy, set `NODE_EXTRA_CA_CERTS` (and on Node 22+
  `NODE_OPTIONS=--use-system-ca`) so the API client can connect.

## Extending further

The built-in judge covers tool-call intent. If you want a different shape (e.g.
adjudicating the `review` tier into an allow, or judging prompts), you can still add
a separate OpenCode plugin alongside `agt-governance`, or fork and register an async
backend in `plugin/src/policy.mjs`. Keep the same rule that held before this feature
shipped and still holds now: **a judge may only tighten, never loosen, a
deterministic deny.**

## Recommendation

Keep the deterministic rules as the always-on primary line. Turn the judge on in
**advisory** mode first, **scoped to the risky tools**, watch what it flags on your
workload, and only move it to **enforce** once you trust its precision. Leave
`failClosed` off unless an outage-blocks-everything posture is what you want.

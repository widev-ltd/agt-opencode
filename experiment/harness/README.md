# Deterministic harness (Phase 3) — plugin-vs-plugin, zero-key

Drives the REAL governance engine over the host-neutral corpus and emits a
prevention matrix + metrics. No model, no network, no credentials.

## Run

```bash
# OpenCode (imports the real plugin/src/policy.mjs):
node score.mjs                                  # DEFAULT: full corpus (../corpus/cases/*.jsonl)
node score.mjs --corpus deterministic/smoke-cases.jsonl   # single file (smoke)
node score.mjs --corpus ../corpus/cases/<f>.jsonl         # single bucket

# Claude Code (spawns the real plugins/agt-governance/scripts/agt-hook.mjs):
#   run the copy in agt-claude-code/experiment/harness/ the same way.
```

`--corpus` accepts a single `.jsonl` file OR a directory of them. With no flag it
defaults to `../corpus/cases/` (the full committed corpus), read in **sorted
filename order** so the combined case list — and therefore `matrix.csv` — is
byte-stable across machines.

Outputs to `../results/`: `matrix.csv`, `summary.csv`, `summary.json` (the three
**byte-deterministic** artifacts), plus `latency.json` and
`raw/deterministic-<host>.json` (NOT byte-stable — they carry wall-clock latency
and a `generatedAt` timestamp).

## What is (and is NOT) measured

The deterministic track measures the **PLUGIN column only** (per BENCHMARK-PLAN
track-1). Every matrix cell carries `observed` AND `expected` separately so a
pre-registered hypothesis can never masquerade as a measurement:

| config | observed | why |
|---|---|---|
| `plugin` | real engine decision | the one MEASURED column |
| `ungoverned` | `allow` | by construction (engine off) |
| `native` | `not-measured` | live-only — no offline settings.json entrypoint (Phase 5) |
| `layered` | plugin-component-only | native re-entry is live-only (Phase 5) |

## Pieces

- `deterministic/run-plugin.mjs` — host runner. OC: `import`s the engine, calls
  `evaluatePreToolUse/evaluatePromptSubmission/inspectToolResult`. CC: spawns the
  real hook, writes hook-event JSON to stdin, reads decision JSON from stdout
  (empty stdout = allow ONLY on exit 0; a nonzero exit is a harness error, never
  a silent allow).
- `deterministic/decision-normalize.mjs` — shared classifier + per-host
  extractor. `extractOC/extractCC` → canonical `{effect}`; `classify(call,
  canonical, host)` → `{outcome, layer, reason, deny_kind}`. The ONE host
  asymmetry: a `review` effect is a hard **deny** on OC (permission.ask never
  fires, opencode#7006) but an interactive **ask** (friction) on CC.
- `score.mjs` / `report.mjs` — build the matrix and the metrics.

## Scoring rules (anti-inflation)

- Coverage credit (host-symmetric): a prevention effect (`deny` OR `ask`) earns
  credit ONLY if it was a NAMED-backend match (`deny_kind=policy-match`). A
  generic `defaultEffect` review — fail-closed deny on OC, friction ask on CC —
  earns ZERO coverage. `out-of-scope` cells are excluded from the denominator.
- FPR = benign DENIED / benign (fail-closed denies COUNT). Friction = benign ASKED.
- `deny_kind` split (`policy-match` vs `fail-closed-review`) is preserved, never
  lumped.

## Determinism

`matrix.csv`, `summary.csv`, AND `summary.json` are byte-identical on repeat
(decisions + counts only). Per-decision latency is wall-clock and varies every
run, so it is written to a SEPARATE `latency.json` (not one of the three
byte-stable artifacts) — keeping `summary.json` deterministic. The audit
side-effect is redirected to a tmp path. Gate: run twice, diff the three files.

## OPEN rulings (skeptic) that Phase 4 consumes

1. **CC tool-output scoring.** CC PostToolUse cannot retract output; a suppress
   degrades to an `additionalContext` warning → advisory → `allow`. Defaulted to
   in-scope `allow` (CC tool-output coverage = 0% across those cases), NOT
   `out-of-scope`. Needs a ruling.
2. **deny_kind named-vs-generic.** A NAMED review-effect rule → `policy-match`
   (earns credit); a generic `defaultEffect` review → `fail-closed-review`
   (zero). Implemented; awaiting final skeptic confirmation.

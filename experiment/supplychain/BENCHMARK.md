# Supply-chain governance benchmark

A reproducible, adversarial benchmark for the skill / dependency supply-chain
governance layer. It mirrors the discipline of the settings-vs-plugin benchmark:
a **deterministic, byte-sealed** track for the offline detectors, and a **live,
non-sealed** track for the real vulnerability scanner (whose DB drifts over time).

The numbers describe the **byte-identical shared engine**, so they apply to both
seats (agt-claude-code and agt-opencode); the OC harness reproduces the same seal.

## Headline (deterministic track)

| Metric | Value |
|---|---|
| **Coverage** (named-detector catch of an in-scope threat) | **86.24%** |
| **Prevention** (any deny/review of an in-scope threat) | 86.24% |
| **SVR** (unprevented in-scope threats) | 13.76% |
| **FPR** (benign hard-denied) | **0%** |
| **Friction** (benign sent to review) | 4.92% |
| In-scope threats / benign / total cases | 109 / 61 / 170 |
| **Expected-outcome match rate** (pre-registered = observed) | **100%** |

Coverage == prevention because **every** prevention is a real *named-detector*
catch — there is no fail-closed-only credit. The 13.76% miss is exactly the 15
**calibration-gap** cases: real threats the offline detectors genuinely miss
(documented below, not hidden). 94 of 109 in-scope threats are caught by name.

Per category: dep-typosquat, dep-denied, dep-non-registry, dep-install-script,
dep-npm-alias, dep-unpinned, dep-untrusted-index, skill-dangerous, skill-secret,
skill-injection, and **skill-capability** all **100%**; calibration-gap 0% by
construction (it *is* the documented-miss bucket).

Sealed: `seal-sc.json` combined `765fe231…`; byte-identical on re-run and across
both seats.

## What this measures (and what it does NOT)

- **DETECTOR ACCURACY** under an **enforce** policy (requirePinned:true + a deny
  list + medium severity threshold). This is the *detection ceiling when
  enforcement is on* — and the shipped default now ENFORCES skill+dep governance,
  so this is the shipped posture. (Earlier the default was advisory — same
  findings surfaced as notes, blocking nothing; a deployment that enforces gets
  these detections.)
- The score is computed **directly from detector findings** (severity → outcome),
  deliberately dropping the runtime gate's "review-until-vuln-scanned" coverage
  penalty. So a deployed enforce gate has **MORE friction** than the 4.92% here —
  this FPR/friction is a *floor* measuring detector precision, not the full gate UX.
- The **Tier-2 CVE scan is NOT in this number** — it's the separate live track.

## How skill-capability reaches 100% honestly (least-privilege, not inflation)

An earlier revision scored skill-capability at **50%** and said so, because the
capability profile had *no behavioral discrimination* for network/subprocess: a
"threat" doing `socket.connect` looked identical to a benign skill doing the same,
and only a global budget knob differed. That was a real weakness, scored as a gap
rather than papered over.

It is now a genuine **least-privilege, declared-capability** control, so the 100%
is earned, not assumed:

- A skill **declares** what it may do in its `SKILL.md` frontmatter —
  `allowed-capabilities: [network, subprocess, fsWriteOutsideCwd, secretFileRead]`
  (aliases like `fs-write`, `exec`, `secrets` are accepted).
- The scanner detects each capability a skill **actually uses** (static
  signatures), then compares **used vs declared vs operator budget**:
  - declared **and** within the operator budget → **no finding** (transparent use);
  - **used but not declared** → **finding** (undeclared capability);
  - declared **but** the operator budget forbids it (`maxNetwork:false`, …) →
    **finding** (the budget is a hard ceiling above the declaration).
- So all 6 capability cases are discriminated by a signal **no benign case
  trips**: each threat uses a capability it did **not** declare (or one the
  operator forbids), while the benign capability skills declare exactly what they
  use. This is per-skill opt-in least privilege — declaration is itself a visible,
  reviewable manifest signal, and self-declaration can never override an operator
  budget that forbids the capability.

Capability signatures cover Python / Node / shell / Ruby network, subprocess,
out-of-cwd writes, and credential-file reads — including aliased and dynamic
imports, popular JS HTTP clients (`got`/`undici`/`node-fetch`/`superagent`/`ky`/
`needle`/`phin`), and cloud credential stores (`~/.aws`, `~/.ssh`, kube, gcloud
application-default/legacy, Azure token cache). **Residual limit (documented):** a
module name assembled at runtime from string fragments (`__import__("so"+"cket")`)
cannot be constant-folded by a static signature; the undeclared-capability check
still flags *any* statically-visible use, but a fully string-built indirection to
a capability is an inherent static-analysis blind spot — the Tier-2 transitive
scan and the runtime tool-call gates are the defense-in-depth behind it.

## Honesty notes (from the adversarial credibility panel)

The corpus + scorer were audited by independent skeptics (fairness,
anti-inflation, reproducibility) and an adversarial capability-evasion panel
(A-CAP-EVADE). Findings were **fixed**, which is why the headline is 86.24% and
not a flattering 100%:

1. **Capability was honestly 50%; it is now 100% by a real control,** not by
   relaxing the test — see the section above. The 3 cases that used to be honest
   gaps (network/subprocess) are now caught because they use an **undeclared**
   capability, exactly like the 3 always-caught cases that read credential files /
   write outside cwd.
2. **Short-name typosquats are a documented gap.** `nearestPopular` skips
   candidate names < 5 chars, so `clik`→click slips through (sc-cal-16). Real,
   exploitable, represented on the gap side.

The 15 calibration-gaps (genuine misses, 13.76% SVR) are: split/concatenated
secret tokens (a regex can't constant-fold), base64 blobs with no decode call,
2-edit typosquats, double-homoglyph names, dependency-confusion lookalikes, the
short-name typosquat above, and transitive-only / CVE-by-version threats that
**require the live scanner** (Tier-2). They are real threats the *offline*
detectors miss — listed so the ceiling is honest.

## Live track (Tier-2 CVE detection — NOT sealed)

Real vulnerability scanners over known-vulnerable fixtures, captured 2026-06-19:

| Scanner | DB | Vulnerable caught | True-negatives clean |
|---|---|---|---|
| trivy 0.71.1 | DB v2 (2026-06-18) | 10/10 (high/critical) | 3/3 |
| osv-scanner 2.4.0 | scalibr 0.4.5 | 10/10 (high/critical) | 2/2 |
| pip-audit 2.10.1 | OSV/PyPI live | 5/5 (any-severity*) | 1/2* |

*pip-audit's JSON omits per-vuln severity (plugin bands to medium), so it's
scored on a relaxed any-severity rule and labeled as such; python-only, so npm
fixtures are reported NOT-MEASURED (not as catches/misses). DB-dependent →
**not byte-sealed**; each run is stamped with scanner + DB version + date.

## Reproduce

```bash
cd experiment/supplychain
node harness/validate-sc.mjs        # Cases: 170  Violations: 0
node harness/score-sc.mjs           # -> results-sc/{matrix,summary}-sc.{csv,json}
node harness/make-hash-sc.mjs --check  # seal-sc.json OK; combined=765fe231…
# determinism gate: re-run score-sc.mjs → matrix-sc.csv byte-identical.

# live track (needs trivy/osv-scanner/pip-audit on PATH; pip-audit needs truststore):
cd live && node score-sc-live.mjs --date <YYYY-MM-DD>
```

## Layout

```
experiment/supplychain/
  corpus/
    schema-sc.json              case schema (pre-registration contract)
    cases/{dep-threats,skill-threats,benign,calibration-gaps}.jsonl   170 cases
  harness/
    validate-sc.mjs             schema + invariant validator
    score-sc.mjs                deterministic scorer (findings → outcome, no network)
    report-sc.mjs               matrix + summary (byte-stable)
    make-hash-sc.mjs            seal (corpus + matrix), --check verifies
  results-sc/                   matrix-sc.csv, summary-sc.{csv,json}, seal-sc.json
  live/                         real-scanner CVE track (non-sealed, DB-stamped)
```

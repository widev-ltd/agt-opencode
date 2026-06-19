# Supply-chain governance benchmark

A reproducible, adversarial benchmark for the skill / dependency supply-chain
governance layer. It mirrors the discipline of the settings-vs-plugin benchmark:
a **deterministic, byte-sealed** track for the offline detectors, and a **live,
non-sealed** track for the real vulnerability scanner (whose DB drifts over time).

The numbers describe the **byte-identical shared engine**, so they apply to both
seats (agt-claude-code and agt-opencode).

## Headline (deterministic track)

| Metric | Value |
|---|---|
| **Coverage** (named-detector catch of an in-scope threat) | **83.52%** |
| **Prevention** (any deny/review of an in-scope threat) | 83.52% |
| **SVR** (unprevented in-scope threats) | 16.48% |
| **FPR** (benign hard-denied) | **0%** |
| **Friction** (benign sent to review) | 5.36% |
| In-scope threats / benign / total cases | 91 / 56 / 147 |
| **Expected-outcome match rate** (pre-registered = observed) | **100%** |

Coverage == prevention because **every** prevention is a real *named-detector*
catch — there is no fail-closed-only credit. The 16.48% miss is the 12
**calibration-gap** cases: real threats the offline detectors genuinely miss
(documented, not hidden).

Per category: dep-typosquat, dep-denied, dep-non-registry, dep-install-script,
dep-npm-alias, dep-unpinned, dep-untrusted-index, skill-dangerous, skill-secret,
skill-injection all **100%**; **skill-capability 50%** (see honesty notes).

Sealed: `seal-sc.json` combined `2e5248c6…`; byte-identical on re-run.

## What this measures (and what it does NOT)

- **DETECTOR ACCURACY** under an **enforce** policy (requirePinned:true + a deny
  list + medium severity threshold). This is the *detection ceiling when
  enforcement is on* — NOT what ships. The shipped default now ENFORCES skill+dep governance (this benchmark measures that enforce posture). Earlier it was advisory
  (requirePinned:false, permissive), which surfaces the same findings as notes and
  blocks nothing. A deployment that turns on enforce gets these detections.
- The score is computed **directly from detector findings** (severity → outcome),
  deliberately dropping the runtime gate's "review-until-vuln-scanned" coverage
  penalty. So a deployed enforce gate has **MORE friction** than the 5.36% here —
  this FPR/friction is a *floor* measuring detector precision, not the full gate UX.
- The **Tier-2 CVE scan is NOT in this number** — it's the separate live track.

## Honesty notes (from the adversarial credibility panel)

The corpus + scorer were audited by three independent skeptics (fairness,
anti-inflation, reproducibility). Two real issues were found and **fixed**, which
is why coverage is 83.52% and not a flattering 100%:

1. **skill-capability is honestly 50%, not 100%.** The capability profile has *no
   behavioral discrimination* for network/subprocess — a "threat" that only does
   `socket.connect`/`https.get`/`os.system` is identical to a benign skill that
   does the same; only the per-skill budget knob differs. So those 3 cases
   (cap-03/05/06) are scored as **honest gaps** under a budget *consistent* with
   the benign network/subprocess skills. The 3 real catches (cap-01/02/04) read
   credential files / write outside cwd — signals **no benign case uses**.
   Capability enforcement is a **per-skill opt-in** control (declare each skill's
   allowed capabilities); it is not a global always-on detector.
2. **Short-name typosquats are a documented gap.** `nearestPopular` skips
   candidate names < 5 chars, so `clik`→click slips through (sc-cal-16). Real,
   exploitable, now represented on the gap side.

The 12 calibration-gaps (genuine misses) also include: split/concatenated secret
tokens (regex can't constant-fold), base64 blobs with no decode call, 2-edit
typosquats, double-homoglyph names, dependency-confusion lookalikes, and
transitive-only / CVE-by-version threats that **require the live scanner** (Tier-2).

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
node harness/validate-sc.mjs        # Cases: 147  Violations: 0
node harness/score-sc.mjs           # -> results-sc/{matrix,summary}-sc.{csv,json}
node harness/make-hash-sc.mjs --check  # seal-sc.json OK; combined=2e5248c6…
# determinism gate: re-run score-sc.mjs → matrix-sc.csv byte-identical.

# live track (needs trivy/osv-scanner/pip-audit on PATH; pip-audit needs truststore):
cd live && node score-sc-live.mjs --date <YYYY-MM-DD>
```

## Layout

```
experiment/supplychain/
  corpus/
    schema-sc.json              case schema (pre-registration contract)
    cases/{dep-threats,skill-threats,benign,calibration-gaps}.jsonl   147 cases
  harness/
    validate-sc.mjs             schema + invariant validator
    score-sc.mjs                deterministic scorer (findings → outcome, no network)
    report-sc.mjs               matrix + summary (byte-stable)
    make-hash-sc.mjs            seal (corpus + matrix), --check verifies
  results-sc/                   matrix-sc.csv, summary-sc.{csv,json}, seal-sc.json
  live/                         real-scanner CVE track (non-sealed, DB-stamped)
```

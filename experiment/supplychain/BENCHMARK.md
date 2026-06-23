# Supply-chain detection suite — self-graded regression (NOT an independent benchmark)

> **Read this first — what this is, and what it is NOT.**
> This is a **self-authored regression / characterization suite**, not an
> independent benchmark. The cases, the scorer, **and** the detectors being scored
> are all written by this project. So the numbers below measure *"do our detectors
> behave the way we encoded, on the cases we thought of"* — they are **not**
> evidence of real-world efficacy. There is **no independent corpus** and **no
> measured baseline** (what the host platform blocks *without* the plugin is not
> measured here). Use these numbers as a **regression guard** and an honest ledger
> of known gaps — not as proof of security. Independent signals (real CVE database,
> real-world attacks, overhead) are separate and partly still outstanding — see the
> bottom of this file.

The suite has a **deterministic, byte-reproducible** track (offline detectors,
hashed so a regression shows up as a changed hash) and a **live** track (a real
vulnerability scanner whose DB drifts). Numbers describe the byte-identical shared
engine; both seats reproduce the same hash.

## Self-graded numbers (deterministic track — our detectors over our own cases)

| Metric | Value |
|---|---|
| Named-detector catch of an in-scope threat (we call this "coverage") | **86.08%** |
| Any deny/review of an in-scope threat ("prevention") | 86.08% |
| Unprevented in-scope threats (1 − prevention) | 13.92% |
| Benign hard-denied (false positives) | **0%** |
| Benign sent to review (friction) | **0%** |
| In-scope threats / benign / total cases | 79 / 61 / 140 |
| Pre-registered outcome == observed | **100%** |

> **Scope note (detectors removed).** The `typosquat` (name-distance), `unpinned`,
> and `license-deny` checks were **cut** — typosquat was an FP-prone bespoke
> heuristic that reinvents the scanner/registry ecosystem's job (it false-flagged
> real packages like `scapy`/`pyaml`; see `experiment/independent/`), unpinned is
> the lockfile's job, and license-deny is compliance, not security. Their corpus
> cases (26 dep-threats + 4 typosquat calibration-gaps) were removed with them.
> Removing typosquat also dropped benign **friction from 4.92% to 0%**.

Honest reading of these:
- **"100%" per category and "100% expected-match" are by construction.** I wrote
  the cases to match the detectors; `skill-capability` is 100% because the benign
  cases declare their capabilities and the threat cases do not — I can move that
  number by editing the corpus. "Expected == observed" mostly proves the corpus and
  scorer are internally consistent, not that the system is correct.
- The 13.92% miss is the 11 **calibration-gap** cases — real threats these offline
  detectors genuinely miss, listed below so the ceiling is honest.
- Reproducible: `seal-sc.json` combined `3c63a5a7…`, byte-identical on re-run and
  across both seats. (Reproducibility ≠ validity — a stable hash only proves the
  run repeats, not that the numbers mean anything beyond this corpus.)

## What this measures (and what it does NOT)

- **DETECTOR ACCURACY** under an **enforce** policy (deny list + medium severity
  threshold). This is the *detection ceiling when
  enforcement is on* — and the shipped default now ENFORCES skill+dep governance,
  so this is the shipped posture. (Earlier the default was advisory — same
  findings surfaced as notes, blocking nothing; a deployment that enforces gets
  these detections.)
- The score is computed **directly from detector findings** (severity → outcome),
  deliberately dropping the runtime gate's "review-until-vuln-scanned" coverage
  penalty. So a deployed enforce gate has **MORE friction** than the 0% here —
  this FPR/friction is a *floor* measuring detector precision, not the full gate UX.
- The **Tier-2 CVE scan is NOT in this number** — it's the separate live track.

## How skill-capability is scored (declared-capability least-privilege)

Note the by-construction caveat above: this 100% reflects how the corpus is built,
not an independent result. The *mechanism* is real, though, and worth describing.
An earlier revision scored skill-capability at **50%** and said so, because the
capability profile had *no behavioral discrimination* for network/subprocess: a
"threat" doing `socket.connect` looked identical to a benign skill doing the same,
and only a global budget knob differed. That was a real weakness, scored as a gap
rather than papered over.

It is now a **least-privilege, declared-capability** control — the discrimination
is declared-vs-used, so within this corpus it scores 100%:

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
(A-CAP-EVADE). Findings were **fixed**, which is why the headline is 86.08% and
not a flattering 100%:

1. **Capability was honestly 50%; it is now 100% by a real control,** not by
   relaxing the test — see the section above. The 3 cases that used to be honest
   gaps (network/subprocess) are now caught because they use an **undeclared**
   capability, exactly like the 3 always-caught cases that read credential files /
   write outside cwd.
2. **Typosquat detection was cut, not gamed.** It was an FP-prone name-distance
   heuristic (it false-flagged real packages — see `experiment/independent/`); the
   honest call was to remove it and its corpus cases, not to tune the corpus around
   it. Real-world typosquat/malware detection belongs to the scanner ecosystem.

The 11 calibration-gaps (genuine misses, 13.92% SVR) are: split/concatenated
secret tokens (a regex can't constant-fold), base64 blobs with no decode call,
dependency-confusion lookalikes (internal-name-published-publicly — no offline
detector), and transitive-only / CVE-by-version threats that **require the live
scanner** (Tier-2). They are real threats the *offline* detectors miss — listed so
the ceiling is honest.

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

## Independent signals (the parts NOT self-graded — and what's still owed)

The numbers above are self-graded. These signals are *not* (or are owed):

- **Real CVE database (the one genuinely independent detection signal).** The live
  track scans against trivy/osv/pip-audit vulnerability databases this project does
  not author. A catch there is a real catch of a real published CVE — incl.
  **transitive** ones (e.g. `express@4.16.0` → 11 CVEs across 7 mostly-indirect
  packages). This is the closest thing here to an independent benchmark.
- **Overhead (measured, wall-clock — not self-graded).** OpenCode (resident):
  ~0.33 ms/call; the skill/dep gate adds ~17 µs on ordinary calls. Claude Code
  (process-per-hook): ~244 ms/hook ordinary (≈106 ms is Node startup, ~138 ms the
  SDK+engine load); a skill invocation adds the local scan (seconds on first use,
  then a cache hit). Harness: `experiment/harness/overhead.mjs`.
- **Forgery-resistance of the trust stamp (a real cryptographic property, tested —
  not a corpus metric).** With external signing configured, a stamp not signed by
  the trusted (off-box) key is rejected: a local attacker cannot forge a clean
  "pass." The authoritative test is `scripts/selftest-skill-gate.mjs` (CI-signed →
  allow; unsigned / attacker-signed / tampered → not trusted; strict mode; DB-binding
  freshness) — it drives the real gate. `experiment/signing-sim/` is an illustrative
  end-to-end demo of the same property (it warns and exits non-zero if no scanner is
  present, so it can't silently produce a vacuous "tamper" arm). The unsigned local
  tier is deliberately weak (1-day grace, forgeable).
- **STILL OWED (the honest gap).** There is no independent third-party attack
  corpus and no *measured* host-platform baseline (what native settings block
  without the plugin). Until those exist, the headline numbers remain a self-graded
  characterization, not an independent benchmark.

## Reproduce

```bash
cd experiment/supplychain
node harness/validate-sc.mjs        # Cases: 140  Violations: 0
node harness/score-sc.mjs           # -> results-sc/{matrix,summary}-sc.{csv,json}
node harness/make-hash-sc.mjs --check  # seal-sc.json OK; combined=3c63a5a7…
# determinism gate: re-run score-sc.mjs → matrix-sc.csv byte-identical.

# live track (needs trivy/osv-scanner/pip-audit on PATH; pip-audit needs truststore):
cd live && node score-sc-live.mjs --date <YYYY-MM-DD>
```

## Layout

```
experiment/supplychain/
  corpus/
    schema-sc.json              case schema (pre-registration contract)
    cases/{dep-threats,skill-threats,benign,calibration-gaps}.jsonl   140 cases
  harness/
    validate-sc.mjs             schema + invariant validator
    score-sc.mjs                deterministic scorer (findings → outcome, no network)
    report-sc.mjs               matrix + summary (byte-stable)
    make-hash-sc.mjs            seal (corpus + matrix), --check verifies
  results-sc/                   matrix-sc.csv, summary-sc.{csv,json}, seal-sc.json
  live/                         real-scanner CVE track (non-sealed, DB-stamped)
```

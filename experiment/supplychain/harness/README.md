# Supply-chain governance harness (deterministic) — scorer + seal

Drives the REAL deterministic supply-chain detectors (`skills.scanSkill` +
`deps.scanDependencyMetadata`) over the supply-chain corpus and emits a
prevention matrix + metrics. **No vulnerability scanner, no network, no model,
no credentials** — Tier-1 metadata + skill static analysis only.

## Run

```bash
# from experiment/supplychain/harness/
node validate-sc.mjs                 # corpus is well-formed -> "Cases: N  Violations: 0"
node score-sc.mjs                    # score full corpus (../corpus/cases/*.jsonl) -> ../results-sc/
node score-sc.mjs --corpus <dir|file> --out <dir>   # override corpus / output
node make-hash-sc.mjs                # seal corpus + matrix -> ../results-sc/seal-sc.json
node make-hash-sc.mjs --check        # verify the seal (CI / determinism gate); nonzero on drift
```

Reproduce flow: `validate-sc` → `score-sc` → `make-hash-sc`. `--corpus` accepts a
single `.jsonl` file OR a directory of them; with no flag it defaults to
`../corpus/cases/`, read in **sorted filename order** (and cases scored in sorted
**id** order) so the combined case list — and therefore `matrix-sc.csv` — is
byte-stable across machines.

Outputs to `../results-sc/`: `matrix-sc.csv`, `summary-sc.csv`, `summary-sc.json`
(the three **byte-deterministic** artifacts) and `seal-sc.json` (the SHA-256
seal). Re-running produces byte-identical files; there are no timestamps in any
of them.

## What this measures: DETECTOR ACCURACY (read this caveat)

This benchmark scores the **detectors** — did a detector fire on a case, and at
what severity. It does **not** model the full deployed enforce-gate UX. The real
runtime gate (`checkSkillDeps`) additionally routes a skill through an attestation
cert + `decideFromFindings`, which applies a **"review-until-vuln-scanned"**
coverage penalty (an un-scanned but clean skill is held at `review`, not allowed).
That coverage behavior is a policy concern validated separately (in
`selftest-skill-gate`), and it would push every benign skill to `review` — which
would measure friction, not detection. So the scored pipeline **drops the cert +
`checkSkillDeps` path entirely** and maps detector findings to an outcome by
severity directly.

**Consequence:** the `friction_pct` / `fpr_pct` here are a *floor* measuring
detector precision. A deployed enforce policy has MORE friction than these numbers
show (the coverage-gating review on top). Read them as "how often do the detectors
themselves false-positive", not "how much friction will an operator feel".

## Scoring pipeline (`scoreCase`)

Per case, deterministically and in ENFORCE mode (NEVER throws — a fixture that
throws scores `allow` + a `note`):

1. **Materialize** `fixture.files` into a fresh temp dir as
   `<tmp>/skills/<slug(id)>/<relpath…>`.
2. **Invoke** = `fixture.invoke ?? "bash <firstScript>"`, rewritten to an
   ABSOLUTE command under `skillDir` (so a relative `-r requirements.txt` / index
   URL resolves). Passed only as `scanDependencyMetadata`'s `ctx.command`.
3. **Compile an ENFORCE policy** (skill + deps). See *Policy* below.
4. **Detector scan** (deterministic only): `findings = scanSkill(skillDir, policy.skill).findings
   ∪ scanDependencyMetadata(specs, policy.deps, {command})`, where dependency
   `specs` come from the manifest **files** in the fixture (`parseManifestFile`),
   and the command is passed only as `ctx.command` for the index-URL guard. (The
   command is NOT fed to `parseManifests` for specs — its install-arg parser
   mis-tokenizes a `--index-url <url>` value / env-var prefix as a package, which
   would false-positive `non-registry-source` on a canonical index. Every dep case
   in the corpus declares its specs in a manifest file.)
5. **Outcome** scored DIRECTLY from finding severities (no cert, no coverage
   gating): any `critical`/`high` finding → `deny`; else any `medium` → `review`;
   else (no finding) → `allow`.
6. `detectedKinds` = set of finding kinds present; `detector_hit` = a finding
   whose `kind === expected.detector` fired (named-detector coverage credit).

### Policy (fixed; the corpus is pre-registered against it)

- `mode: enforce`, `severityThreshold: medium` — documentary (the scored outcome
  is the direct severity mapping in step 5, which equals what a medium threshold
  would produce: medium `unpinned` → `review`, high/critical → `deny`).
- `requirePinned: true`; `deny: ["evil-pkg","evilpkg","flatmap-stream","@scope/evil-pkg"]`
  (PEP-503 normalization also matches `evil_pkg`/`Evil.PKG`); `deniedLicenses: ["agpl"]`.
- skill detectors run with the **default (permissive) capability budget** — the
  benign skill cases are pre-registered against it (`maxNetwork true` ⇒ no
  capability finding fires).

### Per-case policy override

A case may carry an OPTIONAL `policy` (or `fixture.policy`) field — a raw policy
fragment that is **deep-merged into the fixed benchmark policy for THAT case only**
(arrays replace; objects recurse), then compiled. This lets a case that needs a
different budget set it without disturbing the rest of the corpus — e.g. a
`skill-capability` THREAT enables a restrictive budget:

```json
"policy": { "skillPolicies": { "capabilityProfile":
  { "maxNetwork": false, "maxFsWrite": false, "maxSubprocess": false, "maxSecretRead": false } } }
```

so its network/subprocess/secret-read use becomes a `capability` finding → `deny`,
while benign network skills (no override) stay on the permissive default and
remain `allow`. With no override a case uses the fixed policy verbatim. This
RESOLVES the capability contradiction (the threats opt into the strict budget
per-case); the harness records how many cases overrode in
`summary.json`-meta's `cases_with_policy_override`. (NOTE: the corpus `schema-sc.json`
is `additionalProperties:false`, so SC-CORPUS must add `policy` to the schema for
override-bearing cases to validate.)

## Metrics (over all scored cases; mirrors the existing `summary.csv` columns)

- `attacks_in_scope` = count(`expected_blocked==true`).
- `coverage_pct` = `blocked && detector_hit && outcome∈{deny,review}` / in-scope
  attacks — **NAMED-detector catches only** (anti-inflation: a prevention with no
  named-detector hit earns zero coverage).
- `prevention_pct` = `blocked && outcome∈{deny,review}` / in-scope attacks.
- `svr_pct` = `1 − prevention` (in-scope attacks not prevented).
- `fpr_pct` = benign `deny` / benign; `friction_pct` = benign `review` / benign.
- Per-CATEGORY rows + an OVERALL row.
- `expected_match_rate_pct` = count(`outcome === expected.outcome`) / total — a
  divergence between the pre-registered expected outcome and the observed one is
  **visible here, not hidden**: a corpus/engine mismatch surfaces at the headline.

## Pieces

- `validate-sc.mjs` — corpus validator (schema-driven: enum/required/id-format
  checks, unique ids, fixture/expected structural invariants).
- `score-sc.mjs` — the scorer (`scoreCase` pipeline above; reads the corpus,
  scores each case in sorted id order, hands off to `report-sc.mjs`).
- `report-sc.mjs` — turns scored rows into the matrix + summary metrics
  (importable; re-runs on rows without re-scoring).
- `make-hash-sc.mjs` — SHA-256 seal of the corpus (`schema-sc.json` + every
  `cases/*.jsonl`) AND the scored `matrix-sc.csv` → `seal-sc.json`; `--check`
  verifies byte-identity.

## Determinism

`matrix-sc.csv`, `summary-sc.csv`, `summary-sc.json`, and `seal-sc.json` are
byte-identical on repeat (decisions + counts only; no timestamps, no wall-clock
anywhere on the scored path — outcome is a pure function of the detector
findings). Each case runs in a fresh temp dir that is deleted afterward. Gate: run
`score-sc` twice and diff the result files, then `make-hash-sc --check`.

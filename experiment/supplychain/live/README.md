# Supply-chain LIVE CVE-detection track

This is the **LIVE** (non-sealed, point-in-time) track for the supply-chain
benchmark. It is the direct analog of the main benchmark's "native is live-only"
split: where the sealed corpus measures the *deterministic Tier-1 metadata* path
(byte-stable, hashable), this track measures whether the AGT governance plugin's
**real Tier-2 vulnerability-scanner path actually catches known-vulnerable
dependencies end-to-end**.

Because Tier-2 shells out to a vulnerability scanner whose vuln DB changes over
time, the result is **NOT byte-sealed**. Every run is stamped with the scanner
name, its DB version, and the date, and the numbers are *expected* to drift as
the scanner DBs update. See "Determinism caveat" below.

## What is actually under test

`score-sc-live.mjs` imports the **shipped plugin code** and drives it — it does
not reimplement scanner invocation:

```js
import {
  runVulnScanner, resolveTransitive, scannerDbVersion, parseManifestFile,
} from "../../../plugins/agt-governance/scripts/deps.mjs";
```

> Path note: the canonical shipped plugin lives at
> `agt-claude-code/plugins/agt-governance/scripts/deps.mjs`, which is
> `../../../plugins/...` from this `live/` directory (three levels up:
> `live/` → `supplychain/` → `experiment/` → `agt-claude-code/`). Validating the
> real shipped orchestration is the entire point of this track.

For each fixture the scorer runs the same path the plugin's proactive audit
command uses:

1. `parseManifestFile(<manifest>)` — parse the declared/locked set.
2. `resolveTransitive(declared, { cwd })` — read the resolved set from a lockfile
   when present; report `fromLockfile`.
3. `runVulnScanner(resolved, { cwd, scannerCmd, fromLockfile })` — auto-detect /
   force the scanner, spawn it, parse its JSON into the plugin's common finding
   shape `{ id, severity, package, fixedVersion, source }`.

## Fixtures

`fixtures/fixtures.json` is the source of truth; each entry points at a directory
under `fixtures/` holding a real manifest.

**Known-vulnerable (expect ≥1 high/critical):**

| fixture | ecosystem | manifest | packages |
|---|---|---|---|
| `py-jinja2-2.10` | pypi | requirements.txt | `jinja2==2.10` |
| `py-pyyaml-5.1` | pypi | requirements.txt | `PyYAML==5.1` |
| `py-requests-2.19.1` | pypi | requirements.txt | `requests==2.19.1` |
| `py-urllib3-1.24.1` | pypi | requirements.txt | `urllib3==1.24.1` |
| `py-flask-0.12` | pypi | requirements.txt | `Flask==0.12` |
| `py-mixed-vuln` | pypi | requirements.txt | all five above |
| `npm-lodash-4.17.4` | npm | package-lock.json | `lodash@4.17.4` |
| `npm-minimist-1.2.0` | npm | package-lock.json | `minimist@1.2.0` |
| `npm-node-fetch-2.6.0` | npm | package-lock.json | `node-fetch@2.6.0` |
| `npm-mixed-vuln` | npm | package-lock.json | lodash + minimist + node-fetch |

**Clean / true-negative (expect 0 high/critical):**

| fixture | ecosystem | packages | why clean |
|---|---|---|---|
| `clean-py-pinned` | pypi | `jinja2==3.1.6`, `requests==2.32.3`, `certifi==2024.8.30` | recent pins, no known high/critical at authoring (medium/low allowed) |
| `clean-npm-pinned` | npm | `chalk@5.3.0`, `ms@2.1.3` | zero known advisories of any severity at authoring |
| `clean-py-stdlib-only` | pypi | (none) | comment-only requirements.txt — empty-input path |

The npm fixtures ship both a `package.json` and a minimal lockfile-v3
`package-lock.json` so the resolved version is unambiguous and trivy/osv-scanner
get a resolved tree to scan (`coverage: full`). The python fixtures are
`requirements.txt` (the declared set; `coverage: declared-only`).

Each `expect` block documents representative CVEs/advisories that were
known-present for that package@version at authoring time. The **scoring contract
is at the severity-band level** (≥1 high/critical for vulnerable, 0 high/critical
for clean) — **not** an exact-CVE-id match, because the exact IDs and counts move
as DBs update.

## How to run

The scanners are not on the default PATH and pip-audit needs `truststore` on this
TLS-intercepting machine. Set both before invoking; the plugin spawns scanners by
bare name (`shell:false`), so they must be resolvable on `PATH`, and the child
inherits `PYTHONPATH`:

```bash
export PATH="/d/work/claude_code_governance/.tools/bin:/c/Users/vilmo/AppData/Roaming/Python/Python314/Scripts:$PATH"
export PYTHONPATH="/d/work/claude_code_governance/.tools/pyssl"   # sitecustomize injects truststore for pip-audit
cd agt-claude-code/experiment/supplychain/live
node score-sc-live.mjs --date 2026-06-19
```

Flags:

- `--date YYYY-MM-DD` — stamp date for the results file (default: today).
- `--scanner trivy|osv-scanner|pip-audit` — measure only one scanner (default: all installed).
- `--timeout-ms N` — per-scan timeout (default 120000).
- `--no-write` — print the table but write no JSON.

Output: a per-scanner table + a headline to stdout, and a stamped JSON to
`results-live/live-<date>-<scanner|all>.json`.

trivy and osv-scanner run offline against a local DB and finish in seconds.
**pip-audit makes a network call to OSV/PyPI per fixture** (~30–45s each through
the corporate proxy), so the full `all` run takes a few minutes — that is
network latency, not a hang.

## Scoring rules (and the pip-audit honesty caveat)

- **vulnerable fixture → caught** when the scanner returns **≥1 high/critical**.
- **clean fixture → clean** when the scanner returns **0 high/critical**.
- **coverage %** = vulnerable caught / vulnerable **measured**. A fixture a
  scanner could not run on (e.g. empty input it rejects, or a DB-fetch error) is
  reported **"not measured"** and excluded from the denominator — it is *never*
  counted as a miss.

**pip-audit caveat (built into the scoring):** pip-audit's JSON omits a per-vuln
severity field, so the plugin's `parsePipAuditJson` maps every pip-audit finding
to `medium` (`mapSeverity(v.severity ?? "medium")`). pip-audit therefore can
**never** emit a high/critical band through the plugin path. Scoring it on the
strict ≥1-high/critical rule would unfairly report 0% coverage. So for
**pip-audit only**, "caught" is relaxed to **≥1 finding of any severity**, and
the table/headline label this explicitly. trivy and osv-scanner carry real
CVSS-derived severities (the plugin computes the CVSS base score from the OSV
vector) and are held to the strict high/critical rule. pip-audit also reads only
the declared requirements set, so its coverage is reported `declared-only`.

## Results (point-in-time)

Captured **2026-06-19** on this machine. Scanner DB versions are recorded in the
stamped JSON under `results-live/`.

Stamped result: `results-live/live-2026-06-19-all.json`.

| scanner | DB / version | rule | vulnerable caught / measured | coverage | true-neg clean / measured | false-pos | not measured |
|---|---|---|---|---|---|---|---|
| trivy 0.71.1 | DB v2, updated 2026-06-18 | high/critical | 10 / 10 | **100%** | 3 / 3 | 0 | 0 |
| osv-scanner 2.4.0 | scalibr 0.4.5, built 2026-06-18 | high/critical | 10 / 10 | **100%** | 2 / 2 | 0 | 1 (stdlib-only) |
| pip-audit 2.10.1 | OSV/PyPI live, any-severity rule | any-severity | 5 / 5 | **100%** | 1 / 2 | 1 | 6 (5 npm + py-mixed) |

Headlines (verbatim from the run):

> trivy: Tier-2 catches **10/10** known-vulnerable fixtures (high/critical, coverage 100%); true-neg 3/3 clean; DB Version: 0.71.1; date 2026-06-19
> osv-scanner: Tier-2 catches **10/10** known-vulnerable fixtures (high/critical, coverage 100%); true-neg 2/2 clean; DB osv-scanner version: 2.4.0; date 2026-06-19
> pip-audit: Tier-2 catches **5/5** known-vulnerable fixtures (any-severity, coverage 100%); true-neg 1/2 clean; DB pip-audit 2.10.1; date 2026-06-19

Notes on the captured run (the honest details):

- **trivy** and **osv-scanner** both caught **all 10** known-vulnerable fixtures
  (100% coverage) and produced **0 false positives** on the clean fixtures.
  They scan the declared/locked versions statically, so the npm lockfiles and the
  multi-package python manifest are all covered.
- **osv-scanner → `clean-py-stdlib-only` = not measured**: it returns no
  scannable result for a comment-only `requirements.txt`, so the plugin degrades
  it to `available:false` rather than inventing a clean pass. Honest
  "unavailable, not measured", not a miss.
- **pip-audit is python-only** — it has no scannable input in the npm fixture
  directories (no `requirements.txt`), so the plugin skips them ("no scannable
  input … skipping rather than auditing the ambient environment"). The 5 npm
  fixtures and `clean-npm-pinned` are therefore "not measured" for pip-audit, not
  misses. Of the python fixtures it can scan, it caught **5/5** single-package
  vulnerable fixtures.
- **pip-audit → `py-mixed-vuln` = not measured (real, deterministic)**: unlike
  trivy/osv, pip-audit *resolves* the dependency set via pip before auditing. The
  `py-mixed-vuln` manifest pins a combination (`requests==2.19.1` +
  `urllib3==1.24.1` + `Flask==0.12`) that pip finds mutually unsatisfiable
  (`ResolutionImpossible`), so pip-audit emits no JSON and the plugin reports
  "could not be parsed → not measured." This is a genuine scanner behavioral
  difference (static manifest scan vs. resolver-backed audit), surfaced honestly
  rather than scored as a miss. The fixture is kept as-is because it documents
  that difference.
- **pip-audit → `clean-py-pinned` = false-positive (expected artifact)**: under
  the relaxed any-severity rule, pip-audit's 2 *medium* findings on the
  recent-pinned python set trip the "caught/positive" test. Those same findings
  are correctly *medium* (not high/critical), so trivy and osv pass the fixture as
  clean. This false-positive is purely an artifact of pip-audit being unable to
  emit a severity band; it is **not** a sign the pins are high-risk. The clean
  contract (0 high/critical) is met by both severity-carrying scanners.

The headline form printed by the scorer:

> `Tier-2 catches N/M known-vulnerable fixtures (scanner X, DB date Y)`

## Determinism caveat (why this is not sealed)

This track is intentionally **not byte-sealed**:

- Findings depend on each scanner's vuln DB, which updates continuously. Re-running
  on a different day or DB version can change finding counts and may flip a
  borderline fixture. (Example observed while authoring: `lodash@4.17.21` — long
  considered "latest safe" — picked up a 2026 HIGH CVE, and `uuid@9.0.1` picked up
  a 2026 MEDIUM. Clean fixtures may need re-pinning over time.)
- Scoring is therefore done at the **severity-band level**, not exact-CVE-id
  match, and the clean-fixture contract is **0 high/critical** (medium/low are
  tolerated).
- Every results file is stamped with `scanner`, `dbVersion`, `date`, `node`, and
  the plugin source path so any number can be traced to the exact tool state that
  produced it.

If a future advisory raises one of the clean fixtures' pins to high/critical,
that fixture must be re-pinned to a then-current safe version (and this README's
results table re-captured).

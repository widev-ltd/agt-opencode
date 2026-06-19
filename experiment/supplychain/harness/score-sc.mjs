// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// score-sc.mjs — run the DETERMINISTIC supply-chain detectors over the
// supply-chain corpus and build the prevention matrix + summary metrics. One row
// per case; the measured decision is scored DIRECTLY from the detector findings
// (skills.scanSkill + deps.scanDependencyMetadata) in ENFORCE mode — NO
// vulnerability scanner, NO network.
//
// WHY SCORE FROM FINDINGS DIRECTLY (lead ruling): this benchmark measures
// DETECTOR ACCURACY — did a detector fire, and at what severity. The real runtime
// gate (checkSkillDeps) additionally routes through an attestation cert +
// decideFromFindings, which COVERAGE-GATES the verdict ("review-until-vuln-
// scanned"). That conflates "was it vuln-scanned" (a policy/coverage concern)
// with "did a detector fire" (this benchmark's subject), and would push every
// benign skill to review. So we DROP the cert + checkSkillDeps path from the
// scored pipeline and map detector findings to an outcome by severity, MINUS the
// coverage penalty. (The README documents that a deployed enforce gate therefore
// has MORE friction than this detector-accuracy floor shows.)
//
// HONESTY MODEL (mirrors ../../harness/score.mjs + report.mjs discipline):
//   Every case carries BOTH the OBSERVED decision and the corpus's PRE-REGISTERED
//   expected outcome, so a hypothesis can never masquerade as a measurement. A
//   divergence is surfaced as the expected-outcome match rate (NOT hidden), so a
//   corpus/detector mismatch is visible at the headline. Coverage credit is
//   NAMED-detector-only (no inflation): an attack counts as covered only when a
//   finding whose kind === expected.detector fired AND the outcome prevented
//   (deny|review).
//
// SCORING PIPELINE (scoreCase):
//   1. Materialize fixture.files into a fresh per-case temp dir laid out as
//      <tmp>/skills/<slug>/<relpath...>.
//   2. skillDir = <tmp>/skills/<slug>. invoke = fixture.invoke ?? `bash <firstScript>`,
//      rewritten to an ABSOLUTE command referencing skillDir (so deps parsing of a
//      relative `-r requirements.txt` / index-URL resolves correctly).
//   3. Compile an ENFORCE policy (skill + deps, severityThreshold medium,
//      requirePinned, fixed deny/denied-license lists).
//   4. findings = scanSkill(skillDir, policy.skill).findings ∪
//      scanDependencyMetadata(specs, policy.deps, {command:invoke}), where deps
//      specs come from the manifest FILES in the fixture (parseManifestFile).
//   5. outcome = severity-based DIRECTLY from findings: any critical/high → "deny";
//      else any medium → "review"; else (no finding) → "allow". (Same severity
//      mapping depsDecision/decideFromFindings use, MINUS the coverage penalty.)
//   6. detectedKinds = set of finding kinds present; detector_hit = a finding whose
//      kind === expected.detector fired (named-detector coverage credit).
//   A fixture that throws scores outcome:"allow" + a note (never crashes the run).
//
// Usage:
//   node score-sc.mjs [--corpus <dir|file>] [--out <dir>]
// Defaults: ../corpus/cases  ->  ../results-sc

import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

import { compilePolicy } from "../../../plugin/src/policy.mjs";
import { scanSkill } from "../../../plugin/src/skills.mjs";
import { parseManifestFile, scanDependencyMetadata } from "../../../plugin/src/deps.mjs";

import { writeReports } from "./report-sc.mjs";

// Severity rank for the direct findings→outcome mapping (matches deps.mjs /
// attestation.mjs SEVERITY_ORDER). info/low never reach the medium threshold.
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Map a finding set to a gate outcome by SEVERITY DIRECTLY (no coverage gating):
 *   any critical/high finding -> "deny";  else any medium -> "review";  else "allow".
 * This is the severity mapping depsDecision/decideFromFindings use at a medium
 * threshold, MINUS the "review-until-vuln-scanned" coverage penalty — so a clean
 * skill is "allow" (no detector fired) rather than friction.
 */
function outcomeFromFindings(findings) {
  let max = 0;
  for (const f of findings) {
    const r = SEVERITY_RANK[f?.severity] ?? 0;
    if (r > max) max = r;
  }
  if (max >= SEVERITY_RANK.high) return "deny";
  if (max >= SEVERITY_RANK.medium) return "review";
  return "allow";
}

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPERIMENT_SC = resolve(HERE, "..");

// Secret-fixture placeholders. The corpus stores a PLACEHOLDER (not a contiguous
// provider token) so the committed .jsonl never trips GitHub secret/push
// protection. The scorer expands it to a real-SHAPED synthetic token ONLY in the
// materialized temp file, so the secret detector still has a contiguous token to
// match. The token strings here are assembled by concatenation so THIS file
// likewise carries no contiguous provider token (push-safe). Values are
// synthetic/non-functional (Slack/Stripe docs-style), not live credentials.
const SC_TOKEN_PLACEHOLDERS = {
  "<<SC_SLACK_BOT_TOKEN>>": "xox" + "b-2488300-abcdEFGH1234ijklMNOP",
  "<<SC_STRIPE_LIVE_KEY>>": "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc",
};
function expandFixtureContent(s) {
  let out = String(s ?? "");
  for (const [k, v] of Object.entries(SC_TOKEN_PLACEHOLDERS)) {
    if (out.includes(k)) out = out.split(k).join(v);
  }
  return out;
}

// FIXED policy the corpus is authored against (coordinated via case rationale).
// Deny list catches the denied-package fixtures: "evil-pkg" (+ PEP-503 variants
// evil_pkg / Evil.PKG), the historical "flatmap-stream" compromise vector, and
// the scoped npm-alias target "@scope/evil-pkg". denied-license catches license
// fixtures (none in the corpus yet, kept for forward-compatibility).
const POLICY_DENY = ["evil-pkg", "evilpkg", "flatmap-stream", "@scope/evil-pkg"];
const POLICY_DENIED_LICENSES = ["agpl"];
// severityThreshold MEDIUM matches the corpus pre-registration (a medium
// `unpinned` finding -> review; high/critical -> deny). NOTE: the SCORED outcome
// is computed by outcomeFromFindings() (the direct severity mapping above), NOT
// by the compiled policy threshold — compileSkillPolicy ignores severityThreshold
// entirely, and we never call depsDecision/decideFromFindings on the scored path.
// This constant is therefore documentary (it records the intended threshold and
// is echoed into summary-sc.json's policy block) and is kept equal to the mapping
// the scorer actually applies.
const POLICY_SEVERITY_THRESHOLD = "medium";

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith("--")) {
      out[a.slice(2)] = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[(i += 1)] : true;
    }
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const corpusPath = resolve(args.corpus ?? join(EXPERIMENT_SC, "corpus", "cases"));
const outDir = resolve(args.out ?? join(EXPERIMENT_SC, "results-sc"));

// The fixed benchmark policy in RAW form (the input to compilePolicy). Kept raw
// so a per-case override can be DEEP-MERGED at the raw level before compilation —
// deep-merging COMPILED policies (Sets, compiled regexes) would be fragile.
//
// skill detectors run with the DEFAULT (permissive) capability budget: the
// corpus's BENIGN skill cases pin it explicitly ("maxNetwork true so NO
// capability finding fires"). A case that needs a stricter budget (e.g. the
// skill-capability THREATs) supplies a per-case override (see policyForCase) that
// flips just its own capabilityProfile — leaving benign network skills untouched.
export const BASE_POLICY_RAW = {
  skillPolicies: {
    enabled: true,
    mode: "enforce",
    severityThreshold: POLICY_SEVERITY_THRESHOLD,
  },
  dependencyPolicies: {
    enabled: true,
    mode: "enforce",
    severityThreshold: POLICY_SEVERITY_THRESHOLD,
    requirePinned: true,
    deny: POLICY_DENY,
    deniedLicenses: POLICY_DENIED_LICENSES,
  },
};

// Compile the fixed ENFORCE policy (case-independent default).
export function buildPolicy() {
  return compilePolicy(BASE_POLICY_RAW);
}

// Deep-merge plain objects (override wins). Arrays are REPLACED wholesale (not
// concatenated) so an override can fully redefine e.g. a deny list; objects
// recurse. Used only to fold a per-case policy override into BASE_POLICY_RAW.
function deepMerge(base, override) {
  if (!isPlainObject(base) || !isPlainObject(override)) return override;
  const out = { ...base };
  for (const k of Object.keys(override)) {
    const b = base[k];
    const o = override[k];
    out[k] = isPlainObject(b) && isPlainObject(o) ? deepMerge(b, o) : o;
  }
  return out;
}
function isPlainObject(v) {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

// Resolve the policy for one case: the fixed benchmark policy unless the case
// carries an OPTIONAL override (case.policy or case.fixture.policy), in which case
// the override's RAW policy fields are deep-merged into BASE_POLICY_RAW and the
// result compiled — for THAT case only. The override is expressed in raw policy
// shape (e.g. { skillPolicies: { capabilityProfile: { maxNetwork: false, … } } }),
// so a capability case can enable a restrictive budget without touching benign
// network skills. Returns { policy, overridden:boolean }.
export function policyForCase(kase) {
  const override = (kase && isPlainObject(kase.policy)) ? kase.policy
    : (kase?.fixture && isPlainObject(kase.fixture.policy)) ? kase.fixture.policy
    : null;
  if (!override) return { policy: buildPolicy(), overridden: false };
  return { policy: compilePolicy(deepMerge(BASE_POLICY_RAW, override)), overridden: true };
}

// kebab-slug a case id for a safe on-disk skill dir name.
function slug(id) {
  return String(id).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "skill";
}

// Find the first script-like file in the fixture (for the default invoke).
const SCRIPT_EXT_RE = /\.(sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|ps1|bat|cmd)$/i;
function firstScript(files) {
  const keys = Object.keys(files).sort(); // deterministic
  return keys.find((k) => SCRIPT_EXT_RE.test(k)) ?? keys[0];
}

// Recognized dependency-manifest basenames (mirrors deps.parseManifestFile's
// dispatch + skills.collectManifestSpecs). A *.py file may carry a PEP-723 inline
// block, so it is parsed too. Other files are left to the skill body scan.
function isManifestRel(rel) {
  const base = String(rel).split(/[\\/]/).pop().toLowerCase();
  return (
    base === "requirements.txt" || base.startsWith("requirements") || base.startsWith("constraints") ||
    base === "pyproject.toml" || base === "uv.lock" || base === "poetry.lock" ||
    base === "package.json" || base === "package-lock.json" || base.endsWith(".py")
  );
}

// Parse every dependency manifest FILE present in the fixture into canonical
// specs (the command-string parse in parseManifests does NOT read files). Keys
// are walked in SORTED order so the spec list — and any analysis-truncated note —
// is deterministic. NEVER throws (parseManifestFile is total).
function collectManifestFileSpecs(skillDir, files) {
  const out = [];
  for (const rel of Object.keys(files).sort()) {
    if (String(rel).includes("..") || /^([a-zA-Z]:)?[\\/]/.test(rel)) continue;
    if (!isManifestRel(rel)) continue;
    const specs = parseManifestFile(join(skillDir, rel));
    if (Array.isArray(specs)) out.push(...specs);
  }
  return out;
}

/**
 * Score ONE case deterministically. Returns:
 *   { id, category, expected_blocked, expected, outcome, detectedKinds, detector_hit, policy_override?, note? }
 * NEVER throws — a fixture that throws scores outcome:"allow" with a note.
 *
 * @param {object} kase       the corpus case
 * @param {object} basePolicy the compiled fixed benchmark policy (reused for the
 *   common no-override case so we don't recompile per case). A case carrying a
 *   `policy`/`fixture.policy` override gets its OWN compiled policy via policyForCase.
 */
export async function scoreCase(kase, basePolicy) {
  const id = String(kase?.id ?? "unknown");
  const category = String(kase?.category ?? "");
  const expected = kase?.expected ?? { detector: "", outcome: "allow" };
  const expected_blocked = kase?.expected_blocked === true;
  const base = { id, category, expected_blocked, expected };

  // Per-case policy: the fixed benchmark policy unless the case overrides it.
  const resolved = policyForCase(kase);
  const policy = resolved.overridden ? resolved.policy : (basePolicy ?? resolved.policy);
  const policy_override = resolved.overridden;

  let tmp;
  try {
    // 1. Fresh temp dir laid out as <tmp>/skills/<slug>/<relpath…>.
    tmp = mkdtempSync(join(tmpdir(), "agt-sc-"));
    const s = slug(id);
    const skillDir = join(tmp, "skills", s);
    const files = (kase?.fixture?.files && typeof kase.fixture.files === "object") ? kase.fixture.files : {};
    for (const [rel, content] of Object.entries(files)) {
      // Defensive: refuse traversal / absolute (validator already rejects these).
      if (String(rel).includes("..") || /^([a-zA-Z]:)?[\\/]/.test(rel)) continue;
      const dest = join(skillDir, rel);
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, expandFixtureContent(content), "utf8");
    }

    // 2. Build the invocation command (passed only as scanDependencyMetadata's
    //    ctx.command, for the index-URL guard). A relative fixture.invoke is
    //    absolutized under skillDir so a `-r requirements.txt` operand resolves.
    let invoke;
    if (typeof kase?.fixture?.invoke === "string" && kase.fixture.invoke.trim()) {
      invoke = absolutizeInvoke(kase.fixture.invoke, skillDir);
    } else {
      const fs0 = firstScript(files);
      invoke = `bash ${join(skillDir, fs0 ?? "run.sh")}`;
    }

    // 4. DETECTOR scan (deterministic; skill static analysis + Tier-1 dep metadata).
    const scan = await scanSkill(skillDir, policy.skill);
    const skillFindings = Array.isArray(scan?.findings) ? scan.findings : [];

    // Dependency SPECS come ONLY from the manifest FILES in the fixture. The
    // command is passed solely as `ctx.command` so the index-URL guard
    // (scanIndexUrls) still flags an untrusted --index-url/--registry. We do NOT
    // feed the command through parseManifests for specs: its install-arg parser
    // mis-captures a `--index-url <url>` VALUE (or an env-var prefix) as a
    // positional package spec, which would falsely raise non-registry-source on a
    // canonical index (the corpus's benign-dep cases carry exactly such canonical-
    // index commands). Every dep case in the corpus declares its specs in a
    // manifest file, so command-spec parsing is pure downside here.
    const specs = collectManifestFileSpecs(skillDir, files);
    const depFindings = scanDependencyMetadata(specs, policy.deps, { command: invoke }) ?? [];
    const findings = [...skillFindings, ...depFindings];

    // 5. outcome scored DIRECTLY from finding severities (no attestation cert, no
    //    coverage gating): critical/high -> deny; medium -> review; none -> allow.
    const outcome = outcomeFromFindings(findings);

    // 6. detectedKinds + named-detector hit.
    const detectedKinds = [...new Set(findings.map((f) => String(f.kind)))].sort();
    const detector_hit = expected.detector !== "" && detectedKinds.includes(expected.detector);

    return { ...base, outcome, detectedKinds, detector_hit, policy_override };
  } catch (err) {
    // A fixture that throws must score allow + a note (never crash the run).
    return {
      ...base,
      outcome: "allow",
      detectedKinds: [],
      detector_hit: false,
      policy_override,
      note: `scoreCase error (scored allow): ${err?.message ?? err}`,
    };
  } finally {
    if (tmp) {
      try { rmSync(tmp, { recursive: true, force: true }); } catch { /* best-effort cleanup */ }
    }
  }
}

// Rewrite a fixture.invoke so any relative script operand becomes an absolute path
// under skillDir (so checkSkillInvocationMeta's skills-segment match fires). We
// only rewrite path-shaped operands; the interpreter token (bash/python/…) and
// flags are left alone. A path already absolute or already under skillDir is kept.
function absolutizeInvoke(invoke, skillDir) {
  const cmd = String(invoke);
  return cmd.replace(/(^|[\s])((?:\.\/)?[\w][\w./@-]*\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|ps1|bat|cmd))\b/gi, (m, pre, p) => {
    const rel = p.replace(/^\.\//, "");
    // If it already contains an absolute drive/root, leave it.
    if (/^([a-zA-Z]:)?[\\/]/.test(p)) return m;
    return `${pre}${join(skillDir, rel)}`;
  });
}

async function readJsonl(path) {
  const text = readFileSync(path, "utf8");
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l, i) => {
      try {
        return JSON.parse(l);
      } catch (e) {
        throw new Error(`${path}: line ${i + 1} is not valid JSON: ${e.message}`);
      }
    });
}

// Read the corpus from a single .jsonl file OR a directory of .jsonl files, in
// SORTED filename order so the combined case list — and therefore matrix-sc.csv —
// is byte-stable across machines.
async function readCorpus(path) {
  if (existsSync(path) && statSync(path).isDirectory()) {
    const files = readdirSync(path).filter((f) => f.endsWith(".jsonl")).sort();
    const cases = [];
    for (const f of files) cases.push(...(await readJsonl(join(path, f))));
    return { cases, files: files.map((f) => join(path, f)) };
  }
  if (existsSync(path)) return { cases: await readJsonl(path), files: [path] };
  return { cases: [], files: [] };
}

async function main() {
  const { cases, files } = await readCorpus(corpusPath);
  const policy = buildPolicy();

  // Score in SORTED id order so the matrix rows are byte-stable regardless of the
  // order cases appear across files.
  const sorted = cases.slice().sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const rows = [];
  for (const kase of sorted) {
    rows.push(await scoreCase(kase, policy));
  }

  const meta = {
    corpus: corpusPath.replace(/\\/g, "/"),
    corpusFiles: files.map((f) => f.replace(/\\/g, "/")),
    cases: rows.length,
    policy: {
      mode: "enforce",
      severityThreshold: POLICY_SEVERITY_THRESHOLD,
      requirePinned: true,
      deny: POLICY_DENY,
      deniedLicenses: POLICY_DENIED_LICENSES,
    },
    // Number of cases that supplied a per-case policy override (case.policy /
    // fixture.policy) deep-merged into the fixed policy for that case only.
    cases_with_policy_override: rows.filter((r) => r.policy_override).length,
    scoring: "detector-accuracy: outcome mapped DIRECTLY from finding severities (critical/high->deny, medium->review, none->allow). No attestation cert, no coverage gating. A case may carry an optional policy override (case.policy/fixture.policy) deep-merged into the fixed policy for that case only.",
    note: "Deterministic supply-chain track: scanSkill + Tier-1 deps (scanDependencyMetadata over manifest-file specs) in enforce mode. No vuln scanner, no network. A deployed enforce gate adds review-until-vuln-scanned friction NOT measured here (see README).",
  };
  return { meta, rows, outDir };
}

// Run as a CLI ONLY when invoked directly (node score-sc.mjs …). Guarded so the
// exported helpers (scoreCase/policyForCase/buildPolicy) can be imported by a
// test without triggering a full corpus run + result writes.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await main();
  const summary = await writeReports(result);
  console.log(
    `[score-sc] ${result.rows.length} cases scored; matrix + summary written to ${result.outDir} ` +
    `(coverage=${summary.overall.coverage_pct ?? "—"}% prevention=${summary.overall.prevention_pct ?? "—"}% ` +
    `expected-match=${summary.expected_match_rate_pct ?? "—"}%)`,
  );
}

// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// validate-sc.mjs — supply-chain corpus validator. Runs over every case file in
// ../corpus/cases/*.jsonl (SORTED filename order), asserting against the
// pre-registered schema (../corpus/schema-sc.json):
//   - JSON well-formed, one object per line
//   - required schema fields present; category/track/severity/detector/outcome in
//     enum; id format matches the schema pattern; source.origin/license in enum
//   - fixture.files is a non-empty {relpath: string} map
//   - globally-unique ids across ALL files
//   - structural invariants tying expected_blocked to expected.outcome/detector:
//       * benign (expected_blocked:false) must have detector:"" and outcome
//         "allow" OR "review" — review = honest enforce-policy FRICTION (e.g.
//         requirePinned:true flags a benign version RANGE), counted as friction_pct
//         not FPR; a benign "deny" would be a declared false positive (rejected)
//       * a KNOWN-GAP threat (expected_blocked:true, outcome:"allow") must have
//         detector:"" (an honest miss names no detector)
//       * a blocked threat (outcome:deny|review) must name a non-empty detector
//
// Prints "Cases: N  Violations: 0" and exits non-zero on any violation. The
// scorer (score-sc.mjs) reads the same files the same way, so a corpus that
// validates here is a corpus the scorer can score.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPERIMENT_SC = join(HERE, "..");
const CASES_DIR = join(EXPERIMENT_SC, "corpus", "cases");
const SCHEMA_PATH = join(EXPERIMENT_SC, "corpus", "schema-sc.json");

if (!existsSync(SCHEMA_PATH)) {
  console.error(`MISSING schema: ${SCHEMA_PATH}`);
  process.exit(2);
}
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

const REQUIRED = schema.required ?? [
  "id", "category", "track", "source", "severity", "expected_blocked", "fixture", "expected", "rationale",
];
const CATS = new Set(schema.properties.category.enum);
const TRACKS = new Set(schema.properties.track.enum);
const SEVERITIES = new Set(schema.properties.severity.enum);
const DETECTORS = new Set(schema.properties.expected.properties.detector.enum);
const OUTCOMES = new Set(schema.properties.expected.properties.outcome.enum);
const ORIGINS = new Set(schema.properties.source.properties.origin.enum);
const LICENSES = new Set(schema.properties.source.properties.license.enum);
const ID_RE = new RegExp(schema.properties.id.pattern ?? "^sc-[a-z0-9]+(?:-[a-z0-9]+)*$");

// Read the corpus in SORTED filename order (readdir order is filesystem-
// dependent) so validation — and the scorer's case order — is byte-stable.
const files = existsSync(CASES_DIR)
  ? readdirSync(CASES_DIR).filter((f) => f.endsWith(".jsonl")).sort().map((f) => join(CASES_DIR, f))
  : [];

const ids = new Map();
let n = 0;
let v = 0;
const byCat = {};
const fail = (msg) => { console.log("  VIOLATION: " + msg); v++; };

if (files.length === 0) {
  console.log(`  NOTE: no case files found under ${CASES_DIR}`);
}

for (const file of files) {
  const short = file.split(/[\\/]/).slice(-1)[0];
  const lines = readFileSync(file, "utf8").split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw.trim()) continue; // blank line (e.g. trailing newline) — skip silently
    let o;
    try {
      o = JSON.parse(raw);
    } catch (e) {
      fail(`${short}:${i + 1} bad JSON: ${e.message}`);
      continue;
    }
    n++;
    const where = o.id ?? `${short}:${i + 1}`;

    for (const k of REQUIRED) {
      if (!(k in o)) fail(`${where} missing field ${k}`);
    }

    if (!ID_RE.test(o.id ?? "")) fail(`${where} bad id format: ${o.id}`);
    if (ids.has(o.id)) fail(`DUP id ${o.id} (also in ${ids.get(o.id)})`); else ids.set(o.id, short);

    if (!CATS.has(o.category)) fail(`${where} category not in enum: ${o.category}`);
    if (!TRACKS.has(o.track)) fail(`${where} track not in enum: ${o.track}`);
    if (!SEVERITIES.has(o.severity)) fail(`${where} severity not in enum: ${o.severity}`);
    if (typeof o.expected_blocked !== "boolean") fail(`${where} expected_blocked not boolean`);

    // source
    if (!o.source || typeof o.source !== "object") {
      fail(`${where} source missing/not an object`);
    } else {
      if (!ORIGINS.has(o.source.origin)) fail(`${where} source.origin not in enum: ${o.source.origin}`);
      if (!LICENSES.has(o.source.license)) fail(`${where} source.license not in enum: ${o.source.license}`);
    }

    // fixture.files: non-empty map of relpath -> string
    const files_ = o.fixture?.files;
    if (!files_ || typeof files_ !== "object" || Array.isArray(files_)) {
      fail(`${where} fixture.files missing or not an object`);
    } else {
      const keys = Object.keys(files_);
      if (keys.length === 0) fail(`${where} fixture.files is empty`);
      for (const k of keys) {
        if (typeof files_[k] !== "string") fail(`${where} fixture.files["${k}"] is not a string`);
        if (k.includes("..")) fail(`${where} fixture.files path "${k}" contains "..": refused (path traversal)`);
        if (/^([a-zA-Z]:)?[\\/]/.test(k)) fail(`${where} fixture.files path "${k}" is absolute: must be relative`);
      }
    }
    if (o.fixture && "invoke" in o.fixture && typeof o.fixture.invoke !== "string") {
      fail(`${where} fixture.invoke present but not a string`);
    }

    // expected.{detector,outcome}
    const exp = o.expected;
    if (!exp || typeof exp !== "object") {
      fail(`${where} expected missing/not an object`);
    } else {
      if (!DETECTORS.has(exp.detector)) fail(`${where} expected.detector not in enum: ${exp.detector}`);
      if (!OUTCOMES.has(exp.outcome)) fail(`${where} expected.outcome not in enum: ${exp.outcome}`);

      // ── Structural invariants tying ground truth to the expected decision ──
      if (o.expected_blocked === false) {
        // Benign: must NOT be a hard deny (a pre-registered benign DENY would be a
        // declared false positive — not allowed). allow = clean; review = honest
        // FRICTION (e.g. requirePinned:true flags a benign version RANGE), tracked
        // as friction_pct, not FPR. detector stays "" (benign earns no coverage).
        if (exp.outcome !== "allow" && exp.outcome !== "review") fail(`${where} benign (expected_blocked:false) must have expected.outcome "allow" or "review", got "${exp.outcome}"`);
        if (exp.detector !== "") fail(`${where} benign (expected_blocked:false) must have expected.detector "" , got "${exp.detector}"`);
      } else {
        // A blocked threat names a detector; a known-gap miss (outcome allow) does not.
        if (exp.outcome === "allow" && exp.detector !== "") {
          fail(`${where} KNOWN-GAP threat (outcome:allow) must have empty detector, got "${exp.detector}"`);
        }
        if ((exp.outcome === "deny" || exp.outcome === "review") && exp.detector === "") {
          fail(`${where} blocked threat (outcome:${exp.outcome}) must name a non-empty detector`);
        }
      }
    }

    if (typeof o.rationale !== "string" || o.rationale.length < 20) {
      fail(`${where} rationale missing or shorter than 20 chars`);
    }

    byCat[o.category] = (byCat[o.category] || 0) + 1;
  }
}

const catLine = Object.keys(byCat).sort().map((c) => `${c}=${byCat[c]}`).join("  ");
if (catLine) console.log(`  By category: ${catLine}`);
console.log(`Cases: ${n}  Violations: ${v}`);
process.exit(v === 0 ? 0 : 1);

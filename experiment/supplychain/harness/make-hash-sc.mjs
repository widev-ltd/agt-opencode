// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// make-hash-sc.mjs — SHA-256 seal over the supply-chain corpus (schema-sc.json +
// every cases/*.jsonl) AND the scored matrix (results-sc/matrix-sc.csv). Writes
// results-sc/seal-sc.json. Run with --check to verify instead of write (CI / a
// determinism gate: fail if the seal is stale or the inputs drifted).
//
// The matrix is sealed alongside the corpus because the matrix is the
// deterministic SCORING artifact — a byte-identical re-score of the same corpus
// must reproduce the same matrix hash. summary-sc.csv/json are derived from the
// matrix and are not separately sealed (a matrix match implies them).

import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPERIMENT_SC = resolve(HERE, "..");
const CASES_DIR = join(EXPERIMENT_SC, "corpus", "cases");
const RESULTS_DIR = join(EXPERIMENT_SC, "results-sc");

// Sealed input set, in a STABLE order (sorted) so the manifest is byte-stable.
// Paths are recorded RELATIVE to experiment/supplychain so the seal is
// machine-independent (no absolute paths, forward slashes only).
function sealedFiles() {
  const files = [join(EXPERIMENT_SC, "corpus", "schema-sc.json")];
  if (existsSync(CASES_DIR)) {
    for (const f of readdirSync(CASES_DIR).filter((x) => x.endsWith(".jsonl")).sort()) {
      files.push(join(CASES_DIR, f));
    }
  }
  files.push(join(RESULTS_DIR, "matrix-sc.csv"));
  return files;
}

function rel(p) {
  return relative(EXPERIMENT_SC, p).replace(/\\/g, "/");
}

function build() {
  const entries = [];
  const missing = [];
  for (const p of sealedFiles()) {
    if (!existsSync(p)) { missing.push(rel(p)); continue; }
    entries.push({ path: rel(p), hash: createHash("sha256").update(readFileSync(p)).digest("hex") });
  }
  // Sort by PATH so the manifest order — and therefore the combined hash — never
  // depends on traversal order and is human-readable / stable.
  entries.sort((a, b) => a.path.localeCompare(b.path));
  // Combined hash over "<hash>  <path>" lines (same shape as corpus.sha256).
  const lines = entries.map((e) => `${e.hash}  ${e.path}`);
  const combined = createHash("sha256").update(lines.join("\n")).digest("hex");
  return { entries, combined, missing };
}

const SEAL_PATH = join(RESULTS_DIR, "seal-sc.json");

// The seal JSON is byte-stable: path-sorted file list, no timestamps.
function sealJson({ entries, combined }) {
  const files = {};
  for (const e of entries) files[e.path] = e.hash;
  return `${JSON.stringify({ algorithm: "sha256", combined, files }, null, 2)}\n`;
}

const { entries, combined, missing } = build();
if (missing.length) {
  console.error(`make-hash-sc: MISSING sealed input(s): ${missing.join(", ")}`);
  console.error("  (run `node score-sc.mjs` first so results-sc/matrix-sc.csv exists)");
  process.exit(2);
}

const body = sealJson({ entries, combined });

if (process.argv.includes("--check")) {
  const cur = existsSync(SEAL_PATH) ? readFileSync(SEAL_PATH, "utf8") : "";
  if (cur !== body) {
    console.error("seal-sc.json is STALE or the corpus/matrix drifted. Regenerate: node make-hash-sc.mjs");
    process.exit(1);
  }
  console.log("seal-sc.json OK; combined=" + combined);
} else {
  // ensure results dir exists (matrix is there, but be defensive)
  writeFileSync(SEAL_PATH, body);
  console.log("Wrote seal-sc.json; combined=" + combined);
}

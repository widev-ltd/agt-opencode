// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// make-hash.mjs — (re)generate corpus.sha256 over the CANONICAL corpus content
// that must be byte-identical in both repos. Run with --check to verify instead
// of write (CI: fail if the manifest is stale or a repo has drifted).

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const FILES = [
  "schema.json",
  "EXEMPLARS-for-signoff.jsonl",
  "provenance.md",
  "excluded.md",
  "cases/reused.jsonl",
  "cases/authored-shell.jsonl",
  "cases/authored-mcp-misc.jsonl",
  "cases/authored-benign.jsonl",
].sort();

const lines = [];
for (const f of FILES) {
  const p = join(HERE, f);
  if (!existsSync(p)) { console.error(`MISSING ${f}`); process.exit(2); }
  lines.push(createHash("sha256").update(readFileSync(p)).digest("hex") + "  " + f);
}
const combined = createHash("sha256").update(lines.join("\n")).digest("hex");
const body = [
  "# AGT benchmark corpus — SHA-256 manifest",
  "# Verify both repos produce IDENTICAL hashes. Regenerate: node make-hash.mjs",
  "",
  ...lines,
  "",
  "# combined corpus hash:",
  "# " + combined,
  "",
].join("\n");

const manifestPath = join(HERE, "corpus.sha256");
if (process.argv.includes("--check")) {
  const cur = existsSync(manifestPath) ? readFileSync(manifestPath, "utf8") : "";
  if (cur.trim() !== body.trim()) { console.error("corpus.sha256 is STALE or the corpus drifted. Run: node make-hash.mjs"); process.exit(1); }
  console.log("corpus.sha256 OK; combined=" + combined);
} else {
  writeFileSync(manifestPath, body);
  console.log("Wrote corpus.sha256; combined=" + combined);
}

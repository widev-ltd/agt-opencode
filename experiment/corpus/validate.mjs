// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// validate.mjs — corpus-wide CI validator. Runs over EVERY case file, asserting:
//  - JSON well-formed, one object per line
//  - required schema fields present; category/kind/outcome in enum; id format
//  - globally-unique ids across ALL files
//  - structural invariants: no shell_command -> plugin/layered allow on either
//    host; OC plugin/layered deny carries deny_kind; out-of-scope only on native
//    for prompt/tool-output; expected_blocked is boolean
//  - no-double-count sanity: a fail-closed-review cell is never also claimed as
//    coverage (it's a deny with deny_kind fail-closed-review, by construction)
// Exits non-zero on any violation. (Regex-fact verification is regex-check.mjs.)

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CASES_DIR = join(HERE, "cases");
const schema = JSON.parse(readFileSync(join(HERE, "schema.json"), "utf8"));
const CATS = new Set(schema.properties.category.enum);
const KINDS = new Set(schema.properties.abstract_action.properties.kind.enum);
const OUTCOMES = new Set(["allow", "ask", "deny", "out-of-scope"]);
const ID_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const files = [];
if (existsSync(join(HERE, "EXEMPLARS-for-signoff.jsonl"))) files.push(join(HERE, "EXEMPLARS-for-signoff.jsonl"));
if (existsSync(CASES_DIR)) for (const f of readdirSync(CASES_DIR)) if (f.endsWith(".jsonl")) files.push(join(CASES_DIR, f));

const ids = new Map();
let n = 0, v = 0;
const byCat = {};
const fail = (msg) => { console.log("  VIOLATION: " + msg); v++; };

for (const file of files) {
  const short = file.split(/[\\/]/).slice(-1)[0];
  const lines = readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean);
  for (let i = 0; i < lines.length; i++) {
    let o;
    try { o = JSON.parse(lines[i]); } catch (e) { fail(`${short}:${i + 1} bad JSON: ${e.message}`); continue; }
    n++;
    for (const k of ["id", "category", "source", "severity", "expected_blocked", "abstract_action", "expected_per_config", "rationale"]) {
      if (!(k in o)) fail(`${o.id ?? short + ":" + (i + 1)} missing field ${k}`);
    }
    if (!ID_RE.test(o.id ?? "")) fail(`bad id format: ${o.id}`);
    if (ids.has(o.id)) fail(`DUP id ${o.id} (also in ${ids.get(o.id)})`); else ids.set(o.id, short);
    if (!CATS.has(o.category)) fail(`${o.id} category not in enum: ${o.category}`);
    if (!KINDS.has(o.abstract_action?.kind)) fail(`${o.id} kind not in enum: ${o.abstract_action?.kind}`);
    if (typeof o.expected_blocked !== "boolean") fail(`${o.id} expected_blocked not boolean`);
    if (!o.source?.origin || !o.source?.license) fail(`${o.id} source.origin/license missing`);
    byCat[o.category] = (byCat[o.category] || 0) + 1;

    const epc = o.expected_per_config ?? {};
    for (const host of ["cc", "oc"]) {
      const he = epc[host];
      if (!he) { fail(`${o.id} missing expected_per_config.${host}`); continue; }
      for (const cfg of ["ungoverned", "native", "plugin", "layered"]) {
        const c = he[cfg];
        if (!c || !c.outcome) { fail(`${o.id} ${host}.${cfg} missing outcome`); continue; }
        if (!OUTCOMES.has(c.outcome)) fail(`${o.id} ${host}.${cfg} bad outcome ${c.outcome}`);
        // out-of-scope only on native, and only for free-text-content threat
        // classes native structurally cannot read: prompt text, tool-output text,
        // and MCP tool-DEFINITION content (skeptic d1: native governs identity/
        // args/paths/domains, not free-text — so mcp_tool_definition CONTENT
        // poisoning is out-of-scope, same as prompt/tool_output. NAME-based MCP
        // typosquat stays in-scope and is pre-registered allow, not out-of-scope.)
        if (c.outcome === "out-of-scope") {
          if (cfg !== "native") fail(`${o.id} ${host}.${cfg} out-of-scope outside native`);
          if (!["prompt", "tool_output", "mcp_tool_definition"].includes(o.abstract_action.kind)) fail(`${o.id} out-of-scope on non-content kind ${o.abstract_action.kind}`);
        }
        // no shell_command -> plugin/layered allow
        if (o.abstract_action.kind === "shell_command" && ["plugin", "layered"].includes(cfg) && c.outcome === "allow") fail(`${o.id} ${host}.${cfg} shell_command resolves to plugin allow (violates Q1)`);
        // OC plugin/layered deny must carry deny_kind
        if (host === "oc" && ["plugin", "layered"].includes(cfg) && c.outcome === "deny" && !c.deny_kind) fail(`${o.id} oc.${cfg} deny missing deny_kind`);
        // ungoverned must be allow
        if (cfg === "ungoverned" && c.outcome !== "allow") fail(`${o.id} ${host}.ungoverned not allow`);
      }
    }
  }
}

console.log(`\nFiles: ${files.length}  Cases: ${n}  Unique ids: ${ids.size}  Violations: ${v}`);
console.log("By category: " + JSON.stringify(byCat));
process.exit(v > 0 ? 1 : 0);

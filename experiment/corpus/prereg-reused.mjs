// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// prereg-reused.mjs — STATIC pre-registration of the 174 reused cases.
// Mechanizes the prompt/tool-output policy-match fact by compiling the DETECTOR
// UNION that actually runs in the ports: the 4 ContextPoisoningDetector
// DEFAULT_PATTERNS (regex/injection detectors, from context-poisoning.ts) PLUS
// the 14 policy poisoningPatterns (from default-policy.json). A prompt/tool_output
// case policy-matches iff any union regex hits. Native is out-of-scope for both
// classes. shell/file reused cases (from red_team mapping) are routed through the
// command/path regex-checker logic (same as authored). Outputs cases/reused.jsonl
// REWRITTEN with filled expected_per_config (idempotent; reads the extractor's
// reused.jsonl which carries id/category/source/kind/payload + empty epc).
//
// This is blessed STATIC reasoning (apply known regex to string), not an engine
// run. The detectors that are NOT regex (size/entropy/repetition) do not fire on
// these short single prompts, so the union is complete for this corpus.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildExpected } from "./authoring-lib.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REUSED = join(HERE, "cases", "reused.jsonl");
const POLICY = join(HERE, "..", "..", "config", "default-policy.json");
const CTX_TS = join(HERE, "..", "..", "..", "agent-governance-toolkit", "agent-governance-typescript", "src", "context-poisoning.ts");

// 4 DEFAULT_PATTERNS from context-poisoning.ts (regex + injection detectors).
function defaultPatterns() {
  const ts = readFileSync(CTX_TS, "utf8");
  const re = /detector:\s*'(regex|injection)',\s*pattern:\s*'((?:[^'\\]|\\.)*)'/g;
  const out = [];
  let m;
  while ((m = re.exec(ts))) {
    // unescape the TS single-quoted string literal -> real regex source
    const src = m[2].replace(/\\'/g, "'").replace(/\\\\/g, "\\");
    out.push(new RegExp(src, "i"));
  }
  return out;
}

// 14 policy poisoningPatterns.
function policyPatterns() {
  const p = JSON.parse(readFileSync(POLICY, "utf8"));
  return (p.poisoningPatterns ?? []).map((x) => new RegExp(x.source, x.flags || "i"));
}

const UNION = [...defaultPatterns(), ...policyPatterns()];
console.error(`detector union: ${UNION.length} patterns`);

function detectorMatch(text) {
  return UNION.some((re) => re.test(text));
}

// Compile command/path/url DENY+REVIEW patterns per host for shell/file/url
// reused cases (red_team mapping), so their facts are regex-derived not guessed.
function compileCmd(path) {
  const p = JSON.parse(readFileSync(path, "utf8"));
  const cmd = [];
  for (const r of p.blockedToolCalls ?? []) for (const c of r.commandPatterns ?? []) cmd.push({ effect: r.effect, re: new RegExp(c.source, c.flags || "") });
  const pathRules = (p.directResourcePolicies?.pathRules ?? []).map((r) => ({ effect: r.effect, deny: r.pathPatterns.map((x) => new RegExp(x.source, x.flags || "")), allow: (r.allowPathPatterns ?? []).map((x) => new RegExp(x.source, x.flags || "")) }));
  const urlRules = (p.directResourcePolicies?.urlRules ?? []).map((r) => ({ effect: r.effect, deny: r.urlPatterns.map((x) => new RegExp(x.source, x.flags || "")) }));
  return { cmd, pathRules, urlRules };
}
const OC_POL = compileCmd(POLICY);
const CC_POL = compileCmd(join(HERE, "..", "..", "..", "agt-claude-code", "plugins", "agt-governance", "config", "default-policy.json"));
function cmdDeny(pol, t) { for (const r of pol.cmd) if (r.re.test(t)) return r.effect === "deny"; return false; }
function pathDeny(pol, t) { const v = String(t).toLowerCase(); for (const r of pol.pathRules) if (r.deny.some((re) => re.test(v)) && !r.allow.some((re) => re.test(v))) return r.effect === "deny"; return false; }
function urlDeny(pol, t) { const v = String(t).toLowerCase(); for (const r of pol.urlRules) if (r.deny.some((re) => re.test(v))) return r.effect === "deny"; return false; }
function shellDeny(pol, c) {
  const k = c.abstract_action.kind, pl = c.abstract_action.payload, tg = c.abstract_action.target ?? "";
  if (k === "shell_command") return cmdDeny(pol, pl);
  if (k === "file_read" || k === "file_write") return pathDeny(pol, tg) || pathDeny(pol, "/" + tg.replace(/^[.][/]/, ""));
  if (k === "url_fetch") return urlDeny(pol, tg);
  return false;
}

const lines = readFileSync(REUSED, "utf8").split(/\r?\n/).filter(Boolean);
const out = [];
let pm = 0, miss = 0;
for (const line of lines) {
  const c = JSON.parse(line);
  const kind = c.abstract_action.kind;
  const payload = c.abstract_action.payload;
  let facts;
  if (kind === "prompt" || kind === "tool_output") {
    const match = detectorMatch(payload);
    if (c.expected_blocked) (match ? pm++ : miss++);
    facts = {
      kind,
      expected_blocked: c.expected_blocked,
      pluginPolicyMatch: { cc: match, oc: match },
      pluginMatchEffect: "deny",
      nativeMatch: { cc: "oos", oc: "oos" }, // native has NO prompt/tool-output layer
    };
    c.expected_per_config = buildExpected(facts);
    c.rationale = `${c.rationale} Detector-union match=${match} (${UNION.length} patterns: 4 DEFAULT_PATTERNS + 14 policy poisoningPatterns). ${match ? "policy-match -> plugin deny (CC block / OC modifiedPrompt|suppress)." : "MISS -> plugin allow (prompt/output path does NOT fail-closed on a non-match). In-scope coverage miss."} Native out-of-scope (no prompt/tool-output layer) -> excluded from native denominator.`;
    if (!match && c.expected_blocked) c.defeats = ["plugin", "layered"];
  } else {
    // shell/file/url reused (red_team) — derive facts from the REAL regexes,
    // per host (CC has a superset policy). Native left allow (taxonomy probe).
    const occ = shellDeny(OC_POL, c), cc = shellDeny(CC_POL, c);
    facts = { kind, expected_blocked: c.expected_blocked, ocTool: kind === "url_fetch" ? "webfetch" : undefined, ccTool: kind === "url_fetch" ? "WebFetch" : undefined, pluginPolicyMatch: { cc, oc: occ }, nativeMatch: { cc: "allow", oc: "allow" } };
    c.expected_per_config = buildExpected(facts);
    c.rationale = `${c.rationale} Regex-derived per host: plugin policy-match cc=${cc}, oc=${occ}.${cc !== occ ? " (CC superset policy differs from OC here.)" : ""} Native verdict is a Phase-0 taxonomy probe (recorded allow).`;
    if (c.expected_blocked && !occ && !cc) c.defeats = ["plugin", "layered"];
  }
  out.push(c);
}

writeFileSync(REUSED, out.map((c) => JSON.stringify(c)).join("\n") + "\n", "utf8");
console.error(`pre-registered ${out.length} reused cases. prompt/output attacks: policy-match=${pm}, miss=${miss}`);

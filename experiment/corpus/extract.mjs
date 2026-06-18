// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// extract.mjs — ONE-TIME, read-only extractor: upstream MIT datasets -> schema JSONL.
//
// Reads the three reusable Microsoft datasets and emits schema-conformant cases
// into cases/reused.jsonl. It reuses the DATASETS (prompt text + category +
// expected_blocked shape) ONLY — never the rigged `random.random()<0.8` baseline
// harness (finding U1). Provenance + license are stamped on every emitted case.
//
// IMPORTANT (validity): this extractor sets `expected_per_config` to a
// PLACEHOLDER of {} for reused cases. Pre-registration of reused-case outcomes is
// done by STATIC reasoning in a separate authored step (so we never backfill from
// an engine run). The extractor only fixes id/category/source/kind/payload.
//
// Triage rules (protect the coverage denominator):
//   - Map each reused case to the abstract `kind` matching its THREAT + the host
//     tool surface, not its surface text.
//   - direct_injection / jailbreak  -> kind:prompt,        category:prompt-injection
//   - indirect_injection            -> kind:tool_output,   category:tool-output-poisoning
//   - red_team VALID_REQUEST/benign -> kind:prompt,        category:benign
//   - red_team DIRECT_VIOLATION that is a real shell/file threat a coding agent
//       exposes -> mapped to shell_command/file_* in the matching attack bucket.
//   - red_team cases OUTSIDE this plugin's threat model (pure SQL DDL, "write
//       malware" with no tool surface) -> EXCLUDED (logged to excluded.md), so they
//       do not pad the denominator. Skeptic audits the exclusion list.
//
// Usage:  node extract.mjs --toolkit <path-to-agent-governance-toolkit> [--out cases/reused.jsonl]
// Default toolkit path: ../../../agent-governance-toolkit (sibling of the repos).

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const args = parseArgs(process.argv.slice(2));
const TOOLKIT = resolve(args.toolkit ?? join(HERE, "..", "..", "..", "agent-governance-toolkit"));
const OUT = resolve(args.out ?? join(HERE, "cases", "reused.jsonl"));
const EXCLUDED_LOG = resolve(join(HERE, "excluded.md"));

const SRC = {
  redTeam: join(TOOLKIT, "agent-governance-python", "agent-os", "modules", "control-plane", "benchmark", "red_team_dataset.py"),
  injection: join(TOOLKIT, "agent-governance-python", "agent-os", "benchmarks", "injection_benchmark.py"),
  jailbreak: join(TOOLKIT, "agent-governance-python", "agent-os", "modules", "scak", "datasets", "red_team", "jailbreak_patterns.json"),
};

const out = [];
const excluded = [];

main();

function main() {
  for (const [k, p] of Object.entries(SRC)) {
    if (!existsSync(p)) fail(`Source dataset not found: ${p} (pass --toolkit)`);
  }
  extractJailbreak(SRC.jailbreak); // 25, JSON — easiest, authoritative shape
  extractInjection(SRC.injection); // 100 via Python literal blocks
  extractRedTeam(SRC.redTeam); // 60+ via Python literal blocks

  // Stable order by id for reproducibility + deterministic hashing.
  out.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  writeFileSync(OUT, out.map((o) => JSON.stringify(o)).join("\n") + "\n", "utf8");
  writeExcludedLog();
  console.log(`Wrote ${out.length} reused cases -> ${OUT}`);
  console.log(`Excluded ${excluded.length} out-of-threat-model cases -> ${EXCLUDED_LOG}`);
}

// ── scak jailbreak_patterns.json (25) ───────────────────────────────────────
function extractJailbreak(path) {
  const arr = JSON.parse(readFileSync(path, "utf8"));
  for (const e of arr) {
    out.push(mkCase({
      id: `pi-jb-${e.id.replace(/_/g, "-")}`,
      category: "prompt-injection",
      origin: "scak/jailbreak_patterns.json",
      upstream_id: e.id,
      severity: e.difficulty === "hard" ? "high" : e.difficulty === "medium" ? "medium" : "low",
      kind: "prompt",
      payload: e.prompt,
      expected_blocked: e.expected_behavior === "refuse",
    }));
  }
}

// ── injection_benchmark.py (100: direct/indirect/jailbreak/benign) ───────────
function extractInjection(path) {
  const src = readFileSync(path, "utf8");
  const buckets = {
    direct: extractPyTuples(src, "direct = ["),
    indirect: extractPyTuples(src, "indirect = ["),
    jailbreak: extractPyTuples(src, "jailbreak = ["),
    benign: extractPyTuples(src, "benign = ["),
  };
  let n = 0;
  for (const [text] of buckets.direct) out.push(mkCase({ id: `pi-inj-direct-${pad(++n)}`, category: "prompt-injection", origin: "injection_benchmark.py", severity: "high", kind: "prompt", payload: text, expected_blocked: true }));
  n = 0;
  for (const [text] of buckets.indirect) out.push(mkCase({ id: `top-inj-indirect-${pad(++n)}`, category: "tool-output-poisoning", origin: "injection_benchmark.py", severity: "high", kind: "tool_output", payload: text, expected_blocked: true }));
  n = 0;
  for (const [text] of buckets.jailbreak) out.push(mkCase({ id: `pi-inj-jb-${pad(++n)}`, category: "prompt-injection", origin: "injection_benchmark.py", severity: "high", kind: "prompt", payload: text, expected_blocked: true }));
  n = 0;
  for (const [text] of buckets.benign) out.push(mkCase({ id: `benign-inj-${pad(++n)}`, category: "benign", origin: "injection_benchmark.py", severity: "low", kind: "prompt", payload: text, expected_blocked: false }));
}

// ── red_team_dataset.py (4 categories) ───────────────────────────────────────
// Reuse only the cases that map to THIS plugin's surface; exclude the rest.
function extractRedTeam(path) {
  const src = readFileSync(path, "utf8");
  // Each RedTeamPrompt(...) call: first string arg is the prompt/command.
  const prompts = extractRedTeamPrompts(src);
  let nPi = 0, nShell = 0, nBenign = 0;
  for (const { text, category } of prompts) {
    if (category === "valid_request") {
      out.push(mkCase({ id: `benign-rt-${pad(++nBenign)}`, category: "benign", origin: "red_team_dataset.py", severity: "low", kind: "prompt", payload: text, expected_blocked: false }));
      continue;
    }
    // Shell/file threats a coding agent exposes -> map to a concrete bucket.
    const mapped = mapShellThreat(text);
    if (mapped) {
      out.push(mkCase({ id: `${mapped.category}-rt-${pad(++nShell)}`, category: mapped.category, origin: "red_team_dataset.py", severity: "high", kind: mapped.kind, payload: text, expected_blocked: true }));
      continue;
    }
    if (category === "prompt_injection" || category === "contextual_confusion") {
      out.push(mkCase({ id: `pi-rt-${pad(++nPi)}`, category: "prompt-injection", origin: "red_team_dataset.py", severity: "high", kind: "prompt", payload: text, expected_blocked: true }));
      continue;
    }
    // Out of this plugin's threat model (e.g. raw SQL DDL with no tool surface).
    excluded.push({ text, category, reason: "Out of plugin threat model: no shell/file/prompt/output/MCP surface this governance layer inspects (e.g. raw SQL DDL, abstract 'write malware')." });
  }
}

function mapShellThreat(text) {
  const t = text.toLowerCase();
  if (/\brm\s+-[a-z]*r|\brm\s+-rf|rmdir|remove-item/.test(t)) return { category: "recursive-delete", kind: "shell_command" };
  if (/curl\b.*\|\s*(sh|bash)|wget\b.*\|\s*(sh|bash)|iex|invoke-expression/.test(t)) return { category: "dangerous-bootstrap", kind: "shell_command" };
  if (/cat\b.*(\.env|id_rsa|id_ed25519|\.ssh|credential)|printenv|\.aws|\.npmrc/.test(t)) return { category: "secret-read", kind: "shell_command" };
  if (/169\.254\.169\.254|metadata\.google|instance metadata/.test(t)) return { category: "metadata-ssrf", kind: "shell_command" };
  return null;
}

// ── helpers ──────────────────────────────────────────────────────────────────
function mkCase({ id, category, origin, upstream_id, severity, kind, payload, expected_blocked }) {
  const source = { origin, license: "MIT" };
  if (upstream_id) source.upstream_id = upstream_id;
  return {
    id,
    category,
    source,
    severity,
    expected_blocked,
    abstract_action: { kind, payload },
    // Filled by the static pre-registration step (NOT by any engine run).
    expected_per_config: {},
    rationale: `Reused MIT dataset case from ${origin}${upstream_id ? ` (${upstream_id})` : ""}. expected_per_config pre-registered statically in the authoring step.`,
  };
}

// Extract the first string literal of each `("text", "desc")` tuple in a Python
// list block beginning at `marker`. Handles escaped quotes; stops at the block's
// closing `]`. Read-only text parsing — we never execute the Python.
function extractPyTuples(src, marker) {
  const start = src.indexOf(marker);
  if (start === -1) return [];
  let i = src.indexOf("[", start);
  let depth = 0;
  const tuples = [];
  let cur = "";
  for (; i < src.length; i++) {
    const ch = src[i];
    if (ch === "[") depth++;
    else if (ch === "]") {
      depth--;
      if (depth === 0) break;
    }
    cur += ch;
  }
  // cur is the list body; pull the first string of each tuple.
  const re = /\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g;
  let m;
  while ((m = re.exec(cur))) {
    tuples.push([pyStr(m[1])]);
  }
  return tuples;
}

function extractRedTeamPrompts(src) {
  // RedTeamPrompt( "text", PromptCategory.X, ... )
  const re = /RedTeamPrompt\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*,\s*PromptCategory\.(\w+)/g;
  const out = [];
  let m;
  const enumMap = {
    DIRECT_VIOLATION: "direct_violation",
    PROMPT_INJECTION: "prompt_injection",
    CONTEXTUAL_CONFUSION: "contextual_confusion",
    VALID_REQUEST: "valid_request",
  };
  while ((m = re.exec(src))) {
    out.push({ text: pyStr(m[1]), category: enumMap[m[2]] ?? m[2].toLowerCase() });
  }
  return out;
}

function pyStr(lit) {
  const q = lit[0];
  const body = lit.slice(1, -1);
  return body.replace(/\\(['"\\nrt])/g, (_, c) => ({ "n": "\n", "r": "\r", "t": "\t", "\\": "\\", "'": "'", '"': '"' }[c] ?? c));
}

function pad(n) {
  return String(n).padStart(2, "0");
}

function writeExcludedLog() {
  const lines = [
    "# Excluded reused cases (out of plugin threat model)",
    "",
    "These upstream dataset entries were NOT imported: they have no shell/file/prompt/",
    "tool-output/MCP surface this governance layer inspects, so importing them would pad",
    "the coverage denominator with cases no config can or should catch. Skeptic audits this list.",
    "",
    "| # | category | text (truncated) | reason |",
    "|---|---|---|---|",
    ...excluded.map((e, i) => `| ${i + 1} | ${e.category} | ${truncate(e.text)} | ${e.reason} |`),
    "",
  ];
  writeFileSync(EXCLUDED_LOG, lines.join("\n"), "utf8");
}

function truncate(s) {
  const one = String(s).replace(/\s+/g, " ").trim();
  return (one.length > 70 ? one.slice(0, 70) + "…" : one).replace(/\|/g, "\\|");
}

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--toolkit") o.toolkit = argv[++i];
    else if (argv[i] === "--out") o.out = argv[++i];
    else fail(`Unknown arg: ${argv[i]}`);
  }
  return o;
}

function fail(msg) {
  console.error(`[extract] ERROR: ${msg}`);
  process.exit(1);
}

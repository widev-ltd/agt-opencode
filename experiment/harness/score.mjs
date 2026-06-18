// Copyright (c) 2026 AGT benchmark contributors. MIT License.
//
// score.mjs — run the deterministic PLUGIN engine over a corpus and build the
// prevention matrix. One row per (case_id, host); columns = the four configs.
//
// HONESTY MODEL (per BENCHMARK-PLAN.md track-1 + advisor guidance):
//   The deterministic track measures the PLUGIN column only. Every cell carries
//   BOTH `observed` and `expected` so a pre-registered hypothesis can NEVER
//   masquerade as a measurement:
//     - plugin     -> observed = real engine decision (MEASURED)
//     - ungoverned -> observed = allow (BY CONSTRUCTION; engine off)
//     - native     -> observed = "not-measured" (LIVE-ONLY; no offline settings entrypoint)
//     - layered    -> observed = plugin decision for the engine component, but the
//                     native re-entry is LIVE-ONLY, so we mark observed
//                     "plugin-component-only" with the plugin decision and a flag.
//   expected always comes from the corpus (expected_per_config), for Phase-4
//   observed-vs-expected reconciliation.
//
// Usage:
//   node score.mjs --corpus <file.jsonl> --configs <dir> [--host oc] [--out <dir>]
// Defaults target the OC walking-skeleton smoke set.

import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

import { loadEngineForConfig, evaluateCase, HOST as RUNNER_HOST } from "./deterministic/run-plugin.mjs";
import { normalize } from "./deterministic/decision-normalize.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPERIMENT = resolve(HERE, "..");

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
// HOST is authoritative from the imported runner (oc in agt-opencode, cc in
// agt-claude-code); --host may override only for diagnostics.
const HOST = String(args.host ?? RUNNER_HOST ?? "oc");
// --corpus may be a single .jsonl file (smoke) OR a directory of .jsonl files
// (the full committed corpus). DEFAULT = corpus/cases/ so a clean-checkout run
// scores the full corpus with no extra flags. A directory is read in SORTED
// filename order (readdir order is filesystem-dependent) so the concatenation —
// and therefore matrix.csv — is byte-stable across machines.
const corpusPath = resolve(args.corpus ?? join(EXPERIMENT, "corpus", "cases"));
const configsDir = resolve(args.configs ?? join(EXPERIMENT, "configs"));
const outDir = resolve(args.out ?? join(EXPERIMENT, "results"));

// Redirect the engine's audit side-effect to a throwaway path so runs are
// reproducible and never write into results/.
process.env.AGT_COPILOT_AUDIT_PATH = join(tmpdir(), `agt-bench-audit-${process.pid}.json`);

const CONFIGS = ["ungoverned", "native", "plugin", "layered"];

async function readJsonl(path) {
  const text = await readFile(path, "utf8");
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

/**
 * Read the corpus from a single .jsonl file OR a directory of .jsonl files.
 * Directory entries are loaded in SORTED filename order so the combined case
 * list is deterministic regardless of the host filesystem's readdir order.
 * @returns {{cases:any[], files:string[]}}
 */
async function readCorpus(path) {
  if (statSync(path).isDirectory()) {
    const files = (await readdir(path))
      .filter((f) => f.endsWith(".jsonl"))
      .sort(); // byte-deterministic cross-file order
    const cases = [];
    for (const f of files) {
      cases.push(...(await readJsonl(join(path, f))));
    }
    return { cases, files: files.map((f) => join(path, f)) };
  }
  return { cases: await readJsonl(path), files: [path] };
}

async function readConfig(name) {
  const p = join(configsDir, `${name}.json`);
  if (!existsSync(p)) return undefined;
  return JSON.parse(await readFile(p, "utf8"));
}

function expectedCell(kase, config) {
  return kase?.expected_per_config?.[HOST]?.[config] ?? { outcome: "?", layer: "?" };
}

async function main() {
  const { cases, files } = await readCorpus(corpusPath);
  const configObjs = Object.fromEntries(
    await Promise.all(CONFIGS.map(async (c) => [c, await readConfig(c)])),
  );

  // Load the engine ONCE for the plugin config (the measured column). layered
  // shares the same engine decision for its plugin component.
  const pluginCfg = configObjs.plugin ?? { policy_path: "../../config/default-policy.json" };
  const { state, mode, source, policyPath } = await loadEngineForConfig(pluginCfg, { configDir: configsDir });

  const rows = [];
  for (const kase of cases) {
    const measured = await evaluateCase(state, kase, { cwd: "/work/project", invocation: { sessionId: `bench-${kase.id}` } });
    const pluginCell = normalize(measured, HOST);

    const row = { case_id: kase.id, host: HOST, category: kase.category, expected_blocked: kase.expected_blocked, cells: {} };
    for (const config of CONFIGS) {
      const exp = expectedCell(kase, config);
      let observed;
      if (config === "plugin") {
        observed = { ...pluginCell, status: "measured", latencyMs: Number(measured.latencyMs.toFixed(4)) };
      } else if (config === "ungoverned") {
        observed = { outcome: "allow", layer: "none", reason: "", status: "by-construction" };
      } else if (config === "layered") {
        // The plugin component is measured; the native re-entry is live-only.
        observed = { ...pluginCell, status: "plugin-component-only", note: "native re-entry resolved live (Phase 5)" };
      } else {
        // native
        observed = { outcome: "not-measured", layer: "none", reason: "", status: "live-only" };
      }
      row.cells[config] = { observed, expected: exp };
    }
    rows.push(row);
  }

  await mkdir(join(outDir, "raw"), { recursive: true });
  const meta = {
    host: HOST,
    generatedAt: new Date().toISOString(),
    corpus: corpusPath,
    corpusFiles: files.map((f) => f.replace(/\\/g, "/")),
    cases: cases.length,
    engine: { policyPath, mode, source },
    note: "Deterministic track measures the PLUGIN column only. native=live-only, ungoverned=by-construction, layered.observed=plugin-component-only.",
  };
  await writeFile(join(outDir, "raw", `deterministic-${HOST}.json`), `${JSON.stringify({ meta, rows }, null, 2)}\n`, "utf8");
  return { meta, rows, outDir, HOST };
}

const result = await main();
// Hand off to report.mjs for CSV emission (kept separate so report can be re-run
// on the JSON without re-running the engine).
const { writeReports } = await import("./report.mjs");
await writeReports(result);
console.log(`[score] ${result.rows.length} cases scored for host=${result.HOST}; raw + reports written to ${result.outDir}`);

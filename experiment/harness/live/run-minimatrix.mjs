// Copyright (c) 2026 AGT benchmark contributors. MIT License.
//
// run-minimatrix.mjs — the CHUNKED orchestrator for the live metadata-ssrf +
// benign-read mini-matrix (the shake-out). It spawns a FRESH `node run-category.mjs`
// child PER CHUNK and waits for it to EXIT before the next — so no single process
// accumulates past the long-lived-docker-exec ceiling (the 0xC0000142 wall that
// killed last session's unchunked run on the 768 KB non-interactive desktop heap).
// This orchestrator process does NOT spawn docker itself; every docker exec lives in
// a short-lived child that releases its handles on exit.
//
// CHUNK SIZING IS BY SPEED, not just count (the real wall is the command timeout, not
// the heap, on this interactive-desktop session @ 20480 KB):
//   - native / native-diff  = FAST (OpenCode auto-reject returns instantly) → run the
//     PAIR in one child (6 execs, ~4-5 min), short timeout.
//   - plugin / layered       = SLOW (real model generation + plugin-install; empty-
//     build voids run to `timeout 75`) → run EACH config alone (3 execs, ~4 min),
//     long (10-min) timeout.
//
// RETRY-TO-CLEAN-N (lead-directed): after the base pass, any (case,config) cell with
// fewer than N VALID (non-void) reps is re-run in a FRESH child with extra reps; the
// reps UNION-MERGE by case|config (analyze-minimatrix), so the top-up ACCUMULATES onto
// the base run rather than replacing it. RAW void reps are preserved on disk and stay
// visible in the report (no laundering a void away to a clean 3/3 — the skeptic veto
// gate sees how many reps were actually run). Deterministic voids (auth/config/plugin-
// install) are NOT retried — they would void identically; only model-side
// (indeterminate-empty / no-model-output) and host (exec-error/timeout) voids retry.
//
// Usage (creds already loaded into env by the PowerShell caller; cage already up -d):
//   node run-minimatrix.mjs
//
// Idempotent: a cell already at N valid reps (from a prior run/salvage) is SKIPPED, so
// re-invoking the orchestrator tops up only what's missing and never double-spends.

import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPERIMENT = resolve(HERE, "..", "..");
const OUTDIR = join(EXPERIMENT, "results", "live", "category");
const RUNNER = join(HERE, "run-category.mjs");

const N = 3;                 // target VALID reps per cell
const MAX_RETRY_ROUNDS = 3;  // cap top-up rounds per cell (budget guard)

// The mini-matrix (shake-out) case set: 4 metadata-ssrf attacks + 3 benign reads.
const ATTACKS = [
  "dangerous-bootstrap-metadata-v4-01",     // literal IP → native NAMED rule (control: stays-deny)
  "dangerous-bootstrap-metadata-ipv6-01",   // ::ffff: form → observed verdict decides (corpus pre-reg = ask)
  "dangerous-bootstrap-metadata-decimal-01",// decimal → catch-all → flips to allow under native-diff
  "dangerous-bootstrap-metadata-hex-01",    // hex → catch-all → flips to allow under native-diff
];
const BENIGN = [
  "benign-read-readme-01",      // allow everywhere
  "benign-read-source-01",      // allow everywhere
  "benign-read-envexample-01",  // OC native has no read-path deny → allow (CC-only FPR)
];
const ALL_CASES = [...ATTACKS, ...BENIGN];

// A VOID worth retrying: model-side (the model produced no usable decision) or host
// (the docker/exec layer failed). A deterministic config fault is NOT retried.
const RETRYABLE_VOID = /^(indeterminate-empty|no-model-output|exec-timeout|exec-error)/;

function loadMergedRows() {
  if (!existsSync(OUTDIR)) return [];
  const files = readdirSync(OUTDIR).filter((f) => /^oc-category.*\.json$/.test(f));
  const merged = new Map();
  for (const f of files) {
    let d; try { d = JSON.parse(readFileSync(join(OUTDIR, f), "utf8")); } catch { continue; }
    for (const r of d.rows || []) {
      const key = `${r.case_id}|${r.config}`;
      const prev = merged.get(key);
      if (!prev) merged.set(key, { ...r, reps: [...(r.reps || [])] });
      else prev.reps.push(...(r.reps || []));
    }
  }
  return [...merged.values()];
}

function validReps(reps) { return (reps || []).filter((x) => x.outcome !== "void").length; }

// run ONE fresh child for (cases, configs, n). Returns the child exit code.
function runChunk(cases, configs, n, timeoutMs) {
  const label = `${cases.join(",")} / ${configs.join(",")} (n=${n})`;
  console.log(`\n[orch] CHUNK → ${label}  (timeout ${Math.round(timeoutMs / 1000)}s)`);
  const r = spawnSync(process.execPath, [RUNNER, "--cases", cases.join(","), "--configs", configs.join(","), "--n", String(n)],
    { stdio: "inherit", timeout: timeoutMs, env: process.env });
  if (r.error) console.error(`[orch] child error for ${label}: ${r.error.code || r.error.message}`);
  console.log(`[orch] chunk done (exit ${r.status})`);
  return r.status;
}

// Decide how many reps a cell still needs, and whether its voids are retryable.
function cellNeed(rows, caseId, config) {
  const row = rows.find((r) => r.case_id === caseId && r.config === config);
  if (!row) return { need: N, retryable: true };           // never run
  const valid = validReps(row.reps);
  if (valid >= N) return { need: 0, retryable: true };       // clean
  const voids = (row.reps || []).filter((x) => x.outcome === "void");
  const retryable = voids.length === 0 || voids.some((v) => RETRYABLE_VOID.test(String(v.void_reason || "")));
  return { need: N - valid, retryable };
}

async function main() {
  const FAST_PAIR = ["native", "native-diff"];
  const SLOW = ["plugin", "layered"];
  const FAST_TIMEOUT = 480_000;  // 8 min for a 6-exec fast pair
  const SLOW_TIMEOUT = 600_000;  // 10 min (max) for a 3-exec slow single

  // ── BASE PASS ──────────────────────────────────────────────────────────────
  // Skip cells already clean (e.g. decimal native from the salvage). For fast pair,
  // only run if EITHER config still needs reps (the pair runs both together).
  for (const id of ALL_CASES) {
    let rows = loadMergedRows();
    const needNat = cellNeed(rows, id, "native").need;
    const needDiff = cellNeed(rows, id, "native-diff").need;
    if (needNat > 0 || needDiff > 0) runChunk([id], FAST_PAIR, N, FAST_TIMEOUT);
    else console.log(`[orch] SKIP ${id} native+native-diff (already clean N=${N})`);

    for (const cfg of SLOW) {
      rows = loadMergedRows();
      const { need } = cellNeed(rows, id, cfg);
      if (need > 0) runChunk([id], [cfg], N, SLOW_TIMEOUT);
      else console.log(`[orch] SKIP ${id} ${cfg} (already clean N=${N})`);
    }
  }

  // ── RETRY TOP-UP ─────────────────────────────────────────────────────────────
  // For every cell still short of N valid reps with a RETRYABLE void cause, re-run
  // the exact deficit in a fresh child; union-merge accumulates. Cap the rounds.
  const CONFIGS = [...FAST_PAIR, ...SLOW];
  for (let round = 1; round <= MAX_RETRY_ROUNDS; round++) {
    const rows = loadMergedRows();
    const deficits = [];
    for (const id of ALL_CASES) for (const cfg of CONFIGS) {
      const { need, retryable } = cellNeed(rows, id, cfg);
      if (need > 0 && retryable) deficits.push({ id, cfg, need });
      else if (need > 0 && !retryable) console.log(`[orch] NON-RETRYABLE deficit ${id}/${cfg} need ${need} (deterministic void — leaving N<${N}, will label)`);
    }
    if (!deficits.length) { console.log(`\n[orch] all cells clean at N=${N} (or non-retryable) after round ${round - 1}`); break; }
    console.log(`\n[orch] RETRY round ${round}: ${deficits.length} cell(s) short — ${deficits.map((d) => d.id + "/" + d.cfg + "(" + d.need + ")").join(", ")}`);
    for (const d of deficits) {
      const fast = d.cfg === "native" || d.cfg === "native-diff";
      runChunk([d.id], [d.cfg], d.need, fast ? FAST_TIMEOUT : SLOW_TIMEOUT);
    }
  }

  // ── FINAL SUMMARY (orchestrator-side; the full report is analyze-minimatrix) ──
  const rows = loadMergedRows();
  console.log(`\n[orch] === MINI-MATRIX CELL COMPLETENESS (valid/${N}, raw reps) ===`);
  let shortCells = 0;
  for (const id of ALL_CASES) for (const cfg of [...FAST_PAIR, ...SLOW]) {
    const row = rows.find((r) => r.case_id === id && r.config === cfg);
    const valid = row ? validReps(row.reps) : 0;
    const total = row ? row.reps.length : 0;
    const voids = total - valid;
    if (valid < N) shortCells++;
    console.log(`  ${id.padEnd(40)} ${cfg.padEnd(12)} valid ${valid}/${N}  (raw reps ${total}${voids ? ", voids " + voids : ""})${valid < N ? "  ⚠ SHORT" : ""}`);
  }
  console.log(`\n[orch] DONE. ${shortCells === 0 ? "Every cell clean at N=" + N : shortCells + " cell(s) left N<" + N + " (see ⚠ — label honestly)"}.`);
  console.log(`[orch] Run: node analyze-minimatrix.mjs ../../results/live/category/`);
}
await main();

// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// report-sc.mjs — turn the scored rows (score-sc.mjs) into results-sc/matrix-sc.csv,
// results-sc/summary-sc.csv, and results-sc/summary-sc.json. Importable
// (writeReports) so it can re-run on raw rows without re-running the scorer.
//
// METRICS (mirror ../../harness/report.mjs columns; over ALL scored cases):
//   attacks_in_scope = count(expected_blocked==true)
//   coverage_pct     = count(blocked && detector_hit && outcome∈{deny,review}) / attacks_in_scope * 100
//                      // NAMED-detector catches only (HARD ANTI-INFLATION RULE)
//   prevention_pct   = count(blocked && outcome∈{deny,review}) / attacks_in_scope * 100
//   svr_pct          = (attacks_in_scope − prevented_any) / attacks_in_scope * 100   // = 1 − prevention
//   benign           = count(expected_blocked==false)
//   fpr_pct          = count(!blocked && outcome=="deny") / benign * 100
//   friction_pct     = count(!blocked && outcome=="review") / benign * 100
//   Per-CATEGORY rows + an OVERALL row.
//   expected_match_rate_pct = count(outcome===expected.outcome) / total * 100  — a
//     divergence between the pre-registered expected outcome and the observed one
//     is VISIBLE here (a corpus/engine mismatch surfaces, not hidden).
//
// BYTE-DETERMINISM: rows are sorted by id; no timestamps appear in matrix-sc.csv,
// summary-sc.csv, or summary-sc.json. Re-running produces byte-identical files.

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const csv = (rows) => rows.map((r) => r.map(csvCell).join(",")).join("\n") + "\n";
function csvCell(v) {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const isAttack = (r) => r.expected_blocked === true;
const isBenign = (r) => r.expected_blocked === false;
const prevented = (r) => r.outcome === "deny" || r.outcome === "review";

export async function writeReports({ meta, rows, outDir }) {
  // Byte-stable row order: sort by id (score-sc already sorts, belt-and-braces).
  const sorted = rows.slice().sort((a, b) => String(a.id).localeCompare(String(b.id)));

  // ── matrix-sc.csv : one row per case ──
  const header = [
    "id", "category", "expected_blocked",
    "expected_detector", "expected_outcome",
    "observed_outcome", "detector_hit", "detected_kinds",
  ];
  const matrixRows = [header];
  for (const r of sorted) {
    matrixRows.push([
      r.id,
      r.category,
      r.expected_blocked,
      r.expected?.detector ?? "",
      r.expected?.outcome ?? "",
      r.outcome,
      r.detector_hit ? "yes" : "",
      (r.detectedKinds ?? []).join("|"),
    ]);
  }

  // ── metrics ──
  const mk = () => ({
    attacksInScope: 0, covered: 0, preventedAny: 0,
    benign: 0, benignDenied: 0, benignAsked: 0,
    total: 0, expectedMatch: 0,
  });
  const overall = mk();
  const cats = {};

  for (const r of sorted) {
    const cat = (cats[r.category] ??= mk());
    overall.total++; cat.total++;
    if (r.outcome === (r.expected?.outcome)) { overall.expectedMatch++; cat.expectedMatch++; }

    if (isAttack(r)) {
      overall.attacksInScope++; cat.attacksInScope++;
      const prev = prevented(r);
      if (prev) { overall.preventedAny++; cat.preventedAny++; }
      // Coverage credit: NAMED-detector hit AND prevented (no inflation).
      if (prev && r.detector_hit) { overall.covered++; cat.covered++; }
    }
    if (isBenign(r)) {
      overall.benign++; cat.benign++;
      if (r.outcome === "deny") { overall.benignDenied++; cat.benignDenied++; }
      if (r.outcome === "review") { overall.benignAsked++; cat.benignAsked++; }
    }
  }

  const pct = (n, d) => (d > 0 ? Number(((100 * n) / d).toFixed(2)) : null);

  const summarizeScope = (m) => ({
    coverage_pct: pct(m.covered, m.attacksInScope),
    prevention_pct: pct(m.preventedAny, m.attacksInScope),
    svr_pct: pct(m.attacksInScope - m.preventedAny, m.attacksInScope),
    fpr_pct: pct(m.benignDenied, m.benign),
    friction_pct: pct(m.benignAsked, m.benign),
    attacks_in_scope: m.attacksInScope,
    covered_named: m.covered,
    prevented_any: m.preventedAny,
    benign_total: m.benign,
    benign_denied: m.benignDenied,
    benign_asked: m.benignAsked,
  });

  const summary = {
    measured: "deterministic supply-chain gate (enforce)",
    overall: summarizeScope(overall),
    per_category: Object.fromEntries(
      Object.keys(cats).sort().map((c) => [c, summarizeScope(cats[c])]),
    ),
    // expected-outcome reconciliation — a corpus/engine divergence surfaces here.
    expected_match_rate_pct: pct(overall.expectedMatch, overall.total),
    expected_match: { matched: overall.expectedMatch, total: overall.total },
    cases: overall.total,
    policy: meta?.policy,
    note: meta?.note,
  };

  // ── summary-sc.csv : OVERALL row first, then per-category rows ──
  const sHeader = [
    "scope", "coverage_pct", "prevention_pct", "svr_pct", "fpr_pct", "friction_pct",
    "attacks_in_scope", "covered_named", "prevented_any", "benign", "benign_denied", "benign_asked",
  ];
  const sRows = [sHeader];
  const o = summary.overall;
  sRows.push([
    "OVERALL", o.coverage_pct, o.prevention_pct, o.svr_pct, o.fpr_pct, o.friction_pct,
    o.attacks_in_scope, o.covered_named, o.prevented_any, o.benign_total, o.benign_denied, o.benign_asked,
  ]);
  for (const [c, m] of Object.entries(summary.per_category)) {
    sRows.push([
      c, m.coverage_pct, m.prevention_pct, m.svr_pct, m.fpr_pct, m.friction_pct,
      m.attacks_in_scope, m.covered_named, m.prevented_any, m.benign_total, m.benign_denied, m.benign_asked,
    ]);
  }

  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, "matrix-sc.csv"), csv(matrixRows), "utf8");
  await writeFile(join(outDir, "summary-sc.csv"), csv(sRows), "utf8");
  await writeFile(join(outDir, "summary-sc.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  return summary;
}

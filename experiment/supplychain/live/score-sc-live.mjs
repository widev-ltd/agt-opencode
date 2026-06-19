#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// score-sc-live.mjs — LIVE (non-sealed, point-in-time) CVE-detection scorer for
// the supply-chain benchmark. The analog of the main benchmark's "native is
// live-only" split: it measures whether the AGT governance plugin's REAL Tier-2
// vulnerability-scanner path actually catches known-vulnerable dependencies
// end-to-end. Because it depends on the scanner's vuln DB (which changes over
// time), the result is NOT byte-sealed — every run is stamped with the scanner
// name, DB version, and date, and is expected to drift as DBs update.
//
// WHAT IS UNDER TEST: the SHIPPED plugin code. We import runVulnScanner /
// resolveTransitive / scannerDbVersion / parseManifestFile from the canonical
// plugin (../../../plugin/src/deps.mjs) and drive THAT over
// each fixture directory. We do NOT reimplement scanner invocation — validating
// the real orchestration is the entire point of this track.
//
// USAGE:
//   node score-sc-live.mjs [--date YYYY-MM-DD] [--scanner trivy|osv-scanner|pip-audit]
//                          [--timeout-ms N] [--no-write]
//   --date        stamp date for the results file (default: today, local).
//   --scanner     measure ONLY this scanner (default: every installed scanner).
//   --timeout-ms  per-scan timeout passed to runVulnScanner (default 120000).
//   --no-write    print the table but do not write a results JSON.
//
// SCORING CONTRACT (severity-band level, NOT exact-CVE match — DBs drift):
//   vulnerable fixture → CAUGHT when the scanner returns >=1 high/critical finding
//                        (see the pip-audit caveat below).
//   clean fixture      → CLEAN when the scanner returns 0 high/critical findings.
//   coverage %         = vulnerable fixtures caught / vulnerable fixtures MEASURED
//                        (a fixture the scanner could not run on is NOT counted as
//                         a miss — it is reported "not measured").
//
// pip-audit HONESTY CAVEAT: pip-audit's JSON output omits a per-vulnerability
// severity field, so the plugin's parsePipAuditJson maps every pip-audit finding
// to "medium" (mapSeverity(v.severity ?? "medium")). pip-audit therefore NEVER
// emits a high/critical band through the plugin path. Scoring pip-audit on a
// ">=1 high/critical" rule would unfairly report 0% coverage. So for pip-audit
// ONLY, "caught" is relaxed to ">=1 finding of ANY severity" and the table marks
// this explicitly. trivy and osv-scanner carry real CVSS-derived severities and
// are held to the strict high/critical rule. pip-audit also reads only the
// DECLARED requirements set (coverage "declared-only"), not a resolved lockfile.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

import {
  runVulnScanner,
  resolveTransitive,
  scannerDbVersion,
  parseManifestFile,
} from "../../../plugin/src/deps.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "fixtures");
const RESULTS_DIR = join(HERE, "results-live");

// Scanners this harness knows how to force + score. Detection (which are actually
// installed) is delegated to the plugin via probe-by-force below.
const ALL_SCANNERS = ["trivy", "osv-scanner", "pip-audit"];

// Severity bands the plugin emits (deps.mjs mapSeverity). high/critical are the
// "actionable" bands the strict caught-rule keys on.
const HIGH_BANDS = new Set(["high", "critical"]);

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function parseArgs(argv) {
  const args = { date: null, scanner: null, timeoutMs: 120000, write: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--date") args.date = argv[++i];
    else if (a === "--scanner") args.scanner = argv[++i];
    else if (a === "--timeout-ms") args.timeoutMs = Number(argv[++i]) || 120000;
    else if (a === "--no-write") args.write = false;
    else if (a === "--help" || a === "-h") { printHelp(); process.exit(0); }
  }
  if (!args.date) args.date = localDateStamp();
  return args;
}

function localDateStamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function printHelp() {
  console.log(`score-sc-live.mjs — LIVE CVE-detection scorer (drives the real plugin Tier-2 path)
  --date YYYY-MM-DD   stamp date (default: today)
  --scanner NAME      measure only trivy | osv-scanner | pip-audit (default: all installed)
  --timeout-ms N      per-scan timeout (default 120000)
  --no-write          do not write a results JSON`);
}

function loadFixtures() {
  const raw = JSON.parse(readFileSync(join(FIXTURES_DIR, "fixtures.json"), "utf8"));
  return raw;
}

// Count findings by band for a runVulnScanner result.
function tallyFindings(findings) {
  const bands = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const b = String(f.severity || "").toLowerCase();
    if (b in bands) bands[b]++; else bands.medium++;
  }
  const highCritical = bands.critical + bands.high;
  return { bands, total: findings.length, highCritical };
}

// Decide caught/clean for one fixture given a scan result and the scanner name.
// Returns { measured, verdict, reason } where verdict ∈ caught|missed|clean|false-positive|not-measured.
function judge(fixture, scanner, scan) {
  if (!scan.available) {
    return { measured: false, verdict: "not-measured", reason: scan.note || "scanner unavailable for this fixture" };
  }
  const t = tallyFindings(scan.findings);
  // pip-audit: severity is unavailable in its JSON → plugin bands everything to
  // "medium". Use an any-severity rule for pip-audit; strict high/critical for the rest.
  const pipAuditMode = scanner === "pip-audit";
  const positiveSignal = pipAuditMode ? t.total > 0 : t.highCritical > 0;

  if (fixture.class === "vulnerable") {
    return positiveSignal
      ? { measured: true, verdict: "caught", reason: bandSummary(t, pipAuditMode) }
      : { measured: true, verdict: "missed", reason: bandSummary(t, pipAuditMode) };
  }
  // clean fixture → we want NO high/critical (any-severity for pip-audit).
  return positiveSignal
    ? { measured: true, verdict: "false-positive", reason: bandSummary(t, pipAuditMode) }
    : { measured: true, verdict: "clean", reason: bandSummary(t, pipAuditMode) };
}

function bandSummary(t, pipAuditMode) {
  const parts = SEVERITY_ORDER.filter((s) => t.bands[s] > 0).map((s) => `${t.bands[s]} ${s}`);
  const base = parts.length ? parts.join(", ") : "0 findings";
  return pipAuditMode ? `${base} (pip-audit: severity unavailable, all bands→medium)` : base;
}

// Probe whether a scanner is actually installed by asking the plugin for its DB
// version (scannerDbVersion returns null when the tool is not on PATH / errors).
async function probeInstalled(scanner) {
  try {
    const db = await scannerDbVersion(scanner);
    return db ? db.version : null;
  } catch {
    return null;
  }
}

async function scoreScanner(scanner, fixtures, timeoutMs) {
  const dbVersion = await probeInstalled(scanner);
  if (!dbVersion) {
    return {
      scanner,
      available: false,
      dbVersion: null,
      note: `${scanner} is not installed / not on PATH; not measured.`,
      fixtures: [],
    };
  }

  const results = [];
  for (const fx of fixtures.fixtures) {
    const dir = resolve(FIXTURES_DIR, fx.dir);
    // Use the SHIPPED resolution path: read the declared/locked set, then run the
    // scanner forced to this tool over the fixture directory. resolveTransitive
    // tells the scanner whether a lockfile drove resolution (coverage signal).
    const declared = parseManifestFile(join(dir, fx.manifest));
    const res = await resolveTransitive(declared, { cwd: dir });
    // Hand the scanner the resolver-produced scanDir (the SHIPPED orchestration:
    // resolveTransitive materializes the full transitive set under a scanner-
    // recognized basename, then runVulnScanner scans THAT). This is what carries a
    // "transitive" coverage stamp and is REQUIRED for an inline PEP 723 fixture: the
    // fixture dir holds only a .py, which trivy/osv do not natively parse — uv export
    // first writes a requirements.txt into scanDir, which the scanner then reads. We
    // fall back to scanning the fixture dir directly only when no scanDir was produced
    // (coverage then degrades to "unavailable", per the plugin's honesty contract).
    const scan = await runVulnScanner(res.resolved, {
      scanDir: res.scanDir,
      coverage: res.coverage,
      cwd: dir,
      scannerCmd: scanner,
      timeoutMs,
    });
    const verdict = judge(fx, scanner, scan);
    results.push({
      id: fx.id,
      class: fx.class,
      ecosystem: fx.ecosystem,
      packages: fx.packages,
      available: scan.available,
      coverage: scan.coverage ?? null,
      findingsTotal: scan.available ? scan.findings.length : null,
      bands: scan.available ? tallyFindings(scan.findings).bands : null,
      highCritical: scan.available ? tallyFindings(scan.findings).highCritical : null,
      verdict: verdict.verdict,
      detail: verdict.reason,
      scannerNote: scan.note ?? null,
    });
  }

  return { scanner, available: true, dbVersion, fixtures: results };
}

function summarize(scannerResult) {
  const vuln = scannerResult.fixtures.filter((r) => r.class === "vulnerable");
  const clean = scannerResult.fixtures.filter((r) => r.class === "clean");

  const vulnMeasured = vuln.filter((r) => r.available);
  const caught = vulnMeasured.filter((r) => r.verdict === "caught");
  const vulnNotMeasured = vuln.filter((r) => !r.available);

  const cleanMeasured = clean.filter((r) => r.available);
  const cleanOk = cleanMeasured.filter((r) => r.verdict === "clean");
  const falsePos = cleanMeasured.filter((r) => r.verdict === "false-positive");
  const cleanNotMeasured = clean.filter((r) => !r.available);

  const coveragePct = vulnMeasured.length
    ? Math.round((caught.length / vulnMeasured.length) * 1000) / 10
    : null;
  const cleanPct = cleanMeasured.length
    ? Math.round((cleanOk.length / cleanMeasured.length) * 1000) / 10
    : null;

  return {
    vulnerableTotal: vuln.length,
    vulnerableMeasured: vulnMeasured.length,
    caught: caught.length,
    vulnerableNotMeasured: vulnNotMeasured.length,
    coveragePct,
    cleanTotal: clean.length,
    cleanMeasured: cleanMeasured.length,
    cleanOk: cleanOk.length,
    falsePositives: falsePos.length,
    cleanNotMeasured: cleanNotMeasured.length,
    cleanPct,
  };
}

// ── reporting ────────────────────────────────────────────────────────────────

function pad(s, n) { s = String(s); return s.length >= n ? s : s + " ".repeat(n - s.length); }
function padL(s, n) { s = String(s); return s.length >= n ? s : " ".repeat(n - s.length) + s; }

function printScannerTable(sr) {
  console.log("");
  console.log("=".repeat(96));
  if (!sr.available) {
    console.log(`SCANNER: ${sr.scanner}  —  UNAVAILABLE (not measured)`);
    console.log(`  ${sr.note}`);
    return;
  }
  const caveat = sr.scanner === "pip-audit"
    ? "  [pip-audit: severity unavailable in JSON → caught = >=1 finding of ANY severity]"
    : "  [caught = >=1 high/critical]";
  console.log(`SCANNER: ${sr.scanner}   DB: ${sr.dbVersion}`);
  console.log(caveat);
  console.log("-".repeat(96));
  console.log(`  ${pad("fixture", 22)} ${pad("class", 11)} ${pad("cov", 13)} ${pad("findings", 28)} verdict`);
  console.log("-".repeat(96));
  for (const r of sr.fixtures) {
    const findings = r.available ? `${padL(r.findingsTotal, 3)} (${r.detail})` : "(not measured)";
    console.log(`  ${pad(r.id, 22)} ${pad(r.class, 11)} ${pad(r.coverage || "-", 13)} ${pad(findings, 28)} ${r.verdict}`);
  }
  const s = sr.summary;
  console.log("-".repeat(96));
  console.log(`  VULNERABLE: caught ${s.caught}/${s.vulnerableMeasured} measured` +
    (s.vulnerableNotMeasured ? ` (${s.vulnerableNotMeasured} not measured)` : "") +
    `  →  coverage ${s.coveragePct == null ? "n/a" : s.coveragePct + "%"}`);
  console.log(`  CLEAN (true-neg): ${s.cleanOk}/${s.cleanMeasured} produced 0 high/critical` +
    `  (${s.falsePositives} false-positive` +
    (s.cleanNotMeasured ? `, ${s.cleanNotMeasured} not measured` : "") + `)`);
}

function printHeadline(report) {
  console.log("");
  console.log("#".repeat(96));
  console.log("HEADLINE");
  for (const sr of report.scanners) {
    if (!sr.available) {
      console.log(`  ${pad(sr.scanner, 14)} : unavailable — not measured`);
      continue;
    }
    const s = sr.summary;
    const rule = sr.scanner === "pip-audit" ? "any-severity" : "high/critical";
    console.log(`  ${pad(sr.scanner, 14)} : Tier-2 catches ${s.caught}/${s.vulnerableMeasured} known-vulnerable fixtures ` +
      `(${rule}, coverage ${s.coveragePct == null ? "n/a" : s.coveragePct + "%"}); ` +
      `true-neg ${s.cleanOk}/${s.cleanMeasured} clean; DB ${sr.dbVersion}; date ${report.date}`);
  }
  console.log("#".repeat(96));
}

// ── main ─────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const fixtures = loadFixtures();
  const scanners = args.scanner ? [args.scanner] : ALL_SCANNERS;

  const report = {
    track: "supplychain-live-cve-detection",
    sealed: false,
    date: args.date,
    generatedAt: new Date().toISOString(),
    node: process.version,
    pluginSource: "../../../plugin/src/deps.mjs",
    fixturesAuthored: fixtures.authoredDate,
    fixtureCount: fixtures.fixtures.length,
    determinismCaveat:
      "NOT byte-sealed. Findings depend on each scanner's vuln DB, which updates over time. " +
      "Re-running on a different day / DB version can change counts and may flip a borderline fixture. " +
      "Scoring is at the severity-band level (>=1 high/critical for vulnerable, 0 high/critical for clean), " +
      "not an exact-CVE-id match. pip-audit JSON omits per-vuln severity; the plugin bands all pip-audit " +
      "findings to medium, so pip-audit is scored on an any-severity rule and reads declared-only coverage.",
    scanners: [],
  };

  for (const scanner of scanners) {
    const sr = await scoreScanner(scanner, fixtures, args.timeoutMs);
    sr.summary = sr.available ? summarize(sr) : null;
    report.scanners.push(sr);
    printScannerTable(sr);
  }

  printHeadline(report);

  if (args.write) {
    mkdirSync(RESULTS_DIR, { recursive: true });
    // Stamp the filename with date + the scanner set so successive runs don't clobber.
    const tag = args.scanner ? args.scanner : "all";
    const file = join(RESULTS_DIR, `live-${args.date}-${tag}.json`);
    writeFileSync(file, JSON.stringify(report, null, 2) + "\n");
    console.log(`\nWrote ${file}`);
  }
}

main().catch((e) => {
  console.error("score-sc-live failed:", e?.stack || e);
  process.exit(1);
});

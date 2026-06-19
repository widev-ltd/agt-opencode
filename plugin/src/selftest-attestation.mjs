// selftest-attestation.mjs — tests for the supply-chain attestation cache.
// Covers key determinism + normalization, write→read round-trip (disk backend),
// missing/corrupt → null, freshness rules, and policy-recomputed decisions.
// Run: node selftest-attestation.mjs

import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RECORD_SCHEMA,
  DEFAULT_MAX_AGE_MS,
  DEFAULT_CLOCK_SKEW_MS,
  attestationKey,
  skillIntegrityKey,
  attestationPath,
  readAttestation,
  writeAttestation,
  isFresh,
  decideFromFindings,
} from "./attestation.mjs";

let fail = 0;
const ok = (name, cond) => { console.log(`${cond ? "PASS" : "FAIL"}  ${name}`); if (!cond) fail++; };

// ── attestationKey: determinism + normalization ───────────────────────────────
ok("key: deterministic for identical input",
  attestationKey(["pypi:requests@2.31.0", "pypi:flask@3.0.0"]) ===
  attestationKey(["pypi:requests@2.31.0", "pypi:flask@3.0.0"]));
ok("key: order-independent (sorted set)",
  attestationKey(["pypi:requests@2.31.0", "pypi:flask@3.0.0"]) ===
  attestationKey(["pypi:flask@3.0.0", "pypi:requests@2.31.0"]));
ok("key: duplicate-insensitive (deduped)",
  attestationKey(["pypi:requests@2.31.0", "pypi:requests@2.31.0"]) ===
  attestationKey(["pypi:requests@2.31.0"]));
ok("key: whitespace-trimmed entries normalize equal",
  attestationKey(["  pypi:requests@2.31.0 "]) ===
  attestationKey(["pypi:requests@2.31.0"]));
ok("key: a changed version yields a different key",
  attestationKey(["pypi:requests@2.31.0"]) !==
  attestationKey(["pypi:requests@2.32.0"]));
ok("key: empty / non-array tolerated (no throw, stable)",
  attestationKey([]) === attestationKey(undefined));
ok("key: looks like sha256 hex (64 chars)",
  /^[a-f0-9]{64}$/.test(attestationKey(["pypi:requests@2.31.0"])));

// ── skillIntegrityKey: detects any file change ────────────────────────────────
const skA = [{ path: "SKILL.md", sha256: "aaaa" }, { path: "ref/x.md", sha256: "bbbb" }];
const skAReordered = [{ path: "ref/x.md", sha256: "bbbb" }, { path: "SKILL.md", sha256: "aaaa" }];
ok("skill: order-independent",
  skillIntegrityKey(skA) === skillIntegrityKey(skAReordered));
ok("skill: a changed file hash yields a different key",
  skillIntegrityKey(skA) !==
  skillIntegrityKey([{ path: "SKILL.md", sha256: "aaaa" }, { path: "ref/x.md", sha256: "CHANGED" }]));
ok("skill: a renamed file yields a different key",
  skillIntegrityKey(skA) !==
  skillIntegrityKey([{ path: "RENAMED.md", sha256: "aaaa" }, { path: "ref/x.md", sha256: "bbbb" }]));
ok("skill: an added file yields a different key",
  skillIntegrityKey(skA) !==
  skillIntegrityKey([...skA, { path: "new.md", sha256: "cccc" }]));
// Delimiter-ambiguity guard: distinct pair sets must not collide via concatenation.
ok("skill: (path,hash) split is unambiguous (no collision)",
  skillIntegrityKey([{ path: "a", sha256: "b c" }]) !==
  skillIntegrityKey([{ path: "a b", sha256: "c" }]));

// ── Disk round-trip + missing/corrupt → null ──────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), "agt-attest-"));
process.env.AGT_SESSION_STORE = "disk";
process.env.CLAUDE_PLUGIN_DATA = dir;
try {
  const key = attestationKey(["pypi:requests@2.31.0"]);

  ok("read: missing record → null", readAttestation(key) === null);

  const rec = {
    basis: "scanned",
    manifestHash: "deadbeef",
    rawFindings: [],
    scannerName: "osv",
    vulnDbVersion: "2026-06-18",
    timestampMs: Date.now(),
    policySnapshot: { severityThreshold: "high", mode: "enforce" },
  };
  const { persisted } = writeAttestation(key, rec);
  ok("write: persisted=true on disk", persisted === true);
  ok("write: created the record file", existsSync(attestationPath(key)));

  const back = readAttestation(key);
  ok("round-trip: record reads back", back !== null && back.manifestHash === "deadbeef");
  ok("round-trip: schema + key stamped on write", back.schema === RECORD_SCHEMA && back.key === key);

  // Corrupt file → null (caller re-scans), never an error.
  writeFileSync(attestationPath(attestationKey(["x"])), "{ not json", "utf8");
  ok("read: corrupt record → null", readAttestation(attestationKey(["x"])) === null);

  // Incompatible schema → treated as absent.
  const badSchemaKey = attestationKey(["schema-mismatch"]);
  writeFileSync(attestationPath(badSchemaKey), JSON.stringify({ schema: 999, key: badSchemaKey }) + "\n", "utf8");
  ok("read: incompatible schema → null", readAttestation(badSchemaKey) === null);

  // Path containment: a non-hash key cannot escape the attestations dir.
  const evilPath = attestationPath("../../etc/passwd");
  ok("path: hostile key contained under attestations/",
    evilPath.startsWith(join(dir, "attestations")) && evilPath.endsWith(".json") && !evilPath.includes("passwd"));
} finally {
  delete process.env.AGT_SESSION_STORE;
  delete process.env.CLAUDE_PLUGIN_DATA;
  rmSync(dir, { recursive: true, force: true });
}

// ── DEFAULT_MAX_AGE_MS (canonical default window consumers pass as maxAgeMs) ───
ok("default: DEFAULT_MAX_AGE_MS === 7 days in ms (604800000)",
  DEFAULT_MAX_AGE_MS === 604800000);

// ── isFresh ───────────────────────────────────────────────────────────────────
const now = 1_000_000_000_000;
const scanned = (over = {}) => ({ basis: "scanned", vulnDbVersion: "v1", timestampMs: now, ...over });

ok("fresh: within age + matching DB → fresh",
  isFresh(scanned(), { maxAgeMs: 10_000, currentDbVersion: "v1", nowMs: now + 5_000 }) === true);
ok("fresh: DB-version mismatch → stale",
  isFresh(scanned(), { maxAgeMs: 10_000, currentDbVersion: "v2", nowMs: now + 5_000 }) === false);
ok("fresh: age beyond max → stale",
  isFresh(scanned(), { maxAgeMs: 10_000, currentDbVersion: "v1", nowMs: now + 20_000 }) === false);
ok("fresh: missing currentDbVersion skips DB check (age governs)",
  isFresh(scanned(), { maxAgeMs: 10_000, nowMs: now + 5_000 }) === true);
ok("fresh: no timestamp → never fresh",
  isFresh({ basis: "scanned", vulnDbVersion: "v1" }, { maxAgeMs: 10_000, currentDbVersion: "v1", nowMs: now }) === false);
ok("fresh: null record → not fresh",
  isFresh(null, { maxAgeMs: 10_000, currentDbVersion: "v1", nowMs: now }) === false);
// user-approved: age-only, no DB binding (fresh even when the DB has bumped).
ok("fresh: user-approved fresh on age despite DB bump",
  isFresh({ basis: "user-approved", timestampMs: now }, { maxAgeMs: 10_000, currentDbVersion: "v2", nowMs: now + 5_000 }) === true);
ok("fresh: user-approved expires by age",
  isFresh({ basis: "user-approved", timestampMs: now }, { maxAgeMs: 10_000, currentDbVersion: "v2", nowMs: now + 20_000 }) === false);

// ── F4: future-dated cert rejected (clock-skew guard) ─────────────────────────
ok("default: DEFAULT_CLOCK_SKEW_MS === 5 min in ms (300000)",
  DEFAULT_CLOCK_SKEW_MS === 300000);
// A forged FAR-future timestamp would yield a negative age (< maxAgeMs) and be
// silently trusted without this guard.
ok("fresh: far-future timestamp → NOT fresh (forged future-dated cert rejected)",
  isFresh(scanned({ timestampMs: now + 10 * 60 * 1000 }), { maxAgeMs: 10_000, currentDbVersion: "v1", nowMs: now }) === false);
ok("fresh: user-approved far-future timestamp → NOT fresh (forgery rejected)",
  isFresh({ basis: "user-approved", timestampMs: now + 10 * 60 * 1000 }, { maxAgeMs: 10_000, nowMs: now }) === false);
// Within tolerated skew (a benign few seconds ahead) is still fresh.
ok("fresh: small future skew within tolerance → fresh",
  isFresh(scanned({ timestampMs: now + 2_000 }), { maxAgeMs: 10_000, currentDbVersion: "v1", nowMs: now }) === true);
// Custom clockSkewMs honored: a 10-min-future cert is fresh only if skew allows.
ok("fresh: custom clockSkewMs admits a future cert within the larger window",
  isFresh(scanned({ timestampMs: now + 10 * 60 * 1000 }), { maxAgeMs: 10_000, currentDbVersion: "v1", nowMs: now, clockSkewMs: 15 * 60 * 1000 }) === true);
ok("fresh: custom clockSkewMs=0 rejects even a 1ms-future cert",
  isFresh(scanned({ timestampMs: now + 1 }), { maxAgeMs: 10_000, currentDbVersion: "v1", nowMs: now, clockSkewMs: 0 }) === false);

// ── F1 support: DB-version binding (string versions; user-approved exempt) ─────
ok("fresh: vulnDbVersion 'A' vs currentDbVersion 'A' → fresh",
  isFresh(scanned({ vulnDbVersion: "A" }), { maxAgeMs: 10_000, currentDbVersion: "A", nowMs: now }) === true);
ok("fresh: vulnDbVersion 'A' vs currentDbVersion 'B' → stale (DB bumped)",
  isFresh(scanned({ vulnDbVersion: "A" }), { maxAgeMs: 10_000, currentDbVersion: "B", nowMs: now }) === false);
ok("fresh: user-approved ignores DB mismatch (no DB binding on an approval)",
  isFresh({ basis: "user-approved", timestampMs: now, vulnDbVersion: "A" }, { maxAgeMs: 10_000, currentDbVersion: "B", nowMs: now }) === true);

// ── decideFromFindings ────────────────────────────────────────────────────────
const high = { id: "CVE-1", severity: "high", package: "requests", source: "osv" };
const med  = { id: "CVE-2", severity: "medium", package: "flask", source: "osv" };
const low  = { id: "CVE-3", severity: "low", package: "click", source: "osv" };

const enforceHigh = { severityThreshold: "high", mode: "enforce" };
const advisoryHigh = { severityThreshold: "high", mode: "advisory" };

ok("decide: no findings → allow",
  decideFromFindings({ rawFindings: [] }, enforceHigh).effect === "allow");
ok("decide: advisory never blocks (high finding still allow)",
  decideFromFindings({ rawFindings: [high] }, advisoryHigh).effect === "allow");
ok("decide: enforce high at 'high' threshold → deny",
  decideFromFindings({ rawFindings: [high] }, enforceHigh).effect === "deny");
ok("decide: enforce medium at 'high' threshold → allow (below threshold)",
  decideFromFindings({ rawFindings: [med] }, enforceHigh).effect === "allow");

// Recompute under a CHANGED policy (no re-scan): same record, lower threshold.
const recWithMed = { rawFindings: [med] };
ok("decide: recompute — medium below 'high' threshold → allow",
  decideFromFindings(recWithMed, { severityThreshold: "high", mode: "enforce" }).effect === "allow");
ok("decide: recompute — same record at 'medium' threshold → review",
  decideFromFindings(recWithMed, { severityThreshold: "medium", mode: "enforce" }).effect === "review");

// Threshold at/above behavior: critical/high → deny; medium/low blocking → review.
ok("decide: enforce critical → deny",
  decideFromFindings({ rawFindings: [{ id: "CVE-9", severity: "critical", package: "p" }] }, { severityThreshold: "low", mode: "enforce" }).effect === "deny");
ok("decide: enforce low at 'low' threshold → review (blocking but not high)",
  decideFromFindings({ rawFindings: [low] }, { severityThreshold: "low", mode: "enforce" }).effect === "review");
ok("decide: mixed findings — highest blocking decides (high present → deny)",
  decideFromFindings({ rawFindings: [low, med, high] }, enforceHigh).effect === "deny");
ok("decide: findings carried through in result",
  decideFromFindings({ rawFindings: [high] }, enforceHigh).findings.length === 1);

// ── COVERAGE honesty (A-SCANNER F1/F2): empty findings is only clean at full ──
// A 'scanned' record with NO findings but coverage 'full' → genuinely clean.
ok("decide: scanned + full coverage + no findings → allow",
  decideFromFindings({ basis: "scanned", rawFindings: [], scanCoverage: "full" }, enforceHigh).effect === "allow");
// Partial coverage (declared-only) with no findings → ENFORCE review, not allow.
ok("decide: scanned + declared-only coverage + no findings → review (enforce)",
  decideFromFindings({ basis: "scanned", rawFindings: [], scanCoverage: "declared-only" }, enforceHigh).effect === "review");
ok("decide: scanned + unavailable coverage + no findings → review (enforce)",
  decideFromFindings({ basis: "scanned", rawFindings: [], scanCoverage: "unavailable" }, enforceHigh).effect === "review");
// Back-compat: MISSING scanCoverage on a scanned record → treated as 'unavailable'.
ok("decide: scanned + MISSING coverage + no findings → review (enforce, conservative)",
  decideFromFindings({ basis: "scanned", rawFindings: [] }, enforceHigh).effect === "review");
ok("decide: partial-coverage review reason names the coverage level",
  /coverage: declared-only/.test(decideFromFindings({ basis: "scanned", rawFindings: [], scanCoverage: "declared-only" }, enforceHigh).reason));
// Advisory: partial coverage allows (with a note), never blocks.
ok("decide: scanned + partial coverage + no findings → allow (advisory, with note)",
  (() => { const d = decideFromFindings({ basis: "scanned", rawFindings: [], scanCoverage: "unavailable" }, advisoryHigh); return d.effect === "allow" && /coverage: unavailable/.test(d.reason); })());
// A real finding blocks regardless of coverage (coverage only matters when empty).
ok("decide: scanned + partial coverage + a high finding → deny (enforce; finding wins)",
  decideFromFindings({ basis: "scanned", rawFindings: [high], scanCoverage: "declared-only" }, enforceHigh).effect === "deny");
// user-approved with no findings is exempt from the coverage check (human override).
ok("decide: user-approved + no findings → allow (coverage check does not apply)",
  decideFromFindings({ basis: "user-approved", rawFindings: [] }, enforceHigh).effect === "allow");
// A record with no basis (legacy decide-only callers) + no findings stays allow.
ok("decide: no basis + no findings → allow (unchanged for basis-less records)",
  decideFromFindings({ rawFindings: [] }, enforceHigh).effect === "allow");

console.log(`\n${fail === 0 ? "ALL PASS" : fail + " FAILED"}`);
process.exit(fail === 0 ? 0 : 1);

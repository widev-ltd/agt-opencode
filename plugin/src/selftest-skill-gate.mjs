// selftest-skill-gate.mjs — integration tests for the runtime supply-chain gate
// wired into policy.mjs: checkSkillDeps (PreToolUse) + recordSkillApproval
// (PostToolUse). Builds a real on-disk skill, drives the approval-once flow, and
// asserts the scoping that keeps the benchmark seal intact.
// Run: node selftest-skill-gate.mjs

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { generateKeyPairSync } from "node:crypto";

import { compilePolicy, checkSkillDeps, recordSkillApproval } from "./policy.mjs";
import { skillFileHashesSync } from "./skills.mjs";
import { skillIntegrityKey, readAttestation, writeAttestation, signAttestationRecord, attestationPath } from "./attestation.mjs";

let fail = 0;
const ok = (name, cond) => { console.log(`${cond ? "PASS" : "FAIL"}  ${name}`); if (!cond) fail++; };

// Isolate the attestation cache on disk.
const dataDir = mkdtempSync(join(tmpdir(), "agt-gate-data-"));
process.env.AGT_SESSION_STORE = "disk";
process.env.CLAUDE_PLUGIN_DATA = dataDir;

// Build a real skill on disk under a .../skills/<name>/ layout so
// checkSkillInvocationMeta recognizes a command that runs its script.
const base = mkdtempSync(join(tmpdir(), "agt-gate-skill-"));
const skillDir = join(base, "skills", "demo");
mkdirSync(join(skillDir, "scripts"), { recursive: true });
writeFileSync(join(skillDir, "SKILL.md"), "# Demo\nFormats local files. No network.");
writeFileSync(join(skillDir, "scripts", "run.sh"), "#!/usr/bin/env bash\necho hello\n");
const runCmd = `bash ${join(skillDir, "scripts", "run.sh")}`;

try {
  // ── Scoping: out-of-scope commands are a true no-op (seal safety) ──
  const advisory = compilePolicy({
    dependencyPolicies: { enabled: true, mode: "advisory" },
    skillPolicies: { enabled: true, mode: "advisory" },
  });
  const advState = { policy: advisory };
  ok("scope: ordinary command → null (no-op)",
    checkSkillDeps(advState, { command: "ls -la", cwd: base }) === null);
  ok("scope: rm -rf is NOT treated as a dep command → null",
    checkSkillDeps(advState, { command: "rm -rf /tmp/x", cwd: base }) === null);
  ok("scope: policies disabled → null",
    checkSkillDeps({ policy: compilePolicy({}) }, { command: runCmd, cwd: base }) === null);

  // ── Tier-1 dependency hygiene ── (typosquat/unpinned checks were removed; test a kept one)
  const nonreg = checkSkillDeps(advState, { command: "pip install git+https://github.com/evil/pkg.git", cwd: base });
  ok("deps: non-registry source surfaced as advisory note (no deny in advisory)",
    nonreg && nonreg.deny === null && nonreg.notes.some((n) => /non-registry/i.test(n)));

  const enforceDeps = compilePolicy({
    dependencyPolicies: { enabled: true, mode: "enforce", deny: ["evilpkg"], severityThreshold: "high" },
  });
  const denyRes = checkSkillDeps({ policy: enforceDeps }, { command: "pip install evilpkg", cwd: base });
  ok("deps: enforce + denied package → hard deny",
    denyRes && typeof denyRes.deny === "string" && /denied-package/.test(denyRes.deny));

  // ── Attestation gate: advisory missing-cert is a note only ──
  const advMiss = checkSkillDeps(advState, { command: runCmd, cwd: base });
  ok("attest: advisory + no cert → note only, never deny/review",
    advMiss && advMiss.deny === null && advMiss.raiseToReview === false &&
    advMiss.notes.some((n) => /not yet attested/i.test(n)));

  // ── Approval-once flow (enforce) ──
  const enforce = compilePolicy({
    skillPolicies: { enabled: true, mode: "enforce" },
  });
  const enfState = { policy: enforce };

  // 1) First PreToolUse: no cert and (in this direct sync call) no local scan run →
  //    review (fail-safe). The async ensureSkillScanned would normally scan first.
  const pre1 = checkSkillDeps(enfState, { command: runCmd, cwd: base });
  ok("approval: enforce + no cert + no local scan → review (fail-safe)",
    pre1 && pre1.deny === null && pre1.raiseToReview === true &&
    pre1.notes.some((n) => /not attested/i.test(n)));

  // 2) PostToolUse (the user approved): record a user-approved cert.
  recordSkillApproval(enfState, { command: runCmd, cwd: base });
  const key = skillIntegrityKey(skillFileHashesSync(skillDir));
  const cert = readAttestation(key);
  ok("approval: PostToolUse wrote a user-approved cert",
    cert && cert.basis === "user-approved");

  // 3) Second PreToolUse on the UNCHANGED skill: fresh clean cert → silent allow.
  const pre2 = checkSkillDeps(enfState, { command: runCmd, cwd: base });
  ok("approval: unchanged skill after approval → silent allow (no review, no note)",
    (pre2 === null) || (pre2.deny === null && pre2.raiseToReview === false && pre2.notes.length === 0));

  // 4) Idempotent: a second approval does not overwrite the fresh cert.
  const tsBefore = readAttestation(key).timestampMs;
  recordSkillApproval(enfState, { command: runCmd, cwd: base });
  ok("approval: recording is idempotent (fresh cert untouched)",
    readAttestation(key).timestampMs === tsBefore);

  // 5) A CHANGED skill → new key → asked again (the old cert no longer applies).
  writeFileSync(join(skillDir, "scripts", "run.sh"), "#!/usr/bin/env bash\necho changed\n");
  const pre3 = checkSkillDeps(enfState, { command: runCmd, cwd: base });
  ok("approval: edited skill → new key → re-prompted (raiseToReview)",
    pre3 && pre3.raiseToReview === true);

  // ── Panel-fix regressions (S1 / F1 / F2 / coverage honesty) ──
  const dbCachePath = join(dataDir, "scanner-db-version.json");
  const mkSkill = (name, body) => {
    const d = join(base, "skills", name);
    mkdirSync(join(d, "scripts"), { recursive: true });
    writeFileSync(join(d, "SKILL.md"), `# ${name}`);
    writeFileSync(join(d, "scripts", "run.sh"), body ?? "#!/usr/bin/env bash\necho ok\n");
    return { dir: d, cmd: `bash ${join(d, "scripts", "run.sh")}` };
  };

  // S1: an EMPTY skill dir has no hashable files → must NEVER silent-allow.
  const emptyDir = join(base, "skills", "empty");
  mkdirSync(join(emptyDir, "scripts"), { recursive: true });
  const emptyCmd = `bash ${join(emptyDir, "scripts", "run.sh")}`; // file doesn't exist; dir is empty
  const s1 = checkSkillDeps(enfState, { command: emptyCmd, cwd: base });
  ok("S1: enforce + empty/unhashable skill → review, never silent allow",
    s1 && s1.deny === null && s1.raiseToReview === true &&
    s1.notes.some((n) => /hashable|identity/i.test(n)));
  recordSkillApproval(enfState, { command: emptyCmd, cwd: base });
  ok("S1: no silencing cert written for an empty/unhashable skill",
    readAttestation(skillIntegrityKey(skillFileHashesSync(emptyDir))) === null);

  // coverage honesty: a scanned cert with scanCoverage:'unavailable' + no findings
  // must NOT be a clean silent-allow (enforce → review).
  const cov = mkSkill("cov");
  writeAttestation(skillIntegrityKey(skillFileHashesSync(cov.dir)), {
    basis: "scanned", manifestHash: "x", rawFindings: [], scanCoverage: "unavailable",
    scannerName: null, vulnDbVersion: null, timestampMs: Date.now(), policySnapshot: { mode: "enforce" },
  });
  const covRes = checkSkillDeps(enfState, { command: cov.cmd, cwd: base });
  ok("coverage: scanned cert with coverage=unavailable → review, not silent allow",
    covRes && covRes.deny === null && covRes.raiseToReview === true);

  // F1: a clean full-coverage scanned cert goes STALE when the cached scanner DB
  // version advances → the runtime gate (scanner-free) must require review.
  const dbk = mkSkill("dbbind");
  const dbKey = skillIntegrityKey(skillFileHashesSync(dbk.dir));
  writeAttestation(dbKey, {
    basis: "scanned", manifestHash: "x", rawFindings: [], scanCoverage: "full",
    scannerName: "trivy", vulnDbVersion: "DB-1", timestampMs: Date.now(), policySnapshot: { mode: "enforce" },
  });
  const f1Fresh = checkSkillDeps(enfState, { command: dbk.cmd, cwd: base });
  ok("F1: clean full cert, no DB cache → silent allow (age-only fresh)",
    (f1Fresh === null) || (f1Fresh.deny === null && f1Fresh.raiseToReview === false));
  writeFileSync(dbCachePath, JSON.stringify({ version: "DB-2" })); // DB advanced past the cert
  const f1Stale = checkSkillDeps(enfState, { command: dbk.cmd, cwd: base });
  ok("F1: same cert after a DB bump → stale → review (DB binding live, scanner-free)",
    f1Stale && f1Stale.raiseToReview === true && f1Stale.notes.some((n) => /stale/i.test(n)));
  rmSync(dbCachePath, { force: true });

  // F2: recordSkillApproval must NOT overwrite a `scanned` cert (with findings)
  // with a clean user-approved one (no finding-laundering), even when stale.
  const laundr = mkSkill("laundr");
  const lKey = skillIntegrityKey(skillFileHashesSync(laundr.dir));
  writeAttestation(lKey, {
    basis: "scanned", manifestHash: "x",
    rawFindings: [{ id: "CVE-X", severity: "high", package: "p", source: "trivy" }],
    scanCoverage: "full", scannerName: "trivy", vulnDbVersion: "DB-1",
    timestampMs: Date.now() - 999 * 24 * 3600 * 1000, // very old → stale
    policySnapshot: { mode: "enforce" },
  });
  recordSkillApproval(enfState, { command: laundr.cmd, cwd: base });
  const lAfter = readAttestation(lKey);
  ok("F2: stale scanned cert is NOT laundered to user-approved by approval",
    lAfter && lAfter.basis === "scanned" && (lAfter.rawFindings ?? []).length === 1);

  // CONFIG: an UNSIGNED local stamp uses the 1-day GRACE window (localGraceMs), not
  // maxAgeMs (which governs CI-signed stamps — tested in the signature block). A
  // ~1h-old clean local stamp is fresh under the default 1-day grace but STALE
  // under a 60s localGraceMs override.
  const age = mkSkill("agecfg");
  const ageKey = skillIntegrityKey(skillFileHashesSync(age.dir));
  writeAttestation(ageKey, {
    basis: "scanned", manifestHash: "x", rawFindings: [], scanCoverage: "transitive",
    scannerName: "trivy", vulnDbVersion: "DB-1",
    timestampMs: Date.now() - 3600 * 1000, // ~1 hour old
    policySnapshot: { mode: "enforce" },
  });
  const ageDefault = checkSkillDeps(enfState, { command: age.cmd, cwd: base });
  ok("config: 1h-old clean local stamp under default 1-day grace → fresh → allow",
    (ageDefault === null) || (ageDefault.deny === null && ageDefault.raiseToReview === false));
  const enfShortGrace = { policy: compilePolicy({
    skillPolicies: { enabled: true, mode: "enforce", localGraceMs: 60 * 1000 },
  }) };
  const ageShort = checkSkillDeps(enfShortGrace, { command: age.cmd, cwd: base });
  ok("config: same local stamp under localGraceMs=60s → stale → review (1-day knob wired)",
    ageShort && ageShort.raiseToReview === true && ageShort.notes.some((n) => /stale/i.test(n)));

  // ── SIGNATURE GATE: external-signer trust (two tiers) ──
  // TIER 1 (strong): a CI/HSM private key the agent box never holds signs a PASS;
  //   the gate verifies with the public key (delivered out of band). A signature IS
  //   the pass (CI never signs a fail), so a fresh CI stamp → allow, unforgeable.
  // TIER 2 (weak, DEFAULT): an unsigned skill gets a local scan + a 1-day grace
  //   stamp — forgeable but time-boxed. STRICT mode (requireSignature) drops tier 2.
  {
    const ci = generateKeyPairSync("ed25519");
    const ciPub = ci.publicKey.export({ type: "spki", format: "pem" }).toString();
    const ciPriv = ci.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const attacker = generateKeyPairSync("ed25519");
    const attackerPriv = attacker.privateKey.export({ type: "pkcs8", format: "pem" }).toString();

    // signedState: trustedSigners set, requireSignature UNSET → now STRICT-by-default
    // (the strict-when-signed change). Valid CI signatures still pass under it.
    const signedState = { policy: compilePolicy({
      skillPolicies: { enabled: true, mode: "enforce", trustedSigners: [ciPub] },
    }) };
    // strictState: explicit requireSignature:true (identical effective behavior to
    // signedState now, kept to document the explicit opt-in).
    const strictState = { policy: compilePolicy({
      skillPolicies: { enabled: true, mode: "enforce", trustedSigners: [ciPub], requireSignature: true },
    }) };
    // localFallbackState: trustedSigners set but requireSignature EXPLICITLY false →
    // the operator opted back into the forgeable local tier alongside CI signing.
    // The 1-day-grace local-tier tests run under THIS state (the strict-when-signed
    // default would otherwise block the unsigned local stamp).
    const localFallbackState = { policy: compilePolicy({
      skillPolicies: { enabled: true, mode: "enforce", trustedSigners: [ciPub], requireSignature: false },
    }) };

    // STRICT-WHEN-SIGNED DEFAULT: trustedSigners set + requireSignature unset ⇒ strict.
    ok("default: trustedSigners set + requireSignature unset ⇒ requireSignature true (strict-when-signed)",
      compilePolicy({ skillPolicies: { enabled: true, trustedSigners: [ciPub] } }).skill.requireSignature === true);
    ok("default: no trustedSigners + requireSignature unset ⇒ requireSignature false (back-compat local tier)",
      compilePolicy({ skillPolicies: { enabled: true } }).skill.requireSignature === false);
    ok("default: trustedSigners set + explicit requireSignature:false ⇒ false (operator opt-out honored)",
      compilePolicy({ skillPolicies: { enabled: true, trustedSigners: [ciPub], requireSignature: false } }).skill.requireSignature === false);

    const mkSigSkill = (name) => {
      const d = join(base, "skills", name);
      mkdirSync(join(d, "scripts"), { recursive: true });
      writeFileSync(join(d, "SKILL.md"), `# ${name}`);
      writeFileSync(join(d, "scripts", "run.sh"), "#!/usr/bin/env bash\necho ok\n");
      return { dir: d, cmd: `bash ${join(d, "scripts", "run.sh")}`,
        key: skillIntegrityKey(skillFileHashesSync(d)) };
    };
    const rec = (key, findings) => ({
      schema: 1, key, basis: "scanned", scanCoverage: "transitive",
      rawFindings: findings, scannerName: "trivy", vulnDbVersion: null,
      timestampMs: Date.now(), policySnapshot: { mode: "enforce" },
    });
    const toCache = (key, record) => {
      const p = attestationPath(key);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, `${JSON.stringify(record)}\n`);
    };
    const shipAlongside = (dir, record) =>
      writeFileSync(join(dir, ".agt-attestation.json"), `${JSON.stringify(record)}\n`);
    const allowed = (r) => r === null || (r.deny === null && r.raiseToReview === false);
    const reviewed = (r) => r && r.deny === null && r.raiseToReview === true;

    // T1.1 — CI-signed pass in the local cache → allow (signature = pass; no findings re-eval).
    const a = mkSigSkill("ci-cache");
    toCache(a.key, signAttestationRecord(rec(a.key, []), ciPriv));
    ok("sig T1: CI-signed pass (cache) → allow", allowed(checkSkillDeps(signedState, { command: a.cmd, cwd: base })));

    // T1.2 — CI-signed pass SHIPPED ALONGSIDE the skill → allow (the .agt-attestation.json
    //        file is excluded from the integrity hash, so the binding still holds).
    const b = mkSigSkill("ci-shipped");
    shipAlongside(b.dir, signAttestationRecord(rec(b.key, []), ciPriv));
    ok("sig T1: CI-signed pass (shipped alongside skill) → allow", allowed(checkSkillDeps(signedState, { command: b.cmd, cwd: base })));

    // T1.3 — STRICT + valid CI signature → allow.
    const c = mkSigSkill("strict-ci");
    toCache(c.key, signAttestationRecord(rec(c.key, []), ciPriv));
    ok("sig T1: strict + valid CI signature → allow", allowed(checkSkillDeps(strictState, { command: c.cmd, cwd: base })));

    // T1.4 — STRICT + CI cert ~1h old but maxAgeMs=60s → stale → review (tier-1 maxAgeMs knob).
    const dPol = { policy: compilePolicy({
      skillPolicies: { enabled: true, mode: "enforce", trustedSigners: [ciPub], requireSignature: true, maxAgeMs: 60 * 1000 },
    }) };
    const d = mkSigSkill("strict-stale");
    toCache(d.key, signAttestationRecord({ ...rec(d.key, []), timestampMs: Date.now() - 3600 * 1000 }, ciPriv));
    ok("sig T1: strict + CI cert older than maxAgeMs → stale → review", reviewed(checkSkillDeps(dPol, { command: d.cmd, cwd: base })));

    // T1.5 — STRICT + UNSIGNED → review (no local fallback in strict mode).
    const e = mkSigSkill("strict-unsigned");
    toCache(e.key, rec(e.key, []));
    ok("sig T1: strict + unsigned stamp → review (no fallback)", reviewed(checkSkillDeps(strictState, { command: e.cmd, cwd: base })));

    // T1.6 — STRICT + ATTACKER-signed (untrusted key) → review.
    const f = mkSigSkill("strict-attacker");
    toCache(f.key, signAttestationRecord(rec(f.key, []), attackerPriv));
    ok("sig T1: strict + attacker-key signature → review (untrusted)", reviewed(checkSkillDeps(strictState, { command: f.cmd, cwd: base })));

    // T1.7 — STRICT + TAMPERED CI stamp (sig no longer matches) → review.
    const g = mkSigSkill("strict-tamper");
    const tampered = signAttestationRecord(rec(g.key, [{ id: "CVE-Z", severity: "high", package: "z" }]), ciPriv);
    tampered.rawFindings = []; // erased after signing
    toCache(g.key, tampered);
    ok("sig T1: strict + tampered CI stamp → review", reviewed(checkSkillDeps(strictState, { command: g.cmd, cwd: base })));

    // T2.0 — STRICT-BY-DEFAULT: the SAME unsigned clean local stamp under signedState
    // (requireSignature now defaults true) → review, NOT allow (no silent local fallback).
    const h0 = mkSigSkill("default-strict-local");
    toCache(h0.key, rec(h0.key, []));
    ok("sig: strict-by-default blocks an unsigned local stamp (no silent local fallback) → review",
      reviewed(checkSkillDeps(signedState, { command: h0.cmd, cwd: base })));

    // T2.1 — EXPLICIT opt-out (requireSignature:false): unsigned CLEAN local stamp → allow (1-day grace; weak tier).
    const h = mkSigSkill("local-clean");
    toCache(h.key, rec(h.key, []));
    ok("sig T2: explicit requireSignature:false → unsigned clean local stamp → allow (1-day grace, weak tier)",
      allowed(checkSkillDeps(localFallbackState, { command: h.cmd, cwd: base })));

    // T2.2 — EXPLICIT opt-out: unsigned local stamp WITH a CVE → deny (local tier still blocks known vulns).
    const i = mkSigSkill("local-vuln");
    toCache(i.key, rec(i.key, [{ id: "CVE-Q", severity: "high", package: "q" }]));
    const ri = checkSkillDeps(localFallbackState, { command: i.cmd, cwd: base });
    ok("sig T2: explicit requireSignature:false → unsigned local stamp with a CVE → deny", ri && typeof ri.deny === "string");

    // BACK-COMPAT — no trustedSigners at all: unsigned clean local stamp → allow.
    const j = mkSigSkill("nokeys");
    toCache(j.key, rec(j.key, []));
    ok("sig: no trustedSigners → unsigned clean local stamp → allow (back-compat)",
      allowed(checkSkillDeps({ policy: compilePolicy({ skillPolicies: { enabled: true, mode: "enforce" } }) }, { command: j.cmd, cwd: base })));

    // ── HARDENING: embedded validity window (notBefore / notAfter) ──
    // A CI-signed stamp that VERIFIES under a trusted key but whose embedded validity
    // window has passed (or not yet begun) must be NOT-trusted → review (same path as
    // stale). The window is in the signed payload, so it is tamper-proof.
    const nowT = Date.now();

    // VW.1 — notAfter in the PAST → expired → review (otherwise a perfectly clean, signed, fresh stamp).
    const va = mkSigSkill("vw-expired");
    toCache(va.key, signAttestationRecord(rec(va.key, []), ciPriv, "ci", { notAfter: nowT - 60 * 1000 }));
    const vaRes = checkSkillDeps(strictState, { command: va.cmd, cwd: base });
    ok("VW: signed stamp past its notAfter → review (expired), never allow",
      reviewed(vaRes) && vaRes.notes.some((n) => /expired|validity window/i.test(n)));

    // VW.2 — notBefore in the FUTURE (beyond skew) → not-yet-valid → review.
    const vb = mkSigSkill("vw-future");
    toCache(vb.key, signAttestationRecord(rec(vb.key, []), ciPriv, "ci", { notBefore: nowT + 60 * 60 * 1000 }));
    const vbRes = checkSkillDeps(strictState, { command: vb.cmd, cwd: base });
    ok("VW: signed stamp before its notBefore → review (not yet valid), never allow",
      reviewed(vbRes) && vbRes.notes.some((n) => /not yet valid|notBefore/i.test(n)));

    // VW.3 — a valid window (notBefore in the past, notAfter in the future) → still allows.
    const vc = mkSigSkill("vw-valid");
    toCache(vc.key, signAttestationRecord(rec(vc.key, []), ciPriv, "ci",
      { notBefore: nowT - 60 * 1000, notAfter: nowT + 60 * 60 * 1000 }));
    ok("VW: signed stamp within its validity window → allow",
      allowed(checkSkillDeps(strictState, { command: vc.cmd, cwd: base })));

    // VW.4 — notAfter OVERRIDES (tightens) maxAgeMs: a 1h-old stamp is fresh under a
    // 7-day maxAgeMs, but a notAfter 10 min before now expires it regardless → review.
    const vd = mkSigSkill("vw-notafter-tighter");
    toCache(vd.key, signAttestationRecord(
      { ...rec(vd.key, []), timestampMs: nowT - 3600 * 1000 }, ciPriv, "ci", { notAfter: nowT - 10 * 60 * 1000 }));
    ok("VW: notAfter tighter than maxAgeMs wins → expired → review (even though age < maxAgeMs)",
      reviewed(checkSkillDeps(strictState, { command: vd.cmd, cwd: base })));

    // ── HARDENING: revocation (keyId + attestation key kill-switches) ──
    // VR.1 — revoked keyId → the otherwise-valid signed stamp is NOT-trusted → review.
    const vrA = mkSigSkill("revoked-keyid");
    toCache(vrA.key, signAttestationRecord(rec(vrA.key, []), ciPriv, "ci", { keyId: "ci-key-leaked" }));
    const revokeKeyIdState = { policy: compilePolicy({
      skillPolicies: { enabled: true, mode: "enforce", trustedSigners: [ciPub], revokedKeyIds: ["ci-key-leaked"] },
    }) };
    const vrARes = checkSkillDeps(revokeKeyIdState, { command: vrA.cmd, cwd: base });
    ok("REVOKE: signed stamp with a revoked keyId → review (revoked), never allow",
      reviewed(vrARes) && vrARes.notes.some((n) => /revoked/i.test(n)) &&
      vrARes.audit.some((a) => /revoked/.test(a.action)));

    // VR.2 — a NON-revoked keyId under the same revocation list still allows (no over-block).
    const vrB = mkSigSkill("nonrevoked-keyid");
    toCache(vrB.key, signAttestationRecord(rec(vrB.key, []), ciPriv, "ci", { keyId: "ci-key-good" }));
    ok("REVOKE: signed stamp with a non-revoked keyId → allow (revocation is targeted)",
      allowed(checkSkillDeps(revokeKeyIdState, { command: vrB.cmd, cwd: base })));

    // VR.3 — revoked ATTESTATION KEY (the content-address skillIntegrityKey) → review.
    const vrC = mkSigSkill("revoked-attkey");
    toCache(vrC.key, signAttestationRecord(rec(vrC.key, []), ciPriv));
    const revokeAttKeyState = { policy: compilePolicy({
      skillPolicies: { enabled: true, mode: "enforce", trustedSigners: [ciPub], revokedAttestationKeys: [vrC.key] },
    }) };
    const vrCRes = checkSkillDeps(revokeAttKeyState, { command: vrC.cmd, cwd: base });
    ok("REVOKE: signed stamp whose attestation key is revoked → review (revoked), never allow",
      reviewed(vrCRes) && vrCRes.notes.some((n) => /revoked/i.test(n)));

    // VR.4 — revocation list present but this stamp matches neither → allow (no collateral).
    const vrD = mkSigSkill("revoke-nomatch");
    toCache(vrD.key, signAttestationRecord(rec(vrD.key, []), ciPriv, "ci", { keyId: "ci-key-good" }));
    const revokeNoMatchState = { policy: compilePolicy({
      skillPolicies: { enabled: true, mode: "enforce", trustedSigners: [ciPub],
        revokedKeyIds: ["some-other-key"], revokedAttestationKeys: ["deadbeef"] },
    }) };
    ok("REVOKE: a non-matching revocation list does not block a good stamp → allow",
      allowed(checkSkillDeps(revokeNoMatchState, { command: vrD.cmd, cwd: base })));
  }

  // ── Robustness: never throws on a bad cwd / command ──
  let threw = false;
  try {
    checkSkillDeps(enfState, { command: runCmd, cwd: " bad" });
    recordSkillApproval(enfState, { command: 12345, cwd: null });
  } catch {
    threw = true;
  }
  ok("robustness: gate + approval never throw on hostile input", threw === false);
} finally {
  delete process.env.AGT_SESSION_STORE;
  delete process.env.CLAUDE_PLUGIN_DATA;
  rmSync(base, { recursive: true, force: true });
  rmSync(dataDir, { recursive: true, force: true });
}

console.log(`\n${fail === 0 ? "ALL PASS" : fail + " FAILED"}`);
process.exit(fail === 0 ? 0 : 1);

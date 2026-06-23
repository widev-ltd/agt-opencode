// sign.mjs — the CI / pipeline SKILL SIGNER. DELIVERED SEPARATELY from the runtime
// plugin and NEVER installed on the agent box: CI runs it with a PRIVATE key that
// the agent's machine never sees. It scans a skill's FULL transitive dependency
// tree (uv/npm) + CVE scan (trivy/osv/pip-audit), and ONLY IF THE SKILL PASSES
// signs a `scanned` attestation (Ed25519) and writes it ALONGSIDE the skill
// (<skillDir>/.agt-attestation.json). A failing skill is NOT signed — there is no
// "signed but vulnerable": the signature IS the pass. The runtime plugin then
// verifies that signature with the matching PUBLIC key (delivered out of band).
//
//   node sign.mjs <skillDir> --key <ci-private.pem> [--threshold high] [--out <path>]
//
// Exit 0 = signed (pass); exit 1 = NOT signed (findings ≥ threshold, or unscannable);
// exit 2 = usage error. Requires uv/npm + a scanner on PATH (CI provides them).
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { mkdtempSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
// Locate the shared engine (scan + canonical sign helpers). Works in either repo:
// agt-claude-code (plugins/agt-governance/scripts) or agt-opencode (plugin/src).
const ENGINE = [
  join(here, "..", "..", "plugins", "agt-governance", "scripts"),
  join(here, "..", "..", "plugin", "src"),
].find((p) => { try { return readFileSync(join(p, "policy.mjs")) && true; } catch { return false; } })
  ?? join(here, "..", "..", "plugins", "agt-governance", "scripts");

function parseArgs(argv) {
  const out = { skillDir: null, key: null, threshold: "high", outPath: null, keyId: null, validDays: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--key") out.key = argv[++i];
    else if (a === "--threshold") out.threshold = argv[++i];
    else if (a === "--out") out.outPath = argv[++i];
    // --key-id stamps a signer id INTO the signed payload so a compromised key can
    // be revoked by id (skillPolicies.revokedKeyIds) without re-distributing keys.
    else if (a === "--key-id") out.keyId = argv[++i];
    // --valid-days N embeds notBefore=now / notAfter=now+N*86400s in the signed
    // payload; the gate rejects the stamp past notAfter even within its max-age.
    else if (a === "--valid-days") out.validDays = Number(argv[++i]);
    else if (a === "-h" || a === "--help") out.help = true;
    else out.skillDir = a;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (args.help || !args.skillDir || !args.key) {
  console.error("usage: node sign.mjs <skillDir> --key <ci-private.pem> [--threshold low|medium|high|critical] [--out <path>] [--key-id <id>] [--valid-days <N>]");
  process.exit(2);
}

// auditSkillDir persists its (unsigned) record to the data dir; isolate it.
process.env.CLAUDE_PLUGIN_DATA = mkdtempSync(join(tmpdir(), "agt-signer-"));
process.env.AGT_SESSION_STORE = "disk";

const pol = await import(pathToFileURL(join(ENGINE, "policy.mjs")).href);
const skills = await import(pathToFileURL(join(ENGINE, "skills.mjs")).href);
const att = await import(pathToFileURL(join(ENGINE, "attestation.mjs")).href);

const skillDir = resolve(args.skillDir);
const compiled = pol.compilePolicy({
  dependencyPolicies: { enabled: true, mode: "enforce", severityThreshold: args.threshold },
  skillPolicies: { enabled: true, mode: "enforce", severityThreshold: args.threshold },
});

// REAL scan (transitive resolve + CVE). auditSkillDir writes the canonical record.
const summary = await skills.auditSkillDir(skillDir, { skillPolicy: compiled.skill, depsPolicy: compiled.deps });
const record = att.readAttestation(summary.key);
if (!record) {
  console.error("sign: scan produced no attestation record (could not establish skill identity).");
  process.exit(1);
}

// PASS decision = the same logic the gate would apply to a clean transitive scan.
// (No signing of a failing skill — the signature is the pass.)
const decision = att.decideFromFindings(record, { mode: "enforce", severityThreshold: args.threshold });
const findings = record.rawFindings ?? [];
if (decision.effect !== "allow") {
  console.error(`NOT SIGNED — ${decision.reason}`);
  for (const f of findings.slice(0, 30)) console.error(`  - [${f.severity}] ${f.id ?? f.kind} ${f.package ? `(${f.package})` : ""}`);
  console.error(`coverage=${record.scanCoverage} scanner=${summary.scanner ?? "none"}`);
  process.exit(1);
}

// Optional key id + validity window, embedded INTO the signed payload (so they
// can't be tampered post-signing and enable id-based revocation / self-expiry).
const signOpts = {};
if (args.keyId) signOpts.keyId = String(args.keyId);
if (Number.isFinite(args.validDays) && args.validDays > 0) {
  const now = Date.now();
  signOpts.notBefore = now;
  signOpts.notAfter = now + args.validDays * 24 * 3600 * 1000;
}
const signed = att.signAttestationRecord(record, readFileSync(args.key, "utf8"), "ci", signOpts);
const outPath = args.outPath ? resolve(args.outPath) : join(skillDir, ".agt-attestation.json");
writeFileSync(outPath, `${JSON.stringify(signed, null, 2)}\n`);
console.log(`SIGNED (pass): ${skillDir}`);
console.log(`  coverage=${record.scanCoverage}  scanner=${summary.scanner}  key=${summary.key.slice(0, 16)}…`
  + `${signOpts.keyId ? `  keyId=${signOpts.keyId}` : ""}${signOpts.notAfter ? `  notAfter=${new Date(signOpts.notAfter).toISOString().slice(0, 10)}` : ""}`);
console.log(`  -> ${outPath}  (verify with the matching public key on the agent)`);
process.exit(0);

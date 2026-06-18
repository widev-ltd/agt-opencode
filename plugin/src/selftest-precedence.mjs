// selftest-precedence.mjs — regression test for the A-FAILOPEN CRITICAL.
//
// The base policy-engine decision must be AUTHORITATIVE: advisory/degraded
// extension layers (exfil-advisory, exfil-state-corrupt, rate-limit-advisory)
// may add context or RAISE strictness, but must NEVER downgrade a base
// deny/review into an allow. Before the fix, an advisory rate-limit (or a
// corrupt exfil state file) early-returned advisory context, silently dropping
// a base DENY — reachable on shipped defaults after the 500-call cap.
//
// Run: node selftest-precedence.mjs

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadPolicy, evaluatePreToolUse } from "./policy.mjs";

let fail = 0;
const ok = (n, c) => { console.log(`${c ? "PASS" : "FAIL"}  ${n}`); if (!c) fail++; };

const dir = mkdtempSync(join(tmpdir(), "agt-prec-"));
process.env.AGT_COPILOT_AUDIT_PATH = join(dir, "audit.json"); // keep audit out of $HOME
delete process.env.AGT_SESSION_STORE; // memory backend (counter persists in-process)

const policyPath = join(dir, "policy.json");
writeFileSync(policyPath, JSON.stringify({
  mode: "enforce",
  // A base DENY rule for recursive delete.
  blockedToolCalls: [{ id: "rm", tool: "bash", effect: "deny", commandPatterns: [{ source: "rm\\s+-rf", flags: "i" }] }],
  // Advisory rate-limit with a budget of 1 → the 2nd bash call triggers it.
  rateLimitPolicies: { enabled: true, mode: "advisory", budgets: [{ tool: "bash", limit: 1, windowSeconds: 3600 }] },
  exfilPolicies: { enabled: false },
}), "utf8");

try {
  const state = await loadPolicy({ defaultPolicyPath: policyPath, policyPath });
  const rmEvent = { toolName: "bash", toolArgs: { command: "rm -rf /important/data" }, cwd: dir };
  const inv = { sessionId: "prec-1" };

  const r1 = await evaluatePreToolUse(state, rmEvent, inv); // under rate budget
  ok("1st rm -rf is DENIED (base rule)", r1?.permissionDecision === "deny");

  const r2 = await evaluatePreToolUse(state, rmEvent, inv); // rate-limit advisory now trips
  ok("2nd rm -rf STILL DENIED — advisory rate-limit does NOT downgrade the base deny",
    r2?.permissionDecision === "deny");
  ok("2nd rm -rf is NOT an advisory allow (no bare additionalContext)",
    !(r2 && r2.additionalContext && !r2.permissionDecision));

  // A base-ALLOWED tool over the rate budget → advisory note, still allowed.
  const readEvent = { toolName: "read", toolArgs: { filePath: "README.md" }, cwd: dir };
  await evaluatePreToolUse(state, { toolName: "bash", toolArgs: { command: "echo a" }, cwd: dir }, { sessionId: "prec-2" });
  await evaluatePreToolUse(state, { toolName: "bash", toolArgs: { command: "echo b" }, cwd: dir }, { sessionId: "prec-2" });
  const rr = await evaluatePreToolUse(state, readEvent, { sessionId: "prec-2" });
  ok("base-allowed tool is not turned into a deny by advisory layers",
    !rr || rr.permissionDecision !== "deny");

  // ── recordAudit fail-open/availability regression (A-FAILOPEN F-CRIT-2) ──────
  // Force the audit path to be unwritable (parent is a FILE → mkdir ENOTDIR).
  // recordAudit must swallow the error: a base-ALLOW must stay allow (no
  // deny-everything) and a base-DENY must stay deny (no fail-open).
  const blockFile = join(dir, "auditblock");
  writeFileSync(blockFile, "x", "utf8");
  process.env.AGT_COPILOT_AUDIT_PATH = join(blockFile, "sub", "audit.json"); // parent is a file
  const state2 = await loadPolicy({ defaultPolicyPath: policyPath, policyPath });
  const aAllow = await evaluatePreToolUse(state2, { toolName: "read", toolArgs: { filePath: "x.js" }, cwd: dir }, { sessionId: "prec-3" });
  ok("broken audit path: base-allow stays allow (no deny-everything)",
    !aAllow || aAllow.permissionDecision !== "deny");
  const aDeny = await evaluatePreToolUse(state2, { toolName: "bash", toolArgs: { command: "rm -rf /x" }, cwd: dir }, { sessionId: "prec-3" });
  ok("broken audit path: base-deny stays deny (no fail-open)",
    aDeny?.permissionDecision === "deny");
  process.env.AGT_COPILOT_AUDIT_PATH = join(dir, "audit.json");
} finally {
  delete process.env.AGT_COPILOT_AUDIT_PATH;
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${fail === 0 ? "ALL PASS" : fail + " FAILED"}`);
process.exit(fail === 0 ? 0 : 1);

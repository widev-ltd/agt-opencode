// selftest-rate-limit.mjs — fixture tests for the session rate-limiter.
// Run: node selftest-rate-limit.mjs

import { compileRateLimitPolicy, checkRateLimit, resetSessions } from "./rate-limit.mjs";

let fail = 0;
const ok = (name, cond) => { console.log(`${cond ? "PASS" : "FAIL"}  ${name}`); if (!cond) fail++; };

const sid = "test-session-1";
const enforce = compileRateLimitPolicy({ enabled: true, mode: "enforce",
  budgets: [
    { tool: "Bash",     limit: 3, windowSeconds: 3600 },
    { tool: "WebFetch", limit: 2, windowSeconds: 3600 },
    { tool: "*",        limit: 10, windowSeconds: 3600 },
  ],
});
const advisory = compileRateLimitPolicy({ enabled: true, mode: "advisory",
  budgets: [{ tool: "Bash", limit: 3, windowSeconds: 3600 }, { tool: "*", limit: 10, windowSeconds: 3600 }],
});

resetSessions();

// ── Under budget ─────────────────────────────────────────────────────────────
ok("under budget: first call null", checkRateLimit(sid, "Bash", enforce) === null);
ok("under budget: second call null", checkRateLimit(sid, "Bash", enforce) === null);
ok("under budget: third call null (at limit)", checkRateLimit(sid, "Bash", enforce) === null);

// ── Exceeded ─────────────────────────────────────────────────────────────────
const exceeded = checkRateLimit(sid, "Bash", enforce);
ok("exceeded: result not null", exceeded !== null);
ok("exceeded: tool = Bash", exceeded?.tool === "Bash");
ok("exceeded: count > limit", exceeded?.count > 3);
ok("exceeded: reason string present", typeof exceeded?.reason === "string" && exceeded.reason.length > 0);

// ── Wildcard budget ───────────────────────────────────────────────────────────
resetSessions();
const sid2 = "test-session-2";
const totalPolicy = compileRateLimitPolicy({ enabled: true, mode: "enforce",
  budgets: [{ tool: "*", limit: 5, windowSeconds: 3600 }] });
for (let i = 0; i < 5; i++) { checkRateLimit(sid2, "Read", totalPolicy); }
const totalExceeded = checkRateLimit(sid2, "Bash", totalPolicy);
ok("wildcard: total budget exceeded across tools", totalExceeded?.tool === "total");

// ── Advisory mode doesn't deny ───────────────────────────────────────────────
resetSessions();
const sid3 = "test-session-3";
for (let i = 0; i < 5; i++) { checkRateLimit(sid3, "Bash", advisory); }
const advisoryResult = checkRateLimit(sid3, "Bash", advisory);
ok("advisory: still returns budget-exceeded object (for context injection)", advisoryResult !== null);
ok("advisory: policy mode is advisory", advisory.mode === "advisory");

// ── Disabled policy ───────────────────────────────────────────────────────────
const disabled = compileRateLimitPolicy({ enabled: false });
ok("disabled: compiles to null", disabled === null);
ok("disabled: check returns null", checkRateLimit("s", "Bash", null) === null);

// ── Session isolation ─────────────────────────────────────────────────────────
resetSessions();
const sidA = "session-A";
const sidB = "session-B";
const isolatePolicy = compileRateLimitPolicy({ enabled: true, mode: "enforce",
  budgets: [{ tool: "Bash", limit: 1, windowSeconds: 3600 }] });
checkRateLimit(sidA, "Bash", isolatePolicy);
ok("isolation: session A exceeded", checkRateLimit(sidA, "Bash", isolatePolicy) !== null);
ok("isolation: session B not exceeded (separate counter)", checkRateLimit(sidB, "Bash", isolatePolicy) === null);

console.log(`\n${fail === 0 ? "ALL PASS" : fail + " FAILED"}`);
process.exit(fail === 0 ? 0 : 1);

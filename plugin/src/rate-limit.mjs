// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// rate-limit.mjs — Session-level tool-call budget enforcement for the AGT
// governance plugin.
//
// Prevents runaway agent sessions from consuming unbounded tool calls. Budgets
// are per-session (keyed by sessionId) and per-tool. When a budget is exceeded
// the backend returns "review" (ask for approval) in enforce mode, or adds an
// advisory note in advisory mode.
//
// THREAT MODEL:
//   - Infinite loop / runaway agent: a misbehaving or compromised agent issues
//     hundreds of Bash calls in a single session. Budget limits surface this as
//     a governance event rather than silent resource exhaustion.
//   - Cost control: WebFetch / WebSearch calls can be expensive. Budget caps
//     let operators enforce cost ceilings.
//
// POLICY INTEGRATION:
//   rateLimitPolicies.mode = "advisory" → warn only, no ask/deny
//   rateLimitPolicies.mode = "enforce"  → review (ask) on budget exceeded
//   rateLimitPolicies.budgets = [
//     { tool: "Bash",     limit: 100, windowSeconds: 3600 },
//     { tool: "WebFetch", limit: 20,  windowSeconds: 3600 },
//     { tool: "*",        limit: 200, windowSeconds: 3600 },  // total cap
//   ]
//
// SESSION STORAGE:
//   Persisted via session-store.mjs, keyed by sessionId. DISK-backed on Claude
//   Code (fresh process per event, AGT_SESSION_STORE=disk) so counters survive
//   across hook invocations; in-memory on OpenCode (resident). Counters are a
//   plain object { [tool|"*"]: {count, windowStart} }. Concurrency uses
//   last-writer-wins: the counter is a TRIPWIRE, not an accounting ledger —
//   losing one increment under a rare same-session race cannot turn a runaway
//   loop (hundreds of calls) into a non-event.

import { mutateSession, resetNamespace } from "./session-store.mjs";

const NS = "rate-limit";

const DEFAULT_BUDGETS = [
  { tool: "Bash",       limit: 150, windowSeconds: 3600 },
  { tool: "PowerShell", limit: 150, windowSeconds: 3600 },
  { tool: "WebFetch",   limit: 50,  windowSeconds: 3600 },
  { tool: "WebSearch",  limit: 50,  windowSeconds: 3600 },
  { tool: "*",          limit: 500, windowSeconds: 3600 },
];

export function compileRateLimitPolicy(raw) {
  if (!raw || raw.enabled === false) {
    return null;
  }
  const mode = raw.mode === "enforce" ? "enforce" : "advisory";
  const budgets = Array.isArray(raw.budgets) ? raw.budgets : DEFAULT_BUDGETS;
  return {
    mode,
    budgets: budgets.map((b) => ({
      tool: String(b.tool ?? "*"),
      limit: Number(b.limit ?? 100),
      windowSeconds: Number(b.windowSeconds ?? 3600),
    })),
  };
}

/**
 * Record a tool call and check if any budget is exceeded.
 * @returns {{ exceeded: boolean, tool: string, count: number, limit: number, reason: string } | null}
 */
export function checkRateLimit(sessionId, toolName, policy) {
  if (!policy || !sessionId || !toolName) {
    return null;
  }

  const now = Date.now();
  const toolKey = String(toolName).toLowerCase();
  const keysToCheck = [toolKey, "*"];

  // Read-modify-write the counters. A corrupt read yields {} → counters re-arm
  // from zero (acceptable: the tripwire simply re-starts; rate-limit is advisory
  // by default). A failed write (persisted=false) means this increment is not
  // saved — the next call re-reads the old count and undercounts by one; that is
  // an acceptable fail-open for a tripwire and must NOT deny the tool.
  const { result } = mutateSession(NS, sessionId, (data) => {
    const counters = data.counters && typeof data.counters === "object" ? data.counters : {};

    for (const key of keysToCheck) {
      const entry = counters[key] ?? { count: 0, windowStart: now };
      const windowMs =
        (policy.budgets.find((b) => b.tool.toLowerCase() === key)?.windowSeconds ?? 3600) * 1000;
      if (now - entry.windowStart > windowMs) {
        entry.count = 0;
        entry.windowStart = now;
      }
      entry.count++;
      counters[key] = entry;
    }

    // Evaluate budgets against the just-updated counters.
    let exceeded = null;
    for (const budget of policy.budgets) {
      const budgetKey = budget.tool.toLowerCase();
      if (budgetKey !== toolKey && budgetKey !== "*") {
        continue;
      }
      const entry = counters[budgetKey];
      if (entry && entry.count > budget.limit) {
        const targetTool = budget.tool === "*" ? "total" : budget.tool;
        exceeded = {
          exceeded: true,
          tool: targetTool,
          count: entry.count,
          limit: budget.limit,
          reason: `AGT rate-limit: ${targetTool} tool budget exceeded (${entry.count}/${budget.limit} calls in the current session window). Pause and verify this activity is intended before continuing.`,
        };
        break;
      }
    }

    return { data: { ...data, counters, updatedAt: now }, result: exceeded };
  });

  return result;
}

/** Reset all session counters — useful for testing. */
export function resetSessions() {
  resetNamespace(NS);
}

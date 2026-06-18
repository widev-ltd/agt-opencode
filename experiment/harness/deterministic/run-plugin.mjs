// Copyright (c) 2026 AGT benchmark contributors. MIT License.
//
// run-plugin.mjs (OpenCode) — the zero-key deterministic PLUGIN runner.
//
// It imports the REAL engine (agt-opencode/plugin/src/policy.mjs) — no
// reimplementation — and drives each corpus case through the same entry points
// the OpenCode adapter uses:
//   - evaluatePreToolUse(state, {toolName, toolArgs, cwd}, invocation)
//   - evaluatePromptSubmission(state, {prompt}, invocation)
//   - inspectToolResult(state, {toolName, toolResult}, invocation)
// The corpus case is rendered to those args by the host adapter's renderCase()
// (adapters/host.mjs), so the harness never hardcodes host tool names.
//
// SCOPE (per BENCHMARK-PLAN.md track-1): the deterministic track measures the
// PLUGIN column only. `native` requires a live model run (no offline
// settings.json entrypoint) and is resolved in Phase 5; `ungoverned` is allow
// by construction; `layered`'s native component is also live-only. This runner
// therefore returns a RAW engine decision for the plugin config; the scorer
// marks native/layered-native-part as not-measured.
//
// Determinism: one loadPolicy() state is reused across all cases (the engine
// builds a fresh detector per evaluateAction and the default policy carries no
// rate-limit/stateful policyDocument), and the audit side-effect is redirected
// to a throwaway path by the caller (score.mjs sets AGT_COPILOT_AUDIT_PATH).

import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { HOST, renderCase } from "../../adapters/host.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");        // agt-opencode/
const ENGINE_PATH = join(REPO_ROOT, "plugin", "src", "policy.mjs");
const DEFAULT_POLICY = join(REPO_ROOT, "config", "default-policy.json");

if (HOST !== "oc") {
  throw new Error(`run-plugin.mjs (OC) loaded the wrong adapter: HOST=${HOST}`);
}

// Load the real engine module once. pathToFileURL is required on Windows —
// dynamic import() rejects a bare drive-letter path (ERR_UNSUPPORTED_ESM_URL_SCHEME).
const engine = await import(pathToFileURL(ENGINE_PATH).href);

/**
 * Build an engine state for a benchmark config object (configs/*.json).
 * Only the `plugin` (and `layered`) configs are engine-evaluable here; the
 * caller decides which configs to run. policy_path in the config is relative to
 * the config file's directory (experiment/configs/).
 */
export async function loadEngineForConfig(config, { configDir }) {
  const policyPath = config?.policy_path
    ? (isAbsolute(config.policy_path) ? config.policy_path : resolve(configDir, config.policy_path))
    : DEFAULT_POLICY;
  // policy.mjs reads AGT_COPILOT_POLICY_PATH for the user policy; we pass the
  // resolved policy as the configured path so the engine loads exactly it.
  process.env.AGT_COPILOT_POLICY_PATH = policyPath;
  const state = await engine.loadPolicy({ defaultPolicyPath: DEFAULT_POLICY, policyPath });
  return { state, policyPath, mode: state.policy.mode, source: state.source };
}

/**
 * Evaluate ONE rendered case against a loaded engine state. Returns the RAW
 * engine decision plus timing; decision-normalize.mjs turns it into a cell.
 *
 * @returns {{call:string, raw:any, latencyMs:number}}
 */
export async function evaluateRendered(state, rendered, invocation = { sessionId: "bench" }) {
  const t0 = performance.now();
  let raw;
  switch (rendered.call) {
    case "preToolUse":
      raw = await engine.evaluatePreToolUse(
        state,
        { toolName: rendered.toolName, toolArgs: rendered.toolArgs, cwd: rendered.toolArgs?.cwd },
        invocation,
      );
      break;
    case "promptSubmit":
      raw = await engine.evaluatePromptSubmission(state, { prompt: rendered.prompt }, invocation);
      break;
    case "toolOutput":
      raw = await engine.inspectToolResult(
        state,
        { toolName: rendered.toolName, toolResult: rendered.toolResult },
        invocation,
      );
      break;
    default:
      throw new Error(`run-plugin.mjs: unknown rendered.call '${rendered.call}'`);
  }
  const latencyMs = performance.now() - t0;
  return { call: rendered.call, raw, latencyMs };
}

/**
 * Convenience: render a corpus case and evaluate it in one step.
 */
export async function evaluateCase(state, kase, opts = {}) {
  const rendered = renderCase(kase.abstract_action, opts);
  const out = await evaluateRendered(state, rendered, opts.invocation);
  return { ...out, rendered };
}

export { renderCase, HOST };

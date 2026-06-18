// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// regex-check.mjs — mechanizes the PLUGIN policy-match fact for shell/file/url
// cases by compiling the regex SOURCES straight out of both default-policy.json
// files and .test()-ing each case's payload/target. This is "apply a known regex
// to a string to predict an outcome" = blessed static reasoning, NOT an engine
// run (it never calls evaluatePreToolUse). It checks ONLY the pure regex layers:
//   - blockedToolCalls[].commandPatterns      (against shell command text)
//   - directResourcePolicies.pathRules        (against a normalized path)
//   - directResourcePolicies.urlRules         (against a normalized url)
// It deliberately does NOT model engine PROCEDURE: isSafeCleanupCommand bypass,
// normalizePathValue, allowPathPatterns exemptions beyond a direct test, or any
// native (CC/OC) matcher — those stay Phase-0/Phase-4 probes.
//
// Usage:
//   node regex-check.mjs                      # audit authored-shell.jsonl facts
//   node regex-check.mjs --exemplars          # audit the 10 blessed exemplars
// Exits non-zero if any case's recorded pluginPolicyMatch disagrees with the
// compiled regexes, OR any rationale still contains an unresolved hedge.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const POLICY = {
  oc: join(REPO, "agt-opencode", "config", "default-policy.json"),
  cc: join(REPO, "agt-claude-code", "plugins", "agt-governance", "config", "default-policy.json"),
};

function compilePolicy(path) {
  const p = JSON.parse(readFileSync(path, "utf8"));
  const cmd = [];
  for (const rule of p.blockedToolCalls ?? []) {
    for (const cp of rule.commandPatterns ?? []) {
      cmd.push({ id: rule.id, effect: rule.effect, re: new RegExp(cp.source, cp.flags || "") });
    }
  }
  const pathRules = (p.directResourcePolicies?.pathRules ?? []).map((r) => ({
    id: r.id, effect: r.effect, op: r.operation,
    deny: (r.pathPatterns ?? []).map((x) => new RegExp(x.source, x.flags || "")),
    allow: (r.allowPathPatterns ?? []).map((x) => new RegExp(x.source, x.flags || "")),
  }));
  const urlRules = (p.directResourcePolicies?.urlRules ?? []).map((r) => ({
    id: r.id, effect: r.effect,
    deny: (r.urlPatterns ?? []).map((x) => new RegExp(x.source, x.flags || "")),
  }));
  return { cmd, pathRules, urlRules };
}

const POL = { oc: compilePolicy(POLICY.oc), cc: compilePolicy(POLICY.cc) };

// Does any command-pattern match (returns the matched rule's effect or null)?
function commandMatch(pol, text) {
  for (const r of pol.cmd) if (r.re.test(text)) return r.effect; // first match's effect
  return null;
}
// Path rule: matches a deny/review pattern and NOT an allow pattern.
function pathMatch(pol, normalizedPath) {
  for (const r of pol.pathRules) {
    if (r.deny.some((re) => re.test(normalizedPath)) && !r.allow.some((re) => re.test(normalizedPath))) return r.effect;
  }
  return null;
}
function urlMatch(pol, url) {
  for (const r of pol.urlRules) if (r.deny.some((re) => re.test(url))) return r.effect;
  return null;
}

// Predict whether the PLUGIN policy-matches the threat for a case, per host.
// Returns {effect|null}. For shell_command/mcp: command-pattern. For file_*:
// the path rule against the RAW target (we do not model normalizePathValue's
// cwd-resolve/expansion — flagged: a path that only matches after normalization
// is a probe, not asserted here). For url_fetch: url rule against target.
function predict(host, c) {
  const pol = POL[host];
  const aa = c.abstract_action;
  if (aa.kind === "shell_command" || aa.kind === "mcp_tool_definition") {
    return commandMatch(pol, aa.payload);
  }
  if (aa.kind === "file_read" || aa.kind === "file_write") {
    // Test both the raw target and a leading-slash normalized variant so the
    // (^|/) anchors behave like a path segment. We do NOT resolve ~/$HOME/cwd.
    const t = String(aa.target ?? "");
    const variants = [t, t.replace(/\\/g, "/"), "/" + t.replace(/^[.][/]/, "").replace(/^\/+/, "")];
    for (const v of variants) { const e = pathMatch(pol, v.toLowerCase()); if (e) return e; }
    return null;
  }
  if (aa.kind === "url_fetch") {
    return urlMatch(pol, String(aa.target ?? "").toLowerCase());
  }
  return null; // prompt/tool_output handled elsewhere (detector union), not here
}

function audit(file) {
  const lines = readFileSync(join(HERE, file), "utf8").split(/\r?\n/).filter(Boolean);
  const arr = lines.map((l) => JSON.parse(l));
  let mism = 0, hedges = 0;
  for (const c of arr) {
    const aa = c.abstract_action;
    if (!["shell_command", "file_read", "file_write", "url_fetch", "mcp_tool_definition"].includes(aa.kind)) continue;
    const recorded = c.expected_per_config; // we infer recorded pm from cells is unreliable; instead re-derive from facts is not stored. So compare PREDICTED match to the cell semantics:
    // policy-match present iff a host plugin/native shows deny:policy-match attributable to a regex. We instead check: predicted effect vs whether the case is registered as a plugin policy-match.
    for (const host of ["cc", "oc"]) {
      const predicted = predict(host, c); // null | 'deny' | 'review' | 'allow'
      // Recorded plugin policy-match := plugin cell is deny with deny_kind policy-match, OR (CC) ask via a review-effect rule, OR url/path deny.
      const pcell = c.expected_per_config[host].plugin;
      // Recorded DENY-policy-match coverage := plugin cell is a deny attributed
      // to a real rule (deny_kind policy-match), i.e. a deny-effect regex caught
      // the threat. Review-effect matches (ask on CC / fail-closed on OC) are NOT
      // counted as coverage, matching predictedMatch (deny-effect only).
      const recordedPolicyMatch = (pcell.deny_kind === "policy-match") ||
        (host === "cc" && pcell.outcome === "deny");
      // Only a DENY-effect regex match counts as policy-match COVERAGE. A
      // review-effect rule match (e.g. persistence-write) produces review ->
      // CC ask / OC fail-closed, which the no-double-count rule treats as NOT
      // coverage. So review-effect matches are predictedMatch=false here.
      const predictedMatch = predicted === "deny";
      // For bash review-tier, a MISS still yields ask(cc)/fail-closed(oc) — that's NOT a policy-match. So recordedPolicyMatch should equal predictedMatch.
      if (predictedMatch !== recordedPolicyMatch) {
        // Allow the documented exception: path cases needing normalization (we don't resolve ~) -> flag as INFO not error if note says probe/normalize.
        const note = (pcell.note ?? "") + (c.rationale ?? "");
        const normalizationCaveat = /normaliz|probe|~|\$home|cwd/i.test(note) && (aa.kind === "file_read" || aa.kind === "file_write");
        console.log(`${normalizationCaveat ? "INFO" : "MISMATCH"} [${c.id}] ${host}: predicted policy-match=${predictedMatch} (${predicted}) but recorded=${recordedPolicyMatch}`);
        if (!normalizationCaveat) mism++;
      }
    }
    if (/\bVERIFY\b|likely|probably|i think/i.test(c.rationale ?? "")) { console.log(`HEDGE [${c.id}]: rationale contains an unresolved hedge`); hedges++; }
  }
  console.log(`\n${file}: ${arr.length} cases, ${mism} regex mismatches, ${hedges} hedges`);
  return mism + hedges;
}

const target = process.argv.includes("--exemplars") ? "EXEMPLARS-for-signoff.jsonl" : "cases/authored-shell.jsonl";
const problems = audit(target);

// Cross-check: are the two policies' regex sources identical? (the {cc:true,oc:true} assumption)
function sig(pol) { return JSON.stringify([pol.cmd.map((r) => r.re.source), pol.pathRules.map((r) => r.deny.map((x) => x.source)), pol.urlRules.map((r) => r.deny.map((x) => x.source))]); }
if (sig(POL.cc) !== sig(POL.oc)) {
  console.log("\nNOTE: CC and OC default-policy regex SOURCES DIFFER — pluginPolicyMatch.cc and .oc must be derived independently (do not assume identical).");
} else {
  console.log("\nNOTE: CC and OC default-policy regex sources are IDENTICAL — {cc,oc} match facts coincide.");
}

process.exit(problems > 0 ? 1 : 0);

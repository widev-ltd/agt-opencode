// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// host.mjs — OpenCode host adapter for the adversarial benchmark.
//
// Renders a host-NEUTRAL corpus case (abstract_action: {kind, payload, target})
// into the concrete shape the OpenCode deterministic runner feeds to the real
// engine entry points in plugin/src/policy.mjs:
//   - evaluatePreToolUse(state, {toolName, toolArgs, cwd}, invocation)
//   - evaluatePromptSubmission(state, {prompt}, invocation)
//   - inspectToolResult(state, {toolName, toolResult}, invocation)
//   - the MCP scanner path (a tool whose description carries the payload)
//
// The corpus carries NO host tool names; this adapter owns the mapping from the
// abstract `kind` to OpenCode's lowercase tool ids and arg keys. The CC adapter
// (agt-claude-code/experiment/adapters/host.mjs) maps the SAME corpus to Claude
// Code's PascalCase tools + stdin hook-event JSON. Corpus is byte-identical and
// hash-verified across both repos; only the adapters differ.

export const HOST = "oc";

// OpenCode tool ids are lowercase (see config/default-policy.json toolPolicies).
const KIND_TO_TOOL = {
  shell_command: "bash",
  file_read: "read",
  file_write: "write",
  url_fetch: "webfetch",
  mcp_tool_definition: "mcp",
};

// Default arg key per kind. Overridable via abstract_action.render_hints.arg_key.
const KIND_TO_ARG_KEY = {
  shell_command: "command",
  file_read: "filePath",
  file_write: "filePath",
  url_fetch: "url",
};

// Map a host-NEUTRAL render_hints.source_tool (canonical lowercase: bash,
// webfetch, websearch, …) to OpenCode's tool id. The engine classifies tool
// output by tool id (suppressTools=[webfetch,websearch] -> suppress->deny;
// advisoryTools=[bash] -> advisory->allow), so the SOURCE casing/name is
// load-bearing for tool-output scoring. OC ids are already lowercase; we
// canonicalize so a PascalCase hint (WebFetch) still resolves correctly.
const SOURCE_TOOL_TO_TOOL = {
  bash: "bash",
  shell: "bash",
  webfetch: "webfetch",
  websearch: "websearch",
  fetch: "webfetch",
  read: "read",
  write: "write",
};
function resolveSourceTool(sourceTool) {
  if (!sourceTool) return "bash"; // default: bash-sourced (advisory)
  const key = String(sourceTool).toLowerCase();
  return SOURCE_TOOL_TO_TOOL[key] ?? key; // fall through to the (lowercased) id
}

/**
 * Render an abstract corpus action into an OpenCode engine invocation.
 *
 * @param {{kind:string, payload:string, target?:string, render_hints?:object}} abstractAction
 * @param {{cwd?:string}} [opts]
 * @returns {{call:"preToolUse"|"promptSubmit"|"toolOutput", toolName?:string, toolArgs?:object, prompt?:string, toolResult?:string}}
 *   A normalized invocation the OC deterministic runner dispatches to the matching
 *   policy.mjs entry point. `call` selects the entry point; the rest are its args.
 */
export function renderCase(abstractAction, opts = {}) {
  const { kind, payload, target } = abstractAction;
  const hints = abstractAction.render_hints ?? {};
  const cwd = opts.cwd ?? "/work/project";

  switch (kind) {
    case "prompt":
      return { call: "promptSubmit", prompt: String(payload ?? "") };

    case "tool_output":
      // PostToolUse / tool.execute.after scanning. The tool that produced the
      // output defaults to bash unless render_hints.source_tool names another
      // scanned tool. source_tool is host-neutral; resolveSourceTool maps it to
      // OC's tool id so suppressTools/advisoryTools membership is correct
      // (web-sourced -> suppress -> deny; bash-sourced -> advisory -> allow).
      return {
        call: "toolOutput",
        toolName: resolveSourceTool(hints.source_tool),
        toolResult: String(payload ?? ""),
      };

    case "mcp_tool_definition": {
      // The MCP scan runs inside evaluatePreToolUse: the tool's name + the
      // serialized args/description are what McpSecurityScanner inspects. We
      // place the poisoned description in a string arg so it reaches the scanner.
      const toolName = String(hints.mcp_tool_name ?? "external_tool");
      return {
        call: "preToolUse",
        toolName,
        toolArgs: { description: String(payload ?? ""), ...(target ? { target } : {}) },
      };
    }

    case "shell_command":
      return {
        call: "preToolUse",
        toolName: KIND_TO_TOOL.shell_command,
        toolArgs: { [hints.arg_key ?? KIND_TO_ARG_KEY.shell_command]: String(payload ?? ""), cwd },
      };

    case "file_read":
    case "file_write":
    case "url_fetch": {
      const toolName = KIND_TO_TOOL[kind];
      const argKey = hints.arg_key ?? KIND_TO_ARG_KEY[kind];
      const value = kind === "url_fetch" ? (target ?? payload) : (target ?? payload);
      const toolArgs = { [argKey]: String(value ?? ""), cwd };
      // file_write carries the content to write in `content`/`payload`.
      if (kind === "file_write" && payload) {
        toolArgs.content = String(payload);
      }
      return { call: "preToolUse", toolName, toolArgs };
    }

    default:
      throw new Error(`OC adapter: unsupported abstract_action.kind '${kind}'`);
  }
}

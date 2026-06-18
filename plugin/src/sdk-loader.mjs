// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// sdk-loader.mjs — OpenCode build of the Agent Governance SDK loader.
//
// The Claude Code / Copilot CLI builds of this file probe the filesystem for a
// vendored copy of @microsoft/agent-governance-sdk and `import()` it at runtime.
// The OpenCode plugin is shipped as a single esbuild bundle instead: the SDK is
// statically imported here and inlined into `agt-governance.js` at build time.
// This keeps the export surface that the verbatim `policy.mjs` depends on
// (`SDK_ENTRY_ENV`, `loadAgentGovernanceSdk`) while removing the runtime probe.

import * as agentGovernanceSdk from "@microsoft/agent-governance-sdk";

// Kept only so `policy.mjs` (copied verbatim) can re-export it. It has no
// effect in the bundled OpenCode plugin — the SDK is always the inlined copy.
export const SDK_ENTRY_ENV = "AGT_OPENCODE_SDK_ENTRY";

export async function loadAgentGovernanceSdk() {
  const sdk = agentGovernanceSdk.default ?? agentGovernanceSdk;
  return {
    path: "bundled",
    sdk,
    source: "bundled",
  };
}

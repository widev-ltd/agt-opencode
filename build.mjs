// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// build.mjs — bundles the OpenCode plugin into a single self-contained file.
//
// OpenCode loads every file in its plugin directory as an individual plugin, so
// a multi-file plugin cannot be shipped as-is. esbuild bundles the adapter, the
// vendored AGT engine, and the Agent Governance SDK (plus its pure-JS deps)
// into one ESM module: assets/agt-governance.js. That single file is what the
// installer drops into ~/.config/opencode/plugins/.

import { build } from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));

await build({
  entryPoints: [join(root, "plugin", "src", "agt-plugin.ts")],
  outfile: join(root, "assets", "agt-governance.js"),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  legalComments: "inline",
  logLevel: "info",
  banner: {
    js: [
      "// AGT Governance plugin for OpenCode — GENERATED BUNDLE, do not edit.",
      "// Built from agt-opencode/plugin/src by build.mjs.",
      "// Bundles the Microsoft Agent Governance Toolkit SDK (MIT License).",
      // The AGT SDK is CommonJS and require()s Node builtins (crypto, etc.).
      // esbuild's ESM output needs a real `require` for those to resolve.
      'import { createRequire as __agtCreateRequire } from "node:module";',
      "const require = __agtCreateRequire(import.meta.url);",
    ].join("\n"),
  },
});

console.log("Built assets/agt-governance.js");

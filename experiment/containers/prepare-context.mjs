// Copyright (c) 2026 AGT benchmark contributors. MIT License.
//
// prepare-context.mjs — stage the build-context inputs the Dockerfiles COPY,
// pulling them from their canonical repo locations so we do NOT duplicate large
// binaries in git. Staged artifacts are .gitignored. Run before docker build:
//
//   node prepare-context.mjs
//
// Stages into experiment/containers/ (and experiment/ where compose context is):
//   - corporate-ca.pem           <- agt-opencode/verify/corporate-ca.pem
//   - agt-opencode-0.1.0.tgz     <- agt-opencode/agt-opencode-0.1.0.tgz (built by npm pack)
// The compose build context is experiment/ (one level up), so the agent
// Dockerfile references containers/Dockerfile and COPYs paths relative to
// experiment/. We therefore also stage the tgz at experiment/ root.

import { copyFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));        // experiment/containers
const EXPERIMENT = resolve(HERE, "..");                       // experiment/
const REPO = resolve(EXPERIMENT, "..");                       // agt-opencode/

function stage(src, dest, label) {
  if (!existsSync(src)) {
    console.error(`[prepare-context] MISSING ${label}: ${src}`);
    console.error("  (build the plugin tgz with `npm pack` / `npm run build` first.)");
    process.exit(1);
  }
  copyFileSync(src, dest);
  console.log(`[prepare-context] staged ${label} -> ${dest}`);
}

// CA into the containers/ dir (agent + gateway + metadata Dockerfiles COPY it).
stage(join(REPO, "verify", "corporate-ca.pem"), join(HERE, "corporate-ca.pem"), "corporate-ca.pem");

// Plugin tgz. The agent Dockerfile COPYs `agt-opencode-0.1.0.tgz` relative to
// the experiment/ build context.
stage(
  join(REPO, "agt-opencode-0.1.0.tgz"),
  join(EXPERIMENT, "agt-opencode-0.1.0.tgz"),
  "agt-opencode-0.1.0.tgz",
);

console.log("[prepare-context] done. Now: node gen-decoys.mjs >/dev/null && docker compose --profile <none|ssrf|live> build");

#!/usr/bin/env node
// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// agt-opencode — installer CLI entry point. Thin wrapper over lib/cli.mjs.

import { runCli } from "../lib/cli.mjs";

const exitCode = await runCli(process.argv.slice(2));
if (typeof exitCode === "number" && exitCode !== 0) {
  process.exit(exitCode);
}

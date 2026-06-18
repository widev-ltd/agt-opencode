// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// Installer tests — exercise install / uninstall / doctor against a temporary
// OpenCode home so the real ~/.config/opencode is never touched.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { diagnoseInstall, installPackage, uninstallPackage } from "../lib/cli.mjs";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

async function withTempHome(run) {
  const home = await mkdtemp(join(tmpdir(), "agt-opencode-test-"));
  try {
    await run(home);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

test("install places the plugin bundle, seeds a policy, and writes a manifest", async () => {
  await withTempHome(async (home) => {
    const result = await installPackage({ opencodeHome: home, packageRoot });

    assert.ok(existsSync(result.pluginPath), "plugin bundle should be installed");
    assert.ok(result.pluginPath.includes(join("plugins", "agt-governance.js")), "uses plural plugins/ dir");
    assert.ok(existsSync(result.policyPath), "default policy should be seeded");
    assert.ok(existsSync(result.manifestPath), "install manifest should be written");
    assert.equal(result.policySeeded, true);
  });
});

test("install does not overwrite an existing policy unless --force-policy", async () => {
  await withTempHome(async (home) => {
    const first = await installPackage({ opencodeHome: home, packageRoot });
    assert.equal(first.policySeeded, true);

    const second = await installPackage({ opencodeHome: home, packageRoot });
    assert.equal(second.policySeeded, false, "second install must keep the existing policy");

    const forced = await installPackage({ opencodeHome: home, packageRoot, forcePolicy: true });
    assert.equal(forced.policySeeded, true, "--force-policy must reseed the policy");
  });
});

test("doctor reports OK on a fresh managed install", async () => {
  await withTempHome(async (home) => {
    await installPackage({ opencodeHome: home, packageRoot });
    const report = await diagnoseInstall({ opencodeHome: home, packageRoot });

    assert.equal(report.ok, true, `doctor should pass: ${JSON.stringify(report.errors)}`);
    assert.equal(report.pluginInstalled, true);
    assert.equal(report.managedInstall, true);
    assert.equal(report.policyValid, true);
  });
});

test("uninstall removes the managed plugin but preserves the policy by default", async () => {
  await withTempHome(async (home) => {
    const installed = await installPackage({ opencodeHome: home, packageRoot });
    const result = await uninstallPackage({ opencodeHome: home, packageRoot });

    assert.equal(result.managed, true);
    assert.equal(result.pluginRemoved, true);
    assert.equal(existsSync(installed.pluginPath), false, "plugin file should be gone");
    assert.equal(existsSync(installed.policyPath), true, "policy should be preserved");
  });
});

test("uninstall --remove-policy also deletes the policy", async () => {
  await withTempHome(async (home) => {
    const installed = await installPackage({ opencodeHome: home, packageRoot });
    const result = await uninstallPackage({ opencodeHome: home, packageRoot, removePolicy: true });

    assert.equal(result.policyRemoved, true);
    assert.equal(existsSync(installed.policyPath), false, "policy should be removed");
  });
});

test("doctor reports a problem when nothing is installed", async () => {
  await withTempHome(async (home) => {
    const report = await diagnoseInstall({ opencodeHome: home, packageRoot });
    assert.equal(report.ok, false);
    assert.equal(report.pluginInstalled, false);
  });
});

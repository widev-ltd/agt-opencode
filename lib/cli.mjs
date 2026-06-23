// Copyright (c) 2026 AGT Governance plugin contributors.
// Licensed under the MIT License.
//
// cli.mjs — the agt-opencode installer. Places the bundled governance plugin
// into OpenCode's global plugin directory, seeds a default policy, and provides
// install / update / uninstall / doctor / policy lifecycle commands.
//
// Modeled on the Agent Governance Toolkit's Copilot CLI installer. It does not
// edit opencode.json: OpenCode auto-loads every file in its plugins directory.

import { existsSync, readdirSync, statSync } from "node:fs";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve as resolvePath } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

const PACKAGE_NAME = "agt-opencode";
const PLUGIN_FILE_NAME = "agt-governance.js";
const INSTALL_MANIFEST_NAME = ".agt-install-manifest.json";
const SUPPORTED_POLICY_SCHEMA_VERSION = 1;
const PROFILES = ["strict", "balanced", "secure-low-friction", "advisory"];

// ── Path resolution ─────────────────────────────────────────────────────────

export function resolveOpencodeHome(override) {
  if (override) {
    return override;
  }
  if (process.env.OPENCODE_CONFIG_HOME) {
    return process.env.OPENCODE_CONFIG_HOME;
  }
  const xdg = process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
  return join(xdg, "opencode");
}

function getPackageRoot() {
  return dirname(dirname(fileURLToPath(import.meta.url)));
}

function getPaths({ opencodeHome, packageRoot }) {
  return {
    opencodeHome,
    pluginsDir: join(opencodeHome, "plugins"),
    pluginPath: join(opencodeHome, "plugins", PLUGIN_FILE_NAME),
    dataDir: join(opencodeHome, "agt"),
    policyPath: join(opencodeHome, "agt", "policy.json"),
    manifestPath: join(opencodeHome, "agt", INSTALL_MANIFEST_NAME),
    sourceBundlePath: join(packageRoot, "assets", PLUGIN_FILE_NAME),
    sourceDefaultPolicyPath: join(packageRoot, "config", "default-policy.json"),
    sourceProfilesDir: join(packageRoot, "config", "profiles"),
  };
}

async function readPackageMetadata(packageRoot = getPackageRoot()) {
  try {
    return JSON.parse(await readFile(join(packageRoot, "package.json"), "utf-8"));
  } catch {
    return { name: PACKAGE_NAME, version: "0.0.0" };
  }
}

async function readJsonFile(path) {
  return JSON.parse(await readFile(path, "utf-8"));
}

// ── Policy validation ───────────────────────────────────────────────────────

function validatePolicyObject(policy, sourcePath) {
  if (!policy || typeof policy !== "object") {
    throw new Error(`Policy at ${sourcePath} is not a JSON object.`);
  }
  const schemaVersion = policy.schemaVersion ?? 1;
  if (!Number.isInteger(schemaVersion) || schemaVersion < 1) {
    throw new Error(`Policy at ${sourcePath} has an invalid schemaVersion: ${schemaVersion}.`);
  }
  if (schemaVersion > SUPPORTED_POLICY_SCHEMA_VERSION) {
    throw new Error(
      `Policy at ${sourcePath} uses schemaVersion ${schemaVersion}; this installer supports ${SUPPORTED_POLICY_SCHEMA_VERSION}.`,
    );
  }
  if (policy.mode && policy.mode !== "enforce" && policy.mode !== "advisory") {
    throw new Error(`Policy at ${sourcePath} has an invalid mode: ${policy.mode}.`);
  }
  return schemaVersion;
}

function resolvePolicySource({ file, profile, paths }) {
  if (file && profile) {
    throw new Error("Specify either --file or --profile, not both.");
  }
  if (profile) {
    if (!PROFILES.includes(profile)) {
      throw new Error(`Unknown profile '${profile}'. Available: ${PROFILES.join(", ")}.`);
    }
    return join(paths.sourceProfilesDir, `${profile}.json`);
  }
  if (file) {
    return file;
  }
  return paths.sourceDefaultPolicyPath;
}

// ── Commands ────────────────────────────────────────────────────────────────

export async function installPackage({ opencodeHome, packageRoot, forcePolicy = false }) {
  const paths = getPaths({ opencodeHome, packageRoot });
  const metadata = await readPackageMetadata(packageRoot);

  if (!existsSync(paths.sourceBundlePath)) {
    throw new Error(
      `Plugin bundle not found at ${paths.sourceBundlePath}. Run 'npm run build' before installing.`,
    );
  }

  await mkdir(paths.pluginsDir, { recursive: true });
  await mkdir(paths.dataDir, { recursive: true });
  await copyFile(paths.sourceBundlePath, paths.pluginPath);

  const policyExists = existsSync(paths.policyPath);
  const shouldSeedPolicy = !policyExists || forcePolicy;
  if (shouldSeedPolicy) {
    const defaultPolicy = await readJsonFile(paths.sourceDefaultPolicyPath);
    validatePolicyObject(defaultPolicy, paths.sourceDefaultPolicyPath);
    await writeFile(paths.policyPath, JSON.stringify(defaultPolicy, null, 2), "utf-8");
  }

  await writeFile(
    paths.manifestPath,
    JSON.stringify(
      {
        pluginName: PLUGIN_FILE_NAME,
        installedAt: new Date().toISOString(),
        installedBy: metadata.name ?? PACKAGE_NAME,
        installedByVersion: metadata.version ?? "0.0.0",
        policyPath: paths.policyPath,
        policySeededByInstaller: shouldSeedPolicy,
        schemaVersion: 1,
      },
      null,
      2,
    ),
    "utf-8",
  );

  return { ...paths, policySeeded: shouldSeedPolicy };
}

export async function uninstallPackage({ opencodeHome, packageRoot, removePolicy = false }) {
  const paths = getPaths({ opencodeHome, packageRoot });
  const managed = existsSync(paths.manifestPath);

  if (!managed) {
    return { ...paths, pluginRemoved: false, policyRemoved: false, managed: false };
  }

  let pluginRemoved = false;
  if (existsSync(paths.pluginPath)) {
    await rm(paths.pluginPath);
    pluginRemoved = true;
  }
  await rm(paths.manifestPath, { force: true });

  let policyRemoved = false;
  if (removePolicy && existsSync(paths.policyPath)) {
    await rm(paths.policyPath);
    policyRemoved = true;
  }

  return { ...paths, pluginRemoved, policyRemoved, managed: true };
}

function findOpencodeOnPath() {
  const pathDirs = (process.env.PATH || "").split(process.platform === "win32" ? ";" : ":");
  const names =
    process.platform === "win32"
      ? ["opencode.exe", "opencode.cmd", "opencode.bat", "opencode"]
      : ["opencode"];
  for (const dir of pathDirs) {
    for (const name of names) {
      if (dir && existsSync(join(dir, name))) {
        return join(dir, name);
      }
    }
  }
  return null;
}

// ── Supply-chain toolchain probe ──────────────────────────────────────────────
// The Tier-2 transitive CVE scan is delegated to external tools that the operator
// installs separately: resolvers (uv/npm) produce the full transitive set, scanners
// (trivy/osv-scanner/pip-audit) check it for known CVEs. `doctor` reports which of
// these are on PATH so an operator can see, BEFORE a skill is gated, which scan
// capabilities exist on this box.
//
// The detection MUST match the engine's own probe so doctor's verdict agrees with
// what the audit path will actually do. The engine (plugin/src/deps.mjs) probes a
// tool by spawning `<tool> --version` with a 10 s bound and treating it as present
// when: the spawn did not error, did not time out, and EITHER exited 0 OR printed a
// version-shaped token (`\d+\.\d+`) on stdout/stderr (see probeScanner/probeResolver
// there). spawnCapture there routes through `cmd.exe /d /s /c` on Windows so .cmd
// shims like npm resolve; we mirror that exactly. We do NOT reimplement the scan —
// only the same liveness probe — because spawnCapture/probeScanner are module-private
// in the engine (not exported) and that module is owned by another agent.
const SUPPLY_CHAIN_TOOLS = [
  { name: "uv", role: "resolver", ecosystem: "python", what: "resolves the full transitive Python dep set (pyproject/requirements/PEP 723)" },
  { name: "npm", role: "resolver", ecosystem: "node", what: "resolves the full transitive Node dep set (package.json → lockfile)" },
  { name: "trivy", role: "scanner", ecosystem: "both", what: "CVE-scans the resolved set (Python + Node)" },
  { name: "osv-scanner", role: "scanner", ecosystem: "both", what: "CVE-scans the resolved set (Python + Node)" },
  { name: "pip-audit", role: "scanner", ecosystem: "python", what: "CVE-scans resolved Python requirements" },
];

// Spawn `<tool> --version`, bounded, NEVER throws. Returns true when the tool is a
// live, runnable command. Mirrors the engine's spawnCapture + probeScanner success
// test (see comment above). 10 s timeout per probe, windowsHide, no shell.
async function probeTool(name, timeoutMs = 10000) {
  const { spawn } = await import("node:child_process");
  let runCmd = name;
  let runArgs = ["--version"];
  if (process.platform === "win32") {
    const comspec = process.env.ComSpec || process.env.COMSPEC || "cmd.exe";
    runCmd = comspec;
    runArgs = ["/d", "/s", "/c", name, "--version"];
  }
  return await new Promise((resolve) => {
    let child;
    try {
      child = spawn(runCmd, runArgs, { shell: false, windowsHide: true });
    } catch {
      resolve(false);
      return;
    }
    let stdout = "";
    let stderr = "";
    let done = false;
    const MAX_OUT = 64 * 1024;
    const finish = (present) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { child.kill(); } catch { /* already gone */ }
      resolve(present);
    };
    const timer = setTimeout(() => finish(false), timeoutMs); // timed out → not present
    child.stdout?.on("data", (d) => { if (stdout.length < MAX_OUT) stdout += d.toString("utf8"); });
    child.stderr?.on("data", (d) => { if (stderr.length < MAX_OUT) stderr += d.toString("utf8"); });
    child.on("error", () => finish(false)); // spawnError (ENOENT) → not present
    child.on("close", (code) => finish(code === 0 || /\d+\.\d+/.test(stdout) || /\d+\.\d+/.test(stderr)));
  });
}

// Probe every supply-chain tool and derive the scan capabilities the present set
// enables. NEVER throws. Returns a structured report consumed by doctor.
async function probeSupplyChainToolchain() {
  const tools = {};
  await Promise.all(
    SUPPLY_CHAIN_TOOLS.map(async (t) => {
      tools[t.name] = { present: await probeTool(t.name), role: t.role, ecosystem: t.ecosystem };
    }),
  );

  const haveScanner = tools.trivy.present || tools["osv-scanner"].present || tools["pip-audit"].present;
  // Python transitive scan needs uv (resolver) AND a scanner that covers Python.
  const pythonScanner = tools.trivy.present || tools["osv-scanner"].present || tools["pip-audit"].present;
  const pythonTransitive = tools.uv.present && pythonScanner;
  // Node transitive scan needs npm (resolver) AND trivy or osv (pip-audit is Python-only).
  const nodeScanner = tools.trivy.present || tools["osv-scanner"].present;
  const nodeTransitive = tools.npm.present && nodeScanner;

  const capabilities = [];
  capabilities.push({
    label: "Python transitive CVE scan",
    available: pythonTransitive,
    detail: pythonTransitive
      ? `available via uv + ${tools.trivy.present ? "trivy" : tools["osv-scanner"].present ? "osv-scanner" : "pip-audit"}`
      : tools.uv.present
        ? "unavailable — uv present but no CVE scanner (install trivy / osv-scanner / pip-audit)"
        : pythonScanner
          ? "unavailable — a scanner is present but uv (the transitive resolver) is not on PATH"
          : "unavailable — neither uv nor a CVE scanner is on PATH",
  });
  capabilities.push({
    label: "Node transitive CVE scan",
    available: nodeTransitive,
    detail: nodeTransitive
      ? `available via npm + ${tools.trivy.present ? "trivy" : "osv-scanner"}`
      : tools.npm.present
        ? "unavailable — npm present but no trivy/osv-scanner (pip-audit does not cover Node)"
        : nodeScanner
          ? "unavailable — a scanner is present but npm (the transitive resolver) is not on PATH"
          : "unavailable — neither npm nor a Node-capable scanner is on PATH",
  });

  return {
    tools,
    capabilities,
    // The consequence an operator actually cares about: with NO transitive scan
    // capability, an unsigned skill cannot be cleared by a local scan, so in enforce
    // mode it is reviewed/blocked. (A CI-signed skill is unaffected — its attestation
    // was produced where the toolchain existed.)
    anyTransitive: pythonTransitive || nodeTransitive,
    anyScanner: haveScanner,
  };
}

export async function diagnoseInstall({ opencodeHome, packageRoot = getPackageRoot() }) {
  const paths = getPaths({ opencodeHome, packageRoot });
  const metadata = await readPackageMetadata(packageRoot);

  const report = {
    ok: true,
    opencodeHome,
    pluginPath: paths.pluginPath,
    pluginInstalled: existsSync(paths.pluginPath),
    managedInstall: existsSync(paths.manifestPath),
    installedByVersion: null,
    currentPackageVersion: metadata.version ?? null,
    policyPath: paths.policyPath,
    policyValid: false,
    policySchemaVersion: null,
    policySource: existsSync(paths.policyPath) ? "user" : "bundled-default",
    sourceBundlePresent: existsSync(paths.sourceBundlePath),
    opencodeOnPath: findOpencodeOnPath(),
    supplyChainToolchain: null,
    warnings: [],
    errors: [],
  };

  // Supply-chain toolchain probe (informational — does NOT affect report.ok / exit
  // code). Reports which resolvers/scanners are on PATH and the scan capabilities
  // they enable. Never throws; on an unexpected failure it leaves the field null.
  try {
    report.supplyChainToolchain = await probeSupplyChainToolchain();
  } catch (error) {
    report.warnings.push(`Supply-chain toolchain probe failed: ${error.message}`);
  }

  if (report.managedInstall) {
    try {
      const manifest = await readJsonFile(paths.manifestPath);
      report.installedByVersion = manifest.installedByVersion ?? null;
    } catch (error) {
      report.warnings.push(`Install manifest could not be read: ${error.message}`);
    }
  }

  if (!report.pluginInstalled) {
    report.ok = false;
    report.errors.push("Governance plugin is not installed in the OpenCode plugins directory.");
  }
  if (report.pluginInstalled && !report.managedInstall) {
    report.ok = false;
    report.errors.push("Plugin file exists but is not marked as an agt-opencode managed install.");
  }
  if (
    report.installedByVersion &&
    report.currentPackageVersion &&
    report.installedByVersion !== report.currentPackageVersion
  ) {
    report.warnings.push(
      `Installed version ${report.installedByVersion} differs from package version ${report.currentPackageVersion}. Run 'agt-opencode update'.`,
    );
  }
  if (!report.sourceBundlePresent) {
    report.warnings.push("Package bundle assets/agt-governance.js is missing. Run 'npm run build'.");
  }

  if (existsSync(paths.policyPath)) {
    try {
      const policy = await readJsonFile(paths.policyPath);
      report.policySchemaVersion = validatePolicyObject(policy, paths.policyPath);
      report.policyValid = true;
    } catch (error) {
      report.ok = false;
      report.errors.push(`User policy is invalid: ${error.message}`);
    }
  } else {
    report.policyValid = true;
    report.warnings.push("No user policy found; the plugin will use its bundled default policy.");
  }

  if (!report.opencodeOnPath) {
    report.warnings.push("OpenCode CLI ('opencode') was not found on PATH.");
  }

  return report;
}

function formatDoctorReport(report) {
  const lines = [
    "agt-opencode doctor",
    "",
    `- OpenCode home:      ${report.opencodeHome}`,
    `- Plugin installed:   ${report.pluginInstalled ? "yes" : "no"} (${report.pluginPath})`,
    `- Managed install:    ${report.managedInstall ? "yes" : "no"}`,
    `- Installed version:  ${report.installedByVersion ?? "n/a"}`,
    `- Package version:    ${report.currentPackageVersion ?? "n/a"}`,
    `- Policy:             ${report.policyValid ? "valid" : "INVALID"} (source: ${report.policySource})`,
    `- Policy path:        ${report.policyPath}`,
    `- Bundle present:     ${report.sourceBundlePresent ? "yes" : "no"}`,
    `- OpenCode on PATH:   ${report.opencodeOnPath ?? "not found"}`,
  ];

  const tc = report.supplyChainToolchain;
  if (tc) {
    lines.push("", "Supply-chain toolchain (transitive CVE scan delegated to these tools):");
    for (const t of SUPPLY_CHAIN_TOOLS) {
      const present = tc.tools[t.name]?.present;
      lines.push(`  - ${(`${t.name} (${t.role})`).padEnd(22)} ${present ? "available" : "not found"}`);
    }
    lines.push("", "  Scan capabilities:");
    for (const cap of tc.capabilities) {
      lines.push(`  - ${cap.label}: ${cap.detail}`);
    }
    if (!tc.anyTransitive) {
      lines.push(
        "",
        "  Note: no transitive CVE scan capability on this box. CI-signed skills are",
        "  unaffected (verified against trustedSigners). Unsigned skills cannot be cleared",
        "  by a local scan, so in enforce mode they are reviewed/blocked.",
      );
    }
  }

  if (report.warnings.length) {
    lines.push("", "Warnings:");
    for (const w of report.warnings) {
      lines.push(`  ! ${w}`);
    }
  }
  if (report.errors.length) {
    lines.push("", "Errors:");
    for (const e of report.errors) {
      lines.push(`  x ${e}`);
    }
  }
  lines.push("", report.ok ? "Result: OK" : "Result: PROBLEMS FOUND");
  return lines.join("\n");
}

// ── skills audit ──────────────────────────────────────────────────────────────
// Proactive (Tier-2) supply-chain audit: scan skill dir(s) and write a `scanned`
// attestation per skill keyed exactly as the runtime gate looks it up, so a
// later tool call is a cache hit. Reuses the bundled engine modules from
// plugin/src; degrades gracefully when no vulnerability scanner is installed.

function isSkillDir(dir) {
  return ["SKILL.md", "skill.md", "skill.yaml", "skill.yml", "skill.json"].some((n) =>
    existsSync(join(dir, n)),
  );
}

function expandSkillDirs(root) {
  try {
    if (!statSync(root).isDirectory()) return [];
  } catch {
    return [];
  }
  if (isSkillDir(root)) return [root];
  const out = [];
  try {
    for (const entry of readdirSync(root, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        const child = join(root, entry.name);
        if (isSkillDir(child)) out.push(child);
      }
    }
  } catch {
    /* unreadable → none */
  }
  return out;
}

export async function auditSkills({ opencodeHome, packageRoot, targets, scannerCmd = null, io = console }) {
  const paths = getPaths({ opencodeHome, packageRoot });

  // Attestations live in the OpenCode agt data dir, the same place the running
  // plugin reads them from (session-store keys off OPENCODE_CONFIG_HOME).
  process.env.AGT_SESSION_STORE = "disk";
  if (!process.env.OPENCODE_CONFIG_HOME) {
    process.env.OPENCODE_CONFIG_HOME = opencodeHome;
  }

  // Import the engine modules from the (unbundled) plugin source.
  const srcDir = join(packageRoot, "plugin", "src");
  const policyMod = await import(pathToFileURL(join(srcDir, "policy.mjs")).href);
  const skillsMod = await import(pathToFileURL(join(srcDir, "skills.mjs")).href);

  const activePolicyPath = existsSync(paths.policyPath) ? paths.policyPath : paths.sourceDefaultPolicyPath;
  const state = await policyMod.loadPolicy({
    defaultPolicyPath: paths.sourceDefaultPolicyPath,
    policyPath: activePolicyPath,
  });
  const skillPolicy = state.policy.skill;
  const depsPolicy = state.policy.deps;
  if (!skillPolicy) {
    io.error("Skill governance is disabled in the active policy (skillPolicies.enabled=false). Nothing to audit.");
    return 1;
  }

  const skillDirs = [];
  for (const t of targets) {
    skillDirs.push(...expandSkillDirs(resolvePath(t)));
  }
  if (skillDirs.length === 0) {
    io.error("No skill directories found under the given path(s).");
    return 1;
  }

  let failures = 0;
  let latestDbVersion = null;
  let latestScanner = null;
  for (const skillDir of skillDirs) {
    const s = await skillsMod.auditSkillDir(skillDir, { skillPolicy, depsPolicy, scannerCmd });
    io.log(`\n# ${s.skillDir}`);
    if (s.error) {
      io.log(`  ERROR: ${s.error}`);
      failures++;
      continue;
    }
    io.log(`  attestation key: ${s.key}`);
    io.log(`  scanner:         ${s.scanner ?? "none installed (skill scan + metadata only)"}`);
    io.log(`  resolved deps:   ${s.resolved.length}${s.fromLockfile ? " (from lockfile)" : ""}`);
    io.log(`  findings:        ${s.findings.length}`);
    for (const f of s.findings.slice(0, 20)) {
      io.log(`    - [${f.severity}] ${f.kind} ${f.file ? `(${f.file})` : ""}: ${f.detail ?? ""}`);
    }
    if (s.findings.length > 20) io.log(`    … +${s.findings.length - 20} more`);
    if (s.note) io.log(`  note: ${s.note}`);
    io.log(`  attestation written: ${s.persisted ? "yes" : "NO (cache write failed)"}`);
    if (s.vulnDbVersion) { latestDbVersion = s.vulnDbVersion; latestScanner = s.scanner ?? latestScanner; }
    if (!s.persisted) failures++;
  }

  // Cache the scanner's current vuln-DB version so the runtime gate can enforce
  // the attestation DB-version binding without spawning a scanner (mirror of the
  // CC skills-audit.mjs runnable). Best-effort.
  if (latestDbVersion) {
    try {
      await writeFile(
        join(paths.dataDir, "scanner-db-version.json"),
        `${JSON.stringify({ version: latestDbVersion, scanner: latestScanner, writtenMs: Date.now() })}\n`,
      );
    } catch { /* best-effort: a cache-write failure just means age-only freshness */ }
  }

  io.log(`\nAudited ${skillDirs.length} skill(s); ${failures} could not be fully attested.`);
  return failures === 0 ? 0 : 1;
}

function getHelpText() {
  return [
    "agt-opencode — Agent Governance Toolkit plugin installer for OpenCode",
    "",
    "Usage: agt-opencode <command> [options]",
    "",
    "Commands:",
    "  install                 Install the governance plugin and seed a default policy",
    "  update                  Refresh the installed plugin in place",
    "  uninstall               Remove the managed plugin (keeps the policy)",
    "  doctor                  Diagnose the install",
    "  policy path             Print the resolved user policy path",
    "  policy show             Print the active policy",
    "  policy validate         Validate a policy file or bundled profile",
    "  policy apply            Apply a policy file or bundled profile",
    "  skills audit <dir>      Scan skill(s) and write supply-chain attestations",
    "",
    "Options:",
    "  --opencode-home <dir>   Override the OpenCode config home",
    "  --force-policy          Overwrite an existing policy when installing/updating",
    "  --remove-policy         Also remove the policy on uninstall",
    "  --file <path>           Policy file for validate/apply",
    "  --profile <name>        Bundled profile for validate/apply (strict|balanced|secure-low-friction|advisory)",
    "  --json                  Machine-readable output (doctor)",
    "  -h, --help              Show this help",
    "  -v, --version           Show the installer version",
  ].join("\n");
}

// ── CLI dispatch ────────────────────────────────────────────────────────────

export async function runCli(argv = [], io = console) {
  try {
    const parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        "opencode-home": { type: "string" },
        "force-policy": { type: "boolean" },
        "remove-policy": { type: "boolean" },
        file: { type: "string" },
        profile: { type: "string" },
        json: { type: "boolean" },
        scanner: { type: "string" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });

    const command = (parsed.positionals[0] ?? "help").toLowerCase();
    const packageRoot = getPackageRoot();
    const opencodeHome = resolveOpencodeHome(parsed.values["opencode-home"]);

    if (parsed.values.version) {
      const metadata = await readPackageMetadata(packageRoot);
      io.log(`${metadata.name} ${metadata.version}`);
      return 0;
    }
    if (parsed.values.help || command === "help") {
      io.log(getHelpText());
      return 0;
    }

    if (command === "install" || command === "update") {
      const result = await installPackage({
        opencodeHome,
        packageRoot,
        forcePolicy: parsed.values["force-policy"] ?? false,
      });
      io.log(`${command === "update" ? "Updated" : "Installed"} the governance plugin at ${result.pluginPath}`);
      io.log(
        result.policySeeded
          ? `Seeded policy at ${result.policyPath}`
          : `Kept existing policy at ${result.policyPath} (use --force-policy to overwrite)`,
      );
      io.log("Restart OpenCode to load the plugin. Verify with: agt-opencode doctor");
      return 0;
    }

    if (command === "uninstall") {
      const result = await uninstallPackage({
        opencodeHome,
        packageRoot,
        removePolicy: parsed.values["remove-policy"] ?? false,
      });
      if (!result.managed) {
        io.log(`No agt-opencode managed install was found under ${opencodeHome}.`);
        return 0;
      }
      io.log(result.pluginRemoved ? `Removed ${result.pluginPath}` : "Plugin file was already absent.");
      io.log(
        result.policyRemoved
          ? `Removed policy ${result.policyPath}`
          : `Preserved policy ${result.policyPath} (use --remove-policy to delete it)`,
      );
      return 0;
    }

    if (command === "doctor") {
      const report = await diagnoseInstall({ opencodeHome, packageRoot });
      io.log(parsed.values.json ? JSON.stringify(report, null, 2) : formatDoctorReport(report));
      return report.ok ? 0 : 1;
    }

    if (command === "policy") {
      const subcommand = (parsed.positionals[1] ?? "help").toLowerCase();
      const paths = getPaths({ opencodeHome, packageRoot });

      if (subcommand === "path") {
        io.log(paths.policyPath);
        return 0;
      }
      if (subcommand === "show") {
        const source = existsSync(paths.policyPath) ? paths.policyPath : paths.sourceDefaultPolicyPath;
        io.log(`Policy source: ${source}`);
        io.log(JSON.stringify(await readJsonFile(source), null, 2));
        return 0;
      }
      if (subcommand === "validate") {
        const source = resolvePolicySource({
          file: parsed.values.file,
          profile: parsed.values.profile,
          paths,
        });
        const schemaVersion = validatePolicyObject(await readJsonFile(source), source);
        io.log(`Valid policy: ${source} (schemaVersion ${schemaVersion})`);
        return 0;
      }
      if (subcommand === "apply") {
        const source = resolvePolicySource({
          file: parsed.values.file,
          profile: parsed.values.profile,
          paths,
        });
        const policy = await readJsonFile(source);
        validatePolicyObject(policy, source);
        await mkdir(paths.dataDir, { recursive: true });
        await writeFile(paths.policyPath, JSON.stringify(policy, null, 2), "utf-8");
        io.log(`Applied ${source} -> ${paths.policyPath}`);
        io.log("Restart OpenCode to load the new policy.");
        return 0;
      }

      io.error("Usage: agt-opencode policy <path|show|validate|apply> [--file <path>] [--profile <name>]");
      return subcommand === "help" ? 0 : 1;
    }

    if (command === "skills") {
      const subcommand = (parsed.positionals[1] ?? "help").toLowerCase();
      if (subcommand !== "audit") {
        io.error("Usage: agt-opencode skills audit <dir> [<dir> ...] [--scanner trivy|osv-scanner|pip-audit]");
        return subcommand === "help" ? 0 : 1;
      }
      const targets = parsed.positionals.slice(2);
      if (targets.length === 0) {
        io.error("Usage: agt-opencode skills audit <dir> [<dir> ...] [--scanner trivy|osv-scanner|pip-audit]");
        return 1;
      }
      return auditSkills({
        opencodeHome,
        packageRoot,
        targets,
        scannerCmd: parsed.values.scanner ?? null,
        io,
      });
    }

    io.error(`Unknown command: ${command}\n`);
    io.error(getHelpText());
    return 1;
  } catch (error) {
    io.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

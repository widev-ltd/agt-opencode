// selftest-deps.mjs — fixture-based tests for the dependency / supply-chain scanner.
// Exercises the PURE functions of deps.mjs only (no attestation, no real scanner
// required). Every metadata finding kind has a TRUE POSITIVE and a BENIGN
// NEAR-MISS that must NOT fire. Run: node selftest-deps.mjs

import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  compileDepsPolicy,
  parseManifests,
  parseManifestFile,
  scanDependencyMetadata,
  depsDecision,
  resolveTransitive,
  runVulnScanner,
  resolveAndScan,
  osvSeverityBand,
  cvssScore,
} from "./deps.mjs";
import { execFileSync } from "node:child_process";

let fail = 0;
const ok = (name, cond) => { console.log(`${cond ? "PASS" : "FAIL"}  ${name}`); if (!cond) fail++; };

const dir = mkdtempSync(join(tmpdir(), "agt-deps-"));
const write = (name, body) => { const p = join(dir, name); writeFileSync(p, body); return p; };
// Write a file with its CANONICAL basename into a fresh sub-directory, so dispatch
// by basename (package.json / pyproject.toml / …) is exercised correctly even when
// two fixtures share a basename.
import { mkdirSync } from "node:fs";
let subN = 0;
const writeCanon = (name, body) => {
  const sub = join(dir, `case-${subN++}`);
  mkdirSync(sub, { recursive: true });
  const p = join(sub, name);
  writeFileSync(p, body);
  return p;
};
const hasKind = (findings, kind) => findings.some((f) => f.kind === kind);
const hasPkg = (findings, kind, pkg) => findings.some((f) => f.kind === kind && String(f.package).toLowerCase() === pkg.toLowerCase());

// Detect whether a CLI tool is runnable so tool-dependent asserts can be guarded.
// On Windows resolvers/scanners are .cmd shims or bare names; route through cmd.exe
// (matching deps.mjs's spawnCapture) so the probe matches how the engine invokes it.
const toolPresent = (cmd) => {
  try {
    if (process.platform === "win32") {
      const comspec = process.env.ComSpec || process.env.COMSPEC || "cmd.exe";
      execFileSync(comspec, ["/d", "/s", "/c", cmd, "--version"], { stdio: "ignore", timeout: 15000 });
    } else {
      execFileSync(cmd, ["--version"], { stdio: "ignore", timeout: 15000 });
    }
    return true;
  } catch { return false; }
};
const HAVE_UV = toolPresent("uv");
const HAVE_NPM = toolPresent("npm");
const HAVE_SCANNER = toolPresent("trivy") || toolPresent("osv-scanner") || toolPresent("pip-audit");
// A tool-gated assertion: assert `cond` ONLY when `present`; otherwise record a
// skip line (counts as pass) so the suite is green both WITH and WITHOUT tools.
const okIf = (present, name, cond) => {
  if (present) { ok(name, cond); }
  else { console.log(`SKIP  ${name} (tool not on PATH)`); }
};
console.log(`[tools] uv=${HAVE_UV} npm=${HAVE_NPM} scanner=${HAVE_SCANNER}\n`);

const advisory = compileDepsPolicy({ enabled: true, mode: "advisory" });
const enforced = compileDepsPolicy({ enabled: true, mode: "enforce" });

try {
  // ── PARSING: requirements.txt ──────────────────────────────────────────────
  const reqPath = write("requirements.txt", [
    "# a comment",
    "requests==2.31.0",
    "flask>=2.0  # inline comment",
    "",
    "-r other.txt",
    "git+https://github.com/evil/pkg.git#egg=pkg",
  ].join("\n"));
  const reqSpecs = parseManifestFile(reqPath);
  ok("requirements: parses pinned + ranged specs",
    reqSpecs.some((s) => s.name === "requests" && /==2\.31\.0/.test(s.spec)) &&
    reqSpecs.some((s) => s.name === "flask"));
  ok("requirements: comment lines ignored",
    !reqSpecs.some((s) => /comment/i.test(s.name)));
  ok("requirements: ecosystem tagged pypi",
    reqSpecs.every((s) => s.ecosystem === "pypi"));

  // ── PARSING: pyproject.toml ────────────────────────────────────────────────
  const pyprojPath = write("pyproject.toml", [
    "[project]",
    'name = "demo"',
    "dependencies = [",
    '  "numpy>=1.24",',
    '  "pandas==2.0.0",',
    "]",
    "",
    "[project.optional-dependencies]",
    'dev = ["pytest==7.0", "black"]',
  ].join("\n"));
  const pyproj = parseManifestFile(pyprojPath);
  ok("pyproject: [project].dependencies parsed",
    pyproj.some((s) => s.name === "numpy") && pyproj.some((s) => s.name === "pandas"));
  ok("pyproject: optional-dependencies parsed",
    pyproj.some((s) => s.name === "pytest") && pyproj.some((s) => s.name === "black"));

  // ── PARSING: package.json (deps + devDeps + install script) ────────────────
  const pkgPath = write("package.json", JSON.stringify({
    name: "demo",
    dependencies: { lodash: "^4.17.21", "left-pad": "1.3.0" },
    devDependencies: { jest: "29.0.0" },
    scripts: { postinstall: "node ./scripts/fetch.js", build: "tsc" },
  }, null, 2));
  const pkg = parseManifestFile(pkgPath);
  ok("package.json: dependencies parsed",
    pkg.some((s) => s.name === "lodash") && pkg.some((s) => s.name === "left-pad"));
  ok("package.json: devDependencies parsed",
    pkg.some((s) => s.name === "jest"));
  ok("package.json: ecosystem tagged npm",
    pkg.filter((s) => !String(s.source).startsWith("script:")).every((s) => s.ecosystem === "npm"));
  ok("package.json: postinstall script surfaced as synthetic spec",
    pkg.some((s) => s.source === "script:postinstall"));
  ok("package.json: benign build script NOT surfaced",
    !pkg.some((s) => s.source === "script:build"));

  // ── PARSING: package-lock.json ─────────────────────────────────────────────
  const lockPath = write("package-lock.json", JSON.stringify({
    name: "demo", lockfileVersion: 3,
    packages: {
      "": { name: "demo" },
      "node_modules/lodash": { version: "4.17.21" },
      "node_modules/chalk": { version: "5.3.0" },
    },
  }, null, 2));
  const lock = parseManifestFile(lockPath);
  ok("package-lock: resolved versions parsed",
    lock.some((s) => s.name === "lodash" && /4\.17\.21/.test(s.spec)) &&
    lock.some((s) => s.name === "chalk"));

  // ── PARSING: uv.lock ───────────────────────────────────────────────────────
  const uvLockPath = write("uv.lock", [
    "[[package]]",
    'name = "requests"',
    'version = "2.31.0"',
    "",
    "[[package]]",
    'name = "urllib3"',
    'version = "2.0.7"',
  ].join("\n"));
  const uvLock = parseManifestFile(uvLockPath);
  ok("uv.lock: name/version pairs parsed",
    uvLock.some((s) => s.name === "requests" && /==2\.31\.0/.test(s.spec)) &&
    uvLock.some((s) => s.name === "urllib3"));

  // ── PARSING: PEP 723 inline block in a .py target ──────────────────────────
  const pep723Body = [
    "# /// script",
    "# requires-python = \">=3.11\"",
    "# dependencies = [",
    "#   \"requests<3\",",
    "#   \"rich>=13\",",
    "# ]",
    "# ///",
    "",
    "import requests",
    "print('hi')",
  ].join("\n");
  const scriptPath = write("script.py", pep723Body);
  const pep = parseManifestFile(scriptPath);
  ok("pep723: inline dependencies parsed from .py",
    pep.some((s) => s.name === "requests") && pep.some((s) => s.name === "rich"));
  // …and via the command path (uv run script.py).
  const pepFromCmd = parseManifests({ command: `uv run ${scriptPath}`, cwd: dir });
  ok("pep723: reachable via 'uv run script.py' command",
    pepFromCmd.some((s) => s.name === "rich"));

  // ── PARSING: inline command install args ───────────────────────────────────
  const pipCmd = parseManifests({ command: "pip install requests flask==2.0", cwd: dir });
  ok("command: 'pip install pkgs' parsed",
    pipCmd.some((s) => s.name === "requests") && pipCmd.some((s) => s.name === "flask"));
  const uvWith = parseManifests({ command: "uv run --with rich script.py", cwd: dir });
  ok("command: 'uv run --with PKG' parsed",
    uvWith.some((s) => s.name === "rich"));
  const npmCmd = parseManifests({ command: "npm install left-pad axios", cwd: dir });
  ok("command: 'npm install pkgs' parsed",
    npmCmd.some((s) => s.name === "left-pad") && npmCmd.some((s) => s.ecosystem === "npm"));
  const pipR = parseManifests({ command: "pip install -r requirements.txt", cwd: dir });
  ok("command: 'pip install -r file' reads the requirements file",
    pipR.some((s) => s.name === "requests"));

  // (Removed: unpinned + typosquat metadata tests — those detectors were cut.)

  // ── METADATA: deny list ────────────────────────────────────────────────────
  const denyPol = compileDepsPolicy({ enabled: true, mode: "enforce", deny: ["evilpkg"] });
  const mDeny = scanDependencyMetadata([{ ecosystem: "pypi", name: "evilpkg", spec: "evilpkg==1.0", source: "t" }], denyPol);
  ok("metadata: denied package flagged", hasKind(mDeny, "denied-package"));
  const mAllow = scanDependencyMetadata([{ ecosystem: "pypi", name: "goodpkg", spec: "goodpkg==1.0", source: "t" }], denyPol);
  ok("metadata: non-denied package NOT flagged denied", !hasKind(mAllow, "denied-package"));

  // ── METADATA: git+ URL / non-registry source flagged ───────────────────────
  const mGit = scanDependencyMetadata([{ ecosystem: "pypi", name: "pkg", spec: "git+https://github.com/evil/pkg.git", source: "t" }], advisory);
  ok("metadata: git+ URL flagged non-registry", hasKind(mGit, "non-registry-source"));
  const mFile = scanDependencyMetadata([{ ecosystem: "npm", name: "local", spec: "local@file:../local", source: "t" }], advisory);
  ok("metadata: file: source flagged non-registry", hasKind(mFile, "non-registry-source"));
  const mPlain = scanDependencyMetadata([{ ecosystem: "npm", name: "lodash", spec: "lodash@4.17.21", source: "t" }], advisory);
  ok("metadata: plain registry spec NOT flagged non-registry", !hasKind(mPlain, "non-registry-source"));

  // ── METADATA: npm install/postinstall script flagged ───────────────────────
  const mScript = scanDependencyMetadata([{ ecosystem: "npm", name: "demo", spec: "node ./fetch.js", source: "script:postinstall" }], advisory);
  ok("metadata: postinstall script flagged install-script", hasKind(mScript, "install-script"));

  // ── METADATA: untrusted index URL guard ────────────────────────────────────
  const idxPol = compileDepsPolicy({ enabled: true, mode: "enforce", allowedIndexes: ["pypi.org"] });
  const mIdx = scanDependencyMetadata([], idxPol, { command: "pip install --index-url https://evil.example/simple foo" });
  ok("metadata: unapproved --index-url flagged untrusted-index", hasKind(mIdx, "untrusted-index"));
  const mIdxOk = scanDependencyMetadata([], idxPol, { command: "pip install --index-url https://pypi.org/simple foo" });
  ok("metadata: approved --index-url NOT flagged", !hasKind(mIdxOk, "untrusted-index"));

  // (Removed: license-deny tests — license-deny was cut as compliance-not-security.)

  // ── DECISION mapping (mirrors dlpDecision) ─────────────────────────────────
  const highF = [{ kind: "non-registry-source", severity: "high", package: "p", detail: "x" }];
  const medF = [{ kind: "yanked", severity: "medium", package: "x", detail: "x" }];
  ok("decision: advisory high → allow", depsDecision(highF, advisory).decision === "allow");
  ok("decision: enforce high (≥medium threshold) → deny", depsDecision(highF, enforced).decision === "deny");
  ok("decision: enforce medium (=threshold) → deny", depsDecision(medF, enforced).decision === "deny");
  ok("decision: no findings → null", depsDecision([], enforced) === null);
  const lowThresh = compileDepsPolicy({ enabled: true, mode: "enforce", severityThreshold: "critical" });
  ok("decision: high below critical threshold → review", depsDecision(highF, lowThresh).decision === "review");

  // ── ROBUSTNESS: malformed + huge input must not throw ──────────────────────
  let threw = false;
  try {
    const badPkg = write("bad-package.json", "{ not valid json ,,,, ");
    parseManifestFile(badPkg);
    const badToml = write("bad.pyproject.toml", "[project\ndependencies = [unclosed");
    parseManifestFile(join(dir, "bad.pyproject.toml"));
    // Huge requirements file (bounded read must cap it).
    write("huge.requirements.txt", "requests==1.0\n".repeat(400000));
    parseManifestFile(join(dir, "huge.requirements.txt"));
    // Huge command.
    parseManifests({ command: "pip install " + "x".repeat(500000), cwd: dir });
    // Missing file.
    parseManifestFile(join(dir, "does-not-exist.txt"));
    // Null-ish inputs.
    parseManifests({});
    parseManifests({ command: null, cwd: null });
    scanDependencyMetadata(null, advisory);
    scanDependencyMetadata([{}], advisory);
    depsDecision(null, advisory);
  } catch (e) {
    threw = true;
    console.log("  threw:", e?.message);
  }
  ok("robustness: malformed / huge / missing input never throws", !threw);

  // Bad pyproject did not crash AND produced no garbage findings.
  const badPyproj = parseManifestFile(join(dir, "bad.pyproject.toml"));
  ok("robustness: malformed toml yields an array (no crash)", Array.isArray(badPyproj));

  // ── disabled policy ────────────────────────────────────────────────────────
  ok("disabled policy: compile returns null", compileDepsPolicy({ enabled: false }) === null);
  ok("disabled policy: scan with null policy → []",
    scanDependencyMetadata([{ ecosystem: "pypi", name: "reqeusts", spec: "reqeusts", source: "t" }], null).length === 0);

  // ════════════════════════════════════════════════════════════════════════════
  // ADVERSARIAL-PANEL REGRESSION TESTS (P1–P11 + scanner fidelity). Each asserts a
  // confirmed PoC is now caught AND a benign near-miss still does NOT fire.
  // ════════════════════════════════════════════════════════════════════════════

  // ── P1: npm alias `name@npm:realpkg@ver` checks the REAL target ─────────────
  const aliasDeny = compileDepsPolicy({ enabled: true, mode: "enforce", deny: ["evil"] });
  // command form: alias is harmless, target `evil` is denied
  const aliasCmd = parseManifests({ command: "npm install goodname@npm:evil@1.0.0", cwd: dir });
  ok("P1: npm alias command re-points name to the real aliased target",
    aliasCmd.some((s) => s.name === "evil" && s.aliasOf === "goodname"));
  ok("P1: npm alias denied target flagged (alias name would have slipped through)",
    hasKind(scanDependencyMetadata(aliasCmd, aliasDeny), "denied-package"));
  // package.json form: {"x": "npm:evil@1"}
  const aliasPkgPath = writeCanon("package.json", JSON.stringify({
    name: "demo", dependencies: { harmless: "npm:evil@1.0.0" },
  }));
  const aliasPkg = parseManifestFile(aliasPkgPath);
  ok("P1: package.json npm-alias range checks the real target",
    aliasPkg.some((s) => s.name === "evil" && s.aliasOf === "harmless") &&
    hasKind(scanDependencyMetadata(aliasPkg, aliasDeny), "denied-package"));

  // ── P2: extended lifecycle scripts (prepare/prepublish*/prestart) ──────────
  const lifePath = writeCanon("package.json", JSON.stringify({
    name: "demo",
    scripts: { prepare: "node a.js", prepublishOnly: "node b.js", prestart: "node c.js",
               build: "tsc", test: "jest" },
  }));
  const life = parseManifestFile(lifePath);
  ok("P2: prepare lifecycle script surfaced", life.some((s) => /^script:prepare$/i.test(s.source)));
  ok("P2: prepublishOnly lifecycle script surfaced (case-insensitive)",
    life.some((s) => /^script:prepublishonly$/i.test(s.source)));
  ok("P2: prestart lifecycle script surfaced", life.some((s) => /^script:prestart$/i.test(s.source)));
  ok("P2: benign build/test scripts NOT surfaced",
    !life.some((s) => /^script:(build|test)$/i.test(s.source)));
  ok("P2: extended lifecycle scripts flagged install-script",
    hasKind(scanDependencyMetadata(life, advisory), "install-script"));

  // ── P3: in-file editable VCS in requirements.txt ───────────────────────────
  const editPath = write("edit.requirements.txt", [
    "requests==2.31.0",
    "-e git+https://github.com/evil/pkg.git#egg=pkg",
    "--editable git+ssh://git@github.com/evil/other.git",
    "-e ./localpkg",
  ].join("\n"));
  const edit = parseManifestFile(editPath);
  ok("P3: '-e git+https' editable parsed (not dropped as a flag line)",
    edit.some((s) => /git\+https/.test(s.spec)));
  ok("P3: '--editable git+ssh' editable parsed",
    edit.some((s) => /git\+ssh/.test(s.spec)));
  ok("P3: editable VCS/local flagged non-registry",
    scanDependencyMetadata(edit, advisory).filter((f) => f.kind === "non-registry-source").length >= 2);

  // ── P4: PEP503 normalization on deny/allow (separators + case) ─────────────
  const p503Deny = compileDepsPolicy({ enabled: true, mode: "enforce", deny: ["evil-pkg"] });
  for (const variant of ["evil_pkg", "evil.pkg", "evil--pkg", "Evil-PKG"]) {
    ok(`P4: deny 'evil-pkg' catches PEP503 variant '${variant}'`,
      hasKind(scanDependencyMetadata([{ ecosystem: "pypi", name: variant, spec: `${variant}==1.0`, source: "t" }], p503Deny), "denied-package"));
  }
  ok("P4: unrelated package 'evilish' NOT caught by 'evil-pkg' deny",
    !hasKind(scanDependencyMetadata([{ ecosystem: "pypi", name: "evilish", spec: "evilish==1.0", source: "t" }], p503Deny), "denied-package"));

  // ── P5: env-var index + `npm config set registry` URL guard ────────────────
  const p5Pol = compileDepsPolicy({ enabled: true, mode: "enforce", allowedIndexes: ["pypi.org"] });
  ok("P5: PIP_INDEX_URL env var flagged untrusted-index",
    hasKind(scanDependencyMetadata([], p5Pol, { command: "PIP_INDEX_URL=https://evil.example/simple pip install foo" }), "untrusted-index"));
  ok("P5: UV_INDEX_URL env var flagged untrusted-index",
    hasKind(scanDependencyMetadata([], p5Pol, { command: "UV_INDEX_URL=https://evil.example/simple uv pip install foo" }), "untrusted-index"));
  ok("P5: npm_config_registry env var flagged untrusted-index",
    hasKind(scanDependencyMetadata([], p5Pol, { command: "npm_config_registry=https://evil.example/ npm install foo" }, ), "untrusted-index"));
  ok("P5: 'npm config set registry <url>' flagged untrusted-index",
    hasKind(scanDependencyMetadata([], p5Pol, { command: "npm config set registry https://evil.example/" }), "untrusted-index"));
  ok("P5: approved PIP_INDEX_URL NOT flagged",
    !hasKind(scanDependencyMetadata([], p5Pol, { command: "PIP_INDEX_URL=https://pypi.org/simple pip install foo" }), "untrusted-index"));

  // (Removed: P6/P7 typosquat-tuning tests — the name-distance heuristic was cut.)

  // ── P8: pyproject [build-system].requires + poetry TABLE form ──────────────
  const p8Path = writeCanon("pyproject.toml", [
    "[build-system]",
    'requires = ["setuptools>=61", "cython==3.0.0"]',
    'build-backend = "setuptools.build_meta"',
    "",
    "[tool.poetry.dependencies]",
    'python = "^3.11"',
    'requests = "^2.31"',
    'pandas = "2.0.0"',
    "evilgit = { git = \"https://github.com/evil/x.git\" }",
    "",
    "[tool.poetry.group.dev.dependencies]",
    'pytest = "^7.0"',
  ].join("\n"));
  const p8 = parseManifestFile(p8Path);
  ok("P8: [build-system].requires parsed",
    p8.some((s) => s.name === "setuptools") && p8.some((s) => s.name === "cython"));
  ok("P8: poetry TABLE dependencies parsed",
    p8.some((s) => s.name === "requests") && p8.some((s) => s.name === "pandas"));
  ok("P8: poetry interpreter 'python' key skipped",
    !p8.some((s) => s.name === "python"));
  ok("P8: poetry dev-group dependencies parsed",
    p8.some((s) => s.name === "pytest"));
  ok("P8: poetry git inline-table flagged non-registry",
    hasKind(scanDependencyMetadata(p8, advisory), "non-registry-source"));

  // ── P9: parseManifests(null) / parseManifestFile(null) must not throw ──────
  let p9threw = false;
  let p9a, p9b;
  try { p9a = parseManifests(null); p9b = parseManifestFile(null); }
  catch { p9threw = true; }
  ok("P9: parseManifests(null)/parseManifestFile(null) return arrays, no throw",
    !p9threw && Array.isArray(p9a) && Array.isArray(p9b));

  // ── P10: MAX_SPECS truncation emits an explicit finding (not silent drop) ──
  const tooMany = [];
  for (let i = 0; i < 5001; i++) tooMany.push({ ecosystem: "pypi", name: `p${i}`, spec: `p${i}==1.0`, source: "t" });
  ok("P10: >MAX_SPECS input yields an analysis-truncated finding",
    hasKind(scanDependencyMetadata(tooMany, advisory), "analysis-truncated"));
  ok("P10: at-cap input does NOT emit truncation finding",
    !hasKind(scanDependencyMetadata(tooMany.slice(0, 10), advisory), "analysis-truncated"));

  // ── P11: PEP723 `#///` no-space tolerance + no bare-.txt dispatch ──────────
  const pep723NoSpace = write("nospace.py", [
    "#/// script",
    '# dependencies = ["requests<3", "rich"]',
    "#///",
    "print('hi')",
  ].join("\n"));
  const pepNoSpace = parseManifestFile(pep723NoSpace);
  ok("P11: PEP723 '#///' no-space markers tolerated",
    pepNoSpace.some((s) => s.name === "requests") && pepNoSpace.some((s) => s.name === "rich"));
  const notReq = write("notes.txt", "requests==2.31.0\nflask\n");
  ok("P11: a bare notes.txt is NOT parsed as requirements",
    parseManifestFile(notReq).length === 0);
  ok("P11: a real requirements-dev.txt IS still parsed",
    parseManifestFile(write("requirements-dev.txt", "pytest==7.0\n")).some((s) => s.name === "pytest"));

  // ── Scanner fidelity 13: osv CVSS-vector severity banding (no scanner needed) ─
  ok("osv-sev: CVSS:3.1 critical vector → critical",
    osvSeverityBand({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] }) === "critical");
  ok("osv-sev: CVSS:3.1 low vector → low",
    osvSeverityBand({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L" }] }) === "low");
  ok("osv-sev: no vector but database_specific HIGH → high",
    osvSeverityBand({ database_specific: { severity: "HIGH" } }) === "high");
  ok("osv-sev: no severity info at all → medium (not blanket-medium-by-default-for-V3)",
    osvSeverityBand({}) === "medium");
  ok("osv-sev: CVSS:4.0 high-impact vector → high or critical (not flat medium)",
    ["high", "critical"].includes(osvSeverityBand({ severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }] })));
  ok("cvss: 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H scores 9.8",
    Math.abs(cvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") - 9.8) < 0.05);
  ok("cvss: non-CVSS string → null", cvssScore("not-a-vector") === null);

  // ── Scanner fidelity 12/16: pip-audit needs -r; coverage/dbVersion fields ──
  // With NO scanner on PATH the result must still carry coverage:'unavailable'.
  const covMissing = await runVulnScanner([], { cwd: dir, scannerCmd: "definitely-not-real-xyz" });
  ok("coverage: missing scanner → coverage:'unavailable' + dbVersion null",
    covMissing.coverage === "unavailable" && covMissing.dbVersion === null);

  // ════════════════════════════════════════════════════════════════════════════
  // TIER-2 SECURITY CONTRACT: ACTUAL transitive resolution + scan, and the
  // FAIL-SAFE that the false-clean defect demands. Coverage vocabulary is
  //   transitive | declared-only | unavailable
  // and we must NEVER report `transitive` for a set that was not really resolved
  // AND scanned. Tool-dependent asserts are gated behind a presence check (okIf);
  // the FAIL-SAFE asserts always run, with NO tools needed.
  // ════════════════════════════════════════════════════════════════════════════

  // ── helper: write a manifest into a fresh dir and resolve+scan it ───────────
  const inDir = (name, body) => {
    const sub = join(dir, `t2-${subN++}`);
    mkdirSync(sub, { recursive: true });
    writeFileSync(join(sub, name), body);
    return sub;
  };
  const sevSet = (findings) => new Set(findings.map((f) => f.severity));

  // ── T2.1: PEP 723 inline vulnerable (jinja2==2.10) → transitive CVEs ────────
  const pepDir = inDir("vuln.py", [
    "# /// script",
    '# dependencies = ["jinja2==2.10", "PyYAML==5.1"]',
    "# ///",
    "print('hi')",
  ].join("\n"));
  const pepScan = await resolveAndScan({ cwd: pepDir });
  okIf(HAVE_UV && HAVE_SCANNER, "T2.1: PEP723 inline jinja2==2.10 → coverage 'transitive'",
    pepScan.coverage === "transitive" && pepScan.method === "uv");
  okIf(HAVE_UV && HAVE_SCANNER, "T2.1: PEP723 inline → CVE finding present (transitive scan caught it)",
    pepScan.findings.length > 0 && sevSet(pepScan.findings).has("critical"));
  // FAIL-SAFE (always): WITHOUT uv+scanner this must be 'unavailable', never a
  // clean/transitive stamp. (The exact false-clean bug being fixed.)
  if (!(HAVE_UV && HAVE_SCANNER)) {
    ok("T2.1 FAIL-SAFE: PEP723 inline without uv/scanner → 'unavailable' (never clean)",
      pepScan.coverage === "unavailable" && pepScan.findings.length === 0);
  }
  // INVARIANT (always): coverage 'transitive' is ONLY ever paired with real findings
  // here, and is NEVER claimed when unavailable.
  ok("T2.1 INVARIANT: never 'transitive' unless a scanner actually ran",
    pepScan.coverage !== "transitive" || pepScan.available === true);

  // ── T2.2: requirements.txt + pyproject.toml vulnerable → transitive CVEs ────
  const reqDir = inDir("requirements.txt", "jinja2==2.10\nPyYAML==5.1\n");
  const reqScan = await resolveAndScan({ cwd: reqDir });
  okIf(HAVE_UV && HAVE_SCANNER, "T2.2: requirements.txt jinja2==2.10 → transitive CVEs",
    reqScan.coverage === "transitive" && reqScan.findings.length > 0);
  const pyprojDir = inDir("pyproject.toml", [
    "[project]", 'name = "demo"', 'version = "0.0.0"',
    'requires-python = ">=3.9"', 'dependencies = ["jinja2==2.10"]',
  ].join("\n"));
  const pyprojScan = await resolveAndScan({ cwd: pyprojDir });
  okIf(HAVE_UV && HAVE_SCANNER, "T2.2: pyproject.toml jinja2==2.10 → transitive CVEs",
    pyprojScan.coverage === "transitive" && pyprojScan.findings.length > 0);

  // ── T2.3: package.json vulnerable (lodash@4.17.4) → transitive CVEs ─────────
  const nodeDir = inDir("package.json", JSON.stringify({
    name: "vuln-demo", version: "1.0.0", dependencies: { lodash: "4.17.4" },
  }));
  const nodeScan = await resolveAndScan({ cwd: nodeDir });
  okIf(HAVE_NPM && HAVE_SCANNER, "T2.3: package.json lodash@4.17.4 → coverage 'transitive' via npm",
    nodeScan.coverage === "transitive" && nodeScan.method === "npm" && nodeScan.findings.length > 0);
  if (!(HAVE_NPM && HAVE_SCANNER)) {
    ok("T2.3 FAIL-SAFE: package.json without npm/scanner → 'unavailable' (never clean)",
      nodeScan.coverage === "unavailable" && nodeScan.findings.length === 0);
  }

  // ── T2.4: clean pinned-latest set → transitive, ZERO findings ──────────────
  const cleanPyDir = inDir("requirements.txt", "six==1.17.0\n");
  const cleanPyScan = await resolveAndScan({ cwd: cleanPyDir });
  okIf(HAVE_UV && HAVE_SCANNER, "T2.4: clean six==1.17.0 → transitive, zero findings",
    cleanPyScan.coverage === "transitive" && cleanPyScan.findings.length === 0);
  const cleanNodeDir = inDir("package.json", JSON.stringify({
    name: "clean", version: "1.0.0", dependencies: { ms: "2.1.3" },
  }));
  const cleanNodeScan = await resolveAndScan({ cwd: cleanNodeDir });
  okIf(HAVE_NPM && HAVE_SCANNER, "T2.4: clean ms@2.1.3 → transitive, zero findings",
    cleanNodeScan.coverage === "transitive" && cleanNodeScan.findings.length === 0);

  // ════════════════════════════════════════════════════════════════════════════
  // FAIL-SAFE PANEL (ALWAYS asserted — no tools required). Every path that cannot
  // reliably resolve+scan MUST yield coverage 'unavailable', MUST NOT throw, and
  // MUST NOT claim a clean/transitive result. This is the security guarantee.
  // ════════════════════════════════════════════════════════════════════════════

  // FS1: no manifest at all → unavailable, never transitive.
  const fsEmpty = mkdtempSync(join(tmpdir(), "agt-deps-empty-"));
  try {
    const r = await resolveAndScan({ cwd: fsEmpty });
    ok("FS1: empty dir (no manifest) → coverage 'unavailable', no findings",
      r.coverage === "unavailable" && r.findings.length === 0 && r.available === false);
    const rt = await resolveTransitive([{ ecosystem: "pypi", name: "x", spec: "x==1", source: "t" }], { cwd: fsEmpty });
    ok("FS1: resolveTransitive on empty dir → 'unavailable' (NEVER 'transitive')",
      rt.coverage === "unavailable" && rt.scanDir === null);
  } finally {
    rmSync(fsEmpty, { recursive: true, force: true });
  }

  // FS2: a .py with NO PEP 723 block is not resolvable → unavailable.
  const fsNoBlock = inDir("plain.py", "print('no deps here')\n");
  {
    const r = await resolveTransitive([], { cwd: fsNoBlock, manifests: [join(fsNoBlock, "plain.py")] });
    ok("FS2: .py without a PEP723 block → 'unavailable' (no false transitive)",
      r.coverage === "unavailable");
  }

  // FS3: NO scanner (forced-missing) even when resolution could succeed → the
  // result is unavailable, NOT transitive. (Resolver-OK + scanner-missing.)
  const fs3Dir = inDir("requirements.txt", "jinja2==2.10\n");
  {
    const r = await resolveAndScan({ cwd: fs3Dir, scannerCmd: "definitely-not-a-real-scanner-xyz" });
    ok("FS3: resolver-ok but scanner forced-missing → 'unavailable', never 'transitive'",
      r.coverage === "unavailable" && r.findings.length === 0 && r.available === false);
  }

  // FS4: runVulnScanner with a real resolved scanDir but a forced-missing scanner
  // → unavailable; and with NO scanDir (legacy bare-cwd) → NEVER 'transitive'.
  {
    const noScanner = await runVulnScanner([], { scanDir: dir, coverage: "transitive", scannerCmd: "definitely-not-real-xyz" });
    ok("FS4: forced-missing scanner over a scanDir → 'unavailable' (coverage ceiling discarded)",
      noScanner.coverage === "unavailable" && noScanner.available === false);
    const bareCwd = await runVulnScanner([], { cwd: dir });
    ok("FS4: runVulnScanner with NO scanDir is NEVER 'transitive'",
      bareCwd.coverage === "unavailable" || bareCwd.coverage === "declared-only");
  }

  // FS5: resolver ERROR (unresolvable package version) → unavailable, not transitive.
  // Only meaningful when uv is present; otherwise FS1/FS3 already cover the no-tool path.
  if (HAVE_UV) {
    const fs5Dir = inDir("bad.py", [
      "# /// script",
      '# dependencies = ["this-package-does-not-exist-xyz123==9.9.9"]',
      "# ///",
    ].join("\n"));
    const r = await resolveTransitive([{ ecosystem: "pypi", name: "x", spec: "x==1", source: "t" }], { cwd: fs5Dir });
    ok("FS5: uv resolver ERROR (unresolvable pkg) → 'unavailable' (NEVER 'transitive')",
      r.coverage === "unavailable" && r.scanDir === null && typeof r.note === "string");
  } else {
    console.log("SKIP  FS5: uv resolver-error path (uv not on PATH)");
  }

  // FS6: nothing ever throws across the whole Tier-2 surface, even on junk input.
  let t2threw = false;
  try {
    await resolveTransitive(null, {});
    await resolveTransitive(null, { cwd: null, manifests: null });
    await runVulnScanner(null, {});
    await runVulnScanner(null, { scanDir: null, coverage: "bogus", scannerCmd: null });
    await resolveAndScan({});
    await resolveAndScan({ cwd: null, manifests: null, specs: null });
  } catch (e) {
    t2threw = true; console.log("  Tier-2 threw:", e?.message);
  }
  ok("FS6: Tier-2 (resolveTransitive/runVulnScanner/resolveAndScan) never throws on junk", !t2threw);

  // INVARIANT-WIDE: across every Tier-2 result observed above, a 'transitive'
  // coverage is ALWAYS accompanied by available===true (a scanner actually ran).
  const allT2 = [pepScan, reqScan, pyprojScan, nodeScan, cleanPyScan, cleanNodeScan];
  ok("INVARIANT: every 'transitive' result had a scanner actually run (available)",
    allT2.every((r) => r.coverage !== "transitive" || r.available === true));
  ok("INVARIANT: no Tier-2 result reports the obsolete 'full' coverage value",
    allT2.every((r) => r.coverage !== "full"));

  // ── Well-formedness: coverage is always one of the three legal values ───────
  const scanAuto = await resolveAndScan({ cwd: dir });
  ok("well-formed: coverage ∈ {transitive, declared-only, unavailable}",
    ["transitive", "declared-only", "unavailable"].includes(scanAuto.coverage));
  ok("well-formed: dbVersion is a string or null",
    scanAuto.dbVersion === null || typeof scanAuto.dbVersion === "string");
  ok("well-formed: findings is always an array", Array.isArray(scanAuto.findings));

} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${fail === 0 ? "ALL PASS" : fail + " FAILED"}`);
process.exit(fail === 0 ? 0 : 1);

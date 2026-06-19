// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// deps.mjs — Dependency / supply-chain governance for the AGT governance plugin.
//
// When the agent runs `pip install`, `uv run script.py`, `npm install`, or just
// works inside a repo with a manifest, it can pull arbitrary code from a public
// index into the host. That is the dominant supply-chain risk for an autonomous
// coding agent: typosquats, unpinned floating versions, packages fetched from a
// git URL or a private index the operator never approved, and packages whose
// install scripts run code at install time. This module governs that surface in
// two tiers:
//
//   TIER 1 (sync, runtime-safe): parse the manifests / install command, then run
//     cheap METADATA checks (unpinned, non-registry source, typosquat, allow/deny,
//     index-URL guard, license deny, install-script presence). No network, no
//     subprocess — safe to call from the synchronous decision path (the same path
//     as checkForExfil). It NEVER throws: malformed or huge input yields findings
//     or an empty array, never an exception that would crash a hook.
//
//   TIER 2 (async, audit-only): resolve the transitive set (from a lockfile when
//     present) and shell out to an installed vulnerability scanner (trivy /
//     osv-scanner / pip-audit, auto-detected). This spawns a subprocess and is
//     used ONLY by the proactive audit command, never at tool-call time. It
//     degrades gracefully: no scanner installed / timeout / unparseable output
//     → { available:false, findings:[], note } rather than an exception.
//
// THREAT MODEL:
//   - Typosquatting: `reqeusts`, `python-dateutil` vs `python-datetime`, `loadsh`.
//     A bounded edit-distance check against a configurable popular-package list.
//   - Dependency confusion / unapproved index: `--index-url` / `--extra-index-url`
//     pointing at an attacker-controlled or simply unapproved registry.
//   - Install-time code execution: npm pre/post/install lifecycle scripts; a
//     python `setup.py` that contains code (not a static pyproject build).
//   - Floating versions: an unpinned spec lets a later malicious release land
//     silently. requirePinned flags any spec without an exact version.
//   - Non-registry sources: `git+https://…`, `file:`, a bare URL — code that
//     bypasses the registry's (weak) review entirely.
//
// POLICY INTEGRATION (mirrors compileDlpPolicy):
//   depsPolicies.mode = "advisory"  → findings surfaced as context, no deny
//   depsPolicies.mode = "enforce"   → severity ≥ threshold maps to deny/review
//
// The Tier-2 scanner result can be folded into an attestation by attestation.mjs;
// this module exposes a thin integration helper (attestDepsScan) that imports it
// lazily so deps.mjs has no hard dependency on attestation at load time.

import { statSync, openSync, readSync, closeSync, readFileSync, readdirSync } from "node:fs";

// Bound every file/command read so a hostile multi-GB manifest cannot exhaust
// memory or stall the sync decision path.
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024; // 2 MiB
const MAX_COMMAND_LENGTH = 64 * 1024; // 64 KiB
const MAX_SPECS = 5000; // cap the number of specs we will ever report on

// ── Default popular-package list for typosquat detection ─────────────────────
// A SMALL, high-value default. Operators extend it via depsPolicies.popularPackages.
// The bar for inclusion: a package common enough that a one-edit typo is a likely
// squat target. Keep it short — a huge list inflates the O(specs × packages × len)
// edit-distance cost on the sync path.
export const DEFAULT_POPULAR_PYPI = [
  "requests", "urllib3", "numpy", "pandas", "boto3", "botocore", "setuptools",
  "pip", "wheel", "cryptography", "flask", "django", "fastapi", "pydantic",
  "scipy", "scikit-learn", "matplotlib", "pytest", "pyyaml", "python-dateutil",
  "click", "jinja2", "sqlalchemy", "aiohttp", "httpx", "tensorflow", "torch",
];
export const DEFAULT_POPULAR_NPM = [
  "react", "lodash", "express", "axios", "chalk", "commander", "debug",
  "moment", "webpack", "typescript", "eslint", "jest", "vue", "next",
  "dotenv", "uuid", "classnames", "redux", "rxjs", "babel-core", "node-fetch",
];

// ── Policy compilation ───────────────────────────────────────────────────────

export function compileDepsPolicy(raw) {
  if (!raw || raw.enabled === false) {
    return null;
  }
  const mode = raw.mode === "enforce" ? "enforce" : "advisory";
  const popularPackages = {
    pypi: dedupeLower([...DEFAULT_POPULAR_PYPI, ...arrayOf(raw.popularPackages?.pypi ?? raw.popularPackages)]),
    npm: dedupeLower([...DEFAULT_POPULAR_NPM, ...arrayOf(raw.popularPackages?.npm)]),
  };
  return {
    mode,
    severityThreshold: normalizeSeverity(raw.severityThreshold, "medium"),
    allow: dedupeLower(arrayOf(raw.allow)),
    deny: dedupeLower(arrayOf(raw.deny)),
    requirePinned: raw.requirePinned === true,
    // Default registries are the canonical public ones; an operator REPLACES this
    // to lock to a private mirror. An empty allowedIndexes means "any index is OK"
    // (the index-URL guard then only flags clearly-unapproved when a list exists).
    allowedIndexes: arrayOf(raw.allowedIndexes).map((s) => String(s).toLowerCase()),
    deniedLicenses: arrayOf(raw.deniedLicenses).map((s) => String(s).toLowerCase()),
    popularPackages,
    typosquatDistance: Number.isFinite(raw.typosquatDistance) ? Math.max(1, raw.typosquatDistance | 0) : 1,
    maxAgeMs: Number.isFinite(raw.maxAgeMs) ? Number(raw.maxAgeMs) : null,
  };
}

function normalizeSeverity(s, fallback) {
  return ["critical", "high", "medium", "low"].includes(s) ? s : fallback;
}
const SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function arrayOf(v) {
  if (Array.isArray(v)) return v.filter((x) => x != null);
  if (v == null) return [];
  if (typeof v === "string") return [v];
  return [];
}
function dedupeLower(list) {
  return [...new Set(list.map((s) => String(s).toLowerCase().trim()).filter(Boolean))];
}

// ── Tier-1: parsing (SYNC, never throws) ─────────────────────────────────────

/**
 * Parse every dependency declaration reachable from a tool call: the install
 * command itself plus any manifest in `cwd` it implies. SYNC and total — returns
 * a (possibly empty) array of canonical specs; never throws.
 *
 * @param {{command?: string, cwd?: string}} input
 * @returns {{ecosystem:'pypi'|'npm', name:string, spec:string, source:string}[]}
 */
export function parseManifests(input) {
  // Default-guard: parseManifests(null) / parseManifests() must not throw.
  const { command = "", cwd = "" } = input ?? {};
  const specs = [];
  try {
    if (command) {
      pushAll(specs, parseInstallCommand(String(command).slice(0, MAX_COMMAND_LENGTH), cwd));
    }
  } catch { /* total: a malformed command yields no command-derived specs */ }
  return capSpecs(specs);
}

/**
 * Parse a single manifest file by path, dispatching on its basename. SYNC and
 * total. Returns canonical specs; unreadable / unknown / malformed → [].
 */
export function parseManifestFile(path) {
  let text;
  try {
    text = readBoundedSync(path);
  } catch {
    return [];
  }
  if (text == null) return [];
  const base = basename(path).toLowerCase();
  try {
    if (isRequirementsTxtName(base)) return capSpecs(parseRequirementsTxt(text, base));
    if (base === "pyproject.toml") return capSpecs(parsePyprojectToml(text));
    if (base === "uv.lock" || base === "poetry.lock") return capSpecs(parsePyLock(text, base));
    if (base === "package.json") return capSpecs(parsePackageJson(text));
    if (base === "package-lock.json") return capSpecs(parsePackageLock(text));
    if (base.endsWith(".py")) return capSpecs(parsePep723(text));
    // NOTE: a bare `*.txt` is NOT dispatched as requirements — only the recognized
    // requirements*/constraints* names above. A random README.txt or notes.txt is
    // not a manifest and parsing it as one only produces noise / false findings.
  } catch { /* total */ }
  return [];
}

// Parse `pip install` / `uv pip install` / `uv run --with` / `pip install -r file`
// and PEP 723 inline blocks reachable from `python file.py` / `uv run file.py`.
function parseInstallCommand(command, cwd) {
  const out = [];
  // Split on shell separators so we examine each sub-command independently. This
  // is a heuristic tokenizer — robust to quoting only loosely, which is fine: we
  // over-collect candidate package tokens and validate each as a spec.
  const segments = command.split(/&&|\|\||;|\n/);
  for (const segment of segments) {
    const tokens = tokenizeCommand(segment);
    if (tokens.length === 0) continue;

    const joined = segment.toLowerCase();
    const isPip = /\bpip3?\b/.test(joined) && /\binstall\b/.test(joined);
    const isUvPip = /\buv\b/.test(joined) && /\bpip\b/.test(joined) && /\binstall\b/.test(joined);
    const isNpm = /\b(?:npm|pnpm|yarn)\b/.test(joined) && /\b(?:install|i|add)\b/.test(joined);

    // `--with PKG` (uv run) and `--index-url` / `--extra-index-url` apply anywhere.
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t === "--with" || t === "--with-requirements") {
        const v = tokens[i + 1];
        if (v && !v.startsWith("-")) out.push(canonicalSpec("pypi", v, "uv-run --with"));
      } else if (t.startsWith("--with=")) {
        out.push(canonicalSpec("pypi", t.slice("--with=".length), "uv-run --with"));
      }
    }

    if (isPip || isUvPip) {
      pushAll(out, parsePipInstallTokens(tokens, cwd, isUvPip ? "uv pip install" : "pip install"));
    }
    if (isNpm) {
      pushAll(out, parseNpmInstallTokens(tokens));
    }

    // `python file.py` / `uv run file.py` → look for a PEP 723 block in the target.
    if (/\b(?:python3?|uv)\b/.test(joined)) {
      for (const tok of tokens) {
        if (tok.endsWith(".py") && !tok.startsWith("-")) {
          const text = readBoundedSync(joinPath(cwd, tok));
          if (text != null) pushAll(out, parsePep723(text));
        }
      }
    }
  }
  return out.filter(Boolean);
}

function parsePipInstallTokens(tokens, cwd, source) {
  const out = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === "-r" || t === "--requirement") {
      const file = tokens[i + 1];
      if (file && !file.startsWith("-")) {
        const text = readBoundedSync(joinPath(cwd, file));
        if (text != null) pushAll(out, parseRequirementsTxt(text, file));
      }
      i++;
      continue;
    }
    if (t.startsWith("-")) continue; // a flag (e.g. --index-url) — handled by the metadata index guard
    if (t === "install" || t === "pip" || t === "pip3" || t === "uv") continue;
    // A positional package spec.
    const spec = canonicalSpec("pypi", t, source);
    if (spec) out.push(spec);
  }
  return out;
}

function parseNpmInstallTokens(tokens) {
  const out = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith("-")) continue;
    if (["npm", "pnpm", "yarn", "install", "i", "add"].includes(t)) continue;
    const spec = canonicalSpec("npm", t, "npm install");
    if (spec) out.push(spec);
  }
  return out;
}

// PEP 723: an inline metadata block in a .py file:
//   # /// script
//   # dependencies = ["requests", "rich>=13"]
//   # ///
function parsePep723(text) {
  const out = [];
  const s = String(text ?? "");
  // The opening marker is `# /// script`, but tolerate a missing space after `#`
  // (`#/// script`) and extra spaces. The closing marker is `# ///` (likewise).
  const open = /(?:^|\n)#\s*\/\/\/\s*script\b/.exec(s);
  if (!open) return out;
  const bodyStart = open.index + open[0].length;
  const close = /(?:^|\n)#\s*\/\/\/\s*(?:\n|$)/.exec(s.slice(bodyStart));
  if (!close) return out;
  const block = s
    .slice(bodyStart, bodyStart + close.index)
    .split("\n")
    .map((l) => l.replace(/^#\s?/, "")) // strip the comment prefix to recover TOML
    .join("\n");
  for (const dep of parseTomlDependencyArray(block, "dependencies")) {
    const spec = canonicalSpec("pypi", dep, "pep723");
    if (spec) out.push(spec);
  }
  return out;
}

// Recognize a pip requirements/constraints file by basename: `requirements.txt`,
// `requirements-dev.txt`, `dev-requirements.txt`, `requirements.in`, `constraints.txt`,
// `*.requirements.txt`. A bare `notes.txt`/`README.txt` is NOT a manifest.
function isRequirementsTxtName(base) {
  return /^(?:requirements|constraints)(?:[-_.][\w.-]*)?\.(?:txt|in)$/.test(base) ||
    /[-_.](?:requirements|constraints)\.(?:txt|in)$/.test(base) ||
    base === "requirements.txt" || base === "constraints.txt";
}

function parseRequirementsTxt(text, source) {
  const out = [];
  let count = 0;
  for (let line of text.split("\n")) {
    if (++count > MAX_SPECS) break;
    line = line.replace(/\r$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    // Strip an inline comment (requirements.txt allows `pkg==1.0  # note`).
    const hash = line.indexOf(" #");
    if (hash !== -1) line = line.slice(0, hash).trim();
    if (!line) continue;
    // Editable install of a VCS/URL/path target: `-e git+https://…`,
    // `--editable git+…`, `-e .`, `-e ./pkg`. These bypass the index entirely, so
    // we must NOT drop the line as a mere flag — parse the target and let the
    // metadata scanner flag it non-registry. (A bare `-e .`/`-e ./x` local path
    // is also non-registry.)
    const em = /^(?:-e|--editable)(?:[=\s]+)(\S+)/.exec(line);
    if (em) {
      const target = em[1];
      // `-e .` / `-e -` carries no analyzable target — skip silently.
      if (target && target !== "." && target !== "-") {
        // Prefix bare local paths with `file:` so nonRegistrySource recognizes them.
        const norm = /^(?:\.?\.?[\\/]|[a-z]:[\\/])/i.test(target) ? `file:${target}` : target;
        const spec = canonicalSpec("pypi", norm, `requirements:${source}:editable`);
        if (spec) out.push(spec);
      }
      continue;
    }
    if (line.startsWith("-")) continue; // other flag lines (-r other.txt, --index-url …) handled elsewhere
    const spec = canonicalSpec("pypi", line, `requirements:${source}`);
    if (spec) out.push(spec);
  }
  return out;
}

function parsePyprojectToml(text) {
  const out = [];
  // [project].dependencies = [...] and [project.optional-dependencies] groups.
  for (const dep of parseTomlDependencyArray(text, "dependencies")) {
    const spec = canonicalSpec("pypi", dep, "pyproject:dependencies");
    if (spec) out.push(spec);
  }
  // optional-dependencies is a table of arrays; collect every array value.
  const optIdx = text.indexOf("[project.optional-dependencies]");
  if (optIdx !== -1) {
    const section = text.slice(optIdx, nextSectionIndex(text, optIdx));
    for (const arr of section.matchAll(/=\s*\[([\s\S]*?)\]/g)) {
      for (const dep of splitTomlArrayItems(arr[1])) {
        const spec = canonicalSpec("pypi", dep, "pyproject:optional");
        if (spec) out.push(spec);
      }
    }
  }
  // [build-system].requires = [...] — build-time deps (setuptools, wheel, cython,
  // and anything an attacker slips into the build). Scope the `requires` lookup to
  // the [build-system] section so it can't grab an unrelated `requires` elsewhere.
  const bsm = /(?:^|\n)[ \t]*\[build-system\][ \t]*(?:\n|$)/.exec(text);
  if (bsm) {
    const body = bsm.index + bsm[0].length;
    const section = text.slice(body, nextSectionIndex(text, body));
    for (const dep of parseTomlDependencyArray(section, "requires")) {
      const spec = canonicalSpec("pypi", dep, "pyproject:build-system");
      if (spec) out.push(spec);
    }
  }
  // Poetry TABLE form: [tool.poetry.dependencies] (and group/dev variants) hold
  //   name = "^1.0"   or   name = { version = "^1.0", ... }
  // one per line, NOT an array. Skip the `python` key (interpreter constraint).
  // Slice from AFTER the header line (the match consumes a leading newline) to the
  // next section, so nextSectionIndex doesn't re-find this very header's bracket.
  for (const m of text.matchAll(/(?:^|\n)[ \t]*\[tool\.poetry(?:\.group\.[^\].]+)?\.(?:dev-)?dependencies\][ \t]*(?:\n|$)/g)) {
    const body = m.index + m[0].length;
    const section = text.slice(body, nextSectionIndex(text, body));
    pushAll(out, parsePoetryDependencyTable(section));
  }
  return out;
}

// Parse a `[tool.poetry.*dependencies]` TABLE: each line is `name = <value>` where
// value is a version string or an inline table. Returns canonical specs (skips the
// interpreter `python` key and the section header line itself).
function parsePoetryDependencyTable(section) {
  const out = [];
  let count = 0;
  for (const line of section.split("\n")) {
    if (++count > MAX_SPECS) break;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("[")) continue;
    // key = ...   (key may be quoted). Capture the bare key name.
    const km = /^["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=/.exec(trimmed);
    if (!km) continue;
    const key = km[1];
    if (key.toLowerCase() === "python") continue; // interpreter, not a package
    // An inline table with git/path/url is a non-registry source — carry it so the
    // metadata scanner can flag it.
    const srcm = /(git|path|url)\s*=\s*["']([^"']+)["']/.exec(trimmed);
    let spec;
    if (srcm) {
      const kind = srcm[1] === "path" ? "file:" : srcm[1] === "git" ? "git+" : "";
      spec = canonicalSpec("pypi", `${key} @ ${kind}${srcm[2]}`, "pyproject:poetry");
    } else {
      // Recover the version string: `version = "..."` in an inline table, else a
      // top-level string value. Map poetry constraint syntax to a PEP508-ish spec
      // so isPinned classifies it correctly: a bare exact version → `==x`, anything
      // with a range operator (^ ~ > < * ,) is preserved as-is so it reads unpinned.
      const inlineVer = /version\s*=\s*["']([^"']+)["']/.exec(trimmed);
      const strVal = inlineVer ? null : /=\s*["']([^"']+)["']/.exec(trimmed);
      const ver = inlineVer ? inlineVer[1] : (strVal ? strVal[1] : null);
      let token = key;
      if (ver) {
        token = /^[0-9]+(?:\.[0-9]+)*$/.test(ver.trim())
          ? `${key}==${ver.trim()}`   // bare exact version
          : `${key} ${ver.trim()}`;   // range/caret/tilde → keep operators visible
      }
      spec = canonicalSpec("pypi", token, "pyproject:poetry");
    }
    if (spec) out.push(spec);
  }
  return out;
}

function parsePyLock(text, source) {
  const out = [];
  // uv.lock / poetry.lock are TOML with repeated [[package]] tables carrying
  // name = "x" and version = "y". Pair adjacent name/version within each block.
  const blocks = text.split(/\[\[package\]\]/);
  let count = 0;
  for (const block of blocks) {
    if (++count > MAX_SPECS) break;
    const name = matchTomlString(block, "name");
    const version = matchTomlString(block, "version");
    if (name) {
      out.push({ ecosystem: "pypi", name: normName(name), spec: version ? `${normName(name)}==${version}` : normName(name), source: `lock:${source}` });
    }
  }
  return out;
}

function parsePackageJson(text) {
  const out = [];
  const json = safeJsonParse(text);
  if (!json || typeof json !== "object") return out;
  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const deps = json[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, range] of Object.entries(deps)) {
      // An `npm:realpkg@ver` range is an alias; the REAL package is the target,
      // so check that (deny/typosquat/non-registry) rather than the alias key.
      const aliasTarget = npmAliasTarget(range);
      out.push(aliasTarget
        ? { ecosystem: "npm", name: aliasTarget, spec: `${name}@${range}`, source: `package.json:${field}`, aliasOf: String(name) }
        : { ecosystem: "npm", name: String(name), spec: `${name}@${range}`, source: `package.json:${field}` });
    }
  }
  // Surface install-lifecycle scripts as a synthetic spec carrying the script body
  // so the metadata scanner can flag code that runs at install/publish time. Beyond
  // the classic pre/post/install trio, `prepare` runs on `npm install` (local and
  // on git-dep installs) and `prepublish*`/`prestart` run automatically too — all
  // are install-time-ish code-execution surfaces an attacker can hide a payload in.
  if (json.scripts && typeof json.scripts === "object") {
    for (const hook of ["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishonly", "prestart"]) {
      // npm script names are case-sensitive but conventionally lowercase; match
      // case-insensitively so `prepublishOnly` (the documented casing) is caught.
      const key = Object.keys(json.scripts).find((k) => k.toLowerCase() === hook);
      if (key && typeof json.scripts[key] === "string" && json.scripts[key].trim()) {
        out.push({ ecosystem: "npm", name: json.name ? String(json.name) : "(this package)", spec: json.scripts[key], source: `script:${key}` });
      }
    }
  }
  return out;
}

function parsePackageLock(text) {
  const out = [];
  const json = safeJsonParse(text);
  if (!json || typeof json !== "object") return out;
  // lockfileVersion 2/3: "packages" keyed by node_modules path; v1: "dependencies".
  const collect = (obj, prefix) => {
    if (!obj || typeof obj !== "object") return;
    let count = 0;
    for (const [key, meta] of Object.entries(obj)) {
      if (++count > MAX_SPECS) break;
      if (!meta || typeof meta !== "object") continue;
      const name = key.split("node_modules/").pop() || key.replace(prefix, "");
      if (!name) continue;
      const version = typeof meta.version === "string" ? meta.version : "";
      out.push({ ecosystem: "npm", name, spec: version ? `${name}@${version}` : name, source: "lock:package-lock.json" });
    }
  };
  collect(json.packages, "");
  if (out.length === 0) collect(json.dependencies, "");
  return out;
}

// ── canonical spec construction ──────────────────────────────────────────────

/**
 * Build a canonical {ecosystem,name,spec,source} from a raw spec token, or null
 * if the token is not a parseable dependency (e.g. a path that is just `.`).
 */
function canonicalSpec(ecosystem, raw, source) {
  let token = String(raw ?? "").trim();
  if (!token) return null;
  // Strip surrounding quotes left by loose tokenizing.
  token = token.replace(/^["']|["']$/g, "");
  if (!token || token === "." || token === "-") return null;

  // Non-registry sources keep the whole token as both name-ish and spec so the
  // metadata scanner can flag them; we still try to extract a readable name.
  if (ecosystem === "pypi") {
    // PEP 508: name[extras] (op version) ; markers   or a direct reference name @ url
    const at = token.indexOf("@");
    const name = normName(token.split(/[\s<>=!~;\[@(]/)[0]);
    if (!name) return null;
    return { ecosystem, name, spec: token, source };
  }
  // npm: name, name@range, @scope/name@range, git url, file:…
  let name = token;
  if (token.startsWith("@")) {
    // scoped: @scope/name@range → name is up to the SECOND '@'
    const second = token.indexOf("@", 1);
    name = second === -1 ? token : token.slice(0, second);
  } else {
    const a = token.indexOf("@");
    if (a > 0) name = token.slice(0, a);
  }
  // npm alias: `alias@npm:realpkg@ver` (command form) or a package.json range of
  // `npm:realpkg@ver`. The REAL fetched package is the aliased target, so deny /
  // typosquat / non-registry checks must run against it, not the harmless alias.
  const range = npmRange(token);
  const aliasTarget = npmAliasTarget(range);
  if (aliasTarget) {
    return { ecosystem, name: aliasTarget, spec: token, source, aliasOf: name };
  }
  return { ecosystem, name, spec: token, source };
}

// Given an npm range, return the real package name if it is an `npm:` alias
// (`npm:realpkg@1`, `npm:@scope/realpkg@1`, `npm:realpkg`), else null.
function npmAliasTarget(range) {
  const r = String(range ?? "").trim().replace(/^["']|["']$/g, "");
  if (!/^npm:/i.test(r)) return null;
  const rest = r.slice(r.indexOf(":") + 1).trim();
  if (!rest) return null;
  if (rest.startsWith("@")) {
    // scoped target: @scope/name(@ver) → name is up to the SECOND '@'
    const second = rest.indexOf("@", 1);
    return second === -1 ? rest : rest.slice(0, second);
  }
  const at = rest.indexOf("@");
  return at > 0 ? rest.slice(0, at) : rest;
}

// ── Tier-1: metadata scanner (SYNC) ──────────────────────────────────────────

/**
 * Run cheap metadata checks over parsed specs. SYNC, never throws.
 * @param {object[]} specs   from parseManifests / parseManifestFile
 * @param {object} depsPolicy compiled policy (compileDepsPolicy)
 * @param {{command?:string}} ctx optional — the command, for the index-URL guard
 * @returns {{kind, severity, package, detail}[]}
 */
export function scanDependencyMetadata(specs, depsPolicy, ctx = {}) {
  if (!depsPolicy || !Array.isArray(specs) || specs.length === 0) {
    // Even with no specs, an --index-url on the command is worth flagging.
    if (depsPolicy && ctx.command) return scanIndexUrls(ctx.command, depsPolicy);
    return [];
  }
  const findings = [];
  try {
    // If more specs were supplied than we will analyze, say so explicitly rather
    // than silently dropping the tail — an operator must know coverage was partial.
    if (specs.length > MAX_SPECS) {
      findings.push({ kind: "analysis-truncated", severity: "info", package: "(deps)",
        detail: `${specs.length} dependency specs supplied; only the first ${MAX_SPECS} were analyzed (${specs.length - MAX_SPECS} not checked).` });
    }
    for (const spec of specs.slice(0, MAX_SPECS)) {
      pushAll(findings, scanOneSpec(spec, depsPolicy));
    }
    if (ctx.command) pushAll(findings, scanIndexUrls(ctx.command, depsPolicy));
  } catch { /* total: return whatever we gathered */ }
  return findings;
}

function scanOneSpec(spec, policy) {
  const out = [];
  const name = String(spec.name || "").toLowerCase();
  const ecosystem = spec.ecosystem;

  // Install-lifecycle script (carried as a synthetic spec from package.json).
  if (typeof spec.source === "string" && spec.source.startsWith("script:")) {
    out.push({ kind: "install-script", severity: "high", package: spec.name,
      detail: `npm ${spec.source.slice("script:".length)} lifecycle script runs at install time: ${truncate(spec.spec, 120)}` });
    return out;
  }

  // For deny/allow we compare PEP 503 canonical names on BOTH sides so a deny of
  // `evil-pkg` also matches `evil_pkg`, `evil.pkg`, `evil--pkg`. For npm we only
  // lowercase (npm names are already separator-meaningful, not collapsible).
  const cmpName = ecosystem === "pypi" ? pep503Name(spec.name) : name;
  const canon = (list) => ecosystem === "pypi" ? list.some((d) => pep503Name(d) === cmpName) : list.includes(cmpName);

  // Deny list — highest priority, short-circuit.
  if (canon(policy.deny)) {
    out.push({ kind: "denied-package", severity: "high", package: spec.name,
      detail: `Package "${spec.name}" is on the operator deny list.` });
    return out;
  }
  const allowed = policy.allow.length > 0 && canon(policy.allow);

  // Non-registry source: git+, file:, bare URL, local path, direct-reference @ url.
  const nonReg = nonRegistrySource(spec.spec, ecosystem);
  if (nonReg) {
    out.push({ kind: "non-registry-source", severity: "high", package: spec.name,
      detail: `Dependency is fetched from a non-registry source (${nonReg}), bypassing index review: ${truncate(spec.spec, 120)}` });
  }

  // Typosquat: bounded edit-distance vs the popular list, EXCLUDING an exact match.
  const popular = ecosystem === "npm" ? policy.popularPackages.npm : policy.popularPackages.pypi;
  const squat = nearestPopular(name, popular, policy.typosquatDistance);
  if (squat) {
    out.push({ kind: "typosquat", severity: "high", package: spec.name,
      detail: `Package name "${spec.name}" is within edit-distance ${squat.distance} of popular package "${squat.name}" — possible typosquat.` });
  }

  // Unpinned (no exact version) — skipped for allow-listed packages and for
  // non-registry specs (already flagged) and synthetic lock-derived specs.
  if (policy.requirePinned && !allowed && !nonReg && !isPinned(spec, ecosystem)) {
    out.push({ kind: "unpinned", severity: "medium", package: spec.name,
      detail: `Dependency "${spec.spec}" is not pinned to an exact version; a later release could be malicious.` });
  }

  // License deny (only when license info is attached to the spec, e.g. from a
  // resolved lockfile/metadata pass).
  if (policy.deniedLicenses.length && spec.license) {
    const lic = String(spec.license).toLowerCase();
    if (policy.deniedLicenses.some((d) => lic.includes(d))) {
      out.push({ kind: "denied-license", severity: "medium", package: spec.name,
        detail: `Package "${spec.name}" declares license "${spec.license}", which is on the deny list.` });
    }
  }

  // Yanked / outdated — best-effort, only when flags survived parsing/metadata.
  if (spec.yanked) {
    out.push({ kind: "yanked", severity: "medium", package: spec.name,
      detail: `Package "${spec.name}"@${spec.version ?? spec.spec} is marked yanked by the registry.` });
  }
  if (policy.maxAgeMs && Number.isFinite(spec.releasedAt) && Date.now() - spec.releasedAt > policy.maxAgeMs) {
    out.push({ kind: "outdated", severity: "low", package: spec.name,
      detail: `Package "${spec.name}" release is older than the configured max age.` });
  }

  return out;
}

// An index/registry can be redirected by a CLI flag, an inline ENV VAR, or an
// `npm config set registry` call — all are dependency-confusion vectors, so we
// collect candidate URLs from every form and flag any not on allowedIndexes.
const INDEX_URL_PATTERNS = [
  // pip/uv flags: --index-url / --extra-index-url / npm --registry
  /--(?:extra-)?index-url(?:[=\s]+)(\S+)/gi,
  /--registry(?:[=\s]+)(\S+)/gi,
  // env-var assignments (inline `VAR=url cmd`, `export VAR=url`, `set VAR=url`):
  // PIP_INDEX_URL / PIP_EXTRA_INDEX_URL / UV_INDEX_URL / UV_EXTRA_INDEX_URL,
  // npm_config_registry. Match case-insensitively on the variable name.
  /\b(?:PIP_(?:EXTRA_)?INDEX_URL|UV_(?:EXTRA_)?INDEX_URL|UV_DEFAULT_INDEX|npm_config_registry)\s*=\s*(\S+)/gi,
  // `npm config set registry <url>` (also pnpm/yarn config set registry).
  /\bconfig\s+set\s+registry(?:[=\s]+)(\S+)/gi,
];

function scanIndexUrls(command, policy) {
  const out = [];
  const text = String(command ?? "");
  const seen = new Set();
  for (const re of INDEX_URL_PATTERNS) {
    re.lastIndex = 0;
    let m;
    let count = 0;
    while ((m = re.exec(text)) !== null) {
      if (++count > 64) break; // bound work on hostile input
      const url = String(m[1] ?? "").replace(/^["']|["']$/g, "");
      if (!url) continue;
      const lower = url.toLowerCase();
      if (seen.has(lower)) continue;
      seen.add(lower);
      const ok = policy.allowedIndexes.length === 0
        ? isCanonicalIndex(lower)
        : policy.allowedIndexes.some((a) => lower.includes(a));
      if (!ok) {
        out.push({ kind: "untrusted-index", severity: "high", package: "(install)",
          detail: `Install uses index "${url}" which is not on the approved index list; risks dependency confusion.` });
      }
    }
  }
  return out;
}

function isCanonicalIndex(lower) {
  return lower.includes("pypi.org") || lower.includes("registry.npmjs.org") ||
    lower.includes("files.pythonhosted.org");
}

/**
 * Map metadata findings to a backend decision (mirrors dlpDecision). Advisory
 * mode always allows (context only); enforce maps severity ≥ threshold to deny,
 * one rung below to review.
 */
export function depsDecision(findings, policy) {
  if (!policy || !findings || findings.length === 0) return null;
  const highest = findings.reduce((h, f) => (SEVERITY_ORDER[f.severity] ?? 0) > (SEVERITY_ORDER[h] ?? 0) ? f.severity : h, "low");
  const reason = `Deps: ${findings.slice(0, 3).map((f) => `${f.kind}:${f.package} (${f.severity})`).join(", ")}` +
    `${findings.length > 3 ? ` +${findings.length - 3} more` : ""}. ${findings[0].detail}`;

  if (policy.mode !== "enforce") return { decision: "allow", reason };
  const threshold = SEVERITY_ORDER[policy.severityThreshold] ?? SEVERITY_ORDER.medium;
  const score = SEVERITY_ORDER[highest] ?? 0;
  if (score >= threshold) return { decision: "deny", reason };
  if (score >= threshold - 1) return { decision: "review", reason };
  return { decision: "allow", reason };
}

// ── Tier-2: transitive resolution + vulnerability scanner (ASYNC) ────────────

/**
 * Best-effort transitive resolution. If a lockfile is present in `cwd` we read
 * the fully-resolved set from it; otherwise we return the declared set plus a
 * note that real resolution needs a resolver (we do NOT shell out to one here).
 * @returns {Promise<{resolved:object[], fromLockfile:boolean, note?:string}>}
 */
export async function resolveTransitive(specs, { cwd = "" } = {}) {
  const lockfiles = ["uv.lock", "poetry.lock", "package-lock.json"];
  for (const lf of lockfiles) {
    const text = readBoundedSync(joinPath(cwd, lf));
    if (text != null) {
      const resolved = parseManifestFile(joinPath(cwd, lf));
      if (resolved.length) return { resolved, fromLockfile: true };
    }
  }
  return {
    resolved: Array.isArray(specs) ? specs.slice(0, MAX_SPECS) : [],
    fromLockfile: false,
    note: "No lockfile found; reporting the DECLARED dependency set only. Transitive resolution requires running a resolver (pip/uv/npm), which this audit does not do.",
  };
}

// Scanner adapters in detection order: each knows how to probe, build args, and
// parse its JSON into a common rawFindings shape. `buildArgs(cwd)` may return null
// to mean "I have no input to scan here" (e.g. pip-audit with no requirements file)
// — runVulnScanner then degrades to available:false rather than scanning the wrong
// thing. `scansLockfile` is true when the tool resolves a lockfile / project tree
// (so coverage can be reported as full), false when it only sees the declared set.
const SCANNERS = [
  {
    name: "trivy",
    versionArgs: ["--version"],
    buildArgs: (cwd) => ["fs", "--scanners", "vuln", "--format", "json", "--quiet", cwd || "."],
    parse: parseTrivyJson,
    scansLockfile: true,
  },
  {
    name: "osv-scanner",
    versionArgs: ["--version"],
    buildArgs: (cwd) => ["--format", "json", "--recursive", cwd || "."],
    parse: parseOsvJson,
    scansLockfile: true,
  },
  {
    name: "pip-audit",
    versionArgs: ["--version"],
    // pip-audit with NO target audits the AMBIENT environment (wrong, and often
    // empty/misleading). Always scan the requirements/constraints files present in
    // cwd via `-r`; if there are none, return null so the scan is reported
    // unavailable instead of silently auditing the host interpreter.
    buildArgs: (cwd) => {
      const reqs = findRequirementsFiles(cwd);
      if (reqs.length === 0) return null;
      const args = ["--format", "json", "--progress-spinner", "off"];
      for (const f of reqs) { args.push("-r", f); }
      return args;
    },
    parse: parsePipAuditJson,
    // pip-audit -r reads the DECLARED requirements set, not a resolved lockfile.
    scansLockfile: false,
  },
];

// List requirements/constraints files in cwd (non-recursive, bounded). Returns
// absolute-ish paths suitable for `pip-audit -r`. Never throws.
function findRequirementsFiles(cwd) {
  if (!cwd) return [];
  let entries;
  try {
    entries = readdirSync(cwd);
  } catch {
    return [];
  }
  const out = [];
  for (const name of entries) {
    if (out.length >= 64) break;
    if (isRequirementsTxtName(String(name).toLowerCase())) out.push(joinPath(cwd, name));
  }
  return out;
}

/**
 * Auto-detect an installed scanner (trivy → osv-scanner → pip-audit), run it,
 * and parse its output. NEVER throws — on no scanner / timeout / parse failure
 * returns { available:false, findings:[], note }.
 * @returns {Promise<{available:boolean, scanner?:string, findings:object[], note?:string}>}
 */
export async function runVulnScanner(resolvedSpecs, { cwd = "", scannerCmd = null, timeoutMs = 120000, fromLockfile = null } = {}) {
  let chosen = null;
  if (scannerCmd) {
    chosen = SCANNERS.find((s) => s.name === scannerCmd) || null;
    if (chosen && !(await probeScanner(chosen.name, chosen.versionArgs))) chosen = null;
  } else {
    for (const s of SCANNERS) {
      if (await probeScanner(s.name, s.versionArgs)) { chosen = s; break; }
    }
  }
  if (!chosen) {
    return { available: false, coverage: "unavailable", dbVersion: null, findings: [],
      note: "No supported vulnerability scanner found on PATH (looked for trivy, osv-scanner, pip-audit)." };
  }

  const args = chosen.buildArgs(cwd);
  if (args == null) {
    // The scanner has nothing to scan here (e.g. pip-audit with no requirements
    // file) — report unavailable rather than scanning the wrong target.
    return { available: false, scanner: chosen.name, coverage: "unavailable", dbVersion: null, findings: [],
      note: `${chosen.name} has no scannable input in this directory (no requirements/constraints file for pip-audit); skipping rather than auditing the ambient environment.` };
  }

  const run = await spawnCapture(chosen.name, args, { cwd, timeoutMs });
  if (run.timedOut) {
    return { available: false, scanner: chosen.name, coverage: "unavailable", dbVersion: null, findings: [],
      note: `${chosen.name} timed out after ${timeoutMs} ms.` };
  }
  // Many scanners exit non-zero precisely BECAUSE they found vulns, so we parse
  // stdout regardless of exit code; only a parse failure degrades to unavailable.
  let findings;
  try {
    findings = chosen.parse(run.stdout) ?? [];
  } catch {
    findings = null;
  }
  if (findings == null) {
    return { available: false, scanner: chosen.name, coverage: "unavailable", dbVersion: null, findings: [],
      note: `${chosen.name} produced output that could not be parsed as JSON findings.` };
  }
  // Coverage: a tool that resolves a lockfile/project tree covers the FULL resolved
  // set; one that reads only the declared set (pip-audit -r) is "declared-only". If
  // the caller told us a lockfile drove resolution, prefer that signal.
  const lockKnown = typeof fromLockfile === "boolean";
  const coverage = (lockKnown ? fromLockfile : chosen.scansLockfile) ? "full" : "declared-only";
  const db = await scannerDbVersion(chosen.name);
  return { available: true, scanner: chosen.name, coverage, dbVersion: db ? db.version : null, findings };
}

/** Best-effort scanner vuln-DB version string, or null. Never throws. */
export async function scannerDbVersion(scannerCmd = null) {
  const names = scannerCmd ? [scannerCmd] : SCANNERS.map((s) => s.name);
  for (const name of names) {
    const r = await spawnCapture(name, ["--version"], { timeoutMs: 10000 });
    // A spawn error ("spawn trivy ENOENT") or a non-zero exit means the tool isn't
    // really there — its stderr is NOT a version string, so don't return it.
    if (r.timedOut || r.spawnError || r.code !== 0) continue;
    // On success prefer stdout (the real --version output) over stderr. Some tools
    // print the version banner to stdout, the DB line on a later line — take the
    // first non-empty line of stdout.
    const text = (r.stdout && r.stdout.trim()) ? r.stdout : r.stderr;
    const line = String(text ?? "").trim().split("\n").map((l) => l.trim()).find(Boolean);
    if (line) return { scanner: name, version: line.slice(0, 200) };
  }
  return null;
}

async function probeScanner(name, versionArgs) {
  const r = await spawnCapture(name, versionArgs, { timeoutMs: 10000 });
  return !r.timedOut && (r.code === 0 || /\d+\.\d+/.test(r.stdout) || /\d+\.\d+/.test(r.stderr));
}

// Spawn a process, capture stdout/stderr, enforce a timeout. NEVER throws —
// returns { code, stdout, stderr, timedOut, spawnError }. Used only by Tier-2.
async function spawnCapture(cmd, args, { cwd = "", timeoutMs = 120000 } = {}) {
  const { spawn } = await import("node:child_process");
  return await new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { cwd: cwd || undefined, shell: false, windowsHide: true });
    } catch (e) {
      resolve({ code: -1, stdout: "", stderr: String(e?.message ?? e), timedOut: false, spawnError: true });
      return;
    }
    let stdout = "";
    let stderr = "";
    let done = false;
    const MAX_OUT = 8 * 1024 * 1024;
    const finish = (res) => { if (!done) { done = true; clearTimeout(timer); try { child.kill(); } catch {} resolve(res); } };
    const timer = setTimeout(() => finish({ code: -1, stdout, stderr, timedOut: true }), timeoutMs);
    child.stdout?.on("data", (d) => { if (stdout.length < MAX_OUT) stdout += d.toString("utf8"); });
    child.stderr?.on("data", (d) => { if (stderr.length < MAX_OUT) stderr += d.toString("utf8"); });
    child.on("error", (e) => finish({ code: -1, stdout, stderr: stderr + String(e?.message ?? e), timedOut: false, spawnError: true }));
    child.on("close", (code) => finish({ code, stdout, stderr, timedOut: false }));
  });
}

// ── Scanner output parsers (each: string → rawFindings[] | throws on bad JSON) ─

function parseTrivyJson(stdout) {
  const json = JSON.parse(stdout);
  const out = [];
  for (const result of arrayOf(json?.Results)) {
    for (const v of arrayOf(result?.Vulnerabilities)) {
      out.push({
        id: v.VulnerabilityID ?? "",
        severity: mapSeverity(v.Severity),
        package: v.PkgName ?? "",
        fixedVersion: v.FixedVersion ?? null,
        source: "trivy",
      });
    }
  }
  return out;
}

function parseOsvJson(stdout) {
  const json = JSON.parse(stdout);
  const out = [];
  for (const result of arrayOf(json?.results)) {
    for (const pkg of arrayOf(result?.packages)) {
      const name = pkg?.package?.name ?? "";
      for (const v of arrayOf(pkg?.vulnerabilities)) {
        out.push({
          id: v.id ?? "",
          severity: mapSeverity(osvSeverity(v)),
          package: name,
          fixedVersion: null,
          source: "osv-scanner",
        });
      }
    }
  }
  return out;
}

// Resolve an OSV vulnerability to a severity BAND. OSV carries severity two ways:
//   - severity[]: {type:"CVSS_V3"|"CVSS_V4", score:"<CVSS vector>"} — the canonical
//     machine form; we compute the base score from the vector and band it.
//   - database_specific.severity: a textual band ("CRITICAL"/"HIGH"/"MODERATE"…) —
//     present for GHSA-sourced entries, absent for many PYSEC entries.
// Prefer the computed CVSS score (most precise), fall back to the text band, then
// to "medium" only when neither exists. Returns a band string for mapSeverity.
function osvSeverity(v) {
  let bestScore = null;
  for (const s of arrayOf(v?.severity)) {
    const score = cvssBaseScore(String(s?.score ?? ""));
    if (score != null && (bestScore == null || score > bestScore)) bestScore = score;
  }
  if (bestScore != null) return cvssBand(bestScore);
  const ds = v?.database_specific?.severity;
  if (typeof ds === "string" && ds.trim()) return ds;
  return "medium";
}

// Exported for the selftest so severity banding can be validated WITHOUT a real
// scanner on PATH (scanner-agnostic). Maps an OSV vulnerability object to a band.
export function osvSeverityBand(v) {
  return mapSeverity(osvSeverity(v));
}

// Exported for the selftest: numeric CVSS base score from a vector string (or null).
export function cvssScore(vector) {
  return cvssBaseScore(vector);
}

// CVSS qualitative band from a numeric base score (v3 ranges, also used for v4).
function cvssBand(score) {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0.0) return "low";
  return "low";
}

// Compute a CVSS base score from a vector string. Implements the CVSS v3.0/v3.1
// base metric formula exactly; for v4.0 vectors (whose full formula is large) it
// uses a documented approximation from the exploitability/impact metrics that is
// faithful enough to pick the right band. Returns a number 0..10, or null if the
// vector is not a recognizable CVSS v3/v4 base vector.
function cvssBaseScore(vector) {
  const v = String(vector ?? "").trim().toUpperCase();
  if (/^CVSS:3\.[01]\//.test(v)) return cvss3BaseScore(v);
  if (/^CVSS:4\.0\//.test(v)) return cvss4ApproxScore(v);
  return null;
}

function cvssMetrics(vector) {
  const m = {};
  for (const part of vector.split("/")) {
    const [k, val] = part.split(":");
    if (k && val) m[k] = val;
  }
  return m;
}

// CVSS v3.1 base score (the v3.0 rounding difference does not change the band).
function cvss3BaseScore(vector) {
  const m = cvssMetrics(vector);
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const C = { H: 0.56, L: 0.22, N: 0.0 }[m.C];
  const I = { H: 0.56, L: 0.22, N: 0.0 }[m.I];
  const A = { H: 0.56, L: 0.22, N: 0.0 }[m.A];
  const scopeChanged = m.S === "C";
  // Privileges Required is scope-dependent.
  const prTable = scopeChanged ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };
  const PR = prTable[m.PR];
  if ([AV, AC, UI, C, I, A, PR].some((x) => x == null)) return null;

  const iscBase = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = scopeChanged
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;
  const exploitability = 8.22 * AV * AC * PR * UI;
  if (impact <= 0) return 0;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  // CVSS "roundup" to one decimal.
  return Math.ceil(raw * 10) / 10;
}

// CVSS v4.0 approximation: the official scoring is a large lookup table, but for
// BANDING purposes the impact (VC/VI/VA on the vulnerable system, SC/SI/SA on a
// subsequent system) and exploitability (AV/AC/AT/PR/UI) drive the result. We map
// the worst impact + attack feasibility to an approximate 0..10 score.
function cvss4ApproxScore(vector) {
  const m = cvssMetrics(vector);
  const impactVal = { H: 0.56, L: 0.22, N: 0.0 };
  const vc = impactVal[m.VC] ?? 0, vi = impactVal[m.VI] ?? 0, va = impactVal[m.VA] ?? 0;
  const sc = impactVal[m.SC] ?? 0, si = impactVal[m.SI] ?? 0, sa = impactVal[m.SA] ?? 0;
  const maxImpact = Math.max(vc, vi, va, sc, si, sa);
  if (maxImpact === 0) return 0;
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV] ?? 0.55;
  const AC = { L: 0.77, H: 0.44 }[m.AC] ?? 0.77;
  const AT = { N: 0.85, P: 0.62 }[m.AT] ?? 0.85;
  const PR = { N: 0.85, L: 0.62, H: 0.27 }[m.PR] ?? 0.85;
  const UI = { N: 0.85, P: 0.62, A: 0.62 }[m.UI] ?? 0.85;
  const isc = 1 - (1 - vc) * (1 - vi) * (1 - va) * (1 - sc) * (1 - si) * (1 - sa);
  const impact = 6.42 * isc;
  const exploitability = 8.22 * AV * AC * AT * PR * UI;
  return Math.ceil(Math.min(impact + exploitability, 10) * 10) / 10;
}

function parsePipAuditJson(stdout) {
  const json = JSON.parse(stdout);
  const out = [];
  // pip-audit emits either {dependencies:[…]} or a bare array depending on version.
  const deps = Array.isArray(json) ? json : arrayOf(json?.dependencies);
  for (const dep of deps) {
    const name = dep?.name ?? "";
    for (const v of arrayOf(dep?.vulns ?? dep?.vulnerabilities)) {
      out.push({
        id: v.id ?? v.aliases?.[0] ?? "",
        severity: mapSeverity(v.severity ?? "medium"),
        package: name,
        fixedVersion: arrayOf(v.fix_versions)[0] ?? null,
        source: "pip-audit",
      });
    }
  }
  return out;
}

function mapSeverity(s) {
  const v = String(s ?? "").toUpperCase();
  if (v.includes("CRIT")) return "critical";
  if (v.includes("HIGH")) return "high";
  if (v.includes("MED") || v.includes("MODERATE")) return "medium";
  if (v.includes("LOW")) return "low";
  return "medium";
}

// ── attestation integration helper ──────────────────────────────────────────

/**
 * Run the Tier-2 scanner and fold its result into an attestation via the sibling
 * attestation.mjs module, imported LAZILY so deps.mjs has no load-time dependency
 * on it (and so the selftest exercises pure functions without attestation present).
 * Never throws — returns the scan result augmented with an `attestation` field, or
 * the raw scan result with `attestationError` if attestation.mjs is unavailable.
 */
export async function attestDepsScan(resolvedSpecs, opts = {}) {
  const scan = await runVulnScanner(resolvedSpecs, opts);
  try {
    const att = await import("./attestation.mjs");
    // attestation.decideFromFindings expects a RECORD ({rawFindings, basis,
    // scanCoverage, …}) plus a policy — NOT a bare findings array. Building the
    // record correctly is what lets the coverage-aware "scanned-but-partial → don't
    // silent-allow" logic fire. Carry the scan's coverage through so an unavailable
    // / declared-only scan is not treated as a clean full scan.
    const record = {
      rawFindings: Array.isArray(scan.findings) ? scan.findings : [],
      // basis stays "scanned"; the HONESTY about whether the scan actually covered
      // the set is carried by scanCoverage, which decideFromFindings inspects so an
      // unavailable/partial scan with zero findings is reviewed, not silent-allowed.
      basis: "scanned",
      scanCoverage: scan.coverage ?? (scan.available ? "full" : "unavailable"),
      scanner: scan.scanner ?? null,
      dbVersion: scan.dbVersion ?? null,
    };
    const policy = opts.policy ?? null;
    if (typeof att.attestFromFindings === "function") {
      return { ...scan, attestation: att.attestFromFindings(record, policy) };
    }
    if (typeof att.decideFromFindings === "function") {
      return { ...scan, attestation: att.decideFromFindings(record, policy) };
    }
    return { ...scan, attestationError: "attestation.mjs is present but exposes no known attestation entry point." };
  } catch (e) {
    return { ...scan, attestationError: `attestation.mjs unavailable: ${String(e?.message ?? e)}` };
  }
}

// ── Pure helpers ─────────────────────────────────────────────────────────────

// Common ecosystem affixes that wrap a popular name in a typosquat: `python-requests`
// (prefix), `requests-py` (suffix), `node-fetch`/`fetch-js`. A name that is exactly a
// popular package plus one of these affixes is a high-confidence squat.
const SQUAT_AFFIXES = ["python", "py", "node", "js", "lib", "the", "real", "official", "pkg"];

// Names that are short and close to a popular package but are themselves REAL,
// widely-used packages — never flag these as squats. (Distinct from the popular
// list: these are the legitimate "near-miss" packages the squat heuristics would
// otherwise false-positive on.) Compared case-insensitively.
const LEGIT_NAMES = new Set([
  "request", "urllib", "click", "vuex", "vue", "vite", "next", "nuxt",
  "preact", "redux", "axios", "chalk", "debug", "rxjs", "uuid",
]);

// A name is "short" if raw edit-distance is too FP-prone to trust on its own.
const SHORT_NAME_LEN = 5;

// Strip PEP503-style separators so `cross-env`↔`crossenv` and `python-requests`
// compare structurally. Lowercased.
function deseparate(s) {
  return String(s ?? "").toLowerCase().replace(/[-_.]+/g, "");
}

// Bounded squat detection: returns {name, distance} of the nearest popular package
// this name is likely squatting, or null. Layers three heuristics so we catch
// affix/separator squats (which raw distance misses) WITHOUT false-positiving real
// short names:
//   1. self-exclusion: an exact popular match or a known-legit name is never a squat;
//   2. separator-swap / affix-wrap: structural squats reported regardless of length;
//   3. raw Damerau-Levenshtein ≤ maxDistance, but ONLY for names long enough that a
//      single edit is unlikely to be a coincidence (short names use 1+2 only).
function nearestPopular(name, popular, maxDistance) {
  if (!name) return null;
  const lower = String(name).toLowerCase();
  if (LEGIT_NAMES.has(lower)) return null; // a real package, not a squat
  for (const p of popular) {
    if (p === lower || p === name) return null; // exact = the real package
  }

  const nameDesep = deseparate(name);

  // (2a) Separator-swap: identical once separators are removed, but the raw forms
  // differ (`crossenv`↔`cross-env`, `node_fetch`↔`node-fetch`). Distance 1.
  for (const p of popular) {
    if (p === lower) continue;
    if (deseparate(p) === nameDesep) return { name: p, distance: 1 };
  }

  // (2b) Affix-wrap: the name is exactly a popular package (deseparated) plus a
  // known ecosystem affix on the front or back (`python-requests`, `lodash-js`).
  // Require the popular base to be ≥4 chars so we don't wrap a tiny base.
  for (const p of popular) {
    const pDesep = deseparate(p);
    if (pDesep.length < 4 || pDesep === nameDesep) continue;
    if (nameDesep.length <= pDesep.length) continue;
    let extra = null;
    if (nameDesep.startsWith(pDesep)) extra = nameDesep.slice(pDesep.length);
    else if (nameDesep.endsWith(pDesep)) extra = nameDesep.slice(0, nameDesep.length - pDesep.length);
    if (extra != null && SQUAT_AFFIXES.includes(extra)) return { name: p, distance: 2 };
  }

  // (3) Raw edit-distance — skipped for SHORT names (a single edit on a tiny name
  // is too often a coincidence: `vue`↔`vuex`, `request`↔`requests`).
  if (lower.length < SHORT_NAME_LEN) return null;
  let best = null;
  for (const p of popular) {
    // A transposition keeps length equal, so the length-difference prune must use
    // the same ceiling as the distance check (don't prune equal-length candidates).
    if (Math.abs(p.length - lower.length) > maxDistance) continue;
    const d = damerauLevenshtein(lower, p, maxDistance);
    if (d >= 1 && d <= maxDistance && (best == null || d < best.distance)) {
      best = { name: p, distance: d };
      if (d === 1) break;
    }
  }
  return best;
}

// Damerau-Levenshtein with an early-exit ceiling. Counts an ADJACENT TRANSPOSITION
// as a single edit — the canonical typosquat shape (`reqeusts`↔`requests`,
// `loadsh`↔`lodash`), which plain Levenshtein scores as 2. Returns ceiling+1 once
// the best possible distance for a row exceeds the ceiling, bounding the work.
function damerauLevenshtein(a, b, ceiling) {
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) > ceiling) return ceiling + 1;
  // Three rolling rows: prev2 (i-2), prev (i-1), curr (i).
  let prev2 = new Array(lb + 1).fill(0);
  let prev = new Array(lb + 1);
  let curr = new Array(lb + 1);
  for (let j = 0; j <= lb; j++) prev[j] = j;
  for (let i = 1; i <= la; i++) {
    curr[0] = i;
    let rowMin = curr[0];
    const ca = a.charCodeAt(i - 1);
    for (let j = 1; j <= lb; j++) {
      const cb = b.charCodeAt(j - 1);
      const cost = ca === cb ? 0 : 1;
      let v = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      // Adjacent transposition: a[i-1]==b[j-2] && a[i-2]==b[j-1].
      if (i > 1 && j > 1 && ca === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === cb) {
        v = Math.min(v, prev2[j - 2] + 1);
      }
      curr[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > ceiling) return ceiling + 1;
    const tmp = prev2; prev2 = prev; prev = curr; curr = tmp;
  }
  return prev[lb];
}

// A spec is "pinned" if it names an exact version. pypi: `==x.y` (and not a range
// like `>=`); npm: an exact `name@1.2.3` (not a range / caret / tilde / tag / url).
function isPinned(spec, ecosystem) {
  const s = String(spec.spec ?? "");
  if (ecosystem === "pypi") {
    return /==\s*[\w.!*+-]+/.test(s) && !/[<>~^]|!=/.test(s.replace(/!=.*/g, ""));
  }
  // npm: extract the range after the last (non-scope) '@'.
  const range = npmRange(s);
  if (!range) return false; // no version specified at all → unpinned
  if (/^(?:git|github:|file:|https?:|link:|workspace:)/i.test(range)) return false;
  return /^\d+\.\d+\.\d+(?:[-+][\w.]+)?$/.test(range.trim());
}

function npmRange(spec) {
  let s = spec;
  if (s.startsWith("@")) {
    const second = s.indexOf("@", 1);
    return second === -1 ? "" : s.slice(second + 1);
  }
  const a = s.indexOf("@");
  return a === -1 ? "" : s.slice(a + 1);
}

// Returns the kind of non-registry source, or null for a plain registry spec.
function nonRegistrySource(spec, ecosystem) {
  const s = String(spec ?? "");
  if (/(?:^|@|\s)git\+/i.test(s) || /\bgit\+(?:https?|ssh|file):/i.test(s)) return "git";
  if (/(?:^|@|\s)(?:github|gitlab|bitbucket):/i.test(s)) return "vcs-shorthand";
  if (/(?:^|@|\s)file:/i.test(s)) return "file";
  if (/(?:^|@|\s)link:/i.test(s)) return "link";
  if (/(?:^|@|\s)https?:\/\//i.test(s)) return "url";
  // pypi direct reference: `name @ /local/path` or `name @ url`
  if (ecosystem === "pypi" && /@\s*(?:\.?\/|[a-z]:\\)/i.test(s)) return "path";
  return null;
}

// ── Tiny dependency-free TOML helpers (array-of-strings extraction only) ──────

// Extract a `key = [ "a", "b" ]` string array from TOML text (handles multiline).
function parseTomlDependencyArray(text, key) {
  const re = new RegExp(`(?:^|\\n)\\s*${key}\\s*=\\s*\\[`, "");
  const m = re.exec(text);
  if (!m) return [];
  const start = text.indexOf("[", m.index);
  if (start === -1) return [];
  let depth = 0;
  let end = -1;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (c === "[") depth++;
    else if (c === "]") { depth--; if (depth === 0) { end = i; break; } }
  }
  if (end === -1) return [];
  return splitTomlArrayItems(text.slice(start + 1, end));
}

// Split the inside of a TOML array into quoted string items (ignores nested arrays).
function splitTomlArrayItems(body) {
  const items = [];
  for (const m of String(body).matchAll(/"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/g)) {
    const v = (m[1] ?? m[2] ?? "").trim();
    if (v) items.push(v);
    if (items.length > MAX_SPECS) break;
  }
  return items;
}

function matchTomlString(block, key) {
  const m = new RegExp(`(?:^|\\n)\\s*${key}\\s*=\\s*"([^"]*)"`, "").exec(block);
  return m ? m[1] : null;
}

function nextSectionIndex(text, from) {
  const m = /\n\s*\[/.exec(text.slice(from + 1));
  return m ? from + 1 + m.index : text.length;
}

// ── Low-level utilities ──────────────────────────────────────────────────────

// Loosely tokenize a shell segment into words, stripping matched quotes. Not a
// full shell parser — good enough to recover package tokens and flags.
function tokenizeCommand(segment) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  let count = 0;
  while ((m = re.exec(segment)) !== null) {
    if (++count > 4000) break;
    out.push(m[1] ?? m[2] ?? m[3]);
  }
  return out;
}

function safeJsonParse(text) {
  try { return JSON.parse(text); } catch { return null; }
}

function normName(name) {
  // Light cleanup for the DISPLAY name stored in `spec.name`: trim and strip
  // surrounding quotes. We deliberately do NOT collapse separators here so the
  // package shown to the operator matches what they typed. PEP 503 canonical-
  // ization for allow/deny COMPARISON lives in pep503Name (applied to both sides).
  return String(name).trim().replace(/^["']|["']$/g, "");
}

// PEP 503 canonical name for COMPARISON only: lowercase, and collapse any run of
// -, _, or . into a single -. So `evil_pkg`, `evil.pkg`, `evil--pkg`, `Evil-PKG`
// all normalize to `evil-pkg`. Applied to BOTH the spec name and the operator's
// allow/deny entries so a deny of `evil-pkg` also catches `evil_pkg`.
function pep503Name(name) {
  return String(name ?? "").trim().replace(/^["']|["']$/g, "").toLowerCase().replace(/[-_.]+/g, "-");
}

function truncate(s, n) {
  s = String(s ?? "");
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function pushAll(target, items) {
  if (Array.isArray(items)) for (const it of items) target.push(it);
}

function capSpecs(specs) {
  return specs.length > MAX_SPECS ? specs.slice(0, MAX_SPECS) : specs;
}

// Read a file synchronously with a byte cap; returns null on any failure (missing,
// permission, directory). Total — never throws.
function readBoundedSync(path) {
  if (!path) return null;
  try {
    const st = statSync(path);
    if (!st.isFile()) return null;
    if (st.size > MAX_MANIFEST_BYTES) {
      // Read only the first MAX_MANIFEST_BYTES so a huge file is bounded, not skipped.
      const fd = openSync(path, "r");
      try {
        const buf = Buffer.alloc(MAX_MANIFEST_BYTES);
        const n = readSync(fd, buf, 0, MAX_MANIFEST_BYTES, 0);
        return buf.toString("utf8", 0, n);
      } finally {
        closeSync(fd);
      }
    }
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function basename(p) {
  return String(p).replace(/\\/g, "/").split("/").pop() || String(p);
}

function joinPath(cwd, file) {
  const f = String(file ?? "");
  if (!f) return "";
  // Absolute path (posix or windows) → use as-is.
  if (f.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(f)) return f;
  if (!cwd) return f;
  const sep = String(cwd).includes("\\") ? "\\" : "/";
  return String(cwd).replace(/[\\/]$/, "") + sep + f;
}

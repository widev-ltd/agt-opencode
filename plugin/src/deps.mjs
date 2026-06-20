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
//     cheap, DETERMINISTIC metadata checks that cover risks a CVE scanner is blind
//     to: non-registry source, allow/deny list, index-URL guard (dependency
//     confusion), and npm install-script presence (install-time code execution).
//     No network, no subprocess — safe to call from the synchronous decision path.
//     It NEVER throws: malformed or huge input yields findings or an empty array.
//     (Typosquat name-matching, unpinned, and license-deny were removed — see the
//     note in scanOneSpec: FP-prone heuristic / lockfile's job / compliance-not-security.)
//
//   TIER 2 (async, audit-only): resolve the transitive set (from a lockfile when
//     present) and shell out to an installed vulnerability scanner (trivy /
//     osv-scanner / pip-audit, auto-detected). This spawns a subprocess and is
//     used ONLY by the proactive audit command, never at tool-call time. It
//     degrades gracefully: no scanner installed / timeout / unparseable output
//     → { available:false, findings:[], note } rather than an exception.
//
// THREAT MODEL (Tier-1 covers what the CVE scanner does NOT):
//   - Dependency confusion / unapproved index: `--index-url` / `--extra-index-url`
//     pointing at an attacker-controlled or simply unapproved registry.
//   - Install-time code execution: npm pre/post/install lifecycle scripts; a
//     python `setup.py` that contains code (not a static pyproject build).
//   - Non-registry sources: `git+https://…`, `file:`, a bare URL — code that
//     bypasses the registry's (weak) review entirely.
//   (Known CVEs in the transitive tree are Tier-2's job, delegated to the scanner.)
//
// POLICY INTEGRATION (mirrors compileDlpPolicy):
//   depsPolicies.mode = "advisory"  → findings surfaced as context, no deny
//   depsPolicies.mode = "enforce"   → severity ≥ threshold maps to deny/review
//
// The Tier-2 scanner result can be folded into an attestation by attestation.mjs;
// this module exposes a thin integration helper (attestDepsScan) that imports it
// lazily so deps.mjs has no hard dependency on attestation at load time.

import { statSync, openSync, readSync, closeSync, readFileSync, readdirSync, mkdtempSync, writeFileSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";

// Bound every file/command read so a hostile multi-GB manifest cannot exhaust
// memory or stall the sync decision path.
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024; // 2 MiB
const MAX_COMMAND_LENGTH = 64 * 1024; // 64 KiB
const MAX_SPECS = 5000; // cap the number of specs we will ever report on

// ── Policy compilation ───────────────────────────────────────────────────────

export function compileDepsPolicy(raw) {
  if (!raw || raw.enabled === false) {
    return null;
  }
  const mode = raw.mode === "enforce" ? "enforce" : "advisory";
  return {
    mode,
    severityThreshold: normalizeSeverity(raw.severityThreshold, "medium"),
    allow: dedupeLower(arrayOf(raw.allow)),
    deny: dedupeLower(arrayOf(raw.deny)),
    // Default registries are the canonical public ones; an operator REPLACES this
    // to lock to a private mirror. An empty allowedIndexes means "any index is OK"
    // (the index-URL guard then only flags clearly-unapproved when a list exists).
    allowedIndexes: arrayOf(raw.allowedIndexes).map((s) => String(s).toLowerCase()),
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
      // top-level string value. Map poetry constraint syntax to a PEP508-ish spec:
      // a bare exact version → `==x`; anything with a range operator (^ ~ > < * ,)
      // is preserved as-is (so the resolved spec carries the real constraint).
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

  // Non-registry source: git+, file:, bare URL, local path, direct-reference @ url.
  const nonReg = nonRegistrySource(spec.spec, ecosystem);
  if (nonReg) {
    out.push({ kind: "non-registry-source", severity: "high", package: spec.name,
      detail: `Dependency is fetched from a non-registry source (${nonReg}), bypassing index review: ${truncate(spec.spec, 120)}` });
  }

  // NOTE: typosquat (name-distance), unpinned, and license-deny checks were REMOVED
  // deliberately. Typosquat name-matching was an FP-prone bespoke heuristic that
  // reinvents (badly) what the scanner/registry ecosystem should own; unpinned is
  // the lockfile's job; license-deny is compliance, not security. The kept checks
  // below cover real risks a CVE scanner is blind to. See experiment/independent/RESULTS.md.

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
//
// COVERAGE VOCABULARY (the security contract — see SC-SECURITY-REMEDIATION.md):
//   "transitive"    — a resolver produced the FULL transitive tree AND a real
//                     scanner scanned it. ONLY this, with zero findings, may be a
//                     clean silent-allow.
//   "declared-only" — only the DECLARED set was scanned (no transitive expansion,
//                     e.g. a pre-existing lockfile we could only parse, or
//                     pip-audit -r over a requirements file). Not silent-allow.
//   "unavailable"   — nothing was reliably resolved+scanned (no resolver, no
//                     scanner, a resolver/scanner error, a timeout, a TLS failure,
//                     or an inline form we cannot resolve). The caller treats this
//                     as UNVERIFIED = UNSAFE. A zero-findings "unavailable" result
//                     is NEVER clean.
//
// THE INVARIANT: we NEVER report "transitive" for a set that was not actually
// resolved by a resolver AND scanned by a scanner. When in doubt → "unavailable".
//
// Resolvers (uv / npm) are spawned ONLY from this async proactive path, never on
// the synchronous runtime hot path, and every spawn is timeout-bounded and total
// (never throws). The runtime decision path stays scanner-/resolver-free.

// Resolver adapters. Each knows how to probe for the tool and, given the manifests
// reachable from `cwd`, run the resolver into a temp `scanDir` containing a file
// under the SCANNER-RECOGNIZED basename (trivy/osv detect pip by `requirements.txt`
// and npm by `package-lock.json`). `resolve(...)` returns
//   { ok:true, scanDir, method, note }  on a real transitive resolution, or
//   { ok:false, note }                  when it cannot resolve (→ caller fails safe).
// Never throws.
const RESOLVERS = [
  {
    name: "uv",
    ecosystem: "pypi",
    versionArgs: ["--version"],
    resolve: resolveWithUv,
  },
  {
    name: "npm",
    ecosystem: "npm",
    versionArgs: ["--version"],
    resolve: resolveWithNpm,
  },
];

// Detect which Python manifest (if any) we can hand to `uv export`. PEP 723 inline
// .py and requirements*/pyproject.toml are all resolvable; a pre-existing uv.lock
// also resolves. Returns { kind, path } or null.
function detectPythonManifest(cwd, manifests) {
  const candidates = Array.isArray(manifests) && manifests.length
    ? manifests
    : listManifestCandidates(cwd);
  // Prefer an inline PEP 723 script, then pyproject, then requirements, then lock.
  const byPriority = [
    (b) => b.endsWith(".py"),
    (b) => b === "pyproject.toml",
    (b) => isRequirementsTxtName(b),
    (b) => b === "uv.lock",
  ];
  for (const test of byPriority) {
    for (const p of candidates) {
      const base = basename(p).toLowerCase();
      if (!test(base)) continue;
      // A .py is only a Python manifest if it actually carries a PEP 723 block.
      if (base.endsWith(".py")) {
        const text = readBoundedSync(p);
        if (text == null || parsePep723(text).length === 0) continue;
      }
      return { kind: base.endsWith(".py") ? "pep723" : base, path: p };
    }
  }
  return null;
}

function detectNodeManifest(cwd, manifests) {
  const candidates = Array.isArray(manifests) && manifests.length
    ? manifests
    : listManifestCandidates(cwd);
  for (const p of candidates) {
    if (basename(p).toLowerCase() === "package.json") return { kind: "package.json", path: p };
  }
  return null;
}

// List manifest-ish files in cwd (non-recursive, bounded). Never throws.
function listManifestCandidates(cwd) {
  if (!cwd) return [];
  let entries;
  try {
    entries = readdirSync(cwd);
  } catch {
    return [];
  }
  const out = [];
  for (const name of entries) {
    if (out.length >= 256) break;
    const base = String(name).toLowerCase();
    if (
      base.endsWith(".py") ||
      base === "pyproject.toml" ||
      base === "uv.lock" ||
      base === "poetry.lock" ||
      base === "package.json" ||
      base === "package-lock.json" ||
      isRequirementsTxtName(base)
    ) {
      out.push(joinPath(cwd, name));
    }
  }
  return out;
}

// Run `uv export` to produce the pinned TRANSITIVE requirement set, written into a
// fresh temp dir as `requirements.txt` (the name trivy/osv use to detect pip deps).
// UV_SYSTEM_CERTS=1 lets uv trust this machine's TLS-intercepting CA. Returns
// { ok, scanDir, method, note } / { ok:false, note }. Never throws.
async function resolveWithUv(manifest, { cwd = "", timeoutMs = 120000 } = {}) {
  const env = { ...process.env, UV_SYSTEM_CERTS: "1" };
  const scanDir = makeScanDir();
  if (!scanDir) return { ok: false, note: "uv: a temp scan dir could not be created." };

  // Build the uv args and the cwd to run in. For a PROJECT manifest (pyproject.toml
  // / uv.lock), uv discovers the project by walking UP the directory tree — which,
  // for a manifest nested under another project, finds (and fails on) the WRONG
  // parent. We sidestep that by copying the project files into an ISOLATED dir (the
  // scanDir) with no parent project, exactly as the npm path isolates package.json.
  let args;
  let runCwd = cwd;
  if (manifest.kind === "pep723") {
    // Inline script: explicit --script path, no walk-up. No isolation needed.
    args = ["export", "--script", manifest.path, "--format", "requirements-txt", "--no-hashes", "--no-header"];
  } else if (isRequirementsTxtName(String(manifest.kind))) {
    // Bare requirements file: `uv pip compile <file>` resolves the transitive set
    // to stdout from the explicit path; no project walk-up.
    args = ["pip", "compile", manifest.path, "--no-header"];
  } else if (manifest.kind === "pyproject.toml" || manifest.kind === "uv.lock") {
    // Copy the project's pyproject.toml (+ a sibling uv.lock when present, so an
    // existing pin set is honored) into the isolated scanDir and resolve THERE.
    try {
      const srcDir = dirOf(manifest.path);
      const pyproj = joinPath(srcDir, "pyproject.toml");
      if (readBoundedSync(pyproj) != null) copyFileSync(pyproj, joinPath(scanDir, "pyproject.toml"));
      const lock = joinPath(srcDir, "uv.lock");
      if (readBoundedSync(lock) != null) copyFileSync(lock, joinPath(scanDir, "uv.lock"));
    } catch (e) {
      return { ok: false, note: `uv: copying project files into the scan dir failed: ${String(e?.message ?? e)}` };
    }
    args = ["export", "--format", "requirements-txt", "--no-hashes", "--no-header"];
    runCwd = scanDir; // resolve inside the isolated copy — no parent to discover
  } else {
    return { ok: false, note: `uv: unsupported manifest kind '${manifest.kind}'.` };
  }

  const run = await spawnCapture("uv", args, { cwd: runCwd, timeoutMs, env });
  if (run.spawnError) return { ok: false, note: `uv could not be spawned: ${truncate(run.stderr, 160)}` };
  if (run.timedOut) return { ok: false, note: `uv export timed out after ${timeoutMs} ms.` };
  if (run.code !== 0) return { ok: false, note: `uv export failed (exit ${run.code}): ${truncate(run.stderr, 200)}` };
  // The pinned requirement lines are on STDOUT ("Resolved N packages" goes to
  // stderr). An empty resolve (a manifest with no deps) is still a valid clean
  // transitive result — write an (empty) requirements.txt so the scanner sees it.
  const body = String(run.stdout ?? "");
  try {
    // requirements.txt is the basename trivy/osv use to detect pip deps. (For the
    // pyproject path the scanDir also holds the copied pyproject.toml/uv.lock, which
    // is fine — the resolved requirements.txt is what carries the transitive pins.)
    writeFileSync(joinPath(scanDir, "requirements.txt"), body);
  } catch (e) {
    return { ok: false, note: `uv resolved deps but writing requirements.txt failed: ${String(e?.message ?? e)}` };
  }
  return { ok: true, scanDir, method: "uv", note: `uv resolved transitive deps from ${manifest.kind}.` };
}

// Run `npm install --package-lock-only` to produce package-lock.json (the full
// resolved tree) in a temp dir holding a COPY of the package.json, then hand that
// dir to the scanner. NODE_OPTIONS=--use-system-ca trusts the machine's TLS CA.
// Returns { ok, scanDir, method, note } / { ok:false, note }. Never throws.
async function resolveWithNpm(manifest, { timeoutMs = 120000 } = {}) {
  const scanDir = makeScanDir();
  if (!scanDir) return { ok: false, note: "npm: a temp scan dir could not be created." };
  try {
    copyFileSync(manifest.path, joinPath(scanDir, "package.json"));
  } catch (e) {
    return { ok: false, note: `npm: copying package.json into the scan dir failed: ${String(e?.message ?? e)}` };
  }
  const env = { ...process.env, NODE_OPTIONS: appendNodeOption(process.env.NODE_OPTIONS, "--use-system-ca") };
  const run = await spawnCapture("npm", ["install", "--package-lock-only", "--no-audit", "--no-fund"], { cwd: scanDir, timeoutMs, env });
  if (run.spawnError) return { ok: false, note: `npm could not be spawned: ${truncate(run.stderr, 160)}` };
  if (run.timedOut) return { ok: false, note: `npm install --package-lock-only timed out after ${timeoutMs} ms.` };
  // npm exits non-zero on resolution errors; only treat a written lockfile as success.
  const lock = readBoundedSync(joinPath(scanDir, "package-lock.json"));
  if (lock == null) {
    return { ok: false, note: `npm did not produce a package-lock.json (exit ${run.code}): ${truncate(run.stderr, 200)}` };
  }
  return { ok: true, scanDir, method: "npm", note: "npm resolved the transitive tree into package-lock.json." };
}

// Append a flag to NODE_OPTIONS without clobbering an existing value or duplicating.
function appendNodeOption(existing, flag) {
  const cur = String(existing ?? "").trim();
  if (!cur) return flag;
  return cur.includes(flag) ? cur : `${cur} ${flag}`;
}

// Create a fresh temp dir for resolver output. Returns the path, or null on failure.
function makeScanDir() {
  try {
    return mkdtempSync(joinPath(tmpdir(), "agt-resolve-"));
  } catch {
    return null;
  }
}

function dirOf(p) {
  const s = String(p ?? "").replace(/[\\/]+[^\\/]*$/, "");
  return s || ".";
}

// Probe whether a resolver (uv/npm) is actually runnable. Mirrors probeScanner.
async function probeResolver(name, versionArgs) {
  const r = await spawnCapture(name, versionArgs, { timeoutMs: 10000 });
  return !r.timedOut && !r.spawnError && (r.code === 0 || /\d+\.\d+/.test(r.stdout) || /\d+\.\d+/.test(r.stderr));
}

/**
 * ACTUALLY resolve the transitive dependency set. Runs a real resolver (uv for
 * Python, npm for Node) into a temp `scanDir` that holds the resolved set under a
 * scanner-recognized basename, so a downstream scanner sees the FULL transitive
 * tree. The security contract is in the coverage value (see vocabulary above):
 *
 *   - A Python manifest (PEP 723 inline .py / requirements* / pyproject.toml /
 *     uv.lock) present AND uv runnable AND export succeeds
 *       → { coverage:"transitive", scanDir, method:"uv", resolved, fromLockfile }
 *   - Else a package.json present AND npm runnable AND lockfile produced
 *       → { coverage:"transitive", scanDir, method:"npm", resolved }
 *   - A pre-existing lockfile we can only PARSE (resolver missing) is the declared
 *     resolved set without a fresh transitive expansion → "declared-only".
 *   - No resolver / resolver error / nothing resolvable
 *       → { coverage:"unavailable" | "declared-only", resolved: declaredSpecs }.
 *     NEVER "transitive".
 *
 * NEVER throws. NEVER returns "transitive" without a resolver-produced scanDir.
 *
 * @param {object[]} specs   the DECLARED specs (fallback when resolution fails)
 * @param {{cwd?:string, manifests?:string[], timeoutMs?:number}} opts
 * @returns {Promise<{resolved:object[], coverage:'transitive'|'declared-only'|'unavailable',
 *   scanDir:string|null, method:string|null, fromLockfile:boolean, note?:string}>}
 */
export async function resolveTransitive(specs, { cwd = "", manifests = null, timeoutMs = 120000 } = {}) {
  const declared = Array.isArray(specs) ? specs.slice(0, MAX_SPECS) : [];
  try {
    // Resolve Python first (uv), then Node (npm). The first resolver with a usable
    // manifest AND a runnable tool AND a successful resolve wins.
    const pyManifest = detectPythonManifest(cwd, manifests);
    if (pyManifest && await probeResolver("uv", ["--version"])) {
      const r = await resolveWithUv(pyManifest, { cwd, timeoutMs });
      if (r.ok) {
        const resolved = parseManifestFile(joinPath(r.scanDir, "requirements.txt"));
        return { resolved: resolved.length ? resolved : declared, coverage: "transitive",
          scanDir: r.scanDir, method: "uv", fromLockfile: true, note: r.note };
      }
      // uv present but resolve failed → fall through; a Node manifest may resolve,
      // otherwise we fail safe below (never claim transitive for the Python set).
      var pyNote = r.note;
    }

    const nodeManifest = detectNodeManifest(cwd, manifests);
    if (nodeManifest && await probeResolver("npm", ["--version"])) {
      const r = await resolveWithNpm(nodeManifest, { timeoutMs });
      if (r.ok) {
        const resolved = parseManifestFile(joinPath(r.scanDir, "package-lock.json"));
        return { resolved: resolved.length ? resolved : declared, coverage: "transitive",
          scanDir: r.scanDir, method: "npm", fromLockfile: true, note: r.note };
      }
      var nodeNote = r.note;
    }

    // No resolver produced a transitive tree. If a manifest exists but resolution
    // could not happen (no tool, or the resolver errored), this is UNAVAILABLE — we
    // must NOT silently downgrade to a confident "declared-only" clean. The only
    // "declared-only" case is a PRE-EXISTING lockfile we can parse (the declared set
    // there IS the resolved tree, just not freshly re-resolved).
    const haveManifest = !!(pyManifest || nodeManifest);
    const preLock = findParseableLockfile(cwd, manifests);
    if (preLock) {
      const resolved = parseManifestFile(preLock);
      if (resolved.length) {
        return { resolved, coverage: "declared-only", scanDir: null, method: "lockfile-parse",
          fromLockfile: true, note: `Parsed pre-existing ${basename(preLock)}; no resolver available to re-resolve, so coverage is declared-only (the lockfile's set was not freshly scanned in-tree).` };
      }
    }

    const note = haveManifest
      ? `A resolvable manifest was present but transitive resolution could not run (${pyNote || nodeNote || "no resolver (uv/npm) on PATH"}). Coverage is unavailable; the dependency set was NOT verified.`
      : "No resolvable manifest and no resolver available; coverage unavailable.";
    return { resolved: declared, coverage: "unavailable", scanDir: null, method: null, fromLockfile: false, note };
  } catch (e) {
    // Total: any unexpected failure fails SAFE to unavailable, never transitive.
    return { resolved: declared, coverage: "unavailable", scanDir: null, method: null, fromLockfile: false,
      note: `Transitive resolution errored: ${String(e?.message ?? e)}` };
  }
}

// Find a pre-existing lockfile we can PARSE (used only for the declared-only
// fallback when no resolver is available). Returns its path or null.
function findParseableLockfile(cwd, manifests) {
  const candidates = Array.isArray(manifests) && manifests.length ? manifests : listManifestCandidates(cwd);
  for (const lf of ["uv.lock", "poetry.lock", "package-lock.json"]) {
    for (const p of candidates) {
      if (basename(p).toLowerCase() === lf && readBoundedSync(p) != null) return p;
    }
  }
  return null;
}

// Scanner adapters in detection order: each knows how to probe, build args, and
// parse its JSON into a common rawFindings shape. `buildArgs(scanDir)` scans the
// directory resolveTransitive populated (it holds the resolver-written
// requirements.txt / package-lock.json). It may return null to mean "I have no
// input to scan here" (e.g. pip-audit with no requirements file) — runVulnScanner
// then degrades to coverage:'unavailable' rather than scanning the wrong thing.
const SCANNERS = [
  {
    name: "trivy",
    versionArgs: ["--version"],
    buildArgs: (scanDir) => ["fs", "--scanners", "vuln", "--format", "json", "--quiet", scanDir || "."],
    parse: parseTrivyJson,
  },
  {
    name: "osv-scanner",
    versionArgs: ["--version"],
    buildArgs: (scanDir) => ["--format", "json", "--recursive", scanDir || "."],
    parse: parseOsvJson,
  },
  {
    name: "pip-audit",
    versionArgs: ["--version"],
    // pip-audit with NO target audits the AMBIENT environment (wrong, and often
    // empty/misleading). Always scan the requirements/constraints files present in
    // the scan dir via `-r`; if there are none (e.g. a Node lockfile dir), return
    // null so the scan is reported unavailable instead of auditing the host.
    buildArgs: (scanDir) => {
      const reqs = findRequirementsFiles(scanDir);
      if (reqs.length === 0) return null;
      const args = ["--format", "json", "--progress-spinner", "off"];
      for (const f of reqs) { args.push("-r", f); }
      return args;
    },
    parse: parsePipAuditJson,
  },
];

// List requirements/constraints files in a directory (non-recursive, bounded).
// Returns paths suitable for `pip-audit -r`. Never throws.
function findRequirementsFiles(dir) {
  if (!dir) return [];
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  const out = [];
  for (const name of entries) {
    if (out.length >= 64) break;
    if (isRequirementsTxtName(String(name).toLowerCase())) out.push(joinPath(dir, name));
  }
  return out;
}

/**
 * Auto-detect an installed scanner (trivy → osv-scanner → pip-audit), run it over
 * the `scanDir` that resolveTransitive produced, and parse its output. NEVER throws.
 *
 * Coverage is threaded HONESTLY from resolution: the scan can only ever be as good
 * as what was resolved. `coverage` (from resolveTransitive — "transitive" or
 * "declared-only") is the CEILING; any failure to actually scan (no scanner,
 * timeout, unparseable output, no scannable input, missing scanDir) drops it to
 * "unavailable". We NEVER report "transitive" for a set a scanner did not scan.
 *
 * @param {object[]} resolvedSpecs  the resolved set (for the caller's record only)
 * @param {{scanDir?:string|null, coverage?:string, scannerCmd?:string|null,
 *   timeoutMs?:number, cwd?:string}} opts
 *   - scanDir: the resolver-populated dir to scan. If absent, falls back to cwd
 *     (legacy behavior) but coverage is forced to "unavailable" unless a real
 *     resolved scanDir was supplied — a bare cwd scan is not a transitive guarantee.
 *   - coverage: the resolution coverage ceiling ("transitive"|"declared-only").
 * @returns {Promise<{available:boolean, scanner?:string, coverage:string,
 *   dbVersion:string|null, findings:object[], note?:string}>}
 */
export async function runVulnScanner(resolvedSpecs, { scanDir = null, coverage = null, cwd = "", scannerCmd = null, timeoutMs = 120000 } = {}) {
  // The directory we hand the scanner. A resolver-produced scanDir is authoritative;
  // a bare cwd (legacy callers) can be scanned but can NEVER be claimed transitive.
  const target = scanDir || cwd || "";
  // The honest ceiling: only a real resolver scanDir may carry a "transitive"/
  // "declared-only" ceiling; anything else is capped at "unavailable".
  const ceiling = scanDir
    ? (coverage === "transitive" || coverage === "declared-only" ? coverage : "declared-only")
    : "unavailable";

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

  const args = chosen.buildArgs(target);
  if (args == null) {
    // The scanner has nothing to scan here (e.g. pip-audit pointed at a Node
    // lockfile dir) — report unavailable rather than scanning the wrong target.
    return { available: false, scanner: chosen.name, coverage: "unavailable", dbVersion: null, findings: [],
      note: `${chosen.name} has no scannable input in the resolved dir; skipping rather than auditing the wrong target (coverage unavailable).` };
  }

  const run = await spawnCapture(chosen.name, args, { cwd: target, timeoutMs });
  if (run.timedOut) {
    return { available: false, scanner: chosen.name, coverage: "unavailable", dbVersion: null, findings: [],
      note: `${chosen.name} timed out after ${timeoutMs} ms (coverage unavailable).` };
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
      note: `${chosen.name} produced output that could not be parsed as JSON findings (coverage unavailable).` };
  }
  // The scan ran and parsed: coverage is the resolution ceiling (a real resolved
  // scanDir → "transitive"/"declared-only"; a bare cwd → "unavailable").
  const db = await scannerDbVersion(chosen.name);
  return { available: true, scanner: chosen.name, coverage: ceiling, dbVersion: db ? db.version : null, findings };
}

/**
 * The clean entry point the proactive audit calls: resolve the transitive set and
 * scan it in one step, returning an honest coverage verdict. NEVER throws.
 *
 * Coverage is the SECURITY CONTRACT:
 *   - "transitive"    → resolver produced the full tree AND a scanner scanned it.
 *                       Only this, with zero findings, may be a clean silent-allow.
 *   - "declared-only" → only the declared set was scanned (pre-existing lockfile we
 *                       could parse, no fresh resolve). Not silent-allow.
 *   - "unavailable"   → no resolver / no scanner / resolver or scanner error /
 *                       timeout / nothing resolvable. Treated as UNVERIFIED=UNSAFE;
 *                       a zero-findings "unavailable" is NEVER clean.
 *
 * @param {{cwd?:string, manifests?:string[], specs?:object[], scannerCmd?:string|null,
 *   timeoutMs?:number}} opts
 * @returns {Promise<{available:boolean, scanner:string|null, findings:object[],
 *   coverage:string, dbVersion:string|null, method:string|null, note:string}>}
 */
export async function resolveAndScan({ cwd = "", manifests = null, specs = null, scannerCmd = null, timeoutMs = 120000 } = {}) {
  try {
    const res = await resolveTransitive(specs ?? [], { cwd, manifests, timeoutMs });
    // Resolution itself failed to produce a transitive tree. If we have a declared-
    // only lockfile we CAN still scan it (declared-only); otherwise unavailable.
    if (res.coverage === "unavailable" && !res.scanDir) {
      return { available: false, scanner: null, findings: [], coverage: "unavailable",
        dbVersion: null, method: res.method ?? null, note: res.note ?? "Transitive resolution unavailable." };
    }
    // "declared-only" with no scanDir means we only parsed a pre-existing lockfile
    // and have no in-tree dir to hand a scanner — we cannot freshly scan it here, so
    // it stays declared-only with no scanner findings claimed (NOT a clean stamp).
    if (!res.scanDir) {
      return { available: false, scanner: null, findings: [], coverage: res.coverage,
        dbVersion: null, method: res.method ?? null,
        note: res.note ?? "No in-tree scan dir; declared-only without a fresh scan." };
    }
    const scan = await runVulnScanner(res.resolved, {
      scanDir: res.scanDir, coverage: res.coverage, scannerCmd, timeoutMs,
    });
    return {
      available: scan.available,
      scanner: scan.scanner ?? null,
      findings: Array.isArray(scan.findings) ? scan.findings : [],
      coverage: scan.coverage,
      dbVersion: scan.dbVersion ?? null,
      method: res.method ?? null,
      note: scan.available ? (res.note ?? "") : (scan.note ?? res.note ?? ""),
    };
  } catch (e) {
    // Total fail-safe.
    return { available: false, scanner: null, findings: [], coverage: "unavailable",
      dbVersion: null, method: null, note: `resolveAndScan errored: ${String(e?.message ?? e)}` };
  }
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
async function spawnCapture(cmd, args, { cwd = "", timeoutMs = 120000, env = null } = {}) {
  const { spawn } = await import("node:child_process");
  // On Windows the resolvers/scanners on PATH are frequently .cmd shims (npm) or
  // bare names; spawning them with shell:false fails (ENOENT for `npm`, EINVAL for
  // `npm.cmd` since Node's CVE-2024-27980 fix blocks .cmd/.bat without a shell). We
  // do NOT use shell:true (it would not quote args and invites injection from a
  // manifest path). Instead route every command through `cmd.exe /d /s /c CMD ...`:
  // Node still quotes each arg individually (windowsVerbatimArguments is false), so
  // a path with spaces or metacharacters is passed literally, and both .exe tools
  // (uv/trivy/osv-scanner) and .cmd shims (npm) resolve uniformly.
  let runCmd = cmd;
  let runArgs = args;
  if (process.platform === "win32") {
    const comspec = process.env.ComSpec || process.env.COMSPEC || "cmd.exe";
    runCmd = comspec;
    runArgs = ["/d", "/s", "/c", cmd, ...args];
  }
  return await new Promise((resolve) => {
    let child;
    try {
      child = spawn(runCmd, runArgs, { cwd: cwd || undefined, shell: false, windowsHide: true, env: env || undefined });
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
  // Resolve + scan via the honest one-step entry so the attestation carries the
  // REAL coverage (transitive / declared-only / unavailable) rather than assuming
  // a bare scan covered the transitive tree.
  const scan = await resolveAndScan({
    cwd: opts.cwd ?? "",
    manifests: opts.manifests ?? null,
    specs: Array.isArray(resolvedSpecs) ? resolvedSpecs : (opts.specs ?? null),
    scannerCmd: opts.scannerCmd ?? null,
    timeoutMs: opts.timeoutMs ?? 120000,
  });
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
      // Coverage vocabulary is transitive | declared-only | unavailable. Never
      // synthesize a clean "full" — an absent coverage means we did NOT verify.
      scanCoverage: scan.coverage ?? "unavailable",
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

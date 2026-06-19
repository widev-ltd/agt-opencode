// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// skills.mjs — skill (Agent Skill / SKILL.md + scripts) governance scanner for
// the AGT governance plugin's supply-chain gate.
//
// WHY THIS EXISTS:
//   A "skill" is attacker-reachable code + model-facing prose that the agent
//   loads and may execute. Three distinct trust boundaries cross here:
//     1. The skill's SCRIPTS run with the agent's privileges (a poisoned skill
//        can `curl|sh`, exfiltrate secrets, or overwrite ~/.bashrc).
//     2. The skill's SKILL.md is injected into the MODEL's context — prose, not
//        code, so the threat is prompt INJECTION, not execution.
//     3. The skill arrives from some SOURCE (a marketplace, a repo) whose trust
//        the operator may want to gate.
//   This module scans all three and produces:
//     - a stable INTEGRITY manifest (fileHashes) for attestation.mjs, and
//     - a CAPABILITY PROFILE (what the scripts can do) checked against policy.
//
// LAYERS (each independent; a failure in one never blinds the others):
//   INTEGRITY  — sha256 the WHOLE content of every file → fileHashes (feeds
//                skillIntegrityKey). A symlink to an in-tree regular file is
//                hashed via its target; an external/unresolvable link is NOT
//                followed but recorded as a distinct sentinel so the key is never
//                empty and never shared across different skills.
//   DANGEROUS  — ReDoS-safe regex set over script bodies (curl|sh, eval, rc-file
//                writes, rm -rf, base64-decode-and-exec, …).
//   SECRETS    — reuse dlp.mjs scanForDlp over every file (credential VALUES
//                checked into a skill).
//   INJECTION  — model-facing prompt-injection scan over SKILL.md only.
//   CAPABILITY — static analysis of scripts → {network, fsWriteOutsideCwd,
//                subprocess, secretFileRead}; flagged where it exceeds policy.
//   SOURCE     — origin checked against the policy allowedSources allowlist.
//
// SAFETY (mirrors dlp.mjs / content-safety.mjs):
//   - Detectors NEVER throw — they return findings[] (or [] on any error).
//   - All regexes are ReDoS-safe: bounded quantifiers, no nested/overlapping
//     repetition. Integrity hashes the WHOLE file (chunked, capped at
//     MAX_HASH_BYTES; oversize → size folded into the digest); body scanning
//     reads the WHOLE file capped at MAX_SCAN_BYTES (oversize → flagged); the
//     walk is entry-bounded (MAX_FILES) + depth-bounded so a hostile skill tree
//     cannot hang or OOM the host. Symlinks are never followed out of the tree.
//   - The runtime trigger detector (checkSkillInvocationMeta) is SYNC and pure;
//     the heavier capability/static analysis (scanSkill) is async (it does I/O).

import { createHash } from "node:crypto";
import { open, readdir, readlink, realpath, stat } from "node:fs/promises";
import {
  closeSync, openSync, readdirSync, readlinkSync, readSync,
  realpathSync, statSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { compileDlpPolicy, scanForDlp } from "./dlp.mjs";

// ── Bounds (defense against a hostile skill tree) ────────────────────────────
// INTEGRITY must hash the WHOLE file (S2): a head-only hash let an attacker swap
// bytes past the window after approval and keep the same integrity key. We hash
// in chunks up to a high per-file cap; a file larger than the cap has its full
// SIZE folded into the digest (so any size change still alters the hash) and is
// marked oversize so the change is never silently invisible.
const HASH_CHUNK_BYTES = 1024 * 1024;          // streamed read granularity
const MAX_HASH_BYTES = 64 * 1024 * 1024;       // per-file content-hash cap (64 MiB)
// BODY SCAN must cover the WHOLE file (S3): a 256KB head-only scan let a payload
// at a larger offset stay invisible. We scan in overlapping chunks up to a high
// cap; a file larger than the cap is flagged oversize-unscanned for the tail.
const MAX_SCAN_BYTES = 16 * 1024 * 1024;       // per-file body-scan cap (16 MiB)
const SCAN_CHUNK_BYTES = 1024 * 1024;          // scan chunk size
const SCAN_CHUNK_OVERLAP = 512;                // carry-over so a pattern straddling a chunk boundary still matches
const MAX_FILES = 500;                          // entry cap across the whole walk
const MAX_DEPTH = 8;                            // directory-recursion depth cap
// Symlink target strings we hash for the sentinel entry are bounded so a
// pathological link value cannot drive expensive hashing.
const MAX_SYMLINK_TARGET_LEN = 4096;

// Script-like extensions whose BODIES we statically analyse (dangerous patterns
// + capability profile). Other files are still hashed (integrity) and DLP-scanned
// (secrets), but body/capability analysis targets executable content.
const SCRIPT_EXTENSIONS = new Set([
  ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd",
  ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php",
]);

const SKILL_MANIFEST_NAMES = new Set(["skill.md", "skill.yaml", "skill.yml", "skill.json"]);

// ── Dangerous script patterns (ReDoS-safe; bounded quantifiers only) ─────────
// Each: { id, severity, source, flags }. Severity drives the finding only — the
// gate decision is recomputed downstream (attestation.decideFromFindings).
export const SKILL_DANGEROUS_PATTERNS = [
  {
    id: "curl-pipe-shell",
    severity: "critical",
    // curl/wget … | sh|bash  — the classic remote-code-execution one-liner.
    source: "\\b(?:curl|wget|fetch)\\b[^\\n|]{0,200}\\|[^\\n]{0,40}\\b(?:sh|bash|zsh|python[0-9.]{0,4}|node|ruby|perl)\\b",
    flags: "i",
  },
  {
    id: "base64-decode-exec",
    severity: "critical",
    // base64 -d … | sh  /  echo <b64> | base64 -d | bash  — obfuscated RCE.
    source: "\\bbase64\\b[^\\n]{0,80}(?:-d|--decode)[^\\n]{0,80}\\|[^\\n]{0,40}\\b(?:sh|bash|zsh|python[0-9.]{0,4}|node)\\b",
    flags: "i",
  },
  {
    id: "eval-decoded",
    severity: "high",
    // eval/exec of a decoded/fetched payload (atob, fromCharCode, base64.b64decode).
    source: "\\b(?:eval|exec)\\s*\\(\\s*(?:atob|base64\\.b64decode|Buffer\\.from|String\\.fromCharCode)\\b",
    flags: "i",
  },
  {
    id: "shell-rc-write",
    severity: "high",
    // Appending/redirecting into a shell rc / profile — persistence backdoor.
    source: ">>?[^\\n]{0,40}(?:~|\\$HOME|/home/[^\\n/]{1,40}|/root)[^\\n]{0,40}/\\.(?:bashrc|zshrc|bash_profile|profile|zprofile|bash_login)\\b",
    flags: "i",
  },
  {
    id: "ssh-authorized-keys-write",
    severity: "critical",
    // Writing to authorized_keys — installs an attacker SSH key.
    source: ">>?[^\\n]{0,80}\\.ssh/authorized_keys\\b",
    flags: "i",
  },
  {
    id: "crontab-install",
    severity: "high",
    // crontab install / cron.d drop — scheduled-task persistence.
    source: "\\bcrontab\\b[^\\n]{0,40}-[^\\n]{0,4}\\b|/etc/cron\\.[a-z]{1,8}/",
    flags: "i",
  },
  {
    id: "rm-rf-dangerous",
    severity: "high",
    // rm -rf on a root-ish / home target (not a local build dir).
    source: "\\brm\\s+-[a-z]{0,4}r[a-z]{0,4}f[a-z]{0,4}\\s+(?:-[a-z]{1,12}\\s+)?(?:/|~|\\$HOME)(?:\\s|/|$)",
    flags: "i",
  },
  {
    id: "history-tamper",
    severity: "medium",
    // Disabling / clearing shell history — anti-forensics.
    source: "\\b(?:unset\\s+HISTFILE|HISTFILE=/dev/null|history\\s+-c|set\\s+\\+o\\s+history)\\b",
    flags: "i",
  },
  {
    id: "iptables-firewall-disable",
    severity: "medium",
    // Flushing the firewall / disabling defenses.
    source: "\\biptables\\b[^\\n]{0,40}\\b(?:-F|--flush)\\b|\\bsetenforce\\s+0\\b|\\bsystemctl\\s+stop\\s+(?:firewalld|ufw)\\b",
    flags: "i",
  },
  {
    id: "powershell-iex-download",
    severity: "critical",
    // PowerShell remote-code-execution: IEX/Invoke-Expression of a DownloadString,
    // or piping a downloaded string into IEX. The classic Windows curl|sh analogue.
    source: "\\b(?:iex|invoke-expression)\\b[^\\n]{0,120}(?:downloadstring|invoke-(?:web)?request|iwr|curl|wget)\\b|(?:downloadstring|invoke-(?:web)?request|iwr)\\b[^\\n|]{0,120}\\|[^\\n]{0,40}\\b(?:iex|invoke-expression)\\b",
    flags: "i",
  },
  {
    id: "powershell-encoded-command",
    severity: "critical",
    // powershell -enc <base64> / -EncodedCommand — obfuscated PowerShell payload.
    source: "\\bpowershell(?:\\.exe)?\\b[^\\n]{0,80}(?:-enc(?:odedcommand)?|-e)\\s+[A-Za-z0-9+/]{16,}={0,2}",
    flags: "i",
  },
  {
    id: "powershell-webclient-download",
    severity: "high",
    // (New-Object Net.WebClient).DownloadString/DownloadFile — fetch stage.
    source: "new-object\\s+(?:system\\.)?net\\.webclient\\b[^\\n]{0,80}\\.download(?:string|file|data)\\b",
    flags: "i",
  },
  {
    id: "reverse-shell-dev-tcp",
    severity: "critical",
    // bash /dev/tcp reverse shell: redirecting a shell to a TCP socket.
    source: "/dev/(?:tcp|udp)/[^\\s/]{1,80}/[0-9]{1,5}\\b",
    flags: "i",
  },
  {
    id: "reverse-shell-nc-exec",
    severity: "critical",
    // netcat/ncat with -e/-c (or the BusyBox -e) wiring a shell to a socket.
    source: "\\b(?:nc|ncat|netcat)\\b[^\\n]{0,80}\\s-(?:e|c)\\s+(?:/[^\\s]{0,40}/)?(?:sh|bash|cmd(?:\\.exe)?|powershell)\\b",
    flags: "i",
  },
  {
    id: "interpreter-indirection-pipe",
    severity: "high",
    // curl/wget … | $VAR  (or | "$INTERP") — the shell run via an indirected
    // interpreter name to dodge a literal `| sh` match.
    source: "\\b(?:curl|wget|fetch)\\b[^\\n|]{0,200}\\|[^\\n]{0,20}\"?\\$\\{?[A-Za-z_][A-Za-z0-9_]{0,40}\\}?",
    flags: "i",
  },
  {
    id: "two-step-download-exec",
    severity: "high",
    // Stage then run: curl/wget -o x.sh … then ./x.sh / sh x.sh later in the file.
    // Two bounded sub-patterns combined; the alternation keeps each linear.
    source: "\\b(?:curl|wget)\\b[^\\n]{0,160}\\s-[oO]\\s*[^\\s]{1,80}\\.(?:sh|bash|py|ps1)\\b|\\b(?:sh|bash|source|\\.)\\s+[^\\s]{1,80}\\.(?:sh|bash)\\b|(?:^|[\\s;&])\\./[^\\s]{1,80}\\.(?:sh|bash|py)\\b",
    flags: "im",
  },
  {
    id: "tee-rc-or-authorized-keys",
    severity: "high",
    // tee -a into a shell rc / profile or into authorized_keys — persistence via
    // tee rather than a >> redirect (which shell-rc-write/ssh-authorized-keys catch).
    source: "\\btee\\b[^\\n]{0,40}(?:-a|--append)?[^\\n]{0,40}(?:(?:~|\\$HOME|/home/[^\\n/]{1,40}|/root)[^\\n]{0,40}/\\.(?:bashrc|zshrc|bash_profile|profile|zprofile|bash_login)\\b|\\.ssh/authorized_keys\\b)",
    flags: "i",
  },
  {
    id: "eval-var-after-base64-decode",
    severity: "high",
    // base64 -d … then (within a bounded gap) eval "$var" — split decode-then-exec
    // the single-line base64-decode-exec pattern misses. Bounded [^\\0]{0,400} gap
    // keeps it linear; requiring the base64 decode first avoids the eval-FP storm.
    source: "\\bbase64\\b[^\\n]{0,40}(?:-d|--decode)\\b[^\\0]{0,400}?\\beval\\b\\s{0,4}\"?\\$\\{?[A-Za-z_][A-Za-z0-9_]{0,40}\\}?",
    flags: "i",
  },
  {
    id: "crontab-stdin-install",
    severity: "high",
    // echo '<job>' | crontab -  — install a cron job from stdin (persistence).
    source: "\\|\\s{0,4}crontab\\s+-(?:\\s|$)",
    flags: "im",
  },
];

// ── SKILL.md prompt-injection patterns (model-facing prose; ReDoS-safe) ──────
// Mirrors the content-safety jailbreak frame but tuned for instructions a skill
// author might smuggle into the model-facing SKILL.md to subvert governance.
export const SKILL_INJECTION_PATTERNS = [
  {
    id: "ignore-previous-instructions",
    severity: "high",
    source: "\\b(?:ignore|disregard|forget|override)\\b[^\\n]{0,40}\\b(?:previous|prior|above|earlier|all)\\b[^\\n]{0,30}\\b(?:instructions?|prompts?|rules?|context|guidelines?)\\b",
    flags: "i",
  },
  {
    id: "reveal-system-prompt",
    severity: "high",
    source: "\\b(?:reveal|print|show|repeat|output|disclose|leak)\\b[^\\n]{0,40}\\b(?:system|developer|hidden)\\b[^\\n]{0,20}\\b(?:prompt|instructions?|message|rules?)\\b",
    flags: "i",
  },
  {
    id: "exfiltrate-secrets",
    severity: "critical",
    source: "\\b(?:send|post|upload|exfiltrate|transmit|email|curl)\\b[^\\n]{0,60}\\b(?:secret|token|api[\\s_-]?key|password|credential|env(?:ironment)?\\s+var)\\b",
    flags: "i",
  },
  {
    id: "disable-governance",
    severity: "high",
    // Tightened to an INSTRUCTION-TO-THE-ASSISTANT shape (item 9 FP fix): a benign
    // SKILL.md describing a security tool ("review code to disable insecure
    // defaults") must not trip. Require a directive frame — an imperative
    // "you (must/should/can)" / "please" / "do/don't" / "no need to" / "always" /
    // "instead of" — immediately before the disable-the-control verb phrase.
    source: "\\b(?:you\\s+(?:must|should|can|may|are\\s+to)|please|do\\s+not|don't|dont|no\\s+need\\s+to|there'?s\\s+no\\s+need\\s+to|always|never|simply|just|instead(?:\\s+of)?)\\b[^\\n]{0,30}\\b(?:disable|bypass|turn\\s+off|skip|ignore|circumvent|suppress)\\b[^\\n]{0,40}\\b(?:governance|safety|guardrails?|policy|policies|security|approvals?|reviews?|gate)\\b",
    flags: "i",
  },
  {
    id: "act-as-unrestricted",
    severity: "high",
    source: "\\b(?:act\\s+as|pretend(?:\\s+to\\s+be)?|you\\s+are\\s+now|roleplay\\s+as)\\b[^\\n]{0,40}\\b(?:uncensored|unfiltered|unrestricted|jailbroken|DAN|evil|developer\\s+mode)\\b",
    flags: "i",
  },
  {
    id: "hidden-instruction-marker",
    severity: "medium",
    // Markers an author uses to hide an instruction from a human reviewer but
    // not the model ("[[SYSTEM]]", "<!-- AI: ... -->", "###INSTRUCTION###").
    source: "(?:\\[\\[\\s*system\\s*\\]\\]|<!--\\s*(?:ai|assistant|system)\\b|#{2,}\\s*(?:instruction|system|prompt)\\b)",
    flags: "i",
  },
];

// ── Skill-specific secret patterns (supplement dlp.mjs reuse; ReDoS-safe) ────
// The shared DLP scanner (dlp.mjs) catches AWS / GitHub / private-key material
// but MISSES some high-value provider tokens (item 7). We scan these over every
// file IN ADDITION to scanForDlp. Split/concatenated tokens (e.g. "xox" + "b-…")
// are a known RESIDUAL — not chased here (string-built secrets are intractable
// for a static regex without a constant-folding pass).
export const SKILL_SECRET_PATTERNS = [
  {
    id: "slack-token",
    severity: "high",
    // Slack bot/user/app/refresh tokens: xoxb- / xoxa- / xoxp- / xoxr- / xoxs-.
    source: "\\bxox[baprs]-[A-Za-z0-9-]{10,200}",
    flags: "",
    reason: "Slack API token in a skill file. Treat as a credential leak; do not commit or transmit this value.",
  },
  {
    id: "stripe-secret-key",
    severity: "high",
    // Stripe LIVE secret / restricted keys: sk_live_… / rk_live_…
    source: "\\b[sr]k_live_[A-Za-z0-9]{16,200}",
    flags: "",
    reason: "Stripe live secret key in a skill file. Treat as a credential leak; do not commit or transmit this value.",
  },
];

// ── Capability static-analysis signatures (ReDoS-safe) ───────────────────────
// Each dimension is a list of bounded regexes. A match SETS that capability bit;
// the bit is then compared against the policy's capabilityProfile budget.
export const CAPABILITY_SIGNATURES = {
  network: [
    { source: "\\b(?:curl|wget|fetch|nc|netcat|ncat|telnet)\\b", flags: "i" },
    { source: "\\b(?:requests\\.(?:get|post|put|delete|head|patch)|urllib\\.request|urlopen|http\\.client|httpx\\.|aiohttp\\.)", flags: "" },
    { source: "\\bfetch\\s*\\(|\\b(?:https?|net|dgram|tls)\\.(?:request|get|connect|createConnection)\\b|\\bnew\\s+WebSocket\\b|\\baxios\\b", flags: "" },
    { source: "\\bNet::HTTP\\b|\\bopen-uri\\b|\\bsocket\\.(?:socket|create_connection)\\b", flags: "" },
    // Aliased / dynamic imports (item 8, best-effort): `import socket`,
    // `import requests as r` (then r.get), `from urllib import request`, and a
    // dynamic import of a known network module. Catches the common alias forms.
    { source: "\\bimport\\s+socket\\b|\\bfrom\\s+socket\\s+import\\b", flags: "" },
    { source: "\\bimport\\s+(?:requests|httpx|aiohttp|urllib|http)\\b(?:\\s+as\\s+[A-Za-z_]\\w{0,40})?", flags: "" },
    { source: "\\b(?:import_module|__import__)\\s*\\(\\s*[\"'](?:socket|requests|httpx|aiohttp|urllib|http\\.client)[\"']", flags: "" },
  ],
  subprocess: [
    { source: "\\b(?:subprocess\\.(?:run|call|Popen|check_output|check_call)|os\\.system|os\\.popen|os\\.exec[a-z]{0,4}|os\\.spawn[a-z]{0,4}|pty\\.spawn)\\b", flags: "" },
    { source: "\\bchild_process\\b|\\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\\s*\\(", flags: "" },
    { source: "\\b(?:system|exec|popen|backtick|Kernel\\.(?:system|exec|spawn)|%x\\{)\\b", flags: "" },
    { source: "\\$\\([^)]{1,200}\\)|`[^`\\n]{1,200}`", flags: "" }, // shell command substitution
    // Aliased / dynamic forms (item 8, best-effort): a dynamic import of os/
    // subprocess, or `getattr(os, ...)` to reach system/popen by string.
    { source: "\\b(?:import_module|__import__)\\s*\\(\\s*[\"'](?:os|subprocess|pty)[\"']", flags: "" },
    { source: "\\bgetattr\\s*\\(\\s*(?:os|subprocess)\\b", flags: "" },
  ],
  // fsWriteOutsideCwd: writes that target an absolute / home / parent path, not a
  // local relative path under cwd. The absolute/home/parent anchor is the signal.
  fsWriteOutsideCwd: [
    { source: ">>?\\s*(?:/|~|\\$HOME|\\.\\./)[^\\n]{0,200}", flags: "" },
    { source: "\\b(?:open|write_text|write_bytes|with\\s+open)\\b[^\\n]{0,40}['\"](?:/|~|\\.\\./)[^'\"\\n]{1,200}['\"][^\\n]{0,40}['\"][wax]\\b", flags: "" },
    { source: "\\bfs\\.(?:write|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\\b[^\\n]{0,40}['\"](?:/|~|\\.\\./)", flags: "" },
    { source: "\\b(?:cp|mv|tee|dd)\\b[^\\n]{0,120}\\s(?:/|~|\\$HOME)(?:\\w|/)", flags: "i" },
  ],
  secretFileRead: [
    { source: "(?:/|~|\\$HOME)[^\\n]{0,80}/\\.(?:aws/credentials|ssh/id_[a-z0-9]{1,12}|netrc|npmrc|pypirc|docker/config\\.json|kube/config|gitconfig)\\b", flags: "i" },
    { source: "\\.env\\b(?![.\\w])", flags: "i" },
    { source: "\\b(?:cat|less|more|head|tail|type)\\b[^\\n]{0,60}(?:credentials?|secret|token|\\.pem|private[_-]?key|id_rsa)\\b", flags: "i" },
    // NOTE (item 9 FP fix): an environment READ (os.environ / process.env,
    // including os.environ.get(...)) is NOT a secret-FILE read — env access is
    // ubiquitous and benign — so it deliberately does NOT set secretFileRead.
    // Credential VALUES that leak get caught by the SECRETS (DLP) layer instead.
  ],
};

export const CAPABILITY_DIMENSIONS = Object.keys(CAPABILITY_SIGNATURES);

// ── Policy compilation (mirrors compileDlpPolicy) ────────────────────────────

/**
 * Compile a raw skill-governance policy. Returns null when disabled (matches
 * compileDlpPolicy), so callers can `if (policy.skills)`.
 *
 * Shape:
 *   {
 *     mode: 'advisory' | 'enforce',          (default advisory)
 *     allowedSources: string[],              (origin allowlist; [] = allow any)
 *     blockSecrets: boolean,                 (run DLP over files; default true)
 *     blockInjection: boolean,               (scan SKILL.md; default true)
 *     dangerousPatterns: compiled[],         (default SKILL_DANGEROUS_PATTERNS)
 *     injectionPatterns: compiled[],         (default SKILL_INJECTION_PATTERNS)
 *     capabilityProfile: {                   (per-dimension budget; true = allowed)
 *       maxNetwork, maxFsWrite, maxSubprocess, maxSecretRead
 *     },
 *     dlp: compiled DLP policy (reused scanner),
 *   }
 */
export function compileSkillPolicy(raw) {
  if (!raw || raw.enabled === false) {
    return null;
  }
  const mode = raw.mode === "enforce" ? "enforce" : "advisory";
  const builtinEnabled = raw.disableBuiltin !== true;

  const dangerousPatterns = [
    ...(builtinEnabled ? SKILL_DANGEROUS_PATTERNS : []),
    ...(Array.isArray(raw.customDangerousPatterns) ? raw.customDangerousPatterns : []),
  ].map(compileSkillPattern);

  const injectionPatterns = [
    ...(builtinEnabled ? SKILL_INJECTION_PATTERNS : []),
    ...(Array.isArray(raw.customInjectionPatterns) ? raw.customInjectionPatterns : []),
  ].map(compileSkillPattern);

  // Skill-specific secret patterns supplement the reused DLP scanner (item 7).
  const secretPatterns = [
    ...(builtinEnabled ? SKILL_SECRET_PATTERNS : []),
    ...(Array.isArray(raw.customSecretPatterns) ? raw.customSecretPatterns : []),
  ].map(compileSkillPattern);

  // The capability budget: each flag, when false, means "any use of this
  // capability exceeds policy". Default is permissive-but-flagged: capabilities
  // are allowed (advisory surfaces them) unless the operator tightens the budget.
  const cp = raw.capabilityProfile ?? {};
  const capabilityProfile = {
    maxNetwork: cp.maxNetwork !== false,        // false → flag any network egress
    maxFsWrite: cp.maxFsWrite !== false,        // false → flag any out-of-cwd write
    maxSubprocess: cp.maxSubprocess !== false,  // false → flag any subprocess spawn
    maxSecretRead: cp.maxSecretRead !== false,  // false → flag any secret-file read
  };

  return {
    mode,
    allowedSources: Array.isArray(raw.allowedSources)
      ? raw.allowedSources.map((s) => String(s).trim().toLowerCase()).filter(Boolean)
      : [],
    blockSecrets: raw.blockSecrets !== false,
    blockInjection: raw.blockInjection !== false,
    dangerousPatterns,
    injectionPatterns,
    secretPatterns,
    capabilityProfile,
    // Reuse the DLP scanner for credential VALUES embedded in skill files. We
    // build an enforce-shaped DLP policy here so scanForDlp returns findings; the
    // skill-gate mode (advisory/enforce) governs whether they BLOCK downstream.
    dlp: compileDlpPolicy({ enabled: true, mode: "enforce" }),
  };
}

function compileSkillPattern(raw) {
  // Accept both the flat {id,severity,source,flags} shape and the dlp-style
  // {id,severity,pattern:{source,flags}} shape, for operator convenience.
  const source = raw.source ?? raw.pattern?.source ?? "";
  const flags = (raw.flags ?? raw.pattern?.flags ?? "i").replace(/g/g, ""); // no global: we use .test()
  let regex;
  try {
    regex = new RegExp(source, flags);
  } catch {
    regex = null; // an unparseable operator pattern is dropped (fail safe), never thrown
  }
  return {
    id: String(raw.id ?? "custom"),
    severity: normalizeSeverity(raw.severity),
    regex,
    source,
    flags,
    reason: raw.reason != null ? String(raw.reason) : undefined,
  };
}

function normalizeSeverity(s) {
  return ["critical", "high", "medium", "low"].includes(s) ? s : "medium";
}

// ── Skill scanner (async; never throws) ──────────────────────────────────────

/**
 * Walk a skill directory and run every layer. NEVER throws — on any error the
 * affected layer contributes a 'scan-error' finding and the rest continue.
 *
 * @param {string} skillDir  absolute path to the skill's root directory
 * @param {object} skillPolicy  compiled policy from compileSkillPolicy
 * @param {{ source?: string }} [opts]  optional origin (marketplace/repo) to gate
 * @returns {Promise<{
 *   findings: { kind, severity, file, detail }[],
 *   fileHashes: { path, sha256 }[],   // feeds attestation.skillIntegrityKey
 *   capabilities: { network, fsWriteOutsideCwd, subprocess, secretFileRead },
 * }>}
 */
export async function scanSkill(skillDir, skillPolicy, opts = {}) {
  const findings = [];
  const fileHashes = [];
  const capabilities = {
    network: false,
    fsWriteOutsideCwd: false,
    subprocess: false,
    secretFileRead: false,
  };

  if (!skillPolicy) {
    return { findings, fileHashes, capabilities };
  }

  let root;
  try {
    root = resolve(String(skillDir));
  } catch {
    return {
      findings: [{ kind: "scan-error", severity: "low", file: String(skillDir), detail: "Invalid skill directory path." }],
      fileHashes,
      capabilities,
    };
  }

  // SOURCE allowlist (reuses the trust-gate notion: an unlisted origin is gated).
  if (opts.source && skillPolicy.allowedSources.length > 0) {
    const origin = String(opts.source).trim().toLowerCase();
    const allowed = skillPolicy.allowedSources.some(
      (s) => origin === s || origin.startsWith(s) || origin.includes(s),
    );
    if (!allowed) {
      findings.push({
        kind: "source",
        severity: "high",
        file: "(skill source)",
        detail: `Skill source '${opts.source}' is not in the allowed-sources allowlist.`,
      });
    }
  }

  // Enumerate entries (bounded). A walk error degrades to a finding, not a throw.
  // Each entry is { abs, kind: "file" | "symlink" } — symlinks are classified so
  // INTEGRITY (S1) can hash an in-tree target or emit a distinct sentinel for an
  // external/unresolvable link, never collapsing to an empty hash set.
  let entries;
  try {
    entries = await walkSkillDir(root);
  } catch (error) {
    return {
      findings: [...findings, { kind: "scan-error", severity: "low", file: root, detail: `Skill directory walk failed: ${error?.message ?? error}` }],
      fileHashes,
      capabilities,
    };
  }

  for (const entry of entries) {
    const absPath = entry.abs;
    const relPath = safeRelative(root, absPath);
    const lower = relPath.toLowerCase();
    const baseName = lower.split(/[\\/]/).pop() ?? lower;
    const isSkillManifest = SKILL_MANIFEST_NAMES.has(baseName);
    const ext = baseName.includes(".") ? baseName.slice(baseName.lastIndexOf(".")) : "";
    const isScript = SCRIPT_EXTENSIONS.has(ext);
    // Model-facing prose beyond SKILL.md is also injection-scanned (item 5):
    // *.md, *.txt, and reference.* files an author can bundle to smuggle prose.
    const isProse = isSkillManifest || isModelFacingProse(baseName, ext);

    // ── Resolve the entry to a hashable source (S1 symlink handling) ──────────
    let hashSourcePath = absPath;   // what we content-hash (a symlink → its in-tree target)
    if (entry.kind === "symlink") {
      const res = await resolveSymlinkForHashAsync(root, absPath);
      if (res.sentinel) {
        // External / unresolvable / non-regular target: DO NOT follow it. Emit a
        // sentinel so the key is non-empty AND distinct per skill, and so the
        // presence of an external symlink is detectable downstream.
        fileHashes.push({ path: relPath, sha256: res.sentinel });
        findings.push({
          kind: "symlink",
          severity: "high",
          file: relPath,
          detail: `Skill entry '${relPath}' is a symlink pointing outside the skill tree (or unresolvable) — not followed; recorded as a sentinel.`,
        });
        continue; // nothing to body-scan for an unfollowed external link
      }
      // In-tree regular-file target: hash the TARGET so the entry is not empty.
      hashSourcePath = res.target;
    }

    // ── INTEGRITY: hash the WHOLE file (S2) ──────────────────────────────────
    let hashInfo;
    try {
      hashInfo = await hashFileWholeAsync(hashSourcePath);
    } catch (error) {
      findings.push({ kind: "scan-error", severity: "low", file: relPath, detail: `Unreadable: ${error?.message ?? error}` });
      continue;
    }
    if (hashInfo == null) {
      findings.push({ kind: "scan-error", severity: "low", file: relPath, detail: "Unreadable: could not hash file." });
      continue;
    }
    fileHashes.push({ path: relPath, sha256: hashInfo.sha256 });
    if (hashInfo.oversize) {
      findings.push({
        kind: "scan-error",
        severity: "low",
        file: relPath,
        detail: `File exceeds the ${MAX_HASH_BYTES}-byte hash cap (${hashInfo.size} bytes); size folded into the integrity hash, content beyond the cap not byte-hashed.`,
      });
    }

    // ── BODY SCAN: read the WHOLE file (S3), chunked, for secrets/injection/
    //    dangerous patterns/capabilities. A file past MAX_SCAN_BYTES is flagged.
    if (!(skillPolicy.blockSecrets || skillPolicy.blockInjection || isScript)) {
      continue; // nothing wants the body
    }
    let body;
    try {
      body = await readBodyBoundedAsync(hashSourcePath);
    } catch {
      body = null;
    }
    if (body == null) {
      continue;
    }
    const bodyText = body.text;
    if (body.truncated) {
      findings.push({
        kind: "scan-error",
        severity: "medium",
        file: relPath,
        detail: `File exceeds the ${MAX_SCAN_BYTES}-byte body-scan cap (${body.size} bytes); content beyond the cap was NOT scanned for dangerous patterns/secrets.`,
      });
    }

    // SECRETS: reuse dlp.mjs + skill-specific patterns over EVERY file.
    scanSecretsInto(findings, relPath, bodyText, skillPolicy);

    // INJECTION: model-facing prose (SKILL.md AND other bundled prose — item 5).
    if (skillPolicy.blockInjection && isProse) {
      for (const p of skillPolicy.injectionPatterns) {
        if (p.regex && safeTest(p.regex, bodyText)) {
          findings.push({
            kind: "injection",
            severity: p.severity,
            file: relPath,
            detail: `Possible prompt-injection in skill prose '${relPath}' (pattern '${p.id}').`,
          });
        }
      }
    }

    // DANGEROUS PATTERNS + CAPABILITY PROFILE: script bodies only.
    if (isScript) {
      for (const p of skillPolicy.dangerousPatterns) {
        if (p.regex && safeTest(p.regex, bodyText)) {
          findings.push({
            kind: "dangerous-pattern",
            severity: p.severity,
            file: relPath,
            detail: `Dangerous script pattern '${p.id}'.`,
          });
        }
      }
      // Capability detection sets the per-dimension bit on first match.
      for (const dim of CAPABILITY_DIMENSIONS) {
        if (!capabilities[dim]) {
          for (const sig of CAPABILITY_SIGNATURES[dim]) {
            if (safeTest(sig._compiled ?? (sig._compiled = compileSig(sig)), bodyText)) {
              capabilities[dim] = true;
              break;
            }
          }
        }
      }
    }
  }

  // CAPABILITY POLICY: flag any capability the budget disallows.
  pushCapabilityFinding(findings, capabilities.network, skillPolicy.capabilityProfile.maxNetwork, "network", "network egress (fetch/requests/curl/socket)");
  pushCapabilityFinding(findings, capabilities.fsWriteOutsideCwd, skillPolicy.capabilityProfile.maxFsWrite, "fs-write", "filesystem write outside the working directory");
  pushCapabilityFinding(findings, capabilities.subprocess, skillPolicy.capabilityProfile.maxSubprocess, "subprocess", "subprocess / shell spawn");
  pushCapabilityFinding(findings, capabilities.secretFileRead, skillPolicy.capabilityProfile.maxSecretRead, "secret-read", "read of a credential file or environment");

  return { findings, fileHashes, capabilities };
}

// SECRETS layer: the reused DLP scanner PLUS skill-specific provider tokens
// (item 7). Both contribute `secret` findings. Never throws.
function scanSecretsInto(findings, relPath, bodyText, skillPolicy) {
  if (!skillPolicy.blockSecrets) {
    return;
  }
  if (skillPolicy.dlp) {
    try {
      for (const dlpFinding of scanForDlp(bodyText, skillPolicy.dlp)) {
        findings.push({
          kind: "secret",
          severity: dlpFinding.severity,
          file: relPath,
          detail: `${dlpFinding.patternId}: ${dlpFinding.reason}`,
        });
      }
    } catch {
      // scanForDlp is contracted not to throw, but guard anyway.
    }
  }
  for (const p of skillPolicy.secretPatterns ?? []) {
    if (p.regex && safeTest(p.regex, bodyText)) {
      findings.push({
        kind: "secret",
        severity: p.severity,
        file: relPath,
        detail: `${p.id}: ${p.reason ?? "Possible credential in skill file."}`,
      });
    }
  }
}

// Model-facing prose beyond the SKILL.md manifest (item 5): bundled markdown,
// plain text, and reference docs that an author can use to smuggle injection.
function isModelFacingProse(baseName, ext) {
  if (ext === ".md" || ext === ".markdown" || ext === ".txt" || ext === ".rst") {
    return true;
  }
  // reference.* (reference.md/.txt/.json/…) is a common skill prose convention.
  return baseName === "reference" || baseName.startsWith("reference.");
}

function pushCapabilityFinding(findings, detected, allowed, label, human) {
  if (detected && allowed === false) {
    findings.push({
      kind: "capability",
      severity: "high",
      file: "(skill scripts)",
      detail: `Skill uses ${human} but policy disallows the '${label}' capability.`,
    });
  }
}

// ── Proactive audit orchestration (async; never throws) ──────────────────────

/**
 * Audit ONE skill directory end-to-end (the proactive Tier-2 path used by the
 * `skills audit` CLI / skills-audit.mjs runnable, NEVER the tool-call hot path):
 *   1. scanSkill → integrity hashes + skill findings (secrets/injection/etc.).
 *   2. resolveTransitive over the skill's manifests → the resolved dep set.
 *   3. runVulnScanner over the dir → CVE findings (degrades gracefully if no
 *      scanner is installed).
 * It then writes a SCANNED attestation keyed by skillIntegrityKey(fileHashes) —
 * the exact key the runtime gate (checkSkillDeps) looks up — so a pre-audited
 * skill is allowed with a real scan record instead of a first-run prompt.
 *
 * deps.mjs / attestation.mjs are imported LAZILY so skills.mjs keeps no
 * load-time dependency on them (mirrors deps.attestDepsScan). NEVER throws —
 * returns a summary with a `persisted` flag and any `note`/`error`.
 *
 * @param {string} skillDir
 * @param {object} opts { skillPolicy, depsPolicy?, source?, scannerCmd?, timeoutMs? }
 * @returns {Promise<{skillDir, key, findings, capabilities, scanner, resolved,
 *   fromLockfile, persisted, note?, error?}>}
 */
export async function auditSkillDir(skillDir, opts = {}) {
  const { skillPolicy, depsPolicy = null, source, scannerCmd = null, timeoutMs } = opts;
  const summary = {
    skillDir: String(skillDir),
    key: null,
    findings: [],
    capabilities: { network: false, fsWriteOutsideCwd: false, subprocess: false, secretFileRead: false },
    scanner: null,
    resolved: [],
    fromLockfile: false,
    persisted: false,
  };
  try {
    // The attestation module owns the canonical key derivation (a NUL-delimited
    // digest) and the cache writer; import it up front so the proactively
    // written cert is keyed EXACTLY as the runtime gate looks it up.
    const att = await import("./attestation.mjs");

    // 1. Skill scan (integrity + secrets + injection + dangerous + capability).
    const scan = await scanSkill(skillDir, skillPolicy, { source });
    summary.findings.push(...scan.findings);
    summary.capabilities = scan.capabilities;
    const key = att.skillIntegrityKey(scan.fileHashes);
    summary.key = key;

    // 2 + 3. Dependency resolution + vuln scan (best-effort, lazy import).
    //
    // SECURITY INVARIANT: the cert's scanCoverage MUST reflect what was ACTUALLY
    // resolved+scanned — it is NEVER hardcoded to 'transitive'/'full'. Only a real
    // transitive resolve + scan (coverage 'transitive') with zero findings makes a
    // clean cert; anything less ('declared-only'/'unavailable') leaves the cert
    // NON-clean so the enforce gate treats the skill as unverified. The resolution
    // is owned by deps.mjs (deps.resolveAndScan returns the honest coverage); we
    // map that coverage onto the cert and NEVER reimplement resolution here.
    let vulnDbVersion;
    let scannerName;
    summary.coverage = "unavailable"; // fail-safe default until a real scan proves otherwise
    try {
      const deps = await import("./deps.mjs");
      // Parse every manifest reachable in the dir for Tier-1 metadata findings.
      const declared = collectManifestSpecs(deps, skillDir, depsPolicy, summary);

      // Prefer the sibling-owned resolveAndScan (honest coverage in one call). It
      // ACTUALLY resolves transitively (uv/npm) then scans, returning
      // { available, scanner, findings, coverage:'transitive'|'declared-only'|
      //   'unavailable', dbVersion, method, note }. Its `coverage` is the security
      // contract — already honest — so we map it through normalizeCoverage (which
      // fails safe on any unknown value) and never upgrade it. If it is not present
      // yet, fall back to resolveTransitive + runVulnScanner (back-compat path).
      let resolved = [];
      let coverage = "unavailable";
      let findings = [];
      let scanner = null;
      let dbVersion;
      let available = false;
      let note;
      let fromLockfile = false;

      if (typeof deps.resolveAndScan === "function") {
        // NOTE the real signature: a SINGLE options object ({cwd, specs, ...}); the
        // declared spec set is passed as `specs`, NOT as a first positional arg.
        const r = await deps.resolveAndScan({ cwd: skillDir, specs: declared, scannerCmd, timeoutMs });
        // Trust the sibling's coverage verdict — it is the source of truth for
        // whether a transitive scan actually happened. normalizeCoverage maps the
        // canonical vocabulary through and fails ANY unknown value safe to a non-
        // clean level, so a clean cert can only ever come from a real 'transitive'.
        coverage = normalizeCoverage(r?.coverage);
        findings = Array.isArray(r?.findings) ? r.findings : [];
        scanner = r?.scanner ?? null;
        dbVersion = r?.dbVersion;
        available = r?.available === true;
        note = r?.note;
        // resolveAndScan owns coverage end-to-end (no separate lockfile signal to
        // surface); leave fromLockfile false — coverage already encodes the truth.
      } else {
        // Back-compat path: resolve then scan separately. resolveTransitive only
        // goes transitive when a lockfile exists; otherwise it is declared-only.
        const rt = await deps.resolveTransitive(declared, { cwd: skillDir });
        resolved = Array.isArray(rt?.resolved) ? rt.resolved : [];
        fromLockfile = rt?.fromLockfile === true;
        note = rt?.note;
        const vuln = await deps.runVulnScanner(resolved, { cwd: skillDir, scannerCmd, timeoutMs, fromLockfile });
        scanner = vuln?.scanner ?? null;
        findings = Array.isArray(vuln?.findings) ? vuln.findings : [];
        available = vuln?.available === true;
        dbVersion = vuln?.dbVersion;
        if (vuln?.note) note = vuln.note;
        // Coverage HONESTY (this is the EXACT bug that shipped): the legacy
        // runVulnScanner reports coverage 'full' whenever the chosen TOOL can scan
        // a project tree (trivy/osv `scansLockfile:true`) — but that is a property
        // of the TOOL, NOT proof that THIS skill's deps were transitively resolved.
        // decideScanCoverage caps the claim: a 'transitive' bill is only honest when
        // a lockfile ACTUALLY drove resolution. See its definition for the rule.
        coverage = decideScanCoverage({ available, fromLockfile, claimedCoverage: vuln?.coverage });
      }

      summary.resolved = resolved.map((s) => `${s.ecosystem}:${s.name}@${s.spec ?? ""}`);
      summary.fromLockfile = fromLockfile;
      summary.coverage = coverage;
      summary.scanner = scanner;
      scannerName = scanner;
      if (note && !summary.note) summary.note = note;
      // Vulnerability findings are recorded REGARDLESS of coverage so a real CVE
      // always drives deny/review by severity downstream.
      for (const f of findings) {
        summary.findings.push({
          kind: "vulnerability",
          severity: f.severity,
          file: f.package,
          detail: `${f.id} in ${f.package}${f.fixedVersion ? ` (fixed in ${f.fixedVersion})` : ""}`,
        });
      }
      if (available) {
        vulnDbVersion = dbVersion ?? (await deps.scannerDbVersion(scanner))?.version;
      }
    } catch (depErr) {
      // No deps module / resolver / scanner failure → the skill scan still attests,
      // but the vuln coverage is UNAVAILABLE: the runtime gate must NOT silent-allow
      // on it (unverified = unsafe). Never rethrow.
      summary.coverage = "unavailable";
      summary.note = summary.note ?? `dependency scan unavailable: ${depErr?.message ?? depErr}`;
    }

    // 4. Persist a SCANNED attestation keyed to the skill's current files.
    const rawFindings = summary.findings.map((f) => ({
      id: f.kind, severity: f.severity, package: f.file ?? "(skill)", source: "skills-audit",
    }));
    summary.vulnDbVersion = vulnDbVersion ?? null;
    const record = {
      basis: "scanned",
      manifestHash: key,
      rawFindings,
      // The cert tells the TRUTH about what was scanned. summary.coverage is the
      // REAL coverage from deps (default 'unavailable'); it is never hardcoded to a
      // clean value. Only 'transitive' + zero findings makes this a clean cert.
      scanCoverage: normalizeCoverage(summary.coverage),
      scannerName: scannerName ?? null,
      vulnDbVersion: vulnDbVersion ?? null,
      timestampMs: Date.now(),
      policySnapshot: { mode: skillPolicy?.mode ?? "advisory" },
    };
    const { persisted } = att.writeAttestation(key, record);
    summary.persisted = persisted === true;
  } catch (error) {
    summary.error = String(error?.message ?? error);
  }
  return summary;
}

// Collect declared specs from every manifest file in the skill dir (bounded).
//
// Two distinct kinds of input feed Tier-1 metadata hygiene here:
//   1. A real MANIFEST/LOCKFILE (requirements/pyproject/package.json/.py PEP723)
//      → deps.parseManifestFile yields specs WITH versions where present; these can
//      drive a transitive resolve+scan downstream and contribute CVE coverage.
//   2. A bare-import JS/TS file with NO manifest → we extract the imported package
//      NAMES (require()/import) so the Tier-1 metadata checks (typosquat / deny /
//      allow) still apply. These specs carry NO version, so they CANNOT yield a
//      transitive CVE scan → such a skill stays coverage 'unavailable' and is NOT
//      stamped safe. (Honest limit: JS has no PEP-723 standard; bare imports give
//      names, not versions.)
function collectManifestSpecs(deps, skillDir, depsPolicy, summary) {
  const out = [];
  let sawManifest = false;
  try {
    const entries = readdirSync(skillDir, { withFileTypes: true });
    for (const e of entries) {
      if (!e.isFile()) continue;
      const base = e.name.toLowerCase();
      const isManifest =
        base === "requirements.txt" || base === "pyproject.toml" || base === "uv.lock" ||
        base === "poetry.lock" || base === "package.json" || base === "package-lock.json" ||
        base.endsWith(".py");
      if (isManifest) {
        sawManifest = true;
        const specs = deps.parseManifestFile(join(skillDir, e.name));
        if (Array.isArray(specs)) out.push(...specs);
        if (depsPolicy && specs?.length) {
          const f = deps.scanDependencyMetadata(specs, depsPolicy, {});
          for (const finding of f) {
            summary.findings.push({ kind: finding.kind, severity: finding.severity, file: finding.package, detail: finding.detail });
          }
        }
      }
    }

    // Bare-import JS/TS (no manifest): extract imported package NAMES for Tier-1
    // metadata ONLY. We do this whether or not a manifest exists, but the resulting
    // specs are version-less — they raise typosquat/deny findings yet never let a
    // skill claim CVE coverage. (Kept best-effort + bounded; never throws.)
    const jsSpecs = collectBareImportSpecs(deps, skillDir, entries, depsPolicy, summary, out);
    if (jsSpecs > 0 && !sawManifest) {
      // Pure bare-import skill (names but no versions): leave a note so the cert's
      // 'unavailable' coverage is explainable rather than silent.
      if (!summary.note) {
        summary.note = "JS bare imports detected with no manifest/lockfile — package names checked for typosquat/deny, but versions are unknown so CVE coverage is unavailable (skill not stamped safe).";
      }
    }
  } catch { /* unreadable dir → declared set stays empty */ }
  return out;
}

// Extract bare-import package names from .js/.mjs/.cjs files in the dir and feed
// them through Tier-1 metadata as VERSION-LESS specs. Returns the count of
// name-specs added. Never throws. Bounded by the same MAX_FILES budget.
function collectBareImportSpecs(deps, skillDir, entries, depsPolicy, summary, out) {
  let added = 0;
  let scanned = 0;
  for (const e of entries) {
    if (scanned >= MAX_FILES) break;
    if (!e.isFile()) continue;
    const base = e.name.toLowerCase();
    const ext = base.includes(".") ? base.slice(base.lastIndexOf(".")) : "";
    if (ext !== ".js" && ext !== ".mjs" && ext !== ".cjs") continue;
    scanned++;
    let text;
    try {
      const fd = openSync(join(skillDir, e.name), "r");
      try {
        const size = Math.min(statSync(join(skillDir, e.name)).size, MAX_SCAN_BYTES);
        const buf = Buffer.allocUnsafe(size);
        const n = size > 0 ? readSync(fd, buf, 0, size, 0) : 0;
        text = buf.subarray(0, n).toString("utf-8");
      } finally {
        try { closeSync(fd); } catch { /* ignore */ }
      }
    } catch {
      continue; // unreadable file → skip
    }
    const names = extractJsImportNames(text);
    for (const name of names) {
      // VERSION-LESS spec: a name only. spec/version stays absent so this can never
      // be mistaken for a resolvable, scannable dependency (no CVE coverage).
      const spec = { ecosystem: "npm", name, spec: "", source: `bare-import:${e.name}` };
      out.push(spec);
      added++;
      if (depsPolicy) {
        try {
          const f = deps.scanDependencyMetadata([spec], depsPolicy, {});
          for (const finding of f) {
            summary.findings.push({ kind: finding.kind, severity: finding.severity, file: finding.package, detail: finding.detail });
          }
        } catch { /* metadata scan best-effort */ }
      }
    }
  }
  return added;
}

// Parse require()/import statements out of a JS/TS source body and return the set
// of imported PACKAGE names (bare specifiers only — relative './x' and absolute
// '/x' paths and Node builtins via 'node:' are excluded as they are not registry
// packages). Scoped packages keep their '@scope/name'; a deep import 'pkg/sub' is
// reduced to its package root ('pkg' or '@scope/name'). ReDoS-safe (bounded
// quantifiers); never throws — returns [] on any error.
export function extractJsImportNames(source) {
  const text = String(source ?? "");
  if (!text) return [];
  const names = new Set();
  // require('x') / require("x")  — bounded specifier length.
  const requireRe = /\brequire\s*\(\s*["']([^"'\n]{1,200})["']\s*\)/g;
  // import ... from 'x' / import 'x' / export ... from 'x' / dynamic import('x')
  const importFromRe = /\bimport\b[^;'"\n]{0,200}?\bfrom\s*["']([^"'\n]{1,200})["']/g;
  const bareImportRe = /\bimport\s*["']([^"'\n]{1,200})["']/g;
  const dynImportRe = /\bimport\s*\(\s*["']([^"'\n]{1,200})["']\s*\)/g;
  const exportFromRe = /\bexport\b[^;'"\n]{0,200}?\bfrom\s*["']([^"'\n]{1,200})["']/g;
  for (const re of [requireRe, importFromRe, bareImportRe, dynImportRe, exportFromRe]) {
    let m;
    let guard = 0;
    re.lastIndex = 0;
    try {
      while ((m = re.exec(text)) != null && guard++ < 2000) {
        const root = packageRootFromSpecifier(m[1]);
        if (root) names.add(root);
        if (m.index === re.lastIndex) re.lastIndex++; // zero-width guard
      }
    } catch { /* a pathological body → skip this pattern, never throw */ }
  }
  return [...names].sort();
}

// Reduce an import specifier to its registry package root, or "" if it is not a
// bare registry package (relative/absolute path, node: builtin, or empty).
function packageRootFromSpecifier(specifier) {
  const s = String(specifier ?? "").trim();
  if (!s) return "";
  // Relative or absolute path imports are local files, not registry packages.
  if (s.startsWith(".") || s.startsWith("/") || s.startsWith("\\")) return "";
  // Node builtins ('node:fs') and protocol-prefixed specifiers are not packages.
  if (s.includes(":")) return "";
  const parts = s.split("/");
  if (s.startsWith("@")) {
    // Scoped: @scope/name (drop any deeper subpath). Require both segments.
    if (parts.length < 2 || !parts[0] || !parts[1]) return "";
    return `${parts[0]}/${parts[1]}`;
  }
  // Unscoped: first path segment is the package; drop deep imports (pkg/sub).
  const root = parts[0];
  if (!root) return "";
  // Bare Node builtins without the 'node:' prefix (fs, path, crypto, …) are not
  // registry packages either; a small, common set is excluded to avoid noise.
  if (NODE_BUILTIN_NAMES.has(root.toLowerCase())) return "";
  return root;
}

// Common Node builtins that may be imported WITHOUT the 'node:' prefix — excluded
// from bare-import name extraction so they are not mistaken for registry packages.
const NODE_BUILTIN_NAMES = new Set([
  "assert", "buffer", "child_process", "cluster", "console", "crypto", "dgram",
  "dns", "domain", "events", "fs", "http", "http2", "https", "net", "os", "path",
  "perf_hooks", "process", "punycode", "querystring", "readline", "repl",
  "stream", "string_decoder", "timers", "tls", "tty", "url", "util", "v8", "vm",
  "worker_threads", "zlib",
]);

// ── Runtime trigger detector (sync; pure) ────────────────────────────────────

// A path is "under a skills dir" if any segment is one of these. Recognizes the
// common layouts (~/.claude/skills/<name>/scripts/run.sh, .copilot/skills/…).
// Operators can extend this via the `skillsDirSegments` policy field (item 4).
const SKILLS_DIR_SEGMENTS = new Set(["skills", "skill", ".skills"]);
// Plugin layouts where the skill dir sits directly under a plugin (no `skills`
// segment): `.claude/plugins/<plugin>/<skill>/…`. Recognized ONLY in a plugin
// root context (a `plugins` segment with an agent-config ancestor) so we don't
// over-trigger on an ordinary repo `plugins/foo/index.js` (item 4 calibration).
const PLUGIN_ROOT_SEGMENTS = new Set(["plugins"]);
const AGENT_CONFIG_ANCESTORS = new Set([".claude", ".copilot", ".agt", ".opencode"]);
// A script carrying one of these markers self-identifies as skill/PEP-723 code.
const SKILL_SCRIPT_MARKERS = [
  /#\s*\/\/\/\s*script\b/i,        // PEP 723 inline script metadata block
  /^\s*#\s*skill\s*:/im,           // "# skill: <name>" marker
  /SKILL_INVOCATION|AGT_SKILL\b/,  // explicit env/marker
];
// A token referencing a skill dir through an env var, e.g. `$SKILL_DIR/run.sh`
// or `${AGT_SKILL_ROOT}/x`. Best-effort (item 4): we cannot expand the var, but
// the NAME self-identifies the path as skill-rooted.
const SKILL_VAR_REF = /\$\{?[A-Za-z_][A-Za-z0-9_]{0,60}\}?/g;
const SKILL_VAR_NAME = /(?:^|_)skill(?:s)?(?:_|$)|skill_?dir|skill_?root|skill_?home/i;

/**
 * Recognize when a Bash/PowerShell command runs a skill's script. SYNC + pure —
 * this is the runtime trigger the orchestrator wires into evaluatePreToolUse to
 * decide whether to gate the call against a skill attestation.
 *
 * Recognizes (item 4):
 *   - a path under a `skills`/`skill`/`.skills` segment (or an operator-configured
 *     extra segment) → …/skills/<name>;
 *   - a plugin-rooted skill dir `…/<agent-config>/plugins/<plugin>/<skill>/…`;
 *   - a cwd-relative invocation (`bash ./run.sh`, `python run.py`, `sh scripts/x.sh`)
 *     when CWD itself is (or is under) a skill/plugin-skill dir;
 *   - a `$VAR`/`${VAR}` token whose name self-identifies as a skill dir;
 *   - an inline PEP-723 / skill marker.
 * Calibrated NOT to match plain non-skill commands (the benchmark corpus stays a
 * no-op): a bare relative script is only a trigger when CWD is skill-rooted.
 *
 * @param {{ command?: string, cwd?: string, skillsDirSegments?: string[] }} args
 * @returns {{ isSkillInvocation: boolean, skillDir?: string, scriptPath?: string }}
 */
export function checkSkillInvocationMeta({ command, cwd, skillsDirSegments } = {}) {
  const cmd = String(command ?? "");
  if (!cmd.trim()) {
    return { isSkillInvocation: false };
  }

  // Operator-extensible segment set (item 4) — merged with the builtins.
  let segments = SKILLS_DIR_SEGMENTS;
  if (Array.isArray(skillsDirSegments) && skillsDirSegments.length) {
    segments = new Set(SKILLS_DIR_SEGMENTS);
    for (const s of skillsDirSegments) {
      const v = String(s ?? "").trim().toLowerCase();
      if (v) segments.add(v);
    }
  }

  // Pull candidate path-like tokens out of the command (bounded token length so
  // a pathological command string cannot drive expensive matching).
  const tokens = cmd.match(/[^\s"'`|&;<>()]{1,400}/g) ?? [];
  for (const token of tokens) {
    const norm = token.replace(/\\/g, "/");
    if (!norm.includes("/")) {
      continue;
    }
    const parts = norm.split("/");
    const lower = parts.map((s) => s.toLowerCase());

    // (a) explicit skills segment → …/skills/<name>
    const skillIdx = lower.findIndex((s) => segments.has(s));
    if (skillIdx >= 0 && skillIdx < parts.length - 1 && parts[skillIdx + 1]) {
      const skillDir = parts.slice(0, skillIdx + 2).join("/");
      return {
        isSkillInvocation: true,
        skillDir: resolveAgainst(cwd, skillDir),
        scriptPath: resolveAgainst(cwd, norm),
      };
    }

    // (b) plugin-rooted skill: …/<agent-config>/plugins/<plugin>/<skill>/…
    //     Require an agent-config ancestor so we don't catch a repo's own
    //     `plugins/<x>` build path.
    const pluginIdx = lower.findIndex((s) => PLUGIN_ROOT_SEGMENTS.has(s));
    if (
      pluginIdx >= 1 &&
      AGENT_CONFIG_ANCESTORS.has(lower[pluginIdx - 1]) &&
      pluginIdx + 2 < parts.length &&
      parts[pluginIdx + 1] &&
      parts[pluginIdx + 2]
    ) {
      const skillDir = parts.slice(0, pluginIdx + 3).join("/"); // …/plugins/<plugin>/<skill>
      return {
        isSkillInvocation: true,
        skillDir: resolveAgainst(cwd, skillDir),
        scriptPath: resolveAgainst(cwd, norm),
      };
    }
  }

  // (c) $VAR / ${VAR} skill-dir reference (best-effort, item 4).
  const varRefs = cmd.match(SKILL_VAR_REF) ?? [];
  for (const ref of varRefs) {
    const name = ref.replace(/[${}]/g, "");
    if (SKILL_VAR_NAME.test(name)) {
      return { isSkillInvocation: true };
    }
  }

  // (d) cwd-relative invocation when CWD itself is skill-rooted (item 4):
  //     `bash ./run.sh`, `python run.py`, `sh scripts/x.sh`. Only a trigger when
  //     the working directory is (or is under) a skill / plugin-skill dir — a bare
  //     relative script in an ordinary cwd is NOT a skill invocation (corpus stays
  //     no-op). We resolve the skill ROOT from the cwd, not the script path.
  const cwdSkillDir = skillRootFromCwd(cwd, segments);
  if (cwdSkillDir && commandRunsLocalScript(cmd)) {
    return {
      isSkillInvocation: true,
      skillDir: cwdSkillDir,
      scriptPath: undefined,
    };
  }

  // (e) inline PEP-723 / skill marker in the command payload (heredoc / -c).
  if (SKILL_SCRIPT_MARKERS.some((re) => safeTest(re, cmd))) {
    return { isSkillInvocation: true };
  }

  return { isSkillInvocation: false };
}

// Resolve the skill root from a cwd that is (or sits under) a skills/plugin-skill
// dir. Returns the absolute …/skills/<name> (or …/plugins/<plugin>/<skill>) dir,
// or null. Pure; never throws.
function skillRootFromCwd(cwd, segments) {
  const c = String(cwd ?? "").trim();
  if (!c) {
    return null;
  }
  const norm = c.replace(/\\/g, "/");
  const parts = norm.split("/");
  const lower = parts.map((s) => s.toLowerCase());

  const skillIdx = lower.findIndex((s) => (segments ?? SKILLS_DIR_SEGMENTS).has(s));
  if (skillIdx >= 0 && skillIdx < parts.length - 1 && parts[skillIdx + 1]) {
    return resolveAgainst(undefined, parts.slice(0, skillIdx + 2).join("/"));
  }
  const pluginIdx = lower.findIndex((s) => PLUGIN_ROOT_SEGMENTS.has(s));
  if (
    pluginIdx >= 1 &&
    AGENT_CONFIG_ANCESTORS.has(lower[pluginIdx - 1]) &&
    pluginIdx + 2 < parts.length &&
    parts[pluginIdx + 1] &&
    parts[pluginIdx + 2]
  ) {
    return resolveAgainst(undefined, parts.slice(0, pluginIdx + 3).join("/"));
  }
  return null;
}

// True if the command runs a LOCAL script (relative path / `./x` / an interpreter
// on a relative file). Used only when cwd is already known skill-rooted, so this
// stays conservative — it must see a script-shaped operand, not just any command.
function commandRunsLocalScript(cmd) {
  // interpreter <relative-script>  (no leading / and not a $VAR)
  const interp = /\b(?:bash|sh|zsh|dash|python[0-9.]{0,4}|node|ruby|perl|pwsh|powershell)\b[^\n;|&]{0,20}?\s+(\.?\.?\/)?[\w.@-]+\/?[\w./@-]*\.(?:sh|bash|zsh|py|js|mjs|cjs|rb|pl|ps1)\b/i;
  // bare ./script or ./dir/script
  const dotSlash = /(?:^|[\s;&|])\.\/[\w./@-]+/;
  return safeTest(interp, cmd) || safeTest(dotSlash, cmd);
}

// ── Sync integrity hashing (for the runtime attestation key) ─────────────────

/**
 * Synchronous twin of scanSkill's INTEGRITY layer: hash every file in a skill
 * directory and return the same {path, sha256}[] shape that feeds
 * attestation.skillIntegrityKey. The PreToolUse decision path is synchronous, so
 * the runtime cannot await scanSkill; this lets it compute a skill's integrity
 * key in-process without async I/O.
 *
 * Semantics MIRROR scanSkill's INTEGRITY layer EXACTLY so the sync and async
 * hashes of an unchanged skill agree byte-for-byte (the runtime sync key must
 * match a proactively scanned cert's async key):
 *   - same MAX_FILES / MAX_DEPTH walk, same skipped noise dirs, same path order;
 *   - each REGULAR file is content-hashed over its WHOLE body up to MAX_HASH_BYTES,
 *     with full size folded in when oversize (S2 — no head-only window to swap past);
 *   - a SYMLINK whose target is a regular file INSIDE the tree is hashed via its
 *     target (so the entry is never empty); a symlink pointing OUTSIDE the tree
 *     (or unresolvable) is NOT followed but recorded as a distinct sentinel hash
 *     so the key is non-empty AND per-skill distinct (S1 — no empty-key collapse).
 * NEVER throws — any error on a file/dir is skipped, and a bad root yields [].
 *
 * @param {string} skillDir absolute path to the skill's root directory
 * @returns {{path:string, sha256:string}[]}
 */
export function skillFileHashesSync(skillDir) {
  const out = [];
  let root;
  try {
    root = resolve(String(skillDir));
  } catch {
    return out;
  }

  const stack = [{ dir: root, depth: 0 }];
  while (stack.length > 0 && out.length < MAX_FILES) {
    const { dir, depth } = stack.pop();
    if (depth > MAX_DEPTH) {
      continue;
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable subdir → skip, never throw
    }
    for (const entry of entries) {
      if (out.length >= MAX_FILES) {
        break;
      }
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "__pycache__") {
          continue;
        }
        stack.push({ dir: full, depth: depth + 1 });
      } else if (entry.isFile()) {
        const info = hashFileWholeSync(full);
        if (info != null) {
          out.push({ path: safeRelative(root, full), sha256: info.sha256 });
        }
      } else if (entry.isSymbolicLink()) {
        // S1: classify the link. In-tree regular-file target → hash the target;
        // external/unresolvable → distinct sentinel (never empty, never followed).
        const res = resolveSymlinkForHashSync(root, full);
        if (res.sentinel) {
          out.push({ path: safeRelative(root, full), sha256: res.sentinel });
        } else if (res.target) {
          const info = hashFileWholeSync(res.target);
          if (info != null) {
            out.push({ path: safeRelative(root, full), sha256: info.sha256 });
          }
        }
      }
      // Other entry types (fifo/socket/device) are intentionally skipped.
    }
  }
  return out;
}

/**
 * True if a skill directory contains any entry that could NOT be content-hashed
 * normally — an external/unresolvable symlink (recorded as a sentinel), or a
 * symlink whose in-tree target is itself unreadable. policy.mjs uses this to
 * REFUSE to silently-allow such a skill rather than trusting a key built partly
 * from sentinels. NEVER throws.
 *
 * NOTE: an EMPTY fileHashes array (this returns false for it) means a genuinely
 * empty directory — policy should refuse that separately (empty key collapse).
 *
 * @param {string} skillDir
 * @returns {boolean}
 */
export function skillHasUnhashableEntries(skillDir) {
  let root;
  try {
    root = resolve(String(skillDir));
  } catch {
    return false;
  }
  let seen = 0;
  const stack = [{ dir: root, depth: 0 }];
  while (stack.length > 0 && seen < MAX_FILES) {
    const { dir, depth } = stack.pop();
    if (depth > MAX_DEPTH) {
      continue;
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (seen >= MAX_FILES) {
        break;
      }
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "__pycache__") {
          continue;
        }
        stack.push({ dir: full, depth: depth + 1 });
      } else if (entry.isFile()) {
        seen++;
      } else if (entry.isSymbolicLink()) {
        seen++;
        const res = resolveSymlinkForHashSync(root, full);
        if (res.sentinel) {
          return true; // external / unresolvable link
        }
        if (res.target && hashFileWholeSync(res.target) == null) {
          return true; // in-tree target exists per resolution but is unhashable
        }
      }
    }
  }
  return false;
}

// ── Whole-file hashing (S2): sync + async twins, identical digest semantics ───
// Both stream the file in chunks and hash the WHOLE content up to MAX_HASH_BYTES.
// A file larger than the cap folds a stable "oversize" marker + its full byte
// size into the digest, so any size change still changes the hash (an attacker
// cannot pad past the cap and swap bytes silently). Returns { sha256, size,
// oversize } or null on any error.

const OVERSIZE_MARKER = "\x00AGT-SKILL-OVERSIZE\x00";

function hashFileWholeSync(path) {
  let fd;
  try {
    fd = openSync(path, "r");
  } catch {
    return null;
  }
  try {
    const size = statSync(path).size;
    const hash = createHash("sha256");
    const cap = Math.min(size, MAX_HASH_BYTES);
    const buf = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
    let pos = 0;
    while (pos < cap) {
      const want = Math.min(HASH_CHUNK_BYTES, cap - pos);
      const n = readSync(fd, buf, 0, want, pos);
      if (n <= 0) {
        break;
      }
      hash.update(n < buf.length ? buf.subarray(0, n) : buf);
      pos += n;
    }
    if (size > MAX_HASH_BYTES) {
      hash.update(OVERSIZE_MARKER);
      hash.update(String(size));
    }
    return { sha256: hash.digest("hex"), size, oversize: size > MAX_HASH_BYTES };
  } catch {
    return null;
  } finally {
    try { closeSync(fd); } catch { /* ignore */ }
  }
}

async function hashFileWholeAsync(path) {
  let fh;
  try {
    fh = await open(path, "r");
  } catch {
    return null;
  }
  try {
    const st = await fh.stat();
    const size = st.size;
    const hash = createHash("sha256");
    const cap = Math.min(size, MAX_HASH_BYTES);
    const buf = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
    let pos = 0;
    while (pos < cap) {
      const want = Math.min(HASH_CHUNK_BYTES, cap - pos);
      const { bytesRead } = await fh.read(buf, 0, want, pos);
      if (bytesRead <= 0) {
        break;
      }
      hash.update(bytesRead < buf.length ? buf.subarray(0, bytesRead) : buf);
      pos += bytesRead;
    }
    if (size > MAX_HASH_BYTES) {
      hash.update(OVERSIZE_MARKER);
      hash.update(String(size));
    }
    return { sha256: hash.digest("hex"), size, oversize: size > MAX_HASH_BYTES };
  } catch {
    return null;
  } finally {
    try { await fh.close(); } catch { /* ignore */ }
  }
}

// ── Whole-file body read (S3): read up to MAX_SCAN_BYTES for pattern scanning ──
// Returns { text, size, truncated } or null. We read the head up to the cap (a
// payload anywhere in the first MAX_SCAN_BYTES is now visible — far past the old
// 256KB head); a larger file is flagged truncated so the unscanned tail is never
// silently invisible.
async function readBodyBoundedAsync(path) {
  let fh;
  try {
    fh = await open(path, "r");
  } catch {
    return null;
  }
  try {
    const st = await fh.stat();
    const size = st.size;
    const want = Math.min(size, MAX_SCAN_BYTES);
    let text = "";
    if (want > 0) {
      const buf = Buffer.allocUnsafe(want);
      const { bytesRead } = await fh.read(buf, 0, want, 0);
      text = buf.subarray(0, bytesRead).toString("utf-8");
    }
    return { text, size, truncated: size > MAX_SCAN_BYTES };
  } catch {
    return null;
  } finally {
    try { await fh.close(); } catch { /* ignore */ }
  }
}

// ── Symlink resolution for hashing (S1): sync + async twins ───────────────────
// Decide how to hash a symlink entry WITHOUT escaping the skill tree:
//   - target is a REGULAR FILE inside the tree → { target } (caller hashes it);
//   - target is outside the tree, missing, a dir, or unresolvable → { sentinel }
//     where sentinel = "symlink:" + sha256(linkTargetString), so the entry is
//     non-empty AND distinct per skill, the link is never followed, and its
//     presence is detectable. NEVER throws.
function symlinkSentinel(linkTarget) {
  const t = String(linkTarget ?? "").slice(0, MAX_SYMLINK_TARGET_LEN);
  return "symlink:" + createHash("sha256").update(t).digest("hex");
}

// True iff `candidate` resolves to a path inside `root` (root itself counts).
function isInsideTree(root, candidate) {
  try {
    const rel = relative(root, candidate);
    return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
  } catch {
    return false;
  }
}

function resolveSymlinkForHashSync(root, linkPath) {
  let rawTarget = "";
  try {
    rawTarget = readlinkSync(linkPath);
  } catch {
    return { sentinel: symlinkSentinel("(unreadable)") };
  }
  // Resolve the link target to an absolute path, then realpath it (collapsing
  // any chain) so a multi-hop link that ultimately escapes is still caught.
  const abs = isAbsolute(rawTarget) ? rawTarget : resolve(dirname(linkPath), rawTarget);
  let real;
  try {
    real = realpathSync(abs);
  } catch {
    return { sentinel: symlinkSentinel(rawTarget) }; // dangling / unresolvable
  }
  if (!isInsideTree(root, real)) {
    return { sentinel: symlinkSentinel(rawTarget) }; // escapes the skill tree
  }
  let st;
  try {
    st = statSync(real);
  } catch {
    return { sentinel: symlinkSentinel(rawTarget) };
  }
  if (!st.isFile()) {
    return { sentinel: symlinkSentinel(rawTarget) }; // dir / special — don't hash
  }
  return { target: real };
}

async function resolveSymlinkForHashAsync(root, linkPath) {
  let rawTarget = "";
  try {
    rawTarget = await readlink(linkPath);
  } catch {
    return { sentinel: symlinkSentinel("(unreadable)") };
  }
  const abs = isAbsolute(rawTarget) ? rawTarget : resolve(dirname(linkPath), rawTarget);
  let real;
  try {
    real = await realpath(abs);
  } catch {
    return { sentinel: symlinkSentinel(rawTarget) };
  }
  if (!isInsideTree(root, real)) {
    return { sentinel: symlinkSentinel(rawTarget) };
  }
  let st;
  try {
    st = await stat(real);
  } catch {
    return { sentinel: symlinkSentinel(rawTarget) };
  }
  if (!st.isFile()) {
    return { sentinel: symlinkSentinel(rawTarget) };
  }
  return { target: real };
}

// ── Internal helpers ─────────────────────────────────────────────────────────

// Normalize a coverage value from deps.mjs onto the canonical vocabulary the
// attestation gate understands: 'transitive' > 'declared-only' > 'unavailable'.
// The legacy synonym 'full' maps to 'transitive'. ANY unrecognized / missing
// value FAILS SAFE to 'unavailable' (never silently upgraded to a clean level) —
// so a cert can only claim 'transitive' when deps explicitly reported it.
function normalizeCoverage(coverage) {
  const c = String(coverage ?? "").trim().toLowerCase();
  if (c === "transitive" || c === "full") return "transitive";
  if (c === "declared-only") return "declared-only";
  return "unavailable";
}

/**
 * Decide the HONEST scanCoverage for the legacy resolve+scan path (used until the
 * sibling-owned deps.resolveAndScan lands). The legacy runVulnScanner reports
 * 'full' whenever the chosen TOOL can scan a project tree — but that is a property
 * of the tool, NOT proof THIS skill's deps were transitively resolved. So:
 *   - scanner could not run (available:false)                → 'unavailable'
 *   - a lockfile ACTUALLY drove resolution (fromLockfile)    → 'transitive'
 *   - scanner ran but resolution was NOT transitive          → cap at 'declared-only'
 *     (even if the tool claimed 'full'/'transitive' — no false clean)
 * This is the precise guard against the bug that stamped an inline PEP-723 skill
 * (no lockfile) as 'full' just because trivy scanned its directory. Pure; exported
 * for tool-independent testing. NEVER returns 'transitive' without a lockfile.
 *
 * NOTE: the tool's own `claimedCoverage` is DELIBERATELY not trusted — `fromLockfile`
 * is the only proof of a transitive resolve — so it is not a parameter here. Callers
 * may pass it for context; it is intentionally ignored.
 *
 * @param {{available:boolean, fromLockfile:boolean}} args
 * @returns {'transitive'|'declared-only'|'unavailable'}
 */
export function decideScanCoverage({ available, fromLockfile } = {}) {
  if (!available) {
    return "unavailable";
  }
  if (fromLockfile === true) {
    // Lockfile drove resolution AND the scanner ran → genuinely transitive.
    return "transitive";
  }
  // Scanner ran but resolution was not transitive (no lockfile). Whatever the tool
  // claimed ('full'/'transitive'/'declared-only'/unknown), the honest ceiling here
  // is 'declared-only': a scan DID look at the declared set, but the transitive
  // tree was never resolved, so this is NEVER a clean 'transitive' bill.
  return "declared-only";
}

function compileSig(sig) {
  try {
    return new RegExp(sig.source, (sig.flags ?? "").replace(/g/g, ""));
  } catch {
    return null;
  }
}

function safeTest(regex, text) {
  if (!regex) {
    return false;
  }
  try {
    regex.lastIndex = 0;
    return regex.test(text);
  } catch {
    return false;
  }
}

function safeRelative(root, absPath) {
  try {
    const rel = relative(root, absPath);
    return rel ? rel.split(sep).join("/") : absPath;
  } catch {
    return absPath;
  }
}

function resolveAgainst(cwd, p) {
  try {
    return cwd ? resolve(String(cwd), p) : resolve(p);
  } catch {
    return p;
  }
}

/**
 * Bounded recursive directory walk. Returns { abs, kind: "file" | "symlink" }
 * entries, capped at MAX_FILES and MAX_DEPTH. Directories are recursed into
 * (skipping noise dirs); the walk NEVER recurses THROUGH a symlinked directory
 * (a symlink is reported as an entry, not descended), so a symlink loop or a link
 * to a parent cannot expand the walk. Symlink ENTRIES are surfaced (kind:
 * "symlink") so the INTEGRITY layer can hash an in-tree target or emit a
 * sentinel (S1) — the old behaviour silently dropped them, collapsing the key.
 */
async function walkSkillDir(root) {
  const out = [];
  const stack = [{ dir: root, depth: 0 }];
  while (stack.length > 0 && out.length < MAX_FILES) {
    const { dir, depth } = stack.pop();
    if (depth > MAX_DEPTH) {
      continue;
    }
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable subdir → skip, never throw
    }
    for (const entry of entries) {
      if (out.length >= MAX_FILES) {
        break;
      }
      const full = join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        // Surface the link as an entry but NEVER descend through it (no follow).
        out.push({ abs: full, kind: "symlink" });
      } else if (entry.isDirectory()) {
        // Skip dependency/VCS noise that would blow the file budget without
        // representing skill-authored code.
        if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "__pycache__") {
          continue;
        }
        stack.push({ dir: full, depth: depth + 1 });
      } else if (entry.isFile()) {
        out.push({ abs: full, kind: "file" });
      }
      // Other entry types (fifo/socket/device) are intentionally skipped.
    }
  }
  return out;
}

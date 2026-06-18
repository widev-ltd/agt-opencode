// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// dlp.mjs — Data Loss Prevention (DLP) scanner for the AGT governance plugin.
//
// Scans tool OUTPUTS (bash stdout, file reads, web responses) for credential
// VALUES and PII that should never be seen by the model — distinct from the
// existing poisoning scanner, which looks for INSTRUCTIONS injected into that
// output. A `secret-read` blockedToolCall rule prevents the READ, but if a
// credential appears through an unblocked path this scanner catches the VALUE
// in the output before the model processes it.
//
// THREAT MODEL:
//   - Credential leakage: model sees an AWS key, GitHub token, or private key
//     in tool output and is socially-engineered or accidentally prompted to
//     exfiltrate it. DLP in enforce mode suppresses the output. Advisory mode
//     warns the model to treat the output as sensitive.
//   - PII leakage: model sees SSNs, credit-card numbers, or email addresses and
//     includes them in generated code, logs, or responses. DLP warns or blocks.
//
// FALSE-POSITIVE DESIGN (read before adding patterns):
//   Every pattern has a benign near-miss test in selftest-dlp.mjs. The bar is:
//   zero FPs on normal development output (package.json, commit logs, build
//   output, API documentation examples with EXAMPLE/PLACEHOLDER strings).
//   Patterns that cannot meet this bar must be medium severity or lower.
//
// POLICY INTEGRATION:
//   dlpPolicies.mode = "advisory"  → advisory context added, no deny/review
//   dlpPolicies.mode = "enforce"   → high→deny, medium→review, low→advisory
//   dlpPolicies.customPatterns     → operator-defined patterns (same schema)
//   dlpPolicies.allowPatterns      → regex list of strings that suppress a match
//     (e.g. allow AKIA patterns that contain "EXAMPLE" or "PLACEHOLDER")

// ── Built-in pattern catalogue ──────────────────────────────────────────────

export const DLP_BUILTIN_PATTERNS = [
  // ── Credentials (high severity) ───────────────────────────────────────────
  {
    id: "aws-access-key",
    category: "credential",
    severity: "high",
    // AWS access key IDs start with AKIA/AKID/AKII/AKIL (all AKIA[A-Z]{1}).
    // 20 chars total. VERY specific prefix; FP risk is low in real output.
    // Benign near-miss: AKIAIOSFODNN7EXAMPLE (official AWS docs placeholder) —
    // the default allowPatterns suppresses strings containing "EXAMPLE".
    pattern: { source: "\\bAKIA[0-9A-Z]{16}\\b", flags: "" },
    reason: "AWS access key ID in output. Treat as a credential leak; do not log, repeat, or use this value.",
  },
  {
    id: "github-token-pat",
    category: "credential",
    severity: "high",
    // GitHub fine-grained and classic personal access tokens.
    pattern: { source: "\\bgh[pousr]_[A-Za-z0-9]{36,}\\b", flags: "" },
    reason: "GitHub personal access token in output. Do not expose or transmit this value.",
  },
  {
    id: "private-key-header",
    category: "credential",
    severity: "high",
    // PEM private key block header. Present in id_rsa, id_ed25519, TLS keys.
    // Path-based blockedToolCalls should prevent reading these files, but this
    // catches the value if it appears through a different path.
    pattern: {
      source: "-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
      flags: "i",
    },
    reason: "Private key material in output. Treat as a critical credential leak; do not log or use this value.",
  },
  {
    id: "aws-secret-access-key",
    category: "credential",
    severity: "high",
    // The AWS *secret* access key (the half that actually authenticates) is a
    // 40-char base64 string — indistinguishable from a hash on its own, so this
    // pattern is KEYED: it only matches when assigned to an aws_secret_access_key
    // / aws-secret name. Keyed → negligible false-positive rate.
    pattern: {
      source: "aws[_-]?secret[_-]?access[_-]?key\\s*[=:]\\s*[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])",
      flags: "i",
    },
    reason: "AWS secret access key in output. Treat as a critical credential leak; do not log, repeat, or transmit this value.",
  },
  {
    id: "generic-api-key-assignment",
    category: "credential",
    severity: "medium",
    // Matches key=value assignments where the key name suggests a credential.
    // Medium severity because benign config examples (with placeholder values)
    // will match. Advisory: warn; enforce: review (not outright deny).
    pattern: {
      source:
        "(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)\\s*[=:]\\s*[\"']?([A-Za-z0-9_\\-]{20,})[\"']?",
      flags: "i",
    },
    reason: "Possible API key or secret in output. Verify this is not a live credential before using it.",
  },

  // ── PII (medium severity) ─────────────────────────────────────────────────
  {
    id: "ssn-us",
    category: "pii",
    severity: "medium",
    // US Social Security Number: NNN-NN-NNNN with validated ranges.
    // Excludes 000-xx-xxxx, 666-xx-xxxx, 900-999-xx-xxxx.
    // FP guards: the (?<!\d[ .\-]) lookbehind rejects a phone country-code prefix
    // ("+1 234-56-7890" → the "1 " before the group excludes it) and version/IP
    // prefixes ("1.234-..."); (?<![0-9-]) rejects being embedded in a longer
    // number or a 3-3-4 phone number; the trailing (?![0-9]) blocks longer runs.
    pattern: {
      source: "(?<!\\d[ .\\-])(?<![0-9-])(?!000|666|9[0-9]{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}(?![0-9])",
      flags: "",
    },
    reason: "Possible US Social Security Number in output. Do not include this value in generated code or logs.",
  },
  {
    id: "credit-card-number",
    category: "pii",
    severity: "medium",
    // Common PAN patterns: Visa (4xxx), Mastercard (51-55 / 2221-2720),
    // Amex (34/37). The (?<![0-9#a-fA-F]) lookbehind rejects hex-color / hash
    // contexts ("#4111..."); the `validate: luhn` post-check (run in scanForDlp)
    // rejects 16-digit build numbers / IDs that are not valid card numbers,
    // which is the dominant false-positive source for a digits-only regex.
    pattern: {
      source:
        "(?<![0-9#a-fA-F])(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|2(?:2[2-9][1-9]|[3-6][0-9]{2}|7[01][0-9]|720)[0-9]{12}|3[47][0-9]{13})(?![0-9])",
      flags: "",
    },
    validate: "luhn",
    reason: "Possible credit-card number in output. Do not include in generated code, logs, or responses.",
  },

  // ── PII (low severity — advisory only, never enforce-deny) ───────────────
  {
    id: "email-address",
    category: "pii",
    severity: "low",
    // Email addresses appear frequently in normal dev output (git log, npm info,
    // package.json). Low severity: warn in advisory mode only.
    // BOUNDED quantifiers (RFC 5321 local-part<=64, domain<=255, TLD<=24) so a
    // long in-class run with no '@' cannot drive quadratic backtracking (ReDoS).
    pattern: {
      source: "[A-Za-z0-9._%+\\-]{1,64}@[A-Za-z0-9.\\-]{1,255}\\.[A-Za-z]{2,24}",
      flags: "",
    },
    reason: "Email address in output. Verify this is not personally identifiable information before using it.",
  },
];

// Strings matching these patterns suppress a DLP finding — prevents FPs on
// documentation, example strings, and placeholder values.
export const DEFAULT_ALLOW_SNIPPETS = [
  /EXAMPLE/i,
  /PLACEHOLDER/i,
  /YOUR[_-]?(?:API[_-]?)?KEY/i,
  /INSERT[_-]?(?:YOUR)?[_-]?(?:TOKEN|KEY|SECRET)/i,
  /xxxx/i,
  /\*{4,}/,           // masked values like ****
  /redacted/i,
];

// ── Compilation ─────────────────────────────────────────────────────────────

export function compileDlpPolicy(raw) {
  if (!raw || raw.enabled === false) {
    return null;
  }
  const mode = raw.mode === "enforce" ? "enforce" : "advisory";
  const builtinEnabled = raw.disableBuiltin !== true;
  const patterns = [
    ...(builtinEnabled ? DLP_BUILTIN_PATTERNS : []),
    ...(Array.isArray(raw.customPatterns) ? raw.customPatterns : []),
  ].map(compileDlpPattern);

  const allowPatterns = [
    ...DEFAULT_ALLOW_SNIPPETS,
    ...(Array.isArray(raw.allowPatterns)
      ? raw.allowPatterns.map((p) => new RegExp(p.source ?? p, p.flags ?? "i"))
      : []),
  ];

  return { mode, patterns, allowPatterns };
}

function compileDlpPattern(raw) {
  // Compile with the global flag so scanForDlp can iterate ALL matches (a single
  // suppressed first match must not hide a real later one).
  const flags = (raw.pattern.flags ?? "").includes("g")
    ? raw.pattern.flags
    : `${raw.pattern.flags ?? ""}g`;
  return {
    id: String(raw.id ?? "custom"),
    category: String(raw.category ?? "unknown"),
    severity: normalizeSeverity(raw.severity),
    regex: new RegExp(raw.pattern.source, flags),
    validate: raw.validate === "luhn" ? luhnValid : null,
    reason: String(raw.reason ?? "Possible sensitive data detected."),
  };
}

function normalizeSeverity(s) {
  return ["critical", "high", "medium", "low"].includes(s) ? s : "medium";
}

// Luhn checksum — distinguishes a real card PAN from a random 16-digit build
// number / id. Strips non-digits first.
function luhnValid(value) {
  const digits = String(value).replace(/\D/g, "");
  if (digits.length < 13) {
    return false;
  }
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// ── Scanner ─────────────────────────────────────────────────────────────────

/**
 * Scan text for DLP findings.
 * @param {string} text  — tool output or other content to scan
 * @param {object} dlp   — compiled DLP policy from compileDlpPolicy
 * @returns {{ patternId, category, severity, reason }[]}
 */
export function scanForDlp(text, dlp) {
  if (!dlp || !text || !text.trim()) {
    return [];
  }

  const findings = [];
  for (const pattern of dlp.patterns) {
    // Iterate EVERY match for this pattern. A suppressed first match (e.g. an
    // `EXAMPLE` placeholder) must not hide a real later occurrence — checking
    // the allow-window per match closes that bypass.
    pattern.regex.lastIndex = 0;
    let m;
    let hit = false;
    while ((m = pattern.regex.exec(text)) !== null) {
      const value = m[0];
      // Avoid an infinite loop on a zero-width match.
      if (m.index === pattern.regex.lastIndex) {
        pattern.regex.lastIndex++;
      }
      // Optional structural validator (e.g. Luhn for card numbers).
      if (pattern.validate && !pattern.validate(value)) {
        continue;
      }
      const context = text.slice(Math.max(0, m.index - 100), m.index + value.length + 100);
      if (dlp.allowPatterns.some((allow) => allow.test(context))) {
        continue;
      }
      hit = true;
      break; // one finding per pattern is enough (don't inflate the count)
    }
    if (hit) {
      findings.push({
        patternId: pattern.id,
        category: pattern.category,
        severity: pattern.severity,
        reason: pattern.reason,
      });
    }
  }
  return findings;
}

/**
 * Map a list of DLP findings to a backend decision object.
 * In advisory mode always returns allow (context-only); in enforce mode maps
 * severity to deny/review/allow.
 */
export function dlpDecision(findings, mode) {
  if (!findings.length) {
    return null;
  }
  const highestSeverity = findings.reduce((h, f) => {
    const order = { low: 1, medium: 2, high: 3, critical: 4 };
    return (order[f.severity] ?? 0) > (order[h] ?? 0) ? f.severity : h;
  }, "low");

  const reason = `DLP: ${findings
    .slice(0, 3)
    .map((f) => `${f.patternId} (${f.severity})`)
    .join(", ")}${findings.length > 3 ? ` +${findings.length - 3} more` : ""}. ${findings[0].reason}`;

  if (mode === "enforce") {
    if (highestSeverity === "critical" || highestSeverity === "high") {
      return { decision: "deny", reason };
    }
    if (highestSeverity === "medium") {
      return { decision: "review", reason };
    }
    // low → advisory context only
    return { decision: "allow", reason };
  }

  // advisory mode: always allow, but surface the reason
  return { decision: "allow", reason };
}

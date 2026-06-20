# agt skill-signer (CI / pipeline tool — delivered separately)

This is the **external signer** for the skill supply-chain trust model. It is **not
part of the runtime plugin** and must **not** run on an agent's machine. CI (or an
HSM-backed signing service) runs it with a **private key the agent box never sees**.

## What it does

`sign.mjs <skillDir> --key <ci-private.pem>`:

1. Resolves the skill's **full transitive dependency tree** (`uv` for Python incl.
   PEP 723 inline; `npm` for Node) and CVE-scans it (`trivy` / `osv-scanner` /
   `pip-audit`, auto-detected — CI must provide them on `PATH`).
2. **Decides pass/fail** at `--threshold` (default `high`). A failing skill is
   **NOT signed** — there is no signed-but-vulnerable. *The signature is the pass.*
3. On pass, signs the attestation (Ed25519) and writes it **alongside the skill**
   as `.agt-attestation.json`. Distribute that file with the skill.

```bash
node sign.mjs ./skills/my-skill --key ./ci-private.pem            # PASS → writes .agt-attestation.json (exit 0)
node sign.mjs ./skills/my-skill --key ./ci-private.pem --threshold critical
#   FAIL (finding ≥ threshold, or unscannable) → exit 1, nothing signed
```

Exit codes: `0` signed (pass) · `1` not signed (findings/unscannable) · `2` usage.

## End-to-end setup (worked example)

**1. One time — create the signer keypair.** The private key lives only in CI / an
HSM; the public key is what agents trust. Ed25519 (these exact commands are tested):

```bash
openssl genpkey -algorithm ed25519 -out ci-private.pem      # SECRET — keep in CI/HSM only
openssl pkey -in ci-private.pem -pubout -out ci-public.pem  # public — distribute to agents
```

**2. In CI — scan + sign every skill on release.** CI must have `uv`/`npm` + a
scanner (`trivy`/`osv-scanner`/`pip-audit`) on `PATH`. Fail the build if a skill
doesn't pass (the signer exits non-zero, so no `.agt-attestation.json` is written):

```bash
for skill in skills/*/; do
  node tools/skill-signer/sign.mjs "$skill" --key "$CI_PRIVATE_KEY" --threshold high || exit 1
done
# commit/publish each skill's .agt-attestation.json ALONGSIDE the skill
```

**3. Deliver the public key to each agent host — out of band** (config management,
a secret store, a provisioned file). It is NOT bundled in the plugin.

**4. Configure the agent policy to trust it** (`~/.claude/agt/policy.json` or
`~/.config/opencode/agt/policy.json`):

```jsonc
"skillPolicies": {
  "mode": "enforce",
  "trustedSigners": ["/etc/agt/ci-public.pem"],  // PEM path or inline PEM (delivered in step 3)
  "requireSignature": true                        // STRICT: only CI-signed skills run.
                                                  // Omit/false → unsigned skills get a local
                                                  // scan + 1-day grace instead of being blocked.
}
```

**5. Result at runtime.** A skill that ships its CI `.agt-attestation.json` is
verified against the public key, bound to its current files, and allowed silently
(the durable tier). Tamper with the skill or the stamp, sign with the wrong key, or
ship no signature → in strict mode it's blocked; otherwise it falls back to a local
scan + 1-day stamp. (All five of these paths are covered by `selftest-skill-gate.mjs`.)

## Keys — the whole security model rests on key custody

- The **private key** (`--key`) lives only in CI / an HSM / a signing service. If it
  ever reaches an agent machine, the model collapses (a malicious skill could sign
  itself). Treat it like any release-signing key: rotate it, scope it, audit its use.
- The **public key** is delivered to agents **out of band** (config management, a
  secret, a provisioned file) and pointed at via `skillPolicies.trustedSigners`
  (a PEM string or a file path). It is **not** bundled in the plugin.

## How the agent verifies it

The runtime plugin reads the shipped `.agt-attestation.json`, verifies its Ed25519
signature against `trustedSigners`, checks it is bound to the skill's current files
and is within `maxAgeMs`, and only then allows the skill silently (the durable tier).
A skill with no valid CI signature falls back to a **local scan + 1-day** stamp
(weak, forgeable, time-boxed) unless `requireSignature: true` is set (strict).

## Honest limits

- The scan finds **known** CVEs (the scanner's DB) + known patterns — **not**
  novel/zero-day code. A clean signature means "CI's scanner found nothing known."
- Signing makes the verdict **unforgeable**, not **complete**. It is one layer of
  defense-in-depth, not a guarantee. A true execution boundary needs OS-level
  isolation; this is a cooperative guardrail.

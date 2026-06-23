# Changelog

All notable changes to `agt-opencode` (the AGT governance plugin and installer CLI
for OpenCode) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> [!NOTE]
> Releases before `1.0.0` are pre-release: behavior and policy schema may change.

## [Unreleased]

### Changed

- **Enforce by default.** The seeded default policy now ships in `enforce` mode
  rather than advisory. A finding at or above the configured severity threshold
  results in a deny/review decision instead of a context-only note. Apply the
  `advisory` profile (`agt-opencode policy apply --profile advisory`) for the
  previous behavior.
- **Honest-measurement relabeling.** Coverage and decision vocabulary was relabeled
  to state plainly what was actually verified — `transitive` (a resolver produced the
  full tree AND a real scanner scanned it) vs. `declared-only` vs. `unavailable`.
  An `unavailable` scan with zero findings is never treated as a clean silent-allow.
  Documentation reframed throughout as a cooperative guardrail, not a guarantee:
  security rests on the signing private key never reaching an agent box, and a local
  attacker with the user's privileges is out of scope.

### Added

- **`doctor` supply-chain toolchain probe.** `agt-opencode doctor` now reports which
  supply-chain tools are on PATH — `uv`, `npm`, `trivy`, `osv-scanner`, `pip-audit` —
  and states plainly which scan capabilities that enables (e.g. "Python transitive
  CVE scan: available via uv + trivy" / "unavailable — …"). When no transitive scan
  capability exists, it explains the consequence: CI-signed skills are unaffected, but
  unsigned skills cannot be cleared by a local scan and are reviewed/blocked in
  enforce mode. The probe reuses the engine's detection approach (spawn
  `<tool> --version`, bounded, never throws); the existing `doctor` output and
  exit-code behavior are unchanged, and the new section is also present in
  `--json` output (`supplyChainToolchain`).
- **Skill and dependency supply-chain governance.** A two-tier model governs what an
  autonomous agent pulls onto the host:
  - *Tier 1 (sync, deterministic):* parse the install command and any reachable
    manifest, then run cheap metadata checks that a CVE scanner is blind to —
    non-registry sources (`git+`, `file:`, bare URL), the operator allow/deny list,
    an unapproved-index guard (dependency confusion), and npm install-lifecycle
    scripts (install-time code execution). No network, no subprocess.
  - *Tier 2 (async, audit-only):* resolve the full transitive set (uv for Python
    incl. PEP 723 inline; npm for Node) and delegate the CVE scan to an installed
    scanner (trivy / osv-scanner / pip-audit, auto-detected). Surfaced via
    `agt-opencode skills audit <dir>`. Spawns are timeout-bounded and never throw;
    a missing tool degrades to `unavailable`.
- **Two-tier skill trust.** A skill that ships a CI-produced Ed25519 attestation
  (`.agt-attestation.json`) is verified against `skillPolicies.trustedSigners`, bound
  to its current files, and allowed silently (the durable tier). A skill with no
  valid CI signature falls back to a local scan plus a short (1-day) grace stamp —
  weak, time-boxed, and forgeable — unless `requireSignature: true` is set, which
  blocks unsigned skills outright.
- **`skill-signer` (external CI/HSM tool).** Resolves + CVE-scans a skill's
  transitive tree and, only on pass, signs the attestation. There is no
  signed-but-vulnerable: the signature *is* the pass. Ships separately and must never
  run on an agent box. See `tools/skill-signer/KEY-MANAGEMENT.md` for key custody,
  fleet distribution, rotation, and revocation.
- **Optional LLM-as-judge intent layer (`intentJudgePolicies`), off by default.** An
  opt-in layer that asks an LLM to assess the *intent* behind an action. It is
  additive-only (may raise strictness, never relax a deterministic deny), fail-safe
  to the deterministic verdict when the judge is unreachable/times out/errors, and
  does nothing unless an operator configures it.

### Removed

- **Cut FP-prone / out-of-scope checks** from the deterministic dependency layer:
  typosquat name-distance matching (a bespoke heuristic that reinvents, badly, what
  the registry/scanner ecosystem should own), the unpinned-dependency check (the
  lockfile's job), and license-deny (compliance, not security). The kept checks cover
  real risks a CVE scanner cannot see.

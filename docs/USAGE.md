# Usage — agt-opencode

Once installed (see [INSTALL.md](INSTALL.md)) and OpenCode is restarted, the
plugin works automatically — there is nothing to invoke per request. This page
covers what you'll *see*, the management CLI, and how to operate it day to day.

## What happens during a session

Every tool call, prompt, and tool result passes through the governance engine:

- **An allowed tool** (e.g. `read`, `glob`, `grep`, `list`, and under the default
  `balanced` profile also `write`/`edit`) runs normally — you won't notice
  anything.
- **A denied tool call** (e.g. `bash` running `rm -rf` or `Get-Content ~/.ssh/id_rsa`)
  is **aborted**: OpenCode reports that the call was blocked by AGT, with a
  reason.
- **A reviewed tool call** (e.g. `bash`, `webfetch`, `websearch`, `task`) is, in
  the current OpenCode build, also blocked — see *review→deny* below.
- **A flagged prompt** (looks like prompt injection) is rewritten to a neutral
  refusal asking you to restate the request cleanly.
- **Flagged tool output** (e.g. a web page containing "ignore previous
  instructions…") is suppressed or annotated as untrusted before the model sees
  it.
- **A skill being invoked** is gated **before it runs**: its manifests (incl.
  PEP 723 inline metadata) get metadata-hygiene + an attestation lookup, and — in
  the default `enforce` posture — a skill is silent-allowed only if it carries a
  fresh `scanned` attestation proving its full transitive dependency tree was
  resolved and scanned clean. An unverified or vulnerable skill is sent to review
  (or denied if a CVE/dangerous pattern was found). Run `skills audit` ahead of
  time (below) so the first real use is a cheap cache hit instead of a review.

### The review→deny behaviour (important)

OpenCode's interactive-permission hook (`permission.ask`) does not reliably fire
([opencode#7006](https://github.com/anomalyco/opencode/issues/7006)). When a
policy decision is `review`, there is no prompt to approve it, so the gate fails
**closed** and denies the call. Consequences:

- The default **`balanced`** profile is chosen precisely so the agent can still
  do core work (read + write/edit are *allowed*, not reviewed). Only
  `bash`/`webfetch`/`websearch`/`task` are reviewed → currently denied.
- If you need the agent to run shell/web freely, either widen `allowedTools` in
  your policy (you accept the risk) or switch to the **`advisory`** profile,
  which never blocks and only surfaces findings.

See [CONFIGURATION.md](CONFIGURATION.md) to change this.

## The management CLI

Invoke as `node bin/agt-opencode.mjs <command>` (or `agt-opencode <command>` if
the bin is on your PATH). Global option `--opencode-home <dir>` overrides the
config home for any command.

| Command | What it does |
|---|---|
| `install [--force-policy]` | Install the plugin bundle, seed a default policy (force = overwrite existing). |
| `update [--force-policy]` | Refresh the installed plugin in place. |
| `uninstall [--remove-policy]` | Remove the managed plugin (and optionally the policy). |
| `doctor [--json]` | Diagnose the install (plugin present? managed? policy valid? OpenCode on PATH?). |
| `policy path` | Print the resolved user policy path. |
| `policy show` | Print the active policy (user policy, or the bundled default if none). |
| `policy validate --file <path>` / `--profile <name>` | Validate a policy file or a bundled profile without applying it. |
| `policy apply --file <path>` / `--profile <name>` | Write a policy file or bundled profile to the active policy path. |
| `skills audit <dir> [<dir> …] [--scanner trivy\|osv-scanner\|pip-audit]` | Proactively scan one or more skill directories — resolve the full transitive dependency tree (`uv`/`npm`) and run a CVE scanner — then write a `scanned` attestation so the runtime gate is a cheap cache hit. |
| `-h, --help` · `-v, --version` | Help / installer version. |

### Common tasks

Check health:
```bash
agt-opencode doctor
agt-opencode doctor --json    # machine-readable, for CI
```

Inspect the active policy:
```bash
agt-opencode policy path
agt-opencode policy show
```

Switch profile (then restart OpenCode):
```bash
agt-opencode policy apply --profile strict     # lock down
agt-opencode policy apply --profile advisory   # never block, just warn
```

Validate a hand-edited policy before using it:
```bash
agt-opencode policy validate --file ./my-policy.json
agt-opencode policy apply    --file ./my-policy.json
```

> **Restart OpenCode after `apply`/`install`/`update`.** The plugin reads its
> policy at load time.

### Trusting skills — two tiers

A skill is trusted by a **stamp**. There are two ways to get one:

**1. CI-signed (strong, durable) — recommended for shared/published skills.** A
signer *outside the agent box* (CI / HSM) scans the skill and, only if it passes,
signs the attestation with a private key the agent never holds. The signed
`.agt-attestation.json` ships **alongside the skill**; the plugin verifies it with
the trusted **public key** you set in `skillPolicies.trustedSigners` (delivered out
of band — see [CONFIGURATION.md](CONFIGURATION.md#governance-extensions)). A local
attacker can't forge it. Run the **separate** signer in CI (never on an agent box):

```bash
node tools/skill-signer/sign.mjs <skill-dir> --key <ci-private.pem>   # PASS → .agt-attestation.json; FAIL → exit 1
```

**2. Local 1-day grace (weak, default) — for dev / unsigned skills.** An unsigned
skill is scanned locally on first use and, if clean, stamped for **1 day**
(forgeable but time-boxed). Pre-stamp it so the first real use is a cache hit, not an
inline scan:

```bash
agt-opencode skills audit ~/.config/opencode/skills/my-skill
agt-opencode skills audit ./skills/*                       # several at once
agt-opencode skills audit ./skills/x --scanner osv-scanner # force a scanner
```

Both resolve the **full transitive tree** (`uv` for Python incl. PEP 723 inline;
`npm` for Node) and run an auto-detected scanner (`trivy` / `osv-scanner` /
`pip-audit`). Set `skillPolicies.requireSignature: true` for **strict mode** — only
CI-signed skills run, no local fallback.

> **Fail-safe behavior:** a skill is stamped clean-eligible only when its deps were
> actually resolved transitively **and** scanned clean (or carry a valid CI
> signature). If `uv`/`npm` or a scanner is missing, the resolver errors, or a
> bare-import JS skill has no manifest, coverage is `unavailable` → **unverified =
> unsafe** (review/deny), never a false-clean. The scan catches *known* CVEs/patterns
> (not novel/zero-day); only the CI-signed tier resists a local forger.

## The audit log

Every decision is appended to `~/.config/opencode/agt/audit-log.json` as a
SHA-256 hash-chained record that **persists across sessions** (each run links to
the previous entry; it is not reset). `doctor` / `policy show` report whether the
chain verifies.

It is **tamper-evident, not tamper-proof** (keyless chain — see
[OVERVIEW.md](OVERVIEW.md#security-model--read-this)). For real non-repudiation,
forward entries to an append-only sink (SIEM / WORM).

## Debugging

Set `AGT_OPENCODE_DEBUG=1` to log hook payloads and decisions to stderr — useful
to confirm hook order and `permission.ask` behaviour against your OpenCode build:

```bash
AGT_OPENCODE_DEBUG=1 opencode run "list the files here"
```

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Agent can't run any shell/web commands | Expected under `balanced` due to review→deny. Widen `allowedTools` or use `advisory`. |
| Every tool call is denied with "failed to initialise" | The plugin failed to load (fail-closed). Run `agt-opencode doctor`; check Node ≥ 22 and that the bundle exists (`npm run build`). |
| `doctor` says "plugin not installed" | Run `agt-opencode install`, then restart OpenCode. |
| Policy changes have no effect | Restart OpenCode; confirm `policy path` points where you edited, and that no `.opencode/agt-policy.json` per-project override is shadowing it. |
| A skill is sent to review on every use | No fresh `scanned` attestation — run `agt-opencode skills audit <dir>`. If it still won't stamp clean, `uv`/`npm` or a scanner is missing on `PATH` (coverage `unavailable` = fail-safe), or the deps genuinely carry a finding. |
| `skills audit` reports coverage `unavailable` | The resolver (`uv`/`npm`) or scanner (`trivy`/`osv-scanner`/`pip-audit`) isn't on `PATH`, or a bare-import JS skill has no manifest. Install the tooling; this is fail-safe, not a false clean. |
| `npm install` TLS failure | Corporate CA — see the TLS note in [INSTALL.md](INSTALL.md). |

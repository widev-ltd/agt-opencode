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
| `npm install` TLS failure | Corporate CA — see the TLS note in [INSTALL.md](INSTALL.md). |

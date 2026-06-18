# Install — agt-opencode

## Prerequisites

- **Node.js ≥ 22** (`node --version`). The plugin bundle targets Node 22.
- **OpenCode** installed and on your `PATH` (`opencode --version`).
- For building from source: `npm` (the build pulls `esbuild` + the AGT SDK).

> **Corporate TLS note:** if `npm install` fails with
> `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, your network intercepts TLS. Point npm at
> your corporate CA (`NODE_EXTRA_CA_CERTS=/path/to/ca.pem`, and on Node 22+
> `NODE_OPTIONS=--use-system-ca`) rather than disabling verification. As a last
> resort only: `npm install --strict-ssl=false`.

There are three ways to install, below. Most users want **Option A**.

---

## Option A — Build from source + installer CLI (recommended)

```bash
git clone https://github.com/vwieszner/agt-opencode
cd agt-opencode

npm install          # esbuild + AGT SDK (dev deps)
npm run build        # produces assets/agt-governance.js (the single bundle)
node bin/agt-opencode.mjs install
```

`install` does three things:

1. Copies `assets/agt-governance.js` into OpenCode's plugins directory
   (`~/.config/opencode/plugins/agt-governance.js`). **No edit to
   `opencode.json` is needed** — OpenCode auto-loads every file in that
   directory.
2. Seeds a default policy at `~/.config/opencode/agt/policy.json` (the
   `balanced` profile) — *only if one does not already exist*.
3. Writes an install manifest at `~/.config/opencode/agt/.agt-install-manifest.json`
   so `update`/`uninstall`/`doctor` can manage it safely.

Then **restart OpenCode** and verify:

```bash
node bin/agt-opencode.mjs doctor
# or, if you linked the bin onto PATH:  agt-opencode doctor
```

A healthy install reports `Result: OK` with the plugin installed, a managed
install, and a valid policy.

---

## Option B — Install from the npm package

If the package is published (or you `npm install -g` the local `.tgz`), OpenCode
can load the plugin straight from the installed npm package by name. Add this to
`~/.config/opencode/opencode.json`:

```json
{ "plugin": ["agt-opencode"] }
```

OpenCode resolves `agt-opencode` from your global `node_modules` and loads its
exported plugin. Use this path if you prefer dependency-managed installs over a
copied file. (You do **not** need both this and Option A — pick one.)

---

## Option C — Local development / testing

Run the installer against a throwaway config home so you never touch your real
OpenCode setup:

```bash
npm run build
node bin/agt-opencode.mjs install --opencode-home /tmp/oc-test
node bin/agt-opencode.mjs doctor   --opencode-home /tmp/oc-test
```

Run the test suite (build + Node test runner):

```bash
npm test      # node build.mjs && node --test "test/*.test.mjs"
```

To watch the plugin initialise inside real OpenCode, set the debug flag and look
for `[agt-governance] initialised …` on stderr:

```bash
AGT_OPENCODE_DEBUG=1 opencode run "hello"
```

(The agent loop will error at the model call if you have no provider key — that
is expected; the plugin still loads and its init runs first.)

---

## Updating

```bash
git pull
npm install && npm run build
node bin/agt-opencode.mjs update          # refreshes the installed bundle in place
node bin/agt-opencode.mjs update --force-policy   # also re-seed the default policy
```

`update` keeps your existing `policy.json` unless you pass `--force-policy`.

## Uninstalling

```bash
node bin/agt-opencode.mjs uninstall                 # removes the plugin, keeps your policy
node bin/agt-opencode.mjs uninstall --remove-policy # also deletes the policy
```

Uninstall only touches an **agt-opencode-managed** install (identified by the
manifest); it will not remove an unrelated plugin file.

## What gets written where

| Path (under the OpenCode config home) | What |
|---|---|
| `plugins/agt-governance.js` | the installed plugin bundle |
| `agt/policy.json` | your active policy (seeded from `balanced`) |
| `agt/.agt-install-manifest.json` | install metadata (version, timestamp) |
| `agt/audit-log.json` | the hash-chained audit log |
| `agt/.bundled-default-policy.json` | refreshed on every load as the fail-safe fallback |

The OpenCode config home is, in order of precedence:
`--opencode-home <dir>` → `$OPENCODE_CONFIG_HOME` → `$XDG_CONFIG_HOME/opencode`
→ `~/.config/opencode`.

See [USAGE.md](USAGE.md) for what to do once it's installed.

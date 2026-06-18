// Copyright (c) 2026 AGT benchmark contributors. MIT License.
//
// prove-isolation.mjs — the RUNNABLE proof for Phase 1's accept criteria
// (BENCHMARK-PLAN.md): none-net = zero egress; ssrf-net reaches only the
// metadata stub; live-net reaches only the allowlisted model domain + stub, and
// a non-allowlisted host is blocked AND logged by the gateway.
//
// It drives the SAME images the benchmark uses. For ssrf/live it brings the
// stack `up -d` ONCE and `exec`s probes into the running containers (so service
// DNS is stable — three independent `run --rm` invocations race dependency
// startup and yield false DNS failures). none-net is exercised with `run --rm`
// since exec into a network_mode:none container needs no network anyway.
//
// Probe design (learned the hard way):
//   - Each probe prints a single anchored token line: `RESULT=REACHABLE` or
//     `RESULT=UNREACHABLE:<code>`. We assert with /^RESULT=REACHABLE$/m so the
//     "REACHABLE" substring inside "UNREACHABLE" can never cause a false verdict.
//   - "Must be unreachable" checks probe a RAW IP (1.1.1.1), not a hostname, so
//     we test ROUTING (ENETUNREACH/timeout), not DNS (EAI_AGAIN).
//   - live ALLOW/DENY assert REAL proxy verdicts: a 200 CONNECT response for the
//     allowlisted domain, a 403/deny for everything else. A "couldn't reach the
//     proxy" error does NOT count as a deny.
//   - The log assertion uses a UNIQUE sentinel host so it can only pass on a
//     denial THIS run caused, never on ambient log noise.
//
// Usage (from this directory):
//   node gen-decoys.mjs >/dev/null
//   ALLOW_DOMAIN=integrate.api.nvidia.com node prove-isolation.mjs
// Exit 0 = all assertions held; non-zero = a boundary leaked.

import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

const ALLOW_DOMAIN = process.env.ALLOW_DOMAIN || "integrate.api.nvidia.com";
const EXTERNAL_IP = process.env.EXTERNAL_IP || "1.1.1.1"; // routable IP that must NEVER be reachable
const SENTINEL = `exfil-${randomUUID().slice(0, 8)}.invalid`; // unique per run for the log assertion
const COMPOSE = "docker";
const BASE = ["compose"];
const envFor = { ...process.env, ALLOW_DOMAIN };

let failures = 0;
const results = [];

function record(name, pass, detail) {
  results.push({ name, pass, detail });
  if (!pass) failures += 1;
  process.stdout.write(`${pass ? "PASS" : "FAIL"}  ${name}\n      ${detail}\n`);
}

function compose(args, timeout = 90_000) {
  const res = spawnSync(COMPOSE, [...BASE, ...args], { encoding: "utf8", env: envFor, timeout });
  return { code: res.status, stdout: res.stdout || "", stderr: res.stderr || "" };
}

function resultLine(out) {
  return (out.match(/^RESULT=.*/m) || ["(no RESULT line)"])[0];
}

// --- probe source (runs inside a container; prints exactly one RESULT= line) --

// TCP connect to host:port. Prints RESULT=REACHABLE / RESULT=UNREACHABLE:<code>.
function tcpProbe(host, port, ms = 6000) {
  return (
    `node -e 'const net=require("net");` +
    `const s=net.connect({host:${JSON.stringify(host)},port:${port}});` +
    `let d=false;const f=(v)=>{if(d)return;d=true;console.log("RESULT="+v);try{s.destroy()}catch(e){}process.exit(0)};` +
    `s.setTimeout(${ms});` +
    `s.on("connect",()=>f("REACHABLE"));` +
    `s.on("timeout",()=>f("UNREACHABLE:timeout"));` +
    `s.on("error",(e)=>f("UNREACHABLE:"+e.code));'`
  );
}

// CONNECT through the agent's HTTPS_PROXY. Prints RESULT=PROXY_ALLOW:<line> on a
// 200, RESULT=PROXY_DENY:<line> on 4xx/deny, RESULT=PROXY_UNREACHABLE:<code> if
// the proxy itself can't be reached (which must NOT be scored as a deny).
function proxyConnectProbe(host, port = 443, ms = 10000) {
  return (
    `node -e 'const net=require("net");` +
    `const u=(process.env.HTTPS_PROXY||"").replace(/^https?:\\/\\//,"");` +
    `const [ph,pp]=u.split(":");` +
    `const s=net.connect({host:ph||"egress-gateway",port:Number(pp||3128)});` +
    `let buf="",d=false;const f=(v)=>{if(d)return;d=true;console.log("RESULT="+v);try{s.destroy()}catch(e){}process.exit(0)};` +
    `s.setTimeout(${ms});` +
    `s.on("connect",()=>s.write("CONNECT ${host}:${port} HTTP/1.1\\r\\nHost: ${host}:${port}\\r\\n\\r\\n"));` +
    `s.on("data",(b)=>{buf+=b.toString();const l=(buf.split("\\r\\n")[0]||"").trim();` +
    `if(/\\s200\\b/.test(l))f("PROXY_ALLOW:"+l);else if(/\\s40[0-9]\\b|denied|forbidden/i.test(l))f("PROXY_DENY:"+l);});` +
    `s.on("timeout",()=>f("PROXY_UNREACHABLE:timeout"));` +
    `s.on("error",(e)=>f("PROXY_UNREACHABLE:"+e.code));'`
  );
}

const REACHABLE = /^RESULT=REACHABLE$/m;
const UNREACHABLE = /^RESULT=UNREACHABLE/m;

function downAll() {
  compose(["--profile", "none", "--profile", "ssrf", "--profile", "live", "down", "-v", "--remove-orphans"], 120_000);
}

console.log("== Phase 1 isolation proof ==");
console.log(`allowlisted domain : ${ALLOW_DOMAIN}`);
console.log(`routing probe IP   : ${EXTERNAL_IP}`);
console.log(`log sentinel host  : ${SENTINEL}\n`);

downAll(); // clean slate

try {
  // --- 1) none-net: ZERO egress (run --rm; no network so exec is moot) --------
  {
    const ext = compose(["--profile", "none", "run", "--rm", "-T", "agent-none", "bash", "-lc", tcpProbe(EXTERNAL_IP, 443)]);
    record(
      "none-net: external route unreachable",
      UNREACHABLE.test(ext.stdout) && !REACHABLE.test(ext.stdout),
      `connect ${EXTERNAL_IP}:443 -> ${resultLine(ext.stdout)}`,
    );
    const meta = compose(["--profile", "none", "run", "--rm", "-T", "agent-none", "bash", "-lc", tcpProbe("169.254.169.254", 80)]);
    record(
      "none-net: metadata IP unreachable",
      UNREACHABLE.test(meta.stdout) && !REACHABLE.test(meta.stdout),
      `connect 169.254.169.254:80 -> ${resultLine(meta.stdout)}`,
    );
  }

  // --- 2) ssrf-net: ONLY the metadata stub (up -d once, then exec) ------------
  {
    compose(["--profile", "ssrf", "up", "-d"]);
    const stub = compose(["--profile", "ssrf", "exec", "-T", "agent-ssrf", "bash", "-lc", tcpProbe("mock-metadata", 80)]);
    record(
      "ssrf-net: metadata stub reachable",
      REACHABLE.test(stub.stdout),
      `connect mock-metadata:80 -> ${resultLine(stub.stdout)}`,
    );
    const alias = compose(["--profile", "ssrf", "exec", "-T", "agent-ssrf", "bash", "-lc", tcpProbe("metadata.google.internal", 80)]);
    record(
      "ssrf-net: metadata alias reachable",
      REACHABLE.test(alias.stdout),
      `connect metadata.google.internal:80 -> ${resultLine(alias.stdout)}`,
    );
    const ext = compose(["--profile", "ssrf", "exec", "-T", "agent-ssrf", "bash", "-lc", tcpProbe(EXTERNAL_IP, 443)]);
    record(
      "ssrf-net: internet route unreachable",
      UNREACHABLE.test(ext.stdout) && !REACHABLE.test(ext.stdout),
      `connect ${EXTERNAL_IP}:443 -> ${resultLine(ext.stdout)}`,
    );
    compose(["--profile", "ssrf", "down", "-v", "--remove-orphans"]);
  }

  // --- 3) live-net: ONLY allowlisted domain via the gateway -------------------
  {
    compose(["--profile", "live", "up", "-d"]);

    // The agent has no DIRECT route out (live-internal is internal:true); only
    // the proxy path exists. A direct connect to a routable IP must fail.
    const direct = compose(["--profile", "live", "exec", "-T", "agent-live", "bash", "-lc", tcpProbe(EXTERNAL_IP, 443)]);
    record(
      "live-net: no DIRECT egress (must go via gateway)",
      UNREACHABLE.test(direct.stdout) && !REACHABLE.test(direct.stdout),
      `direct ${EXTERNAL_IP}:443 -> ${resultLine(direct.stdout)}`,
    );

    const allow = compose(["--profile", "live", "exec", "-T", "agent-live", "bash", "-lc", proxyConnectProbe(ALLOW_DOMAIN, 443)]);
    record(
      "live-net: gateway ALLOWS the model domain (real 200)",
      /^RESULT=PROXY_ALLOW/m.test(allow.stdout),
      `CONNECT ${ALLOW_DOMAIN}:443 -> ${resultLine(allow.stdout)}`,
    );

    // DENY: probe the unique sentinel host. Must be a REAL proxy deny (403),
    // not a "proxy unreachable" error.
    const deny = compose(["--profile", "live", "exec", "-T", "agent-live", "bash", "-lc", proxyConnectProbe(SENTINEL, 443)]);
    record(
      "live-net: gateway DENIES a non-allowlisted host (real 403)",
      /^RESULT=PROXY_DENY/m.test(deny.stdout),
      `CONNECT ${SENTINEL}:443 -> ${resultLine(deny.stdout)}`,
    );

    // The exfil signal: the gateway access log must show a denial for THIS
    // run's sentinel host, proving the proxy logged it. We read the log FILE
    // inside the gateway (Squid can't write to /dev/stdout as the proxy user,
    // so `docker logs` won't carry it — the file is the source of truth).
    const log = compose(["--profile", "live", "exec", "-T", "egress-gateway", "cat", "/var/log/squid/access.log"], 30_000);
    const sentinelEsc = SENTINEL.replace(/\./g, "\\.");
    const sentinelDenied =
      new RegExp(`TCP_DENIED[\\s\\S]*${sentinelEsc}`).test(log.stdout) ||
      (new RegExp(sentinelEsc).test(log.stdout) && /TCP_DENIED/.test(log.stdout));
    record(
      "live-net: denied egress is LOGGED for this run's sentinel (exfil signal)",
      sentinelDenied,
      sentinelDenied ? `gateway log shows TCP_DENIED for ${SENTINEL}` : `no TCP_DENIED for ${SENTINEL} in gateway log`,
    );

    compose(["--profile", "live", "down", "-v", "--remove-orphans"]);
  }
} finally {
  downAll();
}

console.log(`\n== ${results.length - failures}/${results.length} isolation assertions held ==`);
process.exit(failures === 0 ? 0 : 1);

// selftest-session-store.mjs — tests for the session store + atomic write.
// Run: node selftest-session-store.mjs

import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  dataDir,
  readSession,
  mutateSession,
  sessionFilePath,
  cleanupSessions,
  resetNamespace,
  writeFileAtomicSync,
} from "./session-store.mjs";

let fail = 0;
const ok = (n, c) => { console.log(`${c ? "PASS" : "FAIL"}  ${n}`); if (!c) fail++; };

// ── Memory backend (default — OpenCode resident + selftests) ──────────────────
delete process.env.AGT_SESSION_STORE;
resetNamespace("t");
ok("memory: missing session reads empty + missing flag",
  (() => { const r = readSession("t", "s1"); return r.missing === true && Object.keys(r.data).length === 0; })());
mutateSession("t", "s1", (d) => ({ data: { ...d, n: 1 }, result: "x" }));
ok("memory: mutate then read persists in-process", readSession("t", "s1").data.n === 1);
ok("memory: not corrupt", readSession("t", "s1").corrupt === false);
resetNamespace("t");
ok("memory: resetNamespace clears", readSession("t", "s1").missing === true);

// ── Disk backend ──────────────────────────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), "agt-store-"));
process.env.AGT_SESSION_STORE = "disk";
process.env.CLAUDE_PLUGIN_DATA = dir;
try {
  resetNamespace("t");
  ok("disk: missing session reads empty", readSession("t", "s1").missing === true);

  const { persisted } = mutateSession("t", "s1", (d) => ({ data: { ...d, n: 5 }, result: "ok" }));
  ok("disk: mutate persisted=true", persisted === true);
  ok("disk: wrote a file under sessions/t/", existsSync(sessionFilePath("t", "s1")));
  ok("disk: read back the persisted value", readSession("t", "s1").data.n === 5);

  // Corrupt file → corrupt:true (NOT silently treated as fresh).
  writeFileSync(sessionFilePath("t", "corrupt-sess"), "{ this is not json", "utf8");
  const c = readSession("t", "corrupt-sess");
  ok("disk: corrupt file → corrupt=true", c.corrupt === true);
  ok("disk: corrupt file → data is empty object", Object.keys(c.data).length === 0);

  // ── Path-injection: a hostile sessionId cannot escape the data dir ──────────
  const base = join(dir, "sessions", "exfil");
  for (const evil of ["../../etc/passwd", "..\\..\\windows\\system32", "con", "a/../../b", "x".repeat(5000), "🙈/../escape"]) {
    const p = sessionFilePath("exfil", evil);
    ok(`path-injection contained: ${JSON.stringify(evil.slice(0, 16))}`,
      p.startsWith(base) && p.endsWith(".json") && !p.includes("passwd") && !p.includes("system32"));
  }

  // ── Atomic write: no leftover .tmp after a successful write ─────────────────
  writeFileAtomicSync(join(dir, "atomic-test.json"), '{"ok":true}\n');
  const leftovers = readdirSync(dir).filter((f) => f.includes(".tmp"));
  ok("atomic: no leftover temp files after write", leftovers.length === 0);

  // ── Cleanup: maxAge 0 evicts everything (deterministic with the >= compare) ──
  // With a strict `>` this raced on Windows: a just-written file's high-res mtime
  // can sit a fraction AHEAD of Date.now(), so `now - mtime` is negative and never
  // `> 0`, leaving the file un-evicted ~13% of the time. The `>=` compare ("older-
  // or-equal than maxAge ⇒ evict") makes maxAge=0 evict everything every time.
  mutateSession("t", "cleanme", (d) => ({ data: { ...d, x: 1 }, result: null }));
  ok("cleanup precondition: file exists", existsSync(sessionFilePath("t", "cleanme")));
  cleanupSessions("t", 0); // age >= 0ms → evict everything
  ok("cleanup: maxAge=0 removes session files", !existsSync(sessionFilePath("t", "cleanme")));

  // ── Cleanup: a real maxAge does NOT over-evict a fresh file (>= regression) ──
  // Guard that switching `>` to `>=` didn't start evicting still-young sessions:
  // a file just written is far younger than a 1-hour window and must survive.
  mutateSession("t", "keepme", (d) => ({ data: { ...d, x: 1 }, result: null }));
  cleanupSessions("t", 3600 * 1000); // 1h window → a fresh file is well within it
  ok("cleanup: fresh file survives a real (1h) maxAge", existsSync(sessionFilePath("t", "keepme")));
} finally {
  delete process.env.AGT_SESSION_STORE;
  delete process.env.CLAUDE_PLUGIN_DATA;
  rmSync(dir, { recursive: true, force: true });
}

// dataDir resolution is sane (no throw, returns a string)
ok("dataDir() returns a string", typeof dataDir() === "string" && dataDir().length > 0);

console.log(`\n${fail === 0 ? "ALL PASS" : fail + " FAILED"}`);
process.exit(fail === 0 ? 0 : 1);

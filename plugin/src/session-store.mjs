// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// session-store.mjs — shared persistence layer for the stateful governance
// extensions (exfil, rate-limit) plus the atomic-write primitive reused by the
// audit log.
//
// WHY THIS EXISTS:
//   Claude Code invokes the hook as a FRESH PROCESS per event (PreToolUse,
//   PostToolUse, ...). Module-level in-memory Maps therefore do NOT survive
//   between events on CC — so exfil tracking (populated on PostToolUse) and
//   rate-limit counters (incremented per PreToolUse) were silently inert there.
//   OpenCode is an in-process resident plugin, so its module state DOES persist.
//
//   This store gives both extensions a backend selected at runtime:
//     AGT_SESSION_STORE=disk  → per-session files on disk (Claude Code)
//     unset / "memory"        → module-level Maps (OpenCode resident; tests)
//   The public API is SYNCHRONOUS because the callers (checkRateLimit,
//   trackSecretsFromOutput, checkForExfil) are synchronous and the selftests
//   depend on that. The disk backend uses *Sync fs calls, consistent with the
//   existing audit reader (readFileSync in policy.mjs).
//
// SAFETY:
//   - Per-session file (sha256(sessionId) namespaced) so concurrent CC hook
//     processes for DIFFERENT sessions never contend, and a hostile sessionId
//     ("../", NUL, CON, oversized, unicode) can never escape the data dir.
//   - Atomic writes (temp file + rename) so a torn write never corrupts state.
//   - readSession distinguishes MISSING (fresh) from CORRUPT (parse failed) so
//     callers can fail loud on corruption rather than silently.

import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { mkdir, rename, writeFile, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

// ── Atomic write primitive (shared with the audit log) ───────────────────────

/**
 * Atomically write `contents` to `path`: write to a unique temp file in the SAME
 * directory (guarantees same volume → rename is atomic on POSIX and NTFS, no
 * EXDEV), then rename over the target. The PID+UUID temp suffix prevents two
 * concurrent writers from clobbering each other's temp file.
 */
export function writeFileAtomicSync(path, contents) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`;
  try {
    writeFileSync(tmp, contents, "utf-8");
    renameSync(tmp, path);
  } catch (error) {
    try {
      unlinkSync(tmp);
    } catch {
      // best-effort cleanup; ignore
    }
    throw error;
  }
}

/** Async twin of writeFileAtomicSync (for the async recordAudit path). */
export async function writeFileAtomic(path, contents) {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`;
  try {
    await writeFile(tmp, contents, "utf-8");
    await rename(tmp, path);
  } catch (error) {
    try {
      await unlink(tmp);
    } catch {
      // best-effort cleanup; ignore
    }
    throw error;
  }
}

// ── Cross-process single-writer lock (used by the audit append) ──────────────
//
// A short-lived advisory lock keyed on `targetPath`: create `${targetPath}.lock`
// with O_CREAT|O_EXCL (an atomic test-and-set on POSIX and NTFS). It serializes
// writers ACROSS PROCESSES — the reason it exists is Claude Code's per-event
// process model, where two concurrent same-session hooks would otherwise both
// read the same previous hash and fork the audit chain.
//
// Failure philosophy (matches the audit log's best-effort contract):
//   - A crashed holder must not deadlock the lock: a lock older than `staleMs`
//     is reclaimed. A stale lock that CANNOT be removed (e.g. it is a directory,
//     or a permission error) must NOT cause a spin — acquisition still honors
//     the deadline and returns fn(false). (Regression guard: an un-removable
//     stale lock previously looped forever because the reclaim branch did an
//     unconditional `continue` that skipped the deadline check.)
//   - If the lock cannot be acquired within `timeoutMs`, the callback runs with
//     `acquired=false` so the CALLER decides what to do. The audit log must
//     NEVER block — let alone deny — a tool decision; recordAudit responds to
//     acquired=false by SKIPPING the entry rather than appending off a possibly
//     stale previous-hash, so the verifiable chain never forks.
// The callback MUST be synchronous so the locked region completes atomically
// within a single tick (no interleaving on the resident OpenCode host).

function sleepSync(ms) {
  try {
    // Block the thread without busy-spinning. The wait essentially never fires
    // in practice — the locked region is microseconds — so this only matters
    // under genuine cross-process contention or after a crash.
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch {
    // SharedArrayBuffer unavailable (unusual): fall back to a short busy wait.
    const until = Date.now() + ms;
    while (Date.now() < until) { /* spin */ }
  }
}

/**
 * Run `fn(acquired)` while holding an exclusive lock on `${targetPath}.lock`.
 * `acquired` is true when the lock was held, false when it timed out and `fn`
 * is running best-effort without it. Never throws on lock I/O; the lock is
 * always released in a finally.
 */
export function withFileLock(targetPath, fn, { timeoutMs = 750, staleMs = 10000, retryMs = 15 } = {}) {
  const lockPath = `${targetPath}.lock`;
  const deadline = Date.now() + timeoutMs;
  let fd;
  for (;;) {
    try {
      fd = openSync(lockPath, "wx"); // O_CREAT | O_EXCL | O_WRONLY → fails if held
      break;
    } catch (error) {
      if (error?.code !== "EEXIST") {
        // Unexpected (e.g. parent dir vanished): run best-effort, unlocked.
        return fn(false);
      }
      // Best-effort reclaim of a stale lock left by a crashed holder. Only
      // `continue` (retry the open immediately) when the lock was ACTUALLY
      // removed — an un-removable stale lock (a directory, a permission error)
      // must fall through to the deadline check + sleep below so acquisition
      // can never spin forever.
      try {
        const st = statSync(lockPath);
        if (Date.now() - st.mtimeMs > staleMs) {
          try {
            unlinkSync(lockPath);
            continue; // reclaimed → retry the open
          } catch {
            // un-removable (e.g. a directory) → give up reclaiming; honor deadline
          }
        }
      } catch {
        // Lock vanished/unstatable between open and stat → fall through; a short
        // sleep before the next attempt cannot cause a hang.
      }
      if (Date.now() >= deadline) {
        return fn(false); // give up the lock; proceed best-effort
      }
      sleepSync(retryMs);
    }
  }
  try {
    return fn(true);
  } finally {
    // Close before unlink (Windows cannot unlink a handle opened without
    // FILE_SHARE_DELETE); both are best-effort.
    try { closeSync(fd); } catch { /* ignore */ }
    try { unlinkSync(lockPath); } catch { /* ignore */ }
  }
}

// ── Data dir resolution (mirrors agt-hook.mjs) ───────────────────────────────

export function dataDir() {
  if (process.env.CLAUDE_PLUGIN_DATA) {
    return String(process.env.CLAUDE_PLUGIN_DATA);
  }
  if (process.env.AGT_COPILOT_AUDIT_PATH) {
    return dirname(String(process.env.AGT_COPILOT_AUDIT_PATH));
  }
  return join(homedir(), ".claude", "agt");
}

function useDisk() {
  return String(process.env.AGT_SESSION_STORE ?? "").toLowerCase() === "disk";
}

/**
 * Per-session file path. The sessionId is sha256-hashed (and truncated) so a
 * hostile or malformed sessionId can never produce a path-traversal, a
 * Windows-reserved name, or an oversized filename.
 */
export function sessionFilePath(namespace, sessionId) {
  const ns = String(namespace).replace(/[^a-z0-9_-]/gi, "");
  const hash = createHash("sha256").update(String(sessionId)).digest("hex").slice(0, 32);
  return join(dataDir(), "sessions", ns, `${hash}.json`);
}

// A per-session DIRECTORY (one file per item) — used by the append-only item API
// below so concurrent writers of DIFFERENT items never lose each other's writes.
export function sessionDirPath(namespace, sessionId) {
  const ns = String(namespace).replace(/[^a-z0-9_-]/gi, "");
  const hash = createHash("sha256").update(String(sessionId)).digest("hex").slice(0, 32);
  return join(dataDir(), "sessions", ns, hash);
}

// ── Memory backend (OpenCode resident + tests) ───────────────────────────────

// Map<namespace, Map<sessionId, data>>
const _mem = new Map();
// Map<namespace, Map<sessionId, Map<itemKey, item>>> — for the item API.
const _memItems = new Map();

function memNs(namespace) {
  let m = _mem.get(namespace);
  if (!m) {
    m = new Map();
    _mem.set(namespace, m);
  }
  return m;
}

// ── Public store API (sync) ──────────────────────────────────────────────────

/**
 * Read a session's state.
 * @returns {{ data: object, corrupt: boolean, missing: boolean }}
 *   data is always a plain object ({} when missing/corrupt). `corrupt` is true
 *   ONLY when a present file failed to parse — callers that must fail loud on
 *   lost state (exfil) key off this.
 */
export function readSession(namespace, sessionId) {
  if (!useDisk()) {
    const m = memNs(namespace);
    const data = m.get(String(sessionId));
    return { data: data ? clone(data) : {}, corrupt: false, missing: data === undefined };
  }
  const path = sessionFilePath(namespace, sessionId);
  if (!existsSync(path)) {
    return { data: {}, corrupt: false, missing: true };
  }
  try {
    const parsed = JSON.parse(readFileSync(path, "utf-8"));
    if (parsed && typeof parsed === "object") {
      return { data: parsed, corrupt: false, missing: false };
    }
    return { data: {}, corrupt: true, missing: false };
  } catch {
    // Present but unparseable → corrupt (NOT silently treated as fresh).
    return { data: {}, corrupt: true, missing: false };
  }
}

/**
 * Read-modify-write a session's state.
 * @param fn (data) => { data: newData, result } — receives the current state,
 *   returns the new state to persist plus an arbitrary result to return.
 * @returns {{ result: any, persisted: boolean, corrupt: boolean }}
 *   persisted=false means the write failed (caught, not thrown) — callers must
 *   treat this as a soft degradation, never let it deny every tool.
 */
export function mutateSession(namespace, sessionId, fn) {
  const { data, corrupt } = readSession(namespace, sessionId);
  const { data: newData, result } = fn(data);

  if (!useDisk()) {
    memNs(namespace).set(String(sessionId), clone(newData ?? {}));
    return { result, persisted: true, corrupt };
  }
  try {
    writeFileAtomicSync(sessionFilePath(namespace, sessionId), `${JSON.stringify(newData ?? {})}\n`);
    return { result, persisted: true, corrupt };
  } catch {
    // Disk full / permission / transient: do NOT throw into the policy path.
    return { result, persisted: false, corrupt };
  }
}

// ── Append-only item API (conflict-free under concurrency) ────────────────────
// For grow-only sets (exfil tracked secrets): one file per item keyed by a hash
// of the item key. Concurrent writers of DIFFERENT items write DIFFERENT files,
// so no read-modify-write race can lose an item (unlike mutateSession on a
// single shared file). Same item → same file (idempotent).

function itemFileName(itemKey) {
  return `${createHash("sha256").update(String(itemKey)).digest("hex").slice(0, 32)}.json`;
}

/** Persist one item under a session. Returns {persisted}. Never throws. */
export function appendSessionItem(namespace, sessionId, itemKey, item) {
  if (!useDisk()) {
    let nsm = _memItems.get(namespace);
    if (!nsm) { nsm = new Map(); _memItems.set(namespace, nsm); }
    let sm = nsm.get(String(sessionId));
    if (!sm) { sm = new Map(); nsm.set(String(sessionId), sm); }
    sm.set(String(itemKey), clone(item));
    return { persisted: true };
  }
  try {
    writeFileAtomicSync(join(sessionDirPath(namespace, sessionId), itemFileName(itemKey)), `${JSON.stringify(item)}\n`);
    return { persisted: true };
  } catch {
    return { persisted: false };
  }
}

/**
 * Read all items for a session. Returns {items, corrupt}. `corrupt` is true if a
 * present item file failed to parse (caller may fail loud). A MISSING dir is the
 * normal "nothing tracked yet" case → {items:[], corrupt:false}.
 * Touches the session dir mtime so an actively-checked session is not evicted by
 * age-based cleanup while it is still in use.
 */
export function readSessionItems(namespace, sessionId) {
  if (!useDisk()) {
    const sm = _memItems.get(namespace)?.get(String(sessionId));
    return { items: sm ? [...sm.values()].map(clone) : [], corrupt: false };
  }
  const dir = sessionDirPath(namespace, sessionId);
  if (!existsSync(dir)) {
    return { items: [], corrupt: false };
  }
  let corrupt = false;
  const items = [];
  try {
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".json")) continue;
      try {
        items.push(JSON.parse(readFileSync(join(dir, f), "utf-8")));
      } catch {
        corrupt = true;
      }
    }
    // keep-alive: refresh the dir mtime so cleanup doesn't evict a live session
    try { const now = new Date(); utimesSync(dir, now, now); } catch { /* ignore */ }
  } catch {
    return { items: [], corrupt: true };
  }
  return { items, corrupt };
}

/**
 * Best-effort age-based eviction of a namespace's session files (disk backend).
 * Also enforces a hard file-count cap (oldest-by-mtime evicted first). No-op on
 * the memory backend (the resident host caps its own collections).
 *
 * AGE COMPARISON is `>=` ("older-or-equal than maxAge ⇒ evict") over a
 * NON-NEGATIVE age (`Math.max(0, now - mtime)`): with maxAgeMs=0 EVERYTHING is
 * evicted, deterministically. Two Windows races motivated this:
 *   1. A strict `>` never evicts at maxAge=0 even for a normal positive age.
 *   2. A just-written file's high-resolution mtimeMs (sub-millisecond fraction)
 *      can read as fractionally NEWER than the integer-truncated `now` captured
 *      at the top of this function, making `now - mtime` slightly NEGATIVE. A
 *      raw `>= maxAgeMs(0)` would then be `(-0.4 >= 0)` → false and skip the
 *      eviction ~a few % of the time. Clamping the age to >= 0 means a file is
 *      never treated as "from the future"; at maxAge=0 the age is exactly 0 and
 *      is evicted every time. For any real (positive) age the clamp is a no-op.
 */
export function cleanupSessions(namespace, maxAgeMs = 24 * 3600 * 1000, maxFiles = 5000) {
  if (!useDisk()) {
    return;
  }
  const ns = String(namespace).replace(/[^a-z0-9_-]/gi, "");
  const dir = join(dataDir(), "sessions", ns);
  if (!existsSync(dir)) {
    return;
  }
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  const now = Date.now();
  const remove = (p, isDir) => {
    try { isDir ? rmSync(p, { recursive: true, force: true }) : unlinkSync(p); } catch { /* ignore */ }
  };
  const stats = [];
  for (const ent of entries) {
    // Handle both single-file sessions (rate-limit) and item DIRECTORIES (exfil).
    const isDir = ent.isDirectory();
    if (!isDir && !ent.name.endsWith(".json")) continue;
    const p = join(dir, ent.name);
    try {
      const st = statSync(p);
      // Clamp the age to >= 0 so a sub-millisecond "future" mtime (NTFS high-res
      // mtime vs integer-truncated `now`) cannot flip the comparison negative and
      // skip a maxAge=0 eviction. For any real positive age this is a no-op.
      const ageMs = Math.max(0, now - st.mtimeMs);
      if (ageMs >= maxAgeMs) {
        remove(p, isDir);
      } else {
        stats.push({ p, mtime: st.mtimeMs, isDir });
      }
    } catch {
      // ignore unreadable entry
    }
  }
  if (stats.length > maxFiles) {
    stats.sort((a, b) => a.mtime - b.mtime);
    for (const { p, isDir } of stats.slice(0, stats.length - maxFiles)) {
      remove(p, isDir);
    }
  }
}

/** Clear a namespace entirely (both backends) — used by the reset* test helpers. */
export function resetNamespace(namespace) {
  _mem.delete(namespace);
  _memItems.delete(namespace);
  if (useDisk()) {
    const ns = String(namespace).replace(/[^a-z0-9_-]/gi, "");
    const dir = join(dataDir(), "sessions", ns);
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
}

function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

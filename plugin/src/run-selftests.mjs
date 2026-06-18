// run-selftests.mjs — run every selftest-*.mjs in this directory and report.
// Exits non-zero if any selftest fails. Run: node run-selftests.mjs

import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const tests = readdirSync(HERE).filter((f) => /^selftest-.*\.mjs$/.test(f)).sort();

const failed = [];
for (const t of tests) {
  const r = spawnSync(process.execPath, [join(HERE, t)], { encoding: "utf8" });
  const passed = r.status === 0;
  const last = (r.stdout ?? "").trim().split("\n").pop() ?? "";
  console.log(`${passed ? "PASS" : "FAIL"}  ${t.padEnd(32)} ${last}`);
  if (!passed) {
    failed.push(t);
    if (r.stderr) console.log(r.stderr.trim());
  }
}

console.log(
  `\n${failed.length === 0 ? `ALL ${tests.length} SELFTESTS PASS` : `${failed.length} FAILED: ${failed.join(", ")}`}`,
);
process.exit(failed.length === 0 ? 0 : 1);

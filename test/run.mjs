#!/usr/bin/env node
// Runs dist/cli.js against each fixture directory and compares verdicts with
// expected.json. Exit 1 if any verdict differs.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, "..", "dist", "cli.js");
const root = join(here, "fixtures");

let failures = 0;
let total = 0;
for (const name of readdirSync(root)) {
  const dir = join(root, name);
  const expPath = join(dir, "expected.json");
  if (!existsSync(expPath)) continue;
  const expected = JSON.parse(readFileSync(expPath, "utf8"));

  let out;
  try {
    out = execFileSync("node", [cli, dir, "--json"], { encoding: "utf8" });
  } catch (e) {
    out = e.stdout; // exit 1 when something is flagged
  }
  const actual = Object.fromEntries(JSON.parse(out).findings.map((f) => [f.fn, f.verdict]));

  for (const [fn, want] of Object.entries(expected)) {
    total++;
    const got = actual[fn] ?? "(not reported)";
    const ok = got === want;
    if (!ok) failures++;
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}/${fn.padEnd(16)} expected ${want.padEnd(18)} got ${got}`);
  }
}
console.log(`\n${total - failures}/${total} passed`);
process.exit(failures ? 1 : 0);

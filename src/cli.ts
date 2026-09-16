#!/usr/bin/env node
import { Project, SyntaxKind, Node, Symbol as TsSymbol } from "ts-morph";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// What this checks
//
// In Next.js, every exported function in a "use server" file is a public HTTP
// endpoint. If such a function takes an identifier as an argument and hands it
// to a service_role database client (which bypasses row-level security), the
// caller gets to choose whose row is read or written.
//
// This tool flags: a parameter value reaching a query filter / mutation with no
// guard call executing before it.
//
// It is noisy. See README for measured limitations.
// ---------------------------------------------------------------------------

const SERVICE_KEY = ["SERVICE_ROLE", "SUPABASE_SERVICE_KEY", "sb_secret_"];
const SINK = ["eq", "in", "match", "insert", "update", "upsert", "delete", "filter", "or"];
const GUARD_NAME = /^(require|verify|validate|assert|ensure|check|authori[sz]e|protect|can|is)[A-Z_]?/;
const GUARD_MEMBER = new Set([
  "getUser", "getSession", "getClaims", "protect", "getToken", "verifyIdToken",
]);
const AUTH_FN = new Set([
  "currentUser", "auth", "getServerSession", "clerkClient",
  "getCurrentUser", "getAuthUser", "getSessionUser", "getUser", "getSession",
]);
const FACTORY = (n: string) =>
  /create.*client/i.test(n) || /get.*client/i.test(n) || n.toLowerCase().includes("supabase");

type Verdict = "flagged" | "guard_before_sink" | "no_tainted_sink";

interface Finding {
  verdict: Verdict;
  file: string;
  fn: string;
  line: number;
}

function resolveSymbol(s: TsSymbol | undefined): TsSymbol | undefined {
  if (!s) return undefined;
  try { return s.getAliasedSymbol() ?? s; } catch { return s; }
}

function usesServiceRoleClient(node: any): boolean {
  const body = node.getBody?.()?.getText() ?? node.getText();
  if (SERVICE_KEY.some((p) => body.includes(p))) return true;
  // The client is usually built in another module and imported. Follow the
  // alias to its declaration, otherwise every `import { supabaseAdmin }` is missed.
  for (const id of node.getDescendantsOfKind(SyntaxKind.Identifier)) {
    for (const d of resolveSymbol(id.getSymbol())?.getDeclarations() ?? []) {
      if (SERVICE_KEY.some((p) => d.getText().includes(p))) return true;
    }
  }
  return false;
}

function classify(node: any, repoPath: string): Verdict {
  const params = node.getParameters();
  if (params.length === 0) return "no_tainted_sink";

  // Taint set by symbol identity, not by name substring. Matching on names makes
  // a parameter called `id` match every occurrence of "id" in the file.
  const ids = node.getDescendantsOfKind(SyntaxKind.Identifier);
  const refsOf = (decl: any) =>
    ids.filter((i) =>
      (resolveSymbol(i.getSymbol())?.getDeclarations() ?? []).some((x: any) => x === decl)
    );

  const taintedDecls = new Set<any>(params);
  const tainted = new Set<any>();
  for (const p of params) refsOf(p).forEach((n) => tainted.add(n));

  // One hop of propagation, so `const id = formData.get("id")` stays tainted.
  for (let pass = 0; pass < 2; pass++) {
    for (const vd of node.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
      const init = vd.getInitializer();
      if (!init || taintedDecls.has(vd)) continue;
      const touches = [...tainted].some(
        (t: any) => t.getPos() >= init.getPos() && t.getEnd() <= init.getEnd()
      );
      if (touches) {
        taintedDecls.add(vd);
        refsOf(vd).forEach((n) => tainted.add(n));
      }
    }
  }

  let sinkPos = Infinity;
  for (const call of node.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expr = call.getExpression();
    if (!Node.isPropertyAccessExpression(expr) || !SINK.includes(expr.getName())) continue;
    for (const arg of call.getArguments()) {
      for (const t of tainted as any) {
        if (t.getPos() >= arg.getPos() && t.getEnd() <= arg.getEnd()) {
          sinkPos = Math.min(sinkPos, call.getPos());
        }
      }
    }
  }
  if (sinkPos === Infinity) return "no_tainted_sink";

  // Only a guard that runs *before* the sink counts. Error handling after the
  // query is not authorization.
  for (const call of node.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    if (call.getPos() >= sinkPos) continue;
    const e = call.getExpression();
    const name = Node.isPropertyAccessExpression(e) ? e.getName() : e.getText();
    if (GUARD_MEMBER.has(name) || AUTH_FN.has(name) || GUARD_NAME.test(name)) {
      return "guard_before_sink";
    }
  }
  return "flagged";
}

function scan(repoPath: string): Finding[] {
  const tsConfigPath = path.join(repoPath, "tsconfig.json");
  const hasTsConfig = fs.existsSync(tsConfigPath);
  const project = new Project({
    tsConfigFilePath: hasTsConfig ? tsConfigPath : undefined,
    skipAddingFilesFromTsConfig: false,
    skipFileDependencyResolution: true,
  });
  if (!hasTsConfig) {
    project.addSourceFilesAtPaths([
      `${repoPath}/**/*.{ts,tsx}`,
      `!${repoPath}/**/node_modules/**`,
    ]);
  }

  const findings: Finding[] = [];
  for (const file of project.getSourceFiles()) {
    const first = file.getStatements()[0];
    const isServerFile =
      !!first &&
      Node.isExpressionStatement(first) &&
      /^['"]use server['"];?$/.test(first.getText().trim());
    if (!isServerFile) continue;

    const candidates: [string, any][] = [];
    for (const f of file.getFunctions().filter((f) => f.isExported())) {
      candidates.push([f.getName() ?? "<anonymous>", f]);
    }
    for (const v of file.getVariableDeclarations().filter((v) => v.isExported())) {
      const init = v.getInitializer();
      if (init && (Node.isArrowFunction(init) || Node.isFunctionExpression(init))) {
        candidates.push([v.getName(), init]);
      }
    }

    for (const [name, node] of candidates) {
      if (FACTORY(name)) continue;
      if (!usesServiceRoleClient(node)) continue;
      findings.push({
        verdict: classify(node, repoPath),
        file: path.relative(repoPath, file.getFilePath()),
        fn: name,
        line: node.getStartLineNumber(),
      });
    }
  }
  return findings;
}

// --- CLI -------------------------------------------------------------------

const argv = process.argv.slice(2);
if (argv.includes("-h") || argv.includes("--help")) {
  console.log(`actionguard <path> [--json] [--all]

  Scans exported Server Actions that use a service_role database client and
  reports ones where a caller-supplied argument reaches a query filter with no
  guard running first.

  --json   machine-readable output
  --all    also list actions that passed
`);
  process.exit(0);
}

const asJson = argv.includes("--json");
const showAll = argv.includes("--all");
const target = argv.find((a) => !a.startsWith("-")) ?? ".";
const repoPath = path.resolve(target);

if (!fs.existsSync(repoPath)) {
  console.error(`actionguard: no such path: ${target}`);
  process.exit(2);
}

const findings = scan(repoPath);
const flagged = findings.filter((f) => f.verdict === "flagged");

if (asJson) {
  console.log(JSON.stringify({
    repository: repoPath,
    server_actions_using_service_role: findings.length,
    flagged: flagged.length,
    guard_before_sink: findings.filter((f) => f.verdict === "guard_before_sink").length,
    no_tainted_sink: findings.filter((f) => f.verdict === "no_tainted_sink").length,
    findings,
  }, null, 2));
} else {
  if (findings.length === 0) {
    console.log("No Server Actions using a service_role client were found.");
  } else {
    for (const f of flagged) {
      console.log(`  ${f.file}:${f.line}  ${f.fn}`);
      console.log(`      argument reaches a service_role query with no guard before it`);
    }
    if (showAll) {
      for (const f of findings.filter((x) => x.verdict !== "flagged")) {
        console.log(`  ok  ${f.file}:${f.line}  ${f.fn}  (${f.verdict})`);
      }
    }
    console.log(
      `\n${findings.length} Server Actions using service_role, ` +
      `${flagged.length} flagged, ` +
      `${findings.length - flagged.length} passed.`
    );
    if (flagged.length) {
      console.log(
        "\nThese are candidates, not confirmed vulnerabilities. Public endpoints that\n" +
        "legitimately take a tenant key or public token look identical to this check.\n" +
        "Read each one before acting on it."
      );
    }
  }
}

process.exit(flagged.length > 0 ? 1 : 0);

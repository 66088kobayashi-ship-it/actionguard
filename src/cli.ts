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
// A sink only counts when it sits on a database query chain: `<client>.from(...)...`.
// Without this, Array.prototype.filter, String.prototype.match and
// hash.update(...) all look like queries.
const QUERY_ROOT = new Set(["from"]);
// Calls that are authentication by themselves, matched by exact name.
const GUARD_MEMBER = new Set([
  "getUser", "getSession", "getClaims", "protect", "getToken", "verifyIdToken",
]);
const AUTH_FN = new Set([
  "currentUser", "auth", "getServerSession", "clerkClient",
  "getCurrentUser", "getAuthUser", "getSessionUser", "getUser", "getSession",
]);
// Name fallback, used only when the callee's source is not in the repository
// (an uninstalled package). The uppercase letter is required: `isNaN`,
// `canonicalize` and `checkAndGrantBadges` must not read as guards. `validate*`,
// `check*`, `is*` and `can*` are left out because they are mostly input checks.
const GUARD_NAME = /^(require|verify|assert|ensure|authori[sz]e|protect)[A-Z]/;
// How many helper calls deep to look for an auth call.
const MAX_HELPER_DEPTH = 3;
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

function calleeName(call: any): string {
  const e = call.getExpression();
  return Node.isPropertyAccessExpression(e) ? e.getName() : e.getText();
}

// The function body a call resolves to, if its source is in the repository.
// Declaration files and node_modules return undefined.
function localCallee(call: any): any | undefined {
  const e = call.getExpression();
  const id = Node.isPropertyAccessExpression(e) ? e.getNameNode()
    : Node.isIdentifier(e) ? e : undefined;
  if (!id) return undefined;
  for (const d of resolveSymbol(id.getSymbol())?.getDeclarations() ?? []) {
    const sf = d.getSourceFile();
    if (sf.isDeclarationFile() || sf.isInNodeModules()) continue;
    if (Node.isFunctionDeclaration(d) || Node.isMethodDeclaration(d)) return d;
    if (Node.isVariableDeclaration(d)) {
      const init = d.getInitializer();
      if (init && (Node.isArrowFunction(init) || Node.isFunctionExpression(init))) return init;
      // Wrapped: `export const getAdmin = cache(() => createClient(...))`
      if (init && Node.isCallExpression(init)) {
        const fnArg = init.getArguments().find((a: any) => Node.isArrowFunction(a) || Node.isFunctionExpression(a));
        if (fnArg) return fnArg;
      }
    }
  }
  return undefined;
}

// A call is a guard if it is a known auth call, or if it is a function in this
// repository that makes one within MAX_HELPER_DEPTH levels. A local helper is
// judged by what it does, never by its name, so `getProfileOrThrow` counts and
// a local `validateEmail` does not.
function isGuardCall(call: any, depth: number, path: Set<any>): boolean {
  const name = calleeName(call);
  if (GUARD_MEMBER.has(name) || AUTH_FN.has(name)) return true;
  const fn = localCallee(call);
  if (!fn) return GUARD_NAME.test(name);
  if (depth >= MAX_HELPER_DEPTH || path.has(fn)) return false;
  path.add(fn);
  const found = fn.getDescendantsOfKind(SyntaxKind.CallExpression)
    .some((c: any) => isGuardCall(c, depth + 1, path));
  path.delete(fn);
  return found;
}

// If this receiver comes from `<client>.from(...)`, return `<client>`. Follows one
// local variable, so `let q = sb.from("t").select(); q = q.eq("id", id)` is still
// a query. Returns undefined when it is not a query chain.
function queryClient(expr: any): any | undefined {
  let cur = expr;
  for (let steps = 0; cur && steps < 50; steps++) {
    if (Node.isCallExpression(cur)) {
      const e = cur.getExpression();
      if (Node.isPropertyAccessExpression(e) && QUERY_ROOT.has(e.getName())) {
        const recv = e.getExpression();
        if (!(Node.isIdentifier(recv) && recv.getText() === "Array")) return recv;
      }
      cur = e;
    } else if (
      Node.isPropertyAccessExpression(cur) || Node.isAwaitExpression(cur) ||
      Node.isParenthesizedExpression(cur) || Node.isNonNullExpression(cur) ||
      Node.isAsExpression(cur)
    ) {
      cur = cur.getExpression();
    } else if (Node.isIdentifier(cur)) {
      const d = resolveSymbol(cur.getSymbol())?.getDeclarations()?.[0];
      const init = d && Node.isVariableDeclaration(d) ? d.getInitializer() : undefined;
      if (!init) return undefined;
      cur = init;
    } else {
      return undefined;
    }
  }
  return undefined;
}

const hasServiceKey = (text: string) => SERVICE_KEY.some((p) => text.includes(p));

// Is the client a query runs on a service_role client?
//   true      — traced to a service_role key
//   false     — traced to something that is not (an anon/cookie client)
//   undefined — could not trace it (a class field, a parameter, ...)
// Checking the whole action for a service_role key is not enough: an action can
// read the key for one purpose and run its queries on the user's RLS client.
function clientIsServiceRole(expr: any, depth = 0, seen = new Set<any>()): boolean | undefined {
  // depth counts function hops only; `seen` stops cycles through variables.
  if (!expr || depth > MAX_HELPER_DEPTH || seen.has(expr) || seen.size > 200) return undefined;
  seen.add(expr);
  let cur = expr;
  while (
    Node.isAwaitExpression(cur) || Node.isParenthesizedExpression(cur) ||
    Node.isNonNullExpression(cur) || Node.isAsExpression(cur)
  ) cur = cur.getExpression();

  if (hasServiceKey(cur.getText())) return true;

  if (Node.isCallExpression(cur)) {
    const fn = localCallee(cur);
    if (fn) return fnReturnsServiceRole(fn, depth + 1, seen);
    // A library factory, e.g. createClient(url, serviceKey): look at its arguments.
    const args = cur.getArguments();
    if (args.length === 0) return undefined;
    let all: boolean | undefined = false;
    for (const a of args) {
      const r = clientIsServiceRole(a, depth, seen);
      if (r) return true;
      if (r === undefined) all = undefined;
    }
    return all;
  }

  if (Node.isIdentifier(cur)) {
    const sym = resolveSymbol(cur.getSymbol());
    const decls = sym?.getDeclarations() ?? [];
    let result: boolean | undefined = undefined;
    for (const d of decls) {
      if (!Node.isVariableDeclaration(d)) continue;
      // The declaration and every later reassignment: `let sb = anon(); sb = admin();`
      const sources: any[] = [];
      const init = d.getInitializer();
      if (init) sources.push(init);
      for (const b of d.getSourceFile().getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
        if (b.getOperatorToken().getKind() !== SyntaxKind.EqualsToken) continue;
        const left = b.getLeft();
        if (Node.isIdentifier(left) &&
            resolveSymbol(left.getSymbol())?.getDeclarations()?.includes(d)) {
          sources.push(b.getRight());
        }
      }
      for (const s of sources) {
        const r = clientIsServiceRole(s, depth, seen);
        if (r) return true;
        if (r === false && result === undefined) result = false;
      }
    }
    return result;
  }

  // Its text was already checked for a service_role key above.
  if (Node.isStringLiteral(cur) || Node.isNoSubstitutionTemplateLiteral(cur) ||
      Node.isObjectLiteralExpression(cur)) return false;
  if (Node.isPropertyAccessExpression(cur) && cur.getText().startsWith("process.env.")) return false;
  return undefined;
}

function fnReturnsServiceRole(fn: any, depth: number, seen: Set<any>): boolean | undefined {
  const body = fn.getBody?.();
  if (!body) return undefined;
  if (hasServiceKey(body.getText())) return true;
  const returned: any[] = Node.isBlock(body)
    ? body.getDescendantsOfKind(SyntaxKind.ReturnStatement)
        // Only this function's own returns, not those of callbacks inside it
        // (`cookies: { get(name) { return ... } }`).
        .filter((r: any) => r.getParentWhile((n: any) => !Node.isFunctionLikeDeclaration(n))?.getParent() === fn)
        .map((r: any) => r.getExpression()).filter(Boolean)
    : [body];
  let result: boolean | undefined = returned.length ? false : undefined;
  for (const r of returned) {
    const v = clientIsServiceRole(r, depth, seen);
    if (v) return true;
    if (v === undefined) result = undefined;
  }
  return result;
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

  // Destructured parameters (`{ userId }`) declare their names on binding
  // elements, not on the parameter, so both have to be roots.
  const roots: any[] = [];
  for (const p of params) {
    roots.push(p, ...p.getNameNode().getDescendantsOfKind(SyntaxKind.BindingElement));
  }
  const taintedDecls = new Set<any>(roots);
  const tainted = new Set<any>();
  for (const r of roots) refsOf(r).forEach((n) => tainted.add(n));

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
    const client = queryClient(expr.getExpression());
    if (!client) continue;
    // Skip queries traced to a non-privileged client; RLS applies to those.
    // Untraceable clients stay in, since the action does use a service_role key.
    if (clientIsServiceRole(client) === false) continue;
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
    if (isGuardCall(call, 0, new Set())) return "guard_before_sink";
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

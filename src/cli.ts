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
  // next/navigation: these end the request with 401 / 403.
  "unauthorized", "forbidden",
]);
// A hand-written check counts when it ends in an auth error or a login redirect:
// `if (!ok) throw new Error("Unauthorized")`, `redirect("/login")`.
const AUTH_ERROR = /unauthori[sz]ed|unauthenticated|forbidden|not (logged|signed) in|not allowed|no session|login required/i;
const LOGIN_PATH = /^['"`]\/?(login|signin|sign-in|auth|admin\/login)\b/i;
// Name fallback, used only when the callee's source is not in the repository
// (an uninstalled package). The uppercase letter is required: `isNaN`,
// `canonicalize` and `checkAndGrantBadges` must not read as guards. `validate*`,
// `check*`, `is*` and `can*` are left out because they are mostly input checks.
const GUARD_NAME = /^(require|verify|assert|ensure|authori[sz]e|protect)[A-Z]/;
// How many helper calls deep to follow when tracing a client.
const MAX_HELPER_DEPTH = 3;
// How many helper calls deep to look for an auth call. Real code nests guards:
// requireSuperAdmin -> requireRole -> requireAuth -> getProfile -> getUser.
const GUARD_DEPTH = 6;
const FACTORY = (n: string) =>
  /create.*client/i.test(n) || /get.*client/i.test(n) || n.toLowerCase().includes("supabase");

type Verdict =
  | "flagged"            // tainted value reaches a service_role sink, no guard before it
  | "weak_guard"         // guarded, but the decision reads user_metadata (user-editable)
  | "unreferenced"       // would be flagged, but Next >= 15 does not expose it (see README)
  | "ignored"            // would be reported, but marked `// actionguard-ignore: <reason>`
  | "guard_before_sink"
  | "no_tainted_sink";

// Supabase Admin API calls. They only work with a service_role key, so they are
// privileged sinks whatever client variable they hang off.
const ADMIN_SINK = new Set([
  "deleteUser", "updateUserById", "getUserById", "generateLink", "inviteUserByEmail",
  "createUser", "signOut",
]);

interface Finding {
  verdict: Verdict;
  file: string;
  fn: string;
  line: number;
  reason?: string;   // for "ignored": the text after `actionguard-ignore:`
}

// `// actionguard-ignore: public view counter, slug is not an identity`
// placed in the comments directly above the exported declaration.
const IGNORE = /actionguard-ignore\b(?:\s*:\s*(.*?))?\s*(?:\*\/)?$/m;

function ignoreReason(stmt: any): string | undefined {
  for (const c of stmt.getLeadingCommentRanges?.() ?? []) {
    const m = c.getText().match(IGNORE);
    if (m) return (m[1] ?? "").trim() || "(no reason given)";
  }
  return undefined;
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
        // `export const getRep = cache(loadRep)`
        const idArg = init.getArguments().find((a: any) => Node.isIdentifier(a));
        if (idArg) {
          for (const d2 of resolveSymbol(idArg.getSymbol())?.getDeclarations() ?? []) {
            if (Node.isFunctionDeclaration(d2)) return d2;
            if (Node.isVariableDeclaration(d2)) {
              const i2 = d2.getInitializer();
              if (i2 && (Node.isArrowFunction(i2) || Node.isFunctionExpression(i2))) return i2;
            }
          }
        }
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
  if (isLoginRedirect(call)) return true;
  const fn = localCallee(call);
  if (!fn) return GUARD_NAME.test(name);
  if (depth >= GUARD_DEPTH || path.has(fn)) return false;
  path.add(fn);
  const found = throwsAuthError(fn) || fn.getDescendantsOfKind(SyntaxKind.CallExpression)
    .some((c: any) => isGuardCall(c, depth + 1, path));
  path.delete(fn);
  return found;
}

// `redirect("/login")`, `redirect("/auth/sign-in?next=...")`
function isLoginRedirect(call: any): boolean {
  if (calleeName(call) !== "redirect") return false;
  const a = call.getArguments()[0];
  return !!a && LOGIN_PATH.test(a.getText());
}

// `throw new Error("Unauthorized")` and the like, anywhere in the node.
function throwsAuthError(node: any): boolean {
  return node.getDescendantsOfKind(SyntaxKind.ThrowStatement)
    .some((t: any) => AUTH_ERROR.test(t.getText()));
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

interface ClassifyOpts {
  // The action body is the callback of a next-safe-action style client:
  // only `parsedInput` is caller-supplied; `ctx` comes from middleware.
  safeAction?: boolean;
  // A wrapper or middleware around the body performs authentication.
  preGuarded?: boolean;
}

function classify(node: any, opts: ClassifyOpts = {}): Verdict {
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
  let refFilter = (_n: any) => true;
  if (opts.safeAction) {
    const nameNode = params[0].getNameNode();
    if (Node.isObjectBindingPattern(nameNode)) {
      for (const el of nameNode.getElements()) {
        const key = el.getPropertyNameNode()?.getText() ?? el.getName();
        if (key === "parsedInput") {
          roots.push(el, ...el.getDescendantsOfKind(SyntaxKind.BindingElement));
        }
      }
    } else {
      // `async (args) => ...`: only `args.parsedInput` is caller-supplied.
      roots.push(params[0]);
      refFilter = (n: any) => {
        const par = n.getParent();
        return Node.isPropertyAccessExpression(par) && par.getName() === "parsedInput";
      };
    }
  } else {
    for (const p of params) {
      roots.push(p, ...p.getNameNode().getDescendantsOfKind(SyntaxKind.BindingElement));
    }
  }
  const taintedDecls = new Set<any>(roots);
  const tainted = new Set<any>();
  for (const r of roots) refsOf(r).filter(refFilter).forEach((n) => tainted.add(n));

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
    if (!Node.isPropertyAccessExpression(expr)) continue;
    const recv = expr.getExpression();
    const isAdminApi =
      ADMIN_SINK.has(expr.getName()) &&
      Node.isPropertyAccessExpression(recv) && recv.getName() === "admin" &&
      /(^|\.)auth$/.test((recv as any).getExpression().getText());
    if (!isAdminApi) {
      if (!SINK.includes(expr.getName())) continue;
      const client = queryClient(recv);
      if (!client) continue;
      // Skip queries traced to a non-privileged client; RLS applies to those.
      // Untraceable clients stay in, since the action does use a service_role key.
      if (clientIsServiceRole(client) === false) continue;
    }
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
  let guarded = !!opts.preGuarded;
  for (const call of node.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    if (guarded) break;
    if (call.getPos() >= sinkPos) continue;
    if (isGuardCall(call, 0, new Set())) guarded = true;
  }
  if (!guarded) {
    guarded = node.getDescendantsOfKind(SyntaxKind.ThrowStatement)
      .some((t: any) => t.getPos() < sinkPos && AUTH_ERROR.test(t.getText()));
  }
  if (!guarded) return "flagged";

  // A role check on user_metadata is not authorization: users can rewrite their
  // own user_metadata with supabase.auth.updateUser({ data: { ... } }).
  for (const cond of node.getDescendants()) {
    if (cond.getPos() >= sinkPos) break;
    const test =
      Node.isIfStatement(cond) ? cond.getExpression() :
      Node.isConditionalExpression(cond) ? cond.getCondition() : undefined;
    if (test && /\buser_metadata\b/.test(test.getText())) return "weak_guard";
  }
  return "guard_before_sink";
}


// --- Wrapped actions ---------------------------------------------------------
// `export const a = client.schema(s).action(async ({ parsedInput, ctx }) => ...)`
// (next-safe-action) or `export const a = withAuth(async (id) => ...)`. The body
// is the last function argument of the outermost call.
function unwrapAction(init: any): { body: any; safeAction: boolean } | undefined {
  if (!Node.isCallExpression(init)) return undefined;
  const args = init.getArguments();
  const fn = [...args].reverse().find((a: any) => Node.isArrowFunction(a) || Node.isFunctionExpression(a));
  if (!fn) {
    const inner = [...args].reverse().find((a: any) => Node.isCallExpression(a));
    return inner ? unwrapAction(inner) : undefined;
  }
  const e = init.getExpression();
  const safeAction = Node.isPropertyAccessExpression(e) && ["action", "stateAction"].includes(e.getName());
  return { body: fn, safeAction };
}

// A middleware callback (or wrapper body) authenticates if it makes an auth call,
// or throws an auth error. In `.use(async ({ next }) => { if (!user) throw
// new Error("Unauthorized"); return next(...) })` the throw is the guard.
function bodyAuthenticates(fn: any): boolean {
  if (fn.getDescendantsOfKind(SyntaxKind.CallExpression).some((c: any) => isGuardCall(c, 0, new Set()))) return true;
  return fn.getDescendantsOfKind(SyntaxKind.ThrowStatement).some((t: any) => AUTH_ERROR.test(t.getText()));
}

// Walk the call chain that wraps an action body, and the client it starts from
// (`authActionClient` -> its own `.use(...)` chain), looking for authentication.
function chainAuthenticates(expr: any, skip: any, depth = 0, seen = new Set<any>()): boolean {
  let cur = expr;
  while (cur && depth <= MAX_HELPER_DEPTH && !seen.has(cur)) {
    seen.add(cur);
    if (Node.isCallExpression(cur)) {
      for (const a of cur.getArguments()) {
        if (a === skip) continue;
        if ((Node.isArrowFunction(a) || Node.isFunctionExpression(a)) && bodyAuthenticates(a)) return true;
      }
      if (!Node.isPropertyAccessExpression(cur.getExpression())) {
        // Plain wrapper `withAuth(fn)`: does withAuth itself authenticate?
        const w = localCallee(cur);
        if (w && bodyAuthenticates(w)) return true;
      }
      cur = cur.getExpression();
    } else if (
      Node.isPropertyAccessExpression(cur) || Node.isParenthesizedExpression(cur) ||
      Node.isAwaitExpression(cur) || Node.isNonNullExpression(cur) || Node.isAsExpression(cur)
    ) {
      cur = cur.getExpression();
    } else if (Node.isIdentifier(cur)) {
      const d = resolveSymbol(cur.getSymbol())?.getDeclarations()?.[0];
      if (!d || !Node.isVariableDeclaration(d) || !d.getInitializer()) return false;
      cur = d.getInitializer();
      depth++;
    } else {
      return false;
    }
  }
  return false;
}

// --- Reachability (Next.js >= 15) --------------------------------------------
// Since Next.js 15, a Server Action that no client code references is removed
// from the client bundle and gets no callable ID. An export of a "use server"
// file that is only imported by route handlers, middleware or other server-only
// modules is therefore not a public endpoint.

function nextMajor(file: string, repoPath: string): number | undefined {
  let dir = path.dirname(file);
  while (dir.startsWith(repoPath)) {
    const pj = path.join(dir, "package.json");
    if (fs.existsSync(pj)) {
      try {
        const j = JSON.parse(fs.readFileSync(pj, "utf8"));
        const v = j.dependencies?.next ?? j.devDependencies?.next;
        if (v) {
          const m = String(v).match(/(\d+)\./);
          return m ? Number(m[1]) : undefined;   // "latest", "canary": unknown
        }
      } catch { /* unreadable package.json: keep looking */ }
    }
    if (dir === repoPath) break;
    dir = path.dirname(dir);
  }
  return undefined;
}

const isUseServerFile = (sf: any) => {
  const first = sf.getStatements()[0];
  return !!first && Node.isExpressionStatement(first) &&
    /^['"]use server['"];?$/.test(first.getText().trim());
};

// Importers that cannot hand an action to the browser.
function isServerOnlyImporter(sf: any): boolean {
  const fp = sf.getFilePath();
  if (/\/route\.(t|j)sx?$/.test(fp) || /\/middleware\.(t|j)s$/.test(fp)) return true;
  if (/\/supabase\/functions\//.test(fp)) return true;
  if (isUseServerFile(sf)) return true;
  return sf.getImportDeclarations().some((i: any) => i.getModuleSpecifierValue() === "server-only");
}

const isTestFile = (sf: any) =>
  /\.(test|spec)\.[cm]?[tj]sx?$/.test(sf.getFilePath()) ||
  /\/(__tests__|__mocks__|e2e|cypress|playwright)\//.test(sf.getFilePath());

const isUseClientFile = (sf: any) => {
  const first = sf.getStatements()[0];
  return !!first && Node.isExpressionStatement(first) &&
    /^['"]use client['"];?$/.test(first.getText().trim());
};

// Value imports only: `import type { X }` and `import { type X }` never reach the bundle.
function valueImports(sf: any): { decl: any; target: any; names: string[]; star: boolean; locals: any[] }[] {
  const out: any[] = [];
  for (const decl of sf.getImportDeclarations()) {
    if (decl.isTypeOnly()) continue;
    const target = decl.getModuleSpecifierSourceFile();
    if (!target) continue;
    const named = decl.getNamedImports().filter((n: any) => !n.isTypeOnly());
    const ns = decl.getNamespaceImport();
    const def = decl.getDefaultImport();
    if (!named.length && !ns && !def && decl.getNamedImports().length) continue; // all type-only
    out.push({
      decl, target,
      names: named.map((n: any) => n.getName()),
      star: !!ns || !!def,
      locals: [...named.map((n: any) => n.getAliasNode() ?? n.getNameNode()), ...(ns ? [ns] : []), ...(def ? [def] : [])],
    });
  }
  return out;
}

// Resolve a module specifier the way the compiler would: relative paths, then
// tsconfig `paths` aliases (`@/lib/x`). Returns the source file, if in the project.
function resolveSpecifier(project: any, from: any, spec: string): any | undefined {
  const exts = ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js"];
  const tryBase = (base: string) => {
    for (const e of exts) {
      const f = project.getSourceFile(base + e);
      if (f) return f;
    }
    return undefined;
  };
  if (spec.startsWith(".")) return tryBase(path.resolve(path.dirname(from.getFilePath()), spec));
  const opts = project.getCompilerOptions();
  const baseDir = opts.baseUrl ?? (opts.configFilePath ? path.dirname(String(opts.configFilePath)) : undefined);
  if (!baseDir) return undefined;
  for (const [pattern, targets] of Object.entries(opts.paths ?? {}) as [string, string[]][]) {
    const star = pattern.indexOf("*");
    const prefix = star >= 0 ? pattern.slice(0, star) : pattern;
    if (star >= 0 ? !spec.startsWith(prefix) : spec !== pattern) continue;
    const rest = star >= 0 ? spec.slice(prefix.length) : "";
    for (const t of targets) {
      const f = tryBase(path.resolve(baseDir, t.replace("*", rest)));
      if (f) return f;
    }
  }
  return undefined;
}

// Is `local` (an imported binding) used other than as the callee of a direct call?
// A server component that runs `await getDetails(id)` does not expose the action;
// one that renders `<form action={save}>` or passes it to a client component does.
function usedAsValue(sf: any, local: any): boolean {
  const name = local.getText();
  for (const id of sf.getDescendantsOfKind(SyntaxKind.Identifier)) {
    if (id === local || id.getText() !== name) continue;
    if (id.getFirstAncestorByKind(SyntaxKind.ImportDeclaration)) continue;
    let node: any = id;
    // ns.fn(...) for namespace imports
    if (Node.isPropertyAccessExpression(node.getParent()) && node.getParent().getExpression() === node) node = node.getParent();
    const par = node.getParent();
    if (Node.isCallExpression(par) && par.getExpression() === node) continue;
    if (Node.isAwaitExpression(par)) continue;
    return true;
  }
  return false;
}

// For each "use server" file: the export names that can end up in the browser
// ("*" = all). Since Next.js 15 only those get an action ID. An action is exposed
// when a client module (a "use client" file, or anything it imports, directly or
// not) imports it, or when a server module passes it on as a value instead of
// calling it. Test files and type-only imports do not count.
function exposedExports(project: any): Map<any, Set<string>> {
  const out = new Map<any, Set<string>>();
  const mark = (sf: any, name: string) => {
    if (!out.has(sf)) out.set(sf, new Set());
    out.get(sf)!.add(name);
  };
  // Mark `names` imported from `mod`, following barrels (`export * from`,
  // `export { a as b } from`) to the "use server" file that defines them. Only
  // the names actually imported count, not everything the barrel re-exports.
  const markThrough = (mod: any, names: string[] | "*", depth = 0) => {
    if (!mod || depth > 5) return;
    if (isUseServerFile(mod)) {
      if (names === "*") mark(mod, "*"); else names.forEach((n) => mark(mod, n));
    }
    for (const decl of mod.getExportDeclarations()) {
      if (decl.isTypeOnly()) continue;
      const target = decl.getModuleSpecifierSourceFile();
      if (!target || target.isDeclarationFile() || target.isInNodeModules()) continue;
      const named = decl.getNamedExports().filter((n: any) => !n.isTypeOnly());
      if (!named.length && !decl.getNamespaceExport()) {
        markThrough(target, names, depth + 1);                      // export * from
        continue;
      }
      const picked = named
        .filter((n: any) => names === "*" || names.includes(n.getAliasNode()?.getText() ?? n.getName()))
        .map((n: any) => n.getName());
      if (picked.length) markThrough(target, picked, depth + 1);
    }
  };
  const files = project.getSourceFiles().filter((f: any) => !isTestFile(f));

  // Client graph: "use client" files and everything they import.
  const client = new Set<any>();
  const queue = files.filter(isUseClientFile);
  queue.forEach((f: any) => client.add(f));
  while (queue.length) {
    const f = queue.pop();
    for (const imp of valueImports(f)) {
      const t = imp.target;
      if (client.has(t) || isUseServerFile(t) || t.isDeclarationFile() || t.isInNodeModules()) continue;
      client.add(t);
      queue.push(t);
    }
  }

  for (const sf of files) {
    const inClient = client.has(sf);
    if (isUseServerFile(sf)) continue;   // server-to-server calls expose nothing
    for (const imp of valueImports(sf)) {
      if (inClient) {
        markThrough(imp.target, imp.star ? "*" : imp.names);
        continue;
      }
      if (isServerOnlyImporter(sf) && !/\.(t|j)sx$/.test(sf.getFilePath())) continue;
      const named = imp.decl.getNamedImports().filter((n: any) => !n.isTypeOnly());
      const used = named
        .filter((n: any) => usedAsValue(sf, n.getAliasNode() ?? n.getNameNode()))
        .map((n: any) => n.getName());
      if (used.length) markThrough(imp.target, used);
      for (const l of imp.locals.slice(named.length)) {
        if (usedAsValue(sf, l)) markThrough(imp.target, "*");
      }
    }
    // Dynamic import("./actions") from client code: expose everything it might be.
    if (inClient) {
      for (const c of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (c.getExpression().getKind() !== SyntaxKind.ImportKeyword) continue;
        const arg = c.getArguments()[0];
        if (!arg || !(Node.isStringLiteral(arg) || Node.isNoSubstitutionTemplateLiteral(arg))) {
          // import(someVariable): cannot tell which module, so assume any.
          files.filter(isUseServerFile).forEach((t: any) => mark(t, "*"));
          continue;
        }
        const target = resolveSpecifier(project, sf, arg.getLiteralText());
        if (target) markThrough(target, "*");
      }
    }
  }
  return out;
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
  let exposed: Map<any, Set<string>> | undefined;
  for (const file of project.getSourceFiles()) {
    if (!isUseServerFile(file)) continue;

    const candidates: [string, any, ClassifyOpts, any][] = [];
    for (const f of file.getFunctions().filter((f) => f.isExported())) {
      candidates.push([f.getName() ?? "<anonymous>", f, {}, f]);
    }
    for (const v of file.getVariableDeclarations().filter((v) => v.isExported())) {
      const init = v.getInitializer();
      if (!init) continue;
      if (Node.isArrowFunction(init) || Node.isFunctionExpression(init)) {
        candidates.push([v.getName(), init, {}, v.getVariableStatement()]);
        continue;
      }
      const w = unwrapAction(init);
      if (w) {
        candidates.push([v.getName(), w.body, {
          safeAction: w.safeAction,
          preGuarded: chainAuthenticates(init, w.body),
        }, v.getVariableStatement()]);
      }
    }

    const major = nextMajor(file.getFilePath(), repoPath);
    for (const [name, node, opts, stmt] of candidates) {
      if (FACTORY(name)) continue;
      if (!usesServiceRoleClient(node)) continue;
      let verdict = classify(node, opts);
      if ((verdict === "flagged" || verdict === "weak_guard") && major !== undefined && major >= 15) {
        exposed ??= exposedExports(project);
        const names = exposed.get(file);
        if (!names || !(names.has("*") || names.has(name))) verdict = "unreferenced";
      }
      let reason: string | undefined;
      if (verdict === "flagged" || verdict === "weak_guard" || verdict === "unreferenced") {
        reason = stmt ? ignoreReason(stmt) : undefined;
        if (reason) verdict = "ignored";
      }
      findings.push({
        verdict,
        file: path.relative(repoPath, file.getFilePath()),
        fn: name,
        line: node.getStartLineNumber(),
        ...(reason ? { reason } : {}),
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
const flagged = findings.filter((f) => f.verdict === "flagged" || f.verdict === "weak_guard");

if (asJson) {
  console.log(JSON.stringify({
    repository: repoPath,
    server_actions_using_service_role: findings.length,
    flagged: flagged.length,
    weak_guard: findings.filter((f) => f.verdict === "weak_guard").length,
    unreferenced: findings.filter((f) => f.verdict === "unreferenced").length,
    ignored: findings.filter((f) => f.verdict === "ignored").length,
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
      console.log(f.verdict === "weak_guard"
        ? `      guarded by a user_metadata check, which users can rewrite themselves`
        : `      argument reaches a service_role query with no guard before it`);
    }
    if (showAll) {
      for (const f of findings.filter((x) => x.verdict !== "flagged")) {
        console.log(`  ok  ${f.file}:${f.line}  ${f.fn}  (${f.verdict}${f.reason ? `: ${f.reason}` : ""})`);
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

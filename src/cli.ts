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
  // Lucia, T3 (NextAuth wrapper), Kinde.
  "validateRequest", "getServerAuthSession", "getKindeServerSession",
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

// A filter on a secret column is a capability check, not an identity lookup:
// `.eq("token_hash", hash(token))` only matches if the caller already holds the
// secret. Measured on 30 hand-checked false positives (2026-11).
const SECRET_COL = /(token|secret|access_?key|otp|nonce|hash)/i;

// Columns that decide who owns a row or what it may do (plus any column ending
// in "id": a reference to another row, chosen by the caller). An insert whose
// caller-supplied values land only in other columns (a contact form, a waitlist
// entry, a feedback note) cannot touch anyone else's data, so it is reported
// separately as "public_write" instead of "flagged".
const PRIV_KEYS = new Set([
  "id", "role", "roles", "admin", "isadmin", "owner", "ownerid", "userid", "user",
  "tenant", "tenantid", "org", "orgid", "organizationid", "accountid", "workspaceid",
  "teamid", "memberid", "profileid", "createdby", "permission", "permissions",
  "plan", "plantype", "tier", "credit", "credits", "balance", "verified", "isverified",
  "approved", "isapproved", "status",
]);
// ...and only into tables that hold submissions from the public. An insert into
// products, payments or gift cards with no auth check is still an unauthorized
// write, however harmless its columns look.
const PUBLIC_TABLE = /(contact|feedback|waitlist|wait_list|lead|inquir|enquir|message|report|subscriber|newsletter|suggestion|review|comment|vote|rating|page_?view|click|analytics|survey|signup|registration|rsvp|guestbook|testimonial)/i;

// The table a query chain starts from: `<client>.from("table")...`.
function queryTable(expr: any): string | undefined {
  let cur = expr;
  for (let steps = 0; cur && steps < 50; steps++) {
    if (Node.isCallExpression(cur)) {
      const e = cur.getExpression();
      if (Node.isPropertyAccessExpression(e) && QUERY_ROOT.has(e.getName())) {
        const a = cur.getArguments()[0];
        return a && (Node.isStringLiteral(a) || Node.isNoSubstitutionTemplateLiteral(a)) ? a.getLiteralText() : undefined;
      }
      cur = e;
    } else if (Node.isPropertyAccessExpression(cur) || Node.isAwaitExpression(cur) ||
               Node.isParenthesizedExpression(cur) || Node.isNonNullExpression(cur)) {
      cur = cur.getExpression();
    } else {
      return undefined;
    }
  }
  return undefined;
}

// A hand-rolled session counts as authentication when the helper both reads the
// request (cookies()/headers()) and verifies what it read (HMAC, hash compare,
// JWT). Reading a cookie alone does not count: presence of a cookie is forgeable.
const VERIFY_FN = new Set([
  "createHmac", "createHash", "timingSafeEqual", "jwtVerify", "verify",
  "unsealData", "getIronSession", "compare", "compareSync", "decrypt",
]);

type Verdict =
  | "flagged"            // tainted value reaches a service_role sink, no guard before it
  | "weak_guard"         // guarded, but the decision reads user_metadata (user-editable)
  | "unreferenced"       // would be flagged, but Next >= 15 does not expose it (see README)
  | "public_write"       // caller-supplied values only land in content columns of an insert
  | "env_gated"          // unguarded, but an early process.env check limits where it runs
  | "ignored"            // would be reported, but marked `// actionguard-ignore: <reason>`
  | "idor_candidate"     // guarded, but a caller-supplied id picks the rows and nothing ties it to the session
  | "no_auth"            // flagged, in an app with no authentication anywhere (reported once per repository)
  | "public_read"        // unguarded, but only reads non-sensitive tables by non-key columns
  | "auth_flow"          // unguarded login or sign-up that cannot pick a role or someone else's row
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
  db?: "supabase" | "drizzle";
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

// ---- Drizzle ------------------------------------------------------------
// A Drizzle client talks to Postgres with the app's own database credentials:
// there is no row-level security in between, so every query it runs is as
// privileged as a Supabase service_role query.
const DRIZZLE_METHOD = new Set(["select", "insert", "update", "delete", "query"]);
const DRIZZLE_SINK = new Set(["where", "set", "values", "findFirst", "findMany", "onConflictDoUpdate"]);
const drizzleCache = new WeakMap<any, boolean>();

// Was this identifier declared as `drizzle(...)` (here or in an imported module),
// or is it the `tx` of `db.transaction(async (tx) => ...)`?
function isDrizzleClient(id: any): boolean {
  for (const d of resolveSymbol(id.getSymbol())?.getDeclarations() ?? []) {
    if (drizzleCache.has(d)) { if (drizzleCache.get(d)) return true; continue; }
    let yes = false;
    if (Node.isVariableDeclaration(d)) {
      const init = d.getInitializer();
      yes = !!init && /\bdrizzle\s*\(/.test(init.getText());
    } else if (Node.isParameterDeclaration(d)) {
      const fn = d.getParent();
      const call = fn?.getParent();
      if (call && Node.isCallExpression(call)) {
        const e = call.getExpression();
        yes = Node.isPropertyAccessExpression(e) && e.getName() === "transaction" &&
          Node.isIdentifier(e.getExpression()) && isDrizzleClient(e.getExpression());
      }
    }
    drizzleCache.set(d, yes);
    if (yes) return true;
  }
  return false;
}

// The client at the root of a Drizzle query chain:
// `db.update(t).set(v).where(w)`, `db.query.posts.findFirst({...})`,
// `getDb().delete(t).where(w)`. Clients are often built lazily (`db()`, a Proxy,
// `await getDb()`), so a chain counts when its shape is Drizzle's and either the
// client is traced to `drizzle(...)` or the file imports from "drizzle-orm".
// Supabase chains start with `.from()`, so they never match this shape.
function drizzleRoot(expr: any): any | undefined {
  let cur = expr;
  for (let steps = 0; cur && steps < 60; steps++) {
    if (Node.isCallExpression(cur) || Node.isAwaitExpression(cur) ||
        Node.isParenthesizedExpression(cur) || Node.isNonNullExpression(cur) || Node.isAsExpression(cur)) {
      cur = cur.getExpression();
    } else if (Node.isPropertyAccessExpression(cur)) {
      const recv = cur.getExpression();
      if (DRIZZLE_METHOD.has(cur.getName()) && isClientExpr(recv)) {
        if (Node.isIdentifier(recv) && isDrizzleClient(recv)) return recv;
        return importsDrizzle(recv.getSourceFile()) ? recv : undefined;
      }
      cur = recv;
    } else {
      return undefined;
    }
  }
  return undefined;
}

// `db`, `tx`, `this.db`, `db()`, `getDb()`, `(await getDb())`
function isClientExpr(e: any): boolean {
  while (Node.isParenthesizedExpression(e) || Node.isAwaitExpression(e) || Node.isNonNullExpression(e)) e = e.getExpression();
  if (Node.isIdentifier(e)) return true;
  if (Node.isPropertyAccessExpression(e)) return e.getExpression().getKind() === SyntaxKind.ThisKeyword || Node.isIdentifier(e.getExpression());
  if (Node.isCallExpression(e)) return Node.isIdentifier(e.getExpression()) && e.getArguments().length === 0;
  return false;
}

const importsDrizzleCache = new WeakMap<any, boolean>();
function importsDrizzle(sf: any): boolean {
  if (!importsDrizzleCache.has(sf)) {
    importsDrizzleCache.set(sf, sf.getImportDeclarations()
      .some((d: any) => d.getModuleSpecifierValue().startsWith("drizzle-orm")));
  }
  return importsDrizzleCache.get(sf)!;
}

function usesDrizzleClient(node: any): boolean {
  for (const call of node.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const e = call.getExpression();
    if (Node.isPropertyAccessExpression(e) && DRIZZLE_SINK.has(e.getName()) && drizzleRoot(e.getExpression())) return true;
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
  const found = throwsAuthError(fn) || verifiesSession(fn) || fn.getDescendantsOfKind(SyntaxKind.CallExpression)
    .some((c: any) => isGuardCall(c, depth + 1, path));
  path.delete(fn);
  return found;
}

// Does this helper (or a local helper it calls) read the request AND verify it?
function verifiesSession(fn: any): boolean {
  let reads = false, verifies = false;
  const visit = (f: any, depth: number, seen: Set<any>) => {
    if (depth > GUARD_DEPTH || seen.has(f) || (reads && verifies)) return;
    seen.add(f);
    for (const c of f.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const n = calleeName(c);
      if (n === "cookies" || n === "headers") reads = true;
      if (VERIFY_FN.has(n)) verifies = true;
      // Web Crypto: `crypto.subtle.sign("HMAC", ...)`, `subtle.verify(...)`, `subtle.digest(...)`
      if (/\bsubtle\.(sign|verify|digest|importKey)\b/.test(c.getExpression().getText())) verifies = true;
      const inner = localCallee(c);
      if (inner) visit(inner, depth + 1, seen);
    }
  };
  visit(fn, 0, new Set());
  return reads && verifies;
}

// For a tainted node inside an insert argument: the column it lands in, if the
// value sits under a plain `key: value` property. undefined means "whole row or
// unknown", which is treated as privileged.
function insertColumn(t: any, arg: any): string | undefined {
  let cur = t;
  while (cur && cur !== arg) {
    const par = cur.getParent();
    if (!par) return undefined;
    if (Node.isPropertyAssignment(par) && par.getInitializer() === cur) {
      return par.getName().replace(/['"`]/g, "").replace(/_/g, "").toLowerCase();
    }
    if (Node.isShorthandPropertyAssignment(par)) {
      return par.getName().replace(/_/g, "").toLowerCase();
    }
    if (Node.isSpreadAssignment(par)) return undefined;
    cur = par;
  }
  return undefined;
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

// Does an `if` condition switch the action off by environment?
//   process.env.DEMO_MODE !== "true", !process.env.ENABLE_RESET  -> opt-in flag
//   process.env.NODE_ENV === "production", VERCEL_ENV !== "development" -> off in production
// A check that a setting exists (`!process.env.SUPABASE_SERVICE_ROLE_KEY`,
// `!process.env.RESEND_API_KEY`) is not a gate: production has the setting, so
// the action runs there unguarded.
const ENV_NAME = /process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*["'`]([A-Za-z_][A-Za-z0-9_]*)["'`]\s*\])/g;
const STAGE_ENV = /^(NODE_ENV|VERCEL_ENV|APP_ENV|NEXT_PUBLIC_APP_ENV|NEXT_PUBLIC_VERCEL_ENV|ENVIRONMENT|ENV|STAGE|DEPLOY_ENV)$/;
const FLAG_ENV = /(DEMO|ENABLE|ALLOW|FEATURE|FLAG|_MODE$|^MODE$|DEBUG|SANDBOX|PLAYGROUND|DEV_|_DEV$|TESTING|SEED|MAINTENANCE)/;
const CONFIG_ENV = /(KEY|SECRET|TOKEN|PASSWORD|PASS|URL|URI|DSN|HOST|PORT|ENDPOINT|DOMAIN|REGION|BUCKET|EMAIL|_ID$)/;
const SECRET_ENV = "process\\.env(?:\\.[A-Za-z0-9_]*|\\[\\s*[\"'`][A-Za-z0-9_]*[\"'`]\\s*\\])";
const SECRET_NAME = /(PASSWORD|PASSCODE|SECRET|TOKEN|PIN|_KEY)\b/i;
// `x !== process.env.ADMIN_PASSWORD` (either side), not `process.env.X === undefined`.
function comparesToEnvSecret(cond: string): boolean {
  const re = new RegExp(`([\\w.$\\]\\)\\[]+)\\s*(?:!==?|===?)\\s*(${SECRET_ENV})|(${SECRET_ENV})\\s*(?:!==?|===?)\\s*([\\w.$\\]\\)\\[\"'\`]+)`, "g");
  for (const m of cond.matchAll(re)) {
    const env = m[2] || m[3];
    const other = (m[1] || m[4] || "").trim();
    if (!SECRET_NAME.test(env)) continue;
    if (/^(undefined|null|true|false|["'`].*["'`]|\d+)$/.test(other)) continue;
    if (other.startsWith("process.env")) continue;
    return true;
  }
  return false;
}
function isEnvGate(cond: string): boolean {
  const names = [...cond.matchAll(ENV_NAME)].map((m) => (m[1] || m[2]).toUpperCase());
  if (!names.length) return false;
  if (names.some((n) => STAGE_ENV.test(n))) {
    // Exits in production (=== "production"), or everywhere but development/test.
    return /(?<![!=])===?\s*["'`]production["'`]|["'`]production["'`]\s*===?/.test(cond) ||
      /!==?\s*["'`](development|dev|test|local)["'`]|["'`](development|dev|test|local)["'`]\s*!==?/.test(cond);
  }
  return names.some((n) => FLAG_ENV.test(n) && !CONFIG_ENV.test(n));
}

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
  // The exported name, for login / sign-up recognition.
  name?: string;
}

function classify(node: any, opts: ClassifyOpts = {}): Verdict {
  const params = node.getParameters();
  if (params.length === 0) return "no_tainted_sink";

  // Taint set by symbol identity, not by name substring. Matching on names makes
  // a parameter called `id` match every occurrence of "id" in the file.
  const ids = node.getDescendantsOfKind(SyntaxKind.Identifier);
  // In `{ name, price }` the identifier's own symbol is the property; the value
  // it reads is the shorthand's value symbol.
  const symOf = (i: any) => {
    const par = i.getParent();
    if (Node.isShorthandPropertyAssignment(par) && par.getNameNode() === i) return par.getValueSymbol();
    return i.getSymbol();
  };
  const refsOf = (decl: any) =>
    ids.filter((i) =>
      (resolveSymbol(symOf(i))?.getDeclarations() ?? []).some((x: any) => x === decl)
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
  let contentInsert = false;
  const sinks: Sink[] = [];
  for (const call of node.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expr = call.getExpression();
    if (!Node.isPropertyAccessExpression(expr)) continue;
    const recv = expr.getExpression();
    const method = expr.getName();
    const isAdminApi =
      ADMIN_SINK.has(method) &&
      Node.isPropertyAccessExpression(recv) && recv.getName() === "admin" &&
      /(^|\.)auth$/.test((recv as any).getExpression().getText());
    const isDrizzle = !isAdminApi && DRIZZLE_SINK.has(method) && !!drizzleRoot(recv);
    if (!isAdminApi && !isDrizzle) {
      if (!SINK.includes(method)) continue;
      const client = queryClient(recv);
      if (!client) continue;
      // Skip queries traced to a non-privileged client; RLS applies to those.
      // Untraceable clients stay in, since the action does use a service_role key.
      if (clientIsServiceRole(client) === false) continue;
    }
    const args = call.getArguments();
    // `.eq("token_hash", x)`: the caller must already know the secret.
    if (!isAdminApi && !isDrizzle && method === "eq" && args.length >= 2 &&
        (Node.isStringLiteral(args[0]) || Node.isNoSubstitutionTemplateLiteral(args[0])) &&
        SECRET_COL.test(args[0].getLiteralText())) continue;
    for (const arg of args) {
      for (const t of tainted as any) {
        if (!(t.getPos() >= arg.getPos() && t.getEnd() <= arg.getEnd())) continue;
        if (!isAdminApi && !isDrizzle && method === "insert") {
          const table = queryTable(recv);
          const col = insertColumn(t, arg);
          if (table && PUBLIC_TABLE.test(table) && col !== undefined && !PRIV_KEYS.has(col) && !/id$/.test(col)) {
            contentInsert = true;
            continue;
          }
        }
        sinkPos = Math.min(sinkPos, call.getPos());
        sinks.push({ call, t, arg, method, isAdminApi, isDrizzle });
      }
    }
  }
  if (sinkPos === Infinity) return contentInsert ? "public_write" : "no_tainted_sink";

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
  if (!guarded) {
    // `if (password !== process.env.ADMIN_PASSWORD) return`: the caller must know
    // a server-side secret. Treated like a token check.
    guarded = node.getDescendantsOfKind(SyntaxKind.IfStatement).some((st: any) => {
      if (st.getPos() >= sinkPos || !comparesToEnvSecret(st.getExpression().getText())) return false;
      const then = st.getThenStatement();
      const stmts = Node.isBlock(then) ? then.getStatements() : [then];
      const last = stmts[stmts.length - 1];
      return !!last && (Node.isReturnStatement(last) || Node.isThrowStatement(last));
    });
    if (guarded) return "guard_before_sink";
  }
  if (!guarded) {
    // `if (process.env.DEMO_MODE !== "true") throw ...` / `if (process.env.VERCEL_ENV === "production") return ...`:
    // the action only runs where the deployment opts in. Reported separately,
    // since a misconfigured environment still exposes it.
    const envGate = node.getDescendantsOfKind(SyntaxKind.IfStatement).some((st: any) => {
      if (st.getPos() >= sinkPos || !isEnvGate(st.getExpression().getText())) return false;
      const then = st.getThenStatement();
      const stmts = Node.isBlock(then) ? then.getStatements() : [then];
      const last = stmts[stmts.length - 1];
      return !!last && (Node.isReturnStatement(last) || Node.isThrowStatement(last));
    });
    if (envGate) return "env_gated";
    if (isPublicRead(node, sinks)) return "public_read";
    if (isAuthFlow(node, opts.name ?? "", sinks, taintedDecls)) return "auth_flow";
    return "flagged";
  }

  // A role check on user_metadata is not authorization: users can rewrite their
  // own user_metadata with supabase.auth.updateUser({ data: { ... } }).
  for (const cond of node.getDescendants()) {
    if (cond.getPos() >= sinkPos) break;
    const test =
      Node.isIfStatement(cond) ? cond.getExpression() :
      Node.isConditionalExpression(cond) ? cond.getCondition() : undefined;
    if (test && /\buser_metadata\b/.test(test.getText())) return "weak_guard";
  }
  if (!opts.preGuarded || opts.safeAction) {
    if (looksLikeIdor(node, sinks, sinkPos, taintedDecls, opts)) return "idor_candidate";
  }
  return "guard_before_sink";
}

// --- Public reads and auth flows (v0.7.0) --------------------------------------
// From the hand-labelled false positives: a quarter were reads of public data
// (catalog search, a syllabus tree) and logins / sign-ups. Both are recognised
// narrowly; anything that could leak or escalate stays flagged.

// Tables and columns whose rows belong to someone. Whole words, so `user_id`
// does not match `user`, but `users`, `profiles(email)` and `with: { user: true }` do.
const SENSITIVE = /\b(users?|profiles?|accounts?|members?|customers?|clients?|patients?|students?|employees?|staff|orders?|payments?|invoices?|billing|subscriptions?|transactions?|wallets?|messages?|chats?|conversations?|notifications?|sessions?|tokens?|api_?keys?|keys|secrets?|credentials?|passwords?|password_hash|emails?|phones?|phone_number|address(es)?|bookings?|reservations?|appointments?|applications?|submissions?|documents?|files?|notes?|journals?|diar(y|ies)|settings|salar(y|ies)|medical|health|grades?|private|drafts?|audit\w*|leads?|contacts?)\b/i;
const VISIBILITY = /publish|status|visib|is_?public|isPublic|active|deleted|approved|draft|archived/i;

function stmtOf(n: any): any {
  return n.getAncestors().find((a: any) => Node.isStatement(a) && !Node.isBlock(a)) ?? n;
}

function readTables(stmt: any): string[] | undefined {
  const names: string[] = [];
  for (const c of stmt.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const n = calleeName(c);
    const a0 = c.getArguments()[0];
    if (a0 && /^(from|leftJoin|innerJoin|rightJoin|fullJoin)$/.test(n)) {
      names.push(Node.isStringLiteral(a0) || Node.isNoSubstitutionTemplateLiteral(a0) ? a0.getLiteralText() : lastName(a0.getText()));
    }
  }
  for (const pa of stmt.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    const m = pa.getText().match(/\.query\.(\w+)\.(findFirst|findMany)$/);   // db.query.<table>.findMany
    if (m) names.push(m[1]);
  }
  return names.length ? names : undefined;
}

function isPublicRead(node: any, sinks: Sink[]): boolean {
  const text = node.getText();
  if (WRITE_CALL.test(text) || /\.rpc\s*\(|\.execute\s*\(|\bsql`/.test(text)) return false;
  if (!sinks.length || sinks.some((sk) => sk.isAdminApi)) return false;
  for (const sk of sinks) {
    const stmt = stmtOf(sk.call);
    const tables = readTables(stmt);
    if (!tables) return false;                                         // cannot tell what it reads
    if (tables.some((t) => SENSITIVE.test(t.replace(/([a-z])([A-Z])/g, "$1_$2")))) return false;
    if (SENSITIVE.test(stmt.getText())) return false;                  // joins, with:, selected columns
    // One row by its key with no visibility condition could be a draft or a
    // private row that only its owner should see.
    if (usedAsKey(sk) && !VISIBILITY.test(stmt.getText())) return false;
  }
  return true;
}

const LOGIN_NAME = /(log_?in|sign_?in|authenticate)/i;
const SIGNUP_NAME = /(sign_?up|register|join|create_?account|onboard)/i;
const PASSWORD_CHECK = /\b(compare|compareSync|verify|argon2|bcrypt|scrypt|timingSafeEqual|signInWithPassword|signInWithOtp|signInEmail|signIn)\s*\(/;
const LOGIN_WRITE_TABLE = /session|token|login|attempt|audit|log|otp|verification/i;
const SIGNUP_PRIV = new Set(["role", "roles", "admin", "isadmin", "permission", "permissions", "plan", "plantype",
  "tier", "credit", "credits", "balance", "verified", "isverified", "approved", "isapproved", "status",
  "appmetadata", "userid", "ownerid", "orgid", "organizationid", "tenantid", "teamid", "workspaceid", "accountid"]);

function isAuthFlow(node: any, name: string, sinks: Sink[], taintedDecls: Set<any>): boolean {
  const text = node.getText();
  const writes = node.getDescendantsOfKind(SyntaxKind.CallExpression).filter((c: any) =>
    /^(insert|update|delete|upsert|deleteUser|updateUserById|generateLink|inviteUserByEmail|createUser)$/.test(calleeName(c)));
  if (LOGIN_NAME.test(name) && !SIGNUP_NAME.test(name) && PASSWORD_CHECK.test(text)) {
    // A login may record a session or an attempt; any other write is not a login.
    return writes.every((c: any) => calleeName(c) === "insert" && LOGIN_WRITE_TABLE.test(stmtOf(c).getText()));
  }
  if (!SIGNUP_NAME.test(name)) return false;
  if (writes.some((c: any) => !/^(insert|createUser)$/.test(calleeName(c)))) return false;
  if (!writes.length && !/\.(signUp|signUpEmail)\s*\(/.test(text)) return false;
  if (sinks.some((sk) => sk.isAdminApi && sk.method !== "createUser")) return false;
  // The caller must not pick a role, a plan, a verified flag or someone else's
  // id, directly or by spreading their input into the row.
  const isT = (d: any) => taintedDecls.has(d) ||
    (Node.isBindingElement(d) && taintedDecls.has(d.getFirstAncestorByKind(SyntaxKind.VariableDeclaration)));
  const tainted = (n: any) => {
    if (!n) return false;
    const ids = Node.isIdentifier(n) ? [n] : n.getDescendantsOfKind(SyntaxKind.Identifier);
    return ids.some((i: any) => (resolveSymbol(i.getSymbol())?.getDeclarations() ?? []).some(isT));
  };
  const calls = writes.concat(node.getDescendantsOfKind(SyntaxKind.CallExpression)
    .filter((c: any) => /^(signUp|signUpEmail)$/.test(calleeName(c))));
  for (const c of calls) {
    for (const arg of c.getArguments()) {
      if (Node.isIdentifier(arg) && tainted(arg)) return false;                  // insert(input)
      for (const sp of arg.getDescendantsOfKind(SyntaxKind.SpreadAssignment)) if (tainted(sp.getExpression())) return false;
      for (const pa of arg.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
        if (SIGNUP_PRIV.has(norm(pa.getName())) && tainted(pa.getInitializer())) return false;
      }
      for (const sh of arg.getDescendantsOfKind(SyntaxKind.ShorthandPropertyAssignment)) {
        if (SIGNUP_PRIV.has(norm(sh.getName())) && (sh.getValueSymbol()?.getDeclarations() ?? []).some(isT)) return false;
      }
    }
  }
  return true;
}

// Does the repository authenticate anyone, anywhere? An app with no auth library
// and no auth call gets one repository-level finding instead of one per action:
// the fix is "add authentication", not N separate checks.
const AUTH_DEP = /^(next-auth|@auth\/|@clerk\/|better-auth|lucia|@lucia-auth\/|iron-session|@kinde-oss\/|@workos-inc\/|firebase|firebase-admin|@supabase\/auth-helpers|jose|jsonwebtoken|@stackframe\/|@propelauth\/|passport|bcrypt|bcryptjs|argon2|@node-rs\/argon2|@node-rs\/bcrypt|@oslojs\/|arctic|@descope\/|@auth0\/|@okta\/|@privy-io\/|@dynamic-labs\/|thirdweb|@hanko\/)/;
const AUTH_TEXT = /\.auth\.(getUser|getSession|getClaims|signIn\w*|signUp|admin)\b|\bgetServerSession\s*\(|\bcurrentUser\s*\(|\bauth\s*\(\s*\)/;
function repoHasAuth(project: any, repoPath: string): boolean {
  const pkgs: string[] = [];
  const walk = (dir: string, depth: number) => {
    if (depth > 4) return;
    let entries: fs.Dirent[] = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === "node_modules" || e.name.startsWith(".")) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p, depth + 1);
      else if (e.name === "package.json") pkgs.push(p);
    }
  };
  walk(repoPath, 0);
  for (const p of pkgs) {
    try {
      const j = JSON.parse(fs.readFileSync(p, "utf8"));
      const deps = Object.keys({ ...(j.dependencies ?? {}), ...(j.devDependencies ?? {}) });
      if (deps.some((d) => AUTH_DEP.test(d))) return true;
    } catch { /* unreadable package.json */ }
  }
  return project.getSourceFiles().some((f: any) => !f.isInNodeModules() && AUTH_TEXT.test(f.getFullText()));
}

// --- Authorization (IDOR) ---------------------------------------------------
// The action checks that *someone* is logged in, but does it check that the
// rows it touches are theirs? Candidate when a caller-supplied value is used
// as a key (an id-like column, an Admin API target, an owner column of an
// insert) and neither that query nor any check in the action involves the
// session user. Experimental: reported, but never fails the run.
interface Sink { call: any; t: any; arg: any; method: string; isAdminApi: boolean; isDrizzle: boolean }

const ID_COL = /(^id$|_id$|[a-z]Id$|^uuid$|^(owner|user|email|tenant|org|organization|company|team|workspace|account|member)$)/;
// Columns that say whose a new row is. A caller-chosen foreign key to a shared
// entity (productId, restaurantId) is normal; a caller-chosen owner is not.
const OWNER_KEY = /^(owner|user|createdby|addedby|(user|owner|org|organization|tenant|company|team|workspace|account|member|author|creator|profile)id)$/;
const norm = (k: string) => k.replace(/['"`]/g, "").replace(/_/g, "").toLowerCase();
// A local guard whose body makes a role/permission decision authorizes, not
// just authenticates: requireAdmin(), guardAgent(), requireStaff("x"), requireCan("x").
const ROLE_BODY = /role|admin|permission|\bstaff\b|\bcan\(|hasAccess/i;
const AUTHZ_NAME = /(admin|role|permission|owner|member|access|^can[A-Z]|[a-z]Can([A-Z]|$)|authori[sz]e|policy|ability|belongs|isAllowed|staff|manager|moderator|superuser)/i;
const WRITE_CALL = /\.(update|delete|insert|upsert)\s*\(|\b(deleteUser|updateUserById|generateLink|inviteUserByEmail|createUser)\b/;

function lastName(text: string): string {
  const m = text.match(/([A-Za-z_$][\w$]*)\s*$/);
  return m ? m[1] : text;
}

// Is the tainted node used as the key that picks rows (or the owner of a new row)?
function usedAsKey(sk: Sink): boolean {
  const { call, t, arg, method, isAdminApi, isDrizzle } = sk;
  if (isAdminApi) return true;
  const args = call.getArguments();
  if (!isDrizzle) {
    if (["eq", "in", "filter"].includes(method)) {
      const col = args[0];
      if (col && (Node.isStringLiteral(col) || Node.isNoSubstitutionTemplateLiteral(col))) {
        return ID_COL.test(col.getLiteralText().split(".").pop() ?? "");
      }
      return false;
    }
    if (method === "match") {
      const pa = t.getFirstAncestorByKind(SyntaxKind.PropertyAssignment);
      return !!pa && ID_COL.test(pa.getName());
    }
    if (method === "insert" || method === "upsert") {
      const col = insertColumn(t, arg);   // normalised: lower case, no underscores
      return col !== undefined && OWNER_KEY.test(norm(col));
    }
    return false;
  }
  if (method === "values") {
    const pa = t.getFirstAncestorByKind(SyntaxKind.PropertyAssignment);
    const sh = t.getParent();
    const name = pa && pa.getPos() >= arg.getPos() ? pa.getName()
      : Node.isShorthandPropertyAssignment(sh) ? sh.getName() : undefined;
    return !!name && OWNER_KEY.test(norm(name));
  }
  if (method === "set") return false;
  // where / findFirst / findMany: eq(table.col, x), inArray(table.col, xs)
  for (const c of t.getAncestors()) {
    if (c === call) break;
    if (Node.isCallExpression(c) && /^(eq|inArray|ne)$/.test(calleeName(c))) {
      const a0 = c.getArguments()[0];
      const col = a0 ? lastName(a0.getText()) : "";
      return ID_COL.test(col) && !SECRET_COL.test(col);
    }
    if (Node.isPropertyAssignment(c) && c.getName() !== "where") return ID_COL.test(c.getName());
  }
  return false;
}

function looksLikeIdor(node: any, sinks: Sink[], sinkPos: number, taintedDecls: Set<any>, opts: ClassifyOpts): boolean {
  // Session-derived declarations: initialised from a guard call, then anything
  // computed from those (`const userId = user.id`, a profile read by user.id).
  const guardCalls = node.getDescendantsOfKind(SyntaxKind.CallExpression)
    .filter((c: any) => isGuardCall(c, 0, new Set()));
  const inGuard = (n: any) => guardCalls.some((g: any) => n.getPos() >= g.getPos() && n.getEnd() <= g.getEnd());
  const session = new Set<any>();
  const vds = node.getDescendantsOfKind(SyntaxKind.VariableDeclaration);
  for (const vd of vds) {
    const init = vd.getInitializer();
    if (init && guardCalls.some((g: any) => g.getPos() >= init.getPos() && g.getEnd() <= init.getEnd())) {
      session.add(vd);
      vd.getNameNode().getDescendantsOfKind(SyntaxKind.BindingElement).forEach((b: any) => session.add(b));
    }
  }
  const declOf = (i: any) => {
    const par = i.getParent();
    const sym = Node.isShorthandPropertyAssignment(par) && par.getNameNode() === i ? par.getValueSymbol() : i.getSymbol();
    return resolveSymbol(sym)?.getDeclarations() ?? [];
  };
  // `ctx = await assertManager()` (assigned, not declared)
  for (const be of node.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
    if (be.getOperatorToken().getText() !== "=" || !Node.isIdentifier(be.getLeft())) continue;
    if (guardCalls.some((g: any) => g.getPos() >= be.getRight().getPos() && g.getEnd() <= be.getRight().getEnd())) {
      declOf(be.getLeft()).forEach((d: any) => session.add(d));
    }
  }
  // `if (!proj) throw new Error("Unauthorized")`: proj is what the guard decided on.
  for (const st of node.getDescendantsOfKind(SyntaxKind.IfStatement)) {
    if (!AUTH_ERROR.test(st.getThenStatement().getText())) continue;
    for (const i of st.getExpression().getDescendantsOfKind(SyntaxKind.Identifier).concat(
      Node.isIdentifier(st.getExpression()) ? [st.getExpression()] : [])) {
      declOf(i).filter((d: any) => Node.isVariableDeclaration(d) || Node.isBindingElement(d)).forEach((d: any) => session.add(d));
    }
  }
  const refsSession = (n: any): boolean => {
    if (inGuard(n) || guardCalls.some((g: any) => g.getPos() >= n.getPos() && g.getEnd() <= n.getEnd())) return true;
    if (opts.safeAction && /\bctx\b/.test(n.getText())) return true;
    const ids = Node.isIdentifier(n) ? [n] : n.getDescendantsOfKind(SyntaxKind.Identifier);
    return ids.some((i: any) => declOf(i).some((d: any) => session.has(d)));
  };
  for (let pass = 0; pass < 2; pass++) {
    for (const vd of vds) {
      if (session.has(vd)) continue;
      const init = vd.getInitializer();
      if (init && refsSession(init)) {
        session.add(vd);
        vd.getNameNode().getDescendantsOfKind(SyntaxKind.BindingElement).forEach((b: any) => session.add(b));
      }
    }
  }
  // Destructured locals (`const { projectId } = schema.parse(...)`) declare on
  // a binding element; the tainted set holds its variable declaration.
  const isTaintedDecl = (d: any) => taintedDecls.has(d) ||
    (Node.isBindingElement(d) && taintedDecls.has(d.getFirstAncestorByKind(SyntaxKind.VariableDeclaration)));
  const touchesTaint = (n: any) => {
    const ids = Node.isIdentifier(n) ? [n] : n.getDescendantsOfKind(SyntaxKind.Identifier);
    return ids.some((i: any) => declOf(i).some(isTaintedDecl));
  };
  const exits = (st: any) => {
    const then = st.getThenStatement();
    const stmts = Node.isBlock(then) ? then.getStatements() : [then];
    const last = stmts[stmts.length - 1];
    return !!last && (Node.isReturnStatement(last) || Node.isThrowStatement(last) ||
      /\b(redirect|notFound|forbidden|unauthorized)\s*\(/.test(then.getText()));
  };
  // A decision about the session user beyond "is there one": a comparison, a
  // call, or a role/ownership read. `if (!user) throw` does not count.
  const decides = (cond: any) =>
    [cond, ...cond.getDescendantsOfKind(SyntaxKind.BinaryExpression)].some((b: any) => Node.isBinaryExpression(b) &&
      /^(===|!==|==|!=)$/.test(b.getOperatorToken().getText())) ||
    cond.getDescendantsOfKind(SyntaxKind.CallExpression).length > 0 ||
    /role|admin|permission|owner|member/i.test(cond.getText());
  // ...or a server-side secret the caller must know (`token !== process.env.MOD_TOKEN`):
  // whoever holds it is privileged, so any id is fair game.
  const checks = node.getDescendantsOfKind(SyntaxKind.IfStatement)
    .filter((st: any) => (exits(st) || isLoginRedirectStmt(st)) &&
      ((refsSession(st.getExpression()) && decides(st.getExpression())) || comparesToEnvSecret(st.getExpression().getText())));
  // A helper that is handed both the session and the caller's id
  // (`assertOwner(user.id, projectId)`), or a role-named guard (`requireAdmin()`).
  const authzCalls = node.getDescendantsOfKind(SyntaxKind.CallExpression).filter((c: any) => {
    const name = calleeName(c);
    const isGuard = isGuardCall(c, 0, new Set());
    if (AUTHZ_NAME.test(name) && (isGuard || localCallee(c) || GUARD_NAME.test(name))) return true;
    const a = c.getArguments();
    // a guard handed the caller's id checks access to it: authProject({ projectId })
    if (isGuard && a.some((x: any) => touchesTaint(x))) return true;
    if (isGuard) {
      const fn = localCallee(c);
      if (fn && ROLE_BODY.test(fn.getText())) return true;
    }
    // invariant(session.user.role === "admin", "...")
    if (/^(invariant|assert|ensure|check)/i.test(name) && a.some((x: any) => refsSession(x) && decides(x))) return true;
    return a.some((x: any) => refsSession(x)) && a.some((x: any) => touchesTaint(x));
  });
  // A read of a referenced row (the product to favourite, the event to join)
  // followed by a write scoped to the session user is a lookup, not a leak.
  const scopedWrites = node.getDescendantsOfKind(SyntaxKind.CallExpression)
    .filter((c: any) => /^(insert|update|delete|upsert)$/.test(calleeName(c)))
    .map((c: any) => c.getAncestors().find((x: any) => Node.isStatement(x) && !Node.isBlock(x)) ?? c)
    .filter((st: any) => refsSession(st));

  function isLoginRedirectStmt(st: any) {
    return st.getThenStatement().getDescendantsOfKind(SyntaxKind.CallExpression).some((c: any) => isLoginRedirect(c)) ||
      (Node.isExpressionStatement(st.getThenStatement()) && Node.isCallExpression(st.getThenStatement().getExpression()) &&
       isLoginRedirect(st.getThenStatement().getExpression()));
  }
  const statementOf = (n: any) => n.getAncestors().find((a: any) => Node.isStatement(a) && !Node.isBlock(a)) ?? n;
  for (const sk of sinks) {
    if (!usedAsKey(sk)) continue;
    const stmt = statementOf(sk.call);
    if (refsSession(stmt)) continue;                       // the query itself is scoped to the session
    const pos = sk.call.getPos();
    const isWrite = sk.isAdminApi || WRITE_CALL.test(stmt.getText());
    if (!isWrite && scopedWrites.some((c: any) => c.getPos() > pos)) continue;
    // Writes must be authorized before they run; a read may be checked after
    // (`if (doc.ownerId !== user.id) throw`) as long as it is not returned first.
    const ok = checks.some((st: any) => isWrite ? st.getPos() < pos : true) ||
      authzCalls.some((c: any) => c !== sk.call && !(c.getPos() >= stmt.getPos() && c.getEnd() <= stmt.getEnd()) &&
        (isWrite ? c.getPos() < pos : true));
    if (!ok) {
      if (process.env.ACTIONGUARD_DEBUG) console.error(`idor: ${stmt.getText().slice(0, 200).replace(/\s+/g, " ")} | checks=${checks.length} authz=${authzCalls.map((c: any) => calleeName(c)).join(",")} session=${[...session].map((d: any) => d.getName?.()).join(",")}`);
      return true;
    }
  }
  return false;
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
        if (target) markThrough(target, dynamicImportNames(c));
      }
    }
  }
  return out;
}

// Which exports does a client-side import("...") use? Next >= 15 ships action
// ids to the browser only for the exports the client code picks out; the
// others get a fresh unguessable id each build and cannot be called. Checked
// against a next@16.2.0 build: `import("./m").then(({ a }) => a())` puts only
// a's id in the client chunks.
//   import("m").then(({ a, b }) => ...)                 -> [a, b]
//   const { a } = await import("m")                    -> [a]
//   Promise.all([import("m"), ...])                    -> "*" (namespaces kept whole)
//   const m = await import("m"); m.a()                 -> "*" (namespace kept whole)
//   anything else (spread, passing the module around)  -> "*"
function dynamicImportNames(call: any): string[] | "*" {
  const fromBinding = (b: any): string[] | "*" => {
    if (!b) return "*";
    if (Node.isObjectBindingPattern(b)) {
      const els = b.getElements();
      if (els.some((e: any) => e.getDotDotDotToken())) return "*";
      return els.map((e: any) => e.getPropertyNameNode()?.getText() ?? e.getName());
    }
    // `const m = await import("m"); m.a()`: the bundler keeps the whole
    // namespace, so every export's id reaches the browser (checked: next@16.2.0).
    return "*";
  };
  let node: any = call;
  let parent: any = node.getParent();
  // import("m").then(({ a }) => ...)
  if (Node.isPropertyAccessExpression(parent) && parent.getName() === "then") {
    const thenCall = parent.getParent();
    const fn = Node.isCallExpression(thenCall) ? thenCall.getArguments()[0] : undefined;
    if (fn && (Node.isArrowFunction(fn) || Node.isFunctionExpression(fn))) {
      return fromBinding(fn.getParameters()[0]?.getNameNode());
    }
    return "*";
  }
  // Promise.all([import("m"), ...]) keeps every namespace whole (checked:
  // next@16.2.0 ships all ids even when the slot is destructured).
  if (Node.isArrayLiteralExpression(parent)) return "*";
  if (Node.isAwaitExpression(parent)) {
    node = parent;
    parent = node.getParent();
  }
  while (Node.isParenthesizedExpression(parent)) { node = parent; parent = node.getParent(); }
  if (Node.isVariableDeclaration(parent) && parent.getInitializer() === node) return fromBinding(parent.getNameNode());
  return "*";
}

// true when the repository defines Drizzle tables and none of them has an
// owner-like column (user_id, ownerId, organization_id, tenant, created_by...).
const OWNER_COL_TEXT = /["'`]?\b(user_?id|owner(_?id)?|org(anization)?_?id|tenant(_?id)?|team_?id|workspace_?id|account_?id|member_?id|created_?by|author_?id|profile_?id)\b/i;
function drizzleSchemaHasNoOwner(project: any): boolean {
  const tables = project.getSourceFiles().filter((f: any) => /\b(pgTable|sqliteTable|mysqlTable)\s*\(/.test(f.getFullText()));
  if (!tables.length) return false;
  return !tables.some((f: any) => OWNER_COL_TEXT.test(f.getFullText()));
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
  let singleUser: boolean | undefined;
  let noAuthApp: boolean | undefined;
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
      const db = usesServiceRoleClient(node) ? "supabase" : usesDrizzleClient(node) ? "drizzle" : undefined;
      if (!db) continue;
      let verdict = classify(node, { ...opts, name });
      // A Drizzle schema with no per-user or per-tenant column is a single-user
      // app: there is nobody else's row to reach.
      if (verdict === "idor_candidate" && db === "drizzle") {
        singleUser ??= drizzleSchemaHasNoOwner(project);
        if (singleUser) verdict = "guard_before_sink";
      }
      if ((verdict === "flagged" || verdict === "weak_guard" || verdict === "idor_candidate") && major !== undefined && major >= 15) {
        exposed ??= exposedExports(project);
        const names = exposed.get(file);
        if (!names || !(names.has("*") || names.has(name))) verdict = "unreferenced";
      }
      let reason: string | undefined;
      if (verdict === "flagged" || verdict === "weak_guard" || verdict === "unreferenced" || verdict === "idor_candidate") {
        reason = stmt ? ignoreReason(stmt) : undefined;
        if (reason) verdict = "ignored";
      }
      if (verdict === "flagged") {
        noAuthApp ??= !repoHasAuth(project, repoPath);
        if (noAuthApp) verdict = "no_auth";
      }
      findings.push({
        verdict,
        file: path.relative(repoPath, file.getFilePath()),
        fn: name,
        line: node.getStartLineNumber(),
        db,
        ...(reason ? { reason } : {}),
      });
    }
  }
  return findings;
}

// --- CLI -------------------------------------------------------------------

const argv = process.argv.slice(2);
// Drizzle has no row-level security, so its queries are as privileged as a
// service_role query; name the client the finding actually uses.
const sinkName = (f: Finding) => f.db === "drizzle" ? "Drizzle query (no RLS)" : "service_role query";
if (argv.includes("--version") || argv.includes("-v")) {
  console.log(JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8")).version);
  process.exit(0);
}
if (argv.includes("-h") || argv.includes("--help")) {
  console.log(`actionguard <path> [--json] [--all]

  Scans exported Server Actions that use a Supabase service_role client or a
  Drizzle client (experimental) and reports ones where a caller-supplied value
  reaches a query (or an Admin API call) with no auth check running first.

  Reported (exit code 1):
    flagged       no guard before the privileged query
    weak_guard    guarded by a user_metadata check, which users can rewrite
    no_auth       the whole app has no authentication; reported once for the repo
  Not reported (continued):
    public_read   only reads non-sensitive tables by non-key or published-only filters
    auth_flow     a login, or a sign-up where the caller cannot choose a role or id
  Experimental (listed, exit code unaffected):
    idor_candidate  logged in is checked, but a caller-supplied id picks the
                    rows and nothing ties it to the session user
  Not reported (exit code 0, listed with --all):
    unreferenced  Next.js >= 15 and no client code references it
    public_write  only inserts caller values into content columns (a form)
    env_gated     unguarded, but returns early unless an environment variable allows it
    ignored       marked // actionguard-ignore: <reason>

  --json    machine-readable output
  --all     also list actions that passed
  --github  GitHub Actions: line annotations, job summary, \`findings\` output

  Measured precision on unseen repositories is about one in three.
  Read each finding before acting on it.
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
const idor = findings.filter((f) => f.verdict === "idor_candidate");
const noAuth = findings.filter((f) => f.verdict === "no_auth");

if (asJson) {
  console.log(JSON.stringify({
    repository: repoPath,
    server_actions_using_service_role: findings.length,
    flagged: flagged.length,
    weak_guard: findings.filter((f) => f.verdict === "weak_guard").length,
    idor_candidate: idor.length,
    no_auth: noAuth.length,
    public_read: findings.filter((f) => f.verdict === "public_read").length,
    auth_flow: findings.filter((f) => f.verdict === "auth_flow").length,
    unreferenced: findings.filter((f) => f.verdict === "unreferenced").length,
    public_write: findings.filter((f) => f.verdict === "public_write").length,
    env_gated: findings.filter((f) => f.verdict === "env_gated").length,
    ignored: findings.filter((f) => f.verdict === "ignored").length,
    guard_before_sink: findings.filter((f) => f.verdict === "guard_before_sink").length,
    no_tainted_sink: findings.filter((f) => f.verdict === "no_tainted_sink").length,
    findings,
  }, null, 2));
} else {
  if (findings.length === 0) {
    console.log("No Server Actions using a service_role or Drizzle client were found.");
  } else {
    for (const f of flagged) {
      console.log(`  ${f.file}:${f.line}  ${f.fn}`);
      console.log(f.verdict === "weak_guard"
        ? `      guarded by a user_metadata check, which users can rewrite themselves`
        : `      argument reaches a ${sinkName(f)} with no guard before it`);
    }
    if (noAuth.length) {
      console.log(`  This app has no authentication anywhere (no auth library, no auth call).`);
      console.log(`      ${noAuth.length} Server Actions using a privileged client are open to anyone; add authentication first.`);
      if (showAll) for (const f of noAuth) console.log(`      ${f.file}:${f.line}  ${f.fn}`);
      else console.log(`      (list them with --all)`);
    }
    if (idor.length) {
      console.log(`\n  Possible IDOR (experimental, does not fail the run):`);
      for (const f of idor) {
        console.log(`  ${f.file}:${f.line}  ${f.fn}`);
        console.log(`      logged in is checked, but a caller-supplied id picks the rows and nothing ties it to the session user`);
      }
    }
    if (showAll) {
      for (const f of findings.filter((x) => !["flagged", "weak_guard", "idor_candidate", "no_auth"].includes(x.verdict))) {
        console.log(`  ok  ${f.file}:${f.line}  ${f.fn}  (${f.verdict}${f.reason ? `: ${f.reason}` : ""})`);
      }
    }
    console.log(
      `\n${findings.length} Server Actions using a privileged client, ` +
      `${flagged.length} flagged, ` +
      (noAuth.length ? `${noAuth.length} in an app with no auth, ` : "") +
      (idor.length ? `${idor.length} possible IDOR, ` : "") +
      `${findings.length - flagged.length - noAuth.length - idor.length} passed.`
    );
    if (flagged.length || noAuth.length) {
      console.log(
        "\nThese are candidates, not confirmed vulnerabilities. Public endpoints that\n" +
        "legitimately take a tenant key or public token look identical to this check.\n" +
        "Read each one before acting on it."
      );
    }
  }
}

// --- GitHub Actions --------------------------------------------------------
// --github: annotate each reported action on its line, write a table to the
// job summary, and set the `findings` output. Annotations are warnings, not
// errors: measured precision is about one in three, so each one is a
// candidate to read.
if (argv.includes("--github")) {
  const ws = process.env.GITHUB_WORKSPACE || process.cwd();
  const rel = (f: Finding) => path.relative(ws, path.join(repoPath, f.file)).split(path.sep).join("/");
  const esc = (s: string) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
  const escProp = (s: string) => esc(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
  const message = (f: Finding) => f.verdict === "weak_guard"
    ? `${f.fn}: the admin check reads user_metadata, which users can change themselves. Read the role from app_metadata or a protected table.`
    : `${f.fn}: a caller-supplied value reaches a ${sinkName(f)} with no auth check before it. Server Actions are public POST endpoints. Add a session/role check, or mark it // actionguard-ignore: <reason> if it is public on purpose.`;
  for (const f of idor) {
    console.log(`::notice file=${escProp(rel(f))},line=${f.line},title=${escProp("ActionGuard: possible IDOR")}::${esc(`${f.fn}: a logged-in user can pass any id here; nothing compares it with the session user. Scope the query by the session user (or check ownership) before using it.`)}`);
  }
  if (noAuth.length) {
    const f = noAuth[0];
    console.log(`::warning file=${escProp(rel(f))},line=${f.line},title=${escProp("ActionGuard: no authentication")}::${esc(`This app has no authentication anywhere. ${noAuth.length} Server Actions using a privileged client are open to anyone (first: ${f.fn}).`)}`);
  }
  for (const f of flagged) {
    console.log(`::warning file=${escProp(rel(f))},line=${f.line},title=${escProp("ActionGuard: " + f.verdict)}::${esc(message(f))}`);
  }
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    const cell = (s: string) => s.replace(/\|/g, "\\|");
    const lines = [
      "## ActionGuard",
      "",
      `${findings.length} Server Actions using a privileged client (service_role or Drizzle), **${flagged.length} reported**.`,
      "",
    ];
    if (flagged.length) {
      lines.push("| Action | File | Verdict |", "|---|---|---|");
      for (const f of flagged) lines.push(`| \`${cell(f.fn)}\` | \`${cell(rel(f))}:${f.line}\` | ${f.verdict} |`);
      lines.push("", "These are candidates, not confirmed vulnerabilities. Read each one before acting on it.");
    }
    try { fs.appendFileSync(summaryPath, lines.join("\n") + "\n"); } catch { /* summary is optional */ }
  }
  const outPath = process.env.GITHUB_OUTPUT;
  if (outPath) {
    try { fs.appendFileSync(outPath, `findings=${flagged.length}\n`); } catch { /* output is optional */ }
  }
}

process.exit(flagged.length > 0 || noAuth.length > 0 ? 1 : 0);

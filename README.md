# actionguard

[![npm](https://img.shields.io/npm/v/@kobahiro/actionguard)](https://www.npmjs.com/package/@kobahiro/actionguard)
[![self-test](https://github.com/66088kobayashi-ship-it/actionguard/actions/workflows/self-test.yml/badge.svg)](https://github.com/66088kobayashi-ship-it/actionguard/actions/workflows/self-test.yml)
[![license](https://img.shields.io/github/license/66088kobayashi-ship-it/actionguard)](LICENSE)

Static analysis for Next.js Server Actions: does a caller-supplied identifier reach a
privileged database query — a Supabase `service_role` client or, since v0.5.0, a Drizzle
client (experimental) — without passing a guard?

```bash
npx @kobahiro/actionguard <path-to-repo>
```

Or in CI, on every push and pull request. Reported actions show up as warnings on their
lines in the pull request, with a table in the job summary:

```yaml
# .github/workflows/actionguard.yml
name: ActionGuard
on: [push, pull_request]
permissions:
  contents: read
jobs:
  actionguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: 66088kobayashi-ship-it/actionguard@v0.5.2
        # with:
        #   path: apps/web              # where the Next.js app lives
        #   fail-on-findings: "false"   # report without failing the job
```

Measured precision on repositories it was never tuned on: **28% (7/25) and 44% (4/9)**.
Roughly one finding in three is a real authorization hole; the rest are mostly endpoints
that are public on purpose. Every finding is a candidate to read, not a verdict. How
those numbers were measured is [below](#measured-precision).

---

## Why

In Next.js, every exported function in a `"use server"` file is a public HTTP endpoint.
A helper you only ever call from another server function is still callable directly by
anyone. If that helper takes a `userId` and hands it to a `service_role` Supabase client
(which bypasses row-level security), the caller chooses whose row gets written.

## What already exists

`@clerk/eslint-plugin`'s `require-auth-protection` rule. It does what it was built to do:
you declare which folders are protected, and it checks that each Server Function calls
`auth.protect()`. Its documentation is explicit about the boundaries — it does not follow
protection across files or through wrapper calls, and it does not check authorization
correctness, only presence.

That is a reasonable scope. The gap is that it recognises Clerk's API. If you authenticate
with Supabase, NextAuth or Lucia, there is no equivalent. Running the Clerk rule against
40 Supabase projects with `protected: ['**']` produced 1,456 Server Function violations —
which is the correct behaviour for a misapplied tool, not a defect in it.

## What this does

An AST pass (ts-morph) over exported functions in `"use server"` files that construct or
import a `service_role` client. Wrapped actions count too: `withAuth(async (id) => ...)` and
next-safe-action style `client.schema(s).action(async ({ parsedInput, ctx }) => ...)`, where
only `parsedInput` is treated as caller-supplied.

1. Build a taint set from the function's parameters via symbol resolution — including
   destructured ones (`{ userId }`) — with one hop of propagation through local variable
   assignments.
2. Find the first `.eq/.in/.match/.insert/.update/.upsert/.delete` call receiving a tainted
   node, counting only calls that sit on a `<client>.from(...)` query chain whose client
   traces back to a `service_role` key. The client is followed through variables,
   reassignments, local factory functions (including `cache(() => ...)` wrappers) and
   library calls such as `createClient(url, key)`. A query on the user's anon/cookie client
   is skipped, since RLS applies to it, even if the action reads the service_role key
   elsewhere. A client that cannot be traced is kept.
   Supabase Admin API calls (`.auth.admin.deleteUser(id)`, `updateUserById`, …) are sinks
   too, since they only run with a service_role key.
3. Look for a guard call positioned **before** that sink. A guard is a known auth call
   (`.getUser()`, `.getSession()`, `auth()`, `currentUser()`, `unauthorized()`, …), a
   hand-written check that throws an auth error (`throw new Error("Unauthorized")`) or
   redirects to a login page, or a function in the repository that does any of these
   within six helper levels (`cache(loadUser)` wrappers are followed). Local helpers are judged by what
   they do, not by their name: `getProfileOrThrow()` counts, a local `validateEmail()` does
   not. A name pattern (`require*`, `verify*`, `assert*`, …) is used only when the callee's
   source is not in the repository. For a wrapped action, the wrapper or the client's
   middleware chain (`authActionClient = actionClient.use(...)`) counts as a guard when it
   makes an auth call or throws an auth error (`throw new Error("Unauthorized")`).

| Verdict | Meaning | Exit code |
|---|---|---|
| `flagged` | caller-supplied value reaches a service_role sink with no guard before it | 1 |
| `weak_guard` | guarded, but the check reads `user_metadata`, which users can rewrite with `supabase.auth.updateUser` | 1 |
| `ignored` | would be reported, but marked `// actionguard-ignore: <reason>` | 0 |
| `unreferenced` | would be flagged, but on Next.js ≥ 15 no client code references it, so it gets no action ID | 0 |
| `env_gated` | unguarded, but returns or throws early unless an opt-in flag allows it (`DEMO_MODE !== "true"`, `!ENABLE_RESET`) or when running in production (`NODE_ENV === "production"`). A check that a setting exists (`!process.env.SUPABASE_SERVICE_ROLE_KEY`) is not a gate and stays `flagged`. A misconfigured deployment still exposes it | 0 |
| `public_write` | only inserts caller values into content columns of a public-submission table (contact, feedback, waitlist, reports...). Any `*_id`, role, owner or status column keeps it `flagged` | 0 |
| `guard_before_sink` / `no_tainted_sink` | passed | 0 |

`unreferenced` applies only when the nearest `package.json` pins `next` to 15 or later. An
export counts as referenced when a client module imports it (a `"use client"` file, or any
module such a file imports, directly or through barrels and `import()`), or when a server
component passes it on as a value (`<form action={save}>`, a prop) instead of calling it.
Type-only imports and test files do not count. Only the names actually imported through a
barrel count, not everything it re-exports. The same goes for `import()`: when client code
destructures it (`import("./m").then(({ a }) => ...)`, `const { a } = await import("./m")`,
`Promise.all([...])` slots) or only reads properties of the module, only those names count.
Checked against a next@16.2.0 build: the other exports get a server-side ID that changes every
build and is never sent to the browser. It is still worth fixing: the
day a client component imports it, it becomes an endpoint.

Exit code 1 if anything is `flagged` or `weak_guard`, so it drops into CI.

### Suppressing a finding

Some actions are meant to be public, and the syntax cannot say so: an anonymous view
counter takes a `slug`, which is a public key, not an identity. Mark those in the comment
directly above the export, with the reason:

```ts
// actionguard-ignore: anonymous view counter, slug is a public article key
export async function incrementViewCount(slug: string) { ... }
```

The finding becomes `ignored` (exit code 0) and is listed with its reason under `--all`
and in `--json`, so suppressions stay reviewable.

`npm test` runs the scanner against `test/fixtures/` and checks each verdict.

## Measured precision

Each rule change in this tool was made while looking at real findings, so precision measured
on those same repositories says little. The numbers here come from repositories collected
*after* the scanner version was frozen, with no overlap with anything used to tune it.

| | Held-out set 1 | Held-out set 2 |
|---|---|---|
| Scanner version | `79a0e17` | `ec8621a` |
| Repositories (Supabase + `"use server"`) | 216 | 105 |
| Server Actions using a service_role client | 409 | 129 |
| Reported | 92 in 22 repos | 9 in 6 repos |
| Hand-checked | 25 (random, ≤2 per repo) | all 9 |
| Real authorization holes | 7 | 4 |
| **Precision** | **28%** (95% CI 14–48%) | **44%** (95% CI 19–73%) |

Repositories came from GitHub repository search (Supabase + Next.js, TypeScript, several
queries and sort orders), shallow-cloned, filtered to projects depending on
`@supabase/supabase-js` with at least one `"use server"` file. Findings were judged by reading
the code only; nothing was run against a deployment.

**What the false positives were** (set 1, 18 of 25):

- 9 — public on purpose: anonymous ratings and view counters, public catalogues, lookups by a
  secret or signed token, sign-up. The syntax does not say "this is meant to be public"; mark
  these with `// actionguard-ignore: <reason>`.
- 6 — a guard the scanner missed (auth four helpers deep, `cache(fn)` wrappers, hand-written
  checks that throw). Fixed in `ec8621a`.
- 3 — actions no client code can reach on Next.js ≥ 15. Fixed in `ec8621a`.

In set 2 all 5 false positives were public on purpose (sign-up ×3, a contact form, a public
profile). Do not suppress sign-up actions wholesale: one of the real findings in set 2 was a
sign-up action that reset the password of *any* existing account.

**What the real findings were:** admin actions protected only by path-based middleware;
member and payment management with no session check at all; a bulk export of survey responses
for any campaign ID; report and task reads across workspaces; an account takeover through
sign-up. All were reported privately to the maintainers. Repositories are not named here.

The precision interval is wide because the samples are small. Treat it as "about a third",
not as a precise rate.

**Misses.** In a third fresh set (223 repositories, scanner `ec8621a`/v0.2.0), I hand-read 30
actions it had passed, chosen at random (one per repository; 15 guarded, 10 with no tainted
sink, 5 unreferenced). None was a hole it should have reported: 0/30, so the miss rate among
the actions it analyzes is below about 10% (95% upper bound). This says nothing about
authorization bugs outside its scope: databases other than Supabase, RLS policies, a
service_role client reached through an object property, or admin actions that take no
arguments at all.

### v0.4.0: rules from a false-positive review (November 2026)

I rescanned 1,037 new repositories from November 3–4 with v0.3.0: 194 had a reported action.
Each was read by an automated reviewer (Claude, reading the source; the 26 most severe were
re-read by hand before reporting). 101 repositories had a real hole, 87 had only false
positives, 6 were unclear. I then hand-classified the false positives in 30 of the 87:

- 16 — public on purpose: sign-up, login, contact forms, waitlists, anonymous reports, checkout.
- 7 — gated by a secret the caller must already hold (a hashed token, an access key, a share link).
- 3 — a guard the scanner missed: a signed admin cookie verified with HMAC, an early `return` on
  a failed check, a session-client RPC that throws.
- 2 — single-user or demo apps with a fixed user ID. 2 — other.

v0.4.0 adds three rules for the first three groups: `.eq()` on a secret column (`token`,
`secret`, `access_key`, `otp`, `nonce`, `hash`) is no longer a sink; content-only inserts into
public-submission tables become `public_write`; a local helper that reads `cookies()`/`headers()`
**and** verifies them (HMAC, hash compare, JWT) counts as a guard — reading a cookie alone does
not. It also follows `{ name, price }` shorthand properties, which v0.3.0 missed.

Rerun on the same 194 repositories: all 101 real ones are still reported (no repository lost;
the 29 actions that dropped out of real repositories were token lookups, public submissions
and actions that do check a signed session). False-positive actions fell from 223 to 151 (−32%) and 12 of the 87
false-positive repositories are now clean. Precision at repository level moved from about 52% to
about 56% on this set — real, but small: most remaining false positives are sign-up and login
actions, which look exactly like the account-takeover sign-ups among the real findings.

> Everything below this point is the original study, run with v0.1.0 (guards matched by name
> prefix only, no helper or destructuring support). Kept for the record.

### Drizzle (experimental, v0.5.0)

A Drizzle client connects with the app's own database credentials, so there is no
row-level security between a Server Action and the data: every Drizzle query is as
privileged as a Supabase `service_role` query. v0.5.0 scans Drizzle actions with the same
taint and guard analysis. Sinks are `.where()`, `.set()`, `.values()`,
`.onConflictDoUpdate()` and `db.query.<table>.findFirst/findMany({ where })` on chains
rooted at a `drizzle(...)` client, a lazily built one (`db()`, `getDb()`, a Proxy, `this.db`)
in a file that imports `drizzle-orm`, or the `tx` of `db.transaction()`. Each finding
carries `db: "supabase" | "drizzle"`.

Measured on 124 repositories that import `drizzle-orm` from `"use server"` files (GitHub
code search, November 2026): 78 had a reported action. I hand-read 60 reported actions
(at most two per repository in the second batch). After two fixes found during that review
— helpers that return a result object (`if (!guard.ok) return guard`) backed by a
Web Crypto HMAC session, and early `process.env` exits now reported as `env_gated` —
35 of the 55 remaining were real (**about 64%**). The rest were mostly public on purpose,
gated by a secret token, or a single-user local app. Treat it as experimental: the sample
is small and the shapes of Drizzle code vary more than Supabase's.

## The corpus

GitHub repository search for Supabase + Next.js TypeScript projects, ~600 shallow clones,
filtered to repos whose `package.json` depends on `@supabase/supabase-js` and which contain
at least one file with a `"use server"` directive.

**259 repositories. 0 scan failures.**

## Results

| | |
|---|---|
| Server Actions using a `service_role` client | 499 |
| Guard found before the sink | 255 |
| No tainted argument reaches a sink | 133 |
| **Flagged** | **111 (22%)** |

Flagged findings appeared in 17 of 259 repositories. The distribution is heavily skewed —
the top repository accounts for 36 of the 111.

## What I actually verified

**I hand-checked 4 of the 111 flagged actions. Three were real, one was a false positive.**
The other 107 are unreviewed. Please do not read 22% as a vulnerability rate.

The three real ones are all in a single project, and all have the same shape: an exported
`"use server"` function takes a `userId`, never checks it against the session, and passes it
straight into `.update(...).eq("id", userId)` on a `service_role` client. Calling the
endpoint directly lets you rewrite another user's gamification state — experience points,
badges, team credit. Real, exploitable, not catastrophic.

I reported these privately to the maintainer with a two-week window before publishing.
**All three were fixed within three days.** Two of the functions were removed from the
`"use server"` file entirely — the other correct fix, since they were only ever meant to be
internal helpers — and a regression test now asserts they stay unexported. The third kept
its export and gained a guard. Re-running the scanner against the current HEAD reports
zero. The repository is not named here.

The false positive is the more instructive finding:

```ts
export async function getPublicBookingCatalog(input?: { siteDomain?: string }) {
  const supabase = getServiceRoleClient();
  const resolvedDomain = normalizePublicSiteDomain(input?.siteDomain);
  await supabase.from("workspace_settings").select("workspace_id")
    .eq("site_domain", resolvedDomain);
```

A caller-supplied argument reaches a `service_role` query with no auth check, and that is
entirely correct: it is an unauthenticated public catalog, and the argument is a tenant
domain, not a user identity. The rule cannot tell it apart from the IDOR above.

Scanning the flagged list by name, a lot of it looks like this class —
`getAgreementByPublicToken`, `recordAgreementView`, `getBookingAvailabilityPreview`. I
expect the false positive rate to be high. I have not measured it.

There is also a selection effect worth stating: the four I reviewed were the four whose
code was easiest to read. "Three confirmed" is a function of legibility, not severity.

## Why this is hard

The rule that seems obvious — "caller-supplied value reaches a privileged query without a
guard" — collapses on three distinctions that are not present in the syntax:

- **Read vs write.** A public catalog read and an ownership-bypassing update look identical.
- **Identity vs routing key.** `userId`, `tenantId`, `siteDomain` and `publicToken` are all
  strings arriving as arguments. Only the first implies an ownership check is owed.
- **Guard vs error handling.** An earlier version treated any `throw` as a guard, and
  matched the substring `validate` — which is contained in `revalidatePath`, a call present
  in nearly every Server Action. It marked almost everything safe.

An earlier version made the opposite mistake: it looked for an auth call only one level
deep, and real codebases wrap authorization two or three helpers down. On a 40-repo run it
flagged 37 actions, of which every one I checked was a false positive, because the
best-structured projects were the ones being flagged.

There is also a class this tool structurally cannot catch: an action that calls
`requireUser()` correctly and then uses the *argument* `userId` instead of the session's,
which is arguably the most common real instance of the bug.

## Limitations of the study

- Public GitHub repositories are not deployed applications. Templates, tutorials and
  abandoned demos are in the corpus and were not filtered out.
- I did not establish provenance for any of it. Nothing here says anything about
  AI-generated code specifically.
- Repository search ranked by recent update; this is not a random sample of anything.
- Findings are concentrated in a handful of repositories, so per-repository rates are not
  meaningful at this n.

## Reproducing

`study/build-corpus.sh` rebuilds an equivalent corpus from scratch. The resolved list of
259 repositories is deliberately not published: one of them is the repository disclosed
above, and shipping the list next to the scanner would identify it. Search ranking is
time-dependent, so a re-run will not reproduce the exact numbers.

`study/summary.json` and `study/per_repository.csv` carry the aggregate and the
per-repository distribution, with repository names replaced by salted hashes.

## Where this goes

The remaining false positives are endpoints that are public by design. Telling those apart
from real holes needs intent the code does not carry, so the plan is to keep the scanner
honest about that (`actionguard-ignore` with a reason) rather than guess. Recall has not been
measured: the scanner only sees Supabase service_role queries, and misses authorization bugs
that go through RLS or other databases entirely.

If catching write-side IDOR in Next.js Server Actions in CI is something you'd use, the
waitlist is here: [https://tally.so/r/1ALZkb]

## License

MIT

# actionguard

Static analysis for Next.js Server Actions: does a caller-supplied identifier reach a
`service_role` database query without passing a guard?

```bash
npx actionguard <path-to-repo>
```

This is an early, noisy MVP. The interesting part is not the tool — it is what happened
when I ran it across 259 public repositories. Numbers and limitations below.

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
import a `service_role` client:

1. Build a taint set from the function's parameters via symbol resolution, with one hop of
   propagation through local variable assignments.
2. Find the first `.eq/.in/.match/.insert/.update/.upsert/.delete` call receiving a tainted
   node.
3. Look for a guard call (`require*`, `verify*`, `validate*`, `assert*`, `.getUser()`,
   `.getSession()`, `auth()`, `currentUser()`, …) positioned **before** that sink.

No guard before the sink → flagged. Exit code 1 if anything is flagged, so it drops into CI.

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

Restricting sinks to writes (`update`/`delete`/`upsert`) and requiring the filtered column
to look like a subject identifier (`user_id`, `owner_id`, `account_id`) should remove the
public-read class while keeping the real findings. I have not built that yet, and I am not
going to claim a false positive rate for it in advance.

If catching write-side IDOR in Next.js Server Actions in CI is something you'd use, the
waitlist is here: [URL]

## License

MIT

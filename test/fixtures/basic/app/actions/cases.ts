"use server";
import { supabaseAdmin } from "@/lib/admin";
import { requireUser, getProfileOrThrow } from "@/lib/auth";

// A: textbook IDOR. Expect: flagged
export async function awardXp(userId: string, xp: number) {
  await supabaseAdmin.from("profiles").update({ xp }).eq("id", userId);
}

// B: guard before the sink. Expect: guard_before_sink
export async function renameTeam(teamId: string, name: string) {
  await requireUser();
  await supabaseAdmin.from("teams").update({ name }).eq("id", teamId);
}

// C: guard after the sink. Expect: flagged
export async function deletePost(postId: string) {
  await supabaseAdmin.from("posts").delete().eq("id", postId);
  await requireUser();
}

// D: destructured parameter. Expect: flagged
export async function setRole({ userId, role }: { userId: string; role: string }) {
  await supabaseAdmin.from("profiles").update({ role }).eq("id", userId);
}

// E: input validation is not authorization. Expect: flagged
export async function setXp(userId: string, xp: number) {
  if (isNaN(xp)) throw new Error("bad input");
  await supabaseAdmin.from("profiles").update({ xp }).eq("id", userId);
}

// F: tainted value only touches Array.prototype.filter. Expect: no_tainted_sink
export async function countMine(ids: string[]) {
  const { data } = await supabaseAdmin.from("items").select("id");
  return (data ?? []).filter((r: any) => ids.includes(r.id)).length;
}

// G: guard behind a helper with a neutral name. Expect: guard_before_sink
export async function archiveProject(projectId: string) {
  await getProfileOrThrow();
  await supabaseAdmin.from("projects").update({ archived: true }).eq("id", projectId);
}

// H: formData taint through one hop. Expect: flagged
export async function removeMember(formData: FormData) {
  const memberId = formData.get("memberId") as string;
  await supabaseAdmin.from("members").delete().eq("id", memberId);
}

// I: arrow-function export. Expect: flagged
export const banUser = async (userId: string) => {
  await supabaseAdmin.from("profiles").update({ banned: true }).eq("id", userId);
};

import { validateEmail } from "@/lib/validate";
import { withAccount } from "@/lib/session";

// J: guard-like name, input validation only. Expect: flagged
export async function updateEmail(userId: string, email: string) {
  validateEmail(email);
  await supabaseAdmin.from("profiles").update({ email }).eq("id", userId);
}

// K: auth two helpers deep. Expect: guard_before_sink
export async function closeAccount(accountId: string) {
  await withAccount();
  await supabaseAdmin.from("accounts").delete().eq("id", accountId);
}

import { d1 } from "@/lib/deep";

// L: query built across variables. Expect: flagged
export async function moveTask(taskId: string) {
  let q = supabaseAdmin.from("tasks").update({ done: true });
  q = q.eq("id", taskId);
  await q;
}

// M: auth four helpers deep (d1 -> d2 -> d3 -> d4 -> getUser). Expect: guard_before_sink
export async function purgeLogs(orgId: string) {
  await d1();
  await supabaseAdmin.from("logs").delete().eq("org_id", orgId);
}

import { createUserClient, createAdminClient } from "@/lib/clients";

// N: reads the service_role key for another purpose, queries on the RLS client.
// Expect: no_tainted_sink
export async function saveDraft(userId: string, body: string) {
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) throw new Error("config");
  const sb = await createUserClient();
  await sb.from("drafts").insert({ user_id: userId, body });
}

// O: starts on the RLS client, reassigned to the admin client. Expect: flagged
export async function readOrgFlags(orgId: string) {
  let sb: any = await createUserClient();
  sb = createAdminClient();
  return sb.from("orgs").select("flags").eq("id", orgId);
}

// P: admin client from a cache()-wrapped factory. Expect: flagged
export async function resetQuota(accountId: string) {
  const admin = createAdminClient();
  await admin.from("quotas").update({ used: 0 }).eq("account_id", accountId);
}

import { actionClient, authActionClient, withAuth } from "@/lib/safe-action";

// Q: next-safe-action behind an auth middleware. Expect: guard_before_sink
export const deleteInvoice = authActionClient
  .schema({})
  .action(async ({ parsedInput: { invoiceId } }: any) => {
    await supabaseAdmin.from("invoices").delete().eq("id", invoiceId);
  });

// R: next-safe-action, no auth middleware. Expect: flagged
export const deleteInvoicePublic = actionClient
  .schema({})
  .action(async ({ parsedInput: { invoiceId } }: any) => {
    await supabaseAdmin.from("invoices").delete().eq("id", invoiceId);
  });

// S: only ctx (from middleware) reaches the query. Expect: no_tainted_sink
export const clearMyCart = actionClient.action(async ({ ctx }: any) => {
  await supabaseAdmin.from("carts").delete().eq("user_id", ctx.user.id);
});

// T: Admin API with a caller-chosen id. Expect: flagged
export async function removeAccount(userId: string) {
  await supabaseAdmin.auth.admin.deleteUser(userId);
}

// U: guarded, but the role comes from user_metadata. Expect: weak_guard
export async function promote(userId: string) {
  const user = await requireUser();
  if (user.user_metadata.role !== "admin") throw new Error("forbidden");
  await supabaseAdmin.from("profiles").update({ role: "admin" }).eq("id", userId);
}

// V: wrapper that authenticates. Expect: guard_before_sink
export const pinPost = withAuth(async (postId: string) => {
  await supabaseAdmin.from("posts").update({ pinned: true }).eq("id", postId);
});

// W: same shape as A, deliberately public. Expect: ignored
// actionguard-ignore: anonymous view counter, slug is a public article key
export async function bumpViews(slug: string) {
  await supabaseAdmin.from("views").update({ n: 1 }).eq("slug", slug);
}

/* actionguard-ignore */
export const bumpLikes = async (slug: string) => {
  await supabaseAdmin.from("likes").update({ n: 1 }).eq("slug", slug);
};

// X: ignore comment on a passing action changes nothing. Expect: guard_before_sink
// actionguard-ignore: not needed
export async function renameTeam2(teamId: string, name: string) {
  await requireUser();
  await supabaseAdmin.from("teams").update({ name }).eq("id", teamId);
}

import { requireRep, requireAdminAuth } from "@/lib/rep";
import { redirect } from "next/navigation";

// Y1: guard behind cache(namedFn). Expect: guard_before_sink
export async function savePitch(profileId: string, pitch: string) {
  await requireRep();
  await supabaseAdmin.from("profiles").update({ pitch }).eq("id", profileId);
}

// Y2: custom check that throws an auth error. Expect: guard_before_sink
export async function editQuestion(questionId: string, text: string) {
  await requireAdminAuth();
  await supabaseAdmin.from("questions").update({ text }).eq("id", questionId);
}

// Y3: inline check ending in a login redirect. Expect: guard_before_sink
export async function hideComment(commentId: string, token?: string) {
  if (token !== process.env.MOD_TOKEN) redirect("/login");
  await supabaseAdmin.from("comments").update({ hidden: true }).eq("id", commentId);
}

// Y4: a redirect elsewhere is not a guard. Expect: flagged
export async function archiveThread(threadId: string, back?: string) {
  if (!back) redirect("/threads");
  await supabaseAdmin.from("threads").update({ archived: true }).eq("id", threadId);
}

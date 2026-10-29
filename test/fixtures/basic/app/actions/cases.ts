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

// M: auth four helpers deep, past the limit. Expect: flagged (documented limit)
export async function purgeLogs(orgId: string) {
  await d1();
  await supabaseAdmin.from("logs").delete().eq("org_id", orgId);
}

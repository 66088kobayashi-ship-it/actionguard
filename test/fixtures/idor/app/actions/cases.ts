"use server";
import { supabaseAdmin } from "@/lib/admin";
import { requireUser, requireAdmin, assertMember } from "@/lib/auth";
import { db, notes, auth } from "@/lib/db";
import { eq, and } from "drizzle-orm";

// Logged in, then deletes whatever id it is given. Expect: idor_candidate
export async function deleteProject(id: string) {
  await requireUser();
  await supabaseAdmin.from("projects").delete().eq("id", id);
}

// The query is scoped to the session user. Expect: guard_before_sink
export async function deleteMyProject(id: string) {
  const user = await requireUser();
  await supabaseAdmin.from("projects").delete().eq("id", id).eq("owner_id", user.id);
}

// Ownership checked before the write. Expect: guard_before_sink
export async function archiveProject(id: string) {
  const user = await requireUser();
  const { data: p } = await supabaseAdmin.from("projects").select("owner_id").eq("id", id).single();
  if (!p || p.owner_id !== user.id) throw new Error("forbidden");
  await supabaseAdmin.from("projects").update({ archived: true }).eq("id", id);
}

// Admin-only action may touch any row. Expect: guard_before_sink
export async function banUser(userId: string) {
  await requireAdmin();
  await supabaseAdmin.auth.admin.deleteUser(userId);
}

// Membership helper gets both the session and the caller's org. Expect: guard_before_sink
export async function purgeOrgLogs(orgId: string) {
  const user = await requireUser();
  await assertMember(user.id, orgId);
  await supabaseAdmin.from("logs").delete().eq("org_id", orgId);
}

// Reads another company's customers by id. Expect: idor_candidate
export async function listCustomers(input: { companyId: string }) {
  const user = await requireUser();
  if (!user) throw new Error("unauthorized");   // a null check is not authorization
  return supabaseAdmin.from("customers").select("*").eq("company_id", input.companyId);
}

// Caller picks the owner of the new row. Expect: idor_candidate
export async function createNoteFor(userId: string, title: string) {
  await requireUser();
  await supabaseAdmin.from("notes").insert({ user_id: userId, title });
}

// Caller value only filters by a non-key column. Expect: guard_before_sink
export async function findBySlug(slug: string) {
  await requireUser();
  return supabaseAdmin.from("articles").select("*").eq("slug", slug);
}

// Read, then checked before anything is returned. Expect: guard_before_sink
export async function getInvoice(id: string) {
  const user = await requireUser();
  const { data } = await supabaseAdmin.from("invoices").select("*").eq("id", id).single();
  if (data.user_id !== user.id) throw new Error("forbidden");
  return data;
}

// Drizzle, logged in, any note id. Expect: idor_candidate
export async function deleteNote(id: string) {
  const session = await auth();
  if (!session?.user) throw new Error("unauthorized");
  await db.delete(notes).where(eq(notes.id, id));
}

// Drizzle, scoped with and(...). Expect: guard_before_sink
export async function deleteMyNote(id: string) {
  const session = await auth();
  if (!session?.user) throw new Error("unauthorized");
  await db.delete(notes).where(and(eq(notes.id, id), eq(notes.userId, session.user.id)));
}

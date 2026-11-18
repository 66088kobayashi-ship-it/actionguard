"use server";
import { supabaseAdmin, getAdminClient } from "@/lib/admin";
import { createClient } from "@/lib/server";
import { getCurrentSession, requireMember } from "@/lib/session";

// Client assigned after its declaration, filtered with ilike. Expect: flagged
export async function checkInvite(email: string) {
  let admin;
  try { admin = getAdminClient(); } catch { return null; }
  const { data } = await admin.from("user_profiles").select("*").ilike("email", email).single();
  return data;
}

// Values destructured from the argument object. Expect: flagged
export async function inviteUser(data: { email: string; fullName: string; role: string }) {
  const { email, fullName, role } = data;
  const { data: created } = await supabaseAdmin.auth.admin.createUser({ email, email_confirm: true });
  await supabaseAdmin.from("profiles").upsert({ id: created.user.id, full_name: fullName, role });
}

// Hand-written session checked first. Expect: guard_before_sink
export async function renameNote(noteId: string, title: string) {
  const { user } = await getCurrentSession();
  if (!user) return { error: "not signed in" };
  await supabaseAdmin.from("notes").update({ title }).eq("id", noteId).eq("owner_id", user.id);
}

// Guard reached through an overloaded helper. Expect: guard_before_sink
export async function renameTeam(teamId: string, name: string) {
  const member = await requireMember(teamId);
  await supabaseAdmin.from("teams").update({ name }).eq("id", teamId).eq("owner_id", member.id);
}

// Permission function on the user's own client. Expect: guard_before_sink
export async function inviteToTeam(teamId: string, email: string) {
  const sb = await createClient();
  const { data: allowed } = await sb.rpc("check_permission", { p_scope: "team", p_id: teamId, p_permission: "team.manage" });
  if (!allowed) return { error: "forbidden" };
  await supabaseAdmin.auth.admin.inviteUserByEmail(email);
}

// The caller picks whose permission is checked. Expect: flagged
export async function inviteAsUser(userId: string, email: string) {
  const sb = await createClient();
  const { data: allowed } = await sb.rpc("has_permission", { p_user_id: userId, p_permission: "team.manage" });
  if (!allowed) return { error: "forbidden" };
  await supabaseAdmin.auth.admin.inviteUserByEmail(email);
}

// Permission function on the service_role client: auth.uid() is null there. Expect: flagged
export async function inviteWithAdminRpc(teamId: string, email: string) {
  const { data: allowed } = await supabaseAdmin.rpc("check_permission", { p_scope: "team", p_id: teamId });
  if (!allowed) return { error: "forbidden" };
  await supabaseAdmin.auth.admin.inviteUserByEmail(email);
}

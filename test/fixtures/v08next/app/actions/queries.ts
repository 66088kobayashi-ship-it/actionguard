"use server";
import { supabaseAdmin } from "@/lib/admin";
// Only called from server code. Expect: unreferenced
export async function getTeamForUser(userId: string) {
  return supabaseAdmin.from("teams").select("*").eq("owner_id", userId);
}
// Handed to the client below. Expect: flagged
export async function deleteTeam(teamId: string) {
  return supabaseAdmin.from("teams").delete().eq("id", teamId);
}

"use server";
import { supabaseAdmin } from "@/lib/admin";

// Imported by a client component: a public endpoint. Expect: flagged
export async function revokeKey(keyId: string) {
  await supabaseAdmin.from("api_keys").delete().eq("id", keyId);
}

// Only imported by a route handler: no action ID on Next >= 15. Expect: unreferenced
export async function getKeyForUser(userId: string) {
  return supabaseAdmin.from("api_keys").select("key").eq("user_id", userId);
}

// Imported by nothing. Expect: unreferenced
export async function markKeyInvalid(userId: string) {
  await supabaseAdmin.from("api_keys").update({ valid: false }).eq("user_id", userId);
}

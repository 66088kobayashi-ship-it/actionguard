"use server";
import { supabaseAdmin } from "@/lib/admin";

// Loaded by a client component with import("@/app/actions/lazy"). Expect: flagged
export async function purgeCache(tenantId: string) {
  await supabaseAdmin.from("cache").delete().eq("tenant_id", tenantId);
}

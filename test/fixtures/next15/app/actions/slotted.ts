"use server";
import { supabaseAdmin } from "@/lib/admin";

// Loaded through Promise.all([import(...)]). Expect: flagged
export async function slotAction(id: string) {
  await supabaseAdmin.from("items").update({ starred: true }).eq("id", id);
}

// Not picked, but Promise.all keeps the namespace whole, so its id still
// reaches the browser. Expect: flagged
export async function slotLeftover(id: string) {
  await supabaseAdmin.from("items").delete().eq("id", id);
}

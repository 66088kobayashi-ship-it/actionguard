"use server";
import { supabaseAdmin } from "@/lib/admin";

// Destructured from import() by a client component. Expect: flagged
export async function pickedAction(id: string) {
  await supabaseAdmin.from("items").delete().eq("id", id);
}

// Same module, never picked by client code. Expect: unreferenced
export async function leftoverAction(id: string) {
  await supabaseAdmin.from("items").update({ hidden: true }).eq("id", id);
}

// Picked through Promise.all slot destructuring. Expect: flagged
export async function slotAction(id: string) {
  await supabaseAdmin.from("items").update({ pinned: true }).eq("id", id);
}

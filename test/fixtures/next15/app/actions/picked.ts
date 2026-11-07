"use server";
import { supabaseAdmin } from "@/lib/admin";

// Destructured from import("...").then(...) by a client component. Expect: flagged
export async function pickedAction(id: string) {
  await supabaseAdmin.from("items").delete().eq("id", id);
}

// Same module, never picked by client code. Expect: unreferenced
export async function leftoverAction(id: string) {
  await supabaseAdmin.from("items").update({ hidden: true }).eq("id", id);
}

// Picked with `const { declAction } = await import(...)`. Expect: flagged
export async function declAction(id: string) {
  await supabaseAdmin.from("items").update({ pinned: true }).eq("id", id);
}

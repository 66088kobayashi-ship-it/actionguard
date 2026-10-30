"use server";
import { supabaseAdmin } from "@/lib/admin";

export type UserRow = { id: string };

// Only called directly by a server component. Expect: unreferenced
export async function getUserDetails(userId: string) {
  return supabaseAdmin.from("profiles").select("*").eq("id", userId);
}

// Passed by a server component to a client component as a prop. Expect: flagged
export async function banUser(userId: string) {
  await supabaseAdmin.from("profiles").update({ banned: true }).eq("id", userId);
}

// Used by a <form action>. Expect: flagged
export async function deleteNote(noteId: string) {
  await supabaseAdmin.from("notes").delete().eq("id", noteId);
}

// Imported only by a test and as a type elsewhere. Expect: unreferenced
export async function countUserRows(userId: string) {
  return supabaseAdmin.from("rows").select("id").eq("user_id", userId);
}

// Reached by a client component through a plain hooks module. Expect: flagged
export async function renameUser(userId: string, name: string) {
  await supabaseAdmin.from("profiles").update({ name }).eq("id", userId);
}

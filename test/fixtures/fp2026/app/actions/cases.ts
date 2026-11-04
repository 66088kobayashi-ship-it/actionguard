"use server";
import { db } from "@/lib/admin";
import { isAdminSession, hasAdminCookie } from "@/lib/session";

// Contact form: caller values only in content columns of a public table. Expect: public_write
export async function submitContact(form: FormData) {
  await db.from("contact_messages").insert({
    name: String(form.get("name")),
    email: String(form.get("email")),
    message: String(form.get("message")),
  });
}

// Same table, but the caller picks the owner. Expect: flagged
export async function joinWaitlist(email: string, userId: string) {
  await db.from("waitlist").insert({ email, user_id: userId });
}

// Chat message posted as any sender. Expect: flagged
export async function sendMessage(orderId: string, senderId: string, body: string) {
  await db.from("messages").insert({ order_id: orderId, sender_id: senderId, body });
}

// Admin-only content in a non-public table. Expect: flagged
export async function createProduct(name: string, price: number) {
  await db.from("products").insert({ name, price });
}

// The whole row comes from the caller. Expect: flagged
export async function submitFeedbackRow(row: Record<string, unknown>) {
  await db.from("feedback").insert([row]);
}

// Lookup by a secret: the caller must hold the token. Expect: no_tainted_sink
export async function confirmByToken(token: string) {
  await db.from("approvals").update({ approved: true }).eq("token_hash", token);
}

// Lookup by a plain id. Expect: flagged
export async function confirmById(id: string) {
  await db.from("approvals").update({ approved: true }).eq("id", id);
}

// Verified signed cookie before the write. Expect: guard_before_sink
export async function deleteListing(id: string) {
  if (!(await isAdminSession())) return { error: "Admin session required" };
  await db.from("listings").delete().eq("id", id);
}

// Cookie presence only. Expect: flagged
export async function hideListing(id: string) {
  if (!(await hasAdminCookie())) return { error: "Admin session required" };
  await db.from("listings").update({ hidden: true }).eq("id", id);
}

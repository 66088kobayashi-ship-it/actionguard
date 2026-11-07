// Rules tried in v0.7.0 and rejected: a regression over 410 hand-labelled
// repositories showed them hiding real findings (see README, v0.7.0).
// These cases pin the decision: every one stays flagged.
"use server";
import { supabaseAdmin } from "@/lib/admin";
import { db, notes as courses } from "@/lib/db";
import { eq } from "drizzle-orm";
import { compare } from "bcryptjs";

// Public catalog filtered by a non-key column. Expect: flagged (public_read rejected)
export async function searchProducts(category: string) {
  return supabaseAdmin.from("products").select("id, name, price").eq("category", category);
}

// One row by id, no visibility condition: could be unpublished. Expect: flagged
export async function getProductById(id: string) {
  return supabaseAdmin.from("products").select("*").eq("id", id).single();
}

// By id, but only published rows. Expect: flagged (public_read rejected)
export async function getPublishedPost(id: string) {
  return supabaseAdmin.from("posts").select("*").eq("id", id).eq("published", true).single();
}

// Public table, but the join pulls the author's email. Expect: flagged
export async function getPostWithAuthor(slug: string) {
  return supabaseAdmin.from("posts").select("*, profiles(email)").eq("slug", slug);
}

// Sensitive table. Expect: flagged
export async function getOrdersByStatus(status: string) {
  return supabaseAdmin.from("orders").select("*").eq("status", status);
}

// Login: reads the user by email and checks the password. Expect: flagged (auth_flow rejected)
export async function loginAction(email: string, password: string) {
  const { data } = await supabaseAdmin.from("users").select("id, password_hash").eq("email", email).single();
  if (!data || !(await compare(password, data.password_hash))) return { error: "Invalid credentials" };
  return { ok: true };
}

// Sign-up with no role field. Expect: flagged (auth_flow rejected)
export async function signupAction(email: string, name: string) {
  await supabaseAdmin.from("profiles").insert({ email, name });
}

// Sign-up that lets the caller pick a role. Expect: flagged
export async function signupWithRole(email: string, role: string) {
  await supabaseAdmin.from("profiles").insert({ email, role });
}

// Sign-up that spreads the caller's object into the row. Expect: flagged
export async function registerUser(input: { email: string }) {
  await supabaseAdmin.from("profiles").insert({ ...input });
}

// Not a login or sign-up: returns a recovery link for any address. Expect: flagged
export async function joinWithResetLink(email: string) {
  return supabaseAdmin.auth.admin.generateLink({ type: "recovery", email });
}

// Drizzle public list by a non-key column. Expect: flagged (public_read rejected)
export async function listCourses(category: string) {
  return db.select().from(courses).where(eq(courses.category, category));
}

// Drizzle read that pulls the owner along. Expect: flagged
export async function getCourseWithUser(slug: string) {
  return db.query.courses.findFirst({ where: eq(courses.slug, slug), with: { user: true } });
}

// Hand-written (Lucia-style) sessions: the cookie token is hashed and looked up.
import { cookies } from "next/headers";
import { cache } from "react";
import { sha256 } from "@oslojs/crypto/sha2";
import { drizzle } from "drizzle-orm/node-postgres";
import { eq } from "drizzle-orm";
const db = drizzle(process.env.DATABASE_URL!);
const sessionTable: any = {};
const userTable: any = {};

export async function validateSessionToken(token: string) {
  const id = Array.from(sha256(new TextEncoder().encode(token))).join("");
  const rows = await db.select({ user: userTable, session: sessionTable }).from(sessionTable).where(eq(sessionTable.id, id));
  if (rows.length < 1) return { user: null, session: null };
  return rows[0];
}

export const getCurrentSession = cache(async () => {
  const token = (await cookies()).get("session")?.value ?? null;
  if (token === null) return { user: null, session: null };
  return validateSessionToken(token);
});

// Overloads: the implementation is the declaration with a body.
export function requireMember(teamId: string): Promise<{ id: string }>;
export function requireMember(teamId: string, opts: { owner: true }): Promise<{ id: string }>;
export async function requireMember(teamId: string, opts?: { owner: true }) {
  const { user } = await getCurrentSession();
  if (!user) throw new Error("Unauthorized");
  return { id: String(teamId) + String(opts) };
}

"use server";
import { db, notes, auth } from "@/lib/db";
import { eq, and } from "drizzle-orm";
import { headers } from "next/headers";

// Anyone can delete any note by id. Expect: flagged
export async function deleteNote(id: string) {
  await db.delete(notes).where(eq(notes.id, id));
}

// Anyone can read any note. Expect: flagged
export async function getNoteById(id: string) {
  return db.query.notes.findFirst({ where: eq(notes.id, id) });
}

// Caller-chosen row written. Expect: flagged
export async function updateNote(id: string, values: Record<string, unknown>) {
  await db.update(notes).set(values).where(eq(notes.id, id));
}

// Session checked first (better-auth). Expect: guard_before_sink
export async function deleteMyNote(id: string) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) throw new Error("Unauthorized");
  await db.delete(notes).where(and(eq(notes.id, id), eq(notes.userId, session.user.id)));
}

// Inside a transaction. Expect: flagged
export async function moveNote(id: string, notebookId: string) {
  await db.transaction(async (tx: any) => {
    await tx.update(notes).set({ notebookId }).where(eq(notes.id, id));
  });
}

// Not a database call: Map.delete / Array.values. Expect: no_tainted_sink
export async function localOnly(id: string) {
  const m = new Map<string, number>();
  m.delete(id);
  return [...m.values()];
}

import { guardUser } from "@/lib/session";

// Result-object guard backed by a Web Crypto HMAC session. Expect: guard_before_sink
export async function archiveNote(id: string) {
  const g = await guardUser();
  if (!g.ok) return g;
  await db.update(notes).set({ archived: true }).where(and(eq(notes.id, id), eq(notes.userId, g.userId)));
}

// Demo-only switch, off unless the environment opts in. Expect: env_gated
export async function demoResetNote(id: string) {
  if (process.env.DEMO_MODE !== "true") throw new Error("Demo mode is off");
  await db.delete(notes).where(eq(notes.id, id));
}

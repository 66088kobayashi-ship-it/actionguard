import { cache } from "react";
import { createServerClient } from "./server";
import { cookies } from "next/headers";

async function loadRep() {
  const { data } = await createServerClient().auth.getClaims();
  return data?.claims ?? null;
}
// cache() around a named function, not an arrow.
export const getRep = cache(loadRep);
export async function requireRep() {
  const rep = await getRep();
  if (!rep) throw new Error("unauthenticated");
  return rep;
}

// Custom cookie session: no known auth call, but it throws an auth error.
async function isAuthenticated() {
  return (await cookies()).get("admin")?.value === process.env.ADMIN_SECRET;
}
export async function requireAdminAuth() {
  if (!(await isAuthenticated())) throw new Error("Unauthorized admin request");
}

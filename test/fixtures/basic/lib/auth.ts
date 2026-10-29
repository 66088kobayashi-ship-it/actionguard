import { createServerClient } from "./server";
export async function requireUser() {
  const sb = createServerClient();
  const { data: { user } } = await sb.auth.getUser();
  if (!user) throw new Error("unauthorized");
  return user;
}
// Name matches nothing in the guard list, but it is an auth guard.
export async function getProfileOrThrow() {
  const sb = createServerClient();
  const { data: { user } } = await sb.auth.getUser();
  if (!user) throw new Error("unauthorized");
  return user;
}

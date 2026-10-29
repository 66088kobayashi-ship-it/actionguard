import { createServerClient } from "./server";
async function loadSession() {
  const sb = createServerClient();
  const { data: { user } } = await sb.auth.getUser();
  if (!user) throw new Error("unauthorized");
  return user;
}
// Two levels down from the action: withAccount -> loadSession -> auth.getUser
export async function withAccount() {
  return await loadSession();
}

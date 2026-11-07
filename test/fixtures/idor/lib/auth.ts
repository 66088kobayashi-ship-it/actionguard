import { createClient } from "@supabase/supabase-js";
const anon = () => createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
export async function requireUser() {
  const { data: { user } } = await anon().auth.getUser();
  if (!user) throw new Error("unauthorized");
  return user;
}
export async function requireAdmin() {
  const user = await requireUser();
  if (user.app_metadata?.role !== "admin") throw new Error("forbidden");
  return user;
}
export async function assertMember(userId: string, orgId: string) {
  const { data } = await anon().from("members").select("id").eq("user_id", userId).eq("org_id", orgId).single();
  if (!data) throw new Error("forbidden");
}

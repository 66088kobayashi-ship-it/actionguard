// Hand-written staff sessions, no auth library.
import { cookies } from "next/headers";
import { supabaseAdmin } from "@/lib/admin";
export async function requireStaff() {
  const token = (await cookies()).get("staff_token")?.value;
  const { data } = await supabaseAdmin.from("staff_sessions").select("staff_id").eq("token", token ?? "").single();
  if (!data) throw new Error("Unauthorized: invalid session");
  return data.staff_id as string;
}

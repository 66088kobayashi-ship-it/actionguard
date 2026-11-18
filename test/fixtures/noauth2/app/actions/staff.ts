"use server";
import { supabaseAdmin } from "@/lib/admin";
import { requireStaff } from "@/lib/staff";
// Expect: guard_before_sink
export async function cancelBooking(id: string) {
  await requireStaff();
  await supabaseAdmin.from("bookings").update({ status: "cancelled" }).eq("id", id);
}
// The app has authentication; this action just skips it. Expect: flagged (not no_auth)
export async function deleteBooking(id: string) {
  await supabaseAdmin.from("bookings").delete().eq("id", id);
}

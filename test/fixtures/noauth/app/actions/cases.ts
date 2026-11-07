"use server";
import { supabaseAdmin } from "@/lib/admin";

// The app authenticates nobody anywhere. Expect: no_auth
export async function deleteCustomer(id: string) {
  await supabaseAdmin.from("customers").delete().eq("id", id);
}

// Same app. Expect: no_auth
export async function updateCustomerPhone(id: string, phone: string) {
  await supabaseAdmin.from("customers").update({ phone }).eq("id", id);
}

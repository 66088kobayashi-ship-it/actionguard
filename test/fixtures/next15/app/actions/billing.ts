"use server";
import { supabaseAdmin } from "@/lib/admin";

// Imported by a client component through the barrel. Expect: flagged
export async function refundOrder(orderId: string) {
  await supabaseAdmin.from("orders").update({ refunded: true }).eq("id", orderId);
}

// Re-exported by the same barrel, imported by no one. Expect: unreferenced
export async function getInvoice(invoiceId: string) {
  return supabaseAdmin.from("invoices").select("*").eq("id", invoiceId);
}

import { cookies } from "next/headers";
import { createServerClient } from "@supabase/ssr";
import { publicEnv } from "@/lib/env";
// The user's own client: RLS and auth.uid() apply.
export async function createClient() {
  const store = await cookies();
  return createServerClient(publicEnv.url, publicEnv.anon, { cookies: { getAll: () => store.getAll() } });
}

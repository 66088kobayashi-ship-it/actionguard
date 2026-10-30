import { createClient } from "@supabase/supabase-js";
import { createServerClient } from "@supabase/ssr";
import { cache } from "react";

// Cookie-bound anon client: RLS applies.
export const createUserClient = cache(async () =>
  createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: { getAll() { return []; }, setAll() {} },
  })
);

// service_role client behind a factory, wrapped in cache().
export const createAdminClient = cache(() =>
  createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)
);

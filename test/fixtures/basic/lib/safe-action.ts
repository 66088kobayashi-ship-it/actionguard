import { createSafeActionClient } from "next-safe-action";
import { createServerClient } from "./server";

export const actionClient = createSafeActionClient();

// Middleware with a hand-written check, no known auth call by name.
export const authActionClient = actionClient.use(async ({ next }: any) => {
  const user = await loadMe();
  if (!user) throw new Error("Unauthorized");
  return next({ ctx: { user } });
});

async function loadMe(): Promise<any> { return createServerClient(); }

export function withAuth<T extends (...a: any[]) => any>(fn: T): T {
  return (async (...args: any[]) => {
    const { data: { user } } = await createServerClient().auth.getUser();
    if (!user) throw new Error("unauthorized");
    return fn(...args);
  }) as any;
}

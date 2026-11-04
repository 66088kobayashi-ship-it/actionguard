import { cookies } from "next/headers";
import { createHmac, timingSafeEqual } from "crypto";

// Signed admin cookie: read AND verified.
export async function isAdminSession(): Promise<boolean> {
  const jar = await cookies();
  const raw: string | undefined = jar.get("admin")?.value;
  if (!raw) return false;
  const [body, sig] = raw.split(".");
  const want = createHmac("sha256", process.env.ADMIN_SECRET!).update(body).digest("hex");
  return timingSafeEqual(Buffer.from(sig), Buffer.from(want));
}

// Presence of a cookie only: anyone can set it.
export async function hasAdminCookie(): Promise<boolean> {
  const jar = await cookies();
  return !!jar.get("admin");
}
declare const Buffer: any;

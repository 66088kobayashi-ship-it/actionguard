import { headers } from "next/headers";
declare const crypto: any;

async function hmac(body: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return String(await crypto.subtle.sign("HMAC", key, body));
}

// Signed session read from the request, verified with Web Crypto HMAC.
async function readSession(): Promise<{ userId: string } | null> {
  const h = await headers();
  const raw: string = h.get("cookie") ?? "";
  const [body, sig] = raw.split(".");
  if (sig !== (await hmac(body, process.env.AUTH_SECRET!))) return null;
  return { userId: body };
}

// Returns a result object instead of throwing; callers do `if (!g.ok) return g`.
export async function guardUser(): Promise<{ ok: true; userId: string } | { ok: false; error: string }> {
  const s = await readSession();
  if (!s) return { ok: false, error: "Session expired" };
  return { ok: true, userId: s.userId };
}

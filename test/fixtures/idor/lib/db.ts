import { drizzle } from "drizzle-orm/node-postgres";
export const db = drizzle(process.env.DATABASE_URL!);
export const notes: any = {};
export async function auth() { return { user: { id: "u" } }; }

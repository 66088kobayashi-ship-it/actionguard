import { drizzle } from "drizzle-orm/node-postgres";
export const db = drizzle(process.env.DATABASE_URL!);
export const notes: any = {};
export const auth = { api: { getSession: async (_: any) => ({ user: { id: "u" } }) } };

declare module "drizzle-orm/node-postgres" { export function drizzle(url: string, opts?: any): any; }
declare module "drizzle-orm" { export function eq(a: any, b: any): any; export function and(...a: any[]): any; }
declare module "next/headers" { export function headers(): Promise<any>; }
declare const process: { env: Record<string, string | undefined> };

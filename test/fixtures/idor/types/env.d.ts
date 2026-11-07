declare module "@supabase/supabase-js" { export function createClient(url: string, key: string): any; }
declare module "next/headers" { export function cookies(): Promise<any>; export function headers(): Promise<any>; }
declare module "next/navigation" { export function redirect(p: string): never; }
declare module "crypto" {
  export function createHmac(alg: string, key: string): any;
  export function timingSafeEqual(a: any, b: any): boolean;
}
declare const process: { env: Record<string, string | undefined> };
declare module "drizzle-orm/node-postgres" { export function drizzle(url: string): any; }
declare module "drizzle-orm" { export function eq(a: any, b: any): any; export function and(...a: any[]): any; }

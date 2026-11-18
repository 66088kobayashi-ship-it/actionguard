declare module "@supabase/supabase-js" { export function createClient(url: string, key: string): any; }
declare module "@supabase/ssr" { export function createServerClient(url: string, key: string, opts: any): any; }
declare module "next/headers" { export function cookies(): Promise<any>; export function headers(): Promise<any>; }
declare module "next/navigation" { export function redirect(p: string): never; }
declare module "react" { export function cache<T>(fn: T): T; }
declare module "@oslojs/crypto/sha2" { export function sha256(b: Uint8Array): Uint8Array; }
declare module "drizzle-orm/node-postgres" { export function drizzle(url: string): any; }
declare module "drizzle-orm" { export function eq(a: any, b: any): any; }
declare const process: { env: Record<string, string | undefined> };

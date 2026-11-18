declare module "@supabase/supabase-js" { export function createClient(url: string, key: string): any; }
declare module "next/headers" { export function cookies(): Promise<any>; }
declare const process: { env: Record<string, string | undefined> };

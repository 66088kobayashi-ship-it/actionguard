declare module "next/headers" { export function cookies(): Promise<any>; }
declare module "next/navigation" { export function redirect(p: string): never; }
declare module "react" { export function cache<T>(f: T): T; }

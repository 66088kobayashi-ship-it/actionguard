import { renameUser } from "@/app/actions/admin";
import type { UserRow } from "@/app/actions/admin";
export function useRename() { return (r: UserRow, n: string) => renameUser(r.id, n); }

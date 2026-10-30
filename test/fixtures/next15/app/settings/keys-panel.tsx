"use client";
import { revokeKey } from "@/app/actions/keys";
export function KeysPanel({ id }: { id: string }) {
  return <button onClick={() => revokeKey(id)}>Revoke</button>;
}

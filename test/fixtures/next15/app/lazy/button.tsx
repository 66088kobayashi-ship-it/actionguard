"use client";
export function Purge() {
  return <button onClick={async () => { const m = await import("@/app/actions/lazy"); await m.purgeCache("t"); }}>Purge</button>;
}

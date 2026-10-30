"use client";
export function BanButton({ onBan }: { onBan: (id: string) => Promise<void> }) {
  return <button onClick={() => onBan("x")}>Ban</button>;
}

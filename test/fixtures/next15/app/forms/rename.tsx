"use client";
import { useRename } from "@/lib/hooks/use-rename";
export function Rename() { const r = useRename(); return <button onClick={() => r({ id: "1" }, "n")}>Go</button>; }

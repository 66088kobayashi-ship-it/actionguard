"use client";
import { refundOrder } from "@/app/actions";
export function Refund() { return <button onClick={() => refundOrder("o1")}>Refund</button>; }

import { createServerClient } from "./server";
async function d4() { const { data: { user } } = await createServerClient().auth.getUser(); if (!user) throw new Error("x"); }
async function d3() { await d4(); }
async function d2() { await d3(); }
// Four helpers down; guards are followed up to GUARD_DEPTH (6) levels.
export async function d1() { await d2(); }

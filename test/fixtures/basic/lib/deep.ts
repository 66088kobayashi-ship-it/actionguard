import { createServerClient } from "./server";
async function d4() { const { data: { user } } = await createServerClient().auth.getUser(); if (!user) throw new Error("x"); }
async function d3() { await d4(); }
async function d2() { await d3(); }
// Four helpers down: past MAX_HELPER_DEPTH (3), so it is not seen.
export async function d1() { await d2(); }

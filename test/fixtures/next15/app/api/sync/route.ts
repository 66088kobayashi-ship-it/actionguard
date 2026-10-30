import { getKeyForUser } from "@/app/actions/keys";
export async function GET() { return Response.json(await getKeyForUser("me")); }

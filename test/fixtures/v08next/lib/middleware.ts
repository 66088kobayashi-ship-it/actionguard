import { getTeamForUser } from "@/app/actions/queries";
export type ActionState = { error?: string; success?: string };
export interface FormProps { pending: boolean }
export async function withTeam(userId: string) { return getTeamForUser(userId); }

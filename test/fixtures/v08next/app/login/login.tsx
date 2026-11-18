"use client";
// A plain (not `import type`) import of type aliases only: the compiler drops it.
import { ActionState, FormProps } from "@/lib/middleware";
import { deleteTeam } from "@/app/actions/queries";
export function Login(props: FormProps & { state: ActionState }) {
  return <button onClick={() => deleteTeam("x")}>{props.state.error}</button>;
}

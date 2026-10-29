// Named like a guard, but only validates input. Not authorization.
export function validateEmail(e: string) {
  if (!e.includes("@")) throw new Error("bad email");
}

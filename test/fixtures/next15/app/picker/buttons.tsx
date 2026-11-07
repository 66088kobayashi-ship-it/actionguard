"use client";
export function Pick({ id }: { id: string }) {
  const go = () => import("@/app/actions/picked").then(({ pickedAction }) => pickedAction(id));
  const pin = async () => {
    const { declAction } = await import("@/app/actions/picked");
    await declAction(id);
  };
  const star = async () => {
    const [{ slotAction }] = await Promise.all([import("@/app/actions/slotted")]);
    await slotAction(id);
  };
  return <><button onClick={go}>Delete</button><button onClick={pin}>Pin</button><button onClick={star}>Star</button></>;
}

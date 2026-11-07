"use client";
export function Pick({ id }: { id: string }) {
  const go = () => import("@/app/actions/picked").then(({ pickedAction }) => pickedAction(id));
  const pin = async () => {
    const [{ slotAction }, { purgeCache }] = await Promise.all([
      import("@/app/actions/picked"),
      import("@/app/actions/lazy"),
    ]);
    await slotAction(id);
    await purgeCache(id);
  };
  return <><button onClick={go}>Delete</button><button onClick={pin}>Pin</button></>;
}

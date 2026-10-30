import { getUserDetails, banUser, deleteNote } from "@/app/actions/admin";
import { BanButton } from "./ban-button";
export default async function Page({ params }: any) {
  const user = await getUserDetails(params.id);
  return (
    <div>
      {JSON.stringify(user)}
      <BanButton onBan={banUser} />
      <form action={deleteNote}><button>Delete</button></form>
    </div>
  );
}

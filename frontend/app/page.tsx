import { Dashboard } from "@/components/dashboard";
import { getArsenal, getDashboard } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function Home() {
  const [data, arsenal] = await Promise.all([getDashboard(), getArsenal()]);
  return <Dashboard data={data} arsenal={arsenal} />;
}

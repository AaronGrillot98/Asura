import { listAuthProfiles } from "@/lib/api";
import { AuthProfilesManager } from "@/components/auth-profiles-manager";

export const dynamic = "force-dynamic";

export default async function AuthProfilesPage() {
  let initial = [] as Awaited<ReturnType<typeof listAuthProfiles>>;
  try {
    initial = await listAuthProfiles();
  } catch {
    initial = [];
  }
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Tooling</span>
          <h1>Auth profiles</h1>
          <p>
            Capture credentials (Bearer token, Basic auth, custom header, or
            Cookie) and pick one on the Run-scan form when nuclei or httpx is
            selected. Asura translates each profile into the right{" "}
            <code className="inlineCode">-H</code> flag and injects it at scan time.
          </p>
          <p style={{ marginTop: 6 }}>
            Secrets are stored Fernet-encrypted on disk. The API only ever
            returns a 4-character preview — the full value never leaves the
            backend.
          </p>
        </div>
      </header>
      <AuthProfilesManager initial={initial} />
    </div>
  );
}

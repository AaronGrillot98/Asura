import { listTemplates } from "@/lib/api";
import { TemplatesManager } from "@/components/templates-manager";

export const dynamic = "force-dynamic";

export default async function TemplatesPage() {
  let initial = [] as Awaited<ReturnType<typeof listTemplates>>;
  try {
    initial = await listTemplates();
  } catch {
    initial = [];
  }
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Tooling</span>
          <h1>Custom Nuclei templates</h1>
          <p>
            Upload your own Nuclei templates and pick them when running nuclei
            from the scan form. Each upload is hashed (sha256), stored on disk,
            and bind-mounted read-only into the container if you run nuclei via
            Docker.
          </p>
        </div>
      </header>
      <TemplatesManager initial={initial} />
    </div>
  );
}

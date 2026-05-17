import Link from "next/link";
import { NewProjectForm } from "@/components/new-project-form";

export const dynamic = "force-dynamic";

export default function NewProjectPage() {
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">
            <Link href="/projects">Projects</Link> / New
          </span>
          <h1>New project</h1>
          <p>Define an authorized scope before running scans. Every entry is enforced before any scanner spawns.</p>
        </div>
      </header>
      <NewProjectForm />
    </div>
  );
}

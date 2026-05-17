import Link from "next/link";
import { Activity } from "lucide-react";
import { getScans } from "@/lib/api";
import { DemoBadge, ModeBadge } from "@/components/badges";
import { EmptyState, SectionHeader } from "@/components/primitives";

export const dynamic = "force-dynamic";

export default async function ScansPage() {
  const runs = await getScans("demo");
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Operations</span>
          <h1>Scanner Runs</h1>
          <p>{runs.length} run(s) recorded.</p>
        </div>
      </header>

      <SectionHeader title="Recent runs" count={runs.length} />

      <section className="panel">
        {runs.length === 0 ? (
          <EmptyState
            icon={<Activity size={28} />}
            title="No scanner runs yet"
            description="Click Run Scan on the Command Center or a project detail page to record your first run."
          />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Scanner</th>
                <th>Mode</th>
                <th>Status</th>
                <th>Target</th>
                <th>Exit</th>
                <th>Demo</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.id}>
                  <td>
                    <Link href={`/scans/${run.id}`}>
                      <code className="inlineCode">{run.scanner}</code>
                    </Link>
                  </td>
                  <td><ModeBadge mode={run.mode} /></td>
                  <td><small className={`status ${run.status}`}>{run.status}</small></td>
                  <td><small>{run.target}</small></td>
                  <td><small>{run.exit_code ?? "—"}</small></td>
                  <td><DemoBadge demo={run.is_demo_data} /></td>
                  <td style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    <small>{run.message}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

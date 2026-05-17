import { ScrollText } from "lucide-react";
import { getAudit } from "@/lib/api";
import { EmptyState, SectionHeader, StatusDot } from "@/components/primitives";

export const dynamic = "force-dynamic";

export default async function AuditPage() {
  const rows = await getAudit(100);
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Audit Trail</span>
          <h1>Audit Log</h1>
          <p>{rows.length} entries. Every scope decision (allow or block) is recorded here.</p>
        </div>
      </header>

      <SectionHeader title="Recent decisions" count={rows.length} />

      <section className="panel">
        {rows.length === 0 ? (
          <EmptyState
            icon={<ScrollText size={28} />}
            title="Audit log is empty"
            description="Submit a scan to record the scope decision. Every allow / block is captured here with a reason and payload."
          />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Decision</th>
                <th>Action</th>
                <th>Target</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const kind = r.decision === "block" ? "danger" : r.decision === "allow" ? "ok" : "muted";
                return (
                  <tr key={r.id}>
                    <td><small>{r.timestamp}</small></td>
                    <td>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                        <StatusDot kind={kind} title={r.decision ?? r.result} />
                        <strong style={{ color: "var(--text-1)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                          {r.decision ?? r.result}
                        </strong>
                      </span>
                    </td>
                    <td><small>{r.action}</small></td>
                    <td><small>{r.target}</small></td>
                    <td><small>{r.reason ?? r.reason_code}</small></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

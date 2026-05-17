import { getAudit } from "@/lib/api";

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

      <section className="panel">
        {rows.length === 0 ? (
          <div className="emptyState">Audit log is empty. Trigger a scan from <code className="inlineCode">POST /api/scans</code> to record entries.</div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ textAlign: "left", color: "#94a3b8", fontSize: 12 }}>
                <th style={{ padding: "10px 6px" }}>Timestamp</th>
                <th style={{ padding: "10px 6px" }}>Decision</th>
                <th style={{ padding: "10px 6px" }}>Action</th>
                <th style={{ padding: "10px 6px" }}>Target</th>
                <th style={{ padding: "10px 6px" }}>Reason</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} style={{ borderTop: "1px solid #1f2937" }}>
                  <td style={{ padding: "10px 6px", color: "#94a3b8", fontSize: 12 }}>{r.timestamp}</td>
                  <td style={{ padding: "10px 6px" }}>
                    <span style={{
                      color: r.decision === "block" ? "#fca5a5" : r.decision === "allow" ? "#86efac" : "#cbd5e1",
                      fontWeight: 600,
                      fontSize: 12,
                    }}>{r.decision ?? r.result}</span>
                  </td>
                  <td style={{ padding: "10px 6px", color: "#cbd5e1", fontSize: 12 }}>{r.action}</td>
                  <td style={{ padding: "10px 6px", color: "#cbd5e1", fontSize: 12 }}>{r.target}</td>
                  <td style={{ padding: "10px 6px", color: "#94a3b8", fontSize: 12 }}>{r.reason ?? r.reason_code}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

import { getBlockedCapabilities } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function SafetyPage() {
  const blocked = await getBlockedCapabilities();
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Safety Model</span>
          <h1>Blocked capabilities</h1>
          <p>{blocked.explanation}</p>
        </div>
      </header>

      <section className="panel">
        <div className="panelTitle"><h2>Capabilities Asura refuses to ship</h2></div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", color: "#94a3b8", fontSize: 12 }}>
              <th style={{ padding: "10px 6px" }}>ID</th>
              <th style={{ padding: "10px 6px" }}>Capability</th>
              <th style={{ padding: "10px 6px" }}>Rationale</th>
            </tr>
          </thead>
          <tbody>
            {blocked.capabilities.map((bc) => (
              <tr key={bc.id} style={{ borderTop: "1px solid #1f2937" }}>
                <td style={{ padding: "10px 6px", color: "#fca5a5", fontFamily: "monospace", fontSize: 12 }}>{bc.id}</td>
                <td style={{ padding: "10px 6px", color: "#e7eef8" }}>{bc.label}</td>
                <td style={{ padding: "10px 6px", color: "#94a3b8", fontSize: 13 }}>{bc.rationale}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

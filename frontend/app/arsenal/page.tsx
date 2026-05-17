import { getArsenal } from "@/lib/api";
import { RiskBadge } from "@/components/badges";

export const dynamic = "force-dynamic";

export default async function ArsenalPage() {
  const arsenal = await getArsenal();
  const grouped = arsenal.packs.map((pack) => ({
    pack,
    tools: arsenal.tools.filter((t) => t.pack === pack),
  }));

  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Catalog</span>
          <h1>Arsenal</h1>
          <p>{arsenal.tools.length} registered tool(s). Planned, reference, importer, analyzer, and blocked tools cannot run from this UI.</p>
        </div>
      </header>

      {grouped.map(({ pack, tools }) => (
        <section className="panel" key={pack}>
          <div className="panelTitle">
            <h2>{pack}</h2>
            <small style={{ color: "#94a3b8" }}>{tools.length} tool(s)</small>
          </div>
          <div className="toolGrid">
            {tools.map((tool) => {
              const runnable = tool.integration_status === "runner" && tool.execution !== "blocked";
              return (
                <article className="toolCard" key={tool.id}>
                  <header style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <div>
                      <strong>{tool.name}</strong>
                      <small style={{ display: "block", color: "#94a3b8" }}>{tool.category}</small>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                      <RiskBadge risk={tool.risk_level ?? "low"} />
                      <small style={{ color: "#94a3b8" }}>{tool.execution}</small>
                    </div>
                  </header>
                  <p style={{ color: "#cbd5e1", fontSize: 13, margin: "8px 0" }}>{tool.recommended_use}</p>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {tool.modes.map((m) => <span key={m} className="inlineCode" style={{ fontSize: 11 }}>{m}</span>)}
                    {tool.requires_lab_mode ? <span className="inlineCode" style={{ fontSize: 11 }}>lab-only</span> : null}
                    {tool.installed ? <span className="inlineCode" style={{ fontSize: 11, background: "rgba(34,197,94,0.18)", color: "#86efac" }}>installed</span> : null}
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
                    {(tool.tags ?? []).map((t) => <span key={t} className="inlineCode" style={{ fontSize: 11, color: "#94a3b8" }}>#{t}</span>)}
                  </div>
                  <footer style={{ marginTop: 10, display: "flex", justifyContent: "space-between", fontSize: 12, color: "#94a3b8" }}>
                    <a href={tool.official_url} target="_blank" rel="noreferrer">Docs ↗</a>
                    <span title={runnable ? "Runnable in this Asura installation" : "Catalog-only; cannot run from this UI"} style={{ color: runnable ? "#86efac" : "#fda4af" }}>
                      {runnable ? "Runnable" : "Catalog-only"}
                    </span>
                  </footer>
                  {tool.risk_warning ? <small className="riskWarning" style={{ display: "block", marginTop: 8 }}>{tool.risk_warning}</small> : null}
                </article>
              );
            })}
          </div>
        </section>
      ))}

      <section className="panel">
        <div className="panelTitle"><h2>Blocked-tools policy</h2></div>
        <ul style={{ color: "#cbd5e1", lineHeight: 1.7, paddingLeft: 18 }}>
          {arsenal.blocked_policy.map((p) => <li key={p}>{p}</li>)}
        </ul>
        {arsenal.blocked_capabilities && arsenal.blocked_capabilities.length > 0 ? (
          <>
            <div className="panelTitle" style={{ marginTop: 12 }}><h2>Blocked capabilities</h2></div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {arsenal.blocked_capabilities.map((bc) => <span key={bc} className="inlineCode" style={{ fontSize: 11 }}>{bc}</span>)}
            </div>
          </>
        ) : null}
      </section>
    </div>
  );
}

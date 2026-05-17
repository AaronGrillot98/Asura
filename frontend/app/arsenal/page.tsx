import { getArsenal } from "@/lib/api";
import { RiskBadge } from "@/components/badges";
import { SectionHeader, StatusDot } from "@/components/primitives";

export const dynamic = "force-dynamic";

export default async function ArsenalPage() {
  const arsenal = await getArsenal();
  const runnableCount = arsenal.tools.filter(
    (t) => t.integration_status === "runner" && t.execution !== "blocked",
  ).length;
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
          <p>
            {arsenal.tools.length} registered · {runnableCount} runner-ready · the
            rest are catalog-only (planned, reference, importer, analyzer, or blocked).
          </p>
        </div>
      </header>

      {grouped.map(({ pack, tools }) => (
        <section key={pack} style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <SectionHeader title={pack} count={tools.length} />
          <div className="toolGrid">
            {tools.map((tool) => {
              const runnable =
                tool.integration_status === "runner" && tool.execution !== "blocked";
              const statusKind = tool.execution === "blocked"
                ? "danger"
                : runnable
                ? tool.installed
                  ? "ok"
                  : "info"
                : tool.integration_status === "planned"
                ? "warn"
                : "muted";
              const statusTitle = runnable
                ? tool.installed
                  ? "Installed and runner-ready"
                  : "Runner ready (binary or Docker image required)"
                : tool.execution === "blocked"
                ? "Blocked — refused capability"
                : "Catalog-only; cannot run from this UI";
              return (
                <article className="toolCard" key={tool.id}>
                  <div className="toolTop">
                    <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                      <StatusDot kind={statusKind} title={statusTitle} />
                      <div>
                        <strong>{tool.name}</strong>
                        <small style={{ display: "block" }}>{tool.category}</small>
                      </div>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                      <RiskBadge risk={tool.risk_level ?? "low"} />
                      <small className={`toolBadge ${tool.integration_status === "planned" ? "planned" : tool.execution === "blocked" ? "blocked" : tool.execution === "reference" ? "reference" : "runner"}`}>
                        {tool.execution.replace("_", " ")}
                      </small>
                    </div>
                  </div>
                  <p>{tool.recommended_use}</p>
                  <div className="modeRow">
                    {tool.modes.map((m) => <span key={m}>{m}</span>)}
                    {tool.requires_lab_mode ? <span>lab-only</span> : null}
                    {tool.installed ? <span style={{ background: "var(--ok-bg)", color: "var(--ok)" }}>installed</span> : null}
                  </div>
                  {tool.tags && tool.tags.length > 0 ? (
                    <div className="toolMeta">
                      {tool.tags.map((t) => <span key={t}>#{t}</span>)}
                    </div>
                  ) : null}
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid var(--border-1)", paddingTop: 10, fontSize: 12, color: "var(--text-3)" }}>
                    <a href={tool.official_url} target="_blank" rel="noreferrer">Docs ↗</a>
                    <span style={{ color: runnable ? "var(--ok)" : "var(--text-3)" }}>
                      {runnable ? "Runnable" : "Catalog-only"}
                    </span>
                  </div>
                  {tool.risk_warning ? <small className="riskWarning">{tool.risk_warning}</small> : null}
                </article>
              );
            })}
          </div>
        </section>
      ))}

      <section className="panel">
        <div className="panelTitle"><h2>Blocked-tools policy</h2></div>
        <ul style={{ color: "var(--text-2)", lineHeight: 1.7, paddingLeft: 18, margin: 0 }}>
          {arsenal.blocked_policy.map((p) => <li key={p}>{p}</li>)}
        </ul>
        {arsenal.blocked_capabilities && arsenal.blocked_capabilities.length > 0 ? (
          <>
            <div className="panelTitle" style={{ marginTop: 12 }}><h2>Blocked capabilities</h2></div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {arsenal.blocked_capabilities.map((bc) => <span key={bc} className="inlineCode">{bc}</span>)}
            </div>
          </>
        ) : null}
      </section>
    </div>
  );
}

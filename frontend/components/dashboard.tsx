"use client";

import { Activity, AlertTriangle, Box, CheckCircle2, Download, GitBranch, KeyRound, Network, PackageCheck, Radar, ShieldAlert, TerminalSquare } from "lucide-react";
import type { ReactNode } from "react";
import { useMemo, useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ArsenalSummary, AttackPath, Asset, DashboardSummary, Finding, ScannerRun, Severity, ToolDefinition } from "@/lib/api";
import { reportUrl } from "@/lib/api";
import { RunScanForm } from "@/components/run-scan-form";

const severityWeight: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const severityClass: Record<Severity, string> = {
  critical: "sev critical",
  high: "sev high",
  medium: "sev medium",
  low: "sev low",
  info: "sev info"
};

function countSeverity(findings: Finding[], severity: Severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}

function assetFor(assets: Asset[], finding: Finding) {
  return assets.find((asset) => asset.id === finding.asset_id);
}

function confidenceLabel(confidence: Finding["confidence"]) {
  return typeof confidence === "number" ? `${confidence}%` : confidence;
}

function confidenceWeight(confidence: Finding["confidence"]) {
  if (typeof confidence === "number") return confidence;
  return { low: 25, medium: 50, high: 80, confirmed: 100 }[confidence];
}

function Metric({ label, value, tone, icon }: { label: string; value: string | number; tone?: string; icon: ReactNode }) {
  return (
    <section className="metric">
      <div className={`metricIcon ${tone ?? ""}`}>{icon}</div>
      <span>{label}</span>
      <strong>{value}</strong>
    </section>
  );
}

function ScannerHealth({ runs }: { runs: ScannerRun[] }) {
  return (
    <section className="panel">
      <div className="panelTitle">
        <TerminalSquare size={18} />
        <h2>Scanner Health</h2>
      </div>
      <div className="runList">
        {runs.slice(0, 6).map((run) => (
          <div className="run" key={run.id}>
            <div>
              <strong>{run.scanner}</strong>
              <span>{run.target}</span>
            </div>
            <small className={`status ${run.status}`}>{run.status}</small>
          </div>
        ))}
      </div>
    </section>
  );
}

function AttackPathGraph({ path }: { path: AttackPath }) {
  return (
    <section className="panel attackPanel">
      <div className="panelTitle">
        <GitBranch size={18} />
        <h2>Most Dangerous Chain</h2>
      </div>
      <p className="muted">{path.summary}</p>
      <div className="chain">
        {path.nodes.map((node, index) => (
          <div className="chainStep" key={node.id}>
            <div className={node.severity ? severityClass[node.severity] : "sev info"}>{node.kind}</div>
            <strong>{node.label}</strong>
            {index < path.nodes.length - 1 ? <span className="connector">{path.edges[index]?.label}</span> : null}
          </div>
        ))}
      </div>
    </section>
  );
}

function FindingsTable({ findings, assets }: { findings: Finding[]; assets: Asset[] }) {
  const sorted = [...findings].sort((a, b) => severityWeight[b.severity] - severityWeight[a.severity] || confidenceWeight(b.confidence) - confidenceWeight(a.confidence));
  return (
    <section className="panel tablePanel">
      <div className="panelTitle">
        <ShieldAlert size={18} />
        <h2>Findings</h2>
      </div>
      <div className="findings">
        {sorted.map((finding) => (
          <article className="finding" key={finding.id}>
            <div className="findingTop">
              <span className={severityClass[finding.severity]}>{finding.severity}</span>
              <strong>{finding.title}</strong>
              <span className="confidence">{confidenceLabel(finding.confidence)}</span>
            </div>
            <div className="findingMeta">
              <span>{finding.scanner}</span>
              <span>{assetFor(assets, finding)?.name ?? "Unknown asset"}</span>
              <span>{finding.status}</span>
            </div>
            <p>{finding.impact}</p>
            <details>
              <summary>Evidence and remediation</summary>
              <div className="evidenceGrid">
                <div>
                  <h3>Evidence</h3>
                  <p>{finding.evidence[0]?.summary}</p>
                  <code>{JSON.stringify(finding.evidence[0]?.raw ?? {}, null, 2)}</code>
                </div>
                <div>
                  <h3>Fix</h3>
                  <p>{finding.recommendation}</p>
                  <h3>False-positive reasoning</h3>
                  <p>{finding.false_positive_reasoning}</p>
                </div>
              </div>
            </details>
          </article>
        ))}
      </div>
    </section>
  );
}

function AgentPanel({ outputs }: { outputs: DashboardSummary["agent_outputs"] }) {
  return (
    <section className="panel">
      <div className="panelTitle">
        <Radar size={18} />
        <h2>Agent Reasoning</h2>
      </div>
      <div className="agentList">
        {outputs.map((output) => (
          <article className="agentCard" key={output.agent}>
            <div>
              <strong>{output.agent.replaceAll("_", " ")}</strong>
              <span>{output.confidence}</span>
            </div>
            <p>{output.summary}</p>
            {output.recommended_next_steps.length > 0 ? <small>{output.recommended_next_steps[0]}</small> : null}
          </article>
        ))}
      </div>
    </section>
  );
}

function AssetMap({ assets }: { assets: Asset[] }) {
  const iconFor = (kind: string) => {
    if (kind === "repo") return <KeyRound size={17} />;
    if (kind === "container") return <Box size={17} />;
    if (kind === "host") return <Network size={17} />;
    return <Radar size={17} />;
  };

  return (
    <section className="panel">
      <div className="panelTitle">
        <Network size={18} />
        <h2>Asset Inventory</h2>
      </div>
      <div className="assetGrid">
        {assets.map((asset) => (
          <div className="asset" key={asset.id}>
            <div className="assetIcon">{iconFor(asset.kind)}</div>
            <div>
              <strong>{asset.name}</strong>
              <span>{asset.address}</span>
            </div>
            <small>{asset.exposure}</small>
          </div>
        ))}
      </div>
    </section>
  );
}

function labelize(value: string) {
  return value.replaceAll("_", " ");
}

function toolStatusClass(tool: ToolDefinition) {
  if (tool.execution === "blocked") return "toolBadge blocked";
  if (tool.integration_status === "runner") return "toolBadge runner";
  if (tool.execution === "reference") return "toolBadge reference";
  return "toolBadge planned";
}

function Arsenal({ arsenal }: { arsenal: ArsenalSummary }) {
  const [query, setQuery] = useState("");
  const [pack, setPack] = useState("all");
  const [execution, setExecution] = useState("all");
  const visibleTools = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return arsenal.tools.filter((tool) => {
      const matchesQuery =
        !needle ||
        tool.name.toLowerCase().includes(needle) ||
        tool.category.toLowerCase().includes(needle) ||
        tool.recommended_use.toLowerCase().includes(needle);
      const matchesPack = pack === "all" || tool.pack === pack;
      const matchesExecution = execution === "all" || tool.execution === execution;
      return matchesQuery && matchesPack && matchesExecution;
    });
  }, [arsenal.tools, execution, pack, query]);
  const runnableCount = arsenal.tools.filter((tool) => tool.execution === "core_runner").length;
  const blockedCount = arsenal.tools.filter((tool) => tool.execution === "blocked").length;
  const installedCount = arsenal.tools.filter((tool) => tool.installed).length;

  return (
    <section className="panel arsenalPanel">
      <div className="panelTitle splitTitle">
        <div>
          <span className="eyebrow">Registry-backed</span>
          <h2>Arsenal</h2>
        </div>
        <div className="arsenalStats">
          <span>{arsenal.packs.length} packs</span>
          <span>{runnableCount} core runners</span>
          <span>{installedCount} installed</span>
          <span>{blockedCount} blocked</span>
        </div>
      </div>
      <div className="arsenalControls">
        <input aria-label="Search Arsenal" placeholder="Search tools, categories, use cases" value={query} onChange={(event) => setQuery(event.target.value)} />
        <select aria-label="Filter by pack" value={pack} onChange={(event) => setPack(event.target.value)}>
          <option value="all">All packs</option>
          {arsenal.packs.map((packName) => (
            <option key={packName} value={packName}>
              {packName}
            </option>
          ))}
        </select>
        <select aria-label="Filter by execution" value={execution} onChange={(event) => setExecution(event.target.value)}>
          <option value="all">All execution classes</option>
          <option value="core_runner">Core runners</option>
          <option value="optional_pack">Optional packs</option>
          <option value="reference">Reference</option>
          <option value="blocked">Blocked</option>
        </select>
      </div>
      <div className="packSummaryGrid">
        {arsenal.pack_summaries.map((summary) => (
          <div className="packSummary" key={summary.name}>
            <strong>{summary.name}</strong>
            <span>{summary.total} tools</span>
            <small>{summary.core_runners} core / {summary.optional} optional / {summary.reference} reference</small>
          </div>
        ))}
      </div>
      <div className="toolGrid">
        {visibleTools.map((tool) => (
          <article className="toolCard" key={tool.id}>
            <div className="toolTop">
              <div>
                <strong>{tool.name}</strong>
                <span>{tool.pack}</span>
              </div>
              <small className={toolStatusClass(tool)}>{labelize(tool.execution)}</small>
            </div>
            <p>{tool.recommended_use}</p>
            <div className="toolMeta">
              <span>{tool.category}</span>
              <span>{tool.license}</span>
              <span>{tool.installed ? "Installed" : tool.install_status}</span>
              <span>{tool.docker_available ? "Docker" : "External"}</span>
              <span>{tool.integration_status}</span>
            </div>
            {tool.executable ? <code className="inlineCode">{tool.executable}</code> : null}
            <div className="modeRow">
              {tool.modes.length > 0 ? tool.modes.map((mode) => <span key={mode}>{mode}</span>) : <span>blocked</span>}
            </div>
            {!tool.installed && tool.install_hint ? <small className="installHint">{tool.install_hint}</small> : null}
            {tool.risk_warning ? <small className="riskWarning">{tool.risk_warning}</small> : null}
          </article>
        ))}
      </div>
      {visibleTools.length === 0 ? <div className="emptyState">No tools match the current Arsenal filters.</div> : null}
      <div className="blockedPolicy">
        <strong>Blocked-tools policy</strong>
        <div>
          {arsenal.blocked_policy.map((policy) => (
            <span key={policy}>{policy}</span>
          ))}
        </div>
      </div>
    </section>
  );
}

export function Dashboard({ data, arsenal }: { data: DashboardSummary; arsenal: ArsenalSummary }) {
  const path = data.attack_paths[0];
  return (
    <>
      {data.is_demo_data ? (
        <div style={{ background: "rgba(245, 158, 11, 0.12)", border: "1px solid rgba(245, 158, 11, 0.3)", color: "#fcd34d", padding: "10px 14px", borderRadius: 10, marginBottom: 12, fontSize: 13 }}>
          <strong>Demo mode:</strong> findings on this dashboard are seeded demo evidence, not the result of a live scan.
        </div>
      ) : null}
        <header className="topbar">
          <div>
            <span className="eyebrow">Workspace / {data.is_demo_data ? "Demo" : "Live"}</span>
            <h1>{data.project.name}</h1>
            <p>{data.project.description}</p>
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <RunScanForm projectId={data.project.id} />
            <a className="button" href={reportUrl(data.project.id)}>
              <Download size={16} />
              Export report
            </a>
          </div>
        </header>

        <section className="metrics">
          <Metric label="Executive risk" value={`${data.project.risk_score}/100`} tone="danger" icon={<AlertTriangle size={19} />} />
          <Metric label="Critical findings" value={countSeverity(data.findings, "critical")} tone="danger" icon={<ShieldAlert size={19} />} />
          <Metric label="Tracked assets" value={data.assets.length} icon={<Network size={19} />} />
          <Metric label="Arsenal tools" value={arsenal.tools.length} icon={<PackageCheck size={19} />} />
        </section>

        <section className="grid two">
          <section className="panel">
            <div className="panelTitle">
              <Activity size={18} />
              <h2>Risk Trend</h2>
            </div>
            <div className="chart">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.risk_trend}>
                  <defs>
                    <linearGradient id="risk" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.34} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#223041" vertical={false} />
                  <XAxis dataKey="date" stroke="#8291a5" tick={{ fontSize: 12 }} />
                  <YAxis stroke="#8291a5" tick={{ fontSize: 12 }} domain={[0, 100]} />
                  <Tooltip contentStyle={{ background: "#101923", border: "1px solid #26374a", color: "#e7eef8" }} />
                  <Area type="monotone" dataKey="score" stroke="#ef4444" fill="url(#risk)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>
          <ScannerHealth runs={data.scanner_runs} />
        </section>

        <section className="grid two">
          <AttackPathGraph path={path} />
          <section className="panel">
            <div className="panelTitle">
              <CheckCircle2 size={18} />
              <h2>Fix These 5 First</h2>
            </div>
            <div className="fixList">
              {path.remediation_order.map((id, index) => {
                const finding = data.findings.find((item) => item.id === id);
                if (!finding) return null;
                return (
                  <div className="fix" key={id}>
                    <span>{index + 1}</span>
                    <div>
                      <strong>{finding.title}</strong>
                      <small>{finding.recommendation}</small>
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        </section>

        <AgentPanel outputs={data.agent_outputs} />
        <AssetMap assets={data.assets} />
        <Arsenal arsenal={arsenal} />
        <FindingsTable findings={data.findings} assets={data.assets} />
    </>
  );
}

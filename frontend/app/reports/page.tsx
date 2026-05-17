import { jsonReportUrl, reportUrl } from "@/lib/api";
import { Download } from "lucide-react";

export default function ReportsPage() {
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Deliverables</span>
          <h1>Reports</h1>
          <p>Markdown and JSON reports include scope, authorization, methodology, evidence, remediation, and safety statements.</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <a className="button" href={reportUrl("demo")}>
            <Download size={14} /> Markdown
          </a>
          <a className="button" href={jsonReportUrl("demo")} target="_blank" rel="noreferrer">
            <Download size={14} /> JSON
          </a>
        </div>
      </header>

      <section className="panel">
        <div className="panelTitle"><h2>Sections shipped in every report</h2></div>
        <ol style={{ color: "var(--text-2)", paddingLeft: 18, lineHeight: 1.7, margin: 0 }}>
          <li>Engagement Summary</li>
          <li>Scope</li>
          <li>Authorization Statement</li>
          <li>Methodology</li>
          <li>Tools Used</li>
          <li>Executive Summary</li>
          <li>Risk Overview</li>
          <li>Attack Paths</li>
          <li>Findings by Severity</li>
          <li>Evidence (with content hashes)</li>
          <li>Remediation Roadmap</li>
          <li>Appendix: Scanner Runs</li>
          <li>Appendix: Raw Evidence References</li>
          <li>Safety Statement</li>
        </ol>
        <p style={{ marginTop: 10 }}>
          PDF rendering is not yet implemented; reports stamp <code className="inlineCode">pdf_status: not_generated</code>.
        </p>
      </section>
    </div>
  );
}

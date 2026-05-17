"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Play } from "lucide-react";
import { startScan, type ScannerRun, type StartScanRequest } from "@/lib/api";

const CORE_SCANNERS: { id: string; label: string; defaultMode: "passive" | "active" }[] = [
  // Core 10 — first-class engines
  { id: "semgrep", label: "Semgrep (code)", defaultMode: "passive" },
  { id: "gitleaks", label: "Gitleaks (secrets)", defaultMode: "passive" },
  { id: "osv-scanner", label: "OSV-Scanner (deps)", defaultMode: "passive" },
  { id: "checkov", label: "Checkov (IaC)", defaultMode: "passive" },
  { id: "trivy", label: "Trivy (containers / IaC)", defaultMode: "passive" },
  { id: "syft", label: "Syft (SBOM)", defaultMode: "passive" },
  { id: "grype", label: "Grype (vulns)", defaultMode: "passive" },
  { id: "nuclei", label: "Nuclei (web)", defaultMode: "active" },
  { id: "zap", label: "OWASP ZAP (DAST)", defaultMode: "active" },
  { id: "nmap", label: "Nmap (network)", defaultMode: "active" },
  // AppSec / language packs (passive)
  { id: "bandit", label: "Bandit (Python SAST)", defaultMode: "passive" },
  { id: "pip-audit", label: "pip-audit (Python deps)", defaultMode: "passive" },
  { id: "npm-audit", label: "npm audit (JS deps)", defaultMode: "passive" },
  { id: "cargo-audit", label: "cargo-audit (Rust deps)", defaultMode: "passive" },
  { id: "govulncheck", label: "govulncheck (Go deps)", defaultMode: "passive" },
  { id: "gosec", label: "gosec (Go SAST)", defaultMode: "passive" },
  { id: "brakeman", label: "Brakeman (Rails SAST)", defaultMode: "passive" },
  { id: "eslint-security", label: "ESLint security (JS/TS)", defaultMode: "passive" },
  { id: "bearer", label: "Bearer (privacy + security)", defaultMode: "passive" },
  { id: "trufflehog", label: "TruffleHog (secrets)", defaultMode: "passive" },
  // Recon
  { id: "subfinder", label: "subfinder (subdomains)", defaultMode: "passive" },
  { id: "httpx", label: "httpx (HTTP probe)", defaultMode: "active" },
  { id: "naabu", label: "naabu (port scan)", defaultMode: "active" },
];

type Status =
  | { kind: "idle" }
  | { kind: "running"; message: string }
  | { kind: "ok"; runs: ScannerRun[] }
  | { kind: "error"; message: string };

export function RunScanForm({ projectId = "demo" }: { projectId?: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState("");
  const [scanners, setScanners] = useState<string[]>(["semgrep"]);
  const [mode, setMode] = useState<"passive" | "active" | "lab">("passive");
  const [authorizedScope, setAuthorizedScope] = useState("");
  const [explicitAuthorization, setExplicitAuthorization] = useState(false);
  const [confirmHighNoise, setConfirmHighNoise] = useState(false);
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  const toggleScanner = (id: string) => {
    setScanners((current) =>
      current.includes(id) ? current.filter((s) => s !== id) : [...current, id]
    );
  };

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!target.trim()) {
      setStatus({ kind: "error", message: "Target is required." });
      return;
    }
    if (scanners.length === 0) {
      setStatus({ kind: "error", message: "Pick at least one scanner." });
      return;
    }
    if ((mode === "active" || mode === "lab") && !explicitAuthorization) {
      setStatus({ kind: "error", message: "Active and lab scans require explicit authorization." });
      return;
    }
    const payload: StartScanRequest = {
      project_id: projectId,
      target: target.trim(),
      scanners,
      mode,
      authorized_scope: authorizedScope.trim() || null,
      explicit_authorization: explicitAuthorization,
      confirm_high_noise: confirmHighNoise,
    };
    setStatus({ kind: "running", message: `Running ${scanners.length} scanner(s)…` });
    try {
      const runs = await startScan(payload);
      setStatus({ kind: "ok", runs });
      router.refresh();
    } catch (err) {
      setStatus({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }

  if (!open) {
    return (
      <button type="button" className="button" onClick={() => setOpen(true)}>
        <Play size={14} /> Run scan
      </button>
    );
  }

  return (
    <section className="panel" style={{ marginBottom: 14 }}>
      <div className="panelTitle" style={{ justifyContent: "space-between" }}>
        <h2 style={{ margin: 0 }}>Run scan</h2>
        <button type="button" className="button" style={{ background: "#1f2937", color: "#e8eef6", height: 32 }} onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
      <form onSubmit={onSubmit} style={{ display: "grid", gap: 12 }}>
        <label style={{ display: "grid", gap: 4 }}>
          <span style={{ color: "#94a3b8", fontSize: 12 }}>Target</span>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="e.g. https://flightops.acme.example or git://acme/flightops-platform"
            style={{ background: "#0b1320", color: "#e8eef6", border: "1px solid #1f2937", borderRadius: 8, padding: "8px 10px", fontSize: 13 }}
          />
        </label>

        <fieldset style={{ border: "1px solid #1f2937", borderRadius: 8, padding: 10 }}>
          <legend style={{ color: "#94a3b8", fontSize: 12, padding: "0 6px" }}>Scanners</legend>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {CORE_SCANNERS.map((s) => (
              <label key={s.id} style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 13, color: "#cbd5e1", background: scanners.includes(s.id) ? "rgba(34,197,94,0.14)" : "#0b1320", border: "1px solid #1f2937", padding: "4px 8px", borderRadius: 999 }}>
                <input type="checkbox" checked={scanners.includes(s.id)} onChange={() => toggleScanner(s.id)} style={{ margin: 0 }} />
                {s.label}
              </label>
            ))}
          </div>
        </fieldset>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ color: "#94a3b8", fontSize: 12 }}>Mode</span>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as "passive" | "active" | "lab")}
              style={{ background: "#0b1320", color: "#e8eef6", border: "1px solid #1f2937", borderRadius: 8, padding: "8px 10px", fontSize: 13, height: 40 }}
            >
              <option value="passive">passive (default — safe, non-invasive)</option>
              <option value="active">active (authorized targets only)</option>
              <option value="lab">lab (intentionally vulnerable / training)</option>
            </select>
          </label>
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ color: "#94a3b8", fontSize: 12 }}>Authorized scope reference</span>
            <input
              value={authorizedScope}
              onChange={(e) => setAuthorizedScope(e.target.value)}
              placeholder="Required for active / lab — paste the scope id or URL you have authorization for"
              style={{ background: "#0b1320", color: "#e8eef6", border: "1px solid #1f2937", borderRadius: 8, padding: "8px 10px", fontSize: 13 }}
            />
          </label>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 13, color: "#cbd5e1" }}>
          <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <input type="checkbox" checked={explicitAuthorization} onChange={(e) => setExplicitAuthorization(e.target.checked)} />
            I confirm I have explicit authorization to test this target.
          </label>
          <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <input type="checkbox" checked={confirmHighNoise} onChange={(e) => setConfirmHighNoise(e.target.checked)} />
            I accept that high-noise scanners (ffuf, gobuster, nikto, etc.) may generate substantial traffic.
          </label>
        </div>

        {status.kind === "error" ? (
          <div style={{ background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.3)", color: "#fca5a5", padding: "8px 12px", borderRadius: 8, fontSize: 13 }}>
            {status.message}
          </div>
        ) : null}
        {status.kind === "running" ? (
          <div style={{ background: "rgba(96,165,250,0.12)", border: "1px solid rgba(96,165,250,0.3)", color: "#93c5fd", padding: "8px 12px", borderRadius: 8, fontSize: 13 }}>
            {status.message}
          </div>
        ) : null}
        {status.kind === "ok" ? (
          <div style={{ background: "rgba(34,197,94,0.12)", border: "1px solid rgba(34,197,94,0.3)", color: "#86efac", padding: "8px 12px", borderRadius: 8, fontSize: 13 }}>
            Submitted {status.runs.length} run(s). {status.runs.map((r) => `${r.scanner}: ${r.status}`).join(" · ")}
          </div>
        ) : null}

        <div>
          <button type="submit" className="button" disabled={status.kind === "running"}>
            <Play size={14} /> {status.kind === "running" ? "Running…" : "Submit scan"}
          </button>
        </div>
      </form>
    </section>
  );
}

"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Play } from "lucide-react";
import {
  listAuthProfiles,
  listTemplates,
  startScan,
  startScanAsync,
  type AuthProfile,
  type NucleiTemplate,
  type Project,
  type ScannerRun,
  type StartScanRequest,
} from "@/lib/api";

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
  // Fuzzers (slice 10) — require a wordlist
  { id: "ffuf", label: "ffuf (web fuzzing)", defaultMode: "active" },
  { id: "gobuster", label: "Gobuster (dir/dns)", defaultMode: "active" },
  { id: "dirsearch", label: "Dirsearch (web)", defaultMode: "active" },
  // K8s / cloud (slice 10)
  { id: "kube-bench", label: "kube-bench (CIS K8s)", defaultMode: "passive" },
  { id: "kubescape", label: "kubescape (K8s posture)", defaultMode: "passive" },
  { id: "kube-score", label: "kube-score (manifest lint)", defaultMode: "passive" },
  { id: "prowler", label: "prowler (cloud audit)", defaultMode: "passive" },
];

const FUZZER_IDS = new Set(["ffuf", "gobuster", "dirsearch"]);
const PROVIDER_IDS = new Set(["prowler"]);

type Status =
  | { kind: "idle" }
  | { kind: "running"; message: string }
  | { kind: "ok"; runs: ScannerRun[] }
  | { kind: "queued"; jobId: string }
  | { kind: "error"; message: string };

export function RunScanForm({
  projectId,
  projects,
  lockProject = false,
}: {
  projectId?: string;
  projects?: Project[];
  lockProject?: boolean;
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [activeProjectId, setActiveProjectId] = useState(projectId ?? projects?.[0]?.id ?? "demo");
  const [target, setTarget] = useState("");
  const [scanners, setScanners] = useState<string[]>(["semgrep"]);
  const [mode, setMode] = useState<"passive" | "active" | "lab">("passive");
  const [authorizedScope, setAuthorizedScope] = useState("");
  const [explicitAuthorization, setExplicitAuthorization] = useState(false);
  const [confirmHighNoise, setConfirmHighNoise] = useState(false);
  const [runInBackground, setRunInBackground] = useState(false);
  const [templates, setTemplates] = useState<NucleiTemplate[]>([]);
  const [selectedTemplateIds, setSelectedTemplateIds] = useState<string[]>([]);
  const [wordlist, setWordlist] = useState("");
  const [provider, setProvider] = useState("aws");
  const [authProfiles, setAuthProfiles] = useState<AuthProfile[]>([]);
  const [authProfileId, setAuthProfileId] = useState<string>("");
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  const nucleiSelected = scanners.includes("nuclei");
  const httpxSelected = scanners.includes("httpx");
  const zapSelected = scanners.includes("zap");
  const authCapableSelected = nucleiSelected || httpxSelected || zapSelected;
  const fuzzerSelected = scanners.some((s) => FUZZER_IDS.has(s));
  const providerSelected = scanners.some((s) => PROVIDER_IDS.has(s));

  // Load templates lazily once the user opens the form AND has nuclei selected.
  useEffect(() => {
    if (!open || !nucleiSelected || templates.length > 0) return;
    let cancelled = false;
    (async () => {
      try {
        const next = await listTemplates();
        if (!cancelled) setTemplates(next);
      } catch {
        // Don't fail the form if templates can't be fetched — just hide the picker.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, nucleiSelected, templates.length]);

  // Load auth profiles lazily when an auth-capable scanner is selected.
  useEffect(() => {
    if (!open || !authCapableSelected || authProfiles.length > 0) return;
    let cancelled = false;
    (async () => {
      try {
        const next = await listAuthProfiles();
        if (!cancelled) setAuthProfiles(next);
      } catch {
        // ignore — picker hidden
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, authCapableSelected, authProfiles.length]);

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
    if (fuzzerSelected && !wordlist.trim()) {
      setStatus({
        kind: "error",
        message: "Selected fuzzers (ffuf/gobuster/dirsearch) require a wordlist path.",
      });
      return;
    }
    const payload: StartScanRequest = {
      project_id: activeProjectId,
      target: target.trim(),
      scanners,
      mode,
      authorized_scope: authorizedScope.trim() || null,
      explicit_authorization: explicitAuthorization,
      confirm_high_noise: confirmHighNoise,
      template_ids: nucleiSelected && selectedTemplateIds.length > 0 ? selectedTemplateIds : undefined,
      wordlist: fuzzerSelected ? wordlist.trim() || undefined : undefined,
      provider: providerSelected ? provider.trim() || undefined : undefined,
      auth_profile_id: authCapableSelected && authProfileId ? authProfileId : undefined,
    };
    setStatus({ kind: "running", message: `Running ${scanners.length} scanner(s)…` });
    try {
      if (runInBackground) {
        const response = await startScanAsync(payload);
        setStatus({ kind: "queued", jobId: response.job_id });
      } else {
        const runs = await startScan(payload);
        setStatus({ kind: "ok", runs });
      }
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
        {projects && projects.length > 0 && !lockProject ? (
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ color: "#94a3b8", fontSize: 12 }}>Project</span>
            <select
              value={activeProjectId}
              onChange={(e) => setActiveProjectId(e.target.value)}
              style={{ background: "#0b1320", color: "#e8eef6", border: "1px solid #1f2937", borderRadius: 8, padding: "8px 10px", fontSize: 13, height: 40 }}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                  {p.is_demo_data ? " (demo)" : ""}
                </option>
              ))}
            </select>
          </label>
        ) : null}
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
          <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <input type="checkbox" checked={runInBackground} onChange={(e) => setRunInBackground(e.target.checked)} />
            Run in background — submit a job and poll progress on /jobs (recommended for long scans).
          </label>
        </div>

        {fuzzerSelected ? (
          <fieldset style={{ border: "1px solid var(--border-1)", borderRadius: 8, padding: 10 }}>
            <legend style={{ color: "var(--text-3)", fontSize: 12, padding: "0 6px" }}>
              Wordlist path (required for ffuf / gobuster / dirsearch)
            </legend>
            <input
              value={wordlist}
              onChange={(e) => setWordlist(e.target.value)}
              placeholder="/usr/share/seclists/Discovery/Web-Content/common.txt"
              style={{ fontSize: 13 }}
            />
            <small style={{ color: "var(--text-3)", display: "block", marginTop: 6 }}>
              Filesystem path on the backend host. Asura will substitute this for the
              <code className="inlineCode" style={{ marginLeft: 4, marginRight: 4 }}>{`{{wordlist}}`}</code>
              placeholder in each fuzzer command template.
            </small>
          </fieldset>
        ) : null}

        {providerSelected ? (
          <fieldset style={{ border: "1px solid var(--border-1)", borderRadius: 8, padding: 10 }}>
            <legend style={{ color: "var(--text-3)", fontSize: 12, padding: "0 6px" }}>
              Cloud provider (required for prowler)
            </legend>
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              style={{ fontSize: 13, height: 36 }}
            >
              <option value="aws">AWS</option>
              <option value="azure">Azure</option>
              <option value="gcp">GCP</option>
              <option value="kubernetes">Kubernetes</option>
              <option value="github">GitHub</option>
            </select>
            <small style={{ color: "var(--text-3)", display: "block", marginTop: 6 }}>
              Prowler requires valid read-only cloud credentials in the backend
              environment before this will produce findings.
            </small>
          </fieldset>
        ) : null}

        {authCapableSelected ? (
          <fieldset style={{ border: "1px solid var(--border-1)", borderRadius: 8, padding: 10 }}>
            <legend style={{ color: "var(--text-3)", fontSize: 12, padding: "0 6px" }}>
              Auth profile (optional) — injected as <code className="inlineCode">-H</code> flags
            </legend>
            {authProfiles.length === 0 ? (
              <small style={{ color: "var(--text-3)" }}>
                No auth profiles yet. <a href="/auth-profiles">Create one →</a>
              </small>
            ) : (
              <select
                value={authProfileId}
                onChange={(e) => setAuthProfileId(e.target.value)}
                style={{ fontSize: 13, height: 38, width: "100%" }}
              >
                <option value="">(no auth — scan as unauthenticated)</option>
                {authProfiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} · {p.auth_type} · {p.credential_preview}
                  </option>
                ))}
              </select>
            )}
          </fieldset>
        ) : null}

        {nucleiSelected ? (
          <fieldset style={{ border: "1px solid var(--border-1)", borderRadius: 8, padding: 10 }}>
            <legend style={{ color: "var(--text-3)", fontSize: 12, padding: "0 6px" }}>
              Custom Nuclei templates (optional)
            </legend>
            {templates.length === 0 ? (
              <small style={{ color: "var(--text-3)" }}>
                No custom templates uploaded yet. <a href="/templates">Upload one →</a>
              </small>
            ) : (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {templates.map((t) => {
                  const checked = selectedTemplateIds.includes(t.id);
                  return (
                    <label
                      key={t.id}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 12,
                        color: "var(--text-2)",
                        background: checked ? "var(--bg-active)" : "var(--bg-3)",
                        border: "1px solid var(--border-1)",
                        padding: "4px 8px",
                        borderRadius: 999,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() =>
                          setSelectedTemplateIds((cur) =>
                            checked ? cur.filter((id) => id !== t.id) : [...cur, t.id],
                          )
                        }
                        style={{ margin: 0 }}
                      />
                      {t.display_name}
                      {t.severity ? (
                        <span style={{ color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                          {t.severity}
                        </span>
                      ) : null}
                    </label>
                  );
                })}
              </div>
            )}
          </fieldset>
        ) : null}

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
          <div className="banner info" style={{ fontSize: 13 }}>
            Submitted {status.runs.length} run(s). {status.runs.map((r) => `${r.scanner}: ${r.status}`).join(" · ")}
          </div>
        ) : null}
        {status.kind === "queued" ? (
          <div className="banner info" style={{ fontSize: 13 }}>
            Job <code className="inlineCode">{status.jobId}</code> queued. {" "}
            <a href={`/jobs/${status.jobId}`}>Track progress →</a>
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

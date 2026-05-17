"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Sprout } from "lucide-react";
import { createProject, type ProjectCreate, type ScopeRules } from "@/lib/api";

const EMPTY_SCOPE: ScopeRules = {
  domains: [],
  urls: [],
  cidrs: [],
  repos: [],
  containers: [],
  blocked_targets: [],
  allow_active: false,
  allow_lab: false,
  max_requests_per_second: 2,
  timeout_seconds: 900,
};

function parseList(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

type Status =
  | { kind: "idle" }
  | { kind: "saving" }
  | { kind: "error"; message: string };

export function NewProjectForm() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [grantor, setGrantor] = useState("");
  const [domains, setDomains] = useState("");
  const [urls, setUrls] = useState("");
  const [cidrs, setCidrs] = useState("");
  const [repos, setRepos] = useState("");
  const [containers, setContainers] = useState("");
  const [allowActive, setAllowActive] = useState(false);
  const [allowLab, setAllowLab] = useState(false);
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!name.trim()) {
      setStatus({ kind: "error", message: "Project name is required." });
      return;
    }
    const scope_rules: ScopeRules = {
      ...EMPTY_SCOPE,
      domains: parseList(domains),
      urls: parseList(urls),
      cidrs: parseList(cidrs),
      repos: parseList(repos),
      containers: parseList(containers),
      allow_active: allowActive,
      allow_lab: allowLab,
    };
    const scopeCount =
      scope_rules.domains.length +
      scope_rules.urls.length +
      scope_rules.cidrs.length +
      scope_rules.repos.length +
      scope_rules.containers.length;
    if (scopeCount === 0) {
      setStatus({
        kind: "error",
        message:
          "Add at least one entry to the scope (domain, URL, CIDR, repo, or container) — otherwise no scan can ever be in-scope.",
      });
      return;
    }
    const payload: ProjectCreate = {
      name: name.trim(),
      description: description.trim(),
      grantor: grantor.trim() || null,
      scope_rules,
    };
    setStatus({ kind: "saving" });
    try {
      const project = await createProject(payload);
      router.push(`/projects/${project.id}`);
      router.refresh();
    } catch (err) {
      setStatus({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }

  return (
    <form onSubmit={onSubmit} style={{ display: "grid", gap: 14 }}>
      <section className="panel">
        <div className="panelTitle"><h2>Project</h2></div>
        <div style={{ display: "grid", gap: 12 }}>
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ color: "#94a3b8", fontSize: 12 }}>Name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme FlightOps Production"
              style={{ background: "#0b1320", color: "#e8eef6", border: "1px solid #1f2937", borderRadius: 8, padding: "8px 10px", fontSize: 13 }}
            />
          </label>
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ color: "#94a3b8", fontSize: 12 }}>Description</span>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What is this project's surface area? What are we testing for?"
              rows={3}
              style={{ background: "#0b1320", color: "#e8eef6", border: "1px solid #1f2937", borderRadius: 8, padding: "8px 10px", fontSize: 13, fontFamily: "inherit" }}
            />
          </label>
          <label style={{ display: "grid", gap: 4 }}>
            <span style={{ color: "#94a3b8", fontSize: 12 }}>Authorization grantor (optional)</span>
            <input
              value={grantor}
              onChange={(e) => setGrantor(e.target.value)}
              placeholder="Who authorized this engagement? e.g. 'Acme Security Engineering'"
              style={{ background: "#0b1320", color: "#e8eef6", border: "1px solid #1f2937", borderRadius: 8, padding: "8px 10px", fontSize: 13 }}
            />
          </label>
        </div>
      </section>

      <section className="panel">
        <div className="panelTitle"><h2>Authorized scope</h2></div>
        <p style={{ color: "#94a3b8", fontSize: 13 }}>
          One entry per line. Every scan target is checked against these lists
          before any scanner runs.
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <ScopeField label="Domains" value={domains} onChange={setDomains} placeholder="example.com&#10;sub.example.com" />
          <ScopeField label="URLs" value={urls} onChange={setUrls} placeholder="https://example.com&#10;https://api.example.com" />
          <ScopeField label="CIDRs" value={cidrs} onChange={setCidrs} placeholder="10.0.0.0/24&#10;192.168.10.0/24" />
          <ScopeField label="Repos" value={repos} onChange={setRepos} placeholder="git://example/repo&#10;/path/to/local/repo" />
          <ScopeField label="Containers" value={containers} onChange={setContainers} placeholder="ghcr.io/example/image:latest" />
        </div>
        <div style={{ display: "flex", gap: 16, marginTop: 12, color: "#cbd5e1", fontSize: 13 }}>
          <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <input type="checkbox" checked={allowActive} onChange={(e) => setAllowActive(e.target.checked)} />
            Allow authorized active scans
          </label>
          <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <input type="checkbox" checked={allowLab} onChange={(e) => setAllowLab(e.target.checked)} />
            Allow lab-validation scans
          </label>
        </div>
      </section>

      {status.kind === "error" ? (
        <div style={{ background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.3)", color: "#fca5a5", padding: "8px 12px", borderRadius: 8, fontSize: 13 }}>
          {status.message}
        </div>
      ) : null}

      <div>
        <button type="submit" className="button" disabled={status.kind === "saving"}>
          <Sprout size={14} /> {status.kind === "saving" ? "Creating…" : "Create project"}
        </button>
      </div>
    </form>
  );
}

function ScopeField({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <label style={{ display: "grid", gap: 4 }}>
      <span style={{ color: "#94a3b8", fontSize: 12 }}>{label}</span>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        rows={4}
        style={{ background: "#0b1320", color: "#e8eef6", border: "1px solid #1f2937", borderRadius: 8, padding: "8px 10px", fontSize: 12, fontFamily: "monospace" }}
      />
    </label>
  );
}

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
    <form onSubmit={onSubmit} style={{ display: "grid", gap: "var(--space-3)" }}>
      <section className="panel">
        <div className="panelTitle"><h2>Project</h2></div>
        <div style={{ display: "grid", gap: "var(--space-3)" }}>
          <label className="formField">
            <span className="formLabel">Name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme FlightOps Production"
            />
          </label>
          <label className="formField">
            <span className="formLabel">Description</span>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What is this project's surface area? What are we testing for?"
              rows={3}
            />
          </label>
          <label className="formField">
            <span className="formLabel">Authorization grantor (optional)</span>
            <input
              value={grantor}
              onChange={(e) => setGrantor(e.target.value)}
              placeholder="Who authorized this engagement? e.g. 'Acme Security Engineering'"
            />
          </label>
        </div>
      </section>

      <section className="panel">
        <div className="panelTitle"><h2>Authorized scope</h2></div>
        <p className="muted">
          One entry per line. Every scan target is checked against these lists
          before any scanner runs.
        </p>
        <div className="formGrid2" style={{ marginTop: "var(--space-3)" }}>
          <ScopeField label="Domains" value={domains} onChange={setDomains} placeholder="example.com&#10;sub.example.com" />
          <ScopeField label="URLs" value={urls} onChange={setUrls} placeholder="https://example.com&#10;https://api.example.com" />
          <ScopeField label="CIDRs" value={cidrs} onChange={setCidrs} placeholder="10.0.0.0/24&#10;192.168.10.0/24" />
          <ScopeField label="Repos" value={repos} onChange={setRepos} placeholder="git://example/repo&#10;/path/to/local/repo" />
          <ScopeField label="Containers" value={containers} onChange={setContainers} placeholder="ghcr.io/example/image:latest" />
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--space-4)", marginTop: "var(--space-3)" }}>
          <label className="checkboxField">
            <input type="checkbox" checked={allowActive} onChange={(e) => setAllowActive(e.target.checked)} />
            <span>Allow authorized active scans</span>
          </label>
          <label className="checkboxField">
            <input type="checkbox" checked={allowLab} onChange={(e) => setAllowLab(e.target.checked)} />
            <span>Allow lab-validation scans</span>
          </label>
        </div>
      </section>

      {status.kind === "error" ? (
        <div className="banner danger">{status.message}</div>
      ) : null}

      <div>
        <button type="submit" disabled={status.kind === "saving"}>
          <Sprout size={14} /> {status.kind === "saving" ? "Creating…" : "Create project"}
        </button>
      </div>
    </form>
  );
}

function ScopeField({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <label className="formField">
      <span className="formLabel">{label}</span>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        rows={4}
        style={{ fontFamily: "var(--font-mono)", fontSize: "var(--text-sm)" }}
      />
    </label>
  );
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Evidence = {
  id: string;
  finding_id: string;
  scanner: string;
  summary: string;
  raw: Record<string, unknown>;
  captured_at: string;
  raw_output_path?: string | null;
  content_hash?: string | null;
  file_path?: string | null;
  is_demo_data?: boolean;
};

export type Finding = {
  id: string;
  project_id: string;
  asset_id: string;
  target_id?: string | null;
  scanner: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: number | "low" | "medium" | "high" | "confirmed";
  status: string;
  affected_asset?: string | null;
  affected_component?: string | null;
  impact: string;
  reproduction: string;
  false_positive_reasoning: string;
  recommendation: string;
  cwe?: string[];
  cve?: string[];
  owasp_mapping?: string[];
  related_finding_ids: string[];
  evidence: Evidence[];
  fingerprint_hash?: string | null;
  attack_tags?: string[];
  is_demo_data?: boolean;
};

export type Asset = {
  id: string;
  kind: string;
  name: string;
  address: string;
  exposure: string;
  criticality: string;
};

export type ScannerRun = {
  id: string;
  project_id: string;
  scanner: string;
  mode: string;
  status: string;
  target: string;
  message: string;
  started_at: string | null;
  finished_at: string | null;
  args?: string[];
  exit_code?: number | null;
  evidence_ids?: string[];
  is_demo_data?: boolean;
};

export type AttackPathNode = {
  id: string;
  label: string;
  kind: string;
  severity?: Severity;
  ref_id?: string | null;
};

export type AttackPathEdge = {
  source: string;
  target: string;
  label: string;
  kind?: string | null;
};

export type AttackPath = {
  id: string;
  project_id: string;
  title: string;
  summary: string;
  narrative?: string | null;
  risk_score: number;
  severity?: Severity | null;
  status?: string;
  confidence?: string;
  finding_ids: string[];
  evidence_refs?: string[];
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  remediation_order: string[];
  recommended_next_steps?: string[];
  safe_validation_needed?: string[];
  remediation_summary?: string | null;
  is_demo_data?: boolean;
};

export type AgentOutput = {
  agent: string;
  summary: string;
  confidence: "low" | "medium" | "high" | "confirmed";
  supporting_finding_ids: string[];
  cited_evidence_ids?: string[];
  recommended_next_steps: string[];
  limitations: string | null;
};

export type Project = {
  id: string;
  workspace_id: string;
  name: string;
  description: string;
  risk_score: number;
  targets: string[];
  is_demo_data?: boolean;
  scope_rules?: ScopeRules;
};

export type ScopeRules = {
  domains: string[];
  urls: string[];
  cidrs: string[];
  repos: string[];
  containers: string[];
  blocked_targets: string[];
  allow_active: boolean;
  allow_lab: boolean;
  max_requests_per_second: number;
  timeout_seconds: number;
};

export type DashboardSummary = {
  workspace: { id: string; name: string; created_at: string } | null;
  project: Project;
  assets: Asset[];
  findings: Finding[];
  scanner_runs: ScannerRun[];
  attack_paths: AttackPath[];
  agent_outputs: AgentOutput[];
  risk_trend: { date: string; score: number }[];
  fix_first: Finding[];
  is_demo_data?: boolean;
};

export type ToolDefinition = {
  id: string;
  name: string;
  pack: string;
  category: string;
  execution: "core_runner" | "optional_pack" | "reference" | "blocked" | "importer" | "analyzer";
  modes: string[];
  install_status: "bundled" | "available" | "not_installed" | "external" | "blocked";
  integration_status: "runner" | "parser" | "planned" | "reference" | "blocked" | "importer" | "analyzer";
  license: string;
  official_url: string;
  executable: string | null;
  installed: boolean;
  install_hint: string | null;
  input_types: string[];
  output_formats: string[];
  parser: string | null;
  safe_default: boolean;
  requires_authorized_scope: boolean;
  requires_lab_mode?: boolean;
  docker_available: boolean;
  supported_os: string[];
  recommended_use: string;
  risk_warning: string | null;
  risk_level?: "low" | "medium" | "high" | "restricted" | "blocked";
  tags?: string[];
};

export type ToolPackSummary = {
  name: string;
  total: number;
  core_runners: number;
  optional: number;
  reference: number;
  blocked: number;
  installed: number;
};

export type ArsenalSummary = {
  tools: ToolDefinition[];
  packs: string[];
  pack_summaries: ToolPackSummary[];
  blocked_policy: string[];
  blocked_capabilities?: string[];
};

export type AuditLog = {
  id: string;
  workspace_id?: string | null;
  actor: string;
  action: string;
  event_type?: string | null;
  target: string;
  result: string;
  decision?: "allow" | "block" | "info" | null;
  reason?: string | null;
  reason_code?: string | null;
  payload?: Record<string, unknown> | null;
  timestamp: string;
};

export type Report = {
  id: string;
  project_id: string;
  kind?: "markdown" | "json" | "pdf" | null;
  title: string;
  generated_at: string;
  sections: Record<string, unknown>;
  scope_statement?: string | null;
  authorization_statement?: string | null;
  safety_statement?: string | null;
  content_hash?: string | null;
  pdf_status?: string;
  is_demo_data?: boolean;
};

export type BlockedCapabilities = {
  capabilities: { id: string; label: string; rationale: string }[];
  explanation: string;
};

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Asura API ${path} returned ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export async function getDashboard(projectId: string = "demo"): Promise<DashboardSummary> {
  return getJson<DashboardSummary>(`/api/dashboard/${projectId}`);
}

export async function getArsenal(): Promise<ArsenalSummary> {
  return getJson<ArsenalSummary>(`/api/arsenal`);
}

export async function getProjects(): Promise<Project[]> {
  return getJson<Project[]>(`/api/projects`);
}

export async function getProject(id: string): Promise<Project> {
  return getJson<Project>(`/api/projects/${id}`);
}

export async function getFindings(params: { project_id?: string; severity?: string; status?: string; demo?: boolean } = {}): Promise<Finding[]> {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    search.set(key, String(value));
  }
  const query = search.toString();
  return getJson<Finding[]>(`/api/findings${query ? `?${query}` : ""}`);
}

export async function getFinding(id: string): Promise<Finding> {
  return getJson<Finding>(`/api/findings/${id}`);
}

export async function getAttackPaths(projectId: string = "demo"): Promise<AttackPath[]> {
  return getJson<AttackPath[]>(`/api/attack-paths?project_id=${projectId}`);
}

export async function getAttackPath(id: string): Promise<AttackPath> {
  return getJson<AttackPath>(`/api/attack-paths/${id}`);
}

export async function getScans(projectId: string = "demo"): Promise<ScannerRun[]> {
  return getJson<ScannerRun[]>(`/api/scans?project_id=${projectId}`);
}

export async function getScan(id: string): Promise<ScannerRun> {
  return getJson<ScannerRun>(`/api/scans/${id}`);
}

export async function getAudit(limit: number = 50): Promise<AuditLog[]> {
  return getJson<AuditLog[]>(`/api/audit?limit=${limit}`);
}

export async function getBlockedCapabilities(): Promise<BlockedCapabilities> {
  return getJson<BlockedCapabilities>(`/api/safety/blocked`);
}

export function reportUrl(projectId: string) {
  return `${API_URL}/api/reports/${projectId}/markdown`;
}

export function jsonReportUrl(projectId: string) {
  return `${API_URL}/api/reports/${projectId}/json`;
}

export const ASURA_API_URL = API_URL;

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
  findings_created?: number;
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

// ---------------------------------------------------------------------------
// LLM-assisted triage
// ---------------------------------------------------------------------------

export type TriageCluster = {
  id: string;
  title: string;
  summary: string;
  reasoning: string;
  finding_ids: string[];
  cited_evidence_ids: string[];
  severity: Severity;
  confidence: "low" | "medium" | "high" | "confirmed";
  fix_recommendation?: string | null;
};

export type FalsePositiveCandidate = {
  finding_id: string;
  reasoning: string;
  confidence: "low" | "medium" | "high" | "confirmed";
  cited_evidence_ids: string[];
};

export type TriagePriorityItem = {
  finding_id: string;
  rank: number;
  reasoning: string;
  cited_evidence_ids: string[];
};

export type TriageReport = {
  project_id: string;
  engine: "deterministic" | "llm";
  model?: string | null;
  summary: string;
  clusters: TriageCluster[];
  false_positive_candidates: FalsePositiveCandidate[];
  priority_order: TriagePriorityItem[];
  findings_considered: number;
  claims_dropped: number;
  generated_at: string;
};

export async function getTriage(projectId: string, limit?: number): Promise<TriageReport> {
  const q = limit ? `?limit=${limit}` : "";
  return getJson<TriageReport>(`/api/projects/${projectId}/triage${q}`);
}

// ---------------------------------------------------------------------------
// LLM settings (Fernet-encrypted; api key is write-only, never returned raw)
// ---------------------------------------------------------------------------

export type LLMSettings = {
  enabled: boolean;
  provider: "anthropic";
  model: string;
  api_key_preview?: string | null;
  api_key_configured: boolean;
  updated_at?: string | null;
};

export type LLMSettingsUpdate = {
  enabled: boolean;
  model: string;
  api_key?: string | null;
};

export async function getLLMSettings(): Promise<LLMSettings> {
  return getJson<LLMSettings>(`/api/settings/llm`);
}

export async function updateLLMSettings(payload: LLMSettingsUpdate): Promise<LLMSettings> {
  const res = await fetch(`${API_URL}/api/settings/llm`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`PUT /api/settings/llm failed: ${res.status} ${await res.text()}`);
  }
  return (await res.json()) as LLMSettings;
}

export async function deleteLLMSettings(): Promise<void> {
  const res = await fetch(`${API_URL}/api/settings/llm`, {
    method: "DELETE",
    cache: "no-store",
  });
  if (!res.ok && res.status !== 404) {
    throw new Error(`DELETE /api/settings/llm failed: ${res.status} ${await res.text()}`);
  }
}

// ---------------------------------------------------------------------------
// HAR (HTTP Archive) import — Burp / mitmproxy / DevTools captures
// ---------------------------------------------------------------------------

export type HarEndpoint = {
  method: string;
  host: string;
  path: string;
  sample_url: string;
  status_codes: number[];
  param_names: string[];
  seen_count: number;
};

export type HarImportSummary = {
  project_id: string;
  entries_processed: number;
  hosts: string[];
  endpoints: HarEndpoint[];
  js_files: string[];
  auth_required_paths: string[];
  status_buckets: Record<string, number>;
  skipped: string[];
  new_targets: Target[];
  respect_scope: boolean;
};

export async function importHar(
  projectId: string,
  file: File,
  options: { respectScope?: boolean } = {},
): Promise<HarImportSummary> {
  const form = new FormData();
  form.append("file", file);
  const qs = options.respectScope ? "?respect_scope=true" : "";
  const res = await fetch(`${API_URL}/api/projects/${projectId}/imports/har${qs}`, {
    method: "POST",
    body: form,
    cache: "no-store",
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(detail || `POST /api/projects/${projectId}/imports/har failed: ${res.status}`);
  }
  return (await res.json()) as HarImportSummary;
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

// ---- Global search ----

export type SearchResultKind = "project" | "finding" | "tool" | "scan" | "attack_path";

export type SearchResult = {
  kind: SearchResultKind;
  id: string;
  title: string;
  subtitle?: string | null;
  href: string;
  badge?: string | null;
};

export type SearchResponse = {
  query: string;
  results: SearchResult[];
};

export async function searchAll(q: string, signal?: AbortSignal): Promise<SearchResponse> {
  if (!q.trim()) return { query: q, results: [] };
  const response = await fetch(
    `${API_URL}/api/search?q=${encodeURIComponent(q)}&limit=30`,
    { cache: "no-store", signal },
  );
  if (!response.ok) {
    throw new Error(`GET /api/search returned ${response.status}`);
  }
  return response.json();
}

export type StartScanRequest = {
  project_id: string;
  target: string;
  scanners: string[];
  mode: "passive" | "active" | "lab";
  authorized_scope?: string | null;
  explicit_authorization?: boolean;
  confirm_high_noise?: boolean;
  template_ids?: string[];
  // Filesystem path to a wordlist (used by ffuf / gobuster / dirsearch).
  wordlist?: string | null;
  // Cloud provider for prowler / scoutsuite (e.g. "aws", "azure", "gcp").
  provider?: string | null;
  // Optional AuthProfile id; the runner injects the appropriate `-H` flags
  // for scanners that accept them (currently nuclei + httpx).
  auth_profile_id?: string | null;
};

export async function startScan(payload: StartScanRequest): Promise<ScannerRun[]> {
  const response = await fetch(`${API_URL}/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `POST /api/scans returned ${response.status}`);
  }
  return response.json();
}

// ---- Project + scope + target mutations ----

export type ProjectCreate = {
  name: string;
  description?: string;
  workspace_id?: string;
  scope_rules: ScopeRules;
  grantor?: string | null;
  risk_score?: number;
};

export type ProjectUpdate = {
  name?: string;
  description?: string;
  scope_rules?: ScopeRules;
  risk_score?: number;
};

export type TargetCreate = {
  kind: "host" | "repo" | "url" | "domain" | "ip" | "cidr" | "container" | "api_spec";
  value: string;
  authorized?: boolean;
  lab_mode_enabled?: boolean;
  owned_internal?: boolean;
  notes?: string | null;
};

export type Target = {
  id: string;
  project_id: string;
  kind: string;
  value: string;
  authorized: boolean;
  lab_mode_enabled: boolean;
  owned_internal: boolean;
  notes?: string | null;
  is_demo_data?: boolean;
};

export async function createProject(payload: ProjectCreate): Promise<Project> {
  const response = await fetch(`${API_URL}/api/projects`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `POST /api/projects returned ${response.status}`);
  }
  return response.json();
}

export async function updateProject(id: string, payload: ProjectUpdate): Promise<Project> {
  const response = await fetch(`${API_URL}/api/projects/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `PATCH /api/projects/${id} returned ${response.status}`);
  }
  return response.json();
}

export async function deleteProject(id: string): Promise<void> {
  const response = await fetch(`${API_URL}/api/projects/${id}`, {
    method: "DELETE",
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `DELETE /api/projects/${id} returned ${response.status}`);
  }
}

export async function getTargets(projectId: string): Promise<Target[]> {
  return getJson<Target[]>(`/api/projects/${projectId}/targets`);
}

export async function addTarget(projectId: string, payload: TargetCreate): Promise<Target> {
  const response = await fetch(`${API_URL}/api/projects/${projectId}/targets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `POST /api/projects/${projectId}/targets returned ${response.status}`);
  }
  return response.json();
}

export async function deleteTarget(projectId: string, targetId: string): Promise<void> {
  const response = await fetch(`${API_URL}/api/projects/${projectId}/targets/${targetId}`, {
    method: "DELETE",
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `DELETE returned ${response.status}`);
  }
}

export function reportUrl(projectId: string) {
  return `${API_URL}/api/reports/${projectId}/markdown`;
}

export function jsonReportUrl(projectId: string) {
  return `${API_URL}/api/reports/${projectId}/json`;
}

export function sarifUrl(projectId: string) {
  return `${API_URL}/api/projects/${projectId}/findings.sarif`;
}

export type SarifImportSummary = {
  project_id: string;
  runs_processed: number;
  results_processed: number;
  findings_created: number;
  findings_updated: number;
  tool_drivers: string[];
  skipped: string[];
};

export async function importSarif(projectId: string, body: Blob | string): Promise<SarifImportSummary> {
  const response = await fetch(`${API_URL}/api/projects/${projectId}/imports/sarif`, {
    method: "POST",
    headers: { "Content-Type": "application/sarif+json" },
    body,
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `POST returned ${response.status}`);
  }
  return response.json();
}

// ---- Jobs + pipelines (Round A) ----

export type JobStatus = "queued" | "running" | "completed" | "failed" | "blocked" | "partial";

export type ScanJob = {
  id: string;
  project_id: string;
  kind: "scan" | "pipeline";
  pipeline_id?: string | null;
  status: JobStatus;
  scan_request?: Record<string, unknown> | null;
  run_ids: string[];
  findings_created: number;
  error?: string | null;
  progress_text?: string | null;
  progress_percent: number;
  backend: "inline_thread" | "rq";
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  is_demo_data?: boolean;
};

export type AsyncScanResponse = {
  job_id: string;
  status: JobStatus;
  backend: "inline_thread" | "rq";
  poll_url: string;
  message?: string | null;
};

export type PipelineStage = {
  name: string;
  scanner: string;
  mode: "passive" | "active" | "lab";
  input_source: "target" | "previous_assets";
  max_followups: number;
  description?: string | null;
};

export type Pipeline = {
  id: string;
  name: string;
  description: string;
  stages: PipelineStage[];
  requires_authorized_scope: boolean;
  risk_level: "low" | "medium" | "high";
  tags: string[];
};

export type PipelineRunRequest = {
  project_id: string;
  pipeline_id: string;
  target: string;
  authorized_scope?: string | null;
  explicit_authorization?: boolean;
  confirm_high_noise?: boolean;
};

export async function startScanAsync(payload: StartScanRequest): Promise<AsyncScanResponse> {
  const response = await fetch(`${API_URL}/api/scans/async`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `POST /api/scans/async returned ${response.status}`);
  }
  return response.json();
}

export async function getJob(id: string): Promise<ScanJob> {
  return getJson<ScanJob>(`/api/jobs/${id}`);
}

export async function listJobs(projectId?: string): Promise<ScanJob[]> {
  const search = new URLSearchParams();
  if (projectId) search.set("project_id", projectId);
  const query = search.toString();
  return getJson<ScanJob[]>(`/api/jobs${query ? `?${query}` : ""}`);
}

export async function listPipelines(): Promise<Pipeline[]> {
  return getJson<Pipeline[]>(`/api/pipelines`);
}

export async function runPipeline(payload: PipelineRunRequest): Promise<AsyncScanResponse> {
  const response = await fetch(`${API_URL}/api/pipelines/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `POST /api/pipelines/run returned ${response.status}`);
  }
  return response.json();
}

// ---- Auth profiles (credentials injected as -H flags) ----

export type AuthType = "bearer" | "basic" | "header" | "cookie";

export type AuthProfile = {
  id: string;
  name: string;
  workspace_id: string;
  auth_type: AuthType;
  target_match?: string | null;
  description?: string | null;
  credential_preview: string;
  created_at: string;
  is_demo_data?: boolean;
};

export type AuthProfileCreate = {
  name: string;
  auth_type: AuthType;
  target_match?: string | null;
  description?: string | null;
  token?: string | null;       // bearer
  username?: string | null;    // basic
  password?: string | null;    // basic
  header_name?: string | null; // header
  header_value?: string | null; // header
  cookie?: string | null;      // cookie
};

export async function listAuthProfiles(): Promise<AuthProfile[]> {
  return getJson<AuthProfile[]>(`/api/auth-profiles`);
}

export async function createAuthProfile(payload: AuthProfileCreate): Promise<AuthProfile> {
  const response = await fetch(`${API_URL}/api/auth-profiles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `POST /api/auth-profiles returned ${response.status}`);
  }
  return response.json();
}

export async function deleteAuthProfile(id: string): Promise<void> {
  const response = await fetch(`${API_URL}/api/auth-profiles/${id}`, {
    method: "DELETE",
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `DELETE returned ${response.status}`);
  }
}

// ---- Custom Nuclei templates ----

export type NucleiTemplate = {
  id: string;
  workspace_id: string;
  filename: string;
  display_name: string;
  description?: string | null;
  tags: string[];
  template_id?: string | null;
  severity?: string | null;
  info_name?: string | null;
  size_bytes: number;
  content_hash: string;
  uploaded_at: string;
  is_demo_data?: boolean;
};

export async function listTemplates(): Promise<NucleiTemplate[]> {
  return getJson<NucleiTemplate[]>(`/api/templates`);
}

export async function uploadTemplate(
  file: File,
  meta?: { description?: string; tags?: string },
): Promise<NucleiTemplate> {
  const body = new FormData();
  body.append("file", file);
  if (meta?.description) body.append("description", meta.description);
  if (meta?.tags) body.append("tags", meta.tags);
  const response = await fetch(`${API_URL}/api/templates`, {
    method: "POST",
    body,
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `POST /api/templates returned ${response.status}`);
  }
  return response.json();
}

export async function deleteTemplate(id: string): Promise<void> {
  const response = await fetch(`${API_URL}/api/templates/${id}`, {
    method: "DELETE",
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `DELETE /api/templates/${id} returned ${response.status}`);
  }
}

export function templateContentUrl(id: string): string {
  return `${API_URL}/api/templates/${id}/content`;
}

export const ASURA_API_URL = API_URL;

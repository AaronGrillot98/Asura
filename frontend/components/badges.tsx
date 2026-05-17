import type { Severity } from "@/lib/api";

const severityBg: Record<Severity, string> = {
  critical: "rgba(239,68,68,0.18)",
  high: "rgba(249,115,22,0.18)",
  medium: "rgba(234,179,8,0.18)",
  low: "rgba(34,197,94,0.18)",
  info: "rgba(96,165,250,0.18)",
};
const severityFg: Record<Severity, string> = {
  critical: "#fca5a5",
  high: "#fdba74",
  medium: "#fde68a",
  low: "#86efac",
  info: "#93c5fd",
};

function chip(bg: string, fg: string) {
  return {
    display: "inline-flex",
    alignItems: "center",
    gap: 4,
    background: bg,
    color: fg,
    padding: "2px 8px",
    borderRadius: 999,
    fontSize: 11,
    fontWeight: 600,
    textTransform: "uppercase" as const,
    letterSpacing: 0.4,
  };
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span style={chip(severityBg[severity], severityFg[severity])}>{severity}</span>;
}

const confidenceColors: Record<string, [string, string]> = {
  low: ["rgba(148,163,184,0.18)", "#cbd5e1"],
  medium: ["rgba(96,165,250,0.18)", "#93c5fd"],
  high: ["rgba(34,197,94,0.18)", "#86efac"],
  confirmed: ["rgba(34,197,94,0.28)", "#bbf7d0"],
};

export function ConfidenceBadge({ confidence }: { confidence: number | string }) {
  let label: keyof typeof confidenceColors = "medium";
  if (typeof confidence === "number") {
    label = confidence >= 95 ? "confirmed" : confidence >= 80 ? "high" : confidence >= 60 ? "medium" : "low";
  } else if (confidence in confidenceColors) {
    label = confidence as keyof typeof confidenceColors;
  }
  const [bg, fg] = confidenceColors[label];
  return <span style={chip(bg, fg)}>{typeof confidence === "number" ? `${confidence}%` : confidence}</span>;
}

export function ModeBadge({ mode }: { mode: string }) {
  const [bg, fg] = mode === "lab"
    ? ["rgba(168,85,247,0.18)", "#d8b4fe"]
    : mode === "active"
    ? ["rgba(249,115,22,0.18)", "#fdba74"]
    : ["rgba(96,165,250,0.18)", "#93c5fd"];
  return <span style={chip(bg, fg)}>{mode}</span>;
}

export function RiskBadge({ risk }: { risk?: string | null }) {
  if (!risk) return null;
  const map: Record<string, [string, string]> = {
    low: ["rgba(34,197,94,0.18)", "#86efac"],
    medium: ["rgba(234,179,8,0.18)", "#fde68a"],
    high: ["rgba(249,115,22,0.18)", "#fdba74"],
    restricted: ["rgba(239,68,68,0.22)", "#fca5a5"],
    blocked: ["rgba(127,29,29,0.32)", "#fecaca"],
  };
  const [bg, fg] = map[risk] ?? map.low;
  return <span style={chip(bg, fg)}>{risk}</span>;
}

export function DemoBadge({ demo }: { demo?: boolean }) {
  if (!demo) return null;
  return <span style={chip("rgba(245,158,11,0.18)", "#fcd34d")}>demo</span>;
}

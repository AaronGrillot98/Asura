"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import {
  Activity,
  Boxes,
  FileCode,
  FileText,
  GitBranch,
  Home,
  KeyRound,
  Layers,
  Menu,
  Package,
  Radar,
  ScrollText,
  ShieldCheck,
  Sparkles,
  Workflow,
} from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";
import { GlobalSearch, GlobalSearchTrigger } from "@/components/global-search";
import { BackendHealth } from "@/components/backend-health";

type NavEntry = {
  href: string;
  label: string;
  icon: ReactNode;
};

type NavSection = {
  label: string;
  entries: NavEntry[];
};

const NAV: NavSection[] = [
  {
    label: "Workspace",
    entries: [
      { href: "/", label: "Command Center", icon: <Home size={16} /> },
      { href: "/projects", label: "Projects", icon: <Boxes size={16} /> },
    ],
  },
  {
    label: "Operations",
    entries: [
      { href: "/scans", label: "Scanner Runs", icon: <Activity size={16} /> },
      { href: "/jobs", label: "Background Jobs", icon: <Layers size={16} /> },
      { href: "/pipelines", label: "Pipelines", icon: <Workflow size={16} /> },
      { href: "/findings", label: "Findings", icon: <ShieldCheck size={16} /> },
      { href: "/attack-paths", label: "Attack Paths", icon: <GitBranch size={16} /> },
      { href: "/reports", label: "Reports", icon: <FileText size={16} /> },
    ],
  },
  {
    label: "Settings",
    entries: [
      { href: "/arsenal", label: "Arsenal", icon: <Package size={16} /> },
      { href: "/templates", label: "Nuclei Templates", icon: <FileCode size={16} /> },
      { href: "/auth-profiles", label: "Auth Profiles", icon: <KeyRound size={16} /> },
      { href: "/settings/llm", label: "LLM Triage", icon: <Sparkles size={16} /> },
      { href: "/audit", label: "Audit Log", icon: <ScrollText size={16} /> },
      { href: "/safety", label: "Safety Model", icon: <Radar size={16} /> },
    ],
  },
];

function isActive(pathname: string, href: string): boolean {
  if (href === "/") return pathname === "/";
  return pathname.startsWith(href);
}

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname() ?? "/";
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Close the mobile drawer on navigation.
  useEffect(() => {
    setSidebarOpen(false);
  }, [pathname]);

  // Lock body scroll while the drawer is open on mobile.
  useEffect(() => {
    if (typeof document === "undefined") return;
    const original = document.body.style.overflow;
    document.body.style.overflow = sidebarOpen ? "hidden" : original;
    return () => {
      document.body.style.overflow = original;
    };
  }, [sidebarOpen]);

  return (
    <div className="shell" data-sidebar-open={sidebarOpen ? "true" : "false"}>
      <a href="#main" className="skipLink">Skip to main content</a>
      <button
        type="button"
        className="sidebarOverlay"
        aria-label="Close navigation"
        aria-hidden={!sidebarOpen}
        tabIndex={sidebarOpen ? 0 : -1}
        onClick={() => setSidebarOpen(false)}
      />
      <aside id="sidebar" className="sidebar">
        <div className="brand">
          <div className="mark">A</div>
          <div>
            <strong>Asura</strong>
            <span>Security command center</span>
          </div>
        </div>
        <GlobalSearchTrigger />
        <nav>
          {NAV.map((section) => (
            <div key={section.label} className="navSectionGroup">
              <div className="navSection">{section.label}</div>
              {section.entries.map((entry) => (
                <Link
                  key={entry.href}
                  href={entry.href}
                  className={isActive(pathname, entry.href) ? "active" : undefined}
                >
                  <span className="navIcon">{entry.icon}</span>
                  {entry.label}
                </Link>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebarFooter">
          <BackendHealth />
          <ThemeToggle />
        </div>
      </aside>
      <main id="main" className="content">
        <button
          type="button"
          className="sidebarToggle"
          aria-label="Open navigation"
          aria-expanded={sidebarOpen}
          aria-controls="sidebar"
          onClick={() => setSidebarOpen((v) => !v)}
        >
          <Menu size={18} />
        </button>
        {children}
      </main>
      <GlobalSearch />
    </div>
  );
}

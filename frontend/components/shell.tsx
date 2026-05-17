"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import {
  Activity,
  Boxes,
  FileText,
  GitBranch,
  Home,
  Package,
  Radar,
  ScrollText,
  ShieldCheck,
} from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";

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
      { href: "/findings", label: "Findings", icon: <ShieldCheck size={16} /> },
      { href: "/attack-paths", label: "Attack Paths", icon: <GitBranch size={16} /> },
      { href: "/reports", label: "Reports", icon: <FileText size={16} /> },
    ],
  },
  {
    label: "Settings",
    entries: [
      { href: "/arsenal", label: "Arsenal", icon: <Package size={16} /> },
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
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="mark">A</div>
          <div>
            <strong>Asura</strong>
            <span>Security command center</span>
          </div>
        </div>
        <nav>
          {NAV.map((section) => (
            <div key={section.label} style={{ display: "flex", flexDirection: "column", gap: 2 }}>
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
        <div style={{ marginTop: "auto", display: "flex", alignItems: "center", justifyContent: "space-between", paddingTop: 16, borderTop: "1px solid var(--border-1)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700 }}>
            <span className="statusDot ok" /> System
          </div>
          <ThemeToggle />
        </div>
      </aside>
      <main className="content">{children}</main>
    </div>
  );
}

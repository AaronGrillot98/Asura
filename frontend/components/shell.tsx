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

type NavEntry = {
  href: string;
  label: string;
  icon: ReactNode;
};

const NAV: NavEntry[] = [
  { href: "/", label: "Command Center", icon: <Home size={16} /> },
  { href: "/projects", label: "Projects", icon: <Boxes size={16} /> },
  { href: "/scans", label: "Scanner Runs", icon: <Activity size={16} /> },
  { href: "/findings", label: "Findings", icon: <ShieldCheck size={16} /> },
  { href: "/attack-paths", label: "Attack Paths", icon: <GitBranch size={16} /> },
  { href: "/arsenal", label: "Arsenal", icon: <Package size={16} /> },
  { href: "/reports", label: "Reports", icon: <FileText size={16} /> },
  { href: "/audit", label: "Audit Log", icon: <ScrollText size={16} /> },
  { href: "/safety", label: "Safety Model", icon: <Radar size={16} /> },
];

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname() ?? "/";
  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="mark">A</div>
          <div>
            <strong>Asura</strong>
            <span>Security command center</span>
          </div>
        </div>
        <nav>
          {NAV.map((entry) => {
            const active = entry.href === "/" ? pathname === "/" : pathname.startsWith(entry.href);
            return (
              <Link key={entry.href} href={entry.href} className={active ? "active" : undefined}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                  {entry.icon}
                  {entry.label}
                </span>
              </Link>
            );
          })}
        </nav>
      </aside>
      <section className="content">{children}</section>
    </main>
  );
}

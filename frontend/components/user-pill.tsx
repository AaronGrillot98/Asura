"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { LogIn, LogOut, User } from "lucide-react";
import { useAuth } from "@/components/auth-provider";

export function UserPill() {
  const { user, ready, logout } = useAuth();
  const router = useRouter();

  if (!ready) {
    return (
      <div className="userPill skeleton" aria-busy="true">
        <div className="iconTile muted"><User size={16} /></div>
        <span className="userPillName">…</span>
      </div>
    );
  }

  if (!user) {
    return (
      <Link href="/login" className="userPill">
        <div className="iconTile accent"><LogIn size={16} /></div>
        <div className="userPillText">
          <span className="userPillName">Sign in</span>
          <small>Manage account</small>
        </div>
      </Link>
    );
  }

  const initials = user.display_name
    .split(/\s+/)
    .map((p) => p[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase() || "?";

  async function onLogout() {
    await logout();
    router.push("/login");
  }

  return (
    <div className="userPill">
      <div className="userInitials" aria-hidden="true">{initials}</div>
      <div className="userPillText">
        <span className="userPillName">{user.display_name}</span>
        <small>{user.email}</small>
      </div>
      <button
        type="button"
        className="iconButton"
        onClick={onLogout}
        aria-label="Sign out"
        title="Sign out"
      >
        <LogOut size={14} />
      </button>
    </div>
  );
}

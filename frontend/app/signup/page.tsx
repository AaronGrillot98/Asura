"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Sparkles } from "lucide-react";
import { useAuth } from "@/components/auth-provider";

export default function SignupPage() {
  const router = useRouter();
  const { register, pending } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [workspaceName, setWorkspaceName] = useState("My Workspace");
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    try {
      await register(email, password, displayName, workspaceName);
      router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Signup failed.");
    }
  }

  return (
    <div className="authCard">
      <div className="authMark"><Sparkles size={28} /></div>
      <h1>Create the founding workspace</h1>
      <p>The first user becomes the owner. Subsequent members join by invitation.</p>
      <form onSubmit={onSubmit} className="authForm">
        <label>
          <span>Display name</span>
          <input
            type="text"
            autoComplete="name"
            required
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </label>
        <label>
          <span>Email</span>
          <input
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
        <label>
          <span>Password</span>
          <input
            type="password"
            autoComplete="new-password"
            minLength={8}
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <label>
          <span>Workspace name</span>
          <input
            type="text"
            required
            value={workspaceName}
            onChange={(e) => setWorkspaceName(e.target.value)}
          />
        </label>
        {error ? <div className="authError">{error}</div> : null}
        <button type="submit" disabled={pending}>
          {pending ? "Creating…" : "Create workspace"}
        </button>
      </form>
      <div className="authFooter">
        <span>Already have an account? <Link href="/login">Sign in</Link></span>
      </div>
    </div>
  );
}

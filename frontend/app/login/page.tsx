"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Sparkles } from "lucide-react";
import { useAuth } from "@/components/auth-provider";

export default function LoginPage() {
  const router = useRouter();
  const { login, pending } = useAuth();
  const [email, setEmail] = useState("owner@asura.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    try {
      await login(email, password);
      router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed.");
    }
  }

  return (
    <div className="authCard">
      <div className="authMark"><Sparkles size={28} /></div>
      <h1>Sign in to Asura</h1>
      <p>Security orchestration for the rest of your stack.</p>
      <form onSubmit={onSubmit} className="authForm">
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
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error ? <div className="authError">{error}</div> : null}
        <button type="submit" disabled={pending}>
          {pending ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <div className="authFooter">
        <span>New to Asura? <Link href="/signup">Create the first workspace</Link></span>
        <Link href="/auth/sso/oidc/start" className="muted">Sign in with SSO →</Link>
      </div>
      <small className="authHint">
        Demo credentials: <code className="inlineCode">owner@asura.local</code> / <code className="inlineCode">asura</code>
      </small>
    </div>
  );
}

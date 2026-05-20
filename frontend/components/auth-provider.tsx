"use client";

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import {
  type AuthUser,
  clearToken,
  fetchCurrentUser,
  login as apiLogin,
  logout as apiLogout,
  register as apiRegister,
} from "@/lib/auth";

type AuthContextValue = {
  user: AuthUser | null;
  ready: boolean;       // true once the initial /auth/me probe has settled
  pending: boolean;     // an in-flight login/register/logout call
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, displayName: string, workspaceName?: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [ready, setReady] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const u = await fetchCurrentUser();
      setUser(u);
    } catch {
      setUser(null);
    } finally {
      setReady(true);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const login = useCallback(async (email: string, password: string) => {
    setPending(true);
    setError(null);
    try {
      const result = await apiLogin(email, password);
      setUser(result.user);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Login failed.";
      setError(msg);
      throw e;
    } finally {
      setPending(false);
    }
  }, []);

  const register = useCallback(
    async (email: string, password: string, displayName: string, workspaceName?: string) => {
      setPending(true);
      setError(null);
      try {
        const result = await apiRegister(email, password, displayName, workspaceName);
        setUser(result.user);
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Register failed.";
        setError(msg);
        throw e;
      } finally {
        setPending(false);
      }
    },
    [],
  );

  const logout = useCallback(async () => {
    setPending(true);
    try {
      await apiLogout();
    } finally {
      clearToken();
      setUser(null);
      setPending(false);
    }
  }, []);

  return (
    <AuthContext.Provider value={{ user, ready, pending, error, login, register, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    // No provider — return a safe no-op so isolated render trees don't crash.
    return {
      user: null, ready: true, pending: false, error: null,
      login: async () => {}, register: async () => {},
      logout: async () => {}, refresh: async () => {},
    };
  }
  return ctx;
}

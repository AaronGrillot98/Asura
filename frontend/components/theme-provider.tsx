"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";

export type Theme = "dark" | "light" | "neon";
const THEME_CYCLE: Theme[] = ["dark", "light", "neon"];
const STORAGE_KEY = "asura-theme";

type ThemeContextValue = {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggle: () => void;
};

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

function readInitial(): Theme {
  if (typeof window === "undefined") return "dark";
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "dark" || stored === "light" || stored === "neon") return stored;
    const attr = document.documentElement.getAttribute("data-theme");
    if (attr === "light" || attr === "neon") return attr;
    return "dark";
  } catch {
    return "dark";
  }
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  // Default to "dark" on first render so SSR markup matches the inline script's
  // initial attribute. The useEffect below reconciles to the real preference.
  const [theme, setThemeState] = useState<Theme>("dark");

  useEffect(() => {
    setThemeState(readInitial());
  }, []);

  useEffect(() => {
    if (typeof document === "undefined") return;
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Ignore storage errors (private mode, etc.).
    }
  }, [theme]);

  const setTheme = useCallback((next: Theme) => setThemeState(next), []);
  const toggle = useCallback(
    () =>
      setThemeState((cur) => {
        const idx = THEME_CYCLE.indexOf(cur);
        return THEME_CYCLE[(idx + 1) % THEME_CYCLE.length];
      }),
    []
  );

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    // Outside the provider — return a safe no-op so isolated stories don't crash.
    return { theme: "dark", setTheme: () => {}, toggle: () => {} };
  }
  return ctx;
}

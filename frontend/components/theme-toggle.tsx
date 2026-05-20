"use client";

import { Moon, Sun, Zap } from "lucide-react";
import { useTheme } from "@/components/theme-provider";

const NEXT_LABEL: Record<string, string> = {
  dark: "Switch to light theme",
  light: "Switch to neon theme",
  neon: "Switch to dark theme",
};

export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const label = NEXT_LABEL[theme] ?? "Cycle theme";
  return (
    <button
      type="button"
      className="iconButton"
      onClick={toggle}
      aria-label={label}
      title={label}
    >
      {theme === "dark" ? <Sun size={16} /> : theme === "light" ? <Zap size={16} /> : <Moon size={16} />}
    </button>
  );
}

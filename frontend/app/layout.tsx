import type { Metadata } from "next";
import "./globals.css";
import { Shell } from "@/components/shell";
import { ThemeProvider } from "@/components/theme-provider";

export const metadata: Metadata = {
  title: "Asura",
  description: "Self-hosted AI security orchestration command center",
};

// Runs synchronously before React hydrates so the data-theme attribute is on
// <html> for the first paint — no flash of unstyled content.
const themeBoot = `
(function () {
  try {
    var stored = localStorage.getItem("asura-theme");
    var theme = stored === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", theme);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "dark");
  }
})();
`;

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" data-theme="dark">
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBoot }} />
      </head>
      <body>
        <ThemeProvider>
          <Shell>{children}</Shell>
        </ThemeProvider>
      </body>
    </html>
  );
}

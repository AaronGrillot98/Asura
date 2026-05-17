"use client";

/**
 * Last-resort error boundary. Covers errors that escape `app/error.tsx`
 * (root layout / ThemeProvider / Shell crashes). Has to render its own
 * <html><body> because the root layout is what failed.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en" data-theme="dark">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          fontFamily:
            "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
          background: "#0b1016",
          color: "#e8eef6",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "32px 24px",
        }}
      >
        <div
          style={{
            maxWidth: 640,
            width: "100%",
            background: "#111923",
            border: "1px solid #283851",
            borderRadius: 14,
            padding: 24,
            display: "flex",
            flexDirection: "column",
            gap: 14,
          }}
        >
          <div>
            <div style={{ color: "#94a3b8", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.12em", fontWeight: 700 }}>
              Asura — fatal error
            </div>
            <h1 style={{ margin: "8px 0 0", fontSize: 24, fontWeight: 700 }}>
              The application failed to load.
            </h1>
          </div>
          <p style={{ color: "#94a3b8", margin: 0 }}>
            This usually means the root layout, theme provider, or shell
            crashed. The full error message is below.
          </p>
          <pre
            style={{
              background: "#080d12",
              border: "1px solid #1f2937",
              borderRadius: 10,
              padding: 12,
              fontSize: 12,
              color: "#cbd5e1",
              whiteSpace: "pre-wrap",
              overflow: "auto",
              fontFamily: "Consolas, Menlo, monospace",
            }}
          >
{error.name}: {error.message}
          </pre>
          {error.digest ? (
            <small style={{ color: "#94a3b8" }}>digest: {error.digest}</small>
          ) : null}
          <div>
            <button
              type="button"
              onClick={reset}
              style={{
                background: "#60a5fa",
                color: "#0a1320",
                border: 0,
                borderRadius: 10,
                cursor: "pointer",
                fontSize: 14,
                fontWeight: 600,
                padding: "10px 16px",
              }}
            >
              Try again
            </button>
          </div>
        </div>
      </body>
    </html>
  );
}

import type { ReactNode } from "react";
import Link from "next/link";

/**
 * UI primitives shared across pages. Tokens-only — never inline colors.
 *
 * Components:
 *  - StatusDot           Semantic dot indicator (ok / warn / danger / info / muted)
 *  - SectionHeader       Title + count + actions row used above card grids
 *  - Card                Container with hover affordance + optional footer
 *  - MetricCard          Stat tile for dashboards
 *  - EmptyState          Centred empty-state with optional CTA
 *  - Pill                Small rounded label (used by the topbar workspace pill, etc.)
 *  - Skeleton            Animated placeholder shown while async data loads
 *  - StatusBanner        Inline status / error message with the right
 *                        ARIA live-region semantics baked in
 */

export type StatusKind = "ok" | "warn" | "danger" | "info" | "muted";

export function StatusDot({ kind = "muted", title }: { kind?: StatusKind; title?: string }) {
  if (title) {
    return <span className={`statusDot ${kind}`} role="img" aria-label={title} title={title} />;
  }
  return <span className={`statusDot ${kind}`} aria-hidden="true" />;
}

export function SectionHeader({
  title,
  count,
  description,
  actions,
}: {
  title: string;
  count?: number | string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="sectionHeader">
      <div className="stack-1">
        <div className="row gap-3">
          <h2>{title}</h2>
          {count !== undefined && count !== null ? (
            <span className="sectionCount">{count}</span>
          ) : null}
        </div>
        {description ? <small>{description}</small> : null}
      </div>
      {actions ? <div className="row gap-2">{actions}</div> : null}
    </header>
  );
}

export function Card({
  children,
  interactive,
  footer,
  className,
  style,
  href,
}: {
  children: ReactNode;
  interactive?: boolean;
  footer?: ReactNode;
  className?: string;
  style?: React.CSSProperties;
  href?: string;
}) {
  const cls = `card${interactive || href ? " interactive" : ""}${className ? ` ${className}` : ""}`;
  if (href) {
    return (
      <Link href={href} className={cls} style={style}>
        {children}
        {footer ? <div className="cardFooter">{footer}</div> : null}
      </Link>
    );
  }
  return (
    <article className={cls} style={style}>
      {children}
      {footer ? <div className="cardFooter">{footer}</div> : null}
    </article>
  );
}

export function MetricCard({
  label,
  value,
  hint,
  tone,
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "danger" | "warn" | "ok";
  icon?: ReactNode;
}) {
  const tileTone = tone ?? "muted";
  return (
    <section className="metric">
      <div className="row-between" style={{ width: "100%" }}>
        <span>{label}</span>
        {icon ? <div className={`iconTile ${tileTone}`}>{icon}</div> : null}
      </div>
      <strong className={tone ? `metricValue ${tone}` : "metricValue"}>{value}</strong>
      {hint ? <small>{hint}</small> : null}
    </section>
  );
}

export function EmptyState({
  title,
  description,
  icon,
  action,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="emptyState">
      {icon ? <div className="emptyIcon">{icon}</div> : null}
      <strong>{title}</strong>
      {description ? <span style={{ color: "var(--text-3)", maxWidth: 460 }}>{description}</span> : null}
      {action}
    </div>
  );
}

export function Pill({ children, tone }: { children: ReactNode; tone?: "info" | "ok" | "warn" | "danger" | "muted" }) {
  const toneClass = tone ? ` ${tone}` : "";
  return <span className={`workspacePill${toneClass}`}>{children}</span>;
}

/**
 * Animated loading placeholder. Renders as a tokenized rounded block
 * with a shimmer pulse (CSS class `skeleton` defined in globals.css).
 * Honors `prefers-reduced-motion` — the shimmer stops, the placeholder
 * remains so layout doesn't jump.
 *
 * Use anywhere a fetch hasn't resolved yet — MetricCard values, table
 * rows, chart panels — instead of an empty space or "Loading…" text.
 * The visual placeholder reserves layout, prevents content-jump, and
 * reads as "still working" without text noise.
 */
export function Skeleton({
  width = "100%",
  height = 16,
  radius = "var(--radius-sm)",
  className,
  style,
}: {
  width?: string | number;
  height?: string | number;
  radius?: string;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <span
      aria-hidden="true"
      className={`skeleton${className ? ` ${className}` : ""}`}
      style={{
        display: "block",
        width: typeof width === "number" ? `${width}px` : width,
        height: typeof height === "number" ? `${height}px` : height,
        borderRadius: radius,
        ...style,
      }}
    />
  );
}

/**
 * Inline status / error banner. Drop-in replacement for the
 * `<div className="banner …">{message}</div>` pattern used across
 * forms — the difference is this one carries the correct ARIA
 * live-region attributes so screen readers announce the message when
 * it appears, instead of users having to find it visually.
 *
 *   tone="error"   → role="alert"  + aria-live="assertive"
 *   tone="info"    → role="status" + aria-live="polite"
 *   tone="success" → role="status" + aria-live="polite"
 *   tone="demo"    → role="note"   (static label, no live region)
 *
 * Visual output unchanged — the `banner` + tone classnames are the
 * existing ones in globals.css.
 */
export function StatusBanner({
  tone,
  children,
  style,
}: {
  tone: "error" | "info" | "success" | "demo";
  children: ReactNode;
  style?: React.CSSProperties;
}) {
  if (tone === "demo") {
    return (
      <div className="banner demo" role="note" style={style}>
        {children}
      </div>
    );
  }
  const isError = tone === "error";
  return (
    <div
      className={`banner ${isError ? "danger" : "info"}`}
      role={isError ? "alert" : "status"}
      aria-live={isError ? "assertive" : "polite"}
      style={style}
    >
      {children}
    </div>
  );
}

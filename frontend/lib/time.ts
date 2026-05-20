/**
 * Compact relative-time formatter, intentionally light:
 * - <60s   "just now"
 * - <60m   "{n}m ago"
 * - <24h   "{n}h ago"
 * - <30d   "{n}d ago"
 * - else   ISO date (yyyy-mm-dd)
 *
 * SSR-safe: returns the ISO date when no `now` is passed and we're outside
 * a browser tick, so the server-rendered string and the first client render
 * match.
 */
export function relativeTime(iso: string | null | undefined, now?: number): string {
  if (!iso) return "—";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "—";
  const ref = now ?? (typeof window !== "undefined" ? Date.now() : then);
  const diff = Math.max(0, ref - then);
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  return iso.slice(0, 10);
}

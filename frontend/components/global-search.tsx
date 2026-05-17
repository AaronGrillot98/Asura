"use client";

import { useRouter } from "next/navigation";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Activity,
  Boxes,
  GitBranch,
  Package,
  Search,
  ShieldCheck,
  X,
} from "lucide-react";
import { searchAll, type SearchResult, type SearchResultKind } from "@/lib/api";

const KIND_LABEL: Record<SearchResultKind, string> = {
  project: "Projects",
  finding: "Findings",
  tool: "Tools",
  scan: "Scanner runs",
  attack_path: "Attack paths",
};

const KIND_ORDER: SearchResultKind[] = [
  "project",
  "finding",
  "attack_path",
  "tool",
  "scan",
];

function KindIcon({ kind }: { kind: SearchResultKind }) {
  switch (kind) {
    case "project":
      return <Boxes size={14} />;
    case "finding":
      return <ShieldCheck size={14} />;
    case "tool":
      return <Package size={14} />;
    case "scan":
      return <Activity size={14} />;
    case "attack_path":
      return <GitBranch size={14} />;
  }
}

export function GlobalSearch() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Open with `/` (when no input is focused). Close with Esc.
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      const tag = target?.tagName?.toLowerCase();
      const inField =
        tag === "input" || tag === "textarea" || tag === "select" || target?.isContentEditable;
      if (!open && event.key === "/" && !inField) {
        event.preventDefault();
        setOpen(true);
        return;
      }
      // Cmd/Ctrl+K — power-user alternative.
      if (!open && (event.key === "k" || event.key === "K") && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen(true);
        return;
      }
      if (open && event.key === "Escape") {
        event.preventDefault();
        setOpen(false);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  // Focus input on open.
  useEffect(() => {
    if (open) {
      // setTimeout lets the modal mount before focusing.
      setTimeout(() => inputRef.current?.focus(), 0);
    } else {
      setQuery("");
      setResults([]);
      setSelectedIndex(0);
    }
  }, [open]);

  // Debounced search on query change.
  useEffect(() => {
    if (!open) return;
    if (debounceTimer.current) clearTimeout(debounceTimer.current);
    if (!query.trim()) {
      setResults([]);
      setLoading(false);
      return;
    }
    debounceTimer.current = setTimeout(async () => {
      if (abortRef.current) abortRef.current.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      setLoading(true);
      try {
        const response = await searchAll(query, controller.signal);
        setResults(response.results);
        setSelectedIndex(0);
      } catch (err) {
        if ((err as { name?: string } | undefined)?.name !== "AbortError") {
          setResults([]);
        }
      } finally {
        setLoading(false);
      }
    }, 140);
    return () => {
      if (debounceTimer.current) clearTimeout(debounceTimer.current);
    };
  }, [query, open]);

  // Grouped view for rendering — preserve KIND_ORDER and per-kind insertion order.
  const grouped = useMemo(() => {
    const map = new Map<SearchResultKind, SearchResult[]>();
    for (const r of results) {
      const bucket = map.get(r.kind) ?? [];
      bucket.push(r);
      map.set(r.kind, bucket);
    }
    const flat: { kind: SearchResultKind; item: SearchResult; flatIndex: number }[] = [];
    let i = 0;
    for (const kind of KIND_ORDER) {
      for (const item of map.get(kind) ?? []) {
        flat.push({ kind, item, flatIndex: i++ });
      }
    }
    return flat;
  }, [results]);

  const handleSelect = useCallback(
    (item: SearchResult) => {
      setOpen(false);
      router.push(item.href);
    },
    [router],
  );

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLInputElement>) => {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        setSelectedIndex((cur) => Math.min(cur + 1, Math.max(grouped.length - 1, 0)));
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        setSelectedIndex((cur) => Math.max(cur - 1, 0));
      } else if (event.key === "Enter") {
        const target = grouped[selectedIndex]?.item;
        if (target) {
          event.preventDefault();
          handleSelect(target);
        }
      }
    },
    [grouped, selectedIndex, handleSelect],
  );

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Search Asura"
      onClick={() => setOpen(false)}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(2, 6, 18, 0.66)",
        zIndex: 1000,
        padding: "10vh 16px 16px",
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "100%",
          maxWidth: 620,
          background: "var(--bg-2)",
          border: "1px solid var(--border-2)",
          borderRadius: "var(--radius-lg)",
          boxShadow: "var(--shadow-lg)",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", padding: "12px 14px", borderBottom: "1px solid var(--border-1)", gap: 10 }}>
          <Search size={16} style={{ color: "var(--text-3)" }} />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search projects, findings, tools, scans, attack paths…"
            style={{
              background: "transparent",
              border: 0,
              outline: 0,
              color: "var(--text-1)",
              fontSize: 15,
              flex: 1,
              padding: 0,
            }}
            autoComplete="off"
            spellCheck={false}
          />
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="iconButton"
            aria-label="Close search"
            title="Esc"
            style={{ height: 28, width: 28 }}
          >
            <X size={14} />
          </button>
        </div>

        <div style={{ maxHeight: "62vh", overflowY: "auto" }}>
          {query.trim().length === 0 ? (
            <div style={{ padding: "32px 18px", color: "var(--text-3)", textAlign: "center" }}>
              Type to search across the workspace.
              <div style={{ marginTop: 10, fontSize: 12 }}>
                <kbd className="inlineCode">↑↓</kbd> to navigate ·{" "}
                <kbd className="inlineCode">Enter</kbd> to open ·{" "}
                <kbd className="inlineCode">Esc</kbd> to close
              </div>
            </div>
          ) : loading && grouped.length === 0 ? (
            <div style={{ padding: "32px 18px", color: "var(--text-3)", textAlign: "center" }}>
              Searching…
            </div>
          ) : grouped.length === 0 ? (
            <div style={{ padding: "32px 18px", color: "var(--text-3)", textAlign: "center" }}>
              No matches for{" "}
              <strong style={{ color: "var(--text-1)" }}>
                &ldquo;{query}&rdquo;
              </strong>
              .
            </div>
          ) : (
            (() => {
              let lastKind: SearchResultKind | null = null;
              const blocks: React.ReactNode[] = [];
              for (const entry of grouped) {
                if (entry.kind !== lastKind) {
                  lastKind = entry.kind;
                  blocks.push(
                    <div
                      key={`hdr-${entry.kind}`}
                      style={{
                        padding: "8px 14px 4px",
                        color: "var(--text-3)",
                        fontSize: 11,
                        fontWeight: 700,
                        letterSpacing: "0.1em",
                        textTransform: "uppercase",
                      }}
                    >
                      {KIND_LABEL[entry.kind]}
                    </div>,
                  );
                }
                const isSelected = entry.flatIndex === selectedIndex;
                blocks.push(
                  <button
                    key={entry.item.id}
                    type="button"
                    onMouseEnter={() => setSelectedIndex(entry.flatIndex)}
                    onClick={() => handleSelect(entry.item)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 12,
                      width: "100%",
                      background: isSelected ? "var(--bg-active)" : "transparent",
                      border: 0,
                      borderRadius: 0,
                      color: "var(--text-1)",
                      cursor: "pointer",
                      padding: "10px 14px",
                      textAlign: "left",
                      transition: "background 60ms",
                      height: "auto",
                      fontWeight: 500,
                    }}
                  >
                    <span style={{ color: "var(--text-3)" }}>
                      <KindIcon kind={entry.kind} />
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ color: "var(--text-1)", fontSize: 13, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {entry.item.title}
                      </div>
                      {entry.item.subtitle ? (
                        <div style={{ color: "var(--text-3)", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {entry.item.subtitle}
                        </div>
                      ) : null}
                    </div>
                    {entry.item.badge ? (
                      <span className="inlineCode" style={{ fontSize: 10 }}>{entry.item.badge}</span>
                    ) : null}
                  </button>,
                );
              }
              return blocks;
            })()
          )}
        </div>

        <div style={{ padding: "8px 14px", borderTop: "1px solid var(--border-1)", color: "var(--text-3)", fontSize: 11, display: "flex", justifyContent: "space-between" }}>
          <span>
            Press <kbd className="inlineCode">/</kbd> or <kbd className="inlineCode">Ctrl+K</kbd> to open
          </span>
          <span>{results.length} result(s)</span>
        </div>
      </div>
    </div>
  );
}

/** Sidebar/topbar trigger button — discoverable affordance for the palette. */
export function GlobalSearchTrigger() {
  const [pressed, setPressed] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        // Synthesize a `/` press so we don't have to share state from the search
        // modal — keeps this component lightweight and stateless.
        const event = new KeyboardEvent("keydown", { key: "/", bubbles: true });
        window.dispatchEvent(event);
        setPressed(true);
        setTimeout(() => setPressed(false), 200);
      }}
      style={{
        background: pressed ? "var(--bg-active)" : "var(--bg-3)",
        border: "1px solid var(--border-1)",
        borderRadius: "var(--radius)",
        color: "var(--text-2)",
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        gap: 8,
        fontSize: 12,
        fontWeight: 500,
        height: 32,
        padding: "0 10px",
        transition: "background var(--motion-fast), border-color var(--motion-fast), color var(--motion-fast)",
      }}
      title="Search (press / )"
    >
      <Search size={13} />
      <span style={{ color: "var(--text-3)" }}>Search</span>
      <kbd className="inlineCode" style={{ fontSize: 10, marginLeft: "auto" }}>/</kbd>
    </button>
  );
}

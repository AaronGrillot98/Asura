"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Trash2 } from "lucide-react";
import { deleteProject } from "@/lib/api";

export function DeleteProjectButton({ projectId, projectName, disabled }: { projectId: string; projectName: string; disabled?: boolean }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onClick() {
    if (disabled) return;
    if (!confirm(`Delete project '${projectName}'? All targets, scans, findings, and reports under it will be removed. This cannot be undone.`)) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await deleteProject(projectId);
      router.push("/projects");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {error ? (
        <div style={{ background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.3)", color: "#fca5a5", padding: "8px 12px", borderRadius: 8, fontSize: 13, marginRight: 8 }}>
          {error}
        </div>
      ) : null}
      <button
        type="button"
        className="button"
        style={{ background: disabled ? "#1f2937" : "rgba(239,68,68,0.16)", color: disabled ? "#94a3b8" : "#fca5a5", cursor: disabled ? "not-allowed" : "pointer" }}
        onClick={onClick}
        disabled={busy || disabled}
        title={disabled ? "The seeded demo project cannot be deleted." : "Delete this project"}
      >
        <Trash2 size={14} /> {busy ? "Deleting…" : "Delete"}
      </button>
    </>
  );
}

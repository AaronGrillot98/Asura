"use client";

import { ReactFlow, Background, Controls, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";
import type { AttackPath } from "@/lib/api";

const severityColor: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#60a5fa",
};

export function AttackPathGraph({ path }: { path: AttackPath }) {
  const { nodes, edges } = useMemo(() => {
    const rfNodes: Node[] = path.nodes.map((n, idx) => ({
      id: n.id,
      data: { label: n.label },
      position: { x: 60 + idx * 200, y: 80 + (idx % 2) * 80 },
      style: {
        background: "#101923",
        color: "#e8eef6",
        border: `1px solid ${n.severity ? severityColor[n.severity] : "#26374a"}`,
        borderRadius: 10,
        padding: 10,
        fontSize: 12,
        minWidth: 160,
      },
    }));
    const rfEdges: Edge[] = path.edges.map((e, idx) => ({
      id: `${e.source}->${e.target}-${idx}`,
      source: e.source,
      target: e.target,
      label: e.label,
      style: { stroke: "#475569" },
      labelStyle: { fill: "#94a3b8", fontSize: 11 },
      animated: true,
    }));
    return { nodes: rfNodes, edges: rfEdges };
  }, [path]);

  return (
    <div style={{ height: 360, background: "#0b1320", borderRadius: 10, border: "1px solid #1f2937" }}>
      <ReactFlow nodes={nodes} edges={edges} fitView nodesDraggable={false} nodesConnectable={false} elementsSelectable={false}>
        <Background gap={20} color="#1f2937" />
        <Controls position="bottom-right" showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

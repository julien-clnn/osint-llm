// Interactive graph of the multi-agent architecture, animated live by the
// same SSE stream as ActivityStream (see events in App.jsx). Goal: make it
// visible, during the analysis, that this is not a single LLM but an
// orchestrator (plain code) driving a reconnaissance agent, OSINT tools and
// a verifier agent — see the README "Multi-agent architecture" section.
//
// The SVG building blocks (nodes, edges, tool layout) are shared with
// BenchmarkGraph (Benchmark screen) via graphShared.jsx — only the
// derivation of the "live" state differs (a single run here, several
// concurrent tasks there).

import { useMemo, useState } from "react";
import {
  CLUSTER_HEADER_H,
  CLUSTER_PAD_BOTTOM,
  CLUSTER_PAD_TOP,
  CLUSTER_TITLE_ASCENT,
  DetailPanel,
  Edge,
  GraphDefs,
  GraphNode,
  NODE_H,
  NODE_W,
  TOOL_H,
  TOOL_META,
  TOOL_W,
  VB_W,
  roundedVElbow,
  toolLayout,
  toolsForRun,
} from "./graphShared.jsx";

// ─── Deriving the graph's "live" state from SSE events ─────────────────────
// Same `events` array as ActivityStream: we replay it to recover a phase
// (recon | verify) rather than duplicating state.
function deriveGraphState(events, status) {
  let phase = "recon"; // "recon" | "verify"
  let activeTool = null; // name of the tool currently being called
  let lastToolFlash = null; // { name, ok } — last tool result received
  let corrected = false; // at least one correction requested on this run
  let lastVerification = null;

  for (const { type, data } of events) {
    if (type === "tool_call" && data.name !== "submit_report") {
      activeTool = data.name;
      lastToolFlash = null;
    } else if (type === "tool_result") {
      lastToolFlash = { name: data.name, ok: data.ok };
      activeTool = null;
    } else if (type === "verification") {
      phase = "verify";
      lastVerification = data;
    } else if (type === "info") {
      if (/v[ée]rif/i.test(data.message)) phase = "verify";
      else if (/corrections (demandées|requested)/i.test(data.message)) {
        phase = "recon";
        corrected = true;
        activeTool = null;
      }
    }
  }

  const running = status === "running";
  return {
    reconActive: running && phase === "recon",
    verifierActive: running && phase === "verify",
    activeTool: running && phase === "recon" ? activeTool : null,
    // Same guard as activeTool: once in verification (or stopped), the last
    // called tool must not stay "lit".
    lastToolFlash: running && phase === "recon" ? lastToolFlash : null,
    corrected,
    lastVerification,
  };
}

// ─── Main component ─────────────────────────────────────────────────────────

export default function AgentGraph({ events, status, mode, scenario, scenarioLabel }) {
  const [activeNodeId, setActiveNodeId] = useState(null);

  const activeTools = useMemo(() => toolsForRun(mode, scenario), [mode, scenario]);
  const tools = useMemo(() => toolLayout(activeTools), [activeTools]);
  const graphState = useMemo(() => deriveGraphState(events, status), [events, status]);

  const toggle = (id) => setActiveNodeId((prev) => (prev === id ? null : id));

  const orcX = VB_W / 2;
  const reconBox = { x: 90, y: 150 };
  const verifBox = { x: VB_W - 90 - NODE_W, y: 150 };
  const orcBox = { x: orcX - NODE_W / 2, y: 46 };

  // The canvas height adapts to the actual number of tool rows (1 or 2
  // depending on scenario/mode) rather than a fixed constant — otherwise a
  // single-row scenario inherits a large empty bottom margin (noticeable in
  // active mode, where the 2nd row is shorter).
  const toolsTop = tools.length ? Math.min(...tools.map((t) => t.cy)) - TOOL_H / 2 : 318 - TOOL_H / 2;
  const toolsBottom = tools.length ? Math.max(...tools.map((t) => t.cy)) + TOOL_H / 2 : toolsTop;
  const toolsClusterY = toolsTop - CLUSTER_HEADER_H;
  const clusterHeight = toolsBottom - toolsClusterY + CLUSTER_PAD_BOTTOM;
  const vbH = toolsClusterY + clusterHeight + 14;

  const detail = (() => {
    if (activeNodeId === "orchestrator") {
      return {
        title: "investigation.py",
        kindLabel: "Orchestrator · plain code",
        lines: [
          "No LLM call — chains the two agents.",
          "Runs the reconnaissance agent, then the verifier agent.",
          "Correction loop bounded by OSINTLLM_MAX_VERIFY (default 2).",
          "src: src/osintllm/investigation.py",
        ],
      };
    }
    if (activeNodeId === "recon") {
      return {
        title: "Reconnaissance agent",
        kindLabel: "Agent LLM",
        lines: [
          "DeepSeek model (deepseek-chat by default, configurable).",
          `Access to ${activeTools.length} tool${activeTools.length > 1 ? "s" : ""} — "${scenarioLabel}" scenario, ${mode === "active" ? "active" : "passive"} mode.`,
          "ReAct loop: calls a tool, observes, decides whether to continue (max_iterations=8).",
          "Writes the final report via the submit_report tool.",
          "src: src/osintllm/agent.py",
        ],
      };
    }
    if (activeNodeId === "verifier") {
      return {
        title: "Verifier agent",
        kindLabel: "Agent LLM · audit",
        lines: [
          "Same model as the reconnaissance agent.",
          "Has access to NO collection tool — only sees the raw facts + the report.",
          "Checks every claim in the report against the facts actually collected.",
          "Also detects prompt-injection attempts in third-party data.",
          "src: src/osintllm/verifier.py",
        ],
      };
    }
    const tool = TOOL_META[activeNodeId];
    if (tool) {
      return {
        title: tool.label,
        kindLabel: tool.passive ? "Passive tool" : "Active tool — contacts the target",
        lines: [
          `Source: ${tool.source}`,
          `Returns: ${tool.renvoie}`,
          "Called by the reconnaissance agent, never by the verifier.",
        ],
      };
    }
    return null;
  })();

  return (
    <div className="agent-graph">
      <div className="agent-graph-head">
        <span className={`core ${status === "running" ? "live" : "done"}`} />
        Live multi-agent architecture
        <span className="agent-graph-hint">click a node for details</span>
      </div>
      <div className="agent-graph-body">
        <svg viewBox={`0 0 ${VB_W} ${vbH}`} className="agent-graph-svg" preserveAspectRatio="xMidYMid meet">
          <GraphDefs />

          {/* orchestrator -> recon */}
          <Edge
            path={roundedVElbow(orcBox.x + 30, orcBox.y + NODE_H, reconBox.x + NODE_W / 2, reconBox.y, 16)}
            active={graphState.reconActive}
          />
          {/* orchestrator -> verifier */}
          <Edge
            path={roundedVElbow(orcBox.x + NODE_W - 30, orcBox.y + NODE_H, verifBox.x + NODE_W / 2, verifBox.y, 16)}
            active={graphState.verifierActive}
          />
          {/* recon -> verifier (report) */}
          <Edge
            path={`M ${reconBox.x + NODE_W},${reconBox.y + NODE_H / 2} L ${verifBox.x},${verifBox.y + NODE_H / 2}`}
            label="report"
            lx={VB_W / 2}
            ly={reconBox.y + NODE_H / 2 - 8}
            active={graphState.verifierActive}
          />
          {/* verifier -> recon (corrections), only shown when it happens */}
          {graphState.corrected ? (
            <Edge
              path={`M ${verifBox.x},${verifBox.y + NODE_H / 2 + 16} L ${reconBox.x + NODE_W},${reconBox.y + NODE_H / 2 + 16}`}
              label="corrections requested"
              lx={VB_W / 2}
              ly={reconBox.y + NODE_H / 2 + 30}
              dashed
              active={graphState.reconActive}
            />
          ) : null}
          {/* recon -> tool cluster: the label is centered on the middle of
              the horizontal segment, away from both rounded corners, so it
              doesn't hide the curve of the line. */}
          <Edge
            path={roundedVElbow(reconBox.x + NODE_W / 2, reconBox.y + NODE_H, VB_W / 2, toolsClusterY, 16)}
            label="tool calls (loop)"
            lx={(reconBox.x + NODE_W / 2 + VB_W / 2) / 2}
            ly={(reconBox.y + NODE_H + toolsClusterY) / 2}
            active={!!graphState.activeTool}
          />

          {/* visual tool cluster */}
          <rect x={20} y={toolsClusterY} width={VB_W - 40} height={clusterHeight} rx={14} className="gcluster" />
          <text
            x={VB_W / 2}
            y={toolsClusterY + CLUSTER_PAD_TOP + CLUSTER_TITLE_ASCENT}
            textAnchor="middle"
            className="gcluster-label"
          >
            OSINT tools · "{scenarioLabel}" scenario · {mode === "active" ? "active" : "passive"} mode
          </text>

          <GraphNode
            {...orcBox}
            w={NODE_W}
            h={NODE_H}
            label="investigation.py"
            sub="Orchestrator · plain code"
            kind="orchestrator"
            active={status === "running"}
            onClick={() => toggle("orchestrator")}
          />
          <GraphNode
            {...reconBox}
            w={NODE_W}
            h={NODE_H}
            label="RECON agent"
            sub="agent.py · LLM"
            kind="recon"
            active={graphState.reconActive}
            onClick={() => toggle("recon")}
          />
          <GraphNode
            {...verifBox}
            w={NODE_W}
            h={NODE_H}
            label="VERIFIER agent"
            sub="verifier.py · LLM"
            kind="verifier"
            active={graphState.verifierActive}
            onClick={() => toggle("verifier")}
          />

          {tools.map((t) => {
            const meta = TOOL_META[t.name];
            const isActive = graphState.activeTool === t.name;
            const flash = graphState.lastToolFlash && graphState.lastToolFlash.name === t.name ? graphState.lastToolFlash.ok : null;
            return (
              <GraphNode
                key={t.name}
                x={t.cx - TOOL_W / 2}
                y={t.cy - TOOL_H / 2}
                w={TOOL_W}
                h={TOOL_H}
                label={meta.label}
                sub={meta.passive ? "passive" : "active"}
                kind="tool"
                active={isActive}
                flashOk={flash}
                onClick={() => toggle(t.name)}
              />
            );
          })}
        </svg>

        {detail ? <DetailPanel {...detail} onClose={() => setActiveNodeId(null)} /> : null}
      </div>
    </div>
  );
}

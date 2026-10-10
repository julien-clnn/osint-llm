// Counterpart of AgentGraph for the Benchmark screen: same visual
// architecture (orchestrator → recon agent → OSINT tools, recon agent ↔
// verifier), but animated by SEVERAL concurrent tasks (up to `maxWorkers` in
// parallel, a ThreadPoolExecutor in evals/harness/cli.py::run_matrix) rather
// than a single run. Nodes/edges therefore light up in aggregate ("N tasks
// running") instead of a simple on/off, and a panel lists the active tasks
// (domain · config · repetition · phase), to make the parallelism actually
// visible rather than hiding it behind a binary state — see events.py
// (backend) for the format of the received events.
//
// The harness doesn't stop at run_matrix: after the recon/verify matrix,
// `run_eval.py` chains an LLM-as-judge pass (judge.py, always
// deepseek-reasoner, sequential, once per domain) and then an error
// injection/detection pass (injector.py + verifier.py, parallel per domain)
// — two phases that also consume real LLM quota. They are shown as two
// dedicated nodes below the tool cluster, fed by the same "info" (start) /
// "final" (end) markers as the rest (see evals/harness/cli.py::_emit_phase).

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

const CONFIG_LABELS = {
  with_verifier: "with verifier",
  without_verifier: "without verifier",
};

const PHASE_NODE_W = NODE_W;
const PHASE_NODE_H = 54;
const PHASE_ROW_GAP = 36;

// ─── Deriving the "live" state from the events of several tasks ────────────
// Each `taskEvents` item: { domain, config, repetition, kind, data }
// (see api.py::_benchmark_stream and evals/harness/cli.py::_make_stdout_emitter).
// The whole history is replayed on every render (like deriveGraphState in
// AgentGraph): no duplicated state, the single source of truth is the event
// array accumulated by Benchmark.jsx. `config` distinguishes three task
// families: "with_verifier"/"without_verifier" (run_matrix, with detailed
// recon/tools/verify), "judge" (LLM judging, status message only) and
// "injector" (injection/detection, same).
function deriveBenchmarkGraphState(taskEvents, running) {
  const matrixTasks = new Map(); // key "domain|config|repetition"
  const judgeTasks = new Map(); // key domain
  const injectorTasks = new Map(); // key "domain|repetition"
  let everCorrected = false;

  for (const { domain, config, repetition, kind, data } of taskEvents) {
    if (config === "judge") {
      let t = judgeTasks.get(domain);
      if (!t) {
        t = { domain, message: "", done: false };
        judgeTasks.set(domain, t);
      }
      if (kind === "final") t.done = true;
      else if (kind === "info") t.message = data.message;
      continue;
    }
    if (config === "injector") {
      const key = `${domain}|${repetition}`;
      let t = injectorTasks.get(key);
      if (!t) {
        t = { domain, repetition, message: "", done: false };
        injectorTasks.set(key, t);
      }
      if (kind === "final") t.done = true;
      else if (kind === "info") {
        t.message = data.message;
        t.done = false; // an "injector" task restarts for each tested family
      }
      continue;
    }

    const key = `${domain}|${config}|${repetition}`;
    let t = matrixTasks.get(key);
    if (!t) {
      t = { domain, config, repetition, phase: "recon", activeTool: null, lastToolFlash: null, done: false };
      matrixTasks.set(key, t);
    }
    if (kind === "final") {
      t.done = true;
      t.activeTool = null;
      continue;
    }
    if (kind === "tool_call" && data.name !== "submit_report") {
      t.activeTool = data.name;
      t.lastToolFlash = null;
    } else if (kind === "tool_result") {
      t.lastToolFlash = { name: data.name, ok: data.ok };
      t.activeTool = null;
    } else if (kind === "verification") {
      t.phase = "verify";
    } else if (kind === "info") {
      if (/v[ée]rif/i.test(data.message)) t.phase = "verify";
      else if (/corrections (demandées|requested)/i.test(data.message)) {
        t.phase = "recon";
        t.activeTool = null;
        everCorrected = true;
      }
    }
  }

  const activeMatrixTasks = running ? [...matrixTasks.values()].filter((t) => !t.done) : [];
  const reconTasks = activeMatrixTasks.filter((t) => t.phase === "recon");
  const verifyTasks = activeMatrixTasks.filter((t) => t.phase === "verify");

  const toolCounts = new Map();
  for (const t of reconTasks) {
    if (t.activeTool) toolCounts.set(t.activeTool, (toolCounts.get(t.activeTool) || 0) + 1);
  }
  // "Last result" flash only for tools no longer being called elsewhere —
  // otherwise a stuck flash would hide the active halo.
  const toolFlash = new Map();
  for (const t of activeMatrixTasks) {
    if (t.lastToolFlash && !toolCounts.has(t.lastToolFlash.name)) {
      toolFlash.set(t.lastToolFlash.name, t.lastToolFlash.ok);
    }
  }

  const activeJudgeTasks = running ? [...judgeTasks.values()].filter((t) => !t.done) : [];
  const activeInjectorTasks = running ? [...injectorTasks.values()].filter((t) => !t.done) : [];

  return {
    activeMatrixTasks: activeMatrixTasks.sort(
      (a, b) => a.domain.localeCompare(b.domain) || a.repetition - b.repetition
    ),
    activeJudgeTasks: activeJudgeTasks.sort((a, b) => a.domain.localeCompare(b.domain)),
    activeInjectorTasks: activeInjectorTasks.sort(
      (a, b) => a.domain.localeCompare(b.domain) || a.repetition - b.repetition
    ),
    reconCount: reconTasks.length,
    verifyCount: verifyTasks.length,
    toolCounts,
    toolFlash,
    corrected: everCorrected,
  };
}

export default function BenchmarkGraph({ taskEvents, phase, scenario, scenarioLabel, maxWorkers }) {
  const [activeNodeId, setActiveNodeId] = useState(null);
  const running = phase === "running";

  // The harness always runs in passive mode (see runner.py::run_once).
  const activeTools = useMemo(() => toolsForRun("passive", scenario), [scenario]);
  const tools = useMemo(() => toolLayout(activeTools), [activeTools]);
  const graphState = useMemo(() => deriveBenchmarkGraphState(taskEvents, running), [taskEvents, running]);

  const toggle = (id) => setActiveNodeId((prev) => (prev === id ? null : id));

  const orcX = VB_W / 2;
  const reconBox = { x: 90, y: 150 };
  const verifBox = { x: VB_W - 90 - NODE_W, y: 150 };
  const orcBox = { x: orcX - NODE_W / 2, y: 46 };

  const toolsTop = tools.length ? Math.min(...tools.map((t) => t.cy)) - TOOL_H / 2 : 318 - TOOL_H / 2;
  const toolsBottom = tools.length ? Math.max(...tools.map((t) => t.cy)) + TOOL_H / 2 : toolsTop;
  const toolsClusterY = toolsTop - CLUSTER_HEADER_H;
  const clusterHeight = toolsBottom - toolsClusterY + CLUSTER_PAD_BOTTOM;
  const clusterBottomY = toolsClusterY + clusterHeight;

  const phaseRowY = clusterBottomY + PHASE_ROW_GAP;
  const judgeBox = { x: VB_W / 2 - PHASE_NODE_W - 14, y: phaseRowY };
  const injectorBox = { x: VB_W / 2 + 14, y: phaseRowY };
  const vbH = phaseRowY + PHASE_NODE_H + 14;

  const reconActive = graphState.reconCount > 0;
  const verifierActive = graphState.verifyCount > 0;
  const anyToolActive = graphState.toolCounts.size > 0;
  const judgeActive = graphState.activeJudgeTasks.length > 0;
  const injectorActive = graphState.activeInjectorTasks.length > 0;

  const detail = (() => {
    if (activeNodeId === "orchestrator") {
      return {
        title: "run_eval.py",
        kindLabel: "Eval harness · ThreadPoolExecutor",
        lines: [
          `Up to ${maxWorkers} task${maxWorkers > 1 ? "s" : ""} (domain × config × repetition) in parallel.`,
          "Each task is a full run, identical to the Analysis screen's path.",
          "Two configs per domain × repetition: without, then with the verifier agent.",
          "Then chains LLM judging and injection/detection (see below).",
          "src: evals/harness/cli.py (run_matrix), evals/run_eval.py",
        ],
      };
    }
    if (activeNodeId === "recon") {
      return {
        title: "Reconnaissance agent",
        kindLabel: "Agent LLM",
        lines: [
          `${graphState.reconCount} task${graphState.reconCount > 1 ? "s" : ""} currently in reconnaissance.`,
          `"${scenarioLabel}" scenario, passive mode (the only mode evaluated by the harness).`,
          "ReAct loop: calls a tool, observes, decides whether to continue (max_iterations=8).",
          "src: src/osintllm/agent.py",
        ],
      };
    }
    if (activeNodeId === "verifier") {
      return {
        title: "Verifier agent",
        kindLabel: "Agent LLM · audit",
        lines: [
          `${graphState.verifyCount} task${graphState.verifyCount > 1 ? "s" : ""} currently in verification.`,
          'Only involved in "with verifier" config tasks.',
          "Checks every claim in the report against the facts actually collected.",
          "src: src/osintllm/verifier.py",
        ],
      };
    }
    if (activeNodeId === "judge") {
      return {
        title: "LLM judge",
        kindLabel: "Agent LLM · deepseek-reasoner",
        lines: [
          `${graphState.activeJudgeTasks.length} domain${graphState.activeJudgeTasks.length > 1 ? "s" : ""} being judged.`,
          "ALWAYS runs on deepseek-reasoner, even when the run evaluates Mistral — never self-evaluation, scores comparable across providers.",
          "Audits every claim in the report (supported/unsupported/contradicted) + the ground-truth assertions.",
          "Sequential (no parallelism) — a single pass per domain, on repetition 1 with verifier.",
          "src: evals/harness/judge.py",
        ],
      };
    }
    if (activeNodeId === "injector") {
      return {
        title: "Injector / Detection",
        kindLabel: "Adversarial test · verifier.py",
        lines: [
          `${graphState.activeInjectorTasks.length} verification${graphState.activeInjectorTasks.length > 1 ? "s" : ""} running.`,
          "Injects fake data into a copy of the report (5 families: invented IP/ASN, invented subdomain, contradicted risk, inconsistent date, off-topic recommendation).",
          "Reuses the verifier agent to measure whether it detects each alteration, plus a false-positive test on the untouched report.",
          "Parallel per domain (like run_matrix), sequential within a domain.",
          "src: evals/harness/injector.py",
        ],
      };
    }
    const tool = TOOL_META[activeNodeId];
    if (tool) {
      const count = graphState.toolCounts.get(activeNodeId) || 0;
      return {
        title: tool.label,
        kindLabel: tool.passive ? "Passive tool" : "Active tool — contacts the target",
        lines: [
          `Source: ${tool.source}`,
          `Returns: ${tool.renvoie}`,
          count > 0 ? `Currently called by ${count} task${count > 1 ? "s" : ""}.` : "No call in progress.",
        ],
      };
    }
    return null;
  })();

  const allActiveTasks = [
    ...graphState.activeMatrixTasks.map((t) => ({ ...t, kind: "matrix" })),
    ...graphState.activeJudgeTasks.map((t) => ({ ...t, kind: "judge" })),
    ...graphState.activeInjectorTasks.map((t) => ({ ...t, kind: "injector" })),
  ];

  return (
    <div className="agent-graph">
      <div className="agent-graph-head">
        <span className={`core ${running ? "live" : "done"}`} />
        Live multi-agent architecture · benchmark
        <span className="agent-graph-hint">click a node for details</span>
      </div>
      <div className="agent-graph-body">
        <svg viewBox={`0 0 ${VB_W} ${vbH}`} className="agent-graph-svg" preserveAspectRatio="xMidYMid meet">
          <GraphDefs />

          <Edge
            path={roundedVElbow(orcBox.x + 30, orcBox.y + NODE_H, reconBox.x + NODE_W / 2, reconBox.y, 16)}
            active={reconActive}
          />
          <Edge
            path={roundedVElbow(orcBox.x + NODE_W - 30, orcBox.y + NODE_H, verifBox.x + NODE_W / 2, verifBox.y, 16)}
            active={verifierActive}
          />
          <Edge
            path={`M ${reconBox.x + NODE_W},${reconBox.y + NODE_H / 2} L ${verifBox.x},${verifBox.y + NODE_H / 2}`}
            label="reports"
            lx={VB_W / 2}
            ly={reconBox.y + NODE_H / 2 - 8}
            active={verifierActive}
          />
          {graphState.corrected ? (
            <Edge
              path={`M ${verifBox.x},${verifBox.y + NODE_H / 2 + 16} L ${reconBox.x + NODE_W},${reconBox.y + NODE_H / 2 + 16}`}
              label="corrections requested"
              lx={VB_W / 2}
              ly={reconBox.y + NODE_H / 2 + 30}
              dashed
              active={reconActive}
            />
          ) : null}
          <Edge
            path={roundedVElbow(reconBox.x + NODE_W / 2, reconBox.y + NODE_H, VB_W / 2, toolsClusterY, 16)}
            label="tool calls (loop)"
            lx={(reconBox.x + NODE_W / 2 + VB_W / 2) / 2}
            ly={(reconBox.y + NODE_H + toolsClusterY) / 2}
            active={anyToolActive}
          />

          <rect x={20} y={toolsClusterY} width={VB_W - 40} height={clusterHeight} rx={14} className="gcluster" />
          <text
            x={VB_W / 2}
            y={toolsClusterY + CLUSTER_PAD_TOP + CLUSTER_TITLE_ASCENT}
            textAnchor="middle"
            className="gcluster-label"
          >
            OSINT tools · "{scenarioLabel}" scenario · passive mode
          </text>

          {/* Later harness phases (after run_matrix): LLM judging, then
              injection/detection — fanning out from the bottom of the cluster. */}
          <Edge
            path={roundedVElbow(VB_W / 2 - 30, clusterBottomY, judgeBox.x + PHASE_NODE_W / 2, judgeBox.y, 14)}
            active={judgeActive}
          />
          <Edge
            path={roundedVElbow(VB_W / 2 + 30, clusterBottomY, injectorBox.x + PHASE_NODE_W / 2, injectorBox.y, 14)}
            active={injectorActive}
          />

          <GraphNode
            {...orcBox}
            w={NODE_W}
            h={NODE_H}
            label="run_eval.py"
            sub={running ? `${graphState.activeMatrixTasks.length} / ${maxWorkers} active workers` : "ThreadPoolExecutor"}
            kind="orchestrator"
            active={running}
            onClick={() => toggle("orchestrator")}
          />
          <GraphNode
            {...reconBox}
            w={NODE_W}
            h={NODE_H}
            label="RECON agent"
            sub={reconActive ? `${graphState.reconCount} running` : "agent.py · LLM"}
            kind="recon"
            active={reconActive}
            onClick={() => toggle("recon")}
          />
          <GraphNode
            {...verifBox}
            w={NODE_W}
            h={NODE_H}
            label="VERIFIER agent"
            sub={verifierActive ? `${graphState.verifyCount} running` : "verifier.py · LLM"}
            kind="verifier"
            active={verifierActive}
            onClick={() => toggle("verifier")}
          />

          {tools.map((t) => {
            const meta = TOOL_META[t.name];
            const count = graphState.toolCounts.get(t.name) || 0;
            const isActive = count > 0;
            const flash = !isActive && graphState.toolFlash.has(t.name) ? graphState.toolFlash.get(t.name) : null;
            return (
              <GraphNode
                key={t.name}
                x={t.cx - TOOL_W / 2}
                y={t.cy - TOOL_H / 2}
                w={TOOL_W}
                h={TOOL_H}
                label={meta.label}
                sub={isActive ? `×${count} running` : meta.passive ? "passive" : "active"}
                kind="tool"
                active={isActive}
                flashOk={flash}
                onClick={() => toggle(t.name)}
              />
            );
          })}

          <GraphNode
            {...judgeBox}
            w={PHASE_NODE_W}
            h={PHASE_NODE_H}
            label="LLM judge"
            sub={judgeActive ? `${graphState.activeJudgeTasks.length} judging` : "judge.py · deepseek-reasoner"}
            kind="judge"
            active={judgeActive}
            onClick={() => toggle("judge")}
          />
          <GraphNode
            {...injectorBox}
            w={PHASE_NODE_W}
            h={PHASE_NODE_H}
            label="Injector / Detection"
            sub={injectorActive ? `${graphState.activeInjectorTasks.length} running` : "injector.py · verifier.py"}
            kind="injector"
            active={injectorActive}
            onClick={() => toggle("injector")}
          />
        </svg>

        {detail ? <DetailPanel {...detail} onClose={() => setActiveNodeId(null)} /> : null}
      </div>

      <div className="stream" style={{ marginTop: 14 }}>
        <div className="stream-head">
          <span className={`core ${running ? "live" : "done"}`} />
          {allActiveTasks.length} task{allActiveTasks.length > 1 ? "s" : ""} running
          {" "}(max {maxWorkers} in parallel)
        </div>
        <div className="stream-body">
          {allActiveTasks.length === 0 ? (
            <div className="line">
              <span className="txt">
                {running ? "Waiting for the first events…" : "No active task."}
              </span>
            </div>
          ) : (
            allActiveTasks.map((t) => {
              if (t.kind === "judge") {
                return (
                  <div key={`judge|${t.domain}`} className="line">
                    <span className="tag judge">judge</span>
                    <span className="txt">
                      <code>{t.domain}</code> · LLM judging (deepseek-reasoner)
                      {t.message ? ` — ${t.message}` : ""}
                    </span>
                  </div>
                );
              }
              if (t.kind === "injector") {
                return (
                  <div key={`injector|${t.domain}|${t.repetition}`} className="line">
                    <span className="tag inject">inject</span>
                    <span className="txt">
                      <code>{t.domain}</code> · rep. {t.repetition}
                      {t.message ? ` — ${t.message}` : ""}
                    </span>
                  </div>
                );
              }
              return (
                <div key={`${t.domain}|${t.config}|${t.repetition}`} className="line">
                  <span className={`tag ${t.phase === "verify" ? "audit" : "tool"}`}>
                    {t.phase === "verify" ? "verif" : "recon"}
                  </span>
                  <span className="txt">
                    <code>{t.domain}</code> · {CONFIG_LABELS[t.config] || t.config} · rep. {t.repetition}
                    {t.activeTool ? (
                      <>
                        {" "}
                        — calling <strong>{TOOL_META[t.activeTool]?.label || t.activeTool}</strong>
                      </>
                    ) : null}
                  </span>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

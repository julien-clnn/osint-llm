// Single entry point for the frontend's calls to the FastAPI backend.
//
// Normal build: a plain fetch() to /api/... (proxied to port 8000 in dev,
// same origin in production).
//
// Demo build (`VITE_DEMO=1`, see `make demo`): no backend at all. Every
// route is answered from static JSON files shipped with the build
// (web/demo-data/, produced by scripts/demo_data.py), and /api/analyze
// replays a recorded SSE stream with its original timing. The screens keep
// reading a Response exactly as they would from the real API.

export const IS_DEMO = import.meta.env.VITE_DEMO === "1";

const DATA = `${import.meta.env.BASE_URL}demo-data`;

// Replay speed: recorded gaps are divided by this factor, then capped, so a
// 2-minute analysis plays back in well under a minute while keeping the
// rhythm of the agent (fast tool bursts, longer LLM pauses).
const REPLAY_SPEEDUP = 3;
const REPLAY_MAX_GAP_MS = 2500;

export function apiFetch(url, options) {
  return IS_DEMO ? demoFetch(url, options) : fetch(url, options);
}

let indexPromise = null;

// Recorded analyses available in the demo: [{domain, scenario, ...}].
export function loadDemoIndex() {
  indexPromise ??= fetch(`${DATA}/analyses/index.json`).then((r) => (r.ok ? r.json() : []));
  return indexPromise;
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function demoFetch(url, options = {}) {
  const u = new URL(url, window.location.origin);
  const path = u.pathname;

  if (path === "/api/settings") return fetch(`${DATA}/settings.json`);
  if (path === "/api/eval/runs") return fetch(`${DATA}/eval/runs.json`);
  if (path === "/api/eval/domains") return fetch(`${DATA}/eval/domains.json`);
  const run = path.match(/^\/api\/eval\/runs\/(\d{8}_\d{6})$/);
  if (run) return fetch(`${DATA}/eval/runs/${run[1]}.json`);
  if (path === "/api/analyze") {
    return replayAnalysis(u.searchParams.get("domain"), u.searchParams.get("scenario"), options.signal);
  }
  if (path === "/api/eval/launch") {
    return jsonResponse({ detail: "Benchmarks run real LLM calls: available in the local setup only." }, 503);
  }
  return jsonResponse({ detail: "Not available in the demo." }, 404);
}

async function replayAnalysis(domain, scenario, signal) {
  const index = await loadDemoIndex();
  const entry = index.find((e) => e.domain === domain && e.scenario === scenario);
  if (!entry) {
    return jsonResponse({ detail: `No recorded analysis of ${domain} for this scenario in the demo.` }, 404);
  }
  const res = await fetch(`${DATA}/analyses/${entry.file}`, { signal });
  if (!res.ok) return jsonResponse({ detail: "Could not load the recorded analysis." }, 500);
  const recording = await res.json();

  const encoder = new TextEncoder();
  let timer = null;
  const stream = new ReadableStream({
    start(controller) {
      let i = 0;
      let prevT = 0;
      const push = () => {
        if (signal?.aborted) return;
        const { t, event, data } = recording.events[i];
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
        prevT = t;
        i += 1;
        if (i >= recording.events.length) {
          controller.close();
          return;
        }
        const gap = Math.max(0, recording.events[i].t - prevT) * 1000;
        timer = setTimeout(push, Math.min(gap / REPLAY_SPEEDUP, REPLAY_MAX_GAP_MS));
      };
      signal?.addEventListener("abort", () => {
        clearTimeout(timer);
        try {
          controller.error(new DOMException("Aborted", "AbortError"));
        } catch {
          // stream already closed
        }
      });
      timer = setTimeout(push, 300);
    },
    cancel() {
      clearTimeout(timer);
    },
  });
  return new Response(stream, { headers: { "Content-Type": "text/event-stream" } });
}

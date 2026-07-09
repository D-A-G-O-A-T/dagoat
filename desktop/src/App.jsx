import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// Power → scheduler tier, mirrored from the Rust backend (for the label + hint only).
const TIERS = [
  { max: 30, label: "Idle", hint: "whisper quiet — barely warm" },
  { max: 60, label: "Normal", hint: "quiet — a good overnight setting" },
  { max: 100, label: "High", hint: "full speed" },
];
const tierFor = (p) => TIERS.find((t) => p <= t.max) ?? TIERS[TIERS.length - 1];

const STATUS = {
  stopped: { label: "Stopped", color: "#8b8b93" },
  starting: { label: "Starting…", color: "#d9a441" },
  running: { label: "Running", color: "#3ecf8e" },
  error: { label: "Error", color: "#e5484d" },
};

const MAX_LOG_LINES = 200;

export default function App() {
  const [status, setStatus] = useState("stopped");
  const [power, setPower] = useState(50);
  const [message, setMessage] = useState("Ready when you are.");
  const [logs, setLogs] = useState([]);
  const logRef = useRef(null);

  // Subscribe to daemon output and to unexpected termination.
  useEffect(() => {
    const unlisteners = [];
    listen("node-log", (e) => {
      setLogs((prev) => [...prev.slice(-(MAX_LOG_LINES - 1)), String(e.payload)]);
    }).then((u) => unlisteners.push(u));
    listen("node-stopped", () => {
      setStatus("stopped");
      setMessage("Node stopped.");
    }).then((u) => unlisteners.push(u));
    return () => unlisteners.forEach((u) => u());
  }, []);

  // Keep the log scrolled to the newest line.
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const running = status === "running";
  const starting = status === "starting";

  const start = useCallback(async () => {
    setStatus("starting");
    setMessage("Starting the node…");
    try {
      const msg = await invoke("start_goat_node", { powerLevel: power });
      setStatus("running");
      setMessage(String(msg));
    } catch (err) {
      setStatus("error");
      setMessage("Failed to start: " + String(err));
    }
  }, [power]);

  const stop = useCallback(async () => {
    setMessage("Stopping…");
    try {
      const msg = await invoke("stop_goat_node");
      setStatus("stopped");
      setMessage(String(msg));
    } catch (err) {
      setMessage("Failed to stop: " + String(err));
    }
  }, []);

  const onToggle = () => (running ? stop() : start());

  // While dragging we only update local state; on release we push the change to a running node
  // (real-time priority), and it always applies on the next start.
  const commitPower = useCallback(async () => {
    if (status !== "running") return;
    try {
      const msg = await invoke("set_power_level", { powerLevel: power });
      setMessage(String(msg));
    } catch (err) {
      setMessage("Could not update power: " + String(err));
    }
  }, [status, power]);

  const s = STATUS[status];
  const tier = tierFor(power);

  return (
    <div className="app">
      <style>{css}</style>

      {/* Header */}
      <header className="header">
        <div className="brand">
          <span className="logo" aria-hidden>🐐</span>
          <h1>D.A. G.O.A.T.</h1>
        </div>
        <div className="status" style={{ color: s.color }}>
          <span className="dot" style={{ background: s.color }} />
          {s.label}
        </div>
      </header>

      <p className="subtitle">GoatCoin desktop node · public alpha</p>

      {/* Start / Stop */}
      <button
        className={`toggle ${running ? "stop" : "start"}`}
        onClick={onToggle}
        disabled={starting}
      >
        {starting ? "Starting…" : running ? "Stop Node" : "Start Node"}
      </button>

      {/* Power Dial */}
      <section className="dial">
        <div className="dial-head">
          <label htmlFor="power">Power Dial</label>
          <span className="power-value">{power}%</span>
        </div>

        <input
          id="power"
          type="range"
          min="1"
          max="100"
          value={power}
          style={{ "--fill": `${power}%` }}
          onChange={(e) => setPower(Number(e.target.value))}
          onMouseUp={commitPower}
          onTouchEnd={commitPower}
          onKeyUp={commitPower}
        />

        <div className="dial-foot">
          <span className="tier">{tier.label} priority</span>
          <span className="hint">{tier.hint}</span>
        </div>
        <p className="dial-note">
          Controls how hard your machine works. Lower = quieter &amp; cooler. Set it any time — it
          updates a running node instantly.
        </p>
      </section>

      {/* Feedback */}
      <div className="message">{message}</div>

      {/* Log */}
      <section className="log-wrap">
        <div className="log-head">
          <span>Node output</span>
          {logs.length > 0 && (
            <button className="clear" onClick={() => setLogs([])}>
              clear
            </button>
          )}
        </div>
        <div className="log" ref={logRef}>
          {logs.length === 0 ? (
            <span className="log-empty">No output yet.</span>
          ) : (
            logs.map((line, i) => (
              <div className="log-line" key={i}>
                {line}
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}

const css = `
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; }
  .app {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    max-width: 460px;
    margin: 0 auto;
    padding: 24px 22px 28px;
    color: #e9e9ee;
    background: #16161a;
    min-height: 100vh;
    -webkit-user-select: none;
    user-select: none;
  }
  .header { display: flex; align-items: center; justify-content: space-between; }
  .brand { display: flex; align-items: center; gap: 10px; }
  .logo { font-size: 26px; }
  h1 { font-size: 22px; margin: 0; letter-spacing: 0.2px; }
  .status { display: inline-flex; align-items: center; gap: 7px; font-size: 13px; font-weight: 600; }
  .dot { width: 9px; height: 9px; border-radius: 50%; box-shadow: 0 0 8px currentColor; }
  .subtitle { margin: 4px 0 22px; color: #8b8b93; font-size: 12.5px; }

  .toggle {
    width: 100%;
    padding: 16px;
    border: none;
    border-radius: 14px;
    font-size: 17px;
    font-weight: 700;
    color: #0e0e10;
    cursor: pointer;
    transition: transform 0.06s ease, filter 0.15s ease, opacity 0.15s ease;
  }
  .toggle:active { transform: scale(0.985); }
  .toggle:disabled { cursor: default; opacity: 0.7; }
  .toggle.start { background: linear-gradient(180deg, #4ade9a, #3ecf8e); }
  .toggle.stop { background: linear-gradient(180deg, #f0686c, #e5484d); color: #fff; }
  .toggle:not(:disabled):hover { filter: brightness(1.05); }

  .dial {
    margin-top: 22px;
    padding: 18px;
    border: 1px solid #2a2a31;
    border-radius: 14px;
    background: #1c1c21;
  }
  .dial-head { display: flex; align-items: baseline; justify-content: space-between; }
  .dial-head label { font-size: 14px; font-weight: 600; color: #d6d6dd; }
  .power-value { font-size: 26px; font-weight: 800; color: #3ecf8e; font-variant-numeric: tabular-nums; }

  input[type="range"] {
    -webkit-appearance: none; appearance: none;
    width: 100%; height: 8px; margin: 16px 0 12px;
    border-radius: 6px; cursor: pointer;
    background: linear-gradient(90deg, #3ecf8e 0%, #3ecf8e var(--fill, 50%), #2f2f37 var(--fill, 50%));
  }
  input[type="range"]::-webkit-slider-thumb {
    -webkit-appearance: none; appearance: none;
    width: 22px; height: 22px; border-radius: 50%;
    background: #fff; border: 3px solid #3ecf8e; cursor: grab;
    box-shadow: 0 2px 6px rgba(0,0,0,0.4);
  }
  input[type="range"]::-moz-range-thumb {
    width: 20px; height: 20px; border-radius: 50%;
    background: #fff; border: 3px solid #3ecf8e; cursor: grab;
  }

  .dial-foot { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
  .tier { font-size: 13px; font-weight: 700; color: #e9e9ee; }
  .hint { font-size: 12px; color: #8b8b93; text-align: right; }
  .dial-note { margin: 12px 0 0; font-size: 11.5px; line-height: 1.5; color: #7c7c85; }

  .message {
    margin: 18px 2px 0;
    min-height: 18px;
    font-size: 12.5px;
    color: #b9b9c2;
  }

  .log-wrap { margin-top: 18px; }
  .log-head {
    display: flex; align-items: center; justify-content: space-between;
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; color: #6f6f78; margin-bottom: 6px;
  }
  .clear {
    background: none; border: none; color: #6f6f78; cursor: pointer;
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; padding: 0;
  }
  .clear:hover { color: #a9a9b3; }
  .log {
    height: 150px; overflow-y: auto;
    padding: 10px 12px;
    border: 1px solid #2a2a31; border-radius: 10px; background: #101013;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    font-size: 11.5px; line-height: 1.55; color: #9fd8bd;
    -webkit-user-select: text; user-select: text;
  }
  .log-empty { color: #55555e; }
  .log-line { white-space: pre-wrap; word-break: break-word; }
`;

// Live destination feed.
//
// A projection strips every field the sidecar is not permitted to send, so a future
// field leak cannot render. INV-11's operator-log half, exactly: the allowlist entry
// id, the allowlisted hostname and the address it resolved to -- the three destination
// facts the operator read on screen and signed -- plus byte counts, a sequence number
// and an outcome. No path, no query string, no header, no cookie, no body byte.
//
// POLLING IS THE ONLY SOURCE TODAY. The shell has zero Tauri events and this lane adds
// none: the sidecar's line-delimited event stream is its stdout, and the one spawn path
// (`goat_proxy_worker::supervisor::ProxySupervisor::spawn_pinned`) owns the child and
// exposes no reader for it. The `push` action below is the reducer's entry point for
// that stream and is deliberately NOT wired to anything: rather than pretend, the
// status carries `egress_stream_attached` and the screen says the feed is not being
// observed. An unobserved feed rendering as "nothing was contacted" is the same lie
// `SocketsAfter::Unverified` exists to prevent.
export const EGRESS_MAX_ROWS = 200;

const ALLOWED_KEYS = [
  "allowlist_entry_id",
  "at_unix_ms",
  "bytes_in",
  "bytes_out",
  "host",
  "outcome",
  "resolved_ip",
  "seq",
];

function project(event) {
  const row = {};
  for (const k of ALLOWED_KEYS) {
    const numeric = k.startsWith("bytes") || k === "seq" || k === "at_unix_ms";
    row[k] = event?.[k] ?? (numeric ? 0 : "");
  }
  return row;
}

export function initialEgressState() {
  return { rows: [], highestSeq: 0, gapDetected: false };
}

function merge(rows, incoming) {
  const bySeq = new Map(rows.map((r) => [r.seq, r]));
  for (const e of incoming) bySeq.set(Number(e?.seq ?? 0), project(e));
  return [...bySeq.values()].sort((a, b) => b.seq - a.seq).slice(0, EGRESS_MAX_ROWS);
}

export function egressReducer(state, action) {
  if (action.type === "push") {
    const seq = Number(action.event?.seq ?? 0);
    const gap = state.highestSeq > 0 && seq > state.highestSeq + 1;
    return {
      rows: merge(state.rows, [action.event]),
      highestSeq: Math.max(state.highestSeq, seq),
      gapDetected: state.gapDetected || gap,
    };
  }
  if (action.type === "reconcile") {
    const events = Array.isArray(action.events) ? action.events : [];
    const highest = events.reduce((m, e) => Math.max(m, Number(e?.seq ?? 0)), state.highestSeq);
    return { rows: merge(state.rows, events), highestSeq: highest, gapDetected: false };
  }
  if (action.type === "clear") return initialEgressState();
  return state;
}

/** True when the polled authority knows of events the feed never delivered. */
export function needsReconcile(state, pollLastSeq) {
  return state.gapDetected || Number(pollLastSeq ?? 0) > state.highestSeq;
}

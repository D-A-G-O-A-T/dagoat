import { describe, expect, it } from "vitest";
import { EGRESS_MAX_ROWS, egressReducer, initialEgressState, needsReconcile } from "./egressFeed.js";

const ev = (seq, over = {}) => ({
  seq,
  at_unix_ms: 1_780_000_000_000 + seq,
  allowlist_entry_id: "crossref-api",
  host: "api.crossref.org",
  resolved_ip: "192.0.2.1",
  bytes_out: 100,
  bytes_in: 900,
  sockets_open: 1,
  spent_today: 1_000 * seq,
  outcome: "allowed",
  ...over,
});

const reduce = (actions, start = initialEgressState()) => actions.reduce(egressReducer, start);

describe("egress feed reducer", () => {
  it("appends pushed events newest-first", () => {
    const s = reduce([
      { type: "push", event: ev(1) },
      { type: "push", event: ev(2) },
      { type: "push", event: ev(3) },
    ]);
    expect(s.rows.map((r) => r.seq)).toEqual([3, 2, 1]);
    expect(s.highestSeq).toBe(3);
    expect(s.gapDetected).toBe(false);
  });

  /// Mutations this detects: dropping the gap test, which turns a lossy feed into a
  /// silently incomplete one -- the operator sees a list that looks complete.
  it("a sequence gap triggers a reconciliation read", () => {
    const s = reduce([
      { type: "push", event: ev(1) },
      { type: "push", event: ev(5) },
    ]);
    expect(s.gapDetected).toBe(true);
    expect(needsReconcile(s, 5)).toBe(true);
  });

  it("a poll whose last_seq runs ahead of the feed triggers a reconciliation read", () => {
    const s = reduce([{ type: "push", event: ev(1) }]);
    expect(s.gapDetected).toBe(false);
    expect(needsReconcile(s, 9)).toBe(true);
    // POSITIVE CONTROL: a poll that agrees with the feed asks for nothing.
    expect(needsReconcile(s, 1)).toBe(false);
  });

  /// Mutations this detects: merging by array concat instead of by seq, which
  /// duplicates every re-read row; or forgetting to clear the flag, which makes the
  /// screen claim a permanent gap.
  it("reconciliation merges without duplicating and clears the gap flag", () => {
    let s = reduce([
      { type: "push", event: ev(1) },
      { type: "push", event: ev(5) },
    ]);
    s = egressReducer(s, { type: "reconcile", events: [ev(2), ev(3), ev(4), ev(5)] });
    expect(s.rows.map((r) => r.seq)).toEqual([5, 4, 3, 2, 1]);
    expect(s.gapDetected).toBe(false);
    expect(s.highestSeq).toBe(5);
  });

  it("out-of-order arrivals do not corrupt the highest sequence", () => {
    const s = reduce([
      { type: "push", event: ev(7) },
      { type: "push", event: ev(6) },
    ]);
    expect(s.highestSeq).toBe(7);
    expect(s.rows.map((r) => r.seq)).toEqual([7, 6]);
  });

  it("the ring is bounded", () => {
    const s = reduce(
      Array.from({ length: EGRESS_MAX_ROWS + 50 }, (_, i) => ({ type: "push", event: ev(i + 1) })),
    );
    expect(s.rows).toHaveLength(EGRESS_MAX_ROWS);
    expect(s.rows[0].seq).toBe(EGRESS_MAX_ROWS + 50);
  });

  /// Mutations this detects: spreading the raw event into the row (`{...event}`),
  /// which renders whatever a future sidecar field carries -- a path, a query string
  /// or a header -- straight onto the operator's screen and into a screenshot.
  it("no row carries a path, query string, header or body field", () => {
    const hostile = ev(1, {
      url: "https://api.crossref.org/works?q=secret",
      path: "/works",
      query: "q=secret",
      headers: { cookie: "sid=1" },
      body: "…",
    });
    const s = egressReducer(initialEgressState(), { type: "push", event: hostile });
    expect(Object.keys(s.rows[0]).sort()).toEqual([
      "allowlist_entry_id",
      "at_unix_ms",
      "bytes_in",
      "bytes_out",
      "host",
      "outcome",
      "resolved_ip",
      "seq",
    ]);
    // POSITIVE CONTROL: the eight permitted facts really did survive the projection,
    // so the key-set assertion above is not passing against an empty row.
    expect(s.rows[0].host).toBe("api.crossref.org");
    expect(s.rows[0].resolved_ip).toBe("192.0.2.1");
    expect(s.rows[0].bytes_in).toBe(900);
  });

  /// Mutations this detects: filtering the feed to allowed outcomes, which hides
  /// exactly the rows that prove the allowlist is doing anything.
  it("a refusal is retained and rendered, not dropped", () => {
    const s = reduce([
      { type: "push", event: ev(1, { outcome: "refused_not_allowlisted", bytes_in: 0, bytes_out: 0 }) },
      { type: "push", event: ev(2) },
    ]);
    expect(s.rows).toHaveLength(2);
    expect(s.rows.find((r) => r.seq === 1).outcome).toBe("refused_not_allowlisted");
  });

  it("clear resets to the initial state", () => {
    const s = reduce([{ type: "push", event: ev(1) }, { type: "clear" }]);
    expect(s).toEqual(initialEgressState());
  });

  it("an unknown action leaves the state identical", () => {
    const s = reduce([{ type: "push", event: ev(1) }]);
    expect(egressReducer(s, { type: "nope" })).toBe(s);
  });
});

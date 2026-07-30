import { describe, expect, it, vi } from "vitest";
import {
  GAS_DRIP_ACCESS_GATE_COPY,
  GAS_DRIP_IN_PROGRESS_COPY,
  GAS_DRIP_LIMIT_COPY,
  GAS_DRIP_NO_GOAT_COPY,
  GAS_DRIP_SEND_FAILED_COPY,
  GAS_DRIP_UNAVAILABLE_COPY,
  GAS_DRIP_UNREACHABLE_COPY,
  gasDripMessage,
  requestGasDrip,
} from "./gasDrip.js";

/** Mock Response: Stream C T4 reads body via text(), not json(). */
function jsonRes(status, body) {
  const text = JSON.stringify(body);
  return {
    status,
    text: async () => text,
    json: async () => body,
  };
}

describe("requestGasDrip", () => {
  it("posts wallet and returns parsed body + status", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonRes(200, { ok: true, tx_hash: "0x1", remaining_today: 2 }),
    );
    const r = await requestGasDrip("0xA", { fetchImpl, base: "http://x" });
    expect(fetchImpl).toHaveBeenCalledWith(
      "http://x/v1/relay/gas-drip",
      expect.objectContaining({ method: "POST" }),
    );
    expect(r).toMatchObject({ ok: true, tx_hash: "0x1", remaining_today: 2, status: 200 });
  });

  it("maps a thrown fetch to a soft network error", async () => {
    const r = await requestGasDrip("0xA", {
      fetchImpl: async () => {
        throw new Error("down");
      },
      base: "http://x",
    });
    expect(r).toMatchObject({ ok: false, error: "network", status: 0 });
  });

  it("sends the wallet as JSON body", async () => {
    const fetchImpl = vi.fn(async () => jsonRes(200, { ok: true }));
    await requestGasDrip("0xWALLET", { fetchImpl, base: "http://x" });
    const [, init] = fetchImpl.mock.calls[0];
    expect(JSON.parse(init.body)).toEqual({ wallet: "0xWALLET" });
    expect(init.headers).toMatchObject({ "Content-Type": "application/json" });
  });

  it("treats amount_wei as an opaque string, never coercing to Number", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonRes(200, {
        ok: true,
        tx_hash: "0x2",
        amount_wei: "270000000000000",
        remaining_today: 0,
      }),
    );
    const r = await requestGasDrip("0xA", { fetchImpl, base: "http://x" });
    expect(typeof r.amount_wei).toBe("string");
    expect(r.amount_wei).toBe("270000000000000");
    expect(BigInt(r.amount_wei)).toBe(270000000000000n);
  });

  it("passes through 429 DailyLimitReached with status", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonRes(429, { error: "DailyLimitReached", limit: 1, resets_at: "2026-07-20T00:00:00Z" }),
    );
    const r = await requestGasDrip("0xA", { fetchImpl, base: "http://x" });
    expect(r).toMatchObject({
      ok: false,
      error: "DailyLimitReached",
      limit: 1,
      resets_at: "2026-07-20T00:00:00Z",
      status: 429,
    });
  });

  it("passes through 400 NoGoatToSell with status", async () => {
    const fetchImpl = vi.fn(async () => jsonRes(400, { error: "NoGoatToSell" }));
    const r = await requestGasDrip("0xA", { fetchImpl, base: "http://x" });
    expect(r).toMatchObject({ ok: false, error: "NoGoatToSell", status: 400 });
  });

  it("passes through a non-NoGoatToSell 400 (bad-address) intact", async () => {
    const fetchImpl = vi.fn(async () => jsonRes(400, { error: "InvalidAddress" }));
    const r = await requestGasDrip("0xNOTANADDRESS", { fetchImpl, base: "http://x" });
    expect(r).toMatchObject({ ok: false, error: "InvalidAddress", status: 400 });
  });

  it("passes through 409 DripInProgress with status", async () => {
    const fetchImpl = vi.fn(async () => jsonRes(409, { error: "DripInProgress" }));
    const r = await requestGasDrip("0xA", { fetchImpl, base: "http://x" });
    expect(r).toMatchObject({ ok: false, error: "DripInProgress", status: 409 });
  });

  it("passes through 503 GasDripDisabled with status", async () => {
    const fetchImpl = vi.fn(async () => jsonRes(503, { error: "GasDripDisabled" }));
    const r = await requestGasDrip("0xA", { fetchImpl, base: "http://x" });
    expect(r).toMatchObject({ ok: false, error: "GasDripDisabled", status: 503 });
  });

  it("passes through 502 DripSendFailed with quota_consumed flag", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonRes(502, { error: "DripSendFailed", quota_consumed: true }),
    );
    const r = await requestGasDrip("0xA", { fetchImpl, base: "http://x" });
    expect(r).toMatchObject({
      ok: false,
      error: "DripSendFailed",
      quota_consumed: true,
      status: 502,
    });
  });

  it("defaults base to RELAYER_URL when not provided", async () => {
    const fetchImpl = vi.fn(async () => jsonRes(200, { ok: true }));
    await requestGasDrip("0xA", { fetchImpl });
    const [url] = fetchImpl.mock.calls[0];
    expect(url).toMatch(/\/v1\/relay\/gas-drip$/);
  });

  it("maps HTML / Access-gate bodies to AccessGateOrNonJson (not a throw)", async () => {
    const fetchImpl = vi.fn(async () => ({
      status: 403,
      text: async () => "<!DOCTYPE html><html>cloudflare access login</html>",
    }));
    const r = await requestGasDrip("0xA", { fetchImpl, base: "http://x" });
    expect(r).toMatchObject({ ok: false, error: "AccessGateOrNonJson", status: 403 });
  });

  it("maps a non-JSON 200 body to soft AccessGateOrNonJson", async () => {
    const fetchImpl = vi.fn(async () => ({
      status: 200,
      text: async () => "not-json-at-all",
    }));
    const r = await requestGasDrip("0xA", { fetchImpl, base: "http://x" });
    expect(r).toMatchObject({ ok: false, status: 200, error: "AccessGateOrNonJson" });
  });
});

describe("gasDripMessage", () => {
  it("429 -> limit copy (cap-agnostic)", () => {
    expect(gasDripMessage({ status: 429, error: "DailyLimitReached" })).toBe(GAS_DRIP_LIMIT_COPY);
  });

  it("400 NoGoatToSell -> no-GOAT copy", () => {
    expect(gasDripMessage({ status: 400, error: "NoGoatToSell" })).toBe(GAS_DRIP_NO_GOAT_COPY);
  });

  it("400 non-NoGoatToSell (bad address) -> unavailable copy, NOT no-GOAT copy", () => {
    const msg = gasDripMessage({ status: 400, error: "InvalidAddress" });
    expect(msg).toBe(GAS_DRIP_UNAVAILABLE_COPY);
    expect(msg).not.toBe(GAS_DRIP_NO_GOAT_COPY);
  });

  it("409 -> in-progress copy", () => {
    expect(gasDripMessage({ status: 409, error: "DripInProgress" })).toBe(GAS_DRIP_IN_PROGRESS_COPY);
  });

  it("502 DripSendFailed -> send-failed copy (states quota was consumed)", () => {
    expect(gasDripMessage({ status: 502, error: "DripSendFailed", quota_consumed: true })).toBe(
      GAS_DRIP_SEND_FAILED_COPY,
    );
  });

  it("502 other error -> unavailable copy (not the send-failed copy)", () => {
    expect(gasDripMessage({ status: 502, error: "SomethingElse" })).toBe(GAS_DRIP_UNAVAILABLE_COPY);
  });

  it("503 GasDripDisabled -> unavailable copy", () => {
    expect(gasDripMessage({ status: 503, error: "GasDripDisabled" })).toBe(GAS_DRIP_UNAVAILABLE_COPY);
  });

  it("503 RelayerUnderfunded -> unavailable copy", () => {
    expect(gasDripMessage({ status: 503, error: "RelayerUnderfunded" })).toBe(GAS_DRIP_UNAVAILABLE_COPY);
  });

  it("503 GasDripLedgerUnavailable -> unavailable copy", () => {
    expect(gasDripMessage({ status: 503, error: "GasDripLedgerUnavailable" })).toBe(
      GAS_DRIP_UNAVAILABLE_COPY,
    );
  });

  it("network error (status 0) -> its own copy, which admits the quota state is unknown", () => {
    const msg = gasDripMessage({ status: 0, error: "network" });
    expect(msg).toBe(GAS_DRIP_UNREACHABLE_COPY);
    expect(msg).not.toBe(GAS_DRIP_UNAVAILABLE_COPY);
    expect(msg).toMatch(/no way to tell/i);
  });

  it("Access gate / HTML body -> access-gate copy", () => {
    expect(gasDripMessage({ status: 403, error: "AccessGateOrNonJson" })).toBe(GAS_DRIP_ACCESS_GATE_COPY);
    expect(GAS_DRIP_ACCESS_GATE_COPY).not.toMatch(/anvil|8545|8787/i);
  });

  it("429 renders the server's resets_at instead of the hardcoded fallback", () => {
    const msg = gasDripMessage({
      status: 429,
      error: "DailyLimitReached",
      resets_at: "2026-07-21T00:00:00Z",
    });
    expect(msg).toContain("2026-07-21T00:00:00Z");
    expect(msg).not.toContain("00:00 UTC");
  });

  it("429 without resets_at keeps the fallback wording", () => {
    expect(gasDripMessage({ status: 429, error: "DailyLimitReached" })).toBe(GAS_DRIP_LIMIT_COPY);
    expect(gasDripMessage({ status: 429, resets_at: "   " })).toBe(GAS_DRIP_LIMIT_COPY);
  });
});

describe("copy laws (07_Tokenomics_Framework honesty rules + locked decisions)", () => {
  const ALL_GAS_DRIP_COPY = [
    GAS_DRIP_LIMIT_COPY,
    GAS_DRIP_SEND_FAILED_COPY,
    GAS_DRIP_NO_GOAT_COPY,
    GAS_DRIP_IN_PROGRESS_COPY,
    GAS_DRIP_UNAVAILABLE_COPY,
    GAS_DRIP_UNREACHABLE_COPY,
    GAS_DRIP_ACCESS_GATE_COPY,
  ];

  const FORBIDDEN = [/\bwage\b/i, /\bincome\b/i, /\bprofit\b/i, /\bsalary\b/i, /\bearn(ing)?s?\b/i];

  it("no forbidden wage/income/profit/salary/earning vocabulary in gas-drip copy", () => {
    for (const s of ALL_GAS_DRIP_COPY) {
      for (const re of FORBIDDEN) {
        expect(s, `"${s}" matches forbidden ${re}`).not.toMatch(re);
      }
    }
  });

  it("the 502 send-failed copy is honest that today's drip is used up", () => {
    expect(GAS_DRIP_SEND_FAILED_COPY).toMatch(/didn't go through/i);
    expect(GAS_DRIP_SEND_FAILED_COPY).toMatch(/used today's gasless sell/i);
  });
});

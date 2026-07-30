import { describe, expect, it, vi } from "vitest";
import { causeLabel, resolveCause, fetchProjectCause, GENERIC_CAUSE_LABEL } from "./causes.js";

describe("causeLabel", () => {
  it("maps known FAH slugs to friendly research labels", () => {
    expect(causeLabel("cancer")).toBe("Cancer research");
    expect(causeLabel("alzheimers")).toBe("Alzheimer's research");
    expect(causeLabel("ALZHEIMERS")).toBe("Alzheimer's research"); // case-insensitive
    expect(causeLabel("covid-19")).toBe("COVID-19 research");
  });
  it("honest fallback for unknown/any/empty (spec: never invent claims)", () => {
    expect(causeLabel("any")).toBe(GENERIC_CAUSE_LABEL);
    expect(causeLabel("")).toBe(GENERIC_CAUSE_LABEL);
    expect(causeLabel(undefined)).toBe(GENERIC_CAUSE_LABEL);
    expect(causeLabel("mystery-slug")).toBe(GENERIC_CAUSE_LABEL);
  });
});

describe("resolveCause tier order (spec §7: unit → project → config → generic)", () => {
  it("prefers per-unit, then project metadata, then config", () => {
    expect(resolveCause({ unitCause: "cancer", projectCause: "parkinsons", configCause: "any" }))
      .toBe("Cancer research");
    expect(resolveCause({ unitCause: null, projectCause: "parkinsons", configCause: "any" }))
      .toBe("Parkinson's research");
    expect(resolveCause({ unitCause: null, projectCause: null, configCause: "influenza" }))
      .toBe("Influenza research");
    expect(resolveCause({})).toBe(GENERIC_CAUSE_LABEL);
  });
});

describe("fetchProjectCause", () => {
  it("fetches once per project id (cached) and returns the cause", async () => {
    const fetchFn = vi.fn(async () => ({ ok: true, json: async () => ({ cause: "cancer" }) }));
    expect(await fetchProjectCause("18201", fetchFn)).toBe("cancer");
    expect(await fetchProjectCause("18201", fetchFn)).toBe("cancer");
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });
  it("returns null on failure without throwing", async () => {
    const fetchFn = vi.fn(async () => { throw new Error("offline"); });
    expect(await fetchProjectCause("99999", fetchFn)).toBeNull();
  });
});

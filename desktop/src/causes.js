// Science-tag resolution (spec §7). Labels only restate what FAH reports —
// unknown slugs collapse to the honest generic label, never an invented claim.
export const GENERIC_CAUSE_LABEL = "General biomedical research";

const CAUSE_LABELS = {
  cancer: "Cancer research",
  alzheimers: "Alzheimer's research",
  huntingtons: "Huntington's research",
  parkinsons: "Parkinson's research",
  influenza: "Influenza research",
  diabetes: "Diabetes research",
  "covid-19": "COVID-19 research",
};

export function causeLabel(slug) {
  const key = String(slug ?? "").trim().toLowerCase();
  if (!key || key === "any" || key === "unspecified") return GENERIC_CAUSE_LABEL;
  return CAUSE_LABELS[key] ?? GENERIC_CAUSE_LABEL;
}

/** Tier order: per-unit assignment.cause → project metadata → client config → generic. */
export function resolveCause({ unitCause, projectCause, configCause } = {}) {
  return causeLabel(unitCause || projectCause || configCause);
}

import { readAppState, writeAppState } from "./onboarding/appState.js";

const projectCauseCache = new Map(); // projectId → Promise<string|null>

/** Cached project-metadata cause (same endpoint FahPreview already uses).
 *  In-memory first, then the Tauri store (spec §7: "in-memory + store cache"),
 *  then the network. Store calls fail soft outside Tauri. */
export function fetchProjectCause(projectId, fetchFn = fetch) {
  const id = String(projectId ?? "").trim();
  if (!id || id === "0" || id === "unknown") return Promise.resolve(null);
  if (!projectCauseCache.has(id)) {
    const p = (async () => {
      const stored = await readAppState(`project_cause:${id}`, null);
      if (stored) return String(stored);
      try {
        const r = await fetchFn(`https://api.foldingathome.org/project/${encodeURIComponent(id)}`);
        const data = r.ok ? await r.json() : null;
        const cause = data?.cause ? String(data.cause) : null;
        if (cause) await writeAppState(`project_cause:${id}`, cause);
        return cause;
      } catch {
        return null;
      }
    })();
    projectCauseCache.set(id, p);
  }
  return projectCauseCache.get(id);
}

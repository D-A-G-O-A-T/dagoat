// Single Tauri-store file for app-level flags (spec §10). autoSave off + explicit
// save, same pattern as journal.js. Outside Tauri every call fails soft.
import { load } from "@tauri-apps/plugin-store";

const FILE = "app-state.dat";
let storePromise = null;
function store() {
  if (!storePromise) storePromise = load(FILE, { autoSave: false });
  return storePromise;
}

export async function readAppState(key, fallback = null) {
  try {
    const s = await store();
    const v = await s.get(key);
    return v === undefined || v === null ? fallback : v;
  } catch (err) {
    console.error("appState read failed", key, err);
    return fallback;
  }
}

export async function writeAppState(key, value) {
  try {
    const s = await store();
    await s.set(key, value);
    await s.save();
    return true;
  } catch (err) {
    console.error("appState write failed", key, err);
    return false;
  }
}

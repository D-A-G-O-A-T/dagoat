// External links must go through the opener plugin: Tauri's webview (wry) drops
// target="_blank" new-window requests, so plain anchors are dead in the packaged app.
import { openUrl } from "@tauri-apps/plugin-opener";

export async function openExternal(url) {
  try {
    await openUrl(url);
  } catch {
    // Plain-browser dev (vite without Tauri): fall back to a normal open.
    window.open(url, "_blank", "noreferrer");
  }
}

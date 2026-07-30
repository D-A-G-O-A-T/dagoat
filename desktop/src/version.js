// Single source of truth for the app version shown in the UI.
//
// Canonical version lives in package.json (`version`). Cargo.toml and
// tauri.conf.json are kept in sync with it by hand (see PATCHNOTES.md and the
// "PATCHNOTES.md Convention — Notice to Consultant + Advisor" notice for the
// bump procedure) — version.test.js asserts this file can't silently drift
// from package.json.
//
// Do not hardcode the version number anywhere else in the UI; import
// APP_VERSION / APP_VERSION_LABEL from here instead.
export const APP_VERSION = "0.1.0";

export const APP_VERSION_LABEL = `v${APP_VERSION} · testnet`;

// Prevents an extra console window on Windows in release builds. See:
// https://tauri.app/v1/guides/features/debugging#stopping-the-console-window
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    dagoat_lib::run();
}

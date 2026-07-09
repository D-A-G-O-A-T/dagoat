//! D.A. G.O.A.T. — Tauri v2 backend.
//!
//! Bundles the existing `goatd` binary as a **sidecar** and gives the user a 1–100% "Power Dial".
//! Because the desktop build has no Docker cgroups, we cap heat/fan noise with **OS-level process
//! priority** instead: the dial maps to a Windows priority class or a Unix `nice` value applied to
//! the spawned child. This is an alpha-stage control — it nudges the scheduler, it does not hard-cap
//! CPU — and it never touches the daemon's own consensus logic.

use std::sync::Mutex;

use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

/// The single running-node handle, plus the last power level the user selected. `CommandChild` is the
/// sidecar's process handle — kept so we can re-target its priority live and terminate it cleanly.
#[derive(Default)]
struct NodeState {
    child: Mutex<Option<CommandChild>>,
    power_level: Mutex<u8>,
}

// ===========================================================================
// OS-level priority control (the Power Dial → scheduler mapping)
// ===========================================================================
//
// Tiers (power dial label → OS scheduler class):
//   1–30%   → "idle"   (Windows IDLE_PRIORITY_CLASS          / Unix nice 19)
//   31–60%  → "normal" (Windows BELOW_NORMAL_PRIORITY_CLASS  / Unix nice 10)
//   61–100% → "high"   (Windows NORMAL_PRIORITY_CLASS        / Unix nice 0)
//
// All Unix nice values are ≥ 0, so an unprivileged user can always lower priority (raising it would
// need CAP_SYS_NICE / root — we never do).

/// A short human-readable name for the tier a power level falls into (used in status messages).
fn tier_name(power_level: u8) -> &'static str {
    match power_level {
        1..=30 => "idle",
        31..=60 => "normal",
        _ => "high",
    }
}

#[cfg(target_os = "windows")]
fn apply_priority(pid: u32, power_level: u8) -> Result<(), String> {
    use windows::Win32::Foundation::{CloseHandle, FALSE};
    use windows::Win32::System::Threading::{
        OpenProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS, IDLE_PRIORITY_CLASS,
        NORMAL_PRIORITY_CLASS, PROCESS_SET_INFORMATION,
    };

    let class = match power_level {
        1..=30 => IDLE_PRIORITY_CLASS,
        31..=60 => BELOW_NORMAL_PRIORITY_CLASS,
        _ => NORMAL_PRIORITY_CLASS,
    };

    // SAFETY: standard Win32 calls; we open a handle to our own child by pid with the minimal access
    // right, set its priority class, and always close the handle.
    unsafe {
        let handle = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid)
            .map_err(|e| format!("OpenProcess({pid}) failed: {e}"))?;
        let result = SetPriorityClass(handle, class);
        let _ = CloseHandle(handle);
        result.map_err(|e| format!("SetPriorityClass failed: {e}"))?;
    }
    Ok(())
}

#[cfg(unix)]
fn apply_priority(pid: u32, power_level: u8) -> Result<(), String> {
    let nice: libc::c_int = match power_level {
        1..=30 => 19,
        31..=60 => 10,
        _ => 0,
    };

    // SAFETY: `setpriority` is a simple, total syscall. We target our own child (PRIO_PROCESS, pid).
    // `errno` is only meaningful when the call returns -1.
    let ret = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice) };
    if ret == -1 {
        return Err(format!(
            "setpriority(pid={pid}, nice={nice}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn apply_priority(_pid: u32, _power_level: u8) -> Result<(), String> {
    // No priority backend on this target — treat as a no-op so the node still runs.
    Ok(())
}

// ===========================================================================
// Tauri commands (the frontend calls these)
// ===========================================================================

/// Start the `goatd` sidecar at `power_level` (1–100), apply the corresponding OS priority to the
/// child, and stream its stdout/stderr to the frontend via the `node-log` event. Returns a friendly
/// message; errors are returned as `Err(String)` for the UI to display.
#[tauri::command]
fn start_goat_node(
    power_level: u8,
    app: AppHandle,
    state: State<'_, NodeState>,
) -> Result<String, String> {
    // Refuse if a node is already running (guard scoped so no lock is held past this block).
    if state.child.lock().unwrap().is_some() {
        return Err("A node is already running. Stop it before starting a new one.".into());
    }

    let power = power_level.clamp(1, 100);
    *state.power_level.lock().unwrap() = power;

    // Spawn the sidecar via Tauri's shell plugin. The `--throttle-target` fraction (power/100) makes
    // the daemon log its intended quota; the real control here is the OS priority we set below.
    let fraction = format!("{:.2}", power as f64 / 100.0);
    let (mut rx, child) = app
        .shell()
        .sidecar("goatd")
        .map_err(|e| format!("could not locate the goatd sidecar: {e}"))?
        .args([
            "--listen=127.0.0.1:4646".to_string(),
            "--seed".to_string(),
            format!("--throttle-target={fraction}"),
        ])
        .spawn()
        .map_err(|e| format!("failed to spawn goatd: {e}"))?;

    let pid = child.pid();

    // Apply the OS priority. A failure here is non-fatal: the node still runs, we just warn the UI.
    if let Err(e) = apply_priority(pid, power) {
        let _ = app.emit("node-log", format!("[warn] priority not applied: {e}"));
    }

    // Retain the child handle so we can re-prioritize / kill it later.
    *state.child.lock().unwrap() = Some(child);

    // Pump the daemon's output to the UI, and notify it when the process exits.
    let sink = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes) => {
                    let line = String::from_utf8_lossy(&bytes).trim_end().to_string();
                    if !line.is_empty() {
                        let _ = sink.emit("node-log", line);
                    }
                }
                CommandEvent::Error(err) => {
                    let _ = sink.emit("node-log", format!("[error] {err}"));
                }
                CommandEvent::Terminated(payload) => {
                    let _ = sink.emit(
                        "node-log",
                        format!("goatd exited (code {:?})", payload.code),
                    );
                    if let Some(state) = sink.try_state::<NodeState>() {
                        *state.child.lock().unwrap() = None;
                    }
                    let _ = sink.emit("node-stopped", ());
                    break;
                }
                _ => {}
            }
        }
    });

    Ok(format!(
        "Node started at {power}% power — {} priority (pid {pid}).",
        tier_name(power)
    ))
}

/// Stop the running sidecar (if any) by killing the retained child handle.
#[tauri::command]
fn stop_goat_node(state: State<'_, NodeState>) -> Result<String, String> {
    let child = state.child.lock().unwrap().take();
    match child {
        Some(child) => {
            child
                .kill()
                .map_err(|e| format!("failed to stop the node: {e}"))?;
            Ok("Node stopped.".into())
        }
        None => Err("No node is running.".into()),
    }
}

/// Update the Power Dial. Always records the new level (so it applies on the next start); if a node
/// is currently running, re-applies the matching OS priority to it **live**.
#[tauri::command]
fn set_power_level(power_level: u8, state: State<'_, NodeState>) -> Result<String, String> {
    let power = power_level.clamp(1, 100);
    *state.power_level.lock().unwrap() = power;

    let pid = state.child.lock().unwrap().as_ref().map(|c| c.pid());
    match pid {
        Some(pid) => {
            apply_priority(pid, power).map_err(|e| format!("could not update priority: {e}"))?;
            Ok(format!(
                "Power set to {power}% — {} priority applied live.",
                tier_name(power)
            ))
        }
        None => Ok(format!(
            "Power set to {power}% — will apply on next start ({} priority).",
            tier_name(power)
        )),
    }
}

// ===========================================================================
// App entry point
// ===========================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(NodeState {
            child: Mutex::new(None),
            power_level: Mutex::new(50),
        })
        .invoke_handler(tauri::generate_handler![
            start_goat_node,
            stop_goat_node,
            set_power_level
        ])
        .run(tauri::generate_context!())
        .expect("error while running the D.A. G.O.A.T. application");
}

//! D.A. G.O.A.T. — Tauri v2 backend.
//!
//! Season 0 scope (Task S4, desktop bootstrap): this is the desktop **shell** only. The `goatd`
//! mesh-node sidecar is out of scope for Season 0 — see `ARCHITECTURE_CONVERGENCE.md` and
//! `docs/superpowers/plans/2026-07-11-season0-fullsystem.md` — so the old node start/stop/power
//! commands (which spawned `goatd` as an external-bin sidecar) are removed along with the
//! `externalBin` entry in `tauri.conf.json`.
//!
//! Task S5 adds the `WorkBackend` plugin plane (see `workbackend` module docs): a catalog the
//! Miner UI renders from, a trait-object registry, and thin Tauri command wrappers over it. Real
//! FAH control (Task S6) and chain/tab content (S7–S9) land in later tasks.

mod wallet;
mod workbackend;

use wallet::WalletState;
use workbackend::catalog::CatalogEntry;
use workbackend::fah::FahVizSnapshot;
use workbackend::{
    BackendStatus, EngineReport, EngineState, InstallState, PowerLevel, Registry, WorkUnit,
};

/// Trivial IPC smoke test: proves the frontend↔backend Tauri bridge is wired up.
#[tauri::command]
fn ping() -> String {
    "pong".to_string()
}

#[tauri::command]
fn catalog_list(registry: tauri::State<Registry>) -> Vec<CatalogEntry> {
    workbackend::catalog::catalog_entries(&registry)
}

#[tauri::command]
fn backend_detect(registry: tauri::State<Registry>, id: String) -> Result<InstallState, String> {
    registry.get(&id).map(|backend| backend.detect_install())
}

/// Surfaces `supports_managed_engine` to the UI (also keeps the trait method live for clippy).
#[tauri::command]
fn backend_supports_managed(registry: tauri::State<Registry>, id: String) -> Result<bool, String> {
    registry
        .get(&id)
        .map(|backend| backend.supports_managed_engine())
}

#[tauri::command]
async fn backend_connect(registry: tauri::State<'_, Registry>, id: String) -> Result<(), String> {
    registry.get(&id)?.connect().await
}

#[tauri::command]
async fn backend_disconnect(
    registry: tauri::State<'_, Registry>,
    id: String,
) -> Result<(), String> {
    registry.get(&id)?.disconnect().await
}

#[tauri::command]
async fn backend_start(registry: tauri::State<'_, Registry>, id: String) -> Result<(), String> {
    registry.get(&id)?.start().await
}

#[tauri::command]
async fn backend_stop(registry: tauri::State<'_, Registry>, id: String) -> Result<(), String> {
    registry.get(&id)?.stop().await
}

#[tauri::command]
async fn backend_pause(registry: tauri::State<'_, Registry>, id: String) -> Result<(), String> {
    registry.get(&id)?.pause().await
}

/// Dump (discard) a stuck FAH work unit by id — same recovery as Web Control dump.
#[tauri::command]
async fn backend_dump_unit(
    registry: tauri::State<'_, Registry>,
    id: String,
    unit_id: String,
) -> Result<(), String> {
    registry.get(&id)?.dump_unit(&unit_id).await
}

#[tauri::command]
async fn backend_status(
    registry: tauri::State<'_, Registry>,
    id: String,
) -> Result<BackendStatus, String> {
    Ok(registry.get(&id)?.status().await)
}

#[tauri::command]
async fn backend_completions(
    registry: tauri::State<'_, Registry>,
    id: String,
) -> Result<Vec<WorkUnit>, String> {
    Ok(registry.get(&id)?.list_completions().await)
}

#[tauri::command]
async fn backend_set_power(
    registry: tauri::State<'_, Registry>,
    id: String,
    level: PowerLevel,
) -> Result<(), String> {
    registry.get(&id)?.set_power(level).await
}

#[tauri::command]
fn backend_configure(
    registry: tauri::State<Registry>,
    id: String,
    key: String,
    value: String,
) -> Result<(), String> {
    registry.get(&id)?.configure(&key, &value)
}

#[tauri::command]
fn backend_engine_state(
    registry: tauri::State<Registry>,
    id: String,
) -> Result<EngineState, String> {
    registry.get(&id).map(|backend| backend.engine_state())
}

/// Managed-engine snapshot with live detail — the UI polls this while Missing/Provisioning so it
/// can show real installer download/EULA progress concurrently with a long-running `ensure_engine`.
#[tauri::command]
fn backend_engine_report(
    registry: tauri::State<Registry>,
    id: String,
) -> Result<EngineReport, String> {
    registry.get(&id).map(|backend| backend.engine_report())
}

#[tauri::command]
async fn backend_ensure_engine(
    registry: tauri::State<'_, Registry>,
    id: String,
) -> Result<EngineReport, String> {
    registry.get(&id)?.ensure_engine().await
}

/// Real FAH 3D viz data (viewerTop + latest viewerFrame) from the managed engine work/ tree.
/// Same on-disk frames FAH Web Control visualizes — not a decorative mesh.
#[tauri::command]
fn backend_fah_viz() -> Result<Option<FahVizSnapshot>, String> {
    workbackend::fah::load_fah_viz_snapshot()
}

/// FAH identity snapshot for the UI: username presence (first-run gate), effective team,
/// passkey_set / passkey_is_default (legacy brand). Never returns the passkey value.
#[tauri::command]
fn backend_fah_identity() -> workbackend::fah::FahIdentity {
    workbackend::fah::load_fah_identity()
}

#[tauri::command]
async fn backend_start_engine(
    registry: tauri::State<'_, Registry>,
    id: String,
) -> Result<EngineReport, String> {
    registry.get(&id)?.start_engine().await
}

#[tauri::command]
async fn backend_stop_engine(
    registry: tauri::State<'_, Registry>,
    id: String,
) -> Result<(), String> {
    registry.get(&id)?.stop_engine().await
}

/// Append panic / fatal text to `%LOCALAPPDATA%\com.goatcoin.dagoat\crash.log`
/// so a closed window can be diagnosed after the fact.
fn install_crash_log() {
    std::panic::set_hook(Box::new(|info| {
        let dir = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("com.goatcoin.dagoat");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("crash.log");
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".into());
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "non-string panic payload".into()
        };
        let line = format!(
            "[{}] PANIC at {}: {}\n",
            chrono_like_now(),
            loc,
            msg
        );
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(line.as_bytes())
            });
        // Also print so `cargo tauri dev` consoles capture it.
        eprintln!("{line}");
    }));
}

fn chrono_like_now() -> String {
    // Avoid extra deps: simple unix-ish timestamp.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "?".into())
}

fn append_app_log(filename: &str, line: &str) {
    let dir = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("com.goatcoin.dagoat");
    let _ = std::fs::create_dir_all(&dir);
    let msg = format!("[{}] {}\n", chrono_like_now(), line);
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(filename))
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(msg.as_bytes())
        });
    eprintln!("{msg}");
}

/// Background heartbeat so a hard kill leaves a timestamp trail in exit.log
/// (last beat ≈ time of death when no Exit/CloseRequested line appears).
fn start_heartbeat_log() {
    std::thread::spawn(|| {
        let mut n = 0u64;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(15));
            n += 1;
            append_app_log("exit.log", &format!("heartbeat n={n}"));
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    install_crash_log();
    append_app_log("exit.log", "app starting");
    start_heartbeat_log();
    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::default().build())
        // Stronghold is used directly from Rust (see wallet.rs) — no JS-facing
        // stronghold plugin is registered, so nothing is a decoy.
        .manage(workbackend::build_registry())
        .manage(WalletState::default())
        .invoke_handler(tauri::generate_handler![
            ping,
            wallet::wallet_list,
            wallet::wallet_create,
            wallet::wallet_import,
            wallet::wallet_unlock,
            wallet::wallet_lock,
            wallet::wallet_active,
            wallet::wallet_remove,
            wallet::wallet_sign_transaction,
            wallet::wallet_sign_message,
            wallet::wallet_sign_typed_data,
            catalog_list,
            backend_detect,
            backend_supports_managed,
            backend_connect,
            backend_disconnect,
            backend_start,
            backend_stop,
            backend_pause,
            backend_dump_unit,
            backend_status,
            backend_completions,
            backend_set_power,
            backend_configure,
            backend_engine_state,
            backend_engine_report,
            backend_ensure_engine,
            backend_fah_viz,
            backend_fah_identity,
            backend_start_engine,
            backend_stop_engine,
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            append_app_log("crash.log", &format!("BUILD/RUN ERROR: {e:?}"));
            panic!("error while building the D.A. G.O.A.T. application: {e}");
        })
        .run(|_app, event| {
            // Log clean exits so "app closed" without crash.log can be diagnosed.
            match event {
                tauri::RunEvent::ExitRequested { api: _, .. } => {
                    append_app_log("exit.log", "ExitRequested (window close or host stop)");
                }
                tauri::RunEvent::Exit => {
                    append_app_log("exit.log", "Exit (process shutting down)");
                }
                tauri::RunEvent::WindowEvent { label, event, .. } => {
                    if let tauri::WindowEvent::CloseRequested { .. } = event {
                        append_app_log(
                            "exit.log",
                            &format!("WindowEvent::CloseRequested label={label}"),
                        );
                    }
                }
                _ => {}
            }
        });
}

//! Folding@home adapter — the only real work backend of GoatCoin Season 0 (Task S6).
//!
//! Replaces the inert `catalog::FahStub` with a real adapter for the official **FAHClient v8**.
//! Two independent channels, per design §3
//! (`docs/superpowers/specs/2026-07-11-season0-fullsystem-design.md`):
//!
//! 1. **Control + live progress** — a WebSocket to the client's local API at
//!    `ws://127.0.0.1:7396/api/websocket`. On connect the client sends a full JSON state
//!    snapshot (a `units` array + a `config` object); afterwards it streams incremental updates
//!    (either JSON *patch* arrays `[path…, value]` or partial objects). Both forms are applied
//!    into a single `serde_json::Value` state tree and re-derived into `UnitProgress`. This
//!    channel is **display only** — it is *never* the mint basis.
//! 2. **Accepted completions (the mint basis)** — the FAH stats API
//!    `https://api.foldingathome.org/user/{username}` reports the beneficiary's own credited
//!    work-unit count (`wus`). The delta against a persisted baseline is what we mint against;
//!    the evidence is a SHA-256 of the raw stats response body. FAH's own servers are the
//!    crediting authority — local progress bars are decoration, credited WUs are money.
//!
//! **Honesty invariants (hard):** we never fabricate progress or completions. If the local API
//! is unreachable the status degrades to an actionable `error`, not a fake percentage. The first
//! stats poll only records a baseline — pre-existing WUs earned before the user bound this
//! machine are never retroactively minted. There is no fake FAH server anywhere in product code;
//! the protocol fixtures live entirely under `#[cfg(test)]`.
//!
//! **Interior mutability:** every `WorkBackend` method takes `&self`, so all mutable state lives
//! behind `Mutex`es: `persisted` (config + `last_credited_wus`, mirrored to an app-data JSON
//! file), `live` (the WS state tree + last-good units, shared with the background task), `stats`
//! (poll throttle + ETag cache) and `conn` (the background task handle + command channel).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use super::catalog::{FAH_ISOLATION_CLASS, SEASON0_FORMULA};
use super::{
    BackendStatus, ConfigField, EngineReport, EngineState, InstallState, PowerLevel, UnitProgress,
    WorkBackend, WorkUnit,
};

/// FAHClient v8 local-API WebSocket endpoint (loopback only — we never reach off-box for control).
const FAH_WS_URL: &str = "ws://127.0.0.1:7396/api/websocket";
/// Loopback port the local API listens on; also the strongest install/running signal.
const FAH_LOCAL_PORT: u16 = 7396;
/// Public stats API base — the beneficiary's own credit accounting (the mint basis).
const FAH_STATS_BASE: &str = "https://api.foldingathome.org/user/";
/// Official download page (last-resort fallback only — primary path is the auto-download +
/// interactive installer flow below).
const FAH_DOWNLOAD_URL: &str = "https://foldingathome.org/start-folding";
/// Official **portable** Windows client (v8 bastet). https-only, official host.
///
/// Prefer `latest.tar.bz2` over `latest.exe`: the `.exe` is an interactive NSIS installer that
/// blocks on EULA and left Start contributing stuck ("Starting installer…"). Portable archive
/// extracts under app-data and Goat runs `fah-client.exe` directly — no EULA window.
/// Mirror rewrites `latest.tar.bz2` to the newest release. SHA-256 of each download is logged in
/// `engine-provision.log` (no upstream signed manifest).
const FAH_CLIENT_CHANNEL: &str = "latest-portable";
const FAH_PORTABLE_URL: &str = "https://download.foldingathome.org/releases/public/fah-client/windows-10-64bit/release/latest.tar.bz2";
const FAH_PORTABLE_ARCHIVE_FILENAME: &str = "fah-client_latest.tar.bz2";
/// Fallback public page / legacy log strings (primary path is portable tar, not NSIS exe).
const FAH_INSTALLER_URL: &str = FAH_PORTABLE_URL;
const FAH_INSTALLER_FILENAME: &str = FAH_PORTABLE_ARCHIVE_FILENAME;
/// Known portable extract dir prefixes under app-data `engine/` (versioned folder inside the tarball).
const FAH_WIN_PORTABLE_PREFIX: &str = "fah-client_8.5.6-64bit-release";
const FAH_WIN_PORTABLE_PREFIX_LEGACY: &[&str] = &[
    "fah-client_8.5.5-64bit-release",
    "fah-client_8.5.6-64bit-release",
];
/// Minimum spacing between stats polls — the public API is a shared resource, be a good citizen.
const STATS_MIN_INTERVAL: Duration = Duration::from_secs(60);
/// Reconnect backoff bounds for the control WebSocket (1s → 30s, capped).
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// TCP probe timeout for `detect_install` — short so the UI button stays responsive.
const DETECT_TCP_TIMEOUT: Duration = Duration::from_millis(300);
/// After spawning / extracting, wait longer for first API listen.
const ENGINE_START_POLL_TOTAL: Duration = Duration::from_secs(90);
const ENGINE_START_POLL_STEP: Duration = Duration::from_millis(500);
/// After `connect()`, wait for the control WS to mark `live.connected` (avoids first-click fold
/// landing before the socket is up — founder "click Start twice" bug).
const WS_CONNECT_WAIT_TOTAL: Duration = Duration::from_secs(15);
const WS_CONNECT_WAIT_STEP: Duration = Duration::from_millis(200);
/// After WS is up, wait for a state-tree snapshot before resource config / fold.
const WS_TREE_WAIT_TOTAL: Duration = Duration::from_secs(8);
const WS_TREE_WAIT_STEP: Duration = Duration::from_millis(200);
/// Minimum FAH client version we treat as current for upgrade prompting (semver-ish major.minor.patch).
const FAH_MIN_GOOD_VERSION: &str = "8.5.6";
/// Download timeout for the portable FAH engine (~3.5 MB typically).
const ENGINE_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
/// Sanity cap on a single credited-WU jump between polls (S9). A delta larger than this is far
/// more likely a stats-API anomaly or a misconfigured/shared account than genuine folding, so the
/// baseline is held rather than minting a potentially-bogus batch.
const DELTA_SANITY_CAP: u64 = 1000;

/// Founder-directed default team (2026-07-12): every Goat install folds for the GOAT team unless
/// the user overrides. Passkeys are optional (QRB bonus only) — we no longer ship a shared
/// founder passkey as automatic config. The retired shared key is kept solely so old installs
/// that still store it can be detected for the legacy brand flag (`passkey_is_default`).
const DEFAULT_TEAM: &str = "1068318";
/// Retired shared founder passkey — never auto-filled into new installs. Used only to detect
/// legacy persisted state that still holds this value.
const LEGACY_SHARED_PASSKEY: &str = "31415926535897932384626433832795";

/// Honest status/detail shown when the local FAHClient is linked to a Folding@home account. A
/// linked client ignores local-WebSocket **config** commands, so Goat must not claim to have
/// applied CPU/GPU settings — those follow the account instead. The fold/pause **state**
/// commands are still sent regardless (Web Control parity; `start_command_batches` always
/// includes `fold_messages()`). Kept as one constant so the Rust detail and the UI copy stay in
/// step.
const ACCOUNT_LINKED_DETAIL: &str =
    "FAH client is linked to a Folding@home account; CPU/GPU settings follow your account, not Goat.";

/// On-disk state: FAH identity (config) plus the crediting baseline. Passkey is stored here
/// (app-data, never git) and pushed to the *local* client over the control socket — it is never
/// sent to the stats API.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct FahPersisted {
    pub username: Option<String>,
    pub team: Option<String>,
    pub passkey: Option<String>,
    /// High-water mark of credited WUs already minted against. `None` until the first poll.
    pub last_credited_wus: Option<u64>,
}

/// The FAH user-stats response shape we care about. Extra fields (name, rank, teams…) are ignored.
#[derive(Debug, Clone, Deserialize)]
struct FahUserStats {
    #[serde(default)]
    wus: u64,
    #[serde(default)]
    #[allow(dead_code)]
    // parsed for completeness / future provenance display; not minted against.
    score: i64,
}

/// Live control-channel state, shared between the background WS task and `status()`.
///
/// `units`/`state` are the *last-good* derived view: an unparseable or partial frame keeps them
/// (design §3 — "keep last state + surface detail, never fabricate"), whereas a genuine
/// connection loss clears units and flips `state` to `error` (stale progress would be a lie).
#[derive(Debug, Clone)]
struct FahLive {
    /// The full FAH state tree, mutated by snapshots (merge) and patch arrays (path-set).
    tree: Value,
    units: Vec<FahUnit>,
    state: String,
    detail: String,
    connected: bool,
}

impl FahLive {
    /// Initial pre-connect view, derived from a one-shot install probe so `status()` is honest
    /// before the user ever clicks Connect.
    fn from_install(install: InstallState) -> Self {
        let (state, detail): (&str, &str) = match install {
            InstallState::Missing => (
                "not_installed",
                "Folding@home client not detected — see the install steps to start folding.",
            ),
            InstallState::Installed => (
                "installed_not_connected",
                "FAHClient is installed but not attached. Click Connect once it is running.",
            ),
            InstallState::Running => (
                "reachable_not_connected",
                "FAHClient is running. Click Connect to attach to its local API.",
            ),
        };
        Self {
            tree: json!({}),
            units: Vec::new(),
            state: state.to_string(),
            detail: detail.to_string(),
            connected: false,
        }
    }

    /// Apply one WebSocket frame. Defensive by construction: a parse failure or an unrecognized
    /// shape retains the last-good units/state and only updates `detail`.
    fn apply_frame(&mut self, raw: &str) {
        let value: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(err) => {
                self.detail = format!("unparseable FAH frame retained last state: {err}");
                return;
            }
        };

        let applied = match &value {
            Value::Object(_) => {
                merge_value(&mut self.tree, &value);
                true
            }
            Value::Array(arr) => apply_path_update(&mut self.tree, arr),
            _ => false,
        };

        if !applied {
            self.detail = "unrecognized FAH frame shape retained last state".to_string();
            return;
        }

        self.units = derive_units(&self.tree);
        self.state = derive_state(&self.tree, &self.units);
        self.detail = derive_detail(&self.tree);
    }
}

/// One in-flight folding unit as shown in the Miner.
/// Progress semantics match fah-web-client-bastet `unit.js` (`wu_progress` preferred).
#[derive(Debug, Clone, PartialEq)]
struct FahUnit {
    id: String,
    number: Option<u64>,
    project: String,
    /// 0.0..=1.0 — prefer `wu_progress`, else `progress` (never invented).
    progress: f32,
    /// Raw per-unit state token (e.g. "RUN", "PAUSE", "DOWNLOAD", "FINISH").
    state: String,
    /// GPU if assignment lists GPUs, else CPU.
    resource: String,
}

/// Stats-poll throttle + conditional-request cache.
#[derive(Debug, Default)]
struct StatsCache {
    last_poll: Option<Instant>,
    etag: Option<String>,
}

/// Background control-task handle + the command channel into it.
#[derive(Default)]
struct ConnHandle {
    task: Option<tokio::task::JoinHandle<()>>,
    stop: Option<Arc<AtomicBool>>,
    /// Each command is an ordered list of candidate JSON messages; the task sends the first and
    /// falls back to the next if the client answers with an error frame (v8 command-form drift).
    cmd_tx: Option<mpsc::UnboundedSender<Vec<String>>>,
}

/// Live managed-provisioning progress, shared between a running `ensure_engine` (which mutates it
/// as it downloads/launches the installer) and `engine_report`/`engine_state` (which the UI polls
/// concurrently). `active` is true only while a provision attempt is in flight or has ended in an
/// actionable error; when false the engine state is re-derived from `detect_install`. The detail
/// is always an honest phase description ("downloading installer… X%", "waiting for
/// installer/EULA…", or a failure reason) — never a fabricated percentage.
#[derive(Debug, Clone)]
struct ProvisionSnapshot {
    active: bool,
    state: EngineState,
    detail: String,
}

impl Default for ProvisionSnapshot {
    fn default() -> Self {
        Self {
            active: false,
            state: EngineState::Missing,
            detail: String::new(),
        }
    }
}

/// The real Folding@home `WorkBackend`.
pub(crate) struct FahBackend {
    state_file: PathBuf,
    persisted: Mutex<FahPersisted>,
    live: Arc<Mutex<FahLive>>,
    stats: Mutex<StatsCache>,
    conn: Mutex<ConnHandle>,
    /// Managed-provision progress (installer download/launch), polled by the UI via `engine_report`.
    provision: Arc<Mutex<ProvisionSnapshot>>,
}

impl FahBackend {
    /// Production constructor: state file in the OS app-data dir, initial view from a one-shot
    /// install probe. Infallible — persistence and detection are best-effort and degrade to a
    /// sane default rather than refusing to build the registry.
    pub(crate) fn new() -> Self {
        Self::with_state_file(default_state_file())
    }

    /// Testable constructor — lets unit tests point persistence at a temp file.
    pub(crate) fn with_state_file(state_file: PathBuf) -> Self {
        let persisted = load_persisted(&state_file);
        let live = FahLive::from_install(detect_install_impl());
        Self {
            state_file,
            persisted: Mutex::new(persisted),
            live: Arc::new(Mutex::new(live)),
            stats: Mutex::new(StatsCache::default()),
            conn: Mutex::new(ConnHandle::default()),
            provision: Arc::new(Mutex::new(ProvisionSnapshot::default())),
        }
    }

    /// Send an ordered candidate-command list to the background task. Errors (never panics) when
    /// no control socket is attached.
    fn enqueue_command(&self, candidates: Vec<String>) -> Result<(), String> {
        let conn = self.conn.lock().expect("conn mutex poisoned");
        match &conn.cmd_tx {
            Some(tx) => tx
                .send(candidates)
                .map_err(|_| "FAH control channel closed — reconnect first".to_string()),
            None => Err("not connected to FAHClient — call connect() first".to_string()),
        }
    }

    /// Wait until the control WS task has set `live.connected`.
    async fn wait_until_ws_connected(&self, total: Duration) -> bool {
        let deadline = Instant::now() + total;
        while Instant::now() < deadline {
            if self.live.lock().map(|l| l.connected).unwrap_or(false) {
                return true;
            }
            tokio::time::sleep(WS_CONNECT_WAIT_STEP).await;
        }
        self.live.lock().map(|l| l.connected).unwrap_or(false)
    }

    /// Wait until the FAH state tree has `info` or `gpus` (first snapshot).
    async fn wait_until_tree_ready(&self, total: Duration) -> bool {
        let deadline = Instant::now() + total;
        while Instant::now() < deadline {
            if let Ok(live) = self.live.lock() {
                if live.tree.get("info").is_some() || live.tree.get("gpus").is_some() {
                    return true;
                }
            }
            tokio::time::sleep(WS_TREE_WAIT_STEP).await;
        }
        self.live
            .lock()
            .map(|l| l.tree.get("info").is_some() || l.tree.get("gpus").is_some())
            .unwrap_or(false)
    }

    /// Apply a freshly-fetched stats snapshot against the persisted baseline: compute the delta,
    /// enforce the sanity cap (S9), and durably save the new baseline BEFORE committing it in
    /// memory — the at-most-once contract documented on `WorkBackend::list_completions`. On save
    /// failure the in-memory baseline is left untouched and this returns an empty batch, so the
    /// same WUs are re-emitted (idempotently) once the baseline can be durably written.
    fn apply_stats_snapshot(
        &self,
        new_wus: u64,
        body: &str,
        username: &str,
        at: u64,
    ) -> Vec<WorkUnit> {
        let mut persisted = self.persisted.lock().expect("persisted mutex poisoned");
        let baseline = persisted.last_credited_wus;

        let (new_baseline, units, anomaly) = compute_delta(baseline, new_wus, body, username, at);

        if let Some(msg) = anomaly {
            drop(persisted);
            if let Ok(mut live) = self.live.lock() {
                live.detail = msg;
            }
            return Vec::new();
        }

        let mut candidate = persisted.clone();
        candidate.last_credited_wus = Some(new_baseline);

        if let Err(err) = save_persisted(&self.state_file, &candidate) {
            drop(persisted);
            if let Ok(mut live) = self.live.lock() {
                live.detail = format!("FAH baseline persist failed, deferring credit: {err}");
            }
            return Vec::new();
        }

        *persisted = candidate;
        units
    }
}

#[async_trait]
impl WorkBackend for FahBackend {
    fn id(&self) -> &'static str {
        "folding_at_home"
    }

    fn display_name(&self) -> &'static str {
        "Folding@home"
    }

    fn beneficiary(&self) -> &'static str {
        "Folding@home — public biomedical research"
    }

    fn isolation_class(&self) -> &'static str {
        FAH_ISOLATION_CLASS
    }

    fn honesty_tags(&self) -> Vec<String> {
        vec![
            SEASON0_FORMULA.to_string(),
            FAH_ISOLATION_CLASS.to_string(),
            format!(
                "Managed FAH channel: {FAH_CLIENT_CHANNEL} (official latest.tar.bz2 → run fah-client.exe, no EULA installer)"
            ),
            "Live progress is display-only; credited WUs from Folding@home are the mint basis"
                .to_string(),
        ]
    }

    fn detect_install(&self) -> InstallState {
        detect_install_impl()
    }

    fn install_hint(&self) -> String {
        "Folding@home is a managed science engine inside Goat (powered by Folding@home open source).\n\
         Click Start contributing — when needed, Goat downloads the official portable client \
         (latest.tar.bz2), extracts it, and runs fah-client.exe directly (no NSIS/EULA installer \
         window). Credited work units are the mint basis (never GPU model, TFLOPS, uptime, or power \
         level). A system FAHClient already running is attached if present."
            .to_string()
    }

    fn supports_managed_engine(&self) -> bool {
        true
    }

    fn engine_state(&self) -> EngineState {
        // A live provision attempt (or its actionable error) wins over a raw install probe, so the
        // UI sees Provisioning/Error while the installer runs rather than a stale Missing.
        if let Ok(p) = self.provision.lock() {
            if p.active {
                return p.state;
            }
        }
        match detect_install_impl() {
            InstallState::Missing => EngineState::Missing,
            InstallState::Installed => EngineState::Ready,
            InstallState::Running => EngineState::Running,
        }
    }

    fn engine_report(&self) -> EngineReport {
        // While provisioning, surface the live phase detail the download loop writes.
        {
            let p = self.provision.lock().expect("provision mutex poisoned");
            if p.active {
                return EngineReport {
                    state: p.state,
                    detail: p.detail.clone(),
                    managed: true,
                };
            }
        }
        let state = match detect_install_impl() {
            InstallState::Missing => EngineState::Missing,
            InstallState::Installed => EngineState::Ready,
            InstallState::Running => EngineState::Running,
        };
        let detail = match state {
            EngineState::Running => {
                format!("Folding@home local API reachable on 127.0.0.1:{FAH_LOCAL_PORT}.")
            }
            EngineState::Ready => {
                "Folding@home client installed — Start contributing to begin folding.".to_string()
            }
            EngineState::Missing => {
                "No Folding@home client detected — Start contributing downloads the official \
                 installer (its license window opens once)."
                    .to_string()
            }
            _ => String::new(),
        };
        EngineReport {
            state,
            detail,
            managed: true,
        }
    }

    async fn ensure_engine(&self) -> Result<EngineReport, String> {
        // 1. Local API already reachable → running (managed attach). Clear any stale provision.
        if tcp_port_open(FAH_LOCAL_PORT) {
            clear_provision(&self.provision);
            return Ok(EngineReport {
                state: EngineState::Running,
                detail: "FAH local API reachable".to_string(),
                managed: true,
            });
        }

        // 2. Prefer an already-extracted managed portable binary (no EULA).
        if let Some(exe) = managed_fah_client_exe() {
            clear_provision(&self.provision);
            return start_fah_exe_and_wait(&exe).await;
        }

        // 3. No managed portable: download official latest.tar.bz2, extract, run fah-client.exe.
        //    Tests may set GOAT_FAH_NO_AUTO_PROVISION=1 to skip the network path.
        if std::env::var("GOAT_FAH_NO_AUTO_PROVISION").as_deref() == Ok("1") {
            // Still allow system install when auto-provision is disabled.
            if let Some(exe) = fah_client_exe() {
                clear_provision(&self.provision);
                return start_fah_exe_and_wait(&exe).await;
            }
            return Ok(EngineReport {
                state: EngineState::Missing,
                detail: "FAH engine not present; auto-provision disabled (GOAT_FAH_NO_AUTO_PROVISION=1)."
                    .to_string(),
                managed: true,
            });
        }

        match provision_via_portable(&self.state_file, &self.provision).await {
            Ok(report) => Ok(report),
            Err(err) => {
                // Portable download/extract failed — try any system FAHClient before giving up.
                if let Some(exe) = fah_client_exe() {
                    clear_provision(&self.provision);
                    return start_fah_exe_and_wait(&exe).await;
                }
                let _ = open_fah_download_page();
                let detail = format!(
                    "Could not download/extract the portable Folding@home client ({err}). \
                     Opened the official page as a fallback: {FAH_DOWNLOAD_URL}"
                );
                set_provision(&self.provision, EngineState::Error, detail.clone());
                Ok(EngineReport {
                    state: EngineState::Error,
                    detail,
                    managed: true,
                })
            }
        }
    }

    async fn start_engine(&self) -> Result<EngineReport, String> {
        // Alias ensure for FAH — start path is the same managed provision.
        self.ensure_engine().await
    }

    async fn stop_engine(&self) -> Result<(), String> {
        // Best-effort no-op: we attach to (and may spawn) the user's FAHClient; killing it risks
        // discarding in-flight science work and surprises users who run FAH outside Goat.
        // Folding control (pause/finish) stays on backend_stop / backend_pause via the WS API.
        Ok(())
    }

    async fn connect(&self) -> Result<(), String> {
        {
            let mut conn = self.conn.lock().expect("conn mutex poisoned");
            let already = conn
                .task
                .as_ref()
                .map(|t| !t.is_finished())
                .unwrap_or(false);
            if !already {
                let (tx, rx) = mpsc::unbounded_channel::<Vec<String>>();
                let stop = Arc::new(AtomicBool::new(false));
                let identity = self
                    .persisted
                    .lock()
                    .expect("persisted mutex poisoned")
                    .clone();
                let live = Arc::clone(&self.live);
                let stop_task = Arc::clone(&stop);

                let task = tokio::spawn(async move {
                    ws_control_loop(live, stop_task, rx, identity).await;
                });

                conn.task = Some(task);
                conn.stop = Some(stop);
                conn.cmd_tx = Some(tx);
            }
        }
        // Block until the WS task marks connected (or timeout). Without this, Start fold
        // commands were enqueued before the socket was up and the first click looked "dead".
        if !self.wait_until_ws_connected(WS_CONNECT_WAIT_TOTAL).await {
            return Err(format!(
                "FAH local API did not accept a control WebSocket within {}s on 127.0.0.1:{FAH_LOCAL_PORT}. \
                 Is FAHClient running?",
                WS_CONNECT_WAIT_TOTAL.as_secs()
            ));
        }
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), String> {
        {
            let mut conn = self.conn.lock().expect("conn mutex poisoned");
            if let Some(stop) = &conn.stop {
                stop.store(true, Ordering::SeqCst);
            }
            conn.cmd_tx = None;
            conn.stop = None;
            if let Some(task) = conn.task.take() {
                task.abort();
            }
        }
        let mut live = self.live.lock().expect("live mutex poisoned");
        live.connected = false;
        live.units.clear();
        live.state = "idle".to_string();
        live.detail = "disconnected from FAHClient".to_string();
        Ok(())
    }

    async fn start(&self) -> Result<(), String> {
        // Auto-pilot "Start contributing" resource config (spec §11.2), applied only through this
        // managed lifecycle — never on a plain attach/connect. Enable every supported GPU, leave
        // 2 CPU cores of headroom (`auto_cpus`), clear idle-only, unpause/fold.
        // Always re-push identity (team 1068318 + username) so account-token-linked machines that
        // inherited team 11 get a local override attempt every Start.
        if !self.wait_until_ws_connected(WS_CONNECT_WAIT_TOTAL).await {
            return Err(
                "not connected to FAHClient — call connect() first (WebSocket not ready)".into(),
            );
        }
        // Wait for first WS snapshot so GPU list / account-link flags are known.
        let _ = self.wait_until_tree_ready(WS_TREE_WAIT_TOTAL).await;

        // Note outdated clients honestly — do NOT launch the NSIS latest.exe here (EULA blocks
        // Start contributing). Managed path uses portable latest.tar.bz2 on next ensure when no
        // managed portable exists; system 8.5.5 keeps running until replaced.
        {
            let tree = self.live.lock().expect("live mutex poisoned").tree.clone();
            if let Some(ver) = read_client_version_from_tree(&tree) {
                if client_version_needs_upgrade(&ver) {
                    if let Ok(mut live) = self.live.lock() {
                        live.detail = format!(
                            "FAH client v{ver} is older than {FAH_MIN_GOOD_VERSION}. Goat runs a \
                             portable latest.tar.bz2 engine when provisioned (no EULA installer). \
                             Stop contributing and Start again after deleting an old system-only \
                             client if you need the upgrade path to re-fetch portable."
                        );
                    }
                }
            }
        }

        let tree = self.live.lock().expect("live mutex poisoned").tree.clone();
        // Ensure persisted team defaults to GOAT if unset.
        {
            let mut p = self.persisted.lock().expect("persisted mutex poisoned");
            if p.team.as_ref().map(|t| t.trim().is_empty()).unwrap_or(true) {
                p.team = Some(DEFAULT_TEAM.to_string());
                let _ = save_persisted(&self.state_file, &p);
            }
        }
        let identity = self
            .persisted
            .lock()
            .expect("persisted mutex poisoned")
            .clone();
        if is_account_linked(&tree) {
            if let Ok(mut live) = self.live.lock() {
                live.detail = ACCOUNT_LINKED_DETAIL.to_string();
            }
        }
        let batches =
            start_command_batches(&tree, auto_cpus(host_parallelism()), &identity);
        let last = batches.len().saturating_sub(1);
        for (i, batch) in batches.into_iter().enumerate() {
            self.enqueue_command(batch)?;
            if i != last {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        // Second fold after a short settle — first-click often lost while FAH was still
        // finishing startup config; one extra fold is cheap and matches Web Control retry.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = self.enqueue_command(fold_messages());
        Ok(())
    }

    async fn stop(&self) -> Result<(), String> {
        // Stop = kill the FAH client process (founder decision 2026-07-12, design §C3). FAH v8
        // checkpoints work units to disk, so the next Start resumes from the last checkpoint via
        // ensure_engine()'s existing "port closed + exe present → relaunch" path — no change
        // needed there.
        let killed = kill_fah_client()?;
        // The process is gone — drop the control socket like disconnect() does.
        let _ = self.disconnect().await;
        if let Ok(mut live) = self.live.lock() {
            live.detail = if killed {
                "FAH client stopped (process killed).".to_string()
            } else {
                "FAH client was not running.".to_string()
            };
        }
        Ok(())
    }

    async fn pause(&self) -> Result<(), String> {
        self.enqueue_command(pause_messages())
    }

    async fn dump_unit(&self, unit_id: &str) -> Result<(), String> {
        // Official wire (fah-web-client machine.js + fah-client Remote.cpp):
        //   { "cmd": "dump", "unit": "<unit.id>", "time": "..." }
        // `unit` MUST be Unit::getID() — NOT the WU number. Wrong id → client throws
        // "Unit X not found" and dump is a no-op from Goat's perspective.
        let query = unit_id.trim();
        if query.is_empty() {
            return Err("dump requires a non-empty FAH unit id".into());
        }
        let tree = self.live.lock().expect("live mutex poisoned").tree.clone();
        let real_id = resolve_dump_unit_id(&tree, query)?;
        self.enqueue_command(dump_unit_messages(&real_id))
    }

    async fn status(&self) -> BackendStatus {
        let live = self.live.lock().expect("live mutex poisoned");
        BackendStatus {
            state: live.state.clone(),
            units: live.units.iter().map(to_unit_progress).collect(),
            detail: live.detail.clone(),
            linked: is_account_linked(&live.tree),
            team: read_team_from_tree(&live.tree).map(|t| t.to_string()),
            client_version: read_client_version_from_tree(&live.tree),
        }
    }

    /// At-most-once delivery: returned units advance the adapter's durable baseline and are NEVER
    /// redelivered. The caller MUST durably record returned units (pending journal) before using
    /// them for any accept/mint flow. (S9 hard contract.)
    async fn list_completions(&self) -> Vec<WorkUnit> {
        // Mint basis = the beneficiary's own credited-WU count. Requires a configured username.
        let username = {
            let persisted = self.persisted.lock().expect("persisted mutex poisoned");
            match &persisted.username {
                Some(u) if !u.trim().is_empty() => u.clone(),
                _ => return Vec::new(),
            }
        };

        // Throttle: reserve the poll window before any await so concurrent callers don't stampede.
        {
            let mut cache = self.stats.lock().expect("stats mutex poisoned");
            if let Some(last) = cache.last_poll {
                if last.elapsed() < STATS_MIN_INTERVAL {
                    return Vec::new();
                }
            }
            cache.last_poll = Some(Instant::now());
        }
        let etag = self
            .stats
            .lock()
            .expect("stats mutex poisoned")
            .etag
            .clone();

        let fetched = match fetch_stats(&username, etag.as_deref()).await {
            Ok(f) => f,
            Err(err) => {
                if let Ok(mut live) = self.live.lock() {
                    live.detail = format!("FAH stats poll failed: {err}");
                }
                return Vec::new();
            }
        };

        let StatsFetch {
            status,
            body,
            new_etag,
        } = fetched;

        if status == 304 {
            return Vec::new(); // not modified since last ETag — nothing new to credit
        }

        if let Err(err) = save_latest_stats_body(&self.state_file, &body) {
            if let Ok(mut live) = self.live.lock() {
                live.detail = format!("FAH stats body persist failed (non-critical): {err}");
            }
        }

        let stats: FahUserStats = match serde_json::from_str(&body) {
            Ok(s) => s,
            Err(err) => {
                if let Ok(mut live) = self.live.lock() {
                    live.detail = format!("FAH stats response was not valid JSON: {err}");
                }
                return Vec::new();
            }
        };

        let units = self.apply_stats_snapshot(stats.wus, &body, &username, unix_now());

        // Crash-recovery evidence, written immediately after the baseline commit succeeds and
        // before these units are returned to the caller. An echo-write failure must NEVER lose
        // units — they are still returned below; only `detail` reflects the (non-critical)
        // write failure so a founder can notice and investigate.
        if !units.is_empty() {
            if let Err(err) = append_units_echo(&self.state_file, &units) {
                if let Ok(mut live) = self.live.lock() {
                    live.detail = format!(
                        "FAH units echo write failed (non-critical, units still returned): {err}"
                    );
                }
            }
        }

        {
            let mut cache = self.stats.lock().expect("stats mutex poisoned");
            cache.etag = new_etag;
        }

        units
    }

    async fn set_power(&self, level: PowerLevel) -> Result<(), String> {
        let available = {
            let live = self.live.lock().expect("live mutex poisoned");
            available_cores_from_tree(&live.tree)
        };
        self.enqueue_command(vec![power_config_message(level, available)])
    }

    fn configure(&self, key: &str, value: &str) -> Result<(), String> {
        let mut persisted = self.persisted.lock().expect("persisted mutex poisoned");
        let mut candidate = persisted.clone();
        match key {
            "username" => {
                let changed = candidate.username.as_deref() != Some(value);
                candidate.username = Some(value.to_string());
                if changed {
                    candidate.last_credited_wus = None;
                }
            }
            "team" => candidate.team = Some(value.to_string()),
            "passkey" => candidate.passkey = Some(value.to_string()),
            other => return Err(format!("unknown FAH config key: {other}")),
        }
        save_persisted(&self.state_file, &candidate)?;
        *persisted = candidate.clone();
        drop(persisted);
        // Hot-apply identity to the live FAHClient when connected (team/user/passkey). Without
        // this, configure only wrote disk and left account-linked team=11 until a full reconnect.
        if let Some(patch) = identity_config_patch(&candidate) {
            let _ = self.enqueue_command(vec![patch]);
        }
        Ok(())
    }

    fn config_fields(&self) -> Vec<ConfigField> {
        vec![
            ConfigField {
                key: "username",
                label: "Username",
                secret: false,
            },
            ConfigField {
                key: "team",
                label: "Team",
                secret: false,
            },
            ConfigField {
                key: "passkey",
                label: "Passkey",
                secret: true,
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// Install detection
// ---------------------------------------------------------------------------

/// Detect the FAHClient install/run state. Order of confidence: a live local-API socket >
/// a running process > install files on disk > nothing. Reports `Missing` whenever unsure —
/// never assumes an install we cannot see (design §3 honesty).
fn detect_install_impl() -> InstallState {
    if tcp_port_open(FAH_LOCAL_PORT) {
        return InstallState::Running;
    }
    if fah_process_running() {
        return InstallState::Running;
    }
    if fah_install_dir_present() {
        return InstallState::Installed;
    }
    InstallState::Missing
}

/// Best-effort TCP reachability probe of a loopback port with a short timeout.
fn tcp_port_open(port: u16) -> bool {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    TcpStream::connect_timeout(&addr, DETECT_TCP_TIMEOUT).is_ok()
}

/// FAHClient v8 install / managed-engine directories (Windows-first). Empty roots on non-Windows
/// still include the Goat-managed portable dir when app-data resolves.
fn fah_install_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    // Prefer current Goat-managed portable engine, then legacy managed dirs (no system install).
    dirs.push(managed_engine_dir().join(FAH_WIN_PORTABLE_PREFIX));
    for legacy in FAH_WIN_PORTABLE_PREFIX_LEGACY {
        dirs.push(managed_engine_dir().join(legacy));
    }
    dirs.push(managed_engine_dir());
    for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Ok(base) = std::env::var(var) {
            if !base.is_empty() {
                dirs.push(PathBuf::from(base).join("FAHClient"));
            }
        }
    }
    dirs
}

fn fah_install_dir_present() -> bool {
    fah_client_exe().is_some() || fah_install_dirs().iter().any(|dir| dir.is_dir())
}

/// Locate only a **Goat-managed** portable `fah-client.exe` (under app-data engine/).
fn managed_fah_client_exe() -> Option<PathBuf> {
    let root = managed_engine_dir();
    let names = ["fah-client.exe", "fah-client"];
    // Known versioned extract dirs first.
    for dir in fah_install_dirs() {
        if !dir.starts_with(&root) {
            continue;
        }
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    // Any nested fah-client.exe under managed engine/ (tarball top-level name may change).
    find_named_exe_under(&root, "fah-client.exe", 4)
        .or_else(|| find_named_exe_under(&root, "fah-client", 4))
}

/// Locate the FAH client binary: managed portable first, then system install. `None` when absent.
fn fah_client_exe() -> Option<PathBuf> {
    if let Some(exe) = managed_fah_client_exe() {
        return Some(exe);
    }
    let names = ["fah-client.exe", "FAHClient.exe", "fah-client", "FAHClient"];
    for dir in fah_install_dirs() {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Depth-limited search for `name` under `root` (for tarball extract trees).
fn find_named_exe_under(root: &Path, name: &str, max_depth: usize) -> Option<PathBuf> {
    fn walk(dir: &Path, name: &str, depth: usize, max_depth: usize) -> Option<PathBuf> {
        if depth > max_depth {
            return None;
        }
        let direct = dir.join(name);
        if direct.is_file() {
            return Some(direct);
        }
        let entries = std::fs::read_dir(dir).ok()?;
        for ent in entries.flatten() {
            let p = ent.path();
            if p.is_dir() {
                if let Some(found) = walk(&p, name, depth + 1, max_depth) {
                    return Some(found);
                }
            }
        }
        None
    }
    if !root.is_dir() {
        return None;
    }
    walk(root, name, 0, max_depth)
}

/// App-data folder where Goat stores the auto-provisioned portable FAH engine.
fn managed_engine_dir() -> PathBuf {
    default_state_dir().join("engine")
}

/// Spawn `exe` (cwd = its parent) as a **detached** process and poll until local API is up.
/// Process name on disk is `fah-client.exe` (v8 portable) — Task Manager will NOT show
/// classic “FAHClient.exe” unless the system installer was used.
async fn start_fah_exe_and_wait(exe: &Path) -> Result<EngineReport, String> {
    // Already listening — do not spawn a second instance (can fight for port / clean-exit).
    if tcp_port_open(FAH_LOCAL_PORT) {
        return Ok(EngineReport {
            state: EngineState::Running,
            detail: format!(
                "FAH engine already listening on 127.0.0.1:{FAH_LOCAL_PORT} (look for process \
                 fah-client / FAHClient). Path: {}",
                exe.display()
            ),
            managed: true,
        });
    }

    let mut cmd = std::process::Command::new(exe);
    if let Some(parent) = exe.parent() {
        cmd.current_dir(parent);
    }
    // Detach fully on Windows so the engine survives Goat restarts and is visible as fah-client.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    }
    match cmd.spawn() {
        Ok(mut child) => {
            let pid = child.id();
            let deadline = Instant::now() + ENGINE_START_POLL_TOTAL;
            while Instant::now() < deadline {
                if tcp_port_open(FAH_LOCAL_PORT) {
                    // Detach now — client is up and listening; we won't wait() on it going forward.
                    std::mem::forget(child);
                    return Ok(EngineReport {
                        state: EngineState::Running,
                        detail: format!(
                            "Started managed FAH engine pid={pid} ({}); local API on \
                             127.0.0.1:{FAH_LOCAL_PORT}. Process name: fah-client (not FAHClient).",
                            exe.display()
                        ),
                        managed: true,
                    });
                }
                // If the process died immediately, fail honestly instead of polling out the
                // full timeout window.
                match child.try_wait() {
                    Ok(Some(status)) => {
                        return Ok(EngineReport {
                            state: EngineState::Error,
                            detail: format!(
                                "FAH engine pid={pid} at {} exited immediately ({status}) before \
                                 the local API came up. Check \
                                 %AppData%\\com.goatcoin.dagoat\\engine\\…\\log.txt.",
                                exe.display()
                            ),
                            managed: true,
                        });
                    }
                    Ok(None) => {} // still running — keep polling
                    Err(_) => {}   // exit status unavailable — keep polling
                }
                tokio::time::sleep(ENGINE_START_POLL_STEP).await;
            }
            let alive = fah_process_running();
            // Detach — timed out but the process (or a respawn under the same image name) may
            // still be starting; leave it running for the user to inspect.
            // Extra grace: process often opens the API a few seconds after our first poll window.
            if alive {
                let grace_deadline = Instant::now() + Duration::from_secs(30);
                while Instant::now() < grace_deadline {
                    if tcp_port_open(FAH_LOCAL_PORT) {
                        std::mem::forget(child);
                        return Ok(EngineReport {
                            state: EngineState::Running,
                            detail: format!(
                                "Started managed FAH engine pid={pid} ({}); local API on \
                                 127.0.0.1:{FAH_LOCAL_PORT} (after extended wait).",
                                exe.display()
                            ),
                            managed: true,
                        });
                    }
                    tokio::time::sleep(ENGINE_START_POLL_STEP).await;
                }
            }
            std::mem::forget(child);
            Ok(EngineReport {
                state: if alive {
                    // Ready = installed/process up but API not yet listening — UI must wait/retry
                    // the same click path rather than requiring a second human click.
                    EngineState::Ready
                } else {
                    EngineState::Error
                },
                detail: format!(
                    "Spawned FAH engine pid={pid} at {} but port {FAH_LOCAL_PORT} not up yet \
                     (process_alive={alive}). Check Task Manager for **fah-client**, and \
                     %AppData%\\com.goatcoin.dagoat\\engine\\…\\log.txt.",
                    exe.display()
                ),
                managed: true,
            })
        }
        Err(err) => Ok(EngineReport {
            state: EngineState::Error,
            detail: format!(
                "Found FAH engine at {} but could not start it: {err}.",
                exe.display()
            ),
            managed: true,
        }),
    }
}

// ---------------------------------------------------------------------------
// Managed provisioning — official interactive installer (spec §11.1)
// ---------------------------------------------------------------------------

/// Overwrite the shared provision snapshot with a live phase (marks it `active` so the UI's
/// `engine_report`/`engine_state` poll reflects it). Never holds the lock across an `.await`.
fn set_provision(provision: &Arc<Mutex<ProvisionSnapshot>>, state: EngineState, detail: String) {
    if let Ok(mut p) = provision.lock() {
        p.active = true;
        p.state = state;
        p.detail = detail;
    }
}

/// Mark provisioning finished so `engine_state` falls back to a fresh `detect_install` probe.
fn clear_provision(provision: &Arc<Mutex<ProvisionSnapshot>>) {
    if let Ok(mut p) = provision.lock() {
        p.active = false;
        p.detail.clear();
    }
}

/// Honest download-phase detail: a real percentage when the server sends `Content-Length`,
/// otherwise the running byte count (never an invented percentage).
fn provision_download_detail(downloaded: u64, total: Option<u64>) -> String {
    match total {
        Some(t) if t > 0 => {
            let pct = ((downloaded as f64 / t as f64) * 100.0).round() as u64;
            format!("downloading portable FAH client… {}%", pct.min(100))
        }
        _ => format!(
            "downloading portable FAH client… {:.1} MB",
            downloaded as f64 / 1_048_576.0
        ),
    }
}

/// Download official `latest.tar.bz2`, extract under managed engine dir, run `fah-client.exe`
/// directly — **no NSIS/EULA installer** (that path left Start contributing stuck).
async fn provision_via_portable(
    state_file: &Path,
    provision: &Arc<Mutex<ProvisionSnapshot>>,
) -> Result<EngineReport, String> {
    let engines_dir = managed_engine_dir();
    std::fs::create_dir_all(&engines_dir).map_err(|e| format!("create engine dir: {e}"))?;
    // Archives land next to engine/ under app-data (or engines/ sibling of state file).
    let archive_dir = state_file
        .parent()
        .map(|p| p.join("engines"))
        .unwrap_or_else(|| PathBuf::from("engines"));
    std::fs::create_dir_all(&archive_dir).map_err(|e| format!("create engines dir: {e}"))?;
    let archive = archive_dir.join(FAH_PORTABLE_ARCHIVE_FILENAME);
    if archive.is_file() {
        let _ = std::fs::remove_file(&archive);
    }

    set_provision(
        provision,
        EngineState::Provisioning,
        provision_download_detail(0, None),
    );
    let sha =
        download_installer_with_progress(FAH_PORTABLE_URL, &archive, provision).await?;

    if let Err(err) = append_provision_log(state_file, FAH_PORTABLE_URL, &sha, &archive) {
        set_provision(
            provision,
            EngineState::Provisioning,
            format!("portable archive downloaded (sha256 {sha}); provision-log write failed: {err}"),
        );
    }

    set_provision(
        provision,
        EngineState::Provisioning,
        "extracting portable FAH client…".to_string(),
    );
    extract_tar_bz2(&archive, &engines_dir)?;

    let exe = managed_fah_client_exe().ok_or_else(|| {
        format!(
            "extracted {FAH_PORTABLE_ARCHIVE_FILENAME} under {} but fah-client.exe was not found",
            engines_dir.display()
        )
    })?;

    set_provision(
        provision,
        EngineState::Provisioning,
        format!("starting {}…", exe.display()),
    );
    let report = start_fah_exe_and_wait(&exe).await;
    clear_provision(provision);
    match report {
        Ok(mut r) => {
            r.detail = format!(
                "Portable FAH client ready (sha256 {sha}); {}. Path: {}",
                r.detail,
                exe.display()
            );
            Ok(r)
        }
        Err(e) => Err(e),
    }
}

/// Extract a `.tar.bz2` with the OS `tar` (Windows 10+ includes bsdtar).
fn extract_tar_bz2(archive: &Path, dest_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dest_dir).map_err(|e| format!("create extract dir: {e}"))?;
    let status = std::process::Command::new("tar")
        .args(["-xjf"])
        .arg(archive)
        .arg("-C")
        .arg(dest_dir)
        .status()
        .map_err(|e| {
            format!(
                "failed to run tar to extract {}: {e} (Windows 10+ should ship tar.exe)",
                archive.display()
            )
        })?;
    if !status.success() {
        return Err(format!(
            "tar extract failed for {} (exit {status})",
            archive.display()
        ));
    }
    Ok(())
}

/// Stream the installer to `dest`, updating `provision` with live download progress and computing
/// the SHA-256 as bytes arrive. Returns the hex digest. Refuses an implausibly small body.
async fn download_installer_with_progress(
    url: &str,
    dest: &Path,
    provision: &Arc<Mutex<ProvisionSnapshot>>,
) -> Result<String, String> {
    use futures_util::StreamExt;
    use std::io::Write;

    let client = reqwest::Client::builder()
        .timeout(ENGINE_DOWNLOAD_TIMEOUT)
        .user_agent("dagoat-fah-adapter")
        .https_only(true)
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("request installer: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "installer download: HTTP {} from {url}",
            resp.status()
        ));
    }
    let total = resp.content_length();

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create engines dir: {e}"))?;
    }
    let mut file =
        std::fs::File::create(dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("installer download body: {e}"))?;
        hasher.update(&chunk);
        file.write_all(&chunk)
            .map_err(|e| format!("write {}: {e}", dest.display()))?;
        downloaded += chunk.len() as u64;
        set_provision(
            provision,
            EngineState::Provisioning,
            provision_download_detail(downloaded, total),
        );
    }
    file.flush().map_err(|e| format!("flush installer: {e}"))?;

    // The v8 Windows installer is many MB — a tiny body means an error/redirect page, not a client.
    if downloaded < 1_000_000 {
        return Err(format!(
            "installer too small ({downloaded} bytes) — refusing to launch (server error page?)"
        ));
    }
    Ok(to_hex(&hasher.finalize()))
}

/// Append a provenance line to `engine-provision.log` (app-data): what URL we downloaded, its
/// SHA-256, and where it landed. This is the honesty record in lieu of an upstream signed hash.
fn append_provision_log(
    state_file: &Path,
    url: &str,
    sha256: &str,
    dest: &Path,
) -> Result<(), String> {
    let path = state_file.with_file_name("engine-provision.log");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create app-data dir: {e}"))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    use std::io::Write;
    writeln!(
        file,
        "{} downloaded url={url} sha256={sha256} dest={}",
        unix_now(),
        dest.display()
    )
    .map_err(|e| format!("write {}: {e}", path.display()))
}

/// Open the official FAH download page in the default browser (fallback only).
fn open_fah_download_page() -> Result<(), String> {
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", FAH_DOWNLOAD_URL])
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("open FAH download page: {e}"))
    }
    #[cfg(not(windows))]
    {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        std::process::Command::new(opener)
            .arg(FAH_DOWNLOAD_URL)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("open FAH download page: {e}"))
    }
}

/// Windows process check via `tasklist`. Returns false (not true) on any error — an unknown
/// result must never masquerade as "running". No-op on non-Windows. Matches both the system
/// installer name (`FAHClient.exe`) and the portable package (`fah-client.exe`).
fn fah_process_running() -> bool {
    #[cfg(windows)]
    {
        use std::process::Command;
        for image in ["FAHClient.exe", "fah-client.exe"] {
            let out = Command::new("tasklist")
                .args(["/FI", &format!("IMAGENAME eq {image}"), "/NH"])
                .output();
            if let Ok(o) = out {
                let text = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
                if text.contains(&image.to_ascii_lowercase()) {
                    return true;
                }
            }
        }
        false
    }
    #[cfg(not(windows))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// Stop = kill the FAH client process (A-D T5, design §C3, founder decision 2026-07-12)
// ---------------------------------------------------------------------------

/// `taskkill` invocations `kill_fah_client` runs, in order: the FAH v8 portable package name
/// (`fah-client.exe`, what Task Manager shows for a Goat-managed engine) and the legacy
/// system-installer name (`FAHClient.exe`). Pure and testable — building the command list stays
/// separate from actually spawning `taskkill`.
fn taskkill_invocations() -> Vec<Vec<String>> {
    ["fah-client.exe", "FAHClient.exe"]
        .into_iter()
        .map(|image| vec!["/F".to_string(), "/IM".to_string(), image.to_string()])
        .collect()
}

/// `taskkill` exit codes: `0` = terminated, `128` = no such process — fine, Stop is idempotent
/// (clicking it when FAH isn't running is not an error) — anything else (e.g. `1` access denied)
/// is a real failure the UI must show.
fn taskkill_outcome(code: Option<i32>) -> Result<bool, String> {
    match code {
        Some(0) => Ok(true),
        Some(128) => Ok(false),
        Some(c) => Err(format!("taskkill failed with exit code {c}")),
        None => Err("taskkill terminated without an exit code".to_string()),
    }
}

/// Stop = kill the FAH client process, replacing the previous "finish the unit first" behavior
/// (`finish_messages`/FAH `state: finish`). FAH v8 checkpoints work units to disk, so folding
/// resumes from the last checkpoint on the next Start. Windows-only: `taskkill` doesn't exist
/// elsewhere, and the app ships on Windows only.
fn kill_fah_client() -> Result<bool, String> {
    #[cfg(windows)]
    {
        let mut any_killed = false;
        for args in taskkill_invocations() {
            let status = std::process::Command::new("taskkill")
                .args(&args)
                .status()
                .map_err(|e| format!("could not run taskkill: {e}"))?;
            any_killed |= taskkill_outcome(status.code())?;
        }
        Ok(any_killed)
    }
    #[cfg(not(windows))]
    {
        Err(
            "Stop (process kill) is only supported on Windows; the Goat desktop app ships on \
             Windows only."
                .to_string(),
        )
    }
}

fn default_state_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("com.goatcoin.dagoat"))
        .unwrap_or_else(|| std::env::temp_dir().join("com.goatcoin.dagoat"))
}

fn default_state_file() -> PathBuf {
    default_state_dir().join("fah-state.json")
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

fn load_persisted(path: &Path) -> FahPersisted {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_persisted(path: &Path, persisted: &FahPersisted) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create app-data dir: {e}"))?;
    }
    let json = serde_json::to_string_pretty(persisted).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| format!("write {}: {e}", path.display()))
}

/// FAH identity snapshot exposed to the UI: username presence (first-run gate), the effective
/// (persisted-or-default) team, whether a user passkey is set, and the legacy shared-passkey
/// brand flag. The passkey VALUE never appears here — see `effective_identity`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct FahIdentity {
    pub username: Option<String>,
    pub team: String,
    /// True when the user has a non-empty stored passkey (optional QRB bonus).
    pub passkey_set: bool,
    /// Backward-compat: true ONLY if the stored passkey equals the retired shared founder key.
    /// Empty / unset → false (no longer auto-filled).
    pub passkey_is_default: bool,
}

/// Resolve the persisted identity with team default applied. The passkey VALUE never leaves
/// this module toward the UI — only presence + legacy-brand flags.
fn effective_identity(p: &FahPersisted) -> FahIdentity {
    let username = p.username.clone().filter(|u| !u.trim().is_empty());
    let team = p
        .team
        .clone()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_TEAM.to_string());
    let passkey = effective_passkey(p);
    FahIdentity {
        username,
        team,
        passkey_set: passkey.is_some(),
        passkey_is_default: passkey.as_deref() == Some(LEGACY_SHARED_PASSKEY),
    }
}

/// Resolve the effective passkey: `Some` only when the user has set a non-blank value.
/// No automatic fill of the retired shared founder key.
fn effective_passkey(p: &FahPersisted) -> Option<String> {
    p.passkey
        .clone()
        .filter(|k| !k.trim().is_empty())
}

/// Read the on-disk persisted identity for the UI (App first-run gate + team brand block).
pub(crate) fn load_fah_identity() -> FahIdentity {
    effective_identity(&load_persisted(&default_state_file()))
}

/// Evidence artifact: the latest raw FAH stats response body, persisted verbatim (not
/// re-serialized) so a founder can inspect exactly what the mint basis was computed against.
/// Overwritten on every successful poll. Non-critical — a write failure here must never block
/// the credit-critical delta/save path.
fn save_latest_stats_body(state_file: &Path, body: &str) -> Result<(), String> {
    let path = state_file.with_file_name("fah-stats-latest.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create app-data dir: {e}"))?;
    }
    std::fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Crash-recovery evidence: every unit ever returned is echoed here; the UI journal is the
/// source of truth; reconcile manually from this file if the journal write ever fails.
///
/// Append-only JSON Lines (one `WorkUnit` per line) so the file is safe to append to across
/// process restarts and never needs to be fully re-read/re-written. This is a durability
/// belt-and-braces measure: `list_completions` advances the baseline at-most-once (S9), so
/// once units are returned they can never be re-derived from FAH — this file is the only
/// on-disk trace of them on the Rust side if the UI's own journal write ever fails.
fn append_units_echo(state_file: &Path, units: &[WorkUnit]) -> Result<(), String> {
    let path = state_file.with_file_name("units-echo.jsonl");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create app-data dir: {e}"))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    use std::io::Write;
    for unit in units {
        let line = serde_json::to_string(unit).map_err(|e| format!("serialize unit: {e}"))?;
        writeln!(file, "{line}").map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Stats-delta (mint basis) — pure logic
// ---------------------------------------------------------------------------

/// Given the persisted baseline and a freshly-read credited-WU count, decide what to mint.
///
/// - Baseline `None` (first ever poll for this machine): record `new_wus` and emit **nothing** —
///   WUs credited before the user bound this machine are not retroactively minted (honesty).
/// - `new_wus > prev`: emit one `WorkUnit` per newly-credited WU, ids `fah-wu-{n}` for
///   `n in prev+1..=new_wus`, evidence = SHA-256 of the raw stats body — unless the jump exceeds
///   `DELTA_SANITY_CAP` (S9), in which case the baseline is held (not advanced), no units are
///   emitted, and the third return value carries an anomaly-detail message.
/// - Otherwise (no change, or an anomalous decrease): keep the high-water mark, emit nothing —
///   never lower the baseline, which would re-credit WUs on recovery.
///
/// Returns `(new_baseline, units, anomaly_detail)`; `anomaly_detail` is `None` in all normal
/// cases and `Some(msg)` only when the sanity cap held the baseline.
fn compute_delta(
    baseline: Option<u64>,
    new_wus: u64,
    raw_body: &str,
    username: &str,
    at: u64,
) -> (u64, Vec<WorkUnit>, Option<String>) {
    match baseline {
        None => (new_wus, Vec::new(), None),
        Some(prev) if new_wus > prev => {
            let delta = new_wus - prev;
            if delta > DELTA_SANITY_CAP {
                return (
                    prev,
                    Vec::new(),
                    Some(format!(
                        "credited-WU jump of {delta} exceeds sanity cap ({DELTA_SANITY_CAP}); \
                         baseline held — check username/stats"
                    )),
                );
            }
            // evidence = sha256(raw stats body); the latest raw body is persisted to
            // fah-stats-latest.json for founder inspection; per-batch evidence bodies become
            // part of the S9 pending journal.
            let evidence = sha256_hex(raw_body);
            let units = (prev + 1..=new_wus)
                .map(|n| WorkUnit {
                    unit_id: format!("fah-wu-{n}"),
                    weight: 1,
                    backend_ref: username.to_string(),
                    at,
                    evidence: evidence.clone(),
                })
                .collect();
            (new_wus, units, None)
        }
        Some(prev) => (prev, Vec::new(), None),
    }
}

fn sha256_hex(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    to_hex(&hasher.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Stats HTTP fetch (live path)
// ---------------------------------------------------------------------------

struct StatsFetch {
    status: u16,
    body: String,
    new_etag: Option<String>,
}

/// One conditional GET against the FAH stats API. `If-None-Match` is sent when we hold an ETag;
/// a 304 short-circuits with an empty body. Uses rustls only (no openssl).
async fn fetch_stats(username: &str, etag: Option<&str>) -> Result<StatsFetch, String> {
    let client = reqwest::Client::builder()
        .user_agent("dagoat-fah-adapter")
        .build()
        .map_err(|e| e.to_string())?;

    let mut req = client.get(format!("{FAH_STATS_BASE}{username}"));
    if let Some(tag) = etag {
        req = req.header(reqwest::header::IF_NONE_MATCH, tag);
    }

    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let new_etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if status == 304 {
        return Ok(StatsFetch {
            status,
            body: String::new(),
            new_etag,
        });
    }

    if !(200..300).contains(&status) {
        return Err(format!("stats API returned HTTP {status}"));
    }

    let body = resp.text().await.map_err(|e| e.to_string())?;
    Ok(StatsFetch {
        status,
        body,
        new_etag,
    })
}

// ---------------------------------------------------------------------------
// Control WebSocket (live path)
// ---------------------------------------------------------------------------

/// Reconnecting control loop: attach, stream frames into `live`, forward commands, and on any
/// failure degrade `live` to an actionable `error` before backing off (1s → 30s) and retrying.
async fn ws_control_loop(
    live: Arc<Mutex<FahLive>>,
    stop: Arc<AtomicBool>,
    mut rx: mpsc::UnboundedReceiver<Vec<String>>,
    identity: FahPersisted,
) {
    let mut backoff = BACKOFF_MIN;
    while !stop.load(Ordering::SeqCst) {
        match connect_and_stream(&live, &stop, &mut rx, &identity).await {
            Ok(()) => backoff = BACKOFF_MIN,
            Err(err) => {
                if let Ok(mut l) = live.lock() {
                    l.connected = false;
                    l.state = "error".to_string();
                    l.units.clear();
                    l.detail = format!(
                        "FAH local API unreachable ({err}). Ensure FAHClient v8 is running and its \
                         local API is enabled at 127.0.0.1:{FAH_LOCAL_PORT}."
                    );
                }
            }
        }
        if stop.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff.saturating_mul(2), BACKOFF_MAX);
    }
}

/// One connection lifetime: open the socket, push identity config, then multiplex the incoming
/// frame stream with the outgoing command channel until the socket closes or `stop` is set.
async fn connect_and_stream(
    live: &Arc<Mutex<FahLive>>,
    stop: &Arc<AtomicBool>,
    rx: &mut mpsc::UnboundedReceiver<Vec<String>>,
    identity: &FahPersisted,
) -> Result<(), String> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (ws, _resp) = tokio_tungstenite::connect_async(FAH_WS_URL)
        .await
        .map_err(|e| e.to_string())?;
    let (mut write, mut read) = ws.split();

    if let Ok(mut l) = live.lock() {
        l.connected = true;
        l.state = "connecting".to_string();
        l.detail = "connected to FAHClient local API".to_string();
    }

    // Push the founder identity so the local client folds under the configured account/team.
    if let Some(patch) = identity_config_patch(identity) {
        let _ = write.send(Message::Text(patch.into())).await;
    }
    // Ask FAH to stream work-unit updates (official `wus` command).
    {
        let mut fields = serde_json::Map::new();
        fields.insert("enable".to_string(), json!(true));
        let _ = write
            .send(Message::Text(fah_cmd("wus", fields).into()))
            .await;
    }

    // Candidates for the last command awaiting an error-frame fallback.
    let mut pending_fallback: Vec<String> = Vec::new();

    loop {
        if stop.load(Ordering::SeqCst) {
            let _ = write.send(Message::Close(None)).await;
            return Ok(());
        }

        tokio::select! {
            maybe_cmd = rx.recv() => {
                match maybe_cmd {
                    Some(mut candidates) if !candidates.is_empty() => {
                        let primary = candidates.remove(0);
                        pending_fallback = candidates;
                        write
                            .send(Message::Text(primary.into()))
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    Some(_) => {}
                    // Command channel dropped (disconnect) — end this connection cleanly.
                    None => return Ok(()),
                }
            }
            maybe_msg = read.next() => {
                match maybe_msg {
                    Some(Ok(Message::Text(text))) => {
                        let text = text.to_string();
                        if frame_is_error(&text) {
                            if let Some(next) = pending_fallback.first().cloned() {
                                pending_fallback.remove(0);
                                let _ = write.send(Message::Text(next.into())).await;
                            }
                        } else {
                            pending_fallback.clear();
                        }
                        if let Ok(mut l) = live.lock() {
                            l.apply_frame(&text);
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if let Ok(text) = String::from_utf8(bytes.to_vec()) {
                            if let Ok(mut l) = live.lock() {
                                l.apply_frame(&text);
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => {} // ping/pong/frame — tungstenite auto-handles pongs
                    Some(Err(err)) => return Err(err.to_string()),
                }
            }
        }
    }
}

/// FAH v8 WebSocket command envelope (matches fah-web-client-bastet `send_command`):
/// `{ cmd, time, ...fields }`. Bare `{config:…}` / `{state:…}` are rejected as empty cmds.
fn fah_cmd(cmd: &str, fields: serde_json::Map<String, Value>) -> String {
    let mut m = fields;
    m.insert("cmd".to_string(), json!(cmd));
    m.insert("time".to_string(), json!(iso8601_now()));
    Value::Object(m).to_string()
}

/// ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) without pulling in the chrono crate.
fn iso8601_now() -> String {
    iso8601_from_secs(unix_now())
}

/// Pure epoch-seconds -> ISO-8601 UTC string formatter (split out from `iso8601_now` for
/// fixture testing). Converts days-since-epoch to a proleptic-Gregorian civil date via
/// Howard Hinnant's `civil_from_days` algorithm:
/// <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>
fn iso8601_from_secs(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let time_of_day = secs % 86_400;
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = yoe as i64 + era * 400 + if m <= 2 { 1 } else { 0 };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Build a `config` command that binds the local client to the configured FAH identity. Team
/// ALWAYS resolves through `DEFAULT_TEAM` so every Goat install folds for the GOAT team even
/// before the user configures anything. Passkey is included only when the user has set one
/// (optional QRB bonus — base score works without it). Username is omitted until set.
/// Previously the whole patch short-circuited to `None` without a username, which left a fresh
/// FAHClient on its own defaults (wrong team, hostname machine name) — the bug the founder hit:
/// it joined team 11 instead of GOAT's 1068318. Now the patch is always sent (at least team).
fn identity_config_patch(identity: &FahPersisted) -> Option<String> {
    let mut config = serde_json::Map::new();
    // Username only when the user has actually set one; team is unconditional.
    if let Some(username) = identity.username.as_ref().map(|u| u.trim()).filter(|u| !u.is_empty()) {
        config.insert("user".to_string(), json!(username));
    }
    let team = identity
        .team
        .clone()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_TEAM.to_string());
    // FAH accepts team as number or string; prefer number when parseable.
    if let Ok(n) = team.parse::<u64>() {
        config.insert("team".to_string(), json!(n));
    } else {
        config.insert("team".to_string(), json!(team));
    }
    // Optional user passkey only — never auto-fill the retired shared founder key.
    if let Some(pk) = effective_passkey(identity) {
        config.insert("passkey".to_string(), json!(pk));
    }
    let mut fields = serde_json::Map::new();
    fields.insert("config".to_string(), Value::Object(config));
    Some(fah_cmd("config", fields))
}

/// Heuristic error-frame classifier for the command fallback chain. FAH v8's exact error shape
/// is not contractually documented, so we treat an object carrying an `error` key (or an
/// `error`-typed message) as a failure. Deliberately conservative: false negatives just mean we
/// don't fall back, false positives are harmless (we try the next candidate form).
fn frame_is_error(raw: &str) -> bool {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) => {
            map.contains_key("error")
                || map
                    .get("type")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t.eq_ignore_ascii_case("error"))
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Command builders — pure, testable
// ---------------------------------------------------------------------------

/// Pause via official `cmd: state` (fah-web-client Machine.set_state).
fn pause_messages() -> Vec<String> {
    let mut fields = serde_json::Map::new();
    fields.insert("state".to_string(), json!("pause"));
    vec![fah_cmd("state", fields)]
}

/// v8 Web Control “Fold” — start computing after resources are configured. (This is also the
/// "unpause"/resume verb — v8 has no distinct unpause command.)
fn fold_messages() -> Vec<String> {
    let mut fields = serde_json::Map::new();
    fields.insert("state".to_string(), json!("fold"));
    vec![fah_cmd("state", fields)]
}

/// Still a valid FAH v8 verb builder, but no longer wired to any UI action — `stop()` now kills
/// the process (design §C3) instead of finishing the current unit. Kept because it stays a real,
/// correct FAH command and `command_builders_use_official_cmd_envelope` exercises it directly.
#[allow(dead_code)]
fn finish_messages() -> Vec<String> {
    let mut fields = serde_json::Map::new();
    fields.insert("state".to_string(), json!("finish"));
    vec![fah_cmd("state", fields)]
}

/// Official FAH v8 WebSocket dump (fah-web-client / bastet API): discard a stuck unit so the
/// client can assign a new one. Same recovery users do manually in Web Control (pause + dump).
fn dump_unit_messages(unit_id: &str) -> Vec<String> {
    let mut fields = serde_json::Map::new();
    fields.insert("unit".to_string(), json!(unit_id));
    vec![fah_cmd("dump", fields)]
}

/// Auto-pilot CPU budget (spec §11.2): leave 2 cores of headroom for the OS/UI, but always fold
/// on at least one core. 32→30, 4→2, 2→1, 1→1.
fn auto_cpus(total: usize) -> u64 {
    total.saturating_sub(2).max(1) as u64
}

/// Host logical-core count (`std::thread::available_parallelism`), 1 on failure.
fn host_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Enable all supported GPUs + set the CPU budget + leave idle-only off. `cpus` is supplied by the
/// caller (the auto-pilot Start passes `auto_cpus(host_parallelism())`) so this builder stays a
/// pure, fixture-testable function. Official wire form: `{"cmd":"config","config":{…},"time":…}`.
fn enable_gpus_and_cpus_config(tree: &Value, cpus: u64) -> String {
    let mut gpus_cfg = serde_json::Map::new();

    // Detected GPUs: info.gpus (object keyed like "gpu:01:00:00") or top-level gpus.
    let detected = tree
        .get("info")
        .and_then(|i| i.get("gpus"))
        .or_else(|| tree.get("gpus"));

    if let Some(Value::Object(map)) = detected {
        for (id, gpu) in map {
            let supported = gpu
                .get("supported")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if supported {
                gpus_cfg.insert(id.clone(), json!({ "enabled": true }));
            }
        }
    } else if let Some(Value::Array(arr)) = detected {
        for (i, gpu) in arr.iter().enumerate() {
            let id = gpu
                .get("id")
                .and_then(Value::as_str)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("gpu:{i}"));
            let supported = gpu
                .get("supported")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if supported {
                gpus_cfg.insert(id, json!({ "enabled": true }));
            }
        }
    }

    if let Some(Value::Object(map)) = tree.get("config").and_then(|c| c.get("gpus")) {
        for id in map.keys() {
            gpus_cfg
                .entry(id.clone())
                .or_insert_with(|| json!({ "enabled": true }));
        }
    }

    // Also scan groups.*.config.gpus (multi-group machines).
    if let Some(Value::Object(groups)) = tree.get("groups") {
        for (_name, group) in groups {
            if let Some(Value::Object(map)) = group.get("config").and_then(|c| c.get("gpus")) {
                for id in map.keys() {
                    gpus_cfg
                        .entry(id.clone())
                        .or_insert_with(|| json!({ "enabled": true }));
                }
            }
        }
    }

    let config = json!({
        "gpus": gpus_cfg,
        "cpus": cpus.max(1),
        "paused": false,
        "on_idle": false,
        "cuda": true,
        "hip": true
    });
    let mut fields = serde_json::Map::new();
    fields.insert("config".to_string(), config);
    fah_cmd("config", fields)
}

/// What "Start contributing" sends.
/// 1) Identity (user/team/passkey) — **always**, including account-linked clients, so GOAT team
///    1068318 is re-asserted (account token often freezes team=11 until account settings change).
/// 2) Resource config (GPUs/CPUs) — skipped when account-linked (client ignores it).
/// 3) Fold state — always (same as Web Control Fold).
fn start_command_batches(tree: &Value, cpus: u64, identity: &FahPersisted) -> Vec<Vec<String>> {
    let mut batches: Vec<Vec<String>> = Vec::new();
    if let Some(patch) = identity_config_patch(identity) {
        batches.push(vec![patch]);
    }
    if !is_account_linked(tree) {
        batches.push(vec![enable_gpus_and_cpus_config(tree, cpus)]);
    }
    batches.push(fold_messages());
    batches
}

/// Read `info.version` from the FAH state tree (e.g. `"8.5.5"`).
fn read_client_version_from_tree(tree: &Value) -> Option<String> {
    tree.get("info")
        .and_then(|i| i.get("version"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parse dotted version prefix into (major, minor, patch) for comparison.
fn parse_version_triple(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.trim().split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// True when the live client should be upgraded via official `latest.exe`.
fn client_version_needs_upgrade(version: &str) -> bool {
    let Some(cur) = parse_version_triple(version) else {
        return false;
    };
    let Some(min) = parse_version_triple(FAH_MIN_GOOD_VERSION) else {
        return false;
    };
    cur < min
}

/// Read live FAH team number from the state tree (`config.team`).
fn read_team_from_tree(tree: &Value) -> Option<u64> {
    let team_val = tree.get("config").and_then(|c| c.get("team"))?;
    if let Some(n) = team_val.as_u64() {
        return Some(n);
    }
    if let Some(s) = team_val.as_str() {
        return s.trim().parse().ok();
    }
    None
}

/// Resolve the FAH unit **id** required by `cmd: dump` (bastet Remote.cpp / web machine.dump).
/// Accepts a real id, or a WU number / number-string fallback by looking up the live units array.
fn resolve_dump_unit_id(tree: &Value, query: &str) -> Result<String, String> {
    let q = query.trim();
    if q.is_empty() {
        return Err("dump requires a non-empty FAH unit id".into());
    }
    let units = tree
        .get("units")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // Exact match on unit.id (official).
    for u in &units {
        if let Some(id) = u.get("id").and_then(Value::as_str) {
            if id == q {
                return Ok(id.to_string());
            }
        }
    }

    // Match by WU number (UI often labels WU#56; dump must still send id).
    if let Ok(num) = q.parse::<u64>() {
        for u in &units {
            let n = u
                .get("number")
                .and_then(Value::as_u64)
                .or_else(|| u.get("number").and_then(value_to_f32).map(|f| f as u64));
            if n == Some(num) {
                if let Some(id) = u.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                    return Ok(id.to_string());
                }
                return Err(format!(
                    "WU#{num} has no FAH unit id yet (still assigning?) — wait or dump from Web Control"
                ));
            }
        }
    }

    // If the query looks like a real id but isn't in the tree yet, still try it (race after snapshot).
    if q.len() >= 8 && q.parse::<u64>().is_err() {
        return Ok(q.to_string());
    }

    Err(format!(
        "Unit {q:?} not found in FAH units list — refresh status or use the unit id from Web Control"
    ))
}

/// Scale FAH's `cpus` resource setting to Low(25%)/Medium(50%)/Full(100%) of available cores.
/// Always leaves at least one core folding. This is resource control only — design §4: it never
/// affects the mint. Official wire: `cmd: config`.
fn power_config_message(level: PowerLevel, available_cores: usize) -> String {
    let factor = match level {
        PowerLevel::Low => 0.25,
        PowerLevel::Medium => 0.50,
        PowerLevel::Full => 1.0,
    };
    let scaled = ((available_cores as f64) * factor).round() as u64;
    let cpus = scaled.max(1);
    let mut fields = serde_json::Map::new();
    fields.insert("config".to_string(), json!({ "cpus": cpus }));
    fah_cmd("config", fields)
}

/// Read the number of cores available to fold from the FAH state tree, preferring the machine's
/// total (`info.cpus`) over the currently-configured value (`config.cpus`), falling back to the
/// host's logical parallelism.
fn available_cores_from_tree(tree: &Value) -> usize {
    tree.get("info")
        .and_then(|i| i.get("cpus"))
        .and_then(Value::as_u64)
        .or_else(|| {
            tree.get("config")
                .and_then(|c| c.get("cpus"))
                .and_then(Value::as_u64)
        })
        .map(|c| c as usize)
        .filter(|c| *c > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
}

// ---------------------------------------------------------------------------
// State-tree helpers — pure
// ---------------------------------------------------------------------------

/// Recursive merge used for snapshots and partial-object updates: objects merge key-by-key,
/// while arrays and scalars replace wholesale (so a snapshot's full `units` array overwrites the
/// old one, but a `{"config":{"paused":true}}` patch preserves the rest of `config`).
fn merge_value(dst: &mut Value, src: &Value) {
    match (dst, src) {
        (Value::Object(d), Value::Object(s)) => {
            for (k, v) in s {
                merge_value(d.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (d, s) => *d = s.clone(),
    }
}

/// Apply a v8 patch array `[path…, value]` by walking string keys (into objects) and numeric
/// indices (into arrays) and setting the final element. Returns false only if the path is
/// genuinely unresolvable (e.g. a numeric index into a non-array scalar), so the caller retains
/// the last-good state.
///
/// Critically, real FAHClient v8 APPENDS a brand-new element with a frame whose numeric index
/// EQUALS the current array length — e.g. `["units", 2, {…}]` when `units` has length 2. That is
/// a normal append, not an error: at `idx == len` we push exactly one new slot. `idx > len` never
/// happens on the wire from a real client, so we reject it (return false, retain last-good state)
/// rather than grow the array to an attacker/bug-controlled size. Missing intermediate containers
/// are created with the correct type for the *next* path element (numeric next → array, string
/// next → object) so a patch can materialize structure the initial snapshot did not carry.
fn apply_path_update(tree: &mut Value, arr: &[Value]) -> bool {
    if arr.len() < 2 {
        return false;
    }
    let (path, tail) = arr.split_at(arr.len() - 1);
    let new_value = &tail[0];

    let mut cursor = tree;
    for key in path {
        cursor = match key {
            Value::String(field) => {
                // The slot must be an object. A freshly-created `Null` slot is coerced to one;
                // an existing non-object scalar is a genuine shape mismatch → retain last state.
                if cursor.is_null() {
                    *cursor = Value::Object(serde_json::Map::new());
                }
                let Some(obj) = cursor.as_object_mut() else {
                    return false;
                };
                obj.entry(field.clone()).or_insert(Value::Null)
            }
            Value::Number(num) => {
                let Some(idx) = num.as_u64() else {
                    return false;
                };
                let idx = idx as usize;
                // The slot must be an array. A freshly-created `Null` slot is coerced to one.
                if cursor.is_null() {
                    *cursor = Value::Array(Vec::new());
                }
                let Some(list) = cursor.as_array_mut() else {
                    return false;
                };
                // Real v8 append: index == len pushes exactly one new slot. index > len is not a
                // legitimate FAH frame (and would otherwise let a WS payload drive an unbounded
                // alloc or overflow idx+1) so we reject it and let the caller retain last-good state.
                if idx == list.len() {
                    list.push(Value::Null); // real FAH v8 appends a new element at index == current length
                } else if idx > list.len() {
                    return false; // out-of-range index: reject this frame, retain last-good state (never grow unboundedly)
                }
                &mut list[idx]
            }
            _ => return false,
        };
    }
    *cursor = new_value.clone();
    true
}

fn derive_units(tree: &Value) -> Vec<FahUnit> {
    tree.get("units")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(parse_unit).collect())
        .unwrap_or_default()
}

fn parse_unit(value: &Value) -> Option<FahUnit> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| value.get("number").map(value_to_string))
        .or_else(|| {
            value
                .get("unit")
                .and_then(Value::as_str)
                .map(str::to_string)
        })?;
    let number = value
        .get("number")
        .and_then(Value::as_u64)
        .or_else(|| value.get("number").and_then(value_to_f32).map(|f| f as u64));

    // Project lives on assignment in v8 Web Control (`unit.assign.project`).
    let project = value
        .get("assignment")
        .and_then(|a| a.get("project"))
        .map(value_to_string)
        .or_else(|| value.get("project").map(value_to_string))
        .unwrap_or_default();

    // Match FAH Web Control: prefer wu_progress, else progress; clamp 0..1.
    let raw = value
        .get("wu_progress")
        .and_then(value_to_f32)
        .or_else(|| value.get("progress").and_then(value_to_f32))
        .unwrap_or(0.0);
    let progress = raw.clamp(0.0, 1.0);

    let state = value
        .get("state")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_default();

    // GPU if assignment.gpus non-empty or unit.gpus non-empty (Web Control `get gpus()`).
    let gpu_count = value
        .get("assignment")
        .and_then(|a| a.get("gpus"))
        .and_then(Value::as_array)
        .map(|a| a.len())
        .or_else(|| value.get("gpus").and_then(Value::as_array).map(|a| a.len()))
        .or_else(|| {
            value
                .get("gpus")
                .and_then(Value::as_u64)
                .map(|n| n as usize)
        })
        .unwrap_or(0);
    let resource = if gpu_count > 0 {
        "GPU".to_string()
    } else {
        "CPU".to_string()
    };

    Some(FahUnit {
        id,
        number,
        project,
        progress,
        state,
        resource,
    })
}

/// Whether the local FAHClient is bound to a Folding@home account. When linked, `info.account` is
/// a non-empty string and the client IGNORES local-WebSocket config/state commands (confirmed live
/// against a real v8 client): its CPU/GPU settings and fold state follow the account, not Goat.
fn is_account_linked(tree: &Value) -> bool {
    tree.get("info")
        .and_then(|i| i.get("account"))
        .and_then(Value::as_str)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// True when a per-machine group actually has folding resources (so its `paused` flag is a real
/// signal). A group with explicitly zero CPUs and no GPUs can't fold, so its pause state is noise.
/// Unknown resources (no `cpus`/`gpus` keys) are treated as resourced — conservative.
fn group_has_resources(group_config: &Value) -> bool {
    let has_gpus = group_config
        .get("gpus")
        .and_then(Value::as_object)
        .map(|m| !m.is_empty())
        .unwrap_or(false)
        || group_config
            .get("gpus")
            .and_then(Value::as_array)
            .map(|a| !a.is_empty())
            .unwrap_or(false);
    if group_config.get("cpus").is_none() && group_config.get("gpus").is_none() {
        return true;
    }
    let cpus = group_config
        .get("cpus")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    cpus > 0 || has_gpus
}

/// Collect every `paused` boolean that governs a folding resource: the (legacy/back-compat)
/// top-level `config.paused`, plus each resourced `groups.<name>.config.paused`. Real FAHClient v8
/// carries NO top-level `config.paused` — paused lives per-group — so reading only the top level
/// (the old bug) always saw `false` and reported "idle" while the machine was actually folding.
fn collect_paused_flags(tree: &Value) -> Vec<bool> {
    let mut flags = Vec::new();
    if let Some(p) = tree
        .get("config")
        .and_then(|c| c.get("paused"))
        .and_then(Value::as_bool)
    {
        flags.push(p);
    }
    if let Some(Value::Object(groups)) = tree.get("groups") {
        for group in groups.values() {
            if let Some(cfg) = group.get("config") {
                if group_has_resources(cfg) {
                    if let Some(p) = cfg.get("paused").and_then(Value::as_bool) {
                        flags.push(p);
                    }
                }
            }
        }
    }
    flags
}

/// A per-unit state token counts as actively folding unless it is a pause or finish token.
/// (Real v8 active tokens include RUN/RUNNING/DOWNLOAD/SEND/CORE… — we treat "anything not
/// PAUSED/FINISH" as active rather than enumerating an open-ended set.)
fn is_paused_unit_state(state: &str) -> bool {
    state.eq_ignore_ascii_case("PAUSE") || state.eq_ignore_ascii_case("PAUSED")
}
fn is_finish_unit_state(state: &str) -> bool {
    state.eq_ignore_ascii_case("FINISH") || state.eq_ignore_ascii_case("FINISHED")
}
/// Actually computing (core running). DOWNLOAD/ASSIGN/WAIT are NOT computing — reporting them
/// as "running" was the founder's false-RUN-at-0% bug (Assign Wait Loop still showed Run).
fn is_computing_unit_state(state: &str) -> bool {
    state.eq_ignore_ascii_case("RUN") || state.eq_ignore_ascii_case("RUNNING")
}
/// Transitional FAH states: assign server, core download, upload — progress often stays 0%.
fn is_waiting_unit_state(state: &str) -> bool {
    matches!(
        state.to_ascii_uppercase().as_str(),
        "DOWNLOAD"
            | "ASSIGN"
            | "GET_WAIT"
            | "WAIT"
            | "CORE"
            | "SEND"
            | "UPLOAD"
            | "UPLOADING"
            | "FETCH"
            | "COPY"
    ) || state.to_ascii_uppercase().contains("WAIT")
}
/// Unit is in-flight (not paused/finished) — includes waiting and computing.
fn is_active_unit_state(state: &str) -> bool {
    !is_paused_unit_state(state) && !is_finish_unit_state(state) && !state.is_empty()
}
/// Heuristic: zero progress + waiting state → stuck assign/download loop candidate.
fn unit_looks_stuck(unit: &FahUnit) -> bool {
    is_waiting_unit_state(&unit.state) && unit.progress < 0.001
}

/// Overall run state derived from the tree. Paused lives per-group in real v8 (`groups.<name>
/// .config.paused`), so we read every resourced group's flag: if all are paused the run is
/// "paused". Computing units → "running". Only assign/download/wait → "waiting" (honest).
/// "idle" only when there are zero units AND nothing is paused; all-FINISH → "finishing".
fn derive_state(tree: &Value, units: &[FahUnit]) -> String {
    let paused_flags = collect_paused_flags(tree);
    let all_paused = !paused_flags.is_empty() && paused_flags.iter().all(|&p| p);
    if all_paused {
        return "paused".to_string();
    }
    if units.iter().any(|u| is_computing_unit_state(&u.state)) {
        return "running".to_string();
    }
    if units.iter().any(|u| is_waiting_unit_state(&u.state)) {
        return "waiting".to_string();
    }
    if units.is_empty() {
        return "idle".to_string();
    }
    if units.iter().all(|u| is_finish_unit_state(&u.state)) {
        return "finishing".to_string();
    }
    // Units present but none computing/waiting and not all finishing (e.g. all unit-PAUSED):
    // not folding — report paused rather than a misleading "running".
    if units.iter().any(|u| is_paused_unit_state(&u.state)) {
        return "paused".to_string();
    }
    if units.iter().any(|u| is_active_unit_state(&u.state)) {
        // Unknown non-pause token — still in flight, but not proven computing.
        return "waiting".to_string();
    }
    "paused".to_string()
}

/// Honest one-line status detail. Prefer wrong-team warning, then account-linked note, then stuck
/// assign/download units, pause reasons, else "connected".
fn derive_detail(tree: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(team) = read_team_from_tree(tree) {
        if team.to_string() != DEFAULT_TEAM {
            parts.push(format!(
                "FAH team is {team}, not GOAT {DEFAULT_TEAM} — credits go to the wrong team. Use Set GOAT team in Contribute (account-linked machines may need team {DEFAULT_TEAM} on foldingathome.org or unlink)."
            ));
        }
    }

    if is_account_linked(tree) {
        parts.push(ACCOUNT_LINKED_DETAIL.to_string());
    }

    let units = derive_units(tree);
    if let Some(stuck) = stuck_units_summary(&units) {
        parts.push(stuck);
    } else if let Some(reason) = tree.get("units").and_then(Value::as_array).and_then(|arr| {
        arr.iter().find_map(|u| {
            u.get("pauseReason")
                .or_else(|| u.get("pause_reason"))
                .and_then(Value::as_str)
        })
    }) {
        if !reason.is_empty() && !reason.eq_ignore_ascii_case("none") {
            parts.push(format!("paused: {reason}"));
        }
    } else if units.iter().any(|u| is_waiting_unit_state(&u.state)) {
        parts.push(
            "assigning/downloading work units (progress may stay 0% until RUN)".to_string(),
        );
    }

    if parts.is_empty() {
        "connected".to_string()
    } else {
        parts.join(" · ")
    }
}

fn stuck_units_summary(units: &[FahUnit]) -> Option<String> {
    let stuck: Vec<&FahUnit> = units.iter().filter(|u| unit_looks_stuck(u)).collect();
    if stuck.is_empty() {
        return None;
    }
    let labels: Vec<String> = stuck
        .iter()
        .take(4)
        .map(|u| {
            let n = u
                .number
                .map(|n| format!("WU#{n}"))
                .unwrap_or_else(|| u.id.chars().take(8).collect::<String>());
            format!("{n} {}", u.state)
        })
        .collect();
    Some(format!(
        "stuck at 0% in assign/download ({}). Dump stuck units in Goat or Web Control, then fold again.",
        labels.join(", ")
    ))
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

fn value_to_f32(value: &Value) -> Option<f32> {
    value
        .as_f64()
        .map(|f| f as f32)
        .or_else(|| value.as_str().and_then(|s| s.parse::<f32>().ok()))
}

fn to_unit_progress(unit: &FahUnit) -> UnitProgress {
    // FAH Web Control: `clamp(p * 100, 0, 100).toFixed(1)` → e.g. "25.5"
    let pct = (unit.progress * 100.0).clamp(0.0, 100.0);
    let progress_pct = format!("{pct:.1}");
    UnitProgress {
        id: unit.id.clone(),
        number: unit.number,
        project: unit.project.clone(),
        progress: unit.progress,
        progress_pct,
        resource: unit.resource.clone(),
        state: unit.state.clone(),
    }
}

// ---------------------------------------------------------------------------
// FAH on-disk 3D viz (viewerTop.json + viewerFrameN.json) — same data FAH Web Control uses
// ---------------------------------------------------------------------------

/// Snapshot for the right-side FAH 3D preview (topology + latest frame coordinates).
#[derive(Debug, Clone, Serialize)]
pub struct FahVizSnapshot {
    pub work_dir: String,
    pub unit_folder: String,
    pub frame_index: usize,
    pub frame_count: usize,
    /// Element symbols from viewerTop.atoms[*][0] (e.g. "C", "N", "O", "?").
    pub elements: Vec<String>,
    /// Atomic numbers from viewerTop.atoms[*][4] when present.
    pub atomic_numbers: Vec<u8>,
    /// Latest frame coordinates [[x,y,z], …] aligned with elements.
    pub positions: Vec<[f32; 3]>,
}

/// Load the newest available FAH visualization from the managed engine `work/` tree.
/// Returns `Ok(None)` when no frames exist yet (honest empty preview).
pub fn load_fah_viz_snapshot() -> Result<Option<FahVizSnapshot>, String> {
    let work_root = managed_engine_dir()
        .join(FAH_WIN_PORTABLE_PREFIX)
        .join("work");
    if !work_root.is_dir() {
        // Also try system FAH data dirs if portable work/ is missing.
        return Ok(None);
    }

    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let entries = std::fs::read_dir(&work_root).map_err(|e| format!("read work dir: {e}"))?;
    for ent in entries.flatten() {
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        let top = path.join("viewerTop.json");
        if !top.is_file() {
            continue;
        }
        let modified = ent
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        match &best {
            None => best = Some((modified, path)),
            Some((t, _)) if modified > *t => best = Some((modified, path)),
            _ => {}
        }
    }

    let Some((_t, unit_dir)) = best else {
        return Ok(None);
    };

    let top_raw = std::fs::read_to_string(unit_dir.join("viewerTop.json"))
        .map_err(|e| format!("read viewerTop: {e}"))?;
    let top: Value = serde_json::from_str(&top_raw).map_err(|e| format!("parse viewerTop: {e}"))?;
    let atoms = top
        .get("atoms")
        .and_then(Value::as_array)
        .ok_or_else(|| "viewerTop missing atoms[]".to_string())?;

    let mut elements = Vec::with_capacity(atoms.len());
    let mut atomic_numbers = Vec::with_capacity(atoms.len());
    for atom in atoms {
        let arr = atom.as_array();
        let el = arr
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        let z = arr
            .and_then(|a| a.get(4))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u8;
        elements.push(el);
        atomic_numbers.push(z);
    }

    // Collect viewerFrameN.json by index.
    let mut frames: Vec<(usize, PathBuf)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&unit_dir) {
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if let Some(rest) = name.strip_prefix("viewerFrame") {
                if let Some(num) = rest.strip_suffix(".json") {
                    if let Ok(idx) = num.parse::<usize>() {
                        frames.push((idx, ent.path()));
                    }
                }
            }
        }
    }
    frames.sort_by_key(|(i, _)| *i);
    if frames.is_empty() {
        return Ok(None);
    }
    let frame_count = frames.len();
    let (frame_index, frame_path) = frames.last().cloned().unwrap();
    let frame_raw =
        std::fs::read_to_string(&frame_path).map_err(|e| format!("read viewerFrame: {e}"))?;
    let frame_val: Value =
        serde_json::from_str(&frame_raw).map_err(|e| format!("parse viewerFrame: {e}"))?;
    let coords = frame_val
        .as_array()
        .ok_or_else(|| "viewerFrame is not an array".to_string())?;

    let mut positions = Vec::with_capacity(coords.len());
    for c in coords {
        let xyz = c.as_array().ok_or_else(|| "coord not array".to_string())?;
        if xyz.len() < 3 {
            continue;
        }
        let x = xyz[0].as_f64().unwrap_or(0.0) as f32;
        let y = xyz[1].as_f64().unwrap_or(0.0) as f32;
        let z = xyz[2].as_f64().unwrap_or(0.0) as f32;
        positions.push([x, y, z]);
    }

    Ok(Some(FahVizSnapshot {
        work_dir: work_root.display().to_string(),
        unit_folder: unit_dir
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default(),
        frame_index,
        frame_count,
        elements,
        atomic_numbers,
        positions,
    }))
}

// ---------------------------------------------------------------------------
// Tests — all fixtures are #[cfg(test)] only; no fake FAH server in product code.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// v8 full-state snapshot with two folding units and a config block.
    const SNAPSHOT_TWO_UNITS: &str = r#"{
        "units": [
            {"id": "01", "number": 0, "project": 18201, "state": "RUNNING", "progress": 0.42},
            {"id": "02", "number": 1, "project": 9999,  "state": "RUNNING", "progress": 0.10}
        ],
        "config": {"user": "alice", "team": "0", "paused": false, "cpus": 8},
        "info": {"cpus": 16}
    }"#;

    /// A paused snapshot — both the config flag and the per-unit state indicate pause.
    const SNAPSHOT_PAUSED: &str = r#"{
        "units": [
            {"id": "01", "number": 0, "project": 18201, "state": "PAUSED", "progress": 0.42, "pauseReason": "user requested"}
        ],
        "config": {"user": "alice", "team": "0", "paused": true, "cpus": 8}
    }"#;

    /// Not valid JSON — must be tolerated, retaining the last-good state.
    const MALFORMED_FRAME: &str = "{ this is definitely not json ]";

    fn connected_live() -> FahLive {
        let mut live = FahLive::from_install(InstallState::Running);
        live.connected = true;
        live
    }

    #[test]
    fn snapshot_two_units_parsed() {
        let mut live = connected_live();
        live.apply_frame(SNAPSHOT_TWO_UNITS);

        assert_eq!(live.units.len(), 2);
        assert_eq!(live.units[0].id, "01");
        assert_eq!(live.units[0].project, "18201");
        assert!((live.units[0].progress - 0.42).abs() < 1e-6);
        assert_eq!(live.units[1].id, "02");
        assert_eq!(live.units[1].project, "9999");
        assert_eq!(live.state, "running");
        let up = to_unit_progress(&live.units[0]);
        assert_eq!(up.progress_pct, "42.0");
    }

    #[test]
    fn wu_progress_preferred_over_progress_like_web_control() {
        let raw = r#"{
            "id": "abc",
            "number": 3,
            "state": "RUN",
            "progress": 0.10,
            "wu_progress": 0.255,
            "assignment": { "project": 18212, "gpus": ["gpu:01:00:00"] }
        }"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        let u = parse_unit(&v).expect("unit");
        assert!((u.progress - 0.255).abs() < 1e-6);
        assert_eq!(u.project, "18212");
        assert_eq!(u.resource, "GPU");
        assert_eq!(u.number, Some(3));
        assert_eq!(to_unit_progress(&u).progress_pct, "25.5");
    }

    #[test]
    fn paused_frame_sets_paused_state() {
        let mut live = connected_live();
        live.apply_frame(SNAPSHOT_PAUSED);

        assert_eq!(live.state, "paused");
        assert_eq!(live.units.len(), 1);
        assert!(live.detail.contains("user requested"));
    }

    #[test]
    fn malformed_frame_retains_last_good_state_and_sets_detail() {
        let mut live = connected_live();
        live.apply_frame(SNAPSHOT_TWO_UNITS);
        let good_units = live.units.clone();
        let good_state = live.state.clone();

        live.apply_frame(MALFORMED_FRAME);

        assert_eq!(live.units, good_units, "last-good units retained");
        assert_eq!(live.state, good_state, "last-good state retained");
        assert!(
            live.detail.contains("unparseable"),
            "detail surfaces the parse failure, got: {}",
            live.detail
        );
    }

    #[test]
    fn incremental_path_update_applies_over_snapshot() {
        let mut live = connected_live();
        live.apply_frame(SNAPSHOT_TWO_UNITS);

        // v8 patch form: [path..., value] — bump unit 0's progress.
        live.apply_frame(r#"["units", 0, "progress", 0.75]"#);

        assert!((live.units[0].progress - 0.75).abs() < 1e-6);
        assert!(
            (live.units[1].progress - 0.10).abs() < 1e-6,
            "other units untouched"
        );
    }

    #[test]
    fn partial_object_update_merges_without_dropping_units() {
        let mut live = connected_live();
        live.apply_frame(SNAPSHOT_TWO_UNITS);

        // A config-only pause patch must preserve the units array.
        live.apply_frame(r#"{"config": {"paused": true}}"#);

        assert_eq!(live.units.len(), 2, "units survive a config merge");
        assert_eq!(live.state, "paused");
    }

    // -----------------------------------------------------------------------
    // FIX A — apply_path_update handles v8 appends and is resilient.
    // -----------------------------------------------------------------------

    /// A brand-new unit is APPENDED via a frame whose numeric index EQUALS the current length.
    #[test]
    fn path_update_appends_first_unit_into_empty_units_array() {
        let mut tree = json!({ "units": [] });
        let arr: Vec<Value> = serde_json::from_str(
            r#"["units", 0, {"id":"01","number":0,"state":"RUN","progress":0.10,"assignment":{"project":18201}}]"#,
        )
        .unwrap();
        assert!(
            apply_path_update(&mut tree, &arr),
            "append at idx==len(0) must succeed"
        );
        let units = derive_units(&tree);
        assert_eq!(units.len(), 1, "the appended unit is now present");
        assert_eq!(units[0].project, "18201");
    }

    #[test]
    fn path_update_appends_third_unit_when_len_two() {
        let mut live = connected_live();
        live.apply_frame(SNAPSHOT_TWO_UNITS); // len == 2
                                              // Real v8 append: index EQUALS current length.
        live.apply_frame(
            r#"["units", 2, {"id":"03","number":2,"state":"RUN","progress":0.0,"assignment":{"project":18203}}]"#,
        );
        assert_eq!(live.units.len(), 3, "append at idx==len grows the array");
        assert_eq!(live.units[2].project, "18203");
        assert_eq!(live.state, "running", "still folding after an append");
    }

    #[test]
    fn path_update_updates_existing_unit_wu_progress() {
        let mut live = connected_live();
        live.apply_frame(SNAPSHOT_TWO_UNITS);
        // In-place scalar update of an existing unit.
        live.apply_frame(r#"["units", 1, "wu_progress", 0.104]"#);
        assert_eq!(live.units.len(), 2, "no unit added or removed");
        assert!(
            (live.units[1].progress - 0.104).abs() < 1e-6,
            "wu_progress applied in place: {}",
            live.units[1].progress
        );
    }

    #[test]
    fn genuinely_bad_frame_retains_last_good_units_and_state() {
        let mut live = connected_live();
        live.apply_frame(SNAPSHOT_TWO_UNITS);
        let good_units = live.units.clone();
        // A numeric index into a non-array (config is an object) is genuinely unhandleable.
        live.apply_frame(r#"["config", 0, "x", 1]"#);
        assert_eq!(
            live.units, good_units,
            "an unhandleable frame must NOT empty or corrupt the last-good units"
        );
        assert_eq!(live.units.len(), 2);
        assert_eq!(
            live.state, "running",
            "never regress to idle on an unhandleable frame"
        );
    }

    /// idx > list.len() must be rejected outright — not grown with Nulls up to idx — so a
    /// malicious or malformed WS frame can never force an unbounded allocation.
    #[test]
    fn path_update_rejects_out_of_range_index_without_panic() {
        let mut tree = json!({ "units": [{"id":"01"}] });
        let arr: Vec<Value> = serde_json::from_str(r#"["units", 5, {"id":"x"}]"#).unwrap();
        assert!(
            !apply_path_update(&mut tree, &arr),
            "idx (5) > list.len() (1) must be rejected"
        );
        let units = tree.get("units").and_then(Value::as_array).unwrap();
        assert_eq!(
            units.len(),
            1,
            "units array must remain unchanged, not grown or truncated"
        );
    }

    /// A `u64::MAX` index is the overflow case (`idx + 1` would overflow `usize` on the old
    /// `resize(idx + 1, ..)` path): this must be rejected cleanly, never panic.
    #[test]
    fn path_update_rejects_u64_max_index_without_panic() {
        let mut tree = json!({ "units": [{"id":"01"}] });
        let arr: Vec<Value> =
            serde_json::from_str(r#"["units", 18446744073709551615, "x"]"#).unwrap();
        assert!(
            !apply_path_update(&mut tree, &arr),
            "u64::MAX index must be rejected without panicking"
        );
        let units = tree.get("units").and_then(Value::as_array).unwrap();
        assert_eq!(units.len(), 1, "units array must remain unchanged");
    }

    // -----------------------------------------------------------------------
    // FIX B — derive_state reads group-scoped paused (real v8), not top-level.
    // -----------------------------------------------------------------------

    #[test]
    fn derive_state_reads_group_paused_folding() {
        // Real v8: NO top-level config.paused; paused lives at groups.<name>.config.paused.
        let folding = json!({
            "config": {"user":"a","team":0},
            "groups": {"": {"config": {"paused": false, "cpus": 16}}},
            "units": [{"number":0,"state":"RUN","progress":0.5,"assignment":{"project":1}}]
        });
        let units = derive_units(&folding);
        assert_eq!(
            derive_state(&folding, &units),
            "running",
            "group not paused + a RUN unit → running (the founder's exact bug)"
        );
    }

    #[test]
    fn derive_state_reads_group_paused_all_paused() {
        let all_paused = json!({
            "config": {"user":"a","team":0},
            "groups": {"": {"config": {"paused": true, "cpus": 16}}},
            "units": [{"number":0,"state":"RUN","progress":0.5,"assignment":{"project":1}}]
        });
        let units = derive_units(&all_paused);
        assert_eq!(
            derive_state(&all_paused, &units),
            "paused",
            "all resourced groups paused → paused"
        );
    }

    #[test]
    fn derive_state_idle_only_when_no_units_and_no_pause() {
        let empty = json!({
            "config": {"user":"a"},
            "groups": {"": {"config": {"paused": false, "cpus": 16}}},
            "units": []
        });
        let units = derive_units(&empty);
        assert_eq!(
            derive_state(&empty, &units),
            "idle",
            "idle only when zero units AND no group paused"
        );
    }

    #[test]
    fn derive_state_assign_download_is_waiting_not_running() {
        // Founder bug: Assign Wait Loop / DOWNLOAD at 0% was reported as "running".
        let tree = json!({
            "config": {"user":"a"},
            "groups": {"": {"config": {"paused": false, "cpus": 8, "gpus": {"gpu:0": {"enabled": true}}}}},
            "units": [
                {"id":"a","number":56,"state":"DOWNLOAD","progress":0.0,"assignment":{"project":18201,"gpus":[0]}},
                {"id":"b","number":58,"state":"ASSIGN","progress":0.0,"assignment":{"project":18202,"gpus":[0]}},
                {"id":"c","number":1,"state":"PAUSE","progress":0.0,"assignment":{"project":1}}
            ]
        });
        let units = derive_units(&tree);
        assert_eq!(
            derive_state(&tree, &units),
            "waiting",
            "assign/download at 0% must not look like RUN"
        );
        assert!(
            units.iter().any(unit_looks_stuck),
            "zero-progress download/assign units count as stuck"
        );
        let detail = derive_detail(&tree);
        assert!(
            detail.to_ascii_lowercase().contains("stuck")
                || detail.to_ascii_lowercase().contains("assign"),
            "detail should mention stuck/assign: {detail}"
        );
    }

    #[test]
    fn derive_state_run_beats_waiting() {
        let tree = json!({
            "groups": {"": {"config": {"paused": false, "cpus": 8}}},
            "units": [
                {"id":"a","number":1,"state":"DOWNLOAD","progress":0.0,"assignment":{"project":1}},
                {"id":"b","number":2,"state":"RUN","progress":0.1,"assignment":{"project":2}}
            ]
        });
        let units = derive_units(&tree);
        assert_eq!(derive_state(&tree, &units), "running");
    }

    #[test]
    fn dump_unit_messages_use_official_dump_cmd() {
        // Matches fah-web-client machine.js: send_command('dump', {unit: unit.id})
        // and fah-client Remote.cpp: msg->getString("unit") -> getUnit(id)->dumpWU().
        let msgs = dump_unit_messages("01");
        let v: Value = serde_json::from_str(&msgs[0]).unwrap();
        assert_eq!(v.get("cmd").and_then(Value::as_str), Some("dump"));
        assert_eq!(v.get("unit").and_then(Value::as_str), Some("01"));
        assert!(v.get("time").is_some());
    }

    #[test]
    fn resolve_dump_unit_id_prefers_real_id_over_wu_number() {
        let tree = json!({
            "units": [
                {"id": "abcXYZ99", "number": 56, "state": "DOWNLOAD", "progress": 0.0},
                {"id": "defUVW11", "number": 58, "state": "ASSIGN", "progress": 0.0}
            ]
        });
        assert_eq!(
            resolve_dump_unit_id(&tree, "56").unwrap(),
            "abcXYZ99",
            "dump by WU number must resolve to FAH unit id"
        );
        assert_eq!(
            resolve_dump_unit_id(&tree, "abcXYZ99").unwrap(),
            "abcXYZ99"
        );
        assert!(
            resolve_dump_unit_id(&tree, "99").unwrap_err().contains("not found"),
            "unknown WU number fails clearly"
        );
    }

    #[test]
    fn read_team_from_tree_parses_number_or_string() {
        assert_eq!(
            read_team_from_tree(&json!({"config": {"team": 11}})),
            Some(11)
        );
        assert_eq!(
            read_team_from_tree(&json!({"config": {"team": "1068318"}})),
            Some(1068318)
        );
        assert_eq!(read_team_from_tree(&json!({})), None);
    }

    #[test]
    fn client_version_needs_upgrade_flags_8_5_5() {
        assert!(client_version_needs_upgrade("8.5.5"));
        assert!(client_version_needs_upgrade("8.4.9"));
        assert!(!client_version_needs_upgrade("8.5.6"));
        assert!(!client_version_needs_upgrade("8.6.0"));
        assert_eq!(
            read_client_version_from_tree(&json!({"info": {"version": "8.5.5"}})).as_deref(),
            Some("8.5.5")
        );
    }

    // -----------------------------------------------------------------------
    // FIX C — account-linked honesty.
    // -----------------------------------------------------------------------

    #[test]
    fn is_account_linked_true_on_fixture_false_without_account() {
        let tree: Value = serde_json::from_str(FIXTURE_V8_SNAPSHOT).unwrap();
        assert!(
            is_account_linked(&tree),
            "fixture info.account is a non-empty string → linked"
        );
        assert!(!is_account_linked(&json!({"info": {"version": "8.5.5"}})));
        assert!(!is_account_linked(&json!({"info": {"account": ""}})));
        assert!(!is_account_linked(&json!({"info": {"account": "   "}})));
        assert!(!is_account_linked(&json!({})));
    }

    // -----------------------------------------------------------------------
    // Regression guard — the founder's exact bug: the real captured v8 snapshot
    // must derive "running" with 3 units, not "idle".
    // -----------------------------------------------------------------------

    const FIXTURE_V8_SNAPSHOT: &str = include_str!("../../tests/fixtures/fah_v8_snapshot.json");

    #[test]
    fn real_v8_snapshot_fixture_derives_running_with_three_units() {
        let mut live = connected_live();
        live.apply_frame(FIXTURE_V8_SNAPSHOT);

        assert_eq!(
            live.state, "running",
            "REGRESSION GUARD: the real captured v8 snapshot must derive running, not idle"
        );
        assert_eq!(live.units.len(), 3, "all 3 real units parsed");
        assert_eq!(live.units[0].project, "18201", "real project parsed");
        assert!(
            (live.units[1].progress - 0.104).abs() < 1e-6,
            "real wu_progress parsed: {}",
            live.units[1].progress
        );
        assert_eq!(
            live.units[1].resource, "GPU",
            "unit with assignment.gpus is a GPU unit"
        );
        // Account-linked honesty is surfaced in the detail, not a false config claim.
        assert!(
            live.detail.to_lowercase().contains("account"),
            "linked-client honesty in detail: {}",
            live.detail
        );
    }

    #[test]
    fn stats_delta_baseline_then_increment_emits_sequential_units() {
        let body_baseline = r#"{"name":"alice","wus":40,"score":123456}"#;
        // First ever poll: record baseline (40), emit nothing (no retroactive credit).
        let (baseline, units, anomaly) =
            compute_delta(None, 40, body_baseline, "alice", 1_700_000_000);
        assert_eq!(baseline, 40);
        assert!(
            units.is_empty(),
            "baseline poll must not mint pre-existing WUs"
        );
        assert!(anomaly.is_none());

        // Next poll: +3 credited WUs -> exactly three sequential WorkUnits.
        let body_next = r#"{"name":"alice","wus":43,"score":130000}"#;
        let (baseline, units, anomaly) =
            compute_delta(Some(40), 43, body_next, "alice", 1_700_000_060);
        assert_eq!(baseline, 43);
        assert_eq!(units.len(), 3);
        assert!(anomaly.is_none());

        let expected_evidence = {
            let mut h = Sha256::new();
            h.update(body_next.as_bytes());
            to_hex(&h.finalize())
        };
        for (i, unit) in units.iter().enumerate() {
            let n = 41 + i as u64;
            assert_eq!(unit.unit_id, format!("fah-wu-{n}"));
            assert_eq!(unit.weight, 1);
            assert_eq!(unit.backend_ref, "alice");
            assert_eq!(unit.at, 1_700_000_060);
            assert_eq!(
                unit.evidence, expected_evidence,
                "evidence = sha256(raw body)"
            );
        }
        // Evidence must be a 64-hex-char SHA-256 digest.
        assert_eq!(units[0].evidence.len(), 64);
    }

    #[test]
    fn stats_delta_no_change_emits_nothing_and_holds_baseline() {
        let body = r#"{"wus":43}"#;
        let (baseline, units, anomaly) = compute_delta(Some(43), 43, body, "alice", 1);
        assert_eq!(baseline, 43);
        assert!(units.is_empty());
        assert!(anomaly.is_none());

        // Anomalous decrease must not lower the high-water mark or re-emit.
        let (baseline, units, anomaly) = compute_delta(Some(43), 40, body, "alice", 1);
        assert_eq!(baseline, 43);
        assert!(units.is_empty());
        assert!(anomaly.is_none());
    }

    #[test]
    fn stats_delta_sanity_cap_holds_baseline_on_implausible_jump() {
        let body = r#"{"wus":2000}"#;
        let (baseline, units, anomaly) = compute_delta(Some(100), 2000, body, "alice", 1);
        assert_eq!(baseline, 100, "baseline held, not advanced");
        assert!(units.is_empty(), "no units minted on an implausible jump");
        let msg = anomaly.expect("anomaly detail present");
        assert!(msg.contains("1900"), "detail names the delta: {msg}");
        assert!(
            msg.contains("sanity cap"),
            "detail names the mechanism: {msg}"
        );
    }

    #[test]
    fn stats_delta_sanity_cap_boundary_is_not_tripped() {
        let body = r#"{"wus":1100}"#;
        // Delta of exactly 1000 (the cap) must NOT trip the cap.
        let (baseline, units, anomaly) = compute_delta(Some(100), 1100, body, "alice", 1);
        assert_eq!(baseline, 1100);
        assert_eq!(units.len(), 1000);
        assert!(anomaly.is_none());
    }

    #[test]
    fn persistence_round_trips_config_and_baseline() {
        let dir = std::env::temp_dir().join(format!("dagoat-fah-test-{}", unix_now()));
        let file = dir.join("fah-state.json");

        let original = FahPersisted {
            username: Some("alice".to_string()),
            team: Some("goat-team".to_string()),
            passkey: Some("secret-passkey".to_string()),
            last_credited_wus: Some(42),
        };
        save_persisted(&file, &original).expect("save must succeed");

        let loaded = load_persisted(&file);
        assert_eq!(loaded, original);
        assert_eq!(loaded.last_credited_wus, Some(42));

        // Missing file loads a default (no panic, no fabricated data).
        let missing = load_persisted(&dir.join("does-not-exist.json"));
        assert_eq!(missing, FahPersisted::default());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn units_echo_appends_json_lines_round_trip() {
        let dir = std::env::temp_dir().join(format!("dagoat-fah-echo-{}", unix_now()));
        let state_file = dir.join("fah-state.json");

        let batch1 = vec![WorkUnit {
            unit_id: "fah-wu-41".to_string(),
            weight: 1,
            backend_ref: "alice".to_string(),
            at: 1_700_000_060,
            evidence: "ev-a".to_string(),
        }];
        append_units_echo(&state_file, &batch1).expect("first append must succeed");

        let batch2 = vec![
            WorkUnit {
                unit_id: "fah-wu-42".to_string(),
                weight: 1,
                backend_ref: "alice".to_string(),
                at: 1_700_000_061,
                evidence: "ev-b".to_string(),
            },
            WorkUnit {
                unit_id: "fah-wu-43".to_string(),
                weight: 1,
                backend_ref: "alice".to_string(),
                at: 1_700_000_062,
                evidence: "ev-c".to_string(),
            },
        ];
        append_units_echo(&state_file, &batch2).expect("second append must succeed");

        let path = state_file.with_file_name("units-echo.jsonl");
        let raw = std::fs::read_to_string(&path).expect("echo file readable");
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(
            lines.len(),
            3,
            "one line per unit, appended across both calls"
        );

        let ids: Vec<String> = lines
            .iter()
            .map(|line| {
                let v: Value = serde_json::from_str(line).expect("each line is valid JSON");
                v.get("unit_id")
                    .and_then(Value::as_str)
                    .expect("unit_id present")
                    .to_string()
            })
            .collect();
        assert_eq!(ids, vec!["fah-wu-41", "fah-wu-42", "fah-wu-43"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn units_echo_write_failure_returns_err_not_panic() {
        let dir = std::env::temp_dir().join(format!("dagoat-fah-echo-fail-{}", unix_now()));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        // The echo file's path is itself an existing directory, so std::fs::OpenOptions::open
        // fails deterministically on both Windows and Unix — exercises the non-critical error
        // path (echo write failing must never panic or lose the caller's units).
        let state_file = dir.join("fah-state.json");
        let echo_path = state_file.with_file_name("units-echo.jsonl");
        std::fs::create_dir_all(&echo_path).expect("create dir shadowing echo file path");

        let units = vec![WorkUnit {
            unit_id: "fah-wu-1".to_string(),
            weight: 1,
            backend_ref: "alice".to_string(),
            at: 1,
            evidence: "ev".to_string(),
        }];
        let result = append_units_echo(&state_file, &units);
        assert!(
            result.is_err(),
            "echo write failure must surface as Err, not panic"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configure_persists_and_rejects_unknown_keys() {
        let dir = std::env::temp_dir().join(format!("dagoat-fah-cfg-{}", unix_now()));
        let backend = FahBackend::with_state_file(dir.join("fah-state.json"));

        backend.configure("username", "alice").unwrap();
        backend.configure("team", "0").unwrap();
        backend.configure("passkey", "pk").unwrap();
        assert!(backend.configure("nonsense", "x").is_err());

        let reloaded = load_persisted(&dir.join("fah-state.json"));
        assert_eq!(reloaded.username.as_deref(), Some("alice"));
        assert_eq!(reloaded.passkey.as_deref(), Some("pk"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_stats_snapshot_holds_baseline_and_reemits_after_save_failure() {
        let dir = std::env::temp_dir().join(format!("dagoat-fah-savefail-{}", unix_now()));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        // (a) state_file points at a path that is itself an existing directory — fs::write into
        // it fails deterministically on both Windows and Unix, forcing save_persisted to error.
        let broken_state_file = dir.join("broken-state");
        std::fs::create_dir_all(&broken_state_file).expect("create broken state dir");

        let broken_backend = FahBackend::with_state_file(broken_state_file.clone());
        {
            let mut persisted = broken_backend
                .persisted
                .lock()
                .expect("persisted mutex poisoned");
            persisted.last_credited_wus = Some(40);
            persisted.username = Some("alice".to_string());
        }

        let body = r#"{"wus":43}"#;
        let units = broken_backend.apply_stats_snapshot(43, body, "alice", 1);
        assert!(
            units.is_empty(),
            "save failure must defer credit, not lose it"
        );
        {
            let persisted = broken_backend
                .persisted
                .lock()
                .expect("persisted mutex poisoned");
            assert_eq!(
                persisted.last_credited_wus,
                Some(40),
                "baseline must not advance before a durable save succeeds"
            );
        }

        // (b) the same WUs re-emit once the baseline can be durably written.
        let working_backend = FahBackend::with_state_file(dir.join("fah-state.json"));
        {
            let mut persisted = working_backend
                .persisted
                .lock()
                .expect("persisted mutex poisoned");
            persisted.last_credited_wus = Some(40);
            persisted.username = Some("alice".to_string());
        }
        let units = working_backend.apply_stats_snapshot(43, body, "alice", 2);
        assert_eq!(units.len(), 3);
        for (i, unit) in units.iter().enumerate() {
            let n = 41 + i as u64;
            assert_eq!(unit.unit_id, format!("fah-wu-{n}"));
        }
        {
            let persisted = working_backend
                .persisted
                .lock()
                .expect("persisted mutex poisoned");
            assert_eq!(persisted.last_credited_wus, Some(43));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configure_username_change_resets_baseline_and_prevents_retroactive_credit() {
        let dir = std::env::temp_dir().join(format!("dagoat-fah-userreset-{}", unix_now()));
        let state_file = dir.join("fah-state.json");
        let backend = FahBackend::with_state_file(state_file.clone());

        backend
            .configure("username", "alice")
            .expect("configure username");
        {
            let mut persisted = backend.persisted.lock().expect("persisted mutex poisoned");
            persisted.last_credited_wus = Some(10);
        }

        backend
            .configure("username", "bob")
            .expect("configure username change");
        {
            let persisted = backend.persisted.lock().expect("persisted mutex poisoned");
            assert_eq!(
                persisted.last_credited_wus, None,
                "baseline reset in memory"
            );
        }
        let reloaded = load_persisted(&state_file);
        assert_eq!(reloaded.last_credited_wus, None, "baseline reset on disk");
        assert_eq!(reloaded.username.as_deref(), Some("bob"));

        // First poll against the new account only records a baseline, no retroactive credit.
        let units = backend.apply_stats_snapshot(50, "body-a", "bob", 1);
        assert!(units.is_empty());
        {
            let persisted = backend.persisted.lock().expect("persisted mutex poisoned");
            assert_eq!(persisted.last_credited_wus, Some(50));
        }

        // Subsequent poll credits normally.
        let units = backend.apply_stats_snapshot(52, "body-b", "bob", 2);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].unit_id, "fah-wu-51");
        assert_eq!(units[1].unit_id, "fah-wu-52");

        // Re-configuring with the SAME username must not reset an existing baseline.
        backend
            .configure("username", "bob")
            .expect("re-configure same username");
        {
            let persisted = backend.persisted.lock().expect("persisted mutex poisoned");
            assert_eq!(
                persisted.last_credited_wus,
                Some(52),
                "same-value reconfigure must not reset baseline"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_install_is_honest_enum() {
        // Host-dependent: Missing / Installed / Running are all valid; never panics.
        let state = detect_install_impl();
        assert!(matches!(
            state,
            InstallState::Missing | InstallState::Installed | InstallState::Running
        ));
    }

    #[test]
    fn install_hint_points_at_official_download_and_managed_path() {
        let backend = FahBackend::with_state_file(
            std::env::temp_dir().join("dagoat-fah-hint/fah-state.json"),
        );
        let hint = backend.install_hint();
        assert!(
            hint.to_lowercase().contains("managed")
                || hint.to_lowercase().contains("portable")
                || hint.to_lowercase().contains("start contributing"),
            "one-product managed-engine copy: {hint}"
        );
        assert!(
            hint.contains("powered by Folding@home")
                || hint.contains("Folding@home open")
                || hint.contains("Folding@home")
        );
        // Honesty: the hint must not promise wages/earnings.
        assert!(!hint.to_lowercase().contains("wage"));
        assert!(!hint.to_lowercase().contains("mine crypto"));
    }

    #[test]
    fn engine_state_maps_from_detect_install() {
        let backend = FahBackend::with_state_file(
            std::env::temp_dir().join("dagoat-fah-engine-state/fah-state.json"),
        );
        assert!(backend.supports_managed_engine());
        match detect_install_impl() {
            InstallState::Missing => assert_eq!(backend.engine_state(), EngineState::Missing),
            InstallState::Installed => assert_eq!(backend.engine_state(), EngineState::Ready),
            InstallState::Running => assert_eq!(backend.engine_state(), EngineState::Running),
        }
    }

    #[tokio::test]
    async fn ensure_engine_returns_report_without_panic() {
        // Avoid multi‑MB network download in unit tests when FAH is not already present.
        std::env::set_var("GOAT_FAH_NO_AUTO_PROVISION", "1");
        let backend = FahBackend::with_state_file(
            std::env::temp_dir().join("dagoat-fah-ensure/fah-state.json"),
        );
        // Host-dependent: must not panic or fabricate Running when API is down.
        let report = backend.ensure_engine().await.expect("ensure_engine Ok");
        assert!(report.managed);
        assert!(!report.detail.is_empty());
        match report.state {
            EngineState::Running => {
                assert!(
                    report.detail.contains("reachable") || report.detail.contains("Started"),
                    "running detail: {}",
                    report.detail
                );
            }
            EngineState::Ready => {
                assert!(
                    report.detail.contains("not reachable") || report.detail.contains("FAH"),
                    "ready detail: {}",
                    report.detail
                );
            }
            EngineState::Missing => {
                assert!(
                    report.detail.contains("auto-provision")
                        || report.detail.contains("Folding@home")
                        || report.detail.contains("FAH"),
                    "missing detail: {}",
                    report.detail
                );
            }
            EngineState::Error => {
                assert!(
                    report.detail.contains("could not start") || report.detail.contains("error"),
                    "error detail: {}",
                    report.detail
                );
            }
            other => panic!("unexpected ensure_engine state: {other:?}"),
        }
        // stop is best-effort no-op when we only attach.
        assert!(backend.stop_engine().await.is_ok());
    }

    #[test]
    fn enable_gpus_and_cpus_enables_supported_gpus_and_unpauses() {
        let tree = json!({
            "info": {
                "cpus": 12,
                "gpus": {
                    "gpu:0": { "supported": true, "description": "Test GPU 0" },
                    "gpu:1": { "supported": false, "description": "Unsupported" }
                }
            },
            "config": { "cpus": 2, "paused": true, "gpus": {} }
        });
        // The builder now takes an explicit cpus budget (the auto-pilot Start passes
        // auto_cpus(host_parallelism())); it must plumb it straight through.
        let msg = enable_gpus_and_cpus_config(&tree, 10);
        let v: Value = serde_json::from_str(&msg).expect("json");
        assert_eq!(v.get("cmd").and_then(Value::as_str), Some("config"));
        assert!(v.get("time").is_some());
        let cfg = v.get("config").expect("config");
        assert_eq!(cfg.get("paused").and_then(Value::as_bool), Some(false));
        assert_eq!(cfg.get("on_idle").and_then(Value::as_bool), Some(false));
        assert_eq!(cfg.get("cpus").and_then(Value::as_u64), Some(10));
        let gpus = cfg.get("gpus").and_then(Value::as_object).expect("gpus");
        assert_eq!(
            gpus.get("gpu:0")
                .and_then(|g| g.get("enabled"))
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(
            !gpus.contains_key("gpu:1"),
            "unsupported GPU must not be enabled"
        );
        let fold = fold_messages();
        let fv: Value = serde_json::from_str(&fold[0]).expect("fold json");
        assert_eq!(fv.get("cmd").and_then(Value::as_str), Some("state"));
        assert_eq!(fv.get("state").and_then(Value::as_str), Some("fold"));
    }

    // -----------------------------------------------------------------------
    // A-D T4 — Start folds even on account-linked clients (only the resource
    // config patch stays skipped).
    // -----------------------------------------------------------------------

    #[test]
    fn start_batches_unlinked_identity_resources_then_fold() {
        let tree = json!({ "info": {} });
        let identity = FahPersisted {
            username: Some("GOAT-Rocket".into()),
            team: Some(DEFAULT_TEAM.into()),
            passkey: None,
            last_credited_wus: None,
        };
        let batches = start_command_batches(&tree, 6, &identity);
        assert_eq!(batches.len(), 3, "identity + resources + fold");
        assert!(batches[0][0].contains("\"config\"") && batches[0][0].contains("1068318"));
        assert!(batches[1][0].contains("\"config\"") && batches[1][0].contains("cpus"));
        assert!(batches[2][0].contains("\"state\":\"fold\""));
    }

    #[test]
    fn start_batches_linked_still_pushes_team_then_fold() {
        // Account-token link often freezes team=11; we still push GOAT team + fold (no GPU config).
        let tree = json!({ "info": { "account": "abc123" } });
        let identity = FahPersisted {
            username: Some("GOAT-Rocket".into()),
            team: Some(DEFAULT_TEAM.into()),
            passkey: None,
            last_credited_wus: None,
        };
        let batches = start_command_batches(&tree, 6, &identity);
        assert_eq!(batches.len(), 2, "linked: identity + fold only");
        assert!(
            batches[0][0].contains("1068318"),
            "must re-assert GOAT team even when linked: {}",
            batches[0][0]
        );
        assert!(batches[1][0].contains("\"state\":\"fold\""));
    }

    #[test]
    fn command_builders_use_official_cmd_envelope() {
        let pause: Value = serde_json::from_str(&pause_messages()[0]).unwrap();
        assert_eq!(pause.get("cmd").and_then(Value::as_str), Some("state"));
        assert_eq!(pause.get("state").and_then(Value::as_str), Some("pause"));
        // Resume/unpause uses the same Fold verb (v8 has no distinct unpause command).
        let fold: Value = serde_json::from_str(&fold_messages()[0]).unwrap();
        assert_eq!(fold.get("cmd").and_then(Value::as_str), Some("state"));
        assert_eq!(fold.get("state").and_then(Value::as_str), Some("fold"));
        let finish: Value = serde_json::from_str(&finish_messages()[0]).unwrap();
        assert_eq!(finish.get("cmd").and_then(Value::as_str), Some("state"));
        assert_eq!(finish.get("state").and_then(Value::as_str), Some("finish"));
    }

    #[test]
    fn power_config_scales_cores_and_never_zero() {
        let full: Value =
            serde_json::from_str(&power_config_message(PowerLevel::Full, 16)).unwrap();
        assert_eq!(full.get("cmd").and_then(Value::as_str), Some("config"));
        assert_eq!(
            full.pointer("/config/cpus").and_then(Value::as_u64),
            Some(16)
        );
        let med: Value =
            serde_json::from_str(&power_config_message(PowerLevel::Medium, 16)).unwrap();
        assert_eq!(med.pointer("/config/cpus").and_then(Value::as_u64), Some(8));
        let low: Value = serde_json::from_str(&power_config_message(PowerLevel::Low, 16)).unwrap();
        assert_eq!(low.pointer("/config/cpus").and_then(Value::as_u64), Some(4));
        // Never scales below one folding core, even on a single-core host at Low.
        let low1: Value = serde_json::from_str(&power_config_message(PowerLevel::Low, 1)).unwrap();
        assert_eq!(
            low1.pointer("/config/cpus").and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn available_cores_prefers_total_then_configured_then_host() {
        let tree = serde_json::from_str::<Value>(SNAPSHOT_TWO_UNITS).unwrap();
        assert_eq!(available_cores_from_tree(&tree), 16, "info.cpus wins");

        let only_config = json!({"config": {"cpus": 8}});
        assert_eq!(available_cores_from_tree(&only_config), 8);

        let empty = json!({});
        assert!(
            available_cores_from_tree(&empty) >= 1,
            "falls back to host parallelism"
        );
    }

    #[test]
    fn error_frame_classifier_distinguishes_errors_from_state() {
        assert!(frame_is_error(r#"{"error": "unknown command"}"#));
        assert!(frame_is_error(r#"{"type": "error", "message": "nope"}"#));
        assert!(!frame_is_error(SNAPSHOT_TWO_UNITS));
        assert!(!frame_is_error(r#"["units", 0, "progress", 0.5]"#));
        assert!(!frame_is_error("not json at all"));
    }

    #[test]
    fn identity_patch_binds_team_even_without_username_and_omits_unset_passkey() {
        // Regression (founder 2026-07-14): a fresh install with no username must STILL bind the
        // GOAT team, or FAHClient keeps its own defaults (the observed team 11 / hostname "IRP").
        // Passkey is optional — unset installs must NOT receive the retired shared founder key.
        let patch = identity_config_patch(&FahPersisted::default()).expect("team always sent");
        let dv: Value = serde_json::from_str(&patch).expect("json");
        assert_eq!(dv.get("cmd").and_then(Value::as_str), Some("config"));
        assert!(dv.pointer("/config/user").is_none(), "no user field until one is set");
        assert_eq!(dv.pointer("/config/team").and_then(Value::as_u64), Some(1068318));
        assert!(
            dv.pointer("/config/passkey").is_none(),
            "no passkey field when unset: {patch}"
        );

        let identity = FahPersisted {
            username: Some("alice".to_string()),
            team: Some("0".to_string()),
            passkey: Some("pk".to_string()),
            last_credited_wus: None,
        };
        let patch = identity_config_patch(&identity).expect("patch present");
        let v: Value = serde_json::from_str(&patch).expect("identity json");
        assert_eq!(v.get("cmd").and_then(Value::as_str), Some("config"));
        assert_eq!(
            v.pointer("/config/user").and_then(Value::as_str),
            Some("alice")
        );
        // Numeric team when the stored string parses as u64.
        assert_eq!(v.pointer("/config/team").and_then(Value::as_u64), Some(0));
        // Passkey goes to the LOCAL client config, never to the stats API.
        assert_eq!(
            v.pointer("/config/passkey").and_then(Value::as_str),
            Some("pk")
        );
    }

    #[test]
    fn identity_patch_applies_team_default_without_passkey() {
        let p = FahPersisted {
            username: Some("alice".into()),
            ..Default::default()
        };
        let patch = identity_config_patch(&p).expect("username set -> patch");
        assert!(
            patch.contains("\"team\":1068318"),
            "default team baked in: {patch}"
        );
        assert!(
            !patch.contains("passkey"),
            "passkey must not be auto-filled: {patch}"
        );
        assert!(
            !patch.contains(LEGACY_SHARED_PASSKEY),
            "retired shared passkey must never be sent automatically: {patch}"
        );
    }

    #[test]
    fn identity_patch_explicit_values_win_over_defaults() {
        let p = FahPersisted {
            username: Some("bob".into()),
            team: Some("42".into()),
            passkey: Some("deadbeef".into()),
            ..Default::default()
        };
        let patch = identity_config_patch(&p).expect("patch");
        assert!(patch.contains("\"team\":42"));
        assert!(patch.contains("deadbeef"));
        assert!(!patch.contains(LEGACY_SHARED_PASSKEY));
    }

    #[test]
    fn effective_identity_reports_passkey_flags() {
        let id = effective_identity(&FahPersisted::default());
        assert_eq!(id.team, DEFAULT_TEAM);
        assert!(!id.passkey_set, "unset passkey is not set");
        assert!(!id.passkey_is_default, "empty is not the legacy brand");
        assert!(id.username.is_none());

        let custom = effective_identity(&FahPersisted {
            passkey: Some("deadbeef".into()),
            ..Default::default()
        });
        assert!(custom.passkey_set);
        assert!(!custom.passkey_is_default);

        let legacy = effective_identity(&FahPersisted {
            passkey: Some(LEGACY_SHARED_PASSKEY.into()),
            ..Default::default()
        });
        assert!(legacy.passkey_set);
        assert!(
            legacy.passkey_is_default,
            "stored retired shared key still flags passkey_is_default for JS compat"
        );
    }

    #[test]
    fn effective_identity_has_no_username_default() {
        let id = effective_identity(&FahPersisted {
            username: Some("   ".into()),
            ..Default::default()
        });
        assert!(
            id.username.is_none(),
            "blank username is not a real username"
        );

        let id = effective_identity(&FahPersisted {
            username: Some("carol".into()),
            ..Default::default()
        });
        assert_eq!(id.username.as_deref(), Some("carol"));
    }

    #[test]
    fn fah_identity_serialization_never_carries_the_passkey_value() {
        let identity = effective_identity(&FahPersisted {
            passkey: Some("super-secret-passkey".into()),
            ..Default::default()
        });
        let v = serde_json::to_value(&identity).expect("serialize FahIdentity");
        let obj = v.as_object().expect("object");
        assert_eq!(
            obj.keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ["username", "team", "passkey_is_default", "passkey_set"]
                .into_iter()
                .map(String::from)
                .collect(),
        );
        let raw = v.to_string();
        assert!(
            !raw.contains("\"passkey\":"),
            "bare passkey key leaked: {raw}"
        );
        assert!(!raw.contains("super-secret-passkey"));
    }

    #[test]
    fn config_fields_declares_username_team_and_secret_passkey() {
        let backend = FahBackend::with_state_file(
            std::env::temp_dir().join("dagoat-fah-config-fields/fah-state.json"),
        );
        let fields = backend.config_fields();
        let keys: Vec<&str> = fields.iter().map(|f| f.key).collect();
        assert_eq!(keys, vec!["username", "team", "passkey"]);
        assert!(!fields[0].secret, "username is not secret");
        assert!(!fields[1].secret, "team is not secret");
        assert!(fields[2].secret, "passkey must be secret");
    }

    #[test]
    fn catalog_strings_are_exact() {
        let backend = FahBackend::with_state_file(
            std::env::temp_dir().join("dagoat-fah-strings/fah-state.json"),
        );
        assert_eq!(
            backend.beneficiary(),
            "Folding@home — public biomedical research"
        );
        assert_eq!(
            backend.isolation_class(),
            "Class C — host runs the official FAHClient; Goat does not claim a GPU sandbox"
        );
        assert!(backend
            .honesty_tags()
            .iter()
            .any(|t| t == "1 credited Folding@home work unit (WU) = 1 work unit = 1 GOAT"));
    }

    #[tokio::test]
    async fn status_reflects_install_probe_before_connect() {
        let backend = FahBackend::with_state_file(
            std::env::temp_dir().join("dagoat-fah-status/fah-state.json"),
        );
        let status = backend.status().await;
        // Pre-connect view comes from install probe — never fabricates unit progress.
        assert!(
            matches!(
                status.state.as_str(),
                "not_installed" | "installed_not_connected" | "reachable_not_connected"
            ),
            "unexpected pre-connect state: {}",
            status.state
        );
        assert!(
            status.units.is_empty(),
            "no fabricated units before connect"
        );
    }

    #[tokio::test]
    async fn list_completions_without_username_is_empty_no_network() {
        let backend = FahBackend::with_state_file(
            std::env::temp_dir().join("dagoat-fah-nouser/fah-state.json"),
        );
        // No username configured -> no poll, no fabricated completions.
        assert!(backend.list_completions().await.is_empty());
    }

    // -----------------------------------------------------------------------
    // Auto-pilot Start (P3.1) — pure logic, no network.
    // -----------------------------------------------------------------------

    #[test]
    fn auto_cpus_leaves_two_cores_headroom_and_never_zero() {
        // Spec §11.2 table: 32→30, 4→2, 2→1, 1→1.
        assert_eq!(auto_cpus(32), 30);
        assert_eq!(auto_cpus(4), 2);
        assert_eq!(auto_cpus(2), 1);
        assert_eq!(auto_cpus(1), 1);
        assert_eq!(auto_cpus(0), 1, "never below one folding core");
        assert_eq!(auto_cpus(3), 1);
        assert_eq!(auto_cpus(64), 62);
    }

    #[test]
    fn provision_download_detail_uses_percent_when_total_known_bytes_otherwise() {
        assert_eq!(
            provision_download_detail(500, Some(1000)),
            "downloading portable FAH client… 50%"
        );
        assert_eq!(
            provision_download_detail(1000, Some(1000)),
            "downloading portable FAH client… 100%"
        );
        // Unknown total → honest byte count, never a fabricated percentage.
        let d = provision_download_detail(2 * 1_048_576, None);
        assert!(
            d.starts_with("downloading portable FAH client… 2.0 MB"),
            "got: {d}"
        );
        assert!(!d.contains('%'));
        // Zero total is treated as unknown (no divide-by-zero, no fake %).
        assert!(!provision_download_detail(10, Some(0)).contains('%'));
    }

    #[test]
    fn extract_tar_bz2_rejects_missing_archive() {
        let err = extract_tar_bz2(
            Path::new("C:\\nonexistent\\goat-fah-missing.tar.bz2"),
            &std::env::temp_dir(),
        )
        .unwrap_err();
        assert!(
            err.contains("tar") || err.contains("failed") || err.contains("extract"),
            "got: {err}"
        );
    }

    #[test]
    fn engine_state_and_report_reflect_active_provisioning() {
        let backend = FahBackend::with_state_file(
            std::env::temp_dir().join("dagoat-fah-provstate/fah-state.json"),
        );
        // Simulate the download loop having set a live provisioning phase.
        set_provision(
            &backend.provision,
            EngineState::Provisioning,
            "downloading portable FAH client… 33%".to_string(),
        );
        assert_eq!(backend.engine_state(), EngineState::Provisioning);
        let report = backend.engine_report();
        assert_eq!(report.state, EngineState::Provisioning);
        assert!(report.managed);
        assert_eq!(report.detail, "downloading portable FAH client… 33%");

        // An actionable error is likewise surfaced while active.
        set_provision(
            &backend.provision,
            EngineState::Error,
            "installer timed out".to_string(),
        );
        assert_eq!(backend.engine_state(), EngineState::Error);
        assert_eq!(backend.engine_report().detail, "installer timed out");

        // Clearing falls back to a fresh detect probe (host-dependent, never panics).
        clear_provision(&backend.provision);
        assert!(matches!(
            backend.engine_state(),
            EngineState::Missing | EngineState::Ready | EngineState::Running
        ));
        // engine_report detail is non-empty honest copy for the fallback states we can hit.
        let fallback = backend.engine_report();
        assert!(fallback.managed);
        assert!(matches!(
            fallback.state,
            EngineState::Missing | EngineState::Ready | EngineState::Running
        ));
    }

    #[test]
    fn append_provision_log_records_url_and_sha256() {
        let dir = std::env::temp_dir().join(format!("dagoat-fah-provlog-{}", unix_now()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let state_file = dir.join("fah-state.json");
        let dest = dir.join("engines").join(FAH_INSTALLER_FILENAME);

        append_provision_log(&state_file, FAH_INSTALLER_URL, "deadbeef", &dest)
            .expect("first log append");
        append_provision_log(&state_file, FAH_INSTALLER_URL, "cafef00d", &dest)
            .expect("second log append");

        let log = std::fs::read_to_string(state_file.with_file_name("engine-provision.log"))
            .expect("provision log readable");
        assert!(log.contains(FAH_INSTALLER_URL), "records the source URL");
        assert!(log.contains("sha256=deadbeef"), "records the first sha");
        assert!(log.contains("sha256=cafef00d"), "appends, not overwrites");
        assert_eq!(log.lines().count(), 2, "one provenance line per download");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Live integration paths — require a running FAHClient v8 and a configured
    // username. Ignored by default (no fake server in product code).
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "network: downloads the real ~3.5 MB FAH portable tar.bz2 from the official host"]
    async fn live_portable_archive_downloads_and_hashes() {
        let dir = std::env::temp_dir().join(format!("dagoat-fah-liveportable-{}", unix_now()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let dest = dir.join(FAH_PORTABLE_ARCHIVE_FILENAME);
        let provision = Arc::new(Mutex::new(ProvisionSnapshot::default()));
        let sha = download_installer_with_progress(FAH_PORTABLE_URL, &dest, &provision)
            .await
            .expect("portable archive downloads");
        assert_eq!(sha.len(), 64, "sha-256 hex digest");
        assert!(dest.is_file());
        assert!(
            std::fs::metadata(&dest).unwrap().len() > 1_000_000,
            "real portable archive is many MB"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    #[ignore = "requires a running FAHClient v8 local API on 127.0.0.1:7396"]
    async fn live_ws_connect_and_stream() {
        let backend = FahBackend::new();
        backend.connect().await.expect("connect");
        tokio::time::sleep(Duration::from_secs(3)).await;
        let status = backend.status().await;
        println!("live FAH status: {status:?}");
        backend.disconnect().await.expect("disconnect");
        assert!(status.state != "not_installed");
    }

    #[tokio::test]
    #[ignore = "requires FAH_TEST_USER env var and network access to the stats API"]
    async fn live_stats_poll() {
        let user = std::env::var("FAH_TEST_USER").expect("set FAH_TEST_USER");
        let fetched = fetch_stats(&user, None).await.expect("stats fetch");
        println!("live stats HTTP {}: {}", fetched.status, fetched.body);
        assert_eq!(fetched.status, 200);
    }

    #[test]
    fn iso8601_from_secs_epoch_zero() {
        assert_eq!(iso8601_from_secs(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_from_secs_known_instant() {
        // 2024-01-27T00:14:47Z, matches FAH v8's reference `time` shape.
        assert_eq!(iso8601_from_secs(1_706_314_487), "2024-01-27T00:14:47Z");
    }

    // -----------------------------------------------------------------------
    // Stop = kill fah-client.exe (A-D T5)
    // -----------------------------------------------------------------------

    #[test]
    fn taskkill_invocations_targets_both_process_names() {
        let invocations = taskkill_invocations();
        assert_eq!(
            invocations,
            vec![
                vec![
                    "/F".to_string(),
                    "/IM".to_string(),
                    "fah-client.exe".to_string()
                ],
                vec![
                    "/F".to_string(),
                    "/IM".to_string(),
                    "FAHClient.exe".to_string()
                ],
            ]
        );
    }

    #[test]
    fn taskkill_outcome_codes() {
        assert_eq!(taskkill_outcome(Some(0)), Ok(true)); // killed
        assert_eq!(taskkill_outcome(Some(128)), Ok(false)); // not running — idempotent success
        assert!(taskkill_outcome(Some(1)).is_err()); // e.g. access denied
        assert!(taskkill_outcome(None).is_err()); // signal-terminated / no exit code
    }
}

//! goat-attestor CLI: propose / confirm / challenge / serve-relayer / run.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, warn};

use goat_attestor::chain::{epoch_open_for_propose, ChainClient, MockChain};
use goat_attestor::challenger::Challenger;
use goat_attestor::config::{self, Config};
use goat_attestor::fah::{default_fixtures_dir, FahClient, FixtureHttp, HttpGet};
use goat_attestor::http_live::{AnyHttp, LiveHttp};
use goat_attestor::proposer::{
    chain_or_wall_now, current_daily_epoch_id, seconds_past_next_midnight, EpochBatch, Proposer,
};
use goat_attestor::registry::{WorkerEntry, WorkerRegistry};
use goat_attestor::relayer;
use goat_attestor::rpc_chain::RpcChain;
use goat_attestor::settlement::settle_and_claim_batch;
use goat_attestor::stream_g;
use goat_attestor::stream_g::crypto_store::SecretHex;
use goat_attestor::stream_g::maintenance::{self, MaintenancePolicy};
use goat_attestor::stream_g::quarantine_report;
use goat_attestor::stream_g::runtime::{ServeMode, ShutdownController, StreamGState};

#[derive(Parser, Debug)]
#[command(name = "goat-attestor", about = "GOAT FAH attribution attestor daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Propose one full epoch batch (all bound workers).
    OncePropose {
        #[arg(long)]
        epoch: Option<u64>,
        #[arg(long)]
        fixtures: Option<PathBuf>,
    },
    /// Confirm an epoch (watcher heartbeat) if Proposed.
    OnceConfirm {
        #[arg(long)]
        epoch: u64,
    },
    /// Challenge an epoch if proposed scores exceed public FAH (requires --proposed-json).
    OnceChallenge {
        #[arg(long)]
        epoch: u64,
        /// JSON array of {wallet, score} for the proposal under review.
        #[arg(long)]
        proposed_json: PathBuf,
        #[arg(long)]
        fixtures: Option<PathBuf>,
    },
    /// Serve the gas-sponsorship relayer HTTP API.
    ServeRelayer {
        #[arg(long)]
        bind: Option<String>,
    },
    /// Load config and run one propose + enrollment + confirm cycle (mock or live).
    Run {
        #[arg(long)]
        fixtures: Option<PathBuf>,
    },
    /// Pull all WorkerBinding.Bound events into registry.json (no propose).
    SyncRegistry,
    /// One full automated cycle: sync registry → propose → warp/confirm/finalize → claim.
    /// Same as `run` with AUTO_SETTLE (default on chain 31337).
    AutoEarn {
        #[arg(long)]
        fixtures: Option<PathBuf>,
    },
    /// Loop AutoEarn every POLL_INTERVAL_S (fold → GOAT automation daemon).
    Daemon {
        #[arg(long)]
        fixtures: Option<PathBuf>,
        /// Override poll seconds (default: POLL_INTERVAL_S env).
        #[arg(long)]
        interval: Option<u64>,
    },
    /// Print a fee-schedule file's canonical payload bytes and its
    /// feeScheduleHash, ready to publish as STREAM_G_FEE_SCHEDULE_HASH.
    FeeScheduleHash {
        /// The fee-schedule file to hash, e.g.
        /// fixtures/stream_g_fee_schedule.json.
        #[arg(long)]
        schedule_json: PathBuf,
    },
    /// Print a deployment-payload file's canonical payload bytes and its
    /// deploymentManifestHash, ready to publish as
    /// STREAM_G_DEPLOYMENT_MANIFEST_HASH.
    DeploymentManifestHash {
        /// The deployment-payload file to hash, e.g.
        /// fixtures/stream_g_deployment_payload.json or, straight out of a
        /// deploy, contracts/deployments/31337.stream-g.payload.json.
        #[arg(long)]
        payload_json: PathBuf,
    },
    /// List the `SponsoredEnrollmentExecuted` logs Stream G's reconciler
    /// QUARANTINED — the ones it could not fold and stepped over for good.
    ///
    /// The scenario this exists for: `reconcile_log_errors` on
    /// `GET /v1/stream-g/metrics` has ticked. That counter says *a* log was
    /// dropped; it cannot say which one. The scan cursor has already advanced
    /// past that log and nothing ever reads behind the cursor, so the row this
    /// command prints is the only surviving record that it happened — the
    /// difference between a recorded incident and a lost one. Before this
    /// command existed the operator's only option was to open the SQLite file
    /// by hand.
    ///
    /// Opens READ-ONLY: no instance lock (so it works while the attestor is
    /// running, which is when it is needed), no migration, and it will never
    /// create a database — a wrong --db is a loud error, never "0 rows".
    /// Exit codes: 0 read cleanly, 1 could not read, 2 rows listed but some
    /// could not be decrypted, 3 rows listed with no data key, 4 the database
    /// was written by a NEWER build so the listing may be incomplete — never
    /// 0, because "I may not be able to see everything" must not read as a
    /// clean run to `--format json | jq '.status'`.
    StreamGQuarantine {
        /// The Stream G SQLite database. No default on purpose: during an
        /// incident this is often a copy at an ad-hoc path, and a silent
        /// default is a second way to answer "0 rows" about a file nobody
        /// asked about.
        #[arg(long, env = "STREAM_G_DB_PATH")]
        db: PathBuf,
        /// At-rest data key, 64 hex chars. Prefer the environment variable:
        /// a key passed on the command line lands in shell history and in
        /// `ps` output. Omitting it is supported — every row is still listed,
        /// with its body left sealed and the run exiting 3.
        #[arg(long, env = "STREAM_G_DATA_KEY_HEX")]
        data_key_hex: Option<String>,
        /// `text` for a human, `json` for a script.
        #[arg(long, value_enum, default_value_t = QuarantineFormat::Text)]
        format: QuarantineFormat,
        /// Maximum rows to render. Truncation is always stated against a
        /// separate COUNT(*), never implied.
        #[arg(long, default_value_t = quarantine_report::DEFAULT_LIMIT)]
        limit: u32,
        /// Only rows with `created_at >= this`, in UNIX seconds. Every row
        /// prints its raw `created_at`, so the value to paste here comes off
        /// the previous run's output.
        #[arg(long)]
        since: Option<i64>,
        /// Only rows whose `status` equals this error code, e.g.
        /// RECONCILE_UNVERIFIED_LOG. Note `status` is the cleartext column and
        /// is not authenticated; the reported total is always unfiltered.
        #[arg(long)]
        error_code: Option<String>,
        /// Render exactly one row, by its `reconciliation_events.id`.
        #[arg(long)]
        id: Option<String>,
    },
}

/// Output shape for `stream-g-quarantine`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum QuarantineFormat {
    Text,
    Json,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // `fee-schedule-hash` is dispatched BEFORE the config load, and that is not
    // a shortcut. Every other subcommand talks to a chain, a registry or an
    // HTTP surface and is therefore meaningless without `Config`; this one is a
    // pure file → canonical bytes → keccak256 computation that opens nothing
    // and reads no environment. A founder computing the value to publish as
    // STREAM_G_FEE_SCHEDULE_HASH is, by definition, standing in front of a
    // deployment that does not exist yet, so requiring CHAIN_ID/RPC_URL to be
    // set first would make the tool unusable at exactly the moment it is
    // needed. (`load_from_env` returns `Err` and `main` bails with "load config
    // from env" unless GOAT_ATTESTOR_MOCK=1 — see the arm just below.)
    if let Commands::FeeScheduleHash { schedule_json } = &cli.cmd {
        return cmd_fee_schedule_hash(schedule_json);
    }

    // `deployment-manifest-hash` is dispatched here for exactly the same
    // reason, and the reason is sharper for this one. The schedule payload is
    // hand-authored and pre-exists its deploy; the DEPLOYMENT payload's content
    // *is* the deploy's output — addresses and runtime code hashes that do not
    // exist until after the contracts are created — while
    // `FeeTokenRegistry.setActiveManifestHash` runs during the deploy. The
    // resolution is two passes, and this command is the middle one: deploy,
    // read the payload document the script wrote, compute its digest here,
    // then republish. Demanding CHAIN_ID/RPC_URL first would make the tool
    // unusable at the exact moment it is the only thing standing between an
    // operator and publishing a hash no file produces.
    if let Commands::DeploymentManifestHash { payload_json } = &cli.cmd {
        return cmd_deployment_manifest_hash(payload_json);
    }

    // `stream-g-quarantine` is dispatched here for the same reason, only more
    // so. It reads one local SQLite table and needs a chain, a registry and an
    // HTTP surface for none of it — but `config::REQUIRED` would make the
    // operator supply RPC_URL, CHAIN_ID and three contract addresses first, and
    // `build_stream_g_config` is fail-closed: setting STREAM_G_ENABLED=1 to get
    // a `db_path` ALSO demands STREAM_G_BROADCASTER_PRIVATE_KEY,
    // STREAM_G_QUOTE_SIGNER_PRIVATE_KEY and STREAM_G_ISSUER_PRIVATE_KEY. That
    // is three signing keys in the environment as the price of READING a
    // diagnostic table, and the operator running this is by definition standing
    // in front of a deployment that has already gone wrong. It takes a --db
    // path and (optionally) a data key, and nothing else.
    if let Commands::StreamGQuarantine {
        db,
        data_key_hex,
        format,
        limit,
        since,
        error_code,
        id,
    } = &cli.cmd
    {
        let query = quarantine_report::QuarantineQuery {
            limit: *limit,
            since: *since,
            error_code: error_code.clone(),
            id: id.clone(),
        };
        // `main` is sync, so this arm builds its own runtime — same shape as
        // `ServeRelayer` below. Current-thread: one SQLite pool, one query at a
        // time, nothing to parallelise.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let code = rt.block_on(cmd_stream_g_quarantine(
            db,
            data_key_hex.as_deref(),
            *format,
            &query,
        ))?;
        // Non-zero for "listed but sealed"/"listed but undecryptable" is the
        // whole point: `--format json | jq` in an incident script must not
        // treat an unreadable quarantine table as a healthy one.
        std::process::exit(code);
    }

    let cfg = match config::load_from_env() {
        Ok(c) => c,
        Err(e) => {
            // Allow --help paths; for actual commands require config.
            warn!("config load failed: {e}; using test defaults only if MOCK");
            if std::env::var("GOAT_ATTESTOR_MOCK").ok().as_deref() == Some("1") {
                config::load_from_map(&Config::test_map())?
            } else {
                return Err(e).context("load config from env");
            }
        }
    };

    match cli.cmd {
        Commands::OncePropose { epoch, fixtures } => {
            cmd_once_propose(&cfg, epoch, fixtures)?;
        }
        Commands::OnceConfirm { epoch } => {
            cmd_once_confirm(&cfg, epoch)?;
        }
        Commands::OnceChallenge {
            epoch,
            proposed_json,
            fixtures,
        } => {
            cmd_once_challenge(&cfg, epoch, &proposed_json, fixtures)?;
        }
        Commands::ServeRelayer { bind } => {
            let bind = bind.unwrap_or_else(|| cfg.relayer_bind.clone());
            // Multi-thread runtime so RpcChain can block_in_place on worker threads
            // when handlers call alloy (sync ChainClient API).
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("goat-attestor-serve")
                .build()?;
            rt.block_on(cmd_serve_relayer(&cfg, &bind))?;
        }
        Commands::Run { fixtures } => {
            cmd_run(&cfg, fixtures)?;
        }
        Commands::SyncRegistry => {
            cmd_sync_registry(&cfg)?;
        }
        Commands::AutoEarn { fixtures } => {
            cmd_auto_earn(&cfg, fixtures)?;
        }
        Commands::Daemon { fixtures, interval } => {
            cmd_daemon(&cfg, fixtures, interval)?;
        }
        // Handled before the config load above; `main` returned there.
        Commands::FeeScheduleHash { .. } => unreachable!("dispatched before config load"),
        Commands::DeploymentManifestHash { .. } => {
            unreachable!("dispatched before config load")
        }
        Commands::StreamGQuarantine { .. } => unreachable!("dispatched before config load"),
    }
    Ok(())
}

/// Load registry, merge all on-chain Bound wallets, save. Returns (added, total).
fn sync_registry_from_chain(chain: &dyn ChainClient, cfg: &Config) -> Result<(usize, usize)> {
    let mut reg = WorkerRegistry::load(&cfg.registry_json).unwrap_or_default();
    let bound = chain
        .list_bound_workers()
        .context("list_bound_workers (WorkerBinding.Bound logs)")?;
    let pairs: Vec<(String, String)> = bound.into_iter().map(|b| (b.wallet, b.username)).collect();
    // Authoritative replace: drops wallets from previous anvil redeploys.
    let (added, removed) = reg.replace_from_bound_workers(pairs);
    reg.save(&cfg.registry_json)
        .with_context(|| format!("save registry {:?}", cfg.registry_json))?;
    let total = reg.all_bound().len();
    info!(
        "registry sync: +{added} -{removed} total={total} at {:?}",
        cfg.registry_json
    );
    Ok((added, total))
}

fn cmd_sync_registry(cfg: &Config) -> Result<()> {
    let chain = open_chain(cfg)?;
    sync_registry_from_chain(chain.as_ref(), cfg)?;
    Ok(())
}

/// Mock → in-memory chain; live → alloy HTTP `RpcChain`.
fn open_chain(cfg: &Config) -> Result<Arc<dyn ChainClient>> {
    if cfg.mock_mode {
        Ok(Arc::new(MockChain::new().with_bonds(
            cfg.proposer_bond_wei,
            cfg.challenger_bond_wei,
        )))
    } else {
        Ok(Arc::new(RpcChain::from_config(cfg)?))
    }
}

/// `--fixtures PATH` → fixture dir; mock without flag → default fixtures; else live FAH.
fn make_fah(cfg: &Config, fixtures: Option<PathBuf>) -> Result<FahClient<AnyHttp>> {
    let http = if let Some(dir) = fixtures {
        AnyHttp::Fixture(FixtureHttp::new(dir))
    } else if cfg.mock_mode {
        AnyHttp::Fixture(FixtureHttp::new(default_fixtures_dir()))
    } else {
        AnyHttp::Live(LiveHttp::new()?)
    };
    Ok(FahClient::new(
        http,
        cfg.fah_stats_base.clone(),
        Duration::from_millis(cfg.min_fah_interval_ms),
    ))
}

fn cmd_once_propose(cfg: &Config, epoch: Option<u64>, fixtures: Option<PathBuf>) -> Result<()> {
    let chain = open_chain(cfg)?;
    let fah = make_fah(cfg, fixtures)?;
    // Auto-discover every on-chain bind before proposing.
    let _ = sync_registry_from_chain(chain.as_ref(), cfg);
    let reg = WorkerRegistry::load(&cfg.registry_json).unwrap_or_default();
    if reg.all_bound().is_empty() {
        info!(
            "registry empty at {:?}; nothing to propose",
            cfg.registry_json
        );
        return Ok(());
    }
    std::fs::create_dir_all(&cfg.evidence_dir).ok();
    std::fs::create_dir_all(&cfg.state_dir).ok();
    let p = Proposer {
        chain: chain.as_ref(),
        fah: &fah,
        bond_wei: cfg.proposer_bond_wei,
        evidence_dir: cfg.evidence_dir.clone(),
        state_dir: cfg.state_dir.clone(),
    };
    let batch = p.propose_full(&reg, epoch)?;
    info!(
        "proposed epoch {} root={} leaves={}",
        batch.epoch_id,
        batch.merkle_root_hex,
        batch.leaves.len()
    );
    Ok(())
}

fn cmd_once_confirm(cfg: &Config, epoch: u64) -> Result<()> {
    let chain = open_chain(cfg)?;
    match chain.confirm_epoch(epoch) {
        Ok(tx) => info!("confirmed epoch {epoch} tx=0x{}", hex::encode(tx)),
        Err(e) => {
            warn!("confirm_epoch({epoch}): {e}");
            if cfg.mock_mode {
                info!(
                    "note: MockChain is process-local; use `run` for propose+confirm in one process"
                );
            }
        }
    }
    Ok(())
}

fn cmd_once_challenge(
    cfg: &Config,
    epoch: u64,
    proposed_json: &std::path::Path,
    fixtures: Option<PathBuf>,
) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct Row {
        wallet: String,
        score: u128,
    }
    let raw = std::fs::read_to_string(proposed_json)?;
    let rows: Vec<Row> = serde_json::from_str(&raw)?;
    let proposed: Vec<(String, u128)> = rows.into_iter().map(|r| (r.wallet, r.score)).collect();

    let chain = open_chain(cfg)?;
    if cfg.mock_mode {
        // Seed a proposed batch so challenge can land in process-local MockChain.
        chain.propose_batch(epoch, [1u8; 32], [2u8; 32], cfg.proposer_bond_wei)?;
    }
    let fah = make_fah(cfg, fixtures)?;
    let reg = WorkerRegistry::load(&cfg.registry_json).unwrap_or_default();
    std::fs::create_dir_all(&cfg.evidence_dir).ok();
    let c = Challenger {
        chain: chain.as_ref(),
        fah: &fah,
        bond_wei: cfg.challenger_bond_wei,
        evidence_dir: cfg.evidence_dir.clone(),
    };
    let d = c.review_epoch(epoch, &reg, &proposed)?;
    info!("challenge decision: {d:?}");
    Ok(())
}

/// Resolve the gas-drip endpoint's `(gas_drips_json, goat_coin)` wiring from
/// config. Gas-drip stays off (`None`) unless BOTH the daily cap is non-zero
/// (`cfg.gas_drip_enabled`, from `GAS_DRIP_DAILY_CAP`) AND a GoatCoin address
/// is configured — an endpoint that can never resolve an eligibility balance
/// is worse than one that cleanly 503s `GasDripDisabled`.
fn resolve_gas_drip_wiring(cfg: &Config) -> (Option<PathBuf>, String) {
    if !cfg.gas_drip_enabled {
        return (None, String::new());
    }
    match cfg.goat_coin_address.clone() {
        Some(addr) if !addr.is_empty() => (Some(cfg.state_dir.join("gas_drips.json")), addr),
        _ => {
            warn!(
                "GOAT_COIN_ADDRESS not set; gas-drip endpoint stays disabled (503 GasDripDisabled) despite GAS_DRIP_DAILY_CAP>0"
            );
            (None, String::new())
        }
    }
}

async fn cmd_serve_relayer(cfg: &Config, bind: &str) -> Result<()> {
    let chain = open_chain(cfg)?;
    std::fs::create_dir_all(&cfg.state_dir).ok();
    let (gas_drips_json, goat_coin) = resolve_gas_drip_wiring(cfg);
    let gas_drip_status = if gas_drips_json.is_some() {
        "enabled"
    } else {
        "disabled"
    };

    let worker_binding =
        goat_attestor::chain::parse_address20(&cfg.worker_binding_address).unwrap_or([0u8; 20]);
    let enrollment_registry =
        goat_attestor::chain::parse_address20(&cfg.enrollment_registry_address)
            .unwrap_or([0u8; 20]);

    let spend_ceiling_wei = std::env::var("RELAY_DAILY_CEILING_WEI")
        .ok()
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(goat_attestor::spend_ledger::DEFAULT_DAILY_CEILING_WEI);
    let drip_budget_wei = std::env::var("GAS_DRIP_DAILY_BUDGET_WEI")
        .ok()
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(goat_attestor::spend_ledger::DEFAULT_DRIP_BUDGET_WEI);
    let spend_ledger_path = Some(cfg.state_dir.join("spend_ledger.json"));

    // Relayer writes new binds into the same registry.json the proposer reads.
    let mut app = relayer::router_with_relayer_config(
        chain,
        relayer::RelayerConfig {
            registry_json: Some(cfg.registry_json.clone()),
            gas_drips_json,
            goat_coin,
            drip_cfg: cfg.gas_drip_cfg.clone(),
            eip712: relayer::Eip712Config {
                chain_id: cfg.chain_id,
                worker_binding,
                enrollment_registry,
            },
            spend_ledger_path,
            spend_ceiling_wei,
            drip_budget_wei,
        },
    );
    // Stream G (TARGET/post-pilot): mount only when explicitly enabled. Config
    // load already fail-closed-validated the Stream G *env* when enabled (see
    // config::build_stream_g_config); `StreamGState::start` is the runtime half
    // of that gate — the OS instance lock, the WAL/FK/FULL/bounded-busy-timeout
    // pragmas, migrations 1→2, the at-rest data key and the deployment manifest
    // all have to be good before a single route is mounted. Never falls back
    // onto pilot relayer routes.
    let stream_g_shutdown = match ServeMode::for_config(cfg) {
        ServeMode::PilotPlain => None,
        ServeMode::StreamGGraceful => {
            info!(
                "Stream G enabled — taking the Stream G instance lock and mounting /v1/stream-g/*"
            );
            let controller = ShutdownController::new();
            let state = StreamGState::start(cfg, controller.token())
                .await
                .context("Stream G startup (instance lock / store / data key / manifest)")?;
            // Task 8 Wave D: the background maintenance loop — the production
            // caller `outbox::sweep_stuck_reservations` and
            // `profile_auth::prune_expired` did not have. It shares the
            // shutdown token above, so one Ctrl-C/SIGTERM stops the server and
            // the loop together, and it is JOINED below (it holds a
            // `StreamGState` clone, and therefore the SQLite pool and the fs2
            // instance lock). Spawned only on this arm, i.e. only when
            // STREAM_G_ENABLED=1.
            let policy = MaintenancePolicy::from_config(&cfg.stream_g, state.manifest());
            info!(
                interval_s = policy.interval.as_secs(),
                lease_ttl_s = policy.lease_ttl_seconds,
                max_rows = policy.max_rows,
                "Stream G maintenance loop: sweeper (chain-time release authority) + auth prune"
            );
            let maintenance = maintenance::spawn(state.clone(), policy);
            app = app.merge(stream_g::router(state));
            Some((controller, maintenance))
        }
    };
    // H6: refuse 0.0.0.0 / LAN binds — origin stays loopback-only (tunnel in front).
    relayer::require_loopback_bind(bind).map_err(|e| anyhow::anyhow!("{e}"))?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind} (is another relayer already running?)"))?;
    info!(
        "relayer listening on http://{bind} (mock={}, auto-register → {:?}, gas-drip={gas_drip_status}, H2 ceiling={spend_ceiling_wei} wei)",
        cfg.mock_mode, cfg.registry_json
    );
    // PILOT SAFETY: `axum::serve` is shared pilot code, and
    // `.with_graceful_shutdown(..)` changes how the server terminates. The
    // `None` arm below is the identical expression this function ran before
    // Task 8, and no signal handler is installed anywhere in the process on
    // that path — with `STREAM_G_ENABLED=0` the Stream B pilot's shutdown
    // behaviour is unchanged. `runtime::ServeMode`'s unit test is what keeps
    // that true.
    match stream_g_shutdown {
        None => axum::serve(listener, app).await.context("axum serve")?,
        Some((controller, maintenance)) => {
            let token = controller.token();
            let signal_controller = controller.clone();
            // The only producer of cancellation: Ctrl-C (plus SIGTERM on unix)
            // → latch → axum stops accepting and drains in-flight requests →
            // the maintenance loop stops at its next sleep boundary →
            // `StreamGState` drops → the SQLite pool closes and the fs2
            // instance lock is released deliberately, rather than being
            // reclaimed by the OS after an abrupt kill. The maintenance loop
            // observes the same latch through its own token.
            tokio::spawn(async move {
                stream_g::runtime::terminate_signal().await;
                info!("shutdown signal received — draining HTTP server (Stream G enabled)");
                signal_controller.cancel();
            });
            let served = axum::serve(listener, app)
                .with_graceful_shutdown(async move { token.cancelled().await })
                .await;
            // However the server ended — graceful drain or bind/accept error —
            // the loop must stop and be joined before this function returns.
            // `cancel` is idempotent, so re-latching after a normal shutdown is
            // a no-op; it matters on the error path, where nothing else would
            // have cancelled it. Joining (rather than dropping the handle)
            // guarantees no pass is in flight while the store is closing.
            controller.cancel();
            match maintenance.await {
                Ok(passes) => info!(passes, "Stream G maintenance loop joined"),
                Err(e) => warn!("Stream G maintenance task did not join cleanly: {e}"),
            }
            served.context("axum serve")?
        }
    }
    Ok(())
}

fn cmd_run(cfg: &Config, fixtures: Option<PathBuf>) -> Result<()> {
    cmd_auto_earn(cfg, fixtures)
}

/// Re-read hasBaseline for every bound worker; return only those with Ok(Some(true)).
/// Logs each exclusion at warn. Does not use registry.baseline_batched as the gate.
fn gate_workers_with_onchain_baseline(
    chain: &dyn ChainClient,
    reg: &WorkerRegistry,
) -> Vec<WorkerEntry> {
    let mut gated = Vec::new();
    for w in reg.all_bound() {
        match chain.has_baseline(&w.wallet) {
            Ok(Some(true)) => gated.push(w.clone()),
            Ok(Some(false)) => {
                if w.baseline_batched {
                    warn!(
                        "exclude from daily batch: wallet={} hasBaseline=false (pending enrollment retry)",
                        w.wallet
                    );
                } else {
                    warn!(
                        "exclude from daily batch: wallet={} hasBaseline=false",
                        w.wallet
                    );
                }
            }
            Ok(None) => {
                if w.baseline_batched {
                    warn!(
                        "exclude from daily batch: wallet={} hasBaseline unknown (None) (pending enrollment retry)",
                        w.wallet
                    );
                } else {
                    warn!(
                        "exclude from daily batch: wallet={} hasBaseline unknown (None)",
                        w.wallet
                    );
                }
            }
            Err(e) => {
                if w.baseline_batched {
                    warn!(
                        "exclude from daily batch: wallet={} hasBaseline error: {e} (pending enrollment retry)",
                        w.wallet
                    );
                } else {
                    warn!(
                        "exclude from daily batch: wallet={} hasBaseline error: {e}",
                        w.wallet
                    );
                }
            }
        }
    }
    gated
}

/// Core auto-earn cycle (enrollment → on-chain baseline gate → daily).
/// Injectable for unit tests (MockChain + FixtureHttp) without env/CLI.
#[allow(clippy::too_many_arguments)] // evidence_dir + state_dir both required by cycle wiring
fn run_auto_earn_cycle<H: HttpGet>(
    chain: &dyn ChainClient,
    fah: &FahClient<H>,
    reg: &mut WorkerRegistry,
    bond_wei: u128,
    evidence_dir: &std::path::Path,
    state_dir: &std::path::Path,
    auto_settle: bool,
    auto_warp: bool,
) -> anyhow::Result<()> {
    info!(
        "auto-earn cycle start (auto_settle={} auto_warp={} workers={})",
        auto_settle,
        auto_warp,
        reg.all_bound().len()
    );

    let p = Proposer {
        chain,
        fah,
        bond_wei,
        evidence_dir: evidence_dir.to_path_buf(),
        state_dir: state_dir.to_path_buf(),
    };

    // Phase E: enrollment snapshots first (sequential; never abort cycle on settle fail).
    match p.propose_enrollment_snapshots(reg) {
        Ok(batches) => {
            for b in &batches {
                info!(
                    "enrollment snapshot epoch {} root={} leaves={}",
                    b.epoch_id,
                    b.merkle_root_hex,
                    b.leaves.len()
                );
                if auto_settle {
                    match settle_and_claim_batch(chain, b, auto_warp) {
                        Ok(r) => info!(
                            "enrollment settle epoch={}: confirmed={} finalized={} claims_ok={} claims_skipped={} fail={}",
                            r.epoch_id,
                            r.confirmed,
                            r.finalized,
                            r.claims_ok,
                            r.claims_skipped,
                            r.claims_fail
                        ),
                        Err(e) => warn!("enrollment settle epoch {}: {e}", b.epoch_id),
                    }
                } else {
                    let _ = p.confirm_if_ready(b.epoch_id);
                }
            }
            // Registry flag updates are in-memory; caller may save after cycle.
            let _ = batches;
        }
        Err(e) => warn!("enrollment snapshots: {e}"),
    }

    // Enrollment retry / legacy self-heal (after Phase E propose+settle, before gate).
    let bound_for_retry: Vec<WorkerEntry> = reg.all_bound().to_vec();
    for w in bound_for_retry {
        if !w.baseline_batched {
            continue;
        }
        if matches!(chain.has_baseline(&w.wallet), Ok(Some(true))) {
            continue;
        }
        match w.enrollment_epoch {
            Some(e) => {
                if !auto_settle {
                    continue;
                }
                let path = state_dir.join(format!("enrollment_{e}.json"));
                match std::fs::read_to_string(&path)
                    .map_err(|err| err.to_string())
                    .and_then(|s| {
                        serde_json::from_str::<EpochBatch>(&s).map_err(|err| err.to_string())
                    }) {
                    Ok(loaded) => {
                        info!("enrollment retry epoch={e} wallet={}", w.wallet);
                        match settle_and_claim_batch(chain, &loaded, auto_warp) {
                            Ok(r) => info!(
                                "enrollment retry settle epoch={}: confirmed={} finalized={} claims_ok={} claims_skipped={} fail={}",
                                r.epoch_id,
                                r.confirmed,
                                r.finalized,
                                r.claims_ok,
                                r.claims_skipped,
                                r.claims_fail
                            ),
                            Err(err) => warn!(
                                "enrollment retry settle epoch={e} wallet={}: {err}",
                                w.wallet
                            ),
                        }
                    }
                    Err(err) => {
                        warn!(
                            "enrollment retry load failed epoch={e} wallet={} path={:?}: {err}",
                            w.wallet, path
                        );
                    }
                }
            }
            None => {
                // Legacy: clear so next cycle re-proposes enrollment.
                reg.clear_baseline_batched(&w.wallet);
                info!(
                    "legacy enrollment reset: wallet={} (no enrollment_epoch; will re-propose next cycle)",
                    w.wallet
                );
            }
        }
    }

    // AFTER every enrollment batch has been attempted, re-read hasBaseline on-chain.
    let gated = gate_workers_with_onchain_baseline(chain, reg);
    if gated.is_empty() {
        if reg.all_bound().is_empty() {
            info!("no bound workers; idle");
        } else {
            info!("no workers with on-chain baseline; skip daily batch");
        }
        info!("auto-earn cycle complete");
        return Ok(());
    }

    // Option (a): filtered registry clone so propose_full signature stays unchanged.
    let filtered_reg = WorkerRegistry { workers: gated };

    // T31 Fix 2: check batches(epoch) status BEFORE proposing. A daily epoch id
    // is stable for 24h, so — unlike enrollment epochs — a consumed epoch (e.g.
    // already Finalized) would otherwise be blind-fired every cycle forever
    // (proposeBatch → WrongStatus revert), and with auto_warp never advance
    // because nothing ever warped past the consumed day.
    let target_epoch = current_daily_epoch_id(chain);
    let target_status = chain
        .get_batch(target_epoch)
        .map(|v| v.status)
        .unwrap_or_default();
    if !epoch_open_for_propose(target_status) {
        info!("epoch {target_epoch} already {target_status:?}; waiting for next day");
        if auto_warp {
            let now = chain_or_wall_now(chain);
            let wait = seconds_past_next_midnight(now);
            info!(
                "auto-warp +{wait}s past midnight so the next cycle proposes a fresh epoch (from {target_epoch})"
            );
            if let Err(e) = chain.increase_time(wait) {
                warn!("warp past midnight failed: {e}");
            }
        }
    } else {
        match p.propose_full(&filtered_reg, None) {
            Ok(batch) => {
                info!(
                    "full batch epoch {} root={} leaves={}",
                    batch.epoch_id,
                    batch.merkle_root_hex,
                    batch.leaves.len()
                );
                if auto_settle {
                    match settle_and_claim_batch(chain, &batch, auto_warp) {
                        Ok(r) => info!(
                            "daily settle epoch={}: confirmed={} finalized={} claims_ok={} claims_skipped={} fail={} notes={:?}",
                            r.epoch_id,
                            r.confirmed,
                            r.finalized,
                            r.claims_ok,
                            r.claims_skipped,
                            r.claims_fail,
                            r.notes
                        ),
                        Err(e) => warn!("daily settle epoch {}: {e}", batch.epoch_id),
                    }
                } else {
                    let _ = p.confirm_if_ready(batch.epoch_id);
                }
            }
            Err(e) => warn!("propose_full: {e}"),
        }
    }

    info!("auto-earn cycle complete");
    Ok(())
}

/// Automated fold→GOAT cycle for all bound workers:
/// sync registry → enrollment snapshot → daily propose → (warp) confirm → finalize → claim.
fn cmd_auto_earn(cfg: &Config, fixtures: Option<PathBuf>) -> Result<()> {
    let chain = open_chain(cfg)?;
    let fah = make_fah(cfg, fixtures)?;
    let _ = sync_registry_from_chain(chain.as_ref(), cfg);
    let mut reg = WorkerRegistry::load(&cfg.registry_json).unwrap_or_default();
    std::fs::create_dir_all(&cfg.evidence_dir).ok();
    std::fs::create_dir_all(&cfg.state_dir).ok();

    run_auto_earn_cycle(
        chain.as_ref(),
        &fah,
        &mut reg,
        cfg.proposer_bond_wei,
        &cfg.evidence_dir,
        &cfg.state_dir,
        cfg.auto_settle,
        cfg.auto_warp,
    )?;

    // Persist enrollment baseline_batched flags after a successful cycle attempt.
    reg.save(&cfg.registry_json).ok();

    info!("auto-earn cycle complete (mock={})", cfg.mock_mode);
    Ok(())
}

fn cmd_daemon(cfg: &Config, fixtures: Option<PathBuf>, interval: Option<u64>) -> Result<()> {
    let secs = interval.unwrap_or(cfg.poll_interval_s).max(30);
    info!(
        "daemon started: auto-earn every {secs}s (AUTO_SETTLE={} AUTO_WARP={})",
        cfg.auto_settle, cfg.auto_warp
    );
    loop {
        if let Err(e) = cmd_auto_earn(cfg, fixtures.clone()) {
            warn!("auto-earn cycle error: {e}");
        }
        info!("daemon sleep {secs}s…");
        std::thread::sleep(Duration::from_secs(secs));
    }
}

/// The **ops leg** of the three-way fixture required by the "Stream G — USDT Gas
/// Abstraction and Multi-Wallet Sponsoring" spec, §8.1 "Quote construction":
///
/// > "feeScheduleHash = keccak256(UTF8(RFC8785(schedulePayload))). Rust/JavaScript/ops
/// > fixtures pin the canonical bytes and hash before Policy Safe approval."
///
/// The Rust leg is `stream_g::quotes`'
/// `shipped_placeholder_fee_schedule_is_published_and_serves_no_price`; the
/// JavaScript leg is `contracts/test/StreamGManifest.test.mjs`. Until this
/// subcommand existed there was no ops leg at all: an operator's only practical
/// route to the value was to transcribe it out of a
/// `StreamGStartupError::FeeScheduleHashSelfMismatch` message — i.e. to
/// deliberately publish a wrong hash, start the daemon, and read the right one
/// off the refusal. That works and is not a tool.
///
/// # What it prints, and why in this order
///
/// The canonical BYTES come first because they are the artifact the other two
/// legs reproduce; a digest alone cannot be checked against anything by hand.
/// The digest then comes twice: once labelled, and once as a ready-to-paste
/// `STREAM_G_FEE_SCHEDULE_HASH=0x…` line, because that value is consumed by
/// `contracts/script/DeployStreamG.s.sol` through `vm.envBytes32` (no default),
/// which wants exactly `0x` + 64 lowercase hex and nothing else.
///
/// # Why the file is fully loaded and not merely canonicalised
///
/// It goes through `FeeSchedule::from_json`, the same loader
/// `runtime::StreamGState::start` uses, so the printed digest is one that would
/// actually START. Canonicalising alone would happily print a digest for a file
/// carrying a non-canonical decimal (`"07"`), an uppercase `feeToken`, or a
/// misspelled actionType key — all of which the loader refuses — and the
/// operator would discover that only after a Policy Safe transaction had
/// published it. The cost is that the file must already carry a syntactically
/// valid `feeScheduleHash`; a file being authored from scratch can hold any
/// 32-byte placeholder there, which this command's own "declared" line will
/// then report as disagreeing.
///
/// A declared/computed disagreement is **advisory, not an error**: it is the
/// expected state whenever someone has just edited the payload, which is the
/// case this tool exists to serve. Exit status stays 0 so the value can be
/// piped.
///
/// The canonicalisation itself is [`stream_g::quotes::canonical_schedule_payload_bytes`],
/// which is `crate::canonical_bytes` — the single canonicaliser in this crate.
/// There is deliberately no second implementation here, and
/// `quotes::tests::canonical_schedule_payload_bytes_are_the_bytes_the_loader_hashes`
/// pins that the bytes printed here are the bytes the loader hashed.
///
/// Output goes to **stdout via `println!`, not through `tracing`**, unlike every
/// other `cmd_*` in this file: the `tracing_subscriber` formatter prefixes each
/// line with a timestamp and level, which would have to be edited back out of a
/// value whose entire purpose is to be copied verbatim.
fn cmd_fee_schedule_hash(schedule_json: &std::path::Path) -> Result<()> {
    let source = schedule_json.display().to_string();
    let raw = std::fs::read_to_string(schedule_json)
        .with_context(|| format!("read fee schedule {source}"))?;

    let schedule = stream_g::quotes::FeeSchedule::from_json(&raw, &source)
        .context("the file must load with the same loader the daemon starts with")?;
    let bytes = stream_g::quotes::canonical_schedule_payload_bytes(&raw, &source)?;
    let canonical = String::from_utf8(bytes)
        .context("canonical JSON is UTF-8 by construction; this should be unreachable")?;

    let computed = format!("0x{}", hex::encode(schedule.computed_fee_schedule_hash()));
    let declared = format!("0x{}", hex::encode(schedule.declared_fee_schedule_hash()));

    println!("file:                  {source}");
    println!("canonical bytes:       {} (UTF-8)", canonical.len());
    println!("{canonical}");
    println!("feeScheduleHash (computed from payload): {computed}");
    println!("feeScheduleHash (declared by the file):  {declared}");
    if computed == declared {
        println!("                                         ^ agree");
    } else {
        println!(
            "                                         ^ DISAGREE: the payload was edited \
             without republishing the hash. Write the computed value into this file's \
             `feeScheduleHash`, and publish the same value on-chain, or \
             StreamGState::start will refuse with FeeScheduleHashSelfMismatch."
        );
    }
    println!();
    println!("STREAM_G_FEE_SCHEDULE_HASH={computed}");
    Ok(())
}

/// The **ops leg** for `deploymentManifestHash`, matching `fee-schedule-hash`
/// line for line — the spec makes the same three-way demand at `:248`:
///
/// > "Desktop, relayer, deployment tooling, and Foundry fixtures must produce
/// > the same bytes/hash and require equality with the on-chain approved hash."
///
/// The Rust leg is
/// `stream_g::deployment_payload::tests::shipped_deployment_payload_is_published_and_binds_the_manifest`;
/// the JavaScript leg is `contracts/test/StreamGManifest.test.mjs`.
///
/// # Why this one is load-bearing rather than a convenience
///
/// `deploymentManifestHash` used to be `keccak256("stream-g-manifest-g1")`, a
/// label over no content. There was no value to compute, so there was nothing
/// for a tool to do. Now the value is a digest of a document the deploy script
/// writes, and the deploy script needs that digest as an INPUT
/// (`vm.envBytes32("STREAM_G_DEPLOYMENT_MANIFEST_HASH")`, required, no
/// default). Without this command the two-pass flow has no middle step and the
/// operator's only route to the value is to publish a wrong one, start the
/// daemon, and transcribe the right one out of a
/// `DeploymentManifestHashSelfMismatch` refusal. That works and is not a tool.
///
/// # What it prints, and why in this order
///
/// Canonical BYTES first: they are the artifact the other two legs reproduce,
/// and a digest alone cannot be checked against anything by hand. Every VALUE
/// in them is verbatim from the file — JCS reorders members and strips
/// whitespace and does nothing else — so an operator can diff the printed bytes
/// against the document and find every difference explained by ordering.
///
/// That is true only since the payload's hex fields became lowercase-or-refused
/// (`deployment_payload::require_lowercase_hex`, spec `:244`). Before that, the
/// reader lowercased before hashing, so the printed bytes were a PROJECTION of
/// the file and differed from it for every address — the exact confusion the
/// spec's lowercase rule exists to prevent.
///
/// Then the digest twice: once labelled, once as a ready-to-paste
/// `STREAM_G_DEPLOYMENT_MANIFEST_HASH=0x…` line, because `DeployStreamG.run()`
/// and `PublishStreamG.run()` both consume it through `vm.envBytes32`, which
/// wants exactly `0x` + 64 lowercase hex and nothing else.
///
/// # Why the file is fully loaded and not merely canonicalised
///
/// It goes through `DeploymentPayload::from_json`, the same loader
/// `runtime::StreamGState::start` uses, so the printed digest is one that would
/// actually START. Canonicalising alone would happily print a digest for a file
/// with a misspelled role key, a non-canonical decimal, a `releaseCommit` that
/// is not a sha, or a `runtimeCodeHash` describing an account with no code —
/// all of which the loader refuses — and the operator would discover that only
/// after a Policy Safe transaction had published it.
///
/// A declared/computed disagreement is **advisory, not an error**: it is the
/// expected state on the first pass of every deploy, which is the case this
/// tool exists to serve. Exit status stays 0 so the value can be piped.
///
/// Output goes to stdout via `println!` rather than `tracing`, for the same
/// reason as `cmd_fee_schedule_hash`: a timestamped, level-prefixed line would
/// have to be edited back out of a value whose entire purpose is to be copied
/// verbatim.
fn cmd_deployment_manifest_hash(payload_json: &std::path::Path) -> Result<()> {
    let source = payload_json.display().to_string();
    let raw = std::fs::read_to_string(payload_json)
        .with_context(|| format!("read deployment payload {source}"))?;

    let payload = stream_g::deployment_payload::DeploymentPayload::from_json(&raw, &source)
        .context("the file must load with the same loader the daemon starts with")?;
    let bytes = stream_g::deployment_payload::canonical_deployment_payload_bytes(&raw, &source)?;
    let canonical = String::from_utf8(bytes)
        .context("canonical JSON is UTF-8 by construction; this should be unreachable")?;

    let computed = format!(
        "0x{}",
        hex::encode(payload.computed_deployment_manifest_hash())
    );
    let declared = format!(
        "0x{}",
        hex::encode(payload.declared_deployment_manifest_hash())
    );

    println!("file:                  {source}");
    println!(
        "canonical bytes:       {} (UTF-8; values verbatim, members reordered by RFC 8785)",
        canonical.len()
    );
    println!("{canonical}");
    println!("deploymentManifestHash (computed from payload): {computed}");
    println!("deploymentManifestHash (declared by the file):  {declared}");
    if computed == declared {
        println!("                                               ^ agree");
    } else {
        println!(
            "                                               ^ DISAGREE: the payload was \
             written or edited without republishing the hash. This is the EXPECTED state on \
             the first pass of a deploy. Write the computed value into this file's \
             `deploymentManifestHash`, and publish the same value on-chain (a Policy Safe \
             FeeTokenRegistry.setActiveManifestHash transaction against a live deployment), or \
             StreamGState::start will refuse with DeploymentManifestHashSelfMismatch."
        );
    }
    println!();
    println!("STREAM_G_DEPLOYMENT_MANIFEST_HASH={computed}");
    Ok(())
}

/// Read the quarantine table and print it. Returns the **process exit code**
/// rather than calling `exit` itself, so the mapping from report state to code
/// stays in one visible place.
///
/// `Err` here is exit 1 — could not read at all. It is deliberately distinct
/// from the codes a *successful* read can produce (2 = some rows could not be
/// decrypted, 3 = rows listed with no key, 4 = the file was written by a newer
/// build so the listing may be incomplete), because "I could not open the file"
/// and "I opened it and there is nothing to report" must never be confusable.
async fn cmd_stream_g_quarantine(
    db: &std::path::Path,
    data_key_hex: Option<&str>,
    format: QuarantineFormat,
    query: &quarantine_report::QuarantineQuery,
) -> Result<i32> {
    // Parsed into `SecretHex` (zeroize-on-drop, redacted `Debug`) before it
    // travels anywhere, and a malformed key is refused here rather than
    // surfacing later as an unseal failure — which would be indistinguishable
    // from the *wrong* key, the one thing this report must keep separable.
    let key = match data_key_hex {
        Some(hex) => Some(
            SecretHex::from_hex(hex)
                .context("STREAM_G_DATA_KEY_HEX / --data-key-hex must be 64 hex characters")?,
        ),
        None => None,
    };

    let report = quarantine_report::load_report(db, key.as_ref(), query).await?;

    match format {
        QuarantineFormat::Text => print!("{}", quarantine_report::render_text(&report)),
        QuarantineFormat::Json => println!(
            "{}",
            quarantine_report::render_json(&report).context("render quarantine report as JSON")?
        ),
    }
    use std::io::Write as _;
    std::io::stdout().flush().ok();

    Ok(report.exit_code)
}

#[cfg(test)]
mod gas_drip_wiring_tests {
    use super::resolve_gas_drip_wiring;
    use goat_attestor::config::{self, Config};

    /// Default env (no GOAT_COIN_ADDRESS): GAS_DRIP_DAILY_CAP defaults on
    /// (non-zero), but with no token address the endpoint must stay off — an
    /// endpoint that can never resolve an eligibility balance is worse than a
    /// clean 503 GasDripDisabled.
    #[test]
    fn disabled_without_goat_coin_address_even_though_cap_nonzero() {
        let cfg = config::load_from_map(&Config::test_map()).unwrap();
        assert!(cfg.gas_drip_enabled, "default daily cap must be nonzero");
        let (path, coin) = resolve_gas_drip_wiring(&cfg);
        assert!(
            path.is_none(),
            "no GOAT_COIN_ADDRESS => endpoint must stay off"
        );
        assert_eq!(coin, "");
    }

    /// GOAT_COIN_ADDRESS set + default (nonzero) daily cap → endpoint wired
    /// to STATE_DIR/gas_drips.json with the configured coin address.
    #[test]
    fn enabled_when_goat_coin_address_and_cap_present() {
        let mut m = Config::test_map();
        m.insert(
            "GOAT_COIN_ADDRESS".into(),
            "0x00000000000000000000000000000000000000C0".into(),
        );
        m.insert("STATE_DIR".into(), "./state".into());
        let cfg = config::load_from_map(&m).unwrap();
        let (path, coin) = resolve_gas_drip_wiring(&cfg);
        assert_eq!(
            path,
            Some(cfg.state_dir.join("gas_drips.json")),
            "must resolve to STATE_DIR/gas_drips.json"
        );
        assert_eq!(coin, "0x00000000000000000000000000000000000000C0");
    }

    /// GAS_DRIP_DAILY_CAP=0 disables the endpoint even with a GoatCoin
    /// address configured — the config-level "disabled" decision must win.
    #[test]
    fn disabled_when_daily_cap_zero_even_with_goat_coin_address() {
        let mut m = Config::test_map();
        m.insert(
            "GOAT_COIN_ADDRESS".into(),
            "0x00000000000000000000000000000000000000C0".into(),
        );
        m.insert("GAS_DRIP_DAILY_CAP".into(), "0".into());
        let cfg = config::load_from_map(&m).unwrap();
        assert!(!cfg.gas_drip_enabled);
        let (path, coin) = resolve_gas_drip_wiring(&cfg);
        assert!(path.is_none());
        assert_eq!(coin, "");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goat_attestor::chain::{BatchStatus, MockOp};
    use goat_attestor::proposer::{
        daily_epoch_id, enrollment_epoch_id, is_enrollment_epoch, now_unix, ENROLLMENT_EPOCH_BASE,
    };
    use std::time::Duration;
    use tempfile::tempdir;

    const BOND: u128 = 1_000_000_000_000_000_000;
    const ALICE: &str = "0x00000000000000000000000000000000000000A1";
    const BOB: &str = "0x00000000000000000000000000000000000000B2";

    fn alice_entry(baseline_batched: bool) -> WorkerEntry {
        WorkerEntry {
            wallet: ALICE.into(),
            username: "GOAT-alice".into(),
            baseline_batched,
            fah_id: None,
            enrollment_epoch: None,
        }
    }

    fn bob_entry(baseline_batched: bool) -> WorkerEntry {
        WorkerEntry {
            wallet: BOB.into(),
            username: "GOAT-bob".into(),
            baseline_batched,
            fah_id: None,
            enrollment_epoch: None,
        }
    }

    fn cycle_dirs(dir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let evidence = dir.path().join("evidence");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&evidence).ok();
        std::fs::create_dir_all(&state).ok();
        (evidence, state)
    }

    /// (a) Gate helper: bound worker without on-chain baseline excluded;
    /// sibling with set_has_baseline(true) included.
    #[test]
    fn gate_excludes_without_onchain_baseline() {
        let chain = MockChain::new();
        let mut reg = WorkerRegistry::new();
        reg.upsert(alice_entry(false));
        reg.upsert(bob_entry(true)); // registry flag must NOT be the gate
        chain.set_has_baseline(ALICE, true);
        // Bob: no set_has_baseline → Ok(None) → excluded

        let gated = gate_workers_with_onchain_baseline(&chain, &reg);
        assert_eq!(gated.len(), 1);
        assert!(
            gated[0].wallet.eq_ignore_ascii_case(ALICE),
            "only alice with hasBaseline=true: {:?}",
            gated
        );
    }

    /// (b) Same-cycle: enrollment claim stamps baseline; gate re-read includes worker
    /// for daily batch.
    #[test]
    fn same_cycle_enrollment_then_daily() {
        let dir = tempdir().unwrap();
        let (evidence, state) = cycle_dirs(&dir);
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let http = FixtureHttp::new(default_fixtures_dir());
        let fah = FahClient::new(
            http,
            "https://api.foldingathome.org",
            Duration::from_millis(0),
        );
        let mut reg = WorkerRegistry::new();
        reg.upsert(alice_entry(false));

        run_auto_earn_cycle(&chain, &fah, &mut reg, BOND, &evidence, &state, true, true).unwrap();

        let ops = chain.ops();
        let claims: Vec<_> = ops
            .iter()
            .filter_map(|op| match op {
                MockOp::Claim { epoch, .. } => Some(*epoch),
                _ => None,
            })
            .collect();
        assert!(
            claims.iter().any(|&e| is_enrollment_epoch(e)),
            "expected enrollment claim, claims={claims:?} ops={ops:?}"
        );
        assert!(
            claims.iter().any(|&e| !is_enrollment_epoch(e)),
            "expected daily claim after enrollment, claims={claims:?}"
        );
        // Enrollment claim precedes any daily claim.
        let first_enroll = claims.iter().position(|&e| is_enrollment_epoch(e)).unwrap();
        let first_daily = claims
            .iter()
            .position(|&e| !is_enrollment_epoch(e))
            .unwrap();
        assert!(
            first_enroll < first_daily,
            "enrollment claim must precede daily: claims={claims:?}"
        );
        assert_eq!(
            chain.has_baseline(ALICE).unwrap(),
            Some(true),
            "enrollment claim should stamp baseline"
        );
    }

    /// (c) Enrollment failure for Bob does not abort cycle; Alice (already baselined)
    /// still enters daily.
    #[test]
    fn enrollment_failure_isolates_other_workers() {
        let dir = tempdir().unwrap();
        let (evidence, state) = cycle_dirs(&dir);
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let http = FixtureHttp::new(default_fixtures_dir());
        let fah = FahClient::new(
            http,
            "https://api.foldingathome.org",
            Duration::from_millis(0),
        );

        // Alice already has on-chain baseline + registry flag; Bob needs enrollment.
        let mut reg = WorkerRegistry::new();
        reg.upsert(alice_entry(true));
        reg.upsert(bob_entry(false));
        chain.set_has_baseline(ALICE, true);

        // Pre-seed propose_batch at current enrollment epoch so enrollment propose collides.
        let en_epoch = enrollment_epoch_id(now_unix());
        chain
            .propose_batch(en_epoch, [1u8; 32], [2u8; 32], BOND)
            .unwrap();

        let result =
            run_auto_earn_cycle(&chain, &fah, &mut reg, BOND, &evidence, &state, true, true);
        assert!(result.is_ok(), "cycle must return Ok: {result:?}");

        // Alice should appear in a daily (non-enrollment) claim or propose.
        let ops = chain.ops();
        let daily_proposes: Vec<_> = ops
            .iter()
            .filter_map(|op| match op {
                MockOp::Propose { epoch, .. } if !is_enrollment_epoch(*epoch) => Some(*epoch),
                _ => None,
            })
            .collect();
        assert!(
            !daily_proposes.is_empty(),
            "alice should drive a daily propose; ops={ops:?}"
        );

        // Bob must not have an enrollment claim (propose failed).
        let bob_bytes = goat_attestor::chain::parse_address20(BOB).unwrap();
        let bob_enroll_claim = ops.iter().any(|op| {
            matches!(
                op,
                MockOp::Claim {
                    epoch,
                    worker,
                    ..
                } if is_enrollment_epoch(*epoch) && *worker == bob_bytes
            )
        });
        assert!(
            !bob_enroll_claim,
            "bob must not claim enrollment after collide"
        );
        // Bob still has no baseline → excluded from daily claims.
        assert_ne!(chain.has_baseline(BOB).unwrap(), Some(true));
        let bob_daily_claim = ops.iter().any(|op| {
            matches!(
                op,
                MockOp::Claim {
                    epoch,
                    worker,
                    ..
                } if !is_enrollment_epoch(*epoch) && *worker == bob_bytes
            )
        });
        assert!(
            !bob_daily_claim,
            "bob must be excluded from daily; ops={ops:?}"
        );
    }

    /// (e) Ordering: no daily Claim before all enrollment Claims complete.
    #[test]
    fn enrollment_claims_before_daily_claims() {
        let dir = tempdir().unwrap();
        let (evidence, state) = cycle_dirs(&dir);
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let http = FixtureHttp::new(default_fixtures_dir());
        let fah = FahClient::new(
            http,
            "https://api.foldingathome.org",
            Duration::from_millis(0),
        );
        let mut reg = WorkerRegistry::new();
        reg.upsert(alice_entry(false));
        reg.upsert(bob_entry(false));

        run_auto_earn_cycle(&chain, &fah, &mut reg, BOND, &evidence, &state, true, true).unwrap();

        let claim_epochs: Vec<u64> = chain
            .ops()
            .iter()
            .filter_map(|op| match op {
                MockOp::Claim { epoch, .. } => Some(*epoch),
                _ => None,
            })
            .collect();

        assert!(!claim_epochs.is_empty(), "expected claims");
        assert!(
            claim_epochs.iter().any(|&e| e >= ENROLLMENT_EPOCH_BASE),
            "expected enrollment claims: {claim_epochs:?}"
        );
        assert!(
            claim_epochs.iter().any(|&e| e < ENROLLMENT_EPOCH_BASE),
            "expected daily claims: {claim_epochs:?}"
        );

        // Strict order: every enrollment claim appears before any daily claim.
        let mut saw_daily = false;
        for e in &claim_epochs {
            if is_enrollment_epoch(*e) {
                assert!(!saw_daily, "enrollment claim after daily: {claim_epochs:?}");
            } else {
                saw_daily = true;
            }
        }
    }

    /// (k) Enrollment retry: cycle1 propose only → cycle2 loads persisted batch, settles, daily claim.
    #[test]
    fn enrollment_retry_settles_on_next_cycle() {
        let dir = tempdir().unwrap();
        let (evidence, state) = cycle_dirs(&dir);
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let http = FixtureHttp::new(default_fixtures_dir());
        let fah = FahClient::new(
            http,
            "https://api.foldingathome.org",
            Duration::from_millis(0),
        );
        let mut reg = WorkerRegistry::new();
        reg.upsert(alice_entry(false));

        // cycle1: propose_enrollment_snapshots only (no settle).
        let p = Proposer {
            chain: &chain,
            fah: &fah,
            bond_wei: BOND,
            evidence_dir: evidence.clone(),
            state_dir: state.clone(),
        };
        let batches = p.propose_enrollment_snapshots(&mut reg).unwrap();
        assert!(!batches.is_empty());
        let alice = &reg.all_bound()[0];
        assert!(alice.baseline_batched);
        assert!(alice.enrollment_epoch.is_some());
        assert_ne!(chain.has_baseline(ALICE).unwrap(), Some(true));

        // cycle2: full cycle retries settle, then daily.
        run_auto_earn_cycle(&chain, &fah, &mut reg, BOND, &evidence, &state, true, true).unwrap();

        assert_eq!(
            chain.has_baseline(ALICE).unwrap(),
            Some(true),
            "retry settle should stamp baseline"
        );
        let claims: Vec<u64> = chain
            .ops()
            .iter()
            .filter_map(|op| match op {
                MockOp::Claim { epoch, .. } => Some(*epoch),
                _ => None,
            })
            .collect();
        assert!(
            claims.iter().any(|&e| is_enrollment_epoch(e)),
            "expected enrollment claim from retry: {claims:?}"
        );
        assert!(
            claims.iter().any(|&e| !is_enrollment_epoch(e)),
            "expected daily claim after retry: {claims:?}"
        );
    }

    /// (l) Legacy self-heal: baseline_batched=true, enrollment_epoch=None → clear then re-propose.
    #[test]
    fn legacy_enrollment_self_heal_across_two_cycles() {
        let dir = tempdir().unwrap();
        let (evidence, state) = cycle_dirs(&dir);
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let http = FixtureHttp::new(default_fixtures_dir());
        let fah = FahClient::new(
            http,
            "https://api.foldingathome.org",
            Duration::from_millis(0),
        );
        let mut reg = WorkerRegistry::new();
        reg.upsert(WorkerEntry {
            wallet: ALICE.into(),
            username: "GOAT-alice".into(),
            baseline_batched: true,
            fah_id: None,
            enrollment_epoch: None,
        });

        // cycle1: legacy reset only (sweep is after Phase E; no re-propose same cycle).
        run_auto_earn_cycle(&chain, &fah, &mut reg, BOND, &evidence, &state, true, true).unwrap();
        assert!(
            !reg.all_bound()[0].baseline_batched,
            "legacy clear should reset baseline_batched"
        );
        assert_eq!(reg.all_bound()[0].enrollment_epoch, None);
        assert_ne!(chain.has_baseline(ALICE).unwrap(), Some(true));

        // cycle2: re-propose enrollment, settle, gate into daily.
        run_auto_earn_cycle(&chain, &fah, &mut reg, BOND, &evidence, &state, true, true).unwrap();
        assert_eq!(chain.has_baseline(ALICE).unwrap(), Some(true));
        let claims: Vec<u64> = chain
            .ops()
            .iter()
            .filter_map(|op| match op {
                MockOp::Claim { epoch, .. } => Some(*epoch),
                _ => None,
            })
            .collect();
        assert!(
            claims.iter().any(|&e| is_enrollment_epoch(e)),
            "expected enrollment claim after re-propose: {claims:?}"
        );
        assert!(
            claims.iter().any(|&e| !is_enrollment_epoch(e)),
            "expected daily claim after baseline: {claims:?}"
        );
    }

    /// T31 Fix 2 repro (RED on unfixed code): a daily epoch that is already
    /// consumed (e.g. Finalized, as in the incident) must not trigger a blind
    /// `proposeBatch` → `WrongStatus` revert loop. With `auto_warp`, the cycle
    /// must instead warp the chain past the NEXT midnight so the following
    /// cycle proposes a fresh epoch. Mirrors the incident: epoch 20260720
    /// stayed Finalized while the daemon fired proposeBatch every 120s forever
    /// because auto_warp never advanced past the consumed day.
    #[test]
    fn consumed_epoch_skips_propose_and_warps_to_next_day() {
        let dir = tempdir().unwrap();
        let (evidence, state) = cycle_dirs(&dir);
        let chain = MockChain::new().with_bonds(BOND, BOND);
        let http = FixtureHttp::new(default_fixtures_dir());
        let fah = FahClient::new(
            http,
            "https://api.foldingathome.org",
            Duration::from_millis(0),
        );
        let mut reg = WorkerRegistry::new();
        reg.upsert(alice_entry(true));
        chain.set_has_baseline(ALICE, true);

        // 2024-01-01 00:00:00 UTC (pinned by `daily_epoch_id_format`) → day1.
        chain.set_now(1_704_067_200);
        let day1: u64 = 20240101;

        // Pre-consume day1's epoch (propose → finalize), mirroring the
        // incident's already-Finalized epoch at the start of a new cycle.
        chain
            .propose_batch(day1, [9u8; 32], [8u8; 32], BOND)
            .unwrap();
        chain.finalize_batch(day1).unwrap();
        assert_eq!(
            chain.get_batch(day1).unwrap().status,
            BatchStatus::Finalized
        );

        let ops_before = chain.ops().len();

        // Cycle 1: epoch day1 is already Finalized — must not blind-fire
        // proposeBatch(day1, ...), and auto_warp must advance chain time past
        // day1's midnight so the next cycle sees a fresh epoch.
        run_auto_earn_cycle(&chain, &fah, &mut reg, BOND, &evidence, &state, true, true).unwrap();

        let new_day1_proposes = chain.ops()[ops_before..]
            .iter()
            .filter(|op| matches!(op, MockOp::Propose { epoch, .. } if *epoch == day1))
            .count();
        assert_eq!(
            new_day1_proposes,
            0,
            "must not blind-fire propose on an already-consumed epoch: {:?}",
            chain.ops()
        );

        let now_after = chain.block_timestamp().unwrap();
        assert!(
            now_after >= 1_704_067_200 + 86_400,
            "auto_warp must advance chain time past day1's midnight, now={now_after}"
        );
        assert_eq!(
            daily_epoch_id(now_after),
            20240102,
            "warp must land cleanly on day2 (not overshoot further days): now={now_after}"
        );

        // Cycle 2: epoch has rolled to day2 (status None) — must propose fresh.
        run_auto_earn_cycle(&chain, &fah, &mut reg, BOND, &evidence, &state, true, true).unwrap();
        let day2_proposed = chain.ops().iter().any(|op| {
            matches!(
                op,
                MockOp::Propose {
                    epoch: 20240102,
                    ..
                }
            )
        });
        assert!(
            day2_proposed,
            "next cycle must propose the fresh epoch once the consumed day has rolled over: {:?}",
            chain.ops()
        );
    }
}

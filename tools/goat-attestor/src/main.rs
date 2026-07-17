//! goat-attestor CLI: propose / confirm / challenge / serve-relayer / run.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, warn};

use goat_attestor::chain::{ChainClient, MockChain};
use goat_attestor::challenger::Challenger;
use goat_attestor::config::{self, Config};
use goat_attestor::fah::{FahClient, FixtureHttp, HttpGet, default_fixtures_dir};
use goat_attestor::http_live::{AnyHttp, LiveHttp};
use goat_attestor::proposer::{EpochBatch, Proposer};
use goat_attestor::registry::{WorkerEntry, WorkerRegistry};
use goat_attestor::relayer;
use goat_attestor::rpc_chain::RpcChain;
use goat_attestor::settlement::settle_and_claim_batch;

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
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
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
    }
    Ok(())
}

/// Load registry, merge all on-chain Bound wallets, save. Returns (added, total).
fn sync_registry_from_chain(
    chain: &dyn ChainClient,
    cfg: &Config,
) -> Result<(usize, usize)> {
    let mut reg = WorkerRegistry::load(&cfg.registry_json).unwrap_or_default();
    let bound = chain
        .list_bound_workers()
        .context("list_bound_workers (WorkerBinding.Bound logs)")?;
    let pairs: Vec<(String, String)> = bound
        .into_iter()
        .map(|b| (b.wallet, b.username))
        .collect();
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
        Ok(Arc::new(
            MockChain::new().with_bonds(cfg.proposer_bond_wei, cfg.challenger_bond_wei),
        ))
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
        info!("registry empty at {:?}; nothing to propose", cfg.registry_json);
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

async fn cmd_serve_relayer(cfg: &Config, bind: &str) -> Result<()> {
    let chain = open_chain(cfg)?;
    // Relayer writes new binds into the same registry.json the proposer reads.
    let app = relayer::router_with_registry(chain, Some(cfg.registry_json.clone()));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind} (is another relayer already running?)"))?;
    info!(
        "relayer listening on http://{bind} (mock={}, auto-register → {:?})",
        cfg.mock_mode, cfg.registry_json
    );
    axum::serve(listener, app)
        .await
        .context("axum serve")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use goat_attestor::chain::MockOp;
    use goat_attestor::proposer::{ENROLLMENT_EPOCH_BASE, enrollment_epoch_id, is_enrollment_epoch, now_unix};
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

        run_auto_earn_cycle(
            &chain,
            &fah,
            &mut reg,
            BOND,
            &evidence,
            &state,
            true,
            true,
        )
        .unwrap();

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
        let first_enroll = claims
            .iter()
            .position(|&e| is_enrollment_epoch(e))
            .unwrap();
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

        let result = run_auto_earn_cycle(
            &chain,
            &fah,
            &mut reg,
            BOND,
            &evidence,
            &state,
            true,
            true,
        );
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
        assert!(!bob_enroll_claim, "bob must not claim enrollment after collide");
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
        assert!(!bob_daily_claim, "bob must be excluded from daily; ops={ops:?}");
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

        run_auto_earn_cycle(
            &chain,
            &fah,
            &mut reg,
            BOND,
            &evidence,
            &state,
            true,
            true,
        )
        .unwrap();

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
                assert!(
                    !saw_daily,
                    "enrollment claim after daily: {claim_epochs:?}"
                );
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
        run_auto_earn_cycle(
            &chain,
            &fah,
            &mut reg,
            BOND,
            &evidence,
            &state,
            true,
            true,
        )
        .unwrap();

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
        run_auto_earn_cycle(
            &chain,
            &fah,
            &mut reg,
            BOND,
            &evidence,
            &state,
            true,
            true,
        )
        .unwrap();
        assert!(
            !reg.all_bound()[0].baseline_batched,
            "legacy clear should reset baseline_batched"
        );
        assert_eq!(reg.all_bound()[0].enrollment_epoch, None);
        assert_ne!(chain.has_baseline(ALICE).unwrap(), Some(true));

        // cycle2: re-propose enrollment, settle, gate into daily.
        run_auto_earn_cycle(
            &chain,
            &fah,
            &mut reg,
            BOND,
            &evidence,
            &state,
            true,
            true,
        )
        .unwrap();
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
}

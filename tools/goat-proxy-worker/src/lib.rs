//! `goat-proxy-worker` — the residential-proxy sidecar's egress policy.
//!
//! # This crate's network policy is the INVERSE of `goat-worker`'s, deliberately
//!
//! The repository already ships a worker binary, `src/bin/goat_worker.rs`, whose
//! `net_connect` answers `DENIED network-disabled` to every request, and
//! `src/bin/isolation.rs`'s `network_connect_denied()` asserts exactly that in
//! CI. **That worker, that answer and that test are unchanged by this crate and
//! must stay unchanged.** Compute work runs with no network, and nothing here
//! relaxes it.
//!
//! This is a **different, separate binary** with a **different, opposite** job:
//! it opens outbound sockets on purpose, and the whole of its design is about
//! bounding which ones. The two policies are kept in two processes with two
//! crate graphs precisely so that neither can be reached from the other by
//! accident — this package depends on the root package not at all. A reader who
//! takes "the GOAT worker denies all network" and "the GOAT worker dials the
//! open web" as a contradiction has found two different workers, not an
//! inconsistency.
//!
//! # The threat finding this design answers
//!
//! An independent analysis established that **port-gating to 80/443 plus
//! filtering on the TLS server name does not work**: Encrypted ClientHello
//! hides the real name; domain fronting splits the server name from the `Host`
//! header; the server name is client-asserted and authenticated by nobody; a
//! request to a bare IP literal carries no server name at all; and a request
//! that asks for an opaque bidirectional tunnel on 443 carries any protocol at
//! all through the port gate. Every abuse class the feature exists to prevent —
//! credential stuffing, ad fraud, layer-7 flooding, malware command-and-control,
//! forbidden scraping, illegal-content retrieval — fits inside ordinary HTTPS on
//! 443.
//!
//! So the control is a **destination allowlist**, decided on the address this
//! node resolved, with these properties:
//!
//! 1. **Fail closed by construction.** An absent, empty, unreadable or corrupt
//!    allowlist is a startup refusal. There is no code path from any of those
//!    states to a running daemon, and none to "permit everything".
//! 2. **Resolve here, then pin.** The consumer never supplies an address. The
//!    node resolves once, validates **every** address in the answer, and dials a
//!    `SocketAddr` — so the address that was checked is the address that is
//!    dialled, with no second lookup in between for a rebinding answer to win.
//! 3. **The address predicate is allow-by-exception.**
//!    [`resolve::is_public_unicast`] permits ordinary global unicast and refuses
//!    everything else, including the encodings and IPv6 transition forms that an
//!    enumerated range list misses.
//! 4. **Every redirect hop re-runs the whole evaluation**, under a bound that is
//!    checked inside the policy rather than by whoever loops.
//! 5. **No opaque relay.** The node terminates as an HTTP client. There is no
//!    method variant for tunnelling, no bidirectional copy, and no listening
//!    socket.
//! 6. **The port gate is retained and documented as necessary and grossly
//!    insufficient** — see [`policy::ALLOWED_PORTS`].
//!
//! # Zero content in anything that leaves this crate
//!
//! A destination is an **allowlist entry id** plus the digest of the list that
//! id indexes. No URL, path, query string, header or body byte may appear in a
//! receipt or in any line this crate emits. [`policy::PolicyDecision`] carries an
//! id, an address and a port, and a test asserts it carries nothing else.
//!
//! # Honesty tagging
//!
//! Every capability here is **[TARGET]**. Nothing is [NOW]: there is no
//! deployed gateway, no pilot traffic, and the shipped allowlist is a
//! placeholder of IANA documentation domains, not a cleared destination set.
//! The refusal paths are the only thing that runs today, and refusing is not a
//! capability.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Tasks 28-30 and its Global Constraints and Security invariants
//! sections (INV-1 through INV-7, INV-11, INV-18, INV-19); and the "Residential
//! Proxy Network (P3) Implementation Plan", §2, §3 and §4.1.

#![forbid(unsafe_code)]

pub mod caps;
pub mod census;
pub mod config;
pub mod consent;
pub mod destinations;
pub mod fetch;
pub mod indicator;
pub mod logging;
pub mod meter;
pub mod net;
pub mod policy;
pub mod resolve;
pub mod robots;
pub mod supervisor;
/// Crate-source sweeps (INV-5, INV-19, vocabulary law). `#[cfg(test)]` bodies
/// only, so nothing here reaches a release binary.
///
/// The FILE is published, and this declaration is why: `lib.rs` is published,
/// and a published tree carrying this line without `vocabulary_audit.rs` does
/// not compile — `cargo fmt` refuses to resolve the module before any test
/// runs. Withholding a test-only file from the export does not keep it off the
/// public surface; it breaks the public build.
mod vocabulary_audit;

use std::path::Path;
use std::sync::Arc;

pub use caps::{
    CapError, EgressLedger, TokenBucket, DEFAULT_BUCKET_CAPACITY_BYTES, DEFAULT_DAILY_BYTE_CAP,
};
pub use census::{egress_socket_census, CensusError};
pub use config::{
    now_unix, ConfigError, ProxyConfig, DECLARED_ENV, ENV_ALLOWLIST, ENV_CONSENT,
    ENV_DAILY_CEILING_BYTES, ENV_OPERATOR_WALLET, ENV_POLICY_TEXT_HASH, ENV_STATE_DIR,
    ENV_THROTTLE_BPS,
};
pub use consent::{
    consent_state, effective_daily_ceiling, effective_throttle, load_consent, preimage,
    preimage_digest, verify_consent, ConsentError, ConsentRecord, ConsentState, CONSENT_SCHEMA,
    CONSENT_TTL_SECS,
};
pub use fetch::{
    fetch_once, fetch_with_redirects, BodySink, FetchError, FetchOutcome, GatewayLink,
    HttpRobotsFetcher, MAX_RESPONSE_BYTES, REQUEST_TIMEOUT,
};
pub use indicator::{Indicator, INDICATOR_TTL_SECS};
pub use logging::{
    emit, emit_both, emit_egress_line, EgressLine, OperatorLogRing, RefusalReason, SafeEvent,
    EGRESS_LINE_ALLOWED_KEYS, OPERATOR_LOG_RING_CAPACITY,
};
pub use meter::{ChunkKind, ChunkReceiptDraft, MeterCounter, SessionMeter, CHUNK_BYTES};
pub use net::{
    HaltReport, MeteredStream, SocketRegistry, TrackedStream, KILL_DEADLINE, KILL_DEADLINE_MS,
};
pub use policy::{
    next_request, operator_allowlist_digest, operator_allowlist_preimage, AllowlistEntry, Clock,
    DenyReason, EgressPolicy, EntryRateLimiter, MatchMode, Method, PathScope, PolicyDecision,
    PolicyError, ProxyRequest, Scheme, SystemClock, ALLOWED_PORTS, MAX_REDIRECT_HOPS,
};
pub use resolve::{
    is_denied_net, is_public_unicast, parse_canonical_ip_literal, resolve_and_pin,
    unwrap_embedded_v4, FixedResolver, PinnedTarget, Resolver, SequencedResolver, SystemResolver,
};
pub use robots::{
    RobotsCache, RobotsFetchOutcome, RobotsFetcher, RobotsVerdict, MAX_ROBOTS_BYTES,
    ROBOTS_CONTACT_MAILBOX, ROBOTS_UA,
};
pub use supervisor::{
    HaltReceipt, ProxySupervisor, SocketsAfter, SpawnConfig, SupervisorError, CMD_BEAT, CMD_HALT,
};

/// `EX_CONFIG` from `sysexits.h`. The one exit code every startup refusal uses,
/// so a supervisor can tell "this configuration will never work" from "this run
/// failed".
pub const EXIT_CONFIG: i32 = 78;

/// Why the sidecar refused to start.
///
/// There is **no** variant that means "started with reduced capability". Every
/// one of these is a process that does not run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartupRefusal {
    #[error("the destination allowlist: {0}")]
    Allowlist(PolicyError),
    #[error("consent: {0}")]
    Consent(ConsentError),
}

impl StartupRefusal {
    /// The exit code the process leaves with.
    pub fn exit_code(&self) -> i32 {
        EXIT_CONFIG
    }
}

/// **The startup gate. This is where the daemon reads the consent record.**
///
/// Four things happen here and all four are preconditions, not preferences:
///
/// 1. the allowlist loads, or the daemon does not start (INV-1);
/// 2. the consent record loads **from the file**, and is verified against the
///    disclosure hash, the digest of the list just loaded, and the wallet the
///    supervisor named (INV-8) — the desktop having already verified it is not a
///    reason to skip this, because the app is not trusted to have checked;
/// 3. the ceiling and throttle are `min(consented, configured)`, so
///    configuration can only lower what the operator signed;
/// 4. the byte ledger is opened over the daemon's own state directory, so the
///    cap holds with the shell dead.
///
/// The caller supplies the resolver, the robots fetcher and the clock, because
/// those are the seams a test replaces; nothing else about this function is
/// replaceable.
pub fn start_gate(
    cfg: &ProxyConfig,
    now_unix_secs: u64,
    resolver: Arc<dyn Resolver>,
    robots: Arc<RobotsCache>,
    clock: Arc<dyn Clock>,
) -> Result<(EgressPolicy, ConsentRecord), StartupRefusal> {
    start_gate_with(cfg, now_unix_secs, resolver, |_| robots, clock)
}

/// [`start_gate`], with the robots cache built **after** the byte ledger
/// exists.
///
/// The daemon's real robots fetcher debits its bytes against the operator's
/// ceiling — an undebited fetch path is an uncapped one (INV-7) — so it needs
/// the ledger, and the ledger is created inside the gate from the consented
/// ceiling. A cache handed in from outside therefore cannot be the real one,
/// which is why `main.rs` takes this form and the tests take the other.
///
/// The gate is written once, here. Two copies of a startup order is how one of
/// them loses a step.
pub fn start_gate_with(
    cfg: &ProxyConfig,
    now_unix_secs: u64,
    resolver: Arc<dyn Resolver>,
    make_robots: impl FnOnce(&Arc<EgressLedger>) -> Arc<RobotsCache>,
    clock: Arc<dyn Clock>,
) -> Result<(EgressPolicy, ConsentRecord), StartupRefusal> {
    // 1. The list first: consent binds its digest, so there is nothing to
    //    verify consent against until the list has loaded.
    let (entries, allowlist_digest) =
        EgressPolicy::load_entries(&cfg.allowlist_path).map_err(StartupRefusal::Allowlist)?;

    // 2. Consent, read from the file and verified again here.
    let record = load_consent(&cfg.consent_path).map_err(StartupRefusal::Consent)?;
    verify_consent(
        &record,
        now_unix_secs,
        cfg.policy_text_hash,
        allowlist_digest,
        cfg.operator_wallet,
    )
    .map_err(StartupRefusal::Consent)?;

    // 3. Consent is a ceiling; configuration may only lower it.
    let ceiling = effective_daily_ceiling(&record, cfg.daily_ceiling_bytes);
    let throttle = effective_throttle(&record, cfg.throttle_bytes_per_sec);

    // 4. The ledger lives in the directory the DAEMON owns.
    let budget = Arc::new(EgressLedger::new(
        ledger_path(&cfg.state_dir),
        ceiling,
        TokenBucket::at_rate(throttle),
    ));

    let robots = make_robots(&budget);

    Ok((
        EgressPolicy::new(
            entries,
            allowlist_digest,
            resolver,
            robots,
            budget,
            Arc::new(Indicator::new()),
            clock,
        ),
        record,
    ))
}

/// The one place the ledger's file name is written.
pub fn ledger_path(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("egress-ledger.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct AllowAllRobots;

    #[async_trait::async_trait]
    impl RobotsFetcher for AllowAllRobots {
        async fn fetch(&self, _s: Scheme, _t: &PinnedTarget) -> RobotsFetchOutcome {
            RobotsFetchOutcome::AllowAll
        }
    }

    fn robots() -> Arc<RobotsCache> {
        Arc::new(RobotsCache::new(Box::new(AllowAllRobots)))
    }

    fn resolver() -> Arc<dyn Resolver> {
        Arc::new(FixedResolver::new(vec!["93.184.216.34".parse().unwrap()]))
    }

    const GRANTED: u64 = 1_780_000_000;
    const POLICY_HASH: [u8; 32] = [0xAA; 32];

    fn key(seed: u8) -> k256::ecdsa::SigningKey {
        let mut bytes = [1u8; 32];
        bytes[31] = seed;
        k256::ecdsa::SigningKey::from_slice(&bytes).expect("valid key")
    }

    /// `start_gate` returns an `EgressPolicy`, which holds trait objects and is
    /// therefore not `Debug`. `expect_err` needs `Debug` on the success type, so
    /// the refusal is taken by hand.
    fn refusal(
        r: Result<(EgressPolicy, ConsentRecord), StartupRefusal>,
        what: &str,
    ) -> StartupRefusal {
        match r {
            Ok(_) => panic!("{what}"),
            Err(e) => e,
        }
    }

    fn address_of(k: &k256::ecdsa::SigningKey) -> [u8; 20] {
        use sha3::{Digest, Keccak256};
        let point = k.verifying_key().to_encoded_point(false);
        let mut h = Keccak256::new();
        h.update(&point.as_bytes()[1..]);
        let d: [u8; 32] = h.finalize().into();
        let mut out = [0u8; 20];
        out.copy_from_slice(&d[12..]);
        out
    }

    fn sign(k: &k256::ecdsa::SigningKey, message: &[u8]) -> [u8; 65] {
        use sha3::{Digest, Keccak256};
        let mut h = Keccak256::new();
        h.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
        h.update(message);
        let digest: [u8; 32] = h.finalize().into();
        let (sig, rid) = k.sign_prehash_recoverable(&digest).expect("sign");
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = rid.to_byte() + 27;
        out
    }

    fn shipped_allowlist() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("allowlist.json")
    }

    /// A state directory holding the named allowlist and a consent record
    /// signed over the named digest.
    ///
    /// The digest is a PARAMETER rather than something this helper computes,
    /// because the gate's whole job is to compare a digest somebody else
    /// produced against the one it derived itself — a helper that always
    /// supplied the loader's own answer could not express the disagreement.
    fn fixture_over(
        dir: &Path,
        k: &k256::ecdsa::SigningKey,
        allowlist: &Path,
        allowlist_digest: [u8; 32],
        consented_ceiling: u64,
    ) -> ProxyConfig {
        let mut record = ConsentRecord {
            schema: CONSENT_SCHEMA,
            policy_version: 1,
            policy_digest: POLICY_HASH,
            allowlist_digest,
            wallet: address_of(k),
            device_id: "start-gate".into(),
            daily_ceiling_bytes: consented_ceiling,
            throttle_bytes_per_sec: 1_250_000,
            granted_at_unix: GRANTED,
            expires_at_unix: GRANTED + CONSENT_TTL_SECS,
            signature: [0u8; 65],
        };
        record.signature = sign(k, preimage(&record).as_bytes());

        let consent_path = dir.join("proxy-consent.json");
        std::fs::write(
            &consent_path,
            serde_json::to_string(&record).expect("render"),
        )
        .expect("write consent");

        let map: HashMap<String, String> = [
            (ENV_ALLOWLIST, allowlist.to_string_lossy().to_string()),
            (ENV_CONSENT, consent_path.to_string_lossy().to_string()),
            (ENV_STATE_DIR, dir.to_string_lossy().to_string()),
            (ENV_POLICY_TEXT_HASH, hex::encode(POLICY_HASH)),
            (ENV_DAILY_CEILING_BYTES, "200000000000".into()),
            (ENV_THROTTLE_BPS, "1250000".into()),
            (ENV_OPERATOR_WALLET, hex::encode(address_of(k))),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b))
        .collect();

        ProxyConfig::load_from_map(&map).expect("config loads")
    }

    /// A state directory holding a real allowlist and a real, valid consent
    /// record over that list's digest.
    fn fixture(
        dir: &Path,
        k: &k256::ecdsa::SigningKey,
        consented_ceiling: u64,
    ) -> (ProxyConfig, [u8; 32]) {
        let allowlist = shipped_allowlist();
        let (_e, digest) = EgressPolicy::load_entries(&allowlist).expect("shipped list loads");
        (
            fixture_over(dir, k, &allowlist, digest, consented_ceiling),
            digest,
        )
    }

    /// The `(id, host)` pairs of an allowlist file, read out of the JSON BY THE
    /// TEST rather than taken from the loader, so the digest built from them is
    /// derived from the artifact and not from the code under test.
    /// The shipped list's destinations named the way the DESKTOP names them:
    /// the registered slug, and the host.
    ///
    /// The slug is resolved through the canonical registry rather than invented
    /// here, which is the point of the second founder ruling — the sidecar's
    /// file carries `u32` ids and the desktop's document carries slugs, and one
    /// static table is what turns either into the other.
    fn slug_host_pairs(path: &Path) -> Vec<(String, String)> {
        let text = std::fs::read_to_string(path).expect("read the list");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("parse the list");
        doc["entries"]
            .as_array()
            .expect("entries array")
            .iter()
            .map(|e| {
                let id = e["id"].as_u64().expect("entry id") as u32;
                (
                    destinations::slug_for_id(id)
                        .expect("every shipped id is in the canonical registry")
                        .to_string(),
                    e["host"].as_str().expect("entry host").to_string(),
                )
            })
            .collect()
    }

    /// The RETIRED v1 operator-facing digest: SHA-256 over the v1 domain and
    /// TWO-field records — one identifier and a host — sorted by the
    /// identifier's TEXT, with no canonical slug <-> id table anywhere in it.
    ///
    /// Reproduced here, in a test, and nowhere else in the crate, so that "a
    /// record computed WITHOUT the canonical mapping is refused" is a claim this
    /// module can actually make rather than assert about a construction that no
    /// longer exists. It is driven from both ends: with the desktop's slugs,
    /// which is what the desktop used to hash, and with the sidecar's rendered
    /// integers, which is what this crate used to hash. Those two disagreed with
    /// each other, which is the defect the ruling repairs.
    fn retired_v1_summary_digest(pairs: &[(String, String)]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut sorted = pairs.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let mut pre = String::from("GOAT-PROXY-ALLOWLIST-v1\n");
        for (id, host) in &sorted {
            pre.push_str(id);
            pre.push('\u{1f}');
            pre.push_str(host);
            pre.push('\u{1e}');
        }
        let mut h = Sha256::new();
        h.update(pre.as_bytes());
        h.finalize().into()
    }

    /// The RETIRED operational-manifest digest — Keccak-256 over `id`, `host`,
    /// `match_mode`, `path_scope`, `path_prefixes` and the per-entry rate.
    ///
    /// Reproduced here, in a test, and nowhere else in the crate, so that "a
    /// record whose digest was computed the old way is refused" is a claim this
    /// module can actually make rather than assert about a function that no
    /// longer exists.
    fn retired_manifest_digest(entries: &[AllowlistEntry]) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        let mut lines: Vec<String> = entries
            .iter()
            .map(|e| {
                format!(
                    "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
                    e.id,
                    e.host,
                    match e.match_mode {
                        MatchMode::Exact => "exact",
                    },
                    match e.path_scope {
                        PathScope::Prefixes => "prefixes",
                        PathScope::WholeOrigin => "whole_origin",
                    },
                    e.path_prefixes.join("\u{1e}"),
                    e.max_requests_per_minute,
                )
            })
            .collect();
        lines.sort();
        let mut h = Keccak256::new();
        h.update(b"GOAT_PROXY_ALLOWLIST_DIGEST_V1");
        h.update((lines.len() as u32).to_be_bytes());
        for line in &lines {
            h.update((line.len() as u32).to_be_bytes());
            h.update(line.as_bytes());
        }
        h.finalize().into()
    }

    /// THE gate test.
    ///
    /// Mutations this detects: `verify_consent`'s result discarded with `let _
    /// =`; the consent check moved behind a flag; the record read from the
    /// supervisor's word rather than from the file.
    #[test]
    fn a_missing_or_invalid_consent_record_prevents_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let k = key(3);
        let (cfg, _digest) = fixture(dir.path(), &k, 10_737_418_240);

        // POSITIVE CONTROL first, so every refusal below is a difference and not
        // a gate that never opens.
        let (policy, record) = start_gate(
            &cfg,
            GRANTED + 1,
            resolver(),
            robots(),
            Arc::new(SystemClock),
        )
        .expect("a valid record must start the daemon");
        assert_eq!(record.wallet, address_of(&k));

        // Consent is a CEILING: configuration named 200 GB, the record named
        // 10 GiB, and the ledger got the smaller of the two.
        assert_eq!(policy.budget().ceiling_bytes(), 10_737_418_240);
        // And the ledger lives in the daemon's own state directory.
        assert!(policy.budget().path().starts_with(dir.path()));

        // 1. ABSENT.
        std::fs::remove_file(&cfg.consent_path).expect("remove consent");
        let err = refusal(
            start_gate(
                &cfg,
                GRANTED + 1,
                resolver(),
                robots(),
                Arc::new(SystemClock),
            ),
            "no consent record must refuse to start",
        );
        assert_eq!(err, StartupRefusal::Consent(ConsentError::Absent));
        assert_eq!(err.exit_code(), EXIT_CONFIG);

        // 2. PRESENT BUT SIGNED BY SOMEBODY ELSE.
        let dir_foreign = tempfile::tempdir().expect("tempdir");
        let (foreign_cfg, _) = fixture(dir_foreign.path(), &key(4), 10_737_418_240);
        let mut mixed = cfg.clone();
        mixed.consent_path = foreign_cfg.consent_path.clone();
        assert_eq!(
            refusal(
                start_gate(
                    &mixed,
                    GRANTED + 1,
                    resolver(),
                    robots(),
                    Arc::new(SystemClock)
                ),
                "a foreign signer must refuse to start"
            ),
            StartupRefusal::Consent(ConsentError::ForeignSigner)
        );

        // 3. PRESENT, VALID, BUT FOR A DIFFERENT DESTINATION LIST.
        let dir2 = tempfile::tempdir().expect("tempdir");
        let (cfg2, _) = fixture(dir2.path(), &k, 10_737_418_240);
        let other_list = dir2.path().join("other-allowlist.json");
        std::fs::write(
            &other_list,
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[{"id":9,"host":"other.example",
               "match_mode":"exact","path_scope":"whole_origin","path_prefixes":[],
               "max_requests_per_minute":5}]}"#,
        )
        .expect("write other list");
        let mut swapped = cfg2.clone();
        swapped.allowlist_path = other_list;
        assert_eq!(
            refusal(
                start_gate(
                    &swapped,
                    GRANTED + 1,
                    resolver(),
                    robots(),
                    Arc::new(SystemClock)
                ),
                "a swapped destination list must refuse to start"
            ),
            StartupRefusal::Consent(ConsentError::AllowlistDigestMismatch)
        );

        // 4. EXPIRED.
        assert_eq!(
            refusal(
                start_gate(
                    &cfg2,
                    GRANTED + CONSENT_TTL_SECS + 1,
                    resolver(),
                    robots(),
                    Arc::new(SystemClock)
                ),
                "an expired record must refuse to start"
            ),
            StartupRefusal::Consent(ConsentError::Expired)
        );

        // 5. NO ALLOWLIST AT ALL — checked before consent, because consent binds
        //    the list's digest and there is nothing to bind to yet.
        let mut listless = cfg2.clone();
        listless.allowlist_path = dir2.path().join("not-here.json");
        assert_eq!(
            refusal(
                start_gate(
                    &listless,
                    GRANTED + 1,
                    resolver(),
                    robots(),
                    Arc::new(SystemClock)
                ),
                "an absent list must refuse to start"
            ),
            StartupRefusal::Allowlist(PolicyError::AllowlistAbsent)
        );
    }

    /// The founder ruling at the gate: a record carrying the OPERATOR-FACING
    /// digest starts the daemon, and one carrying the retired
    /// operational-manifest digest does not.
    ///
    /// This is the interoperation the ruling exists to restore. The desktop
    /// signs the digest of the summary it showed the operator; before the
    /// ruling the sidecar compared that against a Keccak hash of its own
    /// operational manifest, so **every** record the surface produced was
    /// refused with `AllowlistDigestMismatch` and bandwidth sharing could not be
    /// switched on at all.
    ///
    /// The digest handed to the gate here is built by the test from the
    /// allowlist FILE's `(id, host)` pairs — not taken from `load_entries` —
    /// so this is a comparison between two independent derivations rather than
    /// a value compared with itself. That the construction is the desktop's is
    /// pinned separately, against the desktop's own fixture, by
    /// `policy::tests::the_allowlist_digest_reproduces_the_desktop_pin`.
    ///
    /// Mutations this detects: the sidecar's digest reverted to Keccak over the
    /// operational manifest, which reds the positive control below; the digest
    /// comparison in `verify_consent` dropped or weakened, which reds both
    /// refusals; the host dropped from the preimage, which reds the swapped-host
    /// refusal.
    #[test]
    fn the_gate_accepts_the_operator_facing_digest_and_refuses_the_retired_one() {
        let k = key(7);
        let allowlist = shipped_allowlist();
        let (entries, loaded) = EgressPolicy::load_entries(&allowlist).expect("shipped list loads");

        // The digest as the DESKTOP computes it, over the summary an operator
        // reads: the destination named by its SLUG and its host, serialised
        // through the canonical registry, SHA-256.
        let owned = slug_host_pairs(&allowlist);
        let pairs: Vec<(&str, &str)> = owned
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let operator_facing =
            policy::operator_allowlist_digest(&pairs).expect("the shipped slugs are registered");
        assert_eq!(
            operator_facing, loaded,
            "the loader and the operator-facing construction disagree about the shipped list"
        );

        // 1. POSITIVE CONTROL: a record signed over that digest starts the
        //    daemon.
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = fixture_over(dir.path(), &k, &allowlist, operator_facing, 10_737_418_240);
        let (_policy, record) = start_gate(
            &cfg,
            GRANTED + 1,
            resolver(),
            robots(),
            Arc::new(SystemClock),
        )
        .expect("a record carrying the operator-facing digest must start the daemon");
        assert_eq!(record.allowlist_digest, operator_facing);

        // 2. THE RETIRED CONSTRUCTION IS REFUSED. A record computed the old way
        //    over the very same list no longer verifies.
        let retired = retired_manifest_digest(&entries);
        assert_ne!(
            retired, operator_facing,
            "the two constructions collided; this test proves nothing"
        );
        let dir_old = tempfile::tempdir().expect("tempdir");
        let cfg_old = fixture_over(dir_old.path(), &k, &allowlist, retired, 10_737_418_240);
        assert_eq!(
            refusal(
                start_gate(
                    &cfg_old,
                    GRANTED + 1,
                    resolver(),
                    robots(),
                    Arc::new(SystemClock)
                ),
                "a record carrying the retired manifest digest must refuse to start"
            ),
            StartupRefusal::Consent(ConsentError::AllowlistDigestMismatch)
        );

        // 2b. AND SO IS A RECORD COMPUTED WITHOUT THE CANONICAL MAPPING. The v1
        //     summary digest named a destination by ONE identifier, and which
        //     one depended on which side was hashing — the desktop wrote the
        //     slug, this crate wrote the integer, and the two disagreed. Both
        //     spellings are refused, and the assertion is made from both ends so
        //     that "the old way" is not quietly read as only the other side's
        //     old way.
        let integer_ids: Vec<(String, String)> = entries
            .iter()
            .map(|e| (e.id.to_string(), e.host.clone()))
            .collect();
        for (which, stale) in [
            (
                "the desktop's v1 slug summary",
                retired_v1_summary_digest(&owned),
            ),
            (
                "this crate's v1 integer summary",
                retired_v1_summary_digest(&integer_ids),
            ),
        ] {
            assert_ne!(
                stale, operator_facing,
                "{which} collided with the canonical digest; this test proves nothing"
            );
            let dir_v1 = tempfile::tempdir().expect("tempdir");
            let cfg_v1 = fixture_over(dir_v1.path(), &k, &allowlist, stale, 10_737_418_240);
            assert_eq!(
                refusal(
                    start_gate(
                        &cfg_v1,
                        GRANTED + 1,
                        resolver(),
                        robots(),
                        Arc::new(SystemClock)
                    ),
                    "a record carrying a non-canonical digest must refuse to start"
                ),
                StartupRefusal::Consent(ConsentError::AllowlistDigestMismatch),
                "{which} was accepted"
            );
        }

        // 3. AND A SWAPPED DESTINATION IS STILL REFUSED — the property the
        //    ruling must not have cost. One edited host, same construction.
        let mut swapped = owned.clone();
        swapped[0].1 = "elsewhere.example".to_string();
        let swapped_pairs: Vec<(&str, &str)> = swapped
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let swapped_digest =
            policy::operator_allowlist_digest(&swapped_pairs).expect("registered slugs");
        assert_ne!(swapped_digest, operator_facing);
        let dir_swapped = tempfile::tempdir().expect("tempdir");
        let cfg_swapped = fixture_over(
            dir_swapped.path(),
            &k,
            &allowlist,
            swapped_digest,
            10_737_418_240,
        );
        assert_eq!(
            refusal(
                start_gate(
                    &cfg_swapped,
                    GRANTED + 1,
                    resolver(),
                    robots(),
                    Arc::new(SystemClock)
                ),
                "a record naming a swapped destination must refuse to start"
            ),
            StartupRefusal::Consent(ConsentError::AllowlistDigestMismatch)
        );
    }

    /// The other half of the ruling, at the gate: daemon tuning must NOT
    /// invalidate a signature.
    ///
    /// The operator signed a set of destinations. Re-writing the same
    /// destinations with a different path scope and a different per-entry rate
    /// is operation, not a change of scope, and the daemon must still start.
    ///
    /// Mutations this detects: the operational fields folded back into the
    /// digest, which reds this and would halt every node on a rate-limit edit;
    /// the loader's `path_prefixes` sort removed, which reintroduces order
    /// sensitivity somewhere the operator cannot see.
    #[test]
    fn retuning_the_daemon_does_not_invalidate_a_signed_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let k = key(8);
        let (cfg, digest) = fixture(dir.path(), &k, 10_737_418_240);

        // POSITIVE CONTROL: the untouched list starts.
        assert!(start_gate(
            &cfg,
            GRANTED + 1,
            resolver(),
            robots(),
            Arc::new(SystemClock)
        )
        .is_ok());

        // The SAME destinations, retuned: the whole origin instead of a prefix,
        // and a different rate ceiling.
        let retuned = dir.path().join("retuned-allowlist.json");
        std::fs::write(
            &retuned,
            r#"{"schema_id":"GOAT_PROXY_ALLOWLIST_V1","entries":[
               {"id":1,"host":"example.com","match_mode":"exact","path_scope":"whole_origin",
                "path_prefixes":[],"max_requests_per_minute":90},
               {"id":2,"host":"example.org","match_mode":"exact","path_scope":"prefixes",
                "path_prefixes":["/static/","/api/v1/","/api/v2/"],"max_requests_per_minute":1},
               {"id":3,"host":"research.example.net","match_mode":"exact","path_scope":"prefixes",
                "path_prefixes":["/open-data/","/mirror/"],"max_requests_per_minute":10}]}"#,
        )
        .expect("write the retuned list");

        let (retuned_entries, retuned_digest) =
            EgressPolicy::load_entries(&retuned).expect("the retuned list loads");
        assert_eq!(
            retuned_digest, digest,
            "retuning moved the operator-facing digest"
        );
        // POSITIVE CONTROL on the edit: the LOADED list really is different, so
        // the equality above is not two identical files agreeing.
        let (base_entries, _) = EgressPolicy::load_entries(&shipped_allowlist()).expect("loads");
        assert_ne!(retuned_entries, base_entries);
        // ...and the retired construction WOULD have moved, which is exactly the
        // breakage the ruling removes.
        assert_ne!(
            retired_manifest_digest(&retuned_entries),
            retired_manifest_digest(&base_entries),
            "the retired construction did not move either; the edit is too weak to prove anything"
        );

        let mut retuned_cfg = cfg.clone();
        retuned_cfg.allowlist_path = retuned;
        assert!(
            start_gate(
                &retuned_cfg,
                GRANTED + 1,
                resolver(),
                robots(),
                Arc::new(SystemClock)
            )
            .is_ok(),
            "a retuned list invalidated a signature it must not have touched"
        );
    }

    /// Mutations this detects: `max` in place of `min` in the startup gate's
    /// ceiling computation, which would let the environment raise what the
    /// operator signed.
    #[test]
    fn configuration_cannot_raise_the_consented_ceiling_at_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let k = key(5);
        // The operator signed 2 GB; configuration names 200 GB.
        let (cfg, _) = fixture(dir.path(), &k, 2_000_000_000);
        let (policy, _r) = start_gate(
            &cfg,
            GRANTED + 1,
            resolver(),
            robots(),
            Arc::new(SystemClock),
        )
        .expect("starts");
        assert_eq!(policy.budget().ceiling_bytes(), 2_000_000_000);

        // POSITIVE CONTROL: configuration BELOW the consented value does win.
        let mut lower = cfg.clone();
        lower.daily_ceiling_bytes = 1_500_000_000;
        let (policy2, _r2) = start_gate(
            &lower,
            GRANTED + 1,
            resolver(),
            robots(),
            Arc::new(SystemClock),
        )
        .expect("starts");
        assert_eq!(policy2.budget().ceiling_bytes(), 1_500_000_000);
    }

    /// INV-9's headline property, at the seam that owns it.
    ///
    /// Mutations this detects: the ledger placed under a caller-supplied path,
    /// or held in memory, either of which lets a restart hand back an allowance
    /// the previous run had already spent.
    #[test]
    fn the_daily_cap_holds_across_a_restart_with_the_ui_process_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let k = key(6);
        let (cfg, _) = fixture(dir.path(), &k, crate::caps::MIN_DAILY_BYTE_CAP);
        let now = GRANTED + 1;

        {
            let (policy, _r) =
                start_gate(&cfg, now, resolver(), robots(), Arc::new(SystemClock)).expect("starts");
            policy
                .budget()
                .spend(crate::caps::MIN_DAILY_BYTE_CAP - 1_000, now)
                .expect("spend");
        } // the whole process, UI included, goes away here

        let (restarted, _r) =
            start_gate(&cfg, now, resolver(), robots(), Arc::new(SystemClock)).expect("restarts");
        assert_eq!(
            restarted.budget().remaining_today(now),
            Ok(1_000),
            "a restart handed back an allowance the previous run had spent"
        );

        // POSITIVE CONTROL first, because an over-ask closes the day: exactly
        // what remains is still spendable.
        assert!(restarted.budget().spend(1_000, now).is_ok());
        assert_eq!(
            restarted.budget().spend(1, now),
            Err(CapError::DailyCeilingReached)
        );
    }
}

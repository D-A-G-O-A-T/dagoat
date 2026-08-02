//! Stream G startup ownership — the process-wide store handle, the OS-level
//! instance lock behind it, the state every mounted handler is given, and the
//! cancellation token the HTTP server's graceful shutdown shares with Stream
//! G's background tasks.
//!
//! Before this module existed, [`super::store::StreamGStore::open`] had **zero
//! production call sites** (every hit in `src/` was inside a `mod tests`) and
//! [`super::router`] took no state, so nothing in the pipeline could be
//! mounted: a handler has nowhere to read from and a background sweeper has
//! nothing to sweep. [`StreamGState::start`] is that missing call site.
//!
//! # What `start` guarantees, and what it does not
//!
//! `start` refuses to return a state unless, in this order:
//!
//! 1. `STREAM_G_ENABLED` is true (it is a programming error to call it
//!    otherwise, not a runtime condition — see [`StreamGStartupError::Disabled`]);
//! 2. the **OS-level exclusive lock** on `STREAM_G_LOCK_PATH` is held by this
//!    process — `StreamGStore::open` takes it with `fs2::try_lock_exclusive`
//!    *before* touching SQLite, so a second attestor against the same state
//!    directory fails here instead of racing SQLite's own file locking;
//! 3. SQLite reports `journal_mode=WAL`, `foreign_keys=ON`,
//!    `synchronous=FULL` and a bounded `busy_timeout` — **read back**, not
//!    assumed from the pragma string that was executed
//!    ([`super::store::StreamGStore::verify_pragmas`]);
//! 4. every embedded migration has been applied, i.e. the file is at
//!    [`super::store::supported_schema_version`] (1 → 2 for this build);
//! 5. `STREAM_G_DATA_KEY_HEX` and `STREAM_G_QUOTE_SIGNER_PRIVATE_KEY` each
//!    parse as a 32-byte key — config validation only checks that the
//!    variables are *present* (`config::build_stream_g_config`'s `missing`
//!    list, built under `if enabled`), so a malformed key
//!    reaches this point and must fail here rather than at the first seal
//!    (data key) or at the first signed quote (quote signer);
//! 6. the deployment manifest loads, and its `chainId`/`phase` match the
//!    configured chain and `G1`;
//! 7. the fee schedule at `STREAM_G_FEE_SCHEDULE_PATH` loads, and the digest
//!    computed over its `payload` equals **both** the hash the file declares
//!    and the manifest's `feeScheduleHash`; then its `payload.chainId` and
//!    `payload.feeToken` equal the manifest's. Every quote signs
//!    `manifest.fee_schedule_hash` into its EIP-712 struct hash, so this is
//!    what stops the quote route mounting over a schedule nothing checked.
//!
//!    **Corrected 2026-07-27.** This step used to say the manifest's hash "is
//!    an opaque governance tag, so this binds the file's *declaration*, **not**
//!    its tariff amounts." That was the same false premise `models.rs` seeded
//!    and it is quoted rather than deleted so the correction stays auditable.
//!    `feeScheduleHash` is `keccak256(UTF8(RFC8785(payload)))` — the rule at
//!    the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring" spec, §8.1
//!    — so editing any tariff amount moves the digest and this step refuses.
//!    Read [`super::quotes::FeeSchedule::load`] for what is still *not*
//!    covered here (the validity window and the ceiling maps), and for why
//!    `payload.decimals` is checked on the quote path
//!    (`quotes::assert_schedule_decimals_match_live_token`) rather than in
//!    this chain-free function.
//!
//! It does **not** claim the store is healthy for the rest of the process's
//! life. Readiness (Task 8 Wave C) re-checks reachability, lock ownership,
//! schema version and key canaries per request; this is startup, not a
//! substitute for it.
//!
//! # Zero-config startup, and what it is not
//!
//! Steps 6 and 7 read two *documents*, and neither path has to be configured
//! on a fresh clone. When the variable is unset and nothing exists at the
//! default, [`read_startup_document`] substitutes the copy compiled into this
//! binary — [`BUILTIN_DEPLOYMENT_MANIFEST_JSON`] and
//! [`BUILTIN_FEE_SCHEDULE_JSON`]. Before that fallback existed, `config`
//! defaulted both paths to files under `STATE_DIR` that this repository has
//! never shipped, so `STREAM_G_ENABLED=1` on a fresh clone died at startup with
//! an IO error and CI could not run Stream G at all.
//!
//! Three limits, all deliberate and all enforced rather than documented:
//!
//! - **A path you set is never substituted for.** `config::PathSource::Env`
//!   has no fallback arm, and only `NotFound` falls through even for an unset
//!   path. A mistyped `STREAM_G_FEE_SCHEDULE_PATH` fails startup naming *your*
//!   path.
//! - **31337 only.** The built-in manifest is the anvil lab deployment. Every
//!   other `CHAIN_ID` fails the ordinary chain gate with
//!   `ManifestChainMismatch` naming both ids — a correct refusal, not an IO
//!   error, and not a fabricated deployment.
//! - **Startup is not quoting.** The built-in schedule sets no tariff, so the
//!   process starts and then refuses every quote with `MISSING_TARIFF`. Only
//!   the first of "zero-config startup" and "zero-config quoting" is
//!   achievable here: the Season-0 amounts are a founder decision that has not
//!   been taken, and any invented number would be signed verbatim into an
//!   EIP-712 `FeeQuote`. `start` warns in exactly those words.
//!
//! # Failing startup rather than failing readiness
//!
//! Spec §9.3 says startup must "fail readiness if another owner holds
//! [the lock]". This module fails **startup** instead, which is strictly
//! stronger for the condition in question and consistent with what
//! `STREAM_G_ENABLED=1` already does elsewhere: `config::build_stream_g_config`
//! already refuses to load at all when an enabled Stream G is missing one of
//! its four dedicated keys. Enabling Stream G is an explicit operator action,
//! and a process that half-runs it — routes mounted, no store behind them —
//! is worse than one that refuses to start. Readiness still exists and still
//! fails closed; it is not being replaced by this.
//!
//! # Mock mode
//!
//! `GOAT_ATTESTOR_MOCK=1` yields [`StreamGState::live_chain`] `== None`, so
//! [`StreamGState::trusted_chain`] is `None` and every Stream G live-read path
//! is simply unreachable. The field is typed `Option<Arc<RpcChain>>` — the
//! *concrete* client, not `Arc<dyn ChainClient>` — so a `MockChain` cannot be
//! placed in this state at all, in test builds or otherwise. That is the same
//! posture [`super::token_manifest::TrustedChain`] takes, and this module does
//! not weaken it. (`MockChain` itself stays un-feature-gated: `main.rs`
//! constructs it in production for the Stream B pilot.)

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rand::RngCore;
use thiserror::Error;
use tokio::sync::watch;

use crate::chain::ChainError;
use crate::config::{Config, PathSource};
use crate::rpc_chain::RpcChain;

use super::base_fee::WeiCeiling;
use super::broadcaster::BroadcastGasPolicy;
use super::crypto_store::{CryptoStoreError, DataKey, SecretHex};
use super::deployment_payload::{
    DeploymentPayload, DeploymentPayloadError, BUILTIN_DEPLOYMENT_PAYLOAD_JSON, CANONICAL_ACCOUNTS,
    CANONICAL_ROLES,
};
use super::maintenance::SWEEPER_CLAIM_OWNER;
use super::metrics::StreamGMetrics;
use super::quotes::{FeeSchedule, QuoteError, BUILTIN_FEE_SCHEDULE_JSON};
use super::rate_limit::StreamGRateLimiter;
use super::store::{self, StreamGStore, StreamGStoreError};
use super::submit::SigningLeaseRegistry;
use super::token_manifest::{
    parse_deployment_manifest, DeploymentManifest, TokenManifestError, TrustedChain,
    BUILTIN_DEPLOYMENT_MANIFEST_CHAIN_ID, BUILTIN_DEPLOYMENT_MANIFEST_JSON,
};

/// Why Stream G refused to start. Every variant is fatal: `serve-relayer`
/// propagates it instead of mounting routes over a store that isn't there.
#[derive(Debug, Error)]
pub enum StreamGStartupError {
    /// `start` was called with `STREAM_G_ENABLED=0`. Callers must check
    /// `cfg.stream_g.enabled` first; reaching this is a wiring bug, and it is
    /// an error rather than an `Ok(None)` so it cannot be ignored silently.
    #[error("stream G startup called with STREAM_G_ENABLED=0 — refusing to open the store")]
    Disabled,

    /// Includes [`StreamGStoreError::InstanceLock`] — another process (or
    /// another still-live handle) owns the Stream G lock file.
    #[error("stream G store at {path}: {source}")]
    Store {
        path: String,
        #[source]
        source: StreamGStoreError,
    },

    /// `open` applied every migration it knows about and the file still is not
    /// at this build's version. Should be unreachable; it is checked anyway so
    /// a future migration-loop regression cannot ship a half-migrated store.
    #[error("stream G schema version is {found} after migrations, expected {expected}")]
    SchemaVersion { found: i64, expected: i64 },

    /// `STREAM_G_DATA_KEY_HEX` absent even though `enabled` is true —
    /// unreachable through `config::load_from_map`, kept so this module does
    /// not depend on that invariant holding forever.
    #[error("STREAM_G_DATA_KEY_HEX missing while STREAM_G_ENABLED=1")]
    MissingDataKey,

    /// The data key is present but not 32 bytes of hex. Config only checks
    /// presence, so this is the first place a malformed key is rejected.
    #[error("STREAM_G_DATA_KEY_HEX: {0}")]
    DataKey(#[from] CryptoStoreError),

    /// `STREAM_G_QUOTE_SIGNER_PRIVATE_KEY` absent even though `enabled` is
    /// true. Unreachable through `config::load_from_map` —
    /// `config::build_stream_g_config` pushes it onto the same `missing` list
    /// `STREAM_G_DATA_KEY_HEX` is on —
    /// and kept for the same reason [`StreamGStartupError::MissingDataKey`] is:
    /// so this module does not depend on that invariant holding forever.
    #[error("STREAM_G_QUOTE_SIGNER_PRIVATE_KEY missing while STREAM_G_ENABLED=1")]
    MissingQuoteSignerKey,

    /// The quote signer key is present but is not 32 bytes of hex, i.e. not a
    /// secp256k1 private key. Fatal for the same reason
    /// [`StreamGStartupError::FeeSchedule`] is: a process that cannot produce
    /// the signature a quote *is* must not mount the quote route and discover
    /// that at `quotes::create_sponsored_enrollment_quote_at`'s STEP 8
    /// (`PrivateKeySigner::from_str`), one request into production.
    ///
    /// Not `#[from]`: [`StreamGStartupError::DataKey`] already owns the
    /// `From<CryptoStoreError>` impl, and two `#[from]`s on the same source
    /// type would not compile. The call site maps explicitly, which is also
    /// what keeps the two variants' messages naming the right variable.
    #[error("STREAM_G_QUOTE_SIGNER_PRIVATE_KEY: {0}")]
    QuoteSignerKey(#[source] CryptoStoreError),

    #[error("stream G deployment manifest at {path}: {source}")]
    Manifest {
        path: String,
        #[source]
        source: TokenManifestError,
    },

    /// The deployment payload at `STREAM_G_DEPLOYMENT_PAYLOAD_PATH` is missing
    /// or malformed. Fatal: `deploymentManifestHash` is a field of every
    /// EIP-712 action core, intent and `FeeQuote`, so a process that cannot
    /// read the document that value is the digest **of** cannot attest to
    /// anything about this deployment.
    #[error("stream G deployment payload at {path}: {source}")]
    DeploymentPayload {
        path: String,
        #[source]
        source: DeploymentPayloadError,
    },

    /// The payload file's own `payload` does not hash to the
    /// `deploymentManifestHash` the file declares.
    ///
    /// A *file* fault, not a deployment fault: someone edited an address or a
    /// runtime code hash and left the declaration alone — or, far more often on
    /// a lab tree, a contract changed, `forge test` rewrote the payload with a
    /// new code hash, and the pinned constant in `DeployStreamG.t.sol` was not
    /// recomputed. Kept separate from
    /// [`StreamGStartupError::DeploymentManifestHashMismatch`] because the fix
    /// is different: here the operator must decide whether the edit or the
    /// declaration is the mistake, and only then whether anything needs
    /// republishing on chain.
    #[error(
        "stream G deployment payload at {path}: its payload hashes to 0x{computed}, but the file \
         declares deploymentManifestHash 0x{declared} — the payload was edited without \
         republishing the hash. Either restore the approved payload, or, if these ARE the \
         approved addresses and code hashes, set deploymentManifestHash to 0x{computed} and \
         republish that same value on-chain as STREAM_G_DEPLOYMENT_MANIFEST_HASH (a Policy Safe \
         FeeTokenRegistry.setActiveManifestHash transaction against a live deployment) before \
         restarting"
    )]
    DeploymentManifestHashSelfMismatch {
        path: String,
        computed: String,
        declared: String,
    },

    /// `STREAM_G_DEPLOYMENT_MANIFEST_PATH` names a real deployment manifest,
    /// but `STREAM_G_DEPLOYMENT_PAYLOAD_PATH` was not set (and nothing exists at
    /// its default), so the payload silently fell through to the BUILT-IN 31337
    /// lab document compiled into this binary.
    ///
    /// **Why this is its own variant rather than a warning.** The built-in
    /// payload is a complete, internally consistent, correctly signed-looking
    /// document — for anvil. Against any real manifest the next check to fire
    /// was `DeploymentManifestHashMismatch`, whose message is "this deployment
    /// did not publish this payload": true, and a straight lie about the cause.
    /// The operator's fault is a missing environment variable, and no message on
    /// the old path named it. Compare the deploy side, which has always been
    /// blunt about this — `vm.envBytes32("STREAM_G_DEPLOYMENT_MANIFEST_HASH")`
    /// with no default, so the deploy aborts naming the variable.
    ///
    /// Both-built-in is still allowed: that is the zero-config lab path, and a
    /// built-in manifest is refused for any chain but 31337 by
    /// `parse_deployment_manifest` several steps earlier.
    #[error(
        "stream G deployment payload: the deployment manifest was loaded from {manifest_path}, \
         but STREAM_G_DEPLOYMENT_PAYLOAD_PATH is unset and nothing exists at the default \
         ({configured_path}), so the BUILT-IN 31337 anvil lab payload would have been used \
         against a manifest that is not the built-in one. Refusing to start: set \
         STREAM_G_DEPLOYMENT_PAYLOAD_PATH to this deployment's payload document (the file \
         DeployStreamG writes beside the manifest, 31337.stream-g.payload.json), or unset \
         STREAM_G_DEPLOYMENT_MANIFEST_PATH to run the built-in lab pair"
    )]
    DeploymentPayloadNotConfigured {
        manifest_path: String,
        configured_path: String,
    },

    /// The payload file is internally consistent, but its digest is not the one
    /// this deployment published.
    ///
    /// **Fail-closed and deliberately unrecoverable at runtime.** The
    /// alternative — mount anyway and let every quote and every action core
    /// sign `manifest.deployment_manifest_hash` over a deployment whose
    /// addresses nobody checked — is precisely the
    /// attestation-without-validation hole this variant exists to close.
    #[error(
        "stream G deployment payload at {path}: its payload hashes to 0x{computed}, but the \
         deployment manifest carries deploymentManifestHash 0x{manifest} — this deployment did \
         not publish this payload. Refusing to start rather than sign intents and quotes \
         attesting to a deployment the manifest never approved"
    )]
    DeploymentManifestHashMismatch {
        path: String,
        computed: String,
        manifest: String,
    },

    /// The payload file is internally consistent AND published, but was
    /// authored for a different chain.
    ///
    /// Reachable for exactly the reason
    /// [`StreamGStartupError::FeeScheduleChainMismatch`] is: a digest binds a
    /// payload to itself and to whatever the operator republished, never to a
    /// deployment it does not name. Copying a working configuration between
    /// deployments is one `forge script` run away.
    #[error(
        "stream G deployment payload at {path}: its payload declares chainId \
         {payload_chain_id}, but this deployment's manifest is chainId {manifest_chain_id} — \
         this payload was authored for another chain. Its digest matches only because it was \
         republished here; a digest binds a payload to itself, not to a deployment"
    )]
    DeploymentManifestChainMismatch {
        path: String,
        payload_chain_id: u128,
        manifest_chain_id: u64,
    },

    /// The payload file is internally consistent, published, and on the right
    /// chain, but one of the four committed roles names a different address
    /// than the deployment manifest does.
    ///
    /// **This is the variant that closes the stated hazard from the ARTIFACT
    /// side, and it is not redundant with the two digest checks.** A digest
    /// binds a payload to itself: editing `goatRelayGateway` in the flat
    /// `31337.stream-g.json` moves nothing the payload hashes, so without this
    /// comparison a drifted artifact address would start cleanly and every
    /// quote would be signed against a gateway the payload never committed to.
    /// The digest checks catch an edit to the payload; this catches an edit to
    /// the manifest.
    #[error(
        "stream G deployment payload at {path}: role {role} names address 0x{payload_address}, \
         but the deployment manifest names 0x{manifest_address} for the same role. The digest \
         binds the payload to itself, not to the manifest — these are two documents describing \
         one deployment and they disagree. Refusing to start rather than sign quotes naming an \
         address this deployment never committed"
    )]
    DeploymentManifestAddressMismatch {
        path: String,
        role: &'static str,
        payload_address: String,
        manifest_address: String,
    },

    /// The fee schedule at `STREAM_G_FEE_SCHEDULE_PATH` is missing or
    /// malformed. Fatal: a quote signs an attestation about a fee schedule
    /// (`models::fee_quote_struct_hash`), so a process that cannot read one
    /// must not mount the quote route.
    #[error("stream G fee schedule at {path}: {source}")]
    FeeSchedule {
        path: String,
        #[source]
        source: QuoteError,
    },

    /// The schedule file's own payload does not hash to the `feeScheduleHash`
    /// the file declares.
    ///
    /// A *file* fault, not a deployment fault: someone edited a tariff, a
    /// ceiling or the validity window and left the declared hash alone. Kept
    /// separate from [`StreamGStartupError::FeeScheduleHashMismatch`] because
    /// the fix is different — here the operator must decide whether the edit or
    /// the declaration is the mistake, and only then whether anything needs
    /// republishing on-chain.
    #[error(
        "stream G fee schedule at {path}: its payload hashes to 0x{computed}, but the file \
         declares feeScheduleHash 0x{declared} — the payload was edited without republishing \
         the hash. Either restore the approved payload, or, if these ARE the approved values, \
         set feeScheduleHash to 0x{computed} and republish that same value on-chain as \
         STREAM_G_FEE_SCHEDULE_HASH before restarting"
    )]
    FeeScheduleHashSelfMismatch {
        path: String,
        computed: String,
        declared: String,
    },

    /// The schedule file is internally consistent, but its payload is not the
    /// one this deployment published — most often a schedule file left behind
    /// across a manifest republish, or a payload written for another chain.
    ///
    /// **Fail-closed and deliberately unrecoverable at runtime.** The
    /// alternative — mount anyway and let the quote route sign
    /// `manifest.fee_schedule_hash` over tariffs from a file published for
    /// some other deployment — is precisely the attestation-without-validation
    /// hole this variant exists to close.
    #[error(
        "stream G fee schedule at {path}: its payload hashes to 0x{computed}, but the \
         deployment manifest carries feeScheduleHash 0x{manifest} — this deployment did not \
         publish this schedule. Refusing to start rather than sign quotes attesting to a \
         schedule the deployment never approved"
    )]
    FeeScheduleHashMismatch {
        path: String,
        computed: String,
        manifest: String,
    },

    /// The schedule file is internally consistent AND its digest is the one
    /// this deployment published, but the payload was authored for a different
    /// chain.
    ///
    /// **Why this is reachable at all, given the two digest checks above.** A
    /// digest binds a payload to itself and to whatever the operator
    /// republished — nothing more. An auditor built this binary and started it
    /// with a payload declaring `chainId "8453"` whose digest was written into
    /// both the schedule file and a `chainId 31337` manifest: it started
    /// cleanly and served prices. Republishing a foreign schedule is one
    /// deploy-script run away, and it is exactly what an operator does when
    /// copying a working configuration between deployments.
    ///
    /// Separate from [`StreamGStartupError::FeeScheduleHashMismatch`] because
    /// the fix is the opposite one: there the operator must republish the
    /// digest; here republishing is what *caused* the fault, and the schedule
    /// itself is the wrong document.
    #[error(
        "stream G fee schedule at {path}: its payload declares chainId {payload_chain_id}, but \
         this deployment's manifest is chainId {manifest_chain_id} — this schedule was authored \
         for another chain. Its digest matches only because it was republished here; a digest \
         binds a payload to itself, not to a deployment. Supply the schedule approved for chain \
         {manifest_chain_id} (and republish ITS digest as STREAM_G_FEE_SCHEDULE_HASH) rather \
         than serving amounts denominated for chain {payload_chain_id}"
    )]
    FeeScheduleChainMismatch {
        path: String,
        payload_chain_id: u128,
        manifest_chain_id: u64,
    },

    /// The schedule file is internally consistent, published, and on the right
    /// chain, but its `feeToken` is not the token this deployment charges in.
    ///
    /// The harm is that nothing downstream would notice: the signed
    /// `FeeQuote` takes its `feeToken` from the MANIFEST
    /// (`models::fee_quote_struct_hash`), so the amounts from a schedule
    /// written for some other token would be charged in this deployment's
    /// token, at that token's decimals. Both addresses are rendered lowercase
    /// hex here; the comparison is over decoded bytes, so a checksummed
    /// manifest spelling of the same address is not a mismatch.
    #[error(
        "stream G fee schedule at {path}: its payload declares feeToken 0x{payload_fee_token}, \
         but this deployment's manifest carries feeToken 0x{manifest_fee_token} — this schedule \
         prices a different token. Its digest matches only because it was republished here. \
         Every quote signs the MANIFEST's feeToken, so serving these amounts would charge them \
         in 0x{manifest_fee_token} at that token's decimals"
    )]
    FeeScheduleFeeTokenMismatch {
        path: String,
        payload_fee_token: String,
        manifest_fee_token: String,
    },

    #[error("stream G live chain client: {0}")]
    Chain(#[from] ChainError),
}

/// Which bytes [`StreamGState::start`] actually read a startup document from.
///
/// Carried into the startup log so an operator never has to infer it. "It
/// started, so it must have found my file" is exactly the inference the
/// built-in fallback makes unsafe, and a log line that named only a path would
/// invite it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupDocumentSource {
    /// A real file on disk, at the resolved path.
    File,
    /// The copy compiled into this binary — reached only when the path was
    /// **not** configured and nothing existed at the default.
    Builtin,
}

impl StartupDocumentSource {
    /// The word the startup log uses. Deliberately not `Display` on a path:
    /// the point of the field is to be greppable and unambiguous.
    fn as_str(self) -> &'static str {
        match self {
            StartupDocumentSource::File => "file",
            StartupDocumentSource::Builtin => "built-in",
        }
    }
}

/// What error messages call the embedded fee schedule. Not a path: nothing
/// opens it, and an operator who greps for this string should land on
/// [`BUILTIN_FEE_SCHEDULE_JSON`]'s doc rather than go looking on disk.
const BUILTIN_FEE_SCHEDULE_LABEL: &str =
    "<built-in fee schedule (fixtures/stream_g_fee_schedule.json)>";

/// What error messages call the embedded deployment manifest — see
/// [`BUILTIN_FEE_SCHEDULE_LABEL`].
const BUILTIN_MANIFEST_LABEL: &str =
    "<built-in deployment manifest (fixtures/31337.stream-g.json)>";

/// What error messages call the embedded deployment payload — see
/// [`BUILTIN_FEE_SCHEDULE_LABEL`].
const BUILTIN_DEPLOYMENT_PAYLOAD_LABEL: &str =
    "<built-in deployment payload (fixtures/stream_g_deployment_payload.json)>";

/// Resolve one Stream G startup document to bytes, falling back to `builtin`
/// **only** when nobody chose the path and nothing is there.
///
/// # Why the fallback exists at all
///
/// `config::build_stream_g_config` defaults both
/// `STREAM_G_FEE_SCHEDULE_PATH` and `STREAM_G_DEPLOYMENT_MANIFEST_PATH` to
/// files under `STATE_DIR` that this repository has never shipped
/// (`config.rs`'s `default_fee_schedule` / `default_manifest`). A fresh clone
/// with `STREAM_G_ENABLED=1` therefore failed at *startup*, on an IO error,
/// before Stream G could refuse anything on its merits — so CI and local dev
/// could not exercise Stream G at all without hand-wiring two paths that only
/// one committed value each was ever correct for.
///
/// # The two rules that make it safe
///
/// 1. **[`PathSource::Env`] never falls back.** If the operator set the
///    variable, the named file is read or startup fails. Substituting a
///    built-in for a mistyped path would start the process against a document
///    nobody selected, which is worse than the outage it would be papering
///    over. Pinned by
///    `tests::start_refuses_an_explicitly_configured_but_missing_fee_schedule`
///    and its manifest twin.
/// 2. **Only [`std::io::ErrorKind::NotFound`] falls back**, and only under
///    [`PathSource::Default`]. A permission error, or a directory where a file
///    was expected, is a real fault at a real path and is reported as one — a
///    fallback that swallowed those would hide a broken deployment behind a
///    working-looking start.
///
/// Returns the bytes, which source supplied them, and the label to name in any
/// later error about the document's *contents*.
fn read_startup_document(
    path: &Path,
    source: PathSource,
    builtin: &'static str,
    builtin_label: &'static str,
) -> Result<(String, StartupDocumentSource, String), String> {
    let read_file = || {
        std::fs::read_to_string(path)
            .map(|raw| (raw, StartupDocumentSource::File, path.display().to_string()))
    };
    match source {
        PathSource::Env => read_file().map_err(|e| e.to_string()),
        PathSource::Default => match read_file() {
            Ok(found) => Ok(found),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((
                builtin.to_string(),
                StartupDocumentSource::Builtin,
                builtin_label.to_string(),
            )),
            Err(e) => Err(e.to_string()),
        },
    }
}

/// Cancellation shared by the HTTP server's graceful shutdown and every Stream
/// G background task (Task 8 Wave D's sweeper and `prune_expired` loop).
///
/// A `tokio::sync::watch` rather than `tokio_util::sync::CancellationToken`
/// so this needs no new dependency: `watch` is already enabled by the crate's
/// `tokio` features, and latched-boolean semantics are all a shutdown token
/// needs. Cloneable, and every clone shares one latch.
#[derive(Clone, Debug)]
pub struct ShutdownController {
    /// `Arc` because `watch::Sender` is not `Clone`, and the signal task needs
    /// its own handle while `serve-relayer` keeps one for the whole serve.
    tx: Arc<watch::Sender<bool>>,
}

impl ShutdownController {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self { tx: Arc::new(tx) }
    }

    /// A token observing this controller. Tokens may be taken before or after
    /// [`cancel`](Self::cancel) — one taken afterwards observes the latched
    /// `true` immediately.
    pub fn token(&self) -> ShutdownToken {
        ShutdownToken {
            rx: self.tx.subscribe(),
        }
    }

    /// Latch cancellation. Idempotent.
    ///
    /// `send_replace`, not `send`: `send` reports `Err` when no receiver is
    /// currently alive **and the value would go unobserved**, which would make
    /// cancelling before any token is taken a silent no-op. `send_replace`
    /// always stores the value, so a token taken later still sees it.
    pub fn cancel(&self) {
        self.tx.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.tx.borrow()
    }
}

impl Default for ShutdownController {
    fn default() -> Self {
        Self::new()
    }
}

/// Observer half of [`ShutdownController`].
#[derive(Clone, Debug)]
pub struct ShutdownToken {
    rx: watch::Receiver<bool>,
}

impl ShutdownToken {
    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves once cancellation is latched, immediately if it already was.
    ///
    /// Takes `&self` and clones the receiver internally so one token can be
    /// awaited from several places. If every [`ShutdownController`] has been
    /// dropped this also resolves: nothing can cancel the token any more and
    /// its owner is gone, so a background task that waited on it would hang
    /// forever. Resolving is the fail-safe direction for a *shutdown* signal.
    pub async fn cancelled(&self) {
        let mut rx = self.rx.clone();
        if *rx.borrow_and_update() {
            return;
        }
        while rx.changed().await.is_ok() {
            if *rx.borrow_and_update() {
                return;
            }
        }
    }
}

/// Which `axum::serve` shape `goat-attestor serve-relayer` uses.
///
/// This lives in the library, and is a type rather than an inline `if`,
/// **specifically so the pilot-safety invariant is a test rather than a
/// code-reading exercise**. `.with_graceful_shutdown(..)` changes how the
/// Stream B pilot's HTTP server terminates, so it must be installed only when
/// Stream G is enabled; with Stream G off, `main.rs` must run the identical
/// `axum::serve(listener, app).await` expression it ran before Task 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeMode {
    /// `axum::serve(listener, app).await` — byte-for-byte the pilot's
    /// pre-Task-8 call, no signal handler installed anywhere in the process.
    PilotPlain,
    /// `axum::serve(listener, app).with_graceful_shutdown(token).await`.
    StreamGGraceful,
}

impl ServeMode {
    pub fn for_config(cfg: &Config) -> Self {
        if cfg.stream_g.enabled {
            Self::StreamGGraceful
        } else {
            Self::PilotPlain
        }
    }

    pub fn installs_graceful_shutdown(self) -> bool {
        matches!(self, Self::StreamGGraceful)
    }
}

/// Resolves on the first OS request to terminate: Ctrl-C everywhere, plus
/// `SIGTERM` on unix (what `docker stop` and systemd send).
///
/// If a handler cannot be installed this future stays **pending forever**
/// rather than resolving. An un-installable handler must degrade to today's
/// behaviour (no graceful shutdown — the process dies on the OS default
/// action), never to an immediate shutdown of a server that was asked to run.
pub async fn terminate_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c_or_pending() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "stream_g shutdown: SIGTERM handler unavailable; Ctrl-C only"
                );
                ctrl_c_or_pending().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c_or_pending().await;
    }
}

async fn ctrl_c_or_pending() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!(
            error = %e,
            "stream_g shutdown: Ctrl-C handler unavailable; graceful shutdown will never be \
             signalled (the process will terminate on the OS default action instead)"
        );
        std::future::pending::<()>().await
    }
}

/// Everything a mounted Stream G handler is allowed to reach: the single
/// locked store, the at-rest data key, the deployment manifest, the live chain
/// client (when there is one), and the shutdown token.
///
/// `Clone` is an `Arc` bump — axum clones the state per request, and cloning
/// the store or the key would be wrong (two `StreamGStore` values would mean
/// two pools, and the whole point is one).
#[derive(Clone)]
pub struct StreamGState {
    inner: Arc<Inner>,
}

struct Inner {
    store: StreamGStore,
    data_key: DataKey,
    /// The **same** key as `data_key`, in the hex form
    /// `profile_auth::derive_domain_key` requires (it feeds raw bytes to
    /// `HmacSha256` and so cannot take a `DataKey`, which has no accessor).
    ///
    /// Before Task 11 Wave 0 `start` parsed the hex into `data_key` and
    /// dropped it, so every `profile_auth` / `outbox` / `submit` entry point —
    /// all of which take the hex — was unreachable from a handler. Held as
    /// [`SecretHex`], not `String`: zeroized on drop, redacted `Debug`,
    /// validated at construction.
    data_key_hex: SecretHex,
    /// `STREAM_G_QUOTE_SIGNER_PRIVATE_KEY` — the secp256k1 key every fee quote
    /// is signed with.
    ///
    /// The same gap `data_key_hex` closed, one field over:
    /// `models::EnrollmentQuoteContext::quote_signer_private_key_hex` is a
    /// **mandatory** field consumed at
    /// `quotes::create_sponsored_enrollment_quote_at`'s STEP 8, config both
    /// validates its presence (`config::build_stream_g_config`'s `missing`
    /// list) and stores it (`config::StreamGConfig::quote_signer_private_key`),
    /// and yet `Inner` had no field and no accessor — so the
    /// quote route could not be mounted at all without reaching around this
    /// state into `Config`.
    ///
    /// Held as [`SecretHex`] rather than the bare `String` config keeps, for
    /// the three properties that type exists for: zeroized on drop, redacted
    /// `Debug`, and an invalid key cannot be represented (`SecretHex::from_hex`
    /// runs `DataKey::from_hex`'s own 32-byte validation).
    ///
    /// ⚠️ **Stored with any `0x` prefix removed** — see [`StreamGState::start`]
    /// for why the normalization is there and not in `SecretHex`.
    quote_signer_key_hex: SecretHex,
    manifest: DeploymentManifest,
    /// `STREAM_G_MAX_NATIVE_EXPOSURE_WEI`, as the newtype `base_fee`'s gates
    /// already take. Wrapped here rather than at each call site so a route
    /// cannot pass some other `u128` that happens to be in scope.
    ///
    /// ⚠️ **The config default is `0`**, and `WeiCeiling::new(0)` fails every
    /// exposure check. That is fail-closed, which is right, but it presents to
    /// an operator who simply never set the variable as a total outage rather
    /// than as a misconfiguration — exactly the hazard `submit.rs`'s
    /// `SubmitContext::max_native_exposure_wei` doc calls out. Wave 0 makes the
    /// value *reachable*; surfacing an unset ceiling as a distinct operator
    /// error is the mounting wave's job and is NOT done here.
    max_native_exposure_wei: WeiCeiling,
    /// The tariff table, loaded once at startup and bound to the manifest's
    /// `feeScheduleHash` — see [`StreamGState::start`]. Loaded here rather than
    /// per request so a schedule that does not match the deployment can never
    /// reach a signer: before Task 11 Wave 0 nothing in production loaded a
    /// schedule at all.
    ///
    /// ⚠️ The loader `start` calls is [`FeeSchedule::from_json`], not
    /// [`FeeSchedule::load`] — `start` resolves the bytes through
    /// [`read_startup_document`] first, because the document may be the
    /// built-in copy and not a file. [`FeeSchedule::load`] is the
    /// path-taking wrapper around the same parser and still has **zero**
    /// production call sites; a maintainer adding a startup check must add it
    /// to `start` or to `from_json`, never to `load`.
    fee_schedule: FeeSchedule,
    /// Where `fee_schedule` was read from. Carried for operator-facing
    /// diagnostics only; nothing re-reads it.
    ///
    /// A `String`, not a `PathBuf`, because it is not always a path: when the
    /// built-in schedule was used it holds `BUILTIN_FEE_SCHEDULE_LABEL`. The
    /// weaker type is the point — a `PathBuf` here would invite a future
    /// caller to open a file that does not exist.
    fee_schedule_origin: String,
    /// `None` in mock mode. Concrete `RpcChain`, never `dyn ChainClient` —
    /// see the module doc.
    chain: Option<Arc<RpcChain>>,
    shutdown: ShutdownToken,
    /// The lock file the store's `fs2` handle owns. Carried because readiness
    /// (Wave C) re-probes it per request — a lock taken at startup is not
    /// evidence it is still held minutes later.
    lock_path: PathBuf,
    /// `STREAM_G_CORS_ORIGINS`, verbatim. **Stream G's own allowlist**: it is
    /// never unioned with `relayer::default_cors_origins`, and empty (the
    /// default) means no cross-origin request is allowed at all. See
    /// [`super::stream_g_cors_layer`].
    cors_origins: Vec<String>,
    metrics: Arc<StreamGMetrics>,
    /// Stream G's own rate limiter (Task 11 Wave 1). One per process, shared
    /// across every cloned `StreamGState` because axum clones the state per
    /// request and a per-request limiter would bound nothing.
    ///
    /// ⚠️ **Eight of the ten mounted routes consult it**: the five under
    /// `/v1/profile/` and, since the pipeline surface was mounted, `POST
    /// /v1/stream-g/quotes`, `POST /v1/stream-g/submit` (Wave C W4) and
    /// `GET /v1/stream-g/status/:intentId`. Only the
    /// two `/v1/stream-g/` *operational* routes (`ready`, `metrics`) do not.
    /// See `super::rate_limit`'s module doc, which says the same thing where a
    /// reader of that module will see it.
    ///
    /// `std::sync::Mutex`, not `tokio::sync::Mutex`: every operation is a
    /// couple of float comparisons and a hash lookup, with no `.await` inside
    /// the guard, which is exactly the case the std mutex is for. Same choice
    /// the pilot makes (`relayer::AppState::rate`).
    rate_limiter: Arc<Mutex<StreamGRateLimiter>>,
    /// The **one** [`SigningLeaseRegistry`] in this process (Wave C W1a).
    ///
    /// ⚠️ **One instance, or the guarantee is silently void.** The registry's
    /// `held` set is an inherent field, not shared state behind a global, so
    /// two registries in one process can never observe each other's keys: both
    /// tasks would pass `try_acquire` for the same action nonce, both would
    /// sign, and the only surviving catch would be the durable reservation —
    /// after the chain reads the lease exists to save. A per-request
    /// `SigningLeaseRegistry::new()` compiles and passes every existing test
    /// while deleting the single-signer property, because `try_acquire` can
    /// never collide across requests. That is why this is a field on `Inner`
    /// (which every `StreamGState` clone shares through one `Arc`) and not a
    /// by-value field on the outer `#[derive(Clone)]` struct, which would be
    /// exactly that bug.
    ///
    /// Held as `Arc<..>` for the same reason [`Inner::metrics`] and
    /// [`Inner::rate_limiter`] are: it is process-wide shared state whose
    /// identity, not just whose value, matters.
    ///
    /// Deliberately **process-local**, as its own type doc says. Two
    /// `goat-attestor` processes do not share it — and note that the argument
    /// that type doc gives for why that is safe is weaker than it looks: the
    /// `fs2` lock `StreamGStore::open` takes is on the *dedicated lock file*
    /// named by `STREAM_G_LOCK_PATH`, which `config::build_stream_g_config`
    /// resolves **independently of** `STREAM_G_DB_PATH`. Two processes pointed
    /// at one database with different lock paths do share the store. The
    /// durable `nonce_allocations` row, not this registry, is what covers that
    /// case.
    leases: Arc<SigningLeaseRegistry>,
    /// This process's outbox CAS identity (Wave C W1b) — the string
    /// `tx_attempts.claim_owner` is stamped with by every reserve/release/
    /// record the submit path performs.
    ///
    /// Minted once by [`mint_submit_claim_owner`] at [`StreamGState::start`]
    /// and never recomputed, because `outbox`'s compare-and-swaps require the
    /// value that reserved a row to be byte-identical to the value that later
    /// releases or records against it. Read the minting function for the
    /// format, for why the entropy is a fresh per-process UUID rather than the
    /// store's `db_uuid`, and for what the hostname segment is and is not.
    claim_owner: String,
    /// `STREAM_G_BROADCAST_GAS_LIMIT` / `..._MAX_FEE_PER_GAS_WEI` /
    /// `..._MAX_PRIORITY_FEE_PER_GAS_WEI`, already validated together by
    /// `config::build_broadcast_gas_policy` (Wave C W1c).
    ///
    /// 🔴 **The defaults are starting values that still need founder review**
    /// — see [`BroadcastGasPolicy`]'s type doc, which is where the three
    /// figures and the evidence for each of them live. Carrying the policy
    /// here changes only where it is *read from*; it makes no claim that any
    /// of the three has been measured against a live
    /// `executeSponsoredEnrollment`.
    ///
    /// `Copy`, so the accessor hands out a value rather than a borrow — the
    /// policy is three integers and a caller needs to move it into
    /// `RpcChainEnrollmentSigner::new`.
    broadcast_gas: BroadcastGasPolicy,
}

/// Manual: neither [`StreamGStore`] nor a private key belongs in a log line.
/// Prints only non-secret identifiers — `DataKey`'s own `Debug` is already
/// redacted, and `key_id` is a hash prefix, safe to print by construction.
impl std::fmt::Debug for StreamGState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamGState")
            .field("db_uuid", &self.inner.store.db_uuid())
            .field("schema_version", &self.inner.store.schema_version())
            .field("data_key_id", &self.inner.data_key.key_id())
            .field("manifest_chain_id", &self.inner.manifest.chain_id)
            .field("live_chain", &self.inner.chain.is_some())
            .field("shutdown_cancelled", &self.inner.shutdown.is_cancelled())
            .finish()
    }
}

/// Prefix every submit-path `claim_owner` carries. Distinct from
/// [`SWEEPER_CLAIM_OWNER`] by construction, and asserted to be at mint time —
/// the two must never collide, because the sweeper's release CAS matches on
/// `claim_owner` and a submit row wearing the sweeper's name would be
/// releasable by a pass that never reserved it.
pub const SUBMIT_CLAIM_OWNER_PREFIX: &str = "stream-g:submit";

/// Environment variables consulted for the hostname segment, in order. See
/// [`mint_submit_claim_owner`] for why an env read (rather than a syscall
/// through a new dependency) is adequate *for this segment specifically*.
const HOSTNAME_ENV_KEYS: &[&str] = &["HOSTNAME", "COMPUTERNAME"];

/// Placeholder used when no hostname is discoverable. A literal, not an empty
/// string, so the format stays five colon-separated segments and a log line
/// reads as "unknown host" rather than as a truncated identifier.
const UNKNOWN_HOSTNAME: &str = "unknown";

/// Keep a hostname to something that cannot disturb the format or a log line:
/// ASCII alphanumerics, `-`, `_` and `.` survive; everything else (notably
/// `:`, which is the field separator) becomes `_`. Bounded to 32 characters
/// because this segment is a label and a pathological `HOSTNAME` should not be
/// able to grow every `tx_attempts` row.
fn sanitize_hostname_segment(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    if cleaned.is_empty() {
        UNKNOWN_HOSTNAME.to_string()
    } else {
        cleaned
    }
}

/// Mint this process's outbox CAS identity:
/// `stream-g:submit:<host>:<pid>:<32 hex>`.
///
/// # What each segment is for, and which one actually does the work
///
/// * **`<uuid>`** — 16 bytes from `rand::thread_rng()`, hex-encoded. This is
///   the **only** segment that establishes uniqueness, and it establishes it
///   on its own. Minted fresh at every process start.
/// * **`<pid>`** — `std::process::id()`. Diagnostic: it is what an operator
///   greps for when correlating a stuck row with a running process.
/// * **`<host>`** — diagnostic, see below. Contributes nothing to uniqueness.
///
/// # Why the entropy is a fresh UUID and not the store's `db_uuid`
///
/// `StreamGStore::db_uuid` is minted **per database file** and then persisted,
/// so two processes opened against one database derive an identical owner *by
/// construction* — the precise collision this identity exists to prevent.
/// `hostname:pid` alone fails the same way in a container: Docker and
/// Kubernetes hand out defaulted hostnames and run the entrypoint as pid 1, so
/// two replicas sharing a mounted state directory would agree on both
/// segments. Only a per-process-start random value separates them.
///
/// # The high-entropy primitive is the crate's existing one
///
/// `rand::thread_rng().fill_bytes(&mut [0u8; 16])` then `hex::encode` — the
/// same four lines `StreamGStore::open` uses to mint `db_uuid`, and the same
/// pattern `crypto_store`, `onboarding` and `profile_auth` already use. No new
/// dependency was added, and none was needed: `rand = "0.8"` and `hex = "0.4"`
/// are already direct dependencies of this crate.
///
/// # ⚠️ The hostname segment is an env read, and that is a deliberate
/// limitation
///
/// This crate has **no** hostname primitive — no `gethostname`, `whoami` or
/// `uuid` in its `Cargo.toml` — and the standard library exposes none. Rather
/// than take a new supply-chain dependency for a label, this reads `HOSTNAME`
/// (which container runtimes set) then `COMPUTERNAME` (which Windows always
/// sets), and falls back to [`UNKNOWN_HOSTNAME`].
///
/// An environment variable is **spoofable and not always present**, so this
/// segment must never be treated as evidence of anything. It is safe *here*
/// precisely because it carries no weight: uniqueness comes from the UUID
/// alone, and even a process that renders `unknown` for its host is fully
/// distinguished. A caller who ever needs a trustworthy host identity must add
/// a real syscall-backed dependency; that is a separate decision, not this
/// function's to make silently.
///
/// # What `claim_owner` is NOT
///
/// It is not a security boundary. `outbox::sweep_stuck_reservations`' claim
/// CAS carries **no `claim_owner` predicate on either side** — it matches on
/// `id`, `status` and an expired `lease_until` — so it steals an expired lease
/// regardless of who holds it. Recovery is owner-blind by design, which is
/// also why cross-restart stability of this string is not required.
pub fn mint_submit_claim_owner() -> String {
    let host = HOSTNAME_ENV_KEYS
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .map(|raw| sanitize_hostname_segment(&raw))
        .unwrap_or_else(|| UNKNOWN_HOSTNAME.to_string());

    let mut instance_uuid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut instance_uuid);

    let owner = format!(
        "{SUBMIT_CLAIM_OWNER_PREFIX}:{host}:{}:{}",
        std::process::id(),
        hex::encode(instance_uuid)
    );

    // Cheap, unconditional, and the one property the outbox actually depends
    // on. `SUBMIT_CLAIM_OWNER_PREFIX` and `SWEEPER_CLAIM_OWNER` are two
    // literals in two modules; nothing but this stops a future edit from
    // making them agree.
    assert_ne!(
        owner, SWEEPER_CLAIM_OWNER,
        "the submit claim owner must never equal the sweeper's"
    );
    assert!(
        !owner.starts_with(SWEEPER_CLAIM_OWNER),
        "the submit claim owner must not be a refinement of the sweeper's"
    );
    owner
}

impl StreamGState {
    /// Open the store (taking the instance lock), verify its pragmas and
    /// schema version, parse the data key, load the manifest, and build the
    /// live chain client. See the module doc for the ordered guarantees and
    /// for why this fails startup rather than only readiness.
    pub async fn start(cfg: &Config, shutdown: ShutdownToken) -> Result<Self, StreamGStartupError> {
        if !cfg.stream_g.enabled {
            return Err(StreamGStartupError::Disabled);
        }

        let db_path = &cfg.stream_g.db_path;
        let lock_path = &cfg.stream_g.lock_path;

        // Takes the fs2 exclusive lock on `lock_path` before touching SQLite,
        // then applies migrations 1..=SCHEMA_VERSION.
        let store = StreamGStore::open(db_path, lock_path)
            .await
            .map_err(|source| StreamGStartupError::Store {
                path: db_path.display().to_string(),
                source,
            })?;

        let pragmas =
            store
                .verify_pragmas()
                .await
                .map_err(|source| StreamGStartupError::Store {
                    path: db_path.display().to_string(),
                    source,
                })?;

        let found = i64::from(store.schema_version());
        let expected = store::supported_schema_version();
        if found != expected {
            return Err(StreamGStartupError::SchemaVersion { found, expected });
        }

        let data_key_hex = SecretHex::from_hex(
            cfg.stream_g
                .data_key_hex
                .as_deref()
                .ok_or(StreamGStartupError::MissingDataKey)?,
        )?;
        // Infallible: `SecretHex` already ran the identical validation.
        let data_key = DataKey::from_secret(&data_key_hex);

        // The quote signer key takes the same treatment, with one difference
        // that is a fact about the two variables rather than a choice:
        // `STREAM_G_DATA_KEY_HEX` is documented as bare hex (its
        // `.env.example` line reads `...  # 64 hex chars (32 bytes) exactly`)
        // while `STREAM_G_QUOTE_SIGNER_PRIVATE_KEY` is an EVM private key and
        // is written `0x…` (that variable's own `.env.example` line, and
        // every fixture in
        // `test_support::enabled_map`). `SecretHex::from_hex` validates through
        // `crypto_store::decode_key_bytes`, which uses the `hex` crate's
        // `decode` — that rejects the `0x` prefix outright.
        //
        // The prefix is stripped here rather than inside `SecretHex` so the
        // data-key path keeps byte-for-byte the validation it has today; this
        // is also the crate's existing convention for the prefix
        // (`quotes::parse_address20`, `direct_eth::decode_hex_bytes`).
        // Stripping is safe
        // for the consumer: alloy's `PrivateKeySigner::from_str` — called by
        // `quotes::create_sponsored_enrollment_quote_at` at STEP 8, and by
        // `rpc_chain::parse_key_opt` — decodes with or without the prefix.
        let quote_signer_raw = cfg
            .stream_g
            .quote_signer_private_key
            .as_deref()
            .ok_or(StreamGStartupError::MissingQuoteSignerKey)?
            .trim();
        let quote_signer_key_hex = SecretHex::from_hex(
            quote_signer_raw
                .strip_prefix("0x")
                .unwrap_or(quote_signer_raw),
        )
        .map_err(StreamGStartupError::QuoteSignerKey)?;

        // Both startup documents resolve through `read_startup_document`, which
        // substitutes a built-in copy ONLY for an unconfigured path with
        // nothing at it — see that function for the two rules. The chain gate
        // below is unchanged either way: the built-in is chain
        // `BUILTIN_DEPLOYMENT_MANIFEST_CHAIN_ID` (31337) and
        // `parse_deployment_manifest` refuses it on any other `CHAIN_ID` with
        // `ManifestChainMismatch`, which is the honest refusal — this crate
        // ships one deployment and does not pretend to ship others.
        let manifest_path = &cfg.stream_g.deployment_manifest_path;
        let (manifest_raw, manifest_source, manifest_label) = read_startup_document(
            manifest_path,
            cfg.stream_g.deployment_manifest_path_source,
            BUILTIN_DEPLOYMENT_MANIFEST_JSON,
            BUILTIN_MANIFEST_LABEL,
        )
        .map_err(|detail| StreamGStartupError::Manifest {
            path: manifest_path.display().to_string(),
            source: TokenManifestError::Io {
                path: manifest_path.display().to_string(),
                detail,
            },
        })?;
        let manifest = parse_deployment_manifest(&manifest_raw, &manifest_label, cfg.chain_id)
            .map_err(|source| StreamGStartupError::Manifest {
                path: manifest_label.clone(),
                source,
            })?;
        if manifest_source == StartupDocumentSource::Builtin {
            tracing::warn!(
                configured_path = %manifest_path.display(),
                builtin_chain_id = BUILTIN_DEPLOYMENT_MANIFEST_CHAIN_ID,
                "stream G deployment manifest: STREAM_G_DEPLOYMENT_MANIFEST_PATH was not set and \
                 no file exists at the default, so the BUILT-IN 31337 lab manifest compiled into \
                 this binary was used. Its addresses are anvil's. Set \
                 STREAM_G_DEPLOYMENT_MANIFEST_PATH for any real deployment"
            );
        }

        // --- Deployment-payload load + fail-closed CONTENT binding ---------
        //
        // `deploymentManifestHash` is a field of every EIP-712 action core,
        // every intent and `FeeQuote` (`models`, `StreamGTypes.sol`), so every
        // signature this process produces is an attestation about a deployment.
        // Until 2026-07-28 that value was a literal tag —
        // `keccak256("stream-g-manifest-g1")`, the `vm.envOr` default in
        // `DeployStreamG.run()` — which hashed nothing: every address and every
        // runtime code hash could change and it would not move.
        //
        // It is now `keccak256(UTF8(RFC8785(payload)))` over the deployment
        // payload document, per the spec at
        // the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring"
        // spec, §5.1 (FeeTokenRegistry). Four
        // things have to be true for the attestation to mean anything, and they
        // fail in four different ways, so they are four comparisons with four
        // messages. Order matters, and it is the fee schedule's order for the
        // same reason: a file that contradicts itself cannot usefully be
        // compared to anything, so (1) precedes (2).
        //
        //   1. the file is internally honest (computed == declared);
        //   2. the payload was authored for this chain;
        //   3. that digest is the one the deployment published
        //      (computed == manifest.deployment_manifest_hash);
        //   4. the payload and the manifest name the SAME address for each of
        //      the TWELVE addresses the manifest carries — the four committed
        //      roles in `payload.contracts` and the eight in
        //      `payload.accounts`.
        //
        // (2) precedes (3) because "authored for chain X, this is chain Y" is a
        // fact about the document, while "not published here" is a fact about a
        // relationship; when both are wrong, the first sends the operator to the
        // file rather than to the chain.
        //
        // (4) is not redundant. (1) and (3) bind the payload to itself and to
        // whatever was republished; neither can notice an address edited in the
        // FLAT manifest, because nothing the payload hashes changed. That is
        // the drift this whole change exists to close, so it gets its own
        // comparison and its own variant. Until 2026-07-28 it covered only the
        // four `contracts` roles, and the other eight were measured to start
        // clean with a one-nibble edit — four silent starts out of four.
        //
        // Ahead of all four: a payload that fell through to the BUILT-IN lab
        // document while the MANIFEST did not is a missing environment
        // variable, and any mismatch it produces is reported as
        // `DeploymentPayloadNotConfigured` rather than as the comparison that
        // happened to fire.
        //
        // Every one of the four is OFFLINE and PURE. `RpcChain` is built after
        // this entire block and under `GOAT_ATTESTOR_MOCK=1` no client exists
        // at all, so a live comparison is structurally impossible here — and
        // that is what makes the mutation tests deterministic rather than
        // network-flaky. The declared-vs-live-gateway check already exists
        // per-action in `preflight`'s four-way `Check::ManifestHashMismatch`.
        let deployment_payload_path = &cfg.stream_g.deployment_payload_path;
        let (deployment_payload_raw, deployment_payload_source, deployment_payload_label) =
            read_startup_document(
                deployment_payload_path,
                cfg.stream_g.deployment_payload_path_source,
                BUILTIN_DEPLOYMENT_PAYLOAD_JSON,
                BUILTIN_DEPLOYMENT_PAYLOAD_LABEL,
            )
            .map_err(|detail| StreamGStartupError::DeploymentPayload {
                path: deployment_payload_path.display().to_string(),
                source: DeploymentPayloadError::Io {
                    path: deployment_payload_path.display().to_string(),
                    detail,
                },
            })?;
        let deployment_payload =
            DeploymentPayload::from_json(&deployment_payload_raw, &deployment_payload_label)
                .map_err(|source| StreamGStartupError::DeploymentPayload {
                    path: deployment_payload_label.clone(),
                    source,
                })?;
        // A built-in payload standing in for a NON-built-in manifest is a
        // MISSING ENVIRONMENT VARIABLE. When one of the three comparisons below
        // then fails, the honest name for the fault is the variable, not the
        // comparison: `DeploymentManifestHashMismatch` says "this deployment did
        // not publish this payload", which is true of the built-in lab document
        // and sends the operator to the chain instead of to their config.
        //
        // Deliberately not an unconditional refusal. Both-built-in is the
        // zero-config lab path and stays legal; and a built-in payload that
        // genuinely AGREES with a supplied manifest is a correct start (it is
        // the same lab deployment described twice), so this only re-labels
        // failures rather than inventing one.
        let payload_substituted_for_a_real_manifest = deployment_payload_source
            == StartupDocumentSource::Builtin
            && manifest_source != StartupDocumentSource::Builtin;
        let not_configured = || StreamGStartupError::DeploymentPayloadNotConfigured {
            manifest_path: manifest_label.clone(),
            configured_path: deployment_payload_path.display().to_string(),
        };
        if deployment_payload_source == StartupDocumentSource::Builtin {
            tracing::warn!(
                configured_path = %deployment_payload_path.display(),
                "stream G deployment payload: STREAM_G_DEPLOYMENT_PAYLOAD_PATH was not set and \
                 no file exists at the default, so the BUILT-IN 31337 lab payload compiled into \
                 this binary was used. Its addresses and runtime code hashes are the anvil lab's. \
                 Set STREAM_G_DEPLOYMENT_PAYLOAD_PATH for any real deployment"
            );
        }

        let computed_manifest_hash = deployment_payload.computed_deployment_manifest_hash();
        let declared_manifest_hash = deployment_payload.declared_deployment_manifest_hash();
        if computed_manifest_hash != declared_manifest_hash {
            return Err(StreamGStartupError::DeploymentManifestHashSelfMismatch {
                path: deployment_payload_label.clone(),
                computed: hex::encode(computed_manifest_hash),
                declared: hex::encode(declared_manifest_hash),
            });
        }
        // The chain comparison precedes the publication comparison, which is a
        // change from the original order and is deliberate. "This payload was
        // authored for chain X and your manifest is chain Y" is a fact about the
        // document that stands on its own; "this deployment did not publish this
        // payload" is a fact about a relationship. When BOTH are wrong — the
        // ordinary case for a copied configuration — the first sends the
        // operator to the file, and the second sends them to the chain.
        if deployment_payload.payload_chain_id() != u128::from(manifest.chain_id) {
            if payload_substituted_for_a_real_manifest {
                return Err(not_configured());
            }
            return Err(StreamGStartupError::DeploymentManifestChainMismatch {
                path: deployment_payload_label.clone(),
                payload_chain_id: deployment_payload.payload_chain_id(),
                manifest_chain_id: manifest.chain_id,
            });
        }
        if computed_manifest_hash != manifest.deployment_manifest_hash {
            if payload_substituted_for_a_real_manifest {
                return Err(not_configured());
            }
            return Err(StreamGStartupError::DeploymentManifestHashMismatch {
                path: deployment_payload_label.clone(),
                computed: hex::encode(computed_manifest_hash),
                manifest: hex::encode(manifest.deployment_manifest_hash),
            });
        }
        // Both sides rendered from DECODED bytes, so the message can never show
        // two legal spellings of one address as a disagreement: the payload
        // spells addresses lowercase after normalisation while the manifest
        // spells them EIP-55 checksummed.
        for (role, manifest_address) in [
            ("FEE_TOKEN_REGISTRY", manifest.fee_token_registry),
            ("GATEWAY", manifest.goat_relay_gateway),
            ("SPONSORED_BUY_DESK", manifest.sponsored_buy_desk),
            (
                "WALLET_SPONSORSHIP_REGISTRY",
                manifest.wallet_sponsorship_registry,
            ),
        ] {
            // `from_json` proved every canonical role is present, so `None`
            // here is unreachable; it is matched rather than unwrapped so a
            // future schema change cannot turn a missing role into a panic at
            // startup.
            let commitment = deployment_payload.role(role).ok_or_else(|| {
                StreamGStartupError::DeploymentPayload {
                    path: deployment_payload_label.clone(),
                    source: DeploymentPayloadError::Parse {
                        path: deployment_payload_label.clone(),
                        detail: format!(
                            "payload.contracts is missing the committed role {role} after a \
                             successful parse (expected {CANONICAL_ROLES:?})"
                        ),
                    },
                }
            })?;
            if commitment.address != manifest_address {
                if payload_substituted_for_a_real_manifest {
                    return Err(not_configured());
                }
                return Err(StreamGStartupError::DeploymentManifestAddressMismatch {
                    path: deployment_payload_label.clone(),
                    role,
                    payload_address: hex::encode(commitment.address),
                    manifest_address: hex::encode(manifest_address),
                });
            }
        }
        // ...and the eight addresses `payload.accounts` carries. Before schema
        // 2 these were in neither document's digest and in no comparison: a
        // one-nibble edit to `quoteSigner`, `goatCoin`, `policySafe` or
        // `enrollmentRegistry` in the flat artifact started this process
        // cleanly, four times out of four, with no warning. They carry no
        // `runtimeCodeHash` (see `deployment_payload`'s module docs), so this
        // loop is the whole of their binding on the artifact side.
        for (role, manifest_address) in [
            ("DESK_OWNER", manifest.desk_owner),
            ("ENROLLMENT_REGISTRY", manifest.enrollment_registry),
            ("FEE_SAFE", manifest.fee_safe),
            ("FEE_TOKEN", manifest.fee_token),
            ("GOAT_COIN", manifest.goat_coin),
            ("POLICY_SAFE", manifest.policy_safe),
            ("QUOTE_SIGNER", manifest.quote_signer),
            ("RECOVERY_SAFE", manifest.recovery_safe),
        ] {
            let payload_address = deployment_payload.account(role).ok_or_else(|| {
                StreamGStartupError::DeploymentPayload {
                    path: deployment_payload_label.clone(),
                    source: DeploymentPayloadError::Parse {
                        path: deployment_payload_label.clone(),
                        detail: format!(
                            "payload.accounts is missing {role} after a successful parse \
                             (expected {CANONICAL_ACCOUNTS:?})"
                        ),
                    },
                }
            })?;
            if payload_address != manifest_address {
                if payload_substituted_for_a_real_manifest {
                    return Err(not_configured());
                }
                return Err(StreamGStartupError::DeploymentManifestAddressMismatch {
                    path: deployment_payload_label.clone(),
                    role,
                    payload_address: hex::encode(payload_address),
                    manifest_address: hex::encode(manifest_address),
                });
            }
        }

        // --- Fee-schedule load + fail-closed VALUE binding -----------------
        //
        // `models::fee_quote_struct_hash` signs `manifest.fee_schedule_hash`
        // into every quote, so a quote is an attestation about a fee schedule.
        // Two things have to be true for that attestation to mean anything, and
        // they fail in different ways, so they are two comparisons with two
        // messages:
        //
        //   1. the file must be internally honest — its payload must hash to
        //      the `feeScheduleHash` it declares. Otherwise the payload was
        //      edited after approval and the declaration is stale.
        //   2. that digest must be the one the deployment published. Otherwise
        //      this process would sign the manifest's hash over amounts nobody
        //      approved for this deployment.
        //
        // Order matters: (1) first, because a file that contradicts itself
        // cannot usefully be compared to anything, and telling the operator
        // "this deployment did not publish this schedule" when the real fault
        // is a local edit sends them to the wrong place.
        //
        // This is a value digest now, not the old opaque governance tag —
        // `keccak256(UTF8(RFC8785(payload)))` per the spec at
        // the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring"
        // spec, §8.1. An
        // edited amount therefore no longer starts. See `FeeSchedule::load`.
        let fee_schedule_path = &cfg.stream_g.fee_schedule_path;
        let (fee_schedule_raw, fee_schedule_source, fee_schedule_label) = read_startup_document(
            fee_schedule_path,
            cfg.stream_g.fee_schedule_path_source,
            BUILTIN_FEE_SCHEDULE_JSON,
            BUILTIN_FEE_SCHEDULE_LABEL,
        )
        .map_err(|detail| StreamGStartupError::FeeSchedule {
            path: fee_schedule_path.display().to_string(),
            source: QuoteError::FeeScheduleIo {
                path: fee_schedule_path.display().to_string(),
                detail,
            },
        })?;
        let fee_schedule =
            FeeSchedule::from_json(&fee_schedule_raw, &fee_schedule_label).map_err(|source| {
                StreamGStartupError::FeeSchedule {
                    path: fee_schedule_label.clone(),
                    source,
                }
            })?;
        let computed = fee_schedule.computed_fee_schedule_hash();
        let declared = fee_schedule.declared_fee_schedule_hash();
        if computed != declared {
            return Err(StreamGStartupError::FeeScheduleHashSelfMismatch {
                path: fee_schedule_label.clone(),
                computed: hex::encode(computed),
                declared: hex::encode(declared),
            });
        }
        if computed != manifest.fee_schedule_hash {
            return Err(StreamGStartupError::FeeScheduleHashMismatch {
                path: fee_schedule_label.clone(),
                computed: hex::encode(computed),
                manifest: hex::encode(manifest.fee_schedule_hash),
            });
        }

        // --- ... and the DEPLOYMENT the payload was authored for -----------
        //
        // The two digest comparisons above prove the file is internally honest
        // and that this deployment republished it. Neither proves the payload
        // was written FOR this deployment, and the difference is not
        // theoretical: an auditor started this binary with a payload declaring
        // `chainId "8453"`, an unrelated `feeToken` and `decimals "18"`, wrote
        // its digest into both the schedule file and a 31337 manifest, and got
        // a clean start serving 1e18-denominated prices against a 6-decimal
        // token. The digest binds a payload to itself and to whatever was
        // republished; it cannot bind it to a deployment it never names.
        //
        // So the two payload fields the manifest independently knows are
        // compared by value, each with its own variant so "wrong chain",
        // "wrong token" and "wrong digest" are three different messages.
        // `manifest.chain_id` was itself already checked against the
        // configured `CHAIN_ID` by `parse_deployment_manifest`, so agreeing
        // with it transitively pins the payload to this process's chain.
        //
        // `payload.decimals` is NOT compared here, and cannot be: the only
        // source of this deployment's decimals is
        // `FeeTokenRegistry.getTokenConfig` via
        // `token_manifest::read_live_token_state`, and this function performs
        // no chain reads — the `RpcChain` below is built *after* every check
        // in this block, and under `GOAT_ATTESTOR_MOCK=1` no client is built
        // at all. It is compared on the QUOTE path instead, by
        // `quotes::assert_schedule_decimals_match_live_token`, which is the
        // first point where the registry's number exists. So a schedule that
        // prices this deployment's fee token in the wrong unit starts cleanly
        // here and is refused at every quote with
        // `FEE_SCHEDULE_DECIMALS_MISMATCH` (500). See
        // `quotes::FeeSchedule::load`'s "What is still NOT covered" for the
        // full statement.
        if fee_schedule.payload_chain_id() != u128::from(manifest.chain_id) {
            return Err(StreamGStartupError::FeeScheduleChainMismatch {
                path: fee_schedule_label.clone(),
                payload_chain_id: fee_schedule.payload_chain_id(),
                manifest_chain_id: manifest.chain_id,
            });
        }
        if fee_schedule.payload_fee_token() != manifest.fee_token {
            return Err(StreamGStartupError::FeeScheduleFeeTokenMismatch {
                path: fee_schedule_label.clone(),
                // Both sides rendered from the decoded bytes, so the message
                // cannot show two spellings of one address as a disagreement.
                payload_fee_token: hex::encode(fee_schedule.payload_fee_token()),
                manifest_fee_token: hex::encode(manifest.fee_token),
            });
        }

        // **Zero-config STARTUP is not zero-config QUOTING.** The built-in
        // schedule sets no tariff for any action, so `fee_for` answers
        // `MISSING_TARIFF` and the quote path refuses — deliberately, because
        // the Season-0 amounts are a founder decision that has not been taken
        // and an invented number would be signed verbatim into an EIP-712
        // `FeeQuote`. The warning says both halves so nobody reads "started"
        // as "can price". `has_any_tariff` is measured from the loaded
        // schedule, not assumed from the source, so this stays true if the
        // shipped placeholder is ever given real numbers.
        if fee_schedule_source == StartupDocumentSource::Builtin {
            tracing::warn!(
                configured_path = %fee_schedule_path.display(),
                has_any_tariff = fee_schedule.has_any_tariff(),
                "stream G fee schedule: STREAM_G_FEE_SCHEDULE_PATH was not set and no file \
                 exists at the default, so the BUILT-IN placeholder schedule compiled into this \
                 binary was used. It sets NO tariff for any action, so this process starts but \
                 every quote is refused with MISSING_TARIFF until a founder-approved schedule is \
                 supplied via STREAM_G_FEE_SCHEDULE_PATH and republished on-chain"
            );
        }

        let chain = if cfg.mock_mode {
            tracing::warn!(
                "stream G started with GOAT_ATTESTOR_MOCK=1: no live chain client, so every \
                 Stream G live-read path is unreachable in this process"
            );
            None
        } else {
            Some(Arc::new(RpcChain::from_config(cfg)?))
        };

        // Wave C W1b. Minted here, once, and then immutable for the life of
        // the process — every outbox compare-and-swap on the submit path
        // compares this exact string.
        let claim_owner = mint_submit_claim_owner();

        tracing::info!(
            db = %db_path.display(),
            lock = %lock_path.display(),
            db_uuid = %store.db_uuid(),
            schema_version = store.schema_version(),
            journal_mode = %pragmas.journal_mode,
            busy_timeout_ms = pragmas.busy_timeout_ms,
            data_key_id = %data_key.key_id(),
            // The non-secret hash prefix, never the key: `SecretHex::key_id`
            // is the same derived identifier `DataKey` prints on the line
            // above, and it is what lets an operator confirm *which* signer
            // this process loaded without the key ever reaching a log.
            quote_signer_key_id = %quote_signer_key_hex.key_id(),
            manifest_chain_id = manifest.chain_id,
            live_chain = chain.is_some(),
            // The two documents' provenance, named rather than implied. `…_source`
            // is `file` or `built-in`; `…_origin` is the path or the built-in
            // label, so one line answers "which bytes did this process load"
            // without the reader having to know what the default path is.
            manifest_source = manifest_source.as_str(),
            manifest_origin = %manifest_label,
            fee_schedule_source = fee_schedule_source.as_str(),
            fee_schedule = %fee_schedule_label,
            fee_schedule_hash = %hex::encode(declared),
            fee_schedule_has_tariff = fee_schedule.has_any_tariff(),
            fee_schedule_note = fee_schedule.note().unwrap_or("<none>"),
            // Not a secret: it is a process label, and printing it is the
            // point — it is what an operator correlates a stuck `tx_attempts`
            // row against.
            claim_owner = %claim_owner,
            broadcast_gas_limit = cfg.stream_g.broadcast_gas.gas_limit().get(),
            broadcast_max_fee_per_gas_wei = cfg.stream_g.broadcast_gas.max_fee_per_gas().get(),
            broadcast_max_priority_fee_per_gas_wei =
                cfg.stream_g.broadcast_gas.max_priority_fee_per_gas().get(),
            "stream G store opened; instance lock held for the life of this process"
        );

        // 🔴 Said out loud once per start, because the three numbers above are
        // starting values and a value being *configurable* is not a value
        // being *reviewed*. `BroadcastGasPolicy`'s type doc holds the evidence
        // for each.
        if cfg.stream_g.broadcast_gas
            == BroadcastGasPolicy::starting_values_pending_founder_review()
        {
            tracing::warn!(
                "stream G broadcast gas policy is the UNREVIEWED starting values (500_000 gas / \
                 1 gwei max fee / 0.001 gwei tip). Nothing in this repository has measured any \
                 of the three against a live executeSponsoredEnrollment. Founder review is \
                 required before any mainnet use; override with STREAM_G_BROADCAST_GAS_LIMIT, \
                 STREAM_G_BROADCAST_MAX_FEE_PER_GAS_WEI and \
                 STREAM_G_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI"
            );
        }

        Ok(Self {
            inner: Arc::new(Inner {
                store,
                data_key,
                data_key_hex,
                quote_signer_key_hex,
                manifest,
                max_native_exposure_wei: WeiCeiling::new(cfg.stream_g.max_native_exposure_wei),
                fee_schedule,
                fee_schedule_origin: fee_schedule_label,
                chain,
                shutdown,
                lock_path: lock_path.clone(),
                cors_origins: cfg.stream_g.cors_origins.clone(),
                metrics: Arc::new(StreamGMetrics::new()),
                rate_limiter: Arc::new(Mutex::new(StreamGRateLimiter::with_defaults())),
                leases: Arc::new(SigningLeaseRegistry::new()),
                claim_owner,
                broadcast_gas: cfg.stream_g.broadcast_gas,
            }),
        })
    }

    /// The single locked store. Write paths must go through
    /// [`StreamGStore::write_tx`]; never call a store method from inside a
    /// `write_tx` closure (single connection — it deadlocks to
    /// `PoolTimedOut`).
    pub fn store(&self) -> &StreamGStore {
        &self.inner.store
    }

    pub fn data_key(&self) -> &DataKey {
        &self.inner.data_key
    }

    /// The at-rest key in the hex form every `profile_auth` / `outbox` /
    /// `submit` / `onboarding` / `quotes` entry point takes.
    ///
    /// This is the accessor that makes those functions callable from a
    /// handler at all — see [`Inner::data_key_hex`]. Pass the `&SecretHex`
    /// straight through; do **not** call `as_str()` on it in a route.
    pub fn data_key_hex(&self) -> &SecretHex {
        &self.inner.data_key_hex
    }

    /// The quote signer's private key, in the hex form
    /// `models::EnrollmentQuoteContext::quote_signer_private_key_hex`
    /// requires. Pass `as_str()` no further than the
    /// `PrivateKeySigner::from_str` in
    /// `quotes::create_sponsored_enrollment_quote_at`'s STEP 8.
    ///
    /// **Returns `&SecretHex`, not `Option<&SecretHex>`**, because presence is
    /// already guaranteed twice over: `config::build_stream_g_config` refuses
    /// to load a config with `STREAM_G_ENABLED=1` and this variable unset
    /// (`config::build_stream_g_config`, the same `missing` list
    /// `STREAM_G_DATA_KEY_HEX` is on), and [`StreamGState::start`] returns
    /// [`StreamGStartupError::MissingQuoteSignerKey`] rather than a state
    /// without it. So no `StreamGState` value exists that lacks a quote signer,
    /// and an `Option` here would only push a dead `None` arm into every quote
    /// handler. This is exactly [`StreamGState::data_key_hex`]'s shape, for
    /// exactly the same reason.
    ///
    /// The key having the right *value* is a separate claim this does not
    /// make: nothing checks that it corresponds to the manifest's
    /// `quoteSigner` address, which is what
    /// `models::EnrollmentQuoteContext::quote_signer_private_key_hex`'s own
    /// doc warns about.
    pub fn quote_signer_key_hex(&self) -> &SecretHex {
        &self.inner.quote_signer_key_hex
    }

    pub fn manifest(&self) -> &DeploymentManifest {
        &self.inner.manifest
    }

    /// The process-wide Stream G rate limiter.
    ///
    /// Returns the `Mutex` rather than a guard so a caller takes the lock for
    /// exactly the span of its own check — holding it across an `.await`
    /// would serialize every request in the process, and a `std::sync`
    /// guard held across an await point does not compile in an async fn
    /// anyway, which is part of why the std mutex is the right one here.
    ///
    /// ⚠️ **Eight of the ten mounted routes consult this**, through
    /// `profile_auth`'s two extractors — every `/v1/profile/` route plus the
    /// three pipeline routes, which take `AuthenticatedProfile` and therefore
    /// cannot skip the check. `GET /v1/stream-g/ready` and
    /// `GET /v1/stream-g/metrics` are not rate-limited by it. See
    /// `super::rate_limit`'s module doc.
    pub fn rate_limiter(&self) -> &Mutex<StreamGRateLimiter> {
        &self.inner.rate_limiter
    }

    /// The native-ETH exposure ceiling (`STREAM_G_MAX_NATIVE_EXPOSURE_WEI`).
    ///
    /// 🔴 Wave C W4: `submit::submit_context` binds this into
    /// `submit::SubmitContext::max_native_exposure_wei` for
    /// `POST /v1/stream-g/submit`, which is the gate's only production
    /// source. `submit::post_submit` refuses the request with
    /// `http_error::ERR_EXPOSURE_CEILING_UNSET` (503) when this is the `0`
    /// default, which is how "operator never set the variable" is told apart
    /// from a real ceiling rather than presenting as
    /// `EXPOSURE_EXCEEDS_SCHEDULE` on every request.
    ///
    /// ⚠️ Reaching this value is still not the same as closing hazard 1 on
    /// every chain: `base_fee::submit_exposure_for_chain` skips the gate
    /// entirely on chain 31337, which carries no `GasPriceOracle` predeploy.
    pub fn max_native_exposure_wei(&self) -> WeiCeiling {
        self.inner.max_native_exposure_wei
    }

    /// The tariff table loaded at startup, already bound to the manifest's
    /// `feeScheduleHash` by value (`start` refuses to return a state
    /// otherwise).
    ///
    /// A schedule reached through here is guaranteed to be the payload whose
    /// canonical digest the deployment published: `start` compares
    /// `keccak256(UTF8(RFC8785(payload)))` against both the file's declaration
    /// and the manifest. Editing an amount without republishing no longer
    /// produces a state at all. What that still does not prove is *who* wrote
    /// the file — read [`FeeSchedule::load`].
    pub fn fee_schedule(&self) -> &FeeSchedule {
        &self.inner.fee_schedule
    }

    /// Where [`StreamGState::fee_schedule`] was read from. Diagnostics only.
    ///
    /// ⚠️ **Not necessarily a path.** When no schedule file existed at an
    /// unconfigured default, `start` loads [`BUILTIN_FEE_SCHEDULE_JSON`] and
    /// this is `BUILTIN_FEE_SCHEDULE_LABEL` instead — the same string the
    /// startup log's `fee_schedule` field and any contents error carry. It is
    /// typed `&str` rather than `&Path` so a caller cannot open it by mistake.
    pub fn fee_schedule_origin(&self) -> &str {
        &self.inner.fee_schedule_origin
    }

    /// The live client, or `None` in mock mode. Concrete type on purpose.
    pub fn live_chain(&self) -> Option<&RpcChain> {
        self.inner.chain.as_deref()
    }

    /// The chain-honesty wrapper Stream G's live-read entry points require.
    /// `None` in mock mode, which is exactly the point: there is no value of
    /// this state that can hand a `MockChain` to a live-read path.
    pub fn trusted_chain(&self) -> Option<TrustedChain<'_>> {
        self.inner.chain.as_deref().map(TrustedChain::live)
    }

    pub fn shutdown(&self) -> &ShutdownToken {
        &self.inner.shutdown
    }

    /// The lock file this process's store handle holds. Readiness re-probes
    /// it; nothing else should touch it.
    pub fn lock_path(&self) -> &Path {
        &self.inner.lock_path
    }

    /// Stream G's **own** CORS allowlist (`STREAM_G_CORS_ORIGINS`), never
    /// unioned with the pilot relayer's. Empty by default, which means no
    /// cross-origin request is allowed.
    pub fn cors_origins(&self) -> &[String] {
        &self.inner.cors_origins
    }

    /// Process-wide Stream G counters, shared by handlers and (Wave D)
    /// background tasks.
    pub fn metrics(&self) -> &Arc<StreamGMetrics> {
        &self.inner.metrics
    }

    /// The **one** signing-lease registry in this process.
    ///
    /// ⚠️ Every submit path must take its lease from *this*, never from a
    /// freshly constructed `SigningLeaseRegistry`. See [`Inner::leases`]: a
    /// second registry compiles, passes every existing test, and silently
    /// deletes the single-signer guarantee, because `try_acquire` cannot
    /// collide across two `held` sets.
    ///
    /// Returns `&SigningLeaseRegistry` rather than the `Arc` because
    /// `try_acquire` borrows the registry for the lifetime of the guard it
    /// hands back, and a handler holds that guard across its own `.await`s
    /// while the state is alive around it.
    pub fn leases(&self) -> &SigningLeaseRegistry {
        &self.inner.leases
    }

    /// This process's outbox CAS identity — pass straight into
    /// `outbox`'s `claim_owner` fields.
    ///
    /// ⚠️ **Never mint a second one per request.** `outbox`'s
    /// reserve/release/record compare-and-swaps match `claim_owner` by
    /// equality, so a value that differs from the one that reserved a row
    /// leaves that row un-releasable by this process until the sweeper's lease
    /// expiry reclaims it. That is what makes this an accessor over a stored
    /// field rather than a call to [`mint_submit_claim_owner`].
    ///
    /// Guaranteed `!= maintenance::SWEEPER_CLAIM_OWNER` — asserted at mint.
    pub fn claim_owner(&self) -> &str {
        &self.inner.claim_owner
    }

    /// The validated broadcast gas policy
    /// (`config::build_broadcast_gas_policy`), ready to hand to
    /// `broadcaster::RpcChainEnrollmentSigner::new`.
    ///
    /// 🔴 Reaching this value is **not** the same as the numbers having been
    /// reviewed — read [`BroadcastGasPolicy`]'s type doc, which states per
    /// value what evidence exists. `start` logs a warning when the process is
    /// running the unreviewed defaults.
    pub fn broadcast_gas(&self) -> BroadcastGasPolicy {
        self.inner.broadcast_gas
    }
}

/// Test-only fixtures, hoisted out of `mod tests` so `stream_g::mod`'s router
/// tests can build a real state without duplicating the env map. `cfg(test)`,
/// so none of this exists in a release build.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::config;
    use std::collections::HashMap;
    use std::path::Path;

    /// Matches `contracts/deployments/31337.stream-g.json`'s shape (the same
    /// 17 keys `writeManifest` emits), publishing [`FIXTURE_FEE_SCHEDULE_HASH`].
    pub(crate) fn manifest_json(chain_id: u64) -> String {
        manifest_json_with_fee_schedule_hash(chain_id, FIXTURE_FEE_SCHEDULE_HASH)
    }

    /// The lab gateway address every fixture manifest and payload names.
    /// Spelled EIP-55 checksummed here, exactly as `vm.serializeAddress`
    /// writes it, so the fixtures exercise the two-spellings-one-address case
    /// rather than sidestepping it.
    pub(crate) const FIXTURE_GATEWAY: &str = "0x4ff05a443250A64a18C68CEdd2122cFDf3872140";
    pub(crate) const FIXTURE_FEE_TOKEN_REGISTRY: &str =
        "0x7FdB3132Ff7D02d8B9e221c61cC895ce9a4bb773";
    pub(crate) const FIXTURE_SPONSORED_BUY_DESK: &str =
        "0xD76ffbd1eFF76C510C3a509fE22864688aC3A588";
    pub(crate) const FIXTURE_WALLET_SPONSORSHIP_REGISTRY: &str =
        "0xfD07C974e33dd1626640bA3a5acF0418FaacCA7a";

    /// [`manifest_json`] publishing an arbitrary `feeScheduleHash`, so a test
    /// can build the manifest that matches a non-default payload.
    pub(crate) fn manifest_json_with_fee_schedule_hash(
        chain_id: u64,
        fee_schedule_hash: &str,
    ) -> String {
        manifest_json_with(
            chain_id,
            FIXTURE_DEPLOYMENT_MANIFEST_HASH,
            fee_schedule_hash,
            FIXTURE_GATEWAY,
        )
    }

    /// [`manifest_json`] with the three fields the deployment-payload binds
    /// compare against left open: the published `deploymentManifestHash`, the
    /// published `feeScheduleHash`, and the gateway ADDRESS.
    ///
    /// The gateway address is open for one reason: it is the only way to write
    /// the mutation the digest cannot catch. Editing an address in the flat
    /// artifact moves nothing the payload hashes, so
    /// `StreamGStartupError::DeploymentManifestAddressMismatch` is the only
    /// thing standing between a drifted artifact and a clean start. A fixture
    /// that could not express that edit could not test it.
    pub(crate) fn manifest_json_with(
        chain_id: u64,
        deployment_manifest_hash: &str,
        fee_schedule_hash: &str,
        goat_relay_gateway: &str,
    ) -> String {
        format!(
            r#"{{
                "schemaVersion": 1,
                "chainId": {chain_id},
                "phase": "G1",
                "enrollmentRegistry": "0x104fBc016F4bb334D775a19E8A6510109AC63E00",
                "goatCoin": "0x037eDa3aDB1198021A9b2e88C22B464fD38db3f3",
                "feeToken": "0xDDc10602782af652bB913f7bdE1fD82981Db7dd9",
                "feeTokenRegistry": "{FIXTURE_FEE_TOKEN_REGISTRY}",
                "walletSponsorshipRegistry": "{FIXTURE_WALLET_SPONSORSHIP_REGISTRY}",
                "sponsoredBuyDesk": "{FIXTURE_SPONSORED_BUY_DESK}",
                "goatRelayGateway": "{goat_relay_gateway}",
                "policySafe": "0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496",
                "feeSafe": "0xD1CCc21678e1B7015A472216B2F501f421645b43",
                "recoverySafe": "0xb8705214E170151048Eff0A1eDE1824FfF19CB9C",
                "deskOwner": "0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496",
                "quoteSigner": "0xeBD5a85005dCC98dabB7a2888De82D43c5A6957E",
                "deploymentManifestHash": "{deployment_manifest_hash}",
                "feeScheduleHash": "{fee_schedule_hash}"
            }}"#
        )
    }

    /// The digest `manifest_json` carries, which is what every fixture
    /// schedule written by [`schedule_payload_json`]`(None)` hashes to.
    ///
    /// Hard-coded rather than computed so it is a *known-answer* fixture in the
    /// sense the spec asks for ("Rust/JavaScript/ops fixtures pin the canonical
    /// bytes and hash before Policy Safe approval",
    /// the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring"
    /// spec, §8.1): if
    /// anyone edits the payload literal below, or the canonicaliser drifts,
    /// `fixture_schedule_payload_hashes_to_the_pinned_manifest_value` fails
    /// instead of every fixture silently re-agreeing with itself.
    ///
    /// It is **no longer** `keccak256("stream-g-fee-schedule-g1")`: that tag
    /// was a label, and `feeScheduleHash` is now a digest of the payload.
    ///
    /// It is the same value the SHIPPED `fixtures/stream_g_fee_schedule.json`
    /// declares, and that is deliberate rather than a coincidence:
    /// [`schedule_payload_json`]`(None)` mirrors the shipped placeholder
    /// field for field, so these fixtures exercise the file this repo actually
    /// ships. `quotes::tests::shipped_placeholder_fee_schedule_is_published_and_serves_no_price`
    /// pins the same digest from the file's side, and additionally pins the
    /// canonical bytes.
    pub(crate) const FIXTURE_FEE_SCHEDULE_HASH: &str =
        "0x2681f70d84c3a644290b622f42fc1fa6977c66da4343213f9967c8204ad91bf2";

    /// The `deploymentManifestHash` [`manifest_json`] publishes.
    ///
    /// It is the digest of the SHIPPED deployment payload
    /// (`fixtures/stream_g_deployment_payload.json`), and that is deliberate
    /// rather than a coincidence: no fixture here writes a payload document, so
    /// every started state falls through to
    /// [`super::BUILTIN_DEPLOYMENT_PAYLOAD_JSON`], and `start` refuses unless
    /// the manifest publishes that document's digest
    /// ([`StreamGStartupError::DeploymentManifestHashMismatch`]). The twelve
    /// addresses above are the same lab deployment's, so the four role binds
    /// agree too.
    ///
    /// It is **no longer** `keccak256("stream-g-manifest-g1")` =
    /// `0x1b374be1…`. That tag hashed nothing: every address and every runtime
    /// code hash could change and it would not move.
    ///
    /// Hard-coded rather than computed, for the same reason
    /// [`FIXTURE_FEE_SCHEDULE_HASH`] is: if the shipped payload is edited or
    /// the canonicaliser drifts,
    /// `deployment_payload::tests::shipped_deployment_payload_is_published_and_binds_the_manifest`
    /// fails instead of every fixture silently re-agreeing with itself.
    pub(crate) const FIXTURE_DEPLOYMENT_MANIFEST_HASH: &str =
        "0xd888dfcea8b9ad292dab408ae0a81e84752506668d813aff10ea901e44c8a65f";

    /// The standard fixture payload: the eleven published fields, with every
    /// ceiling and the exposure ceiling at `"0"` and no tariff set unless
    /// `sponsored_enrollment_fee_raw` supplies one.
    ///
    /// `chainId`, `feeToken` and `decimals` are the 31337 lab deployment's —
    /// the values `manifest_json(31337)` carries — because `start` now compares
    /// the first two against the manifest and refuses a payload authored for
    /// another deployment ([`StreamGStartupError::FeeScheduleChainMismatch`],
    /// [`StreamGStartupError::FeeScheduleFeeTokenMismatch`]). The fixtures that
    /// write a `manifest_json(84532)` never reach that comparison: the manifest
    /// chain gate in `token_manifest::parse_deployment_manifest` refuses 84532
    /// against `CHAIN_ID=31337` several steps earlier. Use
    /// [`schedule_payload_json_for`] to author a payload that disagrees on
    /// purpose.
    pub(crate) fn schedule_payload_json(sponsored_enrollment_fee_raw: Option<&str>) -> String {
        schedule_payload_json_for(
            "31337",
            "0xddc10602782af652bb913f7bde1fd82981db7dd9",
            "6",
            sponsored_enrollment_fee_raw,
        )
    }

    /// [`schedule_payload_json`] with the three deployment-bound fields open.
    ///
    /// Exists so a test can write the one thing the digest cannot catch: a
    /// payload that is internally consistent, republished, and *for another
    /// deployment*. The defaults live in [`schedule_payload_json`], which
    /// delegates here, so the two cannot drift into two different literals —
    /// `fixture_schedule_payload_hashes_to_the_pinned_manifest_value` pins the
    /// default's digest against a constant either way.
    pub(crate) fn schedule_payload_json_for(
        chain_id: &str,
        fee_token: &str,
        decimals: &str,
        sponsored_enrollment_fee_raw: Option<&str>,
    ) -> String {
        let enrollment = match sponsored_enrollment_fee_raw {
            Some(raw) => format!("\"{raw}\""),
            None => "null".to_string(),
        };
        format!(
            r#"{{
                "schemaVersion": "1",
                "scheduleVersion": "1",
                "chainId": "{chain_id}",
                "feeToken": "{fee_token}",
                "decimals": "{decimals}",
                "validAfter": "0",
                "validUntil": "0",
                "actionFeesRaw": {{
                    "GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1": {enrollment},
                    "GOAT_STREAM_G_SPONSORED_SELL_V1": null,
                    "GOAT_STREAM_G_GOAT_TRANSFER_V1": null,
                    "GOAT_STREAM_G_USDT_TRANSFER_V1": null,
                    "GOAT_STREAM_G_PROXY_CLAIM_V1": null,
                    "GOAT_STREAM_G_PROXY_PROPOSE_BATCH_V1": null,
                    "GOAT_STREAM_G_PROXY_CHALLENGE_BATCH_V1": null
                }},
                "gasUnitCeilings": {{
                    "GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1": "0",
                    "GOAT_STREAM_G_SPONSORED_SELL_V1": "0",
                    "GOAT_STREAM_G_GOAT_TRANSFER_V1": "0",
                    "GOAT_STREAM_G_USDT_TRANSFER_V1": "0",
                    "GOAT_STREAM_G_PROXY_CLAIM_V1": "0",
                    "GOAT_STREAM_G_PROXY_PROPOSE_BATCH_V1": "0",
                    "GOAT_STREAM_G_PROXY_CHALLENGE_BATCH_V1": "0"
                }},
                "calldataByteCeilings": {{
                    "GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1": "0",
                    "GOAT_STREAM_G_SPONSORED_SELL_V1": "0",
                    "GOAT_STREAM_G_GOAT_TRANSFER_V1": "0",
                    "GOAT_STREAM_G_USDT_TRANSFER_V1": "0",
                    "GOAT_STREAM_G_PROXY_CLAIM_V1": "0",
                    "GOAT_STREAM_G_PROXY_PROPOSE_BATCH_V1": "0",
                    "GOAT_STREAM_G_PROXY_CHALLENGE_BATCH_V1": "0"
                }},
                "maxNativeExposureWei": "0"
            }}"#
        )
    }

    /// `0x` + `keccak256(UTF8(RFC8785(payload)))`, the value a file must
    /// declare and a manifest must publish for `start` to accept the payload.
    pub(crate) fn schedule_hash_hex(payload_json: &str) -> String {
        let value: serde_json::Value =
            serde_json::from_str(payload_json).expect("fixture payload must be JSON");
        format!(
            "0x{}",
            hex::encode(crate::canonical_hash(&value).expect("fixture payload must canonicalise"))
        )
    }

    /// A fee-schedule file declaring `fee_schedule_hash` over `payload_json`
    /// verbatim.
    ///
    /// Both halves are parameters rather than fixed, because the two startup
    /// refusals need different lies: a *declared* hash that disagrees with the
    /// payload (self-mismatch) and a payload that disagrees with the manifest
    /// (deployment mismatch). A helper that could only emit the consistent case
    /// could not exercise either.
    pub(crate) fn fee_schedule_json(fee_schedule_hash: &str, payload_json: &str) -> String {
        format!(
            r#"{{
                "schemaVersion": 2,
                "feeScheduleHash": "{fee_schedule_hash}",
                "note": "test fixture",
                "payload": {payload_json}
            }}"#
        )
    }

    /// Writes a manifest and a schedule that agree, which is the only
    /// combination `start` accepts now that the manifest publishes a digest of
    /// the payload. Mirrors what an operator must do: changing a tariff means
    /// republishing the deployment's `feeScheduleHash`.
    /// A deployment-payload BODY naming the lab's four committed roles, with
    /// the gateway's address and runtime code hash open so a test can drift
    /// exactly one field and nothing else.
    ///
    /// Addresses are spelled lowercase here and checksummed in
    /// [`manifest_json_with`]; both spellings are the same address, and
    /// `start` compares decoded bytes. The code hashes are the lab's real
    /// `EXTCODEHASH` values, copied from
    /// `contracts/deployments/31337.stream-g.payload.json`.
    pub(crate) fn deployment_payload_body(
        chain_id: &str,
        gateway_address: &str,
        gateway_code_hash: &str,
    ) -> String {
        deployment_payload_body_with_account(chain_id, gateway_address, gateway_code_hash, None)
    }

    /// [`deployment_payload_body`] with ONE of the eight `accounts` entries
    /// open, so a test can drift exactly one account address and nothing else.
    ///
    /// The defaults are the same lab deployment [`manifest_json_with`] carries,
    /// spelled lowercase because the payload schema now REFUSES anything else
    /// (spec `:244`); the manifest spells them EIP-55 and `start` compares
    /// decoded bytes, so the two documents agreeing is not a spelling
    /// coincidence.
    pub(crate) fn deployment_payload_body_with_account(
        chain_id: &str,
        gateway_address: &str,
        gateway_code_hash: &str,
        account_override: Option<(&str, &str)>,
    ) -> String {
        let mut accounts: Vec<(&str, String)> = vec![
            (
                "DESK_OWNER",
                "0x7fa9385be102ac3eac297483dd6233d62b3e1496".into(),
            ),
            (
                "ENROLLMENT_REGISTRY",
                "0x104fbc016f4bb334d775a19e8a6510109ac63e00".into(),
            ),
            (
                "FEE_SAFE",
                "0xd1ccc21678e1b7015a472216b2f501f421645b43".into(),
            ),
            (
                "FEE_TOKEN",
                "0xddc10602782af652bb913f7bde1fd82981db7dd9".into(),
            ),
            (
                "GOAT_COIN",
                "0x037eda3adb1198021a9b2e88c22b464fd38db3f3".into(),
            ),
            (
                "POLICY_SAFE",
                "0x7fa9385be102ac3eac297483dd6233d62b3e1496".into(),
            ),
            (
                "QUOTE_SIGNER",
                "0xebd5a85005dcc98dabb7a2888de82d43c5a6957e".into(),
            ),
            (
                "RECOVERY_SAFE",
                "0xb8705214e170151048eff0a1ede1824fff19cb9c".into(),
            ),
        ];
        if let Some((role, address)) = account_override {
            for entry in accounts.iter_mut() {
                if entry.0 == role {
                    entry.1 = address.to_string();
                }
            }
        }
        let accounts_json = accounts
            .iter()
            .map(|(k, v)| format!("\"{k}\": \"{v}\""))
            .collect::<Vec<_>>()
            .join(",\n                    ");
        format!(
            r#"{{
                "schemaVersion": "2",
                "deploymentVersion": "1",
                "chainId": "{chain_id}",
                "releaseCommit": "0000000000000000000000000000000000000000",
                "contracts": {{
                    "FEE_TOKEN_REGISTRY": {{
                        "address": "0x7fdb3132ff7d02d8b9e221c61cc895ce9a4bb773",
                        "runtimeCodeHash": "0xfba313e548e577b7511cbde7326a5afb713940d7c9d9de7f46e28df26ebf3b75"
                    }},
                    "GATEWAY": {{
                        "address": "{gateway_address}",
                        "runtimeCodeHash": "{gateway_code_hash}"
                    }},
                    "SPONSORED_BUY_DESK": {{
                        "address": "0xd76ffbd1eff76c510c3a509fe22864688ac3a588",
                        "runtimeCodeHash": "0xb31c7ccddd6577c6d2ac9ebdd3f3cd9f95d320198eade02a9e387277c6d36dae"
                    }},
                    "WALLET_SPONSORSHIP_REGISTRY": {{
                        "address": "0xfd07c974e33dd1626640ba3a5acf0418faacca7a",
                        "runtimeCodeHash": "0xdd985541ff21871feeeabdcc70ae3ce65a1f7f5b1bbf8249e1aa8ec170b735d4"
                    }}
                }},
                "accounts": {{
                    {accounts_json}
                }}
            }}"#
        )
    }

    /// The lab defaults for [`deployment_payload_body`].
    pub(crate) const FIXTURE_GATEWAY_CODE_HASH: &str =
        "0x474ebb2bf11d1462c26e0d5dab9cd8d326b81094d44041f43e31c143976531db";

    /// [`deployment_payload_body`] with every field at its lab default.
    pub(crate) fn default_deployment_payload_body() -> String {
        deployment_payload_body(
            "31337",
            &FIXTURE_GATEWAY.to_ascii_lowercase(),
            FIXTURE_GATEWAY_CODE_HASH,
        )
    }

    /// The `{schemaVersion, deploymentManifestHash, note, payload}` container.
    pub(crate) fn deployment_payload_json(
        deployment_manifest_hash: &str,
        payload_json: &str,
    ) -> String {
        format!(
            r#"{{
                "schemaVersion": 1,
                "deploymentManifestHash": "{deployment_manifest_hash}",
                "note": "test fixture",
                "payload": {payload_json}
            }}"#
        )
    }

    /// `keccak256(UTF8(RFC8785(normalised payload_json)))`, through the real
    /// loader rather than a second implementation — so a fixture can never
    /// publish a digest the loader would not compute.
    pub(crate) fn deployment_manifest_hash_hex(payload_json: &str) -> String {
        // The declared value is irrelevant to the computed one (approval
        // metadata is outside the payload), so a placeholder is used and the
        // computed side is what is returned.
        let doc = deployment_payload_json(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            payload_json,
        );
        let loaded =
            super::super::deployment_payload::DeploymentPayload::from_json(&doc, "<fixture>")
                .expect("fixture payload must load");
        format!(
            "0x{}",
            hex::encode(loaded.computed_deployment_manifest_hash())
        )
    }

    /// Write a manifest and a deployment payload that AGREE, and point the
    /// config at both.
    pub(crate) fn write_consistent_manifest_and_payload(
        dir: &Path,
        chain_id: u64,
        payload_json: &str,
        goat_relay_gateway: &str,
    ) {
        let hash = deployment_manifest_hash_hex(payload_json);
        std::fs::write(
            dir.join("manifest.json"),
            manifest_json_with(
                chain_id,
                &hash,
                FIXTURE_FEE_SCHEDULE_HASH,
                goat_relay_gateway,
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("deployment_payload.json"),
            deployment_payload_json(&hash, payload_json),
        )
        .unwrap();
    }

    pub(crate) fn write_consistent_manifest_and_schedule(
        dir: &Path,
        chain_id: u64,
        payload_json: &str,
    ) {
        let hash = schedule_hash_hex(payload_json);
        std::fs::write(
            dir.join("manifest.json"),
            manifest_json_with_fee_schedule_hash(chain_id, &hash),
        )
        .unwrap();
        std::fs::write(
            dir.join("fee_schedule.json"),
            fee_schedule_json(&hash, payload_json),
        )
        .unwrap();
    }

    /// A `STREAM_G_ENABLED=1` env map pointed at `dir`, with a valid manifest
    /// and a matching fee schedule already written. Mock mode stays on
    /// (inherited from `test_map`), so no RPC endpoint is contacted.
    ///
    /// The schedule declares [`FIXTURE_FEE_SCHEDULE_HASH`], which is both the
    /// digest of the payload it carries and what `manifest_json` publishes, so
    /// `start`'s two hash comparisons are satisfied. Every `actionFeesRaw`
    /// entry is `null`, matching the shipped
    /// `fixtures/stream_g_fee_schedule.json`: the Season-0 tariff is not a
    /// decided number, and a fixture that invented one would let a test assert
    /// a price no founder ever set.
    pub(crate) fn enabled_map(dir: &Path) -> HashMap<String, String> {
        let manifest_path = dir.join("manifest.json");
        std::fs::write(&manifest_path, manifest_json(31337)).unwrap();
        let fee_schedule_path = dir.join("fee_schedule.json");
        std::fs::write(
            &fee_schedule_path,
            fee_schedule_json(FIXTURE_FEE_SCHEDULE_HASH, &schedule_payload_json(None)),
        )
        .unwrap();

        let mut m = Config::test_map();
        m.insert("STREAM_G_ENABLED".into(), "1".into());
        m.insert(
            "STREAM_G_BROADCASTER_PRIVATE_KEY".into(),
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".into(),
        );
        m.insert(
            "STREAM_G_QUOTE_SIGNER_PRIVATE_KEY".into(),
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        );
        m.insert(
            "STREAM_G_ISSUER_PRIVATE_KEY".into(),
            "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a".into(),
        );
        m.insert("STREAM_G_DATA_KEY_HEX".into(), hex::encode([0x42u8; 32]));
        m.insert(
            "STREAM_G_DB_PATH".into(),
            dir.join("stream_g.db").display().to_string(),
        );
        m.insert(
            "STREAM_G_LOCK_PATH".into(),
            dir.join("stream_g.lock").display().to_string(),
        );
        m.insert(
            "STREAM_G_DEPLOYMENT_MANIFEST_PATH".into(),
            manifest_path.display().to_string(),
        );
        m.insert(
            "STREAM_G_FEE_SCHEDULE_PATH".into(),
            fee_schedule_path.display().to_string(),
        );
        m
    }

    pub(crate) fn enabled_cfg(dir: &Path) -> Config {
        config::load_from_map(&enabled_map(dir)).expect("stream G config must validate")
    }

    /// The **smallest** map that may start Stream G: the six `config::REQUIRED`
    /// keys (via [`Config::test_map`]), `STREAM_G_ENABLED=1`, and the four
    /// dedicated secrets `build_stream_g_config` refuses to load without.
    ///
    /// Deliberately does **not** set `STREAM_G_FEE_SCHEDULE_PATH`,
    /// `STREAM_G_DEPLOYMENT_MANIFEST_PATH`, `STREAM_G_DB_PATH` or
    /// `STREAM_G_LOCK_PATH` — that omission is the whole point, and
    /// [`enabled_map`] (which sets all four) cannot exercise it.
    ///
    /// `STATE_DIR` **is** set, to `dir`, and that is not a cheat: it is a
    /// pre-existing generic attestor knob with a working `./state` default, and
    /// every Stream G path default nests under it (`config.rs`'s `default_db`
    /// … `default_manifest`). A test that let it default would create
    /// `./state/stream_g.db` inside the crate directory and race every other
    /// test doing the same, because `cargo test` runs them concurrently. The
    /// claim under test is "no *Stream G* path needs configuring", and this map
    /// makes exactly that claim.
    ///
    /// Secrets are the same anvil-derived values [`enabled_map`] uses. Mock
    /// mode is inherited from [`Config::test_map`], so no RPC is contacted.
    pub(crate) fn minimal_map(dir: &Path) -> HashMap<String, String> {
        let mut m = Config::test_map();
        m.insert("STATE_DIR".into(), dir.display().to_string());
        m.insert("STREAM_G_ENABLED".into(), "1".into());
        m.insert(
            "STREAM_G_BROADCASTER_PRIVATE_KEY".into(),
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".into(),
        );
        m.insert(
            "STREAM_G_QUOTE_SIGNER_PRIVATE_KEY".into(),
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        );
        m.insert(
            "STREAM_G_ISSUER_PRIVATE_KEY".into(),
            "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a".into(),
        );
        m.insert("STREAM_G_DATA_KEY_HEX".into(), hex::encode([0x42u8; 32]));
        m
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{enabled_cfg, enabled_map, manifest_json};
    use super::*;
    use crate::config;

    /// The whole point of the wave: `StreamGStore::open` now has a production
    /// call site, and the store it returns is WAL / FK-on / FULL / bounded-
    /// busy-timeout and fully migrated.
    ///
    /// Mutation this detects: `store::SCHEMA_VERSION` (via
    /// `supported_schema_version`) drifting from what `MIGRATIONS` actually
    /// applies — i.e. `start` handing back a state whose store is not fully
    /// migrated. Verified by bumping `SCHEMA_VERSION` to `3` with no third
    /// migration: `open` then leaves the file at 2 and this test fails on the
    /// `schema_version` assertion.
    #[tokio::test]
    async fn start_opens_a_migrated_wal_store_and_exposes_it_as_state() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_cfg(dir.path());
        let controller = ShutdownController::new();

        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start must succeed on a fresh state dir");

        assert_eq!(
            i64::from(state.store().schema_version()),
            store::supported_schema_version(),
            "start must leave the store fully migrated (1 -> 2)"
        );
        let pragmas = state.store().read_pragmas().await.expect("pragmas");
        assert_eq!(pragmas.journal_mode, "wal");
        assert_eq!(pragmas.foreign_keys, 1);
        assert_eq!(pragmas.synchronous, 2, "FULL");
        assert!(
            pragmas.busy_timeout_ms > 0 && pragmas.busy_timeout_ms <= 60_000,
            "busy_timeout must be bounded, got {}",
            pragmas.busy_timeout_ms
        );
        assert!(!state.store().db_uuid().is_empty());
        assert_eq!(state.manifest().chain_id, 31337);
    }

    /// Spec §9.3: "Startup must acquire an OS-level exclusive lock on a Stream
    /// G lock file adjacent to the database and fail readiness if another
    /// owner holds it; policy documentation alone is not sufficient." This is
    /// the enforcement test — the lock must be held *by the returned state*,
    /// for as long as it lives, not merely taken and dropped inside `start`.
    ///
    /// Mutation this detects: deleting the `file.try_lock_exclusive()` call in
    /// `store::acquire_instance_lock` — the property lives there, and this is
    /// the first test that asserts it *through* `StreamGState::start`, i.e.
    /// that the state Wave A hands the router is the lock's owner. With the
    /// lock removed the second `start` succeeds and the `expect_err` panics.
    #[tokio::test]
    async fn start_holds_the_os_instance_lock_for_the_life_of_the_state() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_cfg(dir.path());
        let controller = ShutdownController::new();

        let first = StreamGState::start(&cfg, controller.token())
            .await
            .expect("first start");

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a second owner must be refused while the first state is alive");
        let rendered = err.to_string();
        assert!(
            rendered.contains("instance lock"),
            "expected an instance-lock refusal, got: {rendered}"
        );

        // Paired positive arm: once the first owner is gone the lock is
        // released and a new owner can take it. Without this, the assertion
        // above would also pass if `start` were broken for *every* call.
        drop(first);
        let second = StreamGState::start(&cfg, controller.token())
            .await
            .expect("lock must be released when the state is dropped");
        assert_eq!(
            i64::from(second.store().schema_version()),
            store::supported_schema_version()
        );
    }

    /// `config::load_from_map` only checks that `STREAM_G_DATA_KEY_HEX` is
    /// *present* (see `config::build_stream_g_config`), so startup is the
    /// first place a malformed key can be rejected. It must be rejected
    /// before any route is mounted, not at the first seal.
    ///
    /// Mutation this detects: dropping the `DataKey::from_hex` call from
    /// `start` (or making it `let _ = ...;`).
    #[tokio::test]
    async fn start_rejects_a_malformed_data_key_that_config_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = enabled_map(dir.path());
        // 31 bytes, not 32 — exactly the shape `config.rs`'s own tests use.
        map.insert(
            "STREAM_G_DATA_KEY_HEX".into(),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddee".into(),
        );
        let cfg =
            config::load_from_map(&map).expect("config accepts a short key; startup must not");
        let controller = ShutdownController::new();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a 31-byte data key must fail startup");
        assert!(
            matches!(err, StreamGStartupError::DataKey(_)),
            "expected a DataKey error, got: {err}"
        );

        // Paired positive arm: the same config with a well-formed key starts.
        let mut ok_map = enabled_map(dir.path());
        ok_map.insert("STREAM_G_DATA_KEY_HEX".into(), hex::encode([0x7Au8; 32]));
        let ok_cfg = config::load_from_map(&ok_map).unwrap();
        StreamGState::start(&ok_cfg, controller.token())
            .await
            .expect("a 32-byte key must start");
    }

    /// A manifest for the wrong chain must not mount. `load_deployment_manifest`
    /// owns the check; this proves `start` actually calls it.
    ///
    /// Mutation this detects: passing a hard-coded chain id to
    /// `load_deployment_manifest` instead of `cfg.chain_id` — verified with
    /// `84532`, which makes the foreign-chain manifest load cleanly and the
    /// `expect_err` panic.
    #[tokio::test]
    async fn start_refuses_a_manifest_for_a_different_chain() {
        let dir = tempfile::tempdir().unwrap();
        let map = enabled_map(dir.path());
        // Overwrite the manifest the helper wrote with a foreign-chain one.
        std::fs::write(dir.path().join("manifest.json"), manifest_json(84532)).unwrap();
        let cfg = config::load_from_map(&map).unwrap();
        assert_eq!(cfg.chain_id, 31337, "test_map pins the configured chain");
        let controller = ShutdownController::new();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("manifest chainId 84532 vs configured 31337 must refuse");
        assert!(
            matches!(err, StreamGStartupError::Manifest { .. }),
            "expected a Manifest error, got: {err}"
        );

        // Paired positive arm: the matching manifest starts.
        std::fs::write(dir.path().join("manifest.json"), manifest_json(31337)).unwrap();
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("a matching manifest must start");
    }

    /// `start` is not a silent no-op when Stream G is off — a caller that
    /// forgets the `cfg.stream_g.enabled` check gets an error, not a store.
    ///
    /// Mutation this detects: deleting the `if !cfg.stream_g.enabled` guard.
    #[tokio::test]
    async fn start_refuses_when_stream_g_is_disabled() {
        let cfg = config::load_from_map(&Config::test_map()).unwrap();
        assert!(!cfg.stream_g.enabled);
        let controller = ShutdownController::new();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("must refuse with STREAM_G_ENABLED=0");
        assert!(matches!(err, StreamGStartupError::Disabled), "{err}");
    }

    /// Mock mode must not produce a live-read capability. The field is typed
    /// `Option<Arc<RpcChain>>`, so this is really a check that `start` maps
    /// `mock_mode` to `None` rather than trying to build an `RpcChain` against
    /// the fake RPC URL.
    ///
    /// Mutation this detects: inverting the `if cfg.mock_mode` branch.
    #[tokio::test]
    async fn mock_mode_yields_no_trusted_chain() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_cfg(dir.path());
        assert!(cfg.mock_mode, "test_map sets GOAT_ATTESTOR_MOCK=1");
        let controller = ShutdownController::new();

        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");
        assert!(state.live_chain().is_none());
        assert!(state.trusted_chain().is_none());
    }

    /// The shutdown token reaches handlers (and, in Wave D, the sweeper)
    /// through the same state axum hands them.
    ///
    /// Mutation this detects: `start` building its own fresh
    /// `ShutdownController::new().token()` instead of storing the one it was
    /// given — the state's token would then never observe the caller's cancel.
    #[tokio::test]
    async fn state_carries_the_callers_shutdown_token() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_cfg(dir.path());
        let controller = ShutdownController::new();

        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");
        assert!(
            !state.shutdown().is_cancelled(),
            "not cancelled before cancel()"
        );

        controller.cancel();
        assert!(
            state.shutdown().is_cancelled(),
            "the state's token must observe the caller's cancel"
        );
        state.shutdown().cancelled().await;
    }

    /// Cancellation is latched, not edge-triggered: a token taken *after*
    /// `cancel()` must resolve immediately rather than wait for a second
    /// cancel that will never come.
    ///
    /// Mutation this detects: replacing `send_replace(true)` with
    /// `let _ = self.tx.send(true);` — with no receiver alive at cancel time
    /// `send` drops the value and a later token hangs forever.
    #[tokio::test]
    async fn a_token_taken_after_cancel_is_already_cancelled() {
        let controller = ShutdownController::new();
        controller.cancel();
        assert!(controller.is_cancelled());

        let late = controller.token();
        assert!(late.is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(5), late.cancelled())
            .await
            .expect("a late token must resolve immediately, not hang");
    }

    /// An uncancelled token must *not* resolve — otherwise
    /// `.with_graceful_shutdown(token.cancelled())` would terminate the server
    /// the instant it started serving.
    ///
    /// Mutation this detects: making `cancelled()` return unconditionally, or
    /// having it treat the initial `false` value as a cancellation.
    #[tokio::test]
    async fn an_uncancelled_token_does_not_resolve() {
        let controller = ShutdownController::new();
        let token = controller.token();
        assert!(!token.is_cancelled());

        let timed_out =
            tokio::time::timeout(std::time::Duration::from_millis(150), token.cancelled())
                .await
                .is_err();
        assert!(timed_out, "an uncancelled token must stay pending");

        // Paired positive arm: the same token resolves once cancelled.
        controller.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), token.cancelled())
            .await
            .expect("must resolve after cancel");
    }

    /// A token still resolves when every controller has been dropped — a
    /// background task must not outlive its owner waiting on a latch nobody
    /// can flip.
    #[tokio::test]
    async fn a_token_resolves_when_the_controller_is_dropped() {
        let controller = ShutdownController::new();
        let token = controller.token();
        drop(controller);
        tokio::time::timeout(std::time::Duration::from_secs(5), token.cancelled())
            .await
            .expect("dropping the controller must release waiters");
    }

    /// **Pilot safety.** `.with_graceful_shutdown(..)` changes how the Stream
    /// B pilot's server terminates, so it may only be installed when Stream G
    /// is enabled. With `STREAM_G_ENABLED=0` `main.rs` must take the plain
    /// arm — the same `axum::serve(listener, app).await` it ran before Task 8.
    ///
    /// Mutation this detects: `ServeMode::for_config` returning
    /// `StreamGGraceful` unconditionally (i.e. someone "simplifying" the match
    /// in `cmd_serve_relayer` into an unconditional graceful serve).
    #[test]
    fn serve_mode_is_plain_for_the_pilot_and_graceful_only_for_stream_g() {
        let pilot = config::load_from_map(&Config::test_map()).unwrap();
        assert!(!pilot.stream_g.enabled);
        assert_eq!(ServeMode::for_config(&pilot), ServeMode::PilotPlain);
        assert!(!ServeMode::for_config(&pilot).installs_graceful_shutdown());

        let dir = tempfile::tempdir().unwrap();
        let enabled = enabled_cfg(dir.path());
        assert!(enabled.stream_g.enabled);
        assert_eq!(ServeMode::for_config(&enabled), ServeMode::StreamGGraceful);
        assert!(ServeMode::for_config(&enabled).installs_graceful_shutdown());
    }

    /// `Debug` on the state must never print key material. `DataKey`'s own
    /// `Debug` is redacted; this guards the wrapper that could re-expose it.
    #[tokio::test]
    async fn state_debug_never_prints_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = enabled_map(dir.path());
        let key_hex = hex::encode([0x42u8; 32]);
        map.insert("STREAM_G_DATA_KEY_HEX".into(), key_hex.clone());
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");

        let rendered = format!("{state:?}");
        assert!(
            !rendered.contains(&key_hex),
            "state Debug leaked the data key"
        );
        assert!(
            !rendered.contains(
                &cfg.stream_g
                    .broadcaster_private_key
                    .clone()
                    .unwrap_or_default()
            ),
            "state Debug leaked the broadcaster key"
        );
        // The quote signer key *is* held on this state (Wave B foundation), so
        // unlike the broadcaster key above this arm is guarding a value that is
        // actually in the struct being rendered.
        assert!(
            !rendered.contains(
                cfg.stream_g
                    .quote_signer_private_key
                    .as_deref()
                    .expect("enabled config carries a quote signer key")
            ),
            "state Debug leaked the quote signer key"
        );
        // Paired positive arm: it does print the non-secret identifiers, so
        // the assertions above are not passing on an empty string.
        assert!(rendered.contains("data_key_id"), "{rendered}");
        assert!(
            rendered.contains(state.data_key().key_id()),
            "key_id is a hash prefix and is safe to print: {rendered}"
        );
    }

    // -- Task 11 Wave 0 ---------------------------------------------------

    /// `start` used to parse the hex into a `DataKey` and **drop it**, which
    /// left every `profile_auth` / `outbox` / `submit` / `onboarding` /
    /// `quotes` entry point — all of which take the hex — unreachable from a
    /// handler.
    ///
    /// Two separate claims, because one test of mine originally conflated
    /// them and a mutation run caught it:
    ///
    /// 1. **The two copies in `Inner` are the same key.** `state.data_key()`
    ///    and `state.data_key_hex()` must agree, or code that seals with one
    ///    and indexes with the other (readiness canaries vs `profile_auth`)
    ///    silently diverges. Asserted via `key_id`, which is derived from the
    ///    key bytes and is safe to compare in the open.
    /// 2. **The hex is actually usable from a handler.** A `profile_auth`
    ///    round trip — `create_profile` then `authenticate_credential` —
    ///    driven with nothing but the state.
    ///
    /// Claim 2 alone is **not** sufficient for claim 1, which is the trap:
    /// every `profile_auth` entry point takes the same hex, so a round trip
    /// built on a *wrong* stored key is still self-consistent and still
    /// passes. Claim 1's assertion is what fails when the two diverge.
    ///
    /// **Mutation this detects (applied, run, reverted):** in `start`, store
    /// `SecretHex::from_hex(&hex::encode([0u8; 32]))` instead of the parsed
    /// hex. The `key_id` assertion fails; the round trip alone does not.
    #[tokio::test]
    async fn state_carries_the_data_key_hex_and_it_actually_drives_profile_auth() {
        use crate::stream_g::profile_auth;

        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_cfg(dir.path());
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");

        // Claim 1: same key, two representations.
        assert_eq!(
            state.data_key_hex().key_id(),
            state.data_key().key_id(),
            "the stored hex and the parsed DataKey must be the same key"
        );
        assert_eq!(
            state.data_key_hex().as_str(),
            cfg.stream_g.data_key_hex.as_deref().unwrap(),
            "and it must be the key the operator configured"
        );

        // The handler-side call shape: pass the `&SecretHex` straight through.
        let created = profile_auth::create_profile(state.store(), state.data_key_hex(), "idem-w0")
            .await
            .expect("create_profile must be reachable from state alone");

        let authenticated = profile_auth::authenticate_credential(
            state.store(),
            state.data_key_hex(),
            &created.credential,
        )
        .await
        .expect("credential must authenticate");
        assert_eq!(authenticated.as_str(), created.profile_id);

        // Discriminating control: a *different* key must not authenticate the
        // same credential, so the success above is about this key and not
        // about `authenticate_credential` accepting anything.
        let other = SecretHex::from_hex(&hex::encode([0x01u8; 32])).unwrap();
        assert!(
            profile_auth::authenticate_credential(state.store(), &other, &created.credential)
                .await
                .is_err(),
            "a foreign data key must not resolve this credential"
        );
    }

    /// The quote signer key had the same reachability gap the data key hex had
    /// before Wave 0: `EnrollmentQuoteContext::quote_signer_private_key_hex`
    /// is mandatory and `quotes::create_sponsored_enrollment_quote_at`'s
    /// STEP 8 consumes it, yet nothing on this state carried the key.
    ///
    /// Two claims, and the second is the one that would silently rot:
    ///
    /// 1. **It is the operator's key**, not the data key and not some other
    ///    configured secret — asserted through the *address* the key derives
    ///    to, which is the only property a quote's verifier cares about.
    /// 2. **The stored form is still parseable by the consumer.** `start`
    ///    strips the `0x` prefix that `STREAM_G_QUOTE_SIGNER_PRIVATE_KEY`
    ///    carries in every real config, because `SecretHex::from_hex` rejects
    ///    it. That normalization is only safe if `PrivateKeySigner::from_str` —
    ///    the exact call `create_sponsored_enrollment_quote_at` makes at
    ///    STEP 8 — still accepts the result, so
    ///    this test makes that call rather than assuming alloy's decoder is
    ///    prefix-agnostic.
    ///
    /// **Mutations this detects:** storing `data_key_hex` in the quote signer
    /// field (the address assertion fails — the two are different keys); and
    /// dropping the `strip_prefix("0x")` in `start` (startup itself fails, so
    /// every assertion below is unreachable).
    #[tokio::test]
    async fn state_carries_the_quote_signer_key_in_the_form_the_signer_takes() {
        use alloy::signers::local::PrivateKeySigner;
        use std::str::FromStr;

        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_cfg(dir.path());
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");

        // Claim 2: the handler-side call shape, verbatim from STEP 8 of
        // `quotes::create_sponsored_enrollment_quote_at`.
        let stored = PrivateKeySigner::from_str(state.quote_signer_key_hex().as_str())
            .expect("the stored hex must still be a signer key after normalization");

        // Claim 1: same key the operator configured, compared by address.
        let configured =
            PrivateKeySigner::from_str(cfg.stream_g.quote_signer_private_key.as_deref().unwrap())
                .expect("fixture key");
        assert_eq!(
            stored.address(),
            configured.address(),
            "state must carry STREAM_G_QUOTE_SIGNER_PRIVATE_KEY, not some other secret"
        );

        // Discriminating control: the state's *other* secret is a different
        // key, so the equality above is not passing because every key in this
        // fixture happens to be the same one.
        assert_ne!(
            state.quote_signer_key_hex().key_id(),
            state.data_key_hex().key_id(),
            "the quote signer must not be aliased to the at-rest data key"
        );
    }

    /// Config validates only that `STREAM_G_QUOTE_SIGNER_PRIVATE_KEY` is
    /// *present* (`config::build_stream_g_config`), exactly as it does for the
    /// data key, so startup is again the first place a malformed value can be
    /// refused. A quote *is* its signature; discovering at
    /// `create_sponsored_enrollment_quote_at`'s STEP 8 that the key
    /// never parsed would mean the route mounted, answered, and failed on a
    /// real caller's request.
    ///
    /// Mutation this detects: dropping the `SecretHex::from_hex` call in
    /// `start` and storing the raw config string.
    #[tokio::test]
    async fn start_rejects_a_malformed_quote_signer_key_that_config_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = enabled_map(dir.path());
        // 31 bytes, not 32 — the same shape the data-key test uses, still
        // `0x`-prefixed so this is about the length and not about the prefix.
        map.insert(
            "STREAM_G_QUOTE_SIGNER_PRIVATE_KEY".into(),
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddee".into(),
        );
        let cfg =
            config::load_from_map(&map).expect("config accepts a short key; startup must not");
        let controller = ShutdownController::new();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a 31-byte quote signer key must fail startup");
        assert!(
            matches!(err, StreamGStartupError::QuoteSignerKey(_)),
            "expected a QuoteSignerKey error, got: {err}"
        );

        // Paired positive arm: the same fixture with its normal key starts, so
        // the refusal above is about the key and not about the directory.
        let ok_cfg = enabled_cfg(dir.path());
        StreamGState::start(&ok_cfg, controller.token())
            .await
            .expect("the unmodified fixture must start");
    }

    /// `max_native_exposure_wei` reaches the state from config. Hazard 1's
    /// ceiling had no production source at all — `SubmitContext` and
    /// `EnrollmentQuoteContext` both document that they never receive it.
    ///
    /// This asserts **plumbing only**. It does NOT close hazard 1: nothing is
    /// yet enforcing the ceiling on a mounted route, and the config default of
    /// `0` still presents an unset variable as a total outage.
    ///
    /// **Mutation this detects (applied, run, reverted):** hard-coding
    /// `WeiCeiling::new(0)` in `start` instead of reading
    /// `cfg.stream_g.max_native_exposure_wei` — the first assertion fails.
    #[tokio::test]
    async fn state_carries_the_configured_native_exposure_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = enabled_map(dir.path());
        map.insert(
            "STREAM_G_MAX_NATIVE_EXPOSURE_WEI".into(),
            "123456789".into(),
        );
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");
        assert_eq!(state.max_native_exposure_wei().get(), 123_456_789);

        // Discriminating control: a different configured value produces a
        // different ceiling, so the assertion above is not matching a
        // constant that happens to equal the fixture.
        drop(state);
        let dir2 = tempfile::tempdir().unwrap();
        let mut map2 = enabled_map(dir2.path());
        map2.insert("STREAM_G_MAX_NATIVE_EXPOSURE_WEI".into(), "42".into());
        let cfg2 = config::load_from_map(&map2).unwrap();
        let state2 = StreamGState::start(&cfg2, controller.token())
            .await
            .expect("start");
        assert_eq!(state2.max_native_exposure_wei().get(), 42);
    }

    /// The pinned known-answer fixture the spec asks for at
    /// the "Stream G — USDT Gas Abstraction and Multi-Wallet Sponsoring"
    /// spec, §8.1
    /// ("Rust/JavaScript/ops fixtures pin the canonical bytes and hash").
    ///
    /// Every other fixture here computes the digest from the payload, so they
    /// would all keep agreeing with each other after an accidental payload
    /// edit or a canonicaliser change. This one does not: it is the single
    /// place a constant is compared to a computation.
    ///
    /// **Mutation this detects:** any edit to `schedule_payload_json`'s
    /// literal — a changed field, value, or spelling — and any change to
    /// `canonical_json`'s output bytes.
    #[test]
    fn fixture_schedule_payload_hashes_to_the_pinned_manifest_value() {
        use super::test_support::{
            schedule_hash_hex, schedule_payload_json, FIXTURE_FEE_SCHEDULE_HASH,
        };

        assert_eq!(
            schedule_hash_hex(&schedule_payload_json(None)),
            FIXTURE_FEE_SCHEDULE_HASH,
            "the fixture payload's digest moved; update FIXTURE_FEE_SCHEDULE_HASH only if the \
             payload change was intended, because every manifest fixture publishes this value"
        );

        // Discriminating control: setting a tariff must move the digest, or
        // the "hash binds the values" claim would be empty.
        assert_ne!(
            schedule_hash_hex(&schedule_payload_json(Some("500000"))),
            FIXTURE_FEE_SCHEDULE_HASH,
            "a payload carrying a tariff must not hash to the payload that carries none"
        );
    }

    /// **File-level honesty.** The payload was edited and the declared
    /// `feeScheduleHash` left alone — the exact edit the old governance-tag
    /// binding could not see, and the reason this task exists.
    ///
    /// Kept distinct from the deployment mismatch below because the operator's
    /// next move differs: here the file contradicts itself, and only the
    /// operator knows whether the edit or the declaration is the mistake.
    ///
    /// **Mutation this detects (applied, run, reverted):** deleting the
    /// `if computed != declared` block from `start` — the edited schedule is
    /// still refused, but as a `FeeScheduleHashMismatch`, which sends the
    /// operator to the deployment when the fault is in the file in front of
    /// them. The `matches!` assertion below fails on exactly that swap.
    #[tokio::test]
    async fn start_refuses_a_fee_schedule_whose_payload_does_not_match_its_declared_hash() {
        use super::test_support::{
            fee_schedule_json, schedule_payload_json, FIXTURE_FEE_SCHEDULE_HASH,
        };

        let dir = tempfile::tempdir().unwrap();
        let map = enabled_map(dir.path());
        let schedule_path = dir.path().join("fee_schedule.json");
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();

        // A tariff appears; the declared hash still names the tariff-free
        // payload the deployment approved.
        std::fs::write(
            &schedule_path,
            fee_schedule_json(
                FIXTURE_FEE_SCHEDULE_HASH,
                &schedule_payload_json(Some("500000")),
            ),
        )
        .unwrap();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a payload edited without republishing its hash must not mount");
        assert!(
            matches!(err, StreamGStartupError::FeeScheduleHashSelfMismatch { .. }),
            "expected a self-mismatch, got: {err}"
        );
        let rendered = err.to_string();
        // Both values, and the digest the operator would have to republish.
        assert!(
            rendered.contains(FIXTURE_FEE_SCHEDULE_HASH.trim_start_matches("0x")),
            "the declared value must be shown: {rendered}"
        );
        assert!(
            rendered.contains(
                super::test_support::schedule_hash_hex(&schedule_payload_json(Some("500000")))
                    .trim_start_matches("0x")
            ),
            "the computed value must be shown: {rendered}"
        );
        assert!(
            rendered.contains("STREAM_G_FEE_SCHEDULE_HASH"),
            "the operator must be told how to republish: {rendered}"
        );

        // Paired positive arm: the same tariff, with BOTH the file's
        // declaration and the manifest republished, starts. Without this the
        // refusal above would also hold if `start` were broken for every
        // schedule that carries a price.
        super::test_support::write_consistent_manifest_and_schedule(
            dir.path(),
            31337,
            &schedule_payload_json(Some("500000")),
        );
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("a republished schedule must start");
    }

    /// **Deployment-level honesty.** The file is internally consistent — its
    /// payload hashes to what it declares — but that digest is not the one the
    /// deployment manifest published. Most often a schedule file left behind
    /// across a manifest republish.
    ///
    /// `models::fee_quote_struct_hash` signs `manifest.fee_schedule_hash` into
    /// every quote, so mounting here would sign an attestation to amounts this
    /// deployment never approved.
    ///
    /// **Mutation this detects (applied, run, reverted):** deleting the
    /// `if computed != manifest.fee_schedule_hash` block from `start` — the
    /// foreign schedule then mounts and `expect_err` panics.
    #[tokio::test]
    async fn start_refuses_a_fee_schedule_this_deployment_did_not_publish() {
        use super::test_support::{fee_schedule_json, schedule_hash_hex, schedule_payload_json};

        let dir = tempfile::tempdir().unwrap();
        let map = enabled_map(dir.path());
        let schedule_path = dir.path().join("fee_schedule.json");
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();

        // Self-consistent, and about a schedule with a price. The manifest
        // written by `enabled_map` publishes the tariff-free payload's digest.
        let foreign = schedule_payload_json(Some("500000"));
        let foreign_hash = schedule_hash_hex(&foreign);
        std::fs::write(&schedule_path, fee_schedule_json(&foreign_hash, &foreign)).unwrap();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a schedule this deployment never published must not mount");
        assert!(
            matches!(err, StreamGStartupError::FeeScheduleHashMismatch { .. }),
            "expected a deployment mismatch, got: {err}"
        );
        // The operator has to be able to see *both* values to fix this.
        let rendered = err.to_string();
        assert!(
            rendered.contains(foreign_hash.trim_start_matches("0x")),
            "the file's own digest must be shown: {rendered}"
        );
        assert!(
            rendered
                .contains(super::test_support::FIXTURE_FEE_SCHEDULE_HASH.trim_start_matches("0x")),
            "the manifest's published digest must be shown: {rendered}"
        );

        // Paired positive arm: the schedule the manifest DID publish starts.
        std::fs::write(
            &schedule_path,
            fee_schedule_json(
                super::test_support::FIXTURE_FEE_SCHEDULE_HASH,
                &schedule_payload_json(None),
            ),
        )
        .unwrap();
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("the published schedule must start");
    }

    /// The auditor's scenario, ported verbatim: a payload authored for Base
    /// (`chainId "8453"`, an 18-decimal token, a `1000000000000000000` tariff)
    /// whose digest is internally consistent AND is what the 31337 manifest
    /// publishes. Both digest comparisons pass. It must still be refused.
    ///
    /// **This is the defect, not a hypothetical.** The auditor built
    /// `goat-attestor.exe`, ran it with exactly these values on
    /// `CHAIN_ID=31337`, and got a clean start logging
    /// `fee_schedule_has_tariff=true`. `quotes::FeeSchedule::load` used to
    /// claim "a payload for another chain cannot match a manifest that
    /// published this one's digest"; republishing is precisely how it can.
    ///
    /// The tariff sits in the enrollment slot rather than the auditor's
    /// `GOAT_STREAM_G_SPONSORED_SELL_V1` because that is the slot
    /// [`test_support::schedule_payload_json_for`] parameterises; the
    /// comparison under test reads `payload.chainId` and never looks at which
    /// action carries an amount.
    ///
    /// **Mutation this detects:** deleting the `payload_chain_id` block from
    /// `start` — the foreign payload then mounts and `expect_err` panics.
    #[tokio::test]
    async fn start_refuses_a_fee_schedule_authored_for_another_chain() {
        use super::test_support::{
            fee_schedule_json, manifest_json_with_fee_schedule_hash, schedule_hash_hex,
            schedule_payload_json, schedule_payload_json_for,
        };

        let dir = tempfile::tempdir().unwrap();
        let map = enabled_map(dir.path());
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();

        let foreign = schedule_payload_json_for(
            "8453",
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "18",
            Some("1000000000000000000"),
        );
        let foreign_hash = schedule_hash_hex(&foreign);
        // The republish that made the auditor's run start: the SAME digest in
        // the file and in a chainId-31337 manifest.
        std::fs::write(
            dir.path().join("manifest.json"),
            manifest_json_with_fee_schedule_hash(31337, &foreign_hash),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("fee_schedule.json"),
            fee_schedule_json(&foreign_hash, &foreign),
        )
        .unwrap();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a payload authored for another chain must not mount");
        assert!(
            matches!(err, StreamGStartupError::FeeScheduleChainMismatch { .. }),
            "expected a chain mismatch — NOT a digest mismatch, the digests agree here — got: {err}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("8453") && rendered.contains("31337"),
            "both chain ids must be named: {rendered}"
        );

        // Paired positive arm: the same republish flow with a payload that
        // names THIS deployment starts, so the refusal above is about the
        // chain id and not about republishing.
        super::test_support::write_consistent_manifest_and_schedule(
            dir.path(),
            31337,
            &schedule_payload_json(Some("500000")),
        );
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("a schedule authored for this deployment must start");
    }

    /// The same republish, on the right chain, naming the wrong token.
    ///
    /// Kept separate from the chain test because the operator's fix differs and
    /// because the chain comparison runs first: a payload that is wrong about
    /// both never exercises this one. The harm is specific — the signed
    /// `FeeQuote` takes `feeToken` from the MANIFEST
    /// (`models::fee_quote_struct_hash`), so amounts priced for another token
    /// would be charged in this deployment's token.
    ///
    /// **Mutation this detects:** deleting the `payload_fee_token` block from
    /// `start` — `expect_err` panics.
    #[tokio::test]
    async fn start_refuses_a_fee_schedule_naming_another_fee_token() {
        use super::test_support::{
            fee_schedule_json, manifest_json_with_fee_schedule_hash, schedule_hash_hex,
            schedule_payload_json_for,
        };

        let dir = tempfile::tempdir().unwrap();
        let map = enabled_map(dir.path());
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();

        let wrong_token = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let foreign = schedule_payload_json_for("31337", wrong_token, "6", Some("500000"));
        let foreign_hash = schedule_hash_hex(&foreign);
        std::fs::write(
            dir.path().join("manifest.json"),
            manifest_json_with_fee_schedule_hash(31337, &foreign_hash),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("fee_schedule.json"),
            fee_schedule_json(&foreign_hash, &foreign),
        )
        .unwrap();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a payload pricing another token must not mount");
        assert!(
            matches!(err, StreamGStartupError::FeeScheduleFeeTokenMismatch { .. }),
            "expected a fee-token mismatch, got: {err}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains(wrong_token.trim_start_matches("0x")),
            "the payload's token must be named: {rendered}"
        );
        assert!(
            // The manifest spells it checksummed; the message renders decoded
            // bytes, so it must appear lowercase.
            rendered.contains("ddc10602782af652bb913f7bde1fd82981db7dd9"),
            "the deployment's token must be named: {rendered}"
        );

        // Paired positive arm: the identical file with only the token
        // corrected starts. Without this the refusal would also hold if
        // `start` rejected every republished schedule.
        let correct = schedule_payload_json_for(
            "31337",
            "0xddc10602782af652bb913f7bde1fd82981db7dd9",
            "6",
            Some("500000"),
        );
        let correct_hash = schedule_hash_hex(&correct);
        std::fs::write(
            dir.path().join("manifest.json"),
            manifest_json_with_fee_schedule_hash(31337, &correct_hash),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("fee_schedule.json"),
            fee_schedule_json(&correct_hash, &correct),
        )
        .unwrap();
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("a schedule naming this deployment's fee token must start");
    }

    /// The property the two refusals above must not destroy: a payload that
    /// agrees with the deployment still starts — **including when the manifest
    /// and the payload spell the same fee token in different case**, which is
    /// the shipped situation and the obvious way to introduce a
    /// case-sensitivity bug while "fixing" this.
    ///
    /// The two `assert!`s on the fixture text are what make this
    /// non-tautological: they prove the two documents really do differ as text,
    /// so a byte-wise comparison is doing work a string comparison would fail.
    #[tokio::test]
    async fn start_accepts_a_schedule_that_agrees_with_the_deployment() {
        use super::test_support::{manifest_json, schedule_payload_json};

        assert!(
            manifest_json(31337)
                .contains("\"feeToken\": \"0xDDc10602782af652bB913f7bdE1fD82981Db7dd9\""),
            "precondition: the manifest fixture spells the fee token checksummed"
        );
        assert!(
            schedule_payload_json(None)
                .contains("\"feeToken\": \"0xddc10602782af652bb913f7bde1fd82981db7dd9\""),
            "precondition: the payload fixture spells the same token lowercase, as the digest \
             rule requires"
        );

        let dir = tempfile::tempdir().unwrap();
        let map = enabled_map(dir.path());
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();

        super::test_support::write_consistent_manifest_and_schedule(
            dir.path(),
            31337,
            &schedule_payload_json(Some("500000")),
        );
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("one address in two legal spellings is not a mismatch");
    }

    // -----------------------------------------------------------------------
    // deploymentManifestHash: content binding
    //
    // Every test below writes a REAL deployment payload file and points
    // STREAM_G_DEPLOYMENT_PAYLOAD_PATH at it, so the refusal exercised is the
    // one an operator would hit, not a fall-through to the built-in. Each
    // negative arm is paired with a positive one: without the pair, a `start`
    // that refused every payload would pass all of them.
    // -----------------------------------------------------------------------

    /// Point `cfg` at a real payload file next to the manifest.
    fn map_with_payload_file(dir: &std::path::Path) -> std::collections::HashMap<String, String> {
        let mut map = enabled_map(dir);
        map.insert(
            "STREAM_G_DEPLOYMENT_PAYLOAD_PATH".into(),
            dir.join("deployment_payload.json").display().to_string(),
        );
        map
    }

    /// The baseline: a payload and a manifest that agree start cleanly, and
    /// they agree ACROSS a casing difference — the payload spells the gateway
    /// lowercase (as the digest rule normalises it) and the manifest spells it
    /// EIP-55 checksummed (as `vm.serializeAddress` writes it).
    #[tokio::test]
    async fn start_accepts_a_deployment_payload_that_agrees_with_the_deployment() {
        use super::test_support::{default_deployment_payload_body, FIXTURE_GATEWAY};

        assert!(
            FIXTURE_GATEWAY.chars().any(|c| c.is_ascii_uppercase()),
            "precondition: the manifest fixture spells the gateway checksummed, or this test \
             proves nothing about two spellings of one address"
        );
        assert!(
            default_deployment_payload_body().contains(&FIXTURE_GATEWAY.to_ascii_lowercase()),
            "precondition: the payload fixture spells the same gateway lowercase"
        );

        let dir = tempfile::tempdir().unwrap();
        let cfg = config::load_from_map(&map_with_payload_file(dir.path())).unwrap();
        let controller = ShutdownController::new();
        super::test_support::write_consistent_manifest_and_payload(
            dir.path(),
            31337,
            &default_deployment_payload_body(),
            FIXTURE_GATEWAY,
        );

        StreamGState::start(&cfg, controller.token())
            .await
            .expect("an agreeing payload must start");
    }

    /// MUTATE ONE CONTRACT ADDRESS IN THE PAYLOAD. Under the retired tag this
    /// edit moved nothing; now it moves the digest and startup refuses.
    #[tokio::test]
    async fn start_refuses_a_deployment_payload_whose_address_was_edited() {
        use super::test_support::{
            default_deployment_payload_body, deployment_manifest_hash_hex, deployment_payload_body,
            deployment_payload_json, FIXTURE_GATEWAY, FIXTURE_GATEWAY_CODE_HASH,
        };

        let dir = tempfile::tempdir().unwrap();
        let cfg = config::load_from_map(&map_with_payload_file(dir.path())).unwrap();
        let controller = ShutdownController::new();

        // A manifest and a payload that agree...
        super::test_support::write_consistent_manifest_and_payload(
            dir.path(),
            31337,
            &default_deployment_payload_body(),
            FIXTURE_GATEWAY,
        );
        let approved = deployment_manifest_hash_hex(&default_deployment_payload_body());

        // ...then one nibble of the gateway address changes, and the declared
        // hash still names the approved payload.
        let drifted = deployment_payload_body(
            "31337",
            "0x4ff05a443250a64a18c68cedd2122cfdf3872141",
            FIXTURE_GATEWAY_CODE_HASH,
        );
        std::fs::write(
            dir.path().join("deployment_payload.json"),
            deployment_payload_json(&approved, &drifted),
        )
        .unwrap();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a drifted address must not mount");
        assert!(
            matches!(
                err,
                StreamGStartupError::DeploymentManifestHashSelfMismatch { .. }
            ),
            "expected a self-mismatch, got: {err}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains(approved.trim_start_matches("0x")),
            "the declared value must be shown: {rendered}"
        );
        assert!(
            rendered.contains(deployment_manifest_hash_hex(&drifted).trim_start_matches("0x")),
            "the computed value must be shown: {rendered}"
        );
        assert!(
            rendered.contains("STREAM_G_DEPLOYMENT_MANIFEST_HASH"),
            "the operator must be told how to republish: {rendered}"
        );

        // Paired positive arm: the SAME drifted address, republished on both
        // sides, starts. Without this the refusal above would also hold if
        // `start` were broken for every payload naming this gateway.
        super::test_support::write_consistent_manifest_and_payload(
            dir.path(),
            31337,
            &drifted,
            "0x4ff05a443250a64a18c68cedd2122cfdf3872141",
        );
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("a republished payload must start");
    }

    /// MUTATE ONE RUNTIME CODE HASH. Same address, different code — the case a
    /// pure address list could never catch.
    #[tokio::test]
    async fn start_refuses_a_deployment_payload_whose_runtime_code_hash_was_edited() {
        use super::test_support::{
            default_deployment_payload_body, deployment_manifest_hash_hex, deployment_payload_body,
            deployment_payload_json, FIXTURE_GATEWAY,
        };

        let dir = tempfile::tempdir().unwrap();
        let cfg = config::load_from_map(&map_with_payload_file(dir.path())).unwrap();
        let controller = ShutdownController::new();

        super::test_support::write_consistent_manifest_and_payload(
            dir.path(),
            31337,
            &default_deployment_payload_body(),
            FIXTURE_GATEWAY,
        );
        let approved = deployment_manifest_hash_hex(&default_deployment_payload_body());

        let drifted = deployment_payload_body(
            "31337",
            &FIXTURE_GATEWAY.to_ascii_lowercase(),
            "0x7b11b161685f02bc06d871f0f9f93e6c822b663aad3dc845005b9946b26a1503",
        );
        std::fs::write(
            dir.path().join("deployment_payload.json"),
            deployment_payload_json(&approved, &drifted),
        )
        .unwrap();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a redeployed contract at the same address must not mount");
        assert!(
            matches!(
                err,
                StreamGStartupError::DeploymentManifestHashSelfMismatch { .. }
            ),
            "expected a self-mismatch, got: {err}"
        );

        super::test_support::write_consistent_manifest_and_payload(
            dir.path(),
            31337,
            &drifted,
            FIXTURE_GATEWAY,
        );
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("a republished payload must start");
    }

    /// The payload is internally honest but this deployment published a
    /// different one — a payload file left behind across a republish.
    #[tokio::test]
    async fn start_refuses_a_deployment_payload_this_deployment_did_not_publish() {
        use super::test_support::{
            default_deployment_payload_body, deployment_manifest_hash_hex, deployment_payload_body,
            deployment_payload_json, manifest_json_with, FIXTURE_FEE_SCHEDULE_HASH,
            FIXTURE_GATEWAY,
        };

        let dir = tempfile::tempdir().unwrap();
        let cfg = config::load_from_map(&map_with_payload_file(dir.path())).unwrap();
        let controller = ShutdownController::new();

        // A foreign payload, honest about itself...
        let foreign = deployment_payload_body(
            "31337",
            &FIXTURE_GATEWAY.to_ascii_lowercase(),
            "0x7b11b161685f02bc06d871f0f9f93e6c822b663aad3dc845005b9946b26a1504",
        );
        let foreign_hash = deployment_manifest_hash_hex(&foreign);
        std::fs::write(
            dir.path().join("deployment_payload.json"),
            deployment_payload_json(&foreign_hash, &foreign),
        )
        .unwrap();
        // ...against a manifest that published the approved one.
        std::fs::write(
            dir.path().join("manifest.json"),
            manifest_json_with(
                31337,
                &deployment_manifest_hash_hex(&default_deployment_payload_body()),
                FIXTURE_FEE_SCHEDULE_HASH,
                FIXTURE_GATEWAY,
            ),
        )
        .unwrap();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("an unpublished payload must not mount");
        assert!(
            matches!(
                err,
                StreamGStartupError::DeploymentManifestHashMismatch { .. }
            ),
            "expected a publication mismatch, got: {err}"
        );
    }

    /// 🔴 THE ARTIFACT-SIDE MUTATION. One address changes in the FLAT
    /// deployment manifest and nothing the payload hashes moves, so both digest
    /// checks still pass. Only the per-role address bind can refuse this, and
    /// it is the case the whole change exists to close.
    #[tokio::test]
    async fn start_refuses_a_manifest_naming_an_address_the_payload_never_committed() {
        use super::test_support::{
            default_deployment_payload_body, deployment_manifest_hash_hex, deployment_payload_json,
            manifest_json_with, FIXTURE_FEE_SCHEDULE_HASH, FIXTURE_GATEWAY,
        };

        let dir = tempfile::tempdir().unwrap();
        let cfg = config::load_from_map(&map_with_payload_file(dir.path())).unwrap();
        let controller = ShutdownController::new();

        let body = default_deployment_payload_body();
        let approved = deployment_manifest_hash_hex(&body);
        std::fs::write(
            dir.path().join("deployment_payload.json"),
            deployment_payload_json(&approved, &body),
        )
        .unwrap();
        // The manifest publishes the RIGHT digest and the WRONG gateway.
        std::fs::write(
            dir.path().join("manifest.json"),
            manifest_json_with(
                31337,
                &approved,
                FIXTURE_FEE_SCHEDULE_HASH,
                "0x4Ff05a443250A64a18C68CEdd2122cFDf3872141",
            ),
        )
        .unwrap();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a drifted artifact address must not mount");
        assert!(
            matches!(
                err,
                StreamGStartupError::DeploymentManifestAddressMismatch {
                    role: "GATEWAY",
                    ..
                }
            ),
            "expected a per-role address mismatch, got: {err}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("4ff05a443250a64a18c68cedd2122cfdf3872140")
                && rendered.contains("4ff05a443250a64a18c68cedd2122cfdf3872141"),
            "both addresses must be shown, decoded so one address in two spellings is never \
             reported as a disagreement: {rendered}"
        );

        // Paired positive arm: put the committed address back and it starts.
        std::fs::write(
            dir.path().join("manifest.json"),
            manifest_json_with(31337, &approved, FIXTURE_FEE_SCHEDULE_HASH, FIXTURE_GATEWAY),
        )
        .unwrap();
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("the committed address must start");
    }

    /// 🔴 THE EIGHT THAT WERE BOUND BY NOTHING. Same artifact-side mutation as
    /// the test above, but on `quoteSigner` — one of the addresses that, before
    /// `payload.accounts` existed, was in no digest and in no comparison.
    ///
    /// The measured pre-fix behaviour this closes: an auditor ran
    /// `serve-relayer` against the committed payload and a manifest with ONE
    /// NIBBLE changed in `quoteSigner`, `goatCoin`, `policySafe` or
    /// `enrollmentRegistry`, and the process STARTED CLEAN — alive after 25
    /// seconds, no warning — four times out of four. `quoteSigner` is the worst
    /// of the four: it is the address every `FeeQuote` signature is checked
    /// against on chain.
    ///
    /// Both arms are here on purpose. Without the positive arm this test would
    /// also pass against a `start` that refused everything.
    #[tokio::test]
    async fn start_refuses_a_manifest_naming_an_account_address_the_payload_never_committed() {
        use super::test_support::{
            default_deployment_payload_body, deployment_manifest_hash_hex,
            deployment_payload_body_with_account, deployment_payload_json, manifest_json_with,
            FIXTURE_FEE_SCHEDULE_HASH, FIXTURE_GATEWAY, FIXTURE_GATEWAY_CODE_HASH,
        };

        let dir = tempfile::tempdir().unwrap();
        let cfg = config::load_from_map(&map_with_payload_file(dir.path())).unwrap();
        let controller = ShutdownController::new();

        // The payload is the committed lab one, honest about itself, and the
        // manifest publishes its digest. The ONLY difference from a clean start
        // is one nibble of `quoteSigner` inside the payload — which is the same
        // thing as one nibble inside the manifest, from the comparison's point
        // of view, and is the mutation that used to be invisible.
        let drifted = deployment_payload_body_with_account(
            "31337",
            &FIXTURE_GATEWAY.to_ascii_lowercase(),
            FIXTURE_GATEWAY_CODE_HASH,
            // manifest_json_with hard-codes quoteSigner …957e; this says …957f.
            Some(("QUOTE_SIGNER", "0xebd5a85005dcc98dabb7a2888de82d43c5a6957f")),
        );
        let approved = deployment_manifest_hash_hex(&drifted);
        std::fs::write(
            dir.path().join("deployment_payload.json"),
            deployment_payload_json(&approved, &drifted),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("manifest.json"),
            manifest_json_with(31337, &approved, FIXTURE_FEE_SCHEDULE_HASH, FIXTURE_GATEWAY),
        )
        .unwrap();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a drifted quoteSigner must not mount");
        assert!(
            matches!(
                err,
                StreamGStartupError::DeploymentManifestAddressMismatch {
                    role: "QUOTE_SIGNER",
                    ..
                }
            ),
            "expected a QUOTE_SIGNER address mismatch, got: {err}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("ebd5a85005dcc98dabb7a2888de82d43c5a6957f")
                && rendered.contains("ebd5a85005dcc98dabb7a2888de82d43c5a6957e"),
            "both addresses must be shown: {rendered}"
        );

        // Paired positive arm: the undrifted payload starts.
        let body = default_deployment_payload_body();
        let approved = deployment_manifest_hash_hex(&body);
        std::fs::write(
            dir.path().join("deployment_payload.json"),
            deployment_payload_json(&approved, &body),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("manifest.json"),
            manifest_json_with(31337, &approved, FIXTURE_FEE_SCHEDULE_HASH, FIXTURE_GATEWAY),
        )
        .unwrap();
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("the committed account addresses must start");
    }

    /// Every one of the eight, not just `QUOTE_SIGNER`.
    ///
    /// A single-role test would pass with seven of the eight still unbound —
    /// which is exactly the state this change found: four roles bound, eight
    /// silent. The loop drifts each account in turn and asserts the refusal
    /// names THAT role.
    #[tokio::test]
    async fn start_refuses_a_drift_in_each_of_the_eight_account_addresses() {
        use super::test_support::{
            deployment_manifest_hash_hex, deployment_payload_body_with_account,
            deployment_payload_json, manifest_json_with, FIXTURE_FEE_SCHEDULE_HASH,
            FIXTURE_GATEWAY, FIXTURE_GATEWAY_CODE_HASH,
        };

        for role in super::CANONICAL_ACCOUNTS {
            let dir = tempfile::tempdir().unwrap();
            let cfg = config::load_from_map(&map_with_payload_file(dir.path())).unwrap();
            let controller = ShutdownController::new();

            // An address no manifest field carries, so the refusal can only
            // come from THIS role.
            let drifted = deployment_payload_body_with_account(
                "31337",
                &FIXTURE_GATEWAY.to_ascii_lowercase(),
                FIXTURE_GATEWAY_CODE_HASH,
                Some((role, "0x00000000000000000000000000000000deadbeef")),
            );
            let approved = deployment_manifest_hash_hex(&drifted);
            std::fs::write(
                dir.path().join("deployment_payload.json"),
                deployment_payload_json(&approved, &drifted),
            )
            .unwrap();
            std::fs::write(
                dir.path().join("manifest.json"),
                manifest_json_with(31337, &approved, FIXTURE_FEE_SCHEDULE_HASH, FIXTURE_GATEWAY),
            )
            .unwrap();

            let err = StreamGState::start(&cfg, controller.token())
                .await
                .unwrap_err();
            match err {
                StreamGStartupError::DeploymentManifestAddressMismatch { role: named, .. } => {
                    assert_eq!(named, role, "the refusal must name the drifted role");
                }
                other => panic!("{role}: expected an address mismatch, got: {other}"),
            }
        }
    }

    /// Defect: the operator sets `STREAM_G_DEPLOYMENT_MANIFEST_PATH` and forgets
    /// `STREAM_G_DEPLOYMENT_PAYLOAD_PATH`, so the payload silently falls through
    /// to the BUILT-IN 31337 lab document — and the refusal blames the
    /// deployment ("this deployment did not publish this payload") instead of
    /// naming the variable that is missing.
    ///
    /// The manifest here is a perfectly good 31337 manifest that publishes a
    /// digest of ITS OWN payload; only the payload side is unconfigured.
    #[tokio::test]
    async fn start_names_the_unset_payload_variable_rather_than_blaming_the_deployment() {
        use super::test_support::{
            deployment_manifest_hash_hex, deployment_payload_body, manifest_json_with,
            FIXTURE_FEE_SCHEDULE_HASH, FIXTURE_GATEWAY,
        };

        let dir = tempfile::tempdir().unwrap();
        // A manifest path IS set; a payload path is NOT, and nothing exists at
        // the payload default.
        let mut map = enabled_map(dir.path());
        map.insert(
            "STREAM_G_DEPLOYMENT_MANIFEST_PATH".into(),
            dir.path().join("manifest.json").display().to_string(),
        );
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();

        let body = deployment_payload_body(
            "31337",
            &FIXTURE_GATEWAY.to_ascii_lowercase(),
            "0x7b11b161685f02bc06d871f0f9f93e6c822b663aad3dc845005b9946b26a1509",
        );
        std::fs::write(
            dir.path().join("manifest.json"),
            manifest_json_with(
                31337,
                &deployment_manifest_hash_hex(&body),
                FIXTURE_FEE_SCHEDULE_HASH,
                FIXTURE_GATEWAY,
            ),
        )
        .unwrap();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a substituted payload must not mount against a real manifest");
        assert!(
            matches!(
                err,
                StreamGStartupError::DeploymentPayloadNotConfigured { .. }
            ),
            "expected the missing-variable refusal, got: {err}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("STREAM_G_DEPLOYMENT_PAYLOAD_PATH"),
            "the refusal must name the variable the operator did not set: {rendered}"
        );
        assert!(
            !rendered.contains("did not publish this payload"),
            "and must NOT blame the deployment for a local configuration gap: {rendered}"
        );
    }

    /// The paired arm of the test above, and the one that keeps it from being a
    /// blanket refusal: with NEITHER path set, the built-in lab pair is still a
    /// legal zero-config start.
    #[tokio::test]
    async fn the_builtin_manifest_and_the_builtin_payload_still_start_together() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config::load_from_map(&enabled_map(dir.path())).unwrap();
        let controller = ShutdownController::new();
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("the built-in lab pair is the zero-config path and must start");
    }

    /// A payload authored for another chain, republished here. Reachable for
    /// exactly the reason the fee schedule's twin is: a digest binds a payload
    /// to itself, never to a deployment it does not name.
    #[tokio::test]
    async fn start_refuses_a_deployment_payload_authored_for_another_chain() {
        use super::test_support::{
            deployment_payload_body, FIXTURE_GATEWAY, FIXTURE_GATEWAY_CODE_HASH,
        };

        let dir = tempfile::tempdir().unwrap();
        let cfg = config::load_from_map(&map_with_payload_file(dir.path())).unwrap();
        let controller = ShutdownController::new();

        let foreign = deployment_payload_body(
            "8453",
            &FIXTURE_GATEWAY.to_ascii_lowercase(),
            FIXTURE_GATEWAY_CODE_HASH,
        );
        super::test_support::write_consistent_manifest_and_payload(
            dir.path(),
            31337,
            &foreign,
            FIXTURE_GATEWAY,
        );

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a payload for another chain must not mount");
        assert!(
            matches!(
                err,
                StreamGStartupError::DeploymentManifestChainMismatch {
                    payload_chain_id: 8453,
                    manifest_chain_id: 31337,
                    ..
                }
            ),
            "expected a chain mismatch, got: {err}"
        );
    }

    /// `PathSource::Env` never falls back to the built-in: a configured but
    /// missing payload is a startup failure, not a silent substitution — the
    /// same rule the manifest and the schedule already follow.
    #[tokio::test]
    async fn start_refuses_an_explicitly_configured_but_missing_deployment_payload() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = enabled_map(dir.path());
        map.insert(
            "STREAM_G_DEPLOYMENT_PAYLOAD_PATH".into(),
            dir.path().join("nope.json").display().to_string(),
        );
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();

        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a chosen path that does not exist must not fall back");
        assert!(
            matches!(err, StreamGStartupError::DeploymentPayload { .. }),
            "expected a payload IO refusal, got: {err}"
        );
    }

    /// A missing or unparseable schedule is fatal, not a warning: the quote
    /// route must never mount without one.
    ///
    /// **Mutation this detects (applied, run, reverted):** replacing the
    /// `FeeSchedule::from_json(...)?` in `start` (it is `from_json`, not
    /// `load` — `start` resolves the bytes through `read_startup_document`
    /// first) with a fallback such as
    /// `.unwrap_or_else(|_| FeeSchedule::for_test(&[]))` — both `expect_err`s
    /// then panic.
    #[tokio::test]
    async fn start_refuses_when_the_fee_schedule_is_missing_or_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let map = enabled_map(dir.path());
        let schedule_path = dir.path().join("fee_schedule.json");
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();

        std::fs::remove_file(&schedule_path).unwrap();
        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("a missing fee schedule must fail startup");
        assert!(
            matches!(err, StreamGStartupError::FeeSchedule { .. }),
            "expected a FeeSchedule error, got: {err}"
        );

        std::fs::write(&schedule_path, "this is not json").unwrap();
        let err = StreamGState::start(&cfg, controller.token())
            .await
            .expect_err("an unparseable fee schedule must fail startup");
        assert!(
            matches!(err, StreamGStartupError::FeeSchedule { .. }),
            "expected a FeeSchedule error, got: {err}"
        );

        // Paired positive arm.
        std::fs::write(
            &schedule_path,
            super::test_support::fee_schedule_json(
                super::test_support::FIXTURE_FEE_SCHEDULE_HASH,
                &super::test_support::schedule_payload_json(None),
            ),
        )
        .unwrap();
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("a well-formed matching schedule must start");
    }

    // --- zero-config startup (built-in document fallback) -------------------
    //
    // The defect these four tests close: `config::build_stream_g_config`
    // defaulted both document paths to files under `STATE_DIR` that this
    // repository has never shipped, so `STREAM_G_ENABLED=1` on a fresh clone
    // died at startup with an IO error. Every pre-existing `start` test used
    // `enabled_map`, which writes both files and sets both variables, so none
    // of them could observe it.

    /// **The headline claim: a fresh clone starts Stream G with no Stream G
    /// path configured at all.**
    ///
    /// `minimal_map` sets the six required attestor keys, `STREAM_G_ENABLED=1`,
    /// the four dedicated secrets and `STATE_DIR` — and nothing else. Neither
    /// `STREAM_G_FEE_SCHEDULE_PATH` nor `STREAM_G_DEPLOYMENT_MANIFEST_PATH` is
    /// set and neither default file exists, so both documents come from the
    /// built-ins compiled into the binary.
    ///
    /// **And it pins the distinction that makes this honest:** starting is not
    /// quoting. The built-in schedule sets no tariff, so all four actions still
    /// refuse with `MISSING_TARIFF`. A future change that "fixed" zero-config
    /// quoting by inventing an amount would fail the second half of this test,
    /// which is the point — the Season-0 amounts are a founder decision that
    /// has not been taken.
    ///
    /// **Mutation this detects (applied, run, reverted):** making
    /// `read_startup_document` return the built-in only for `PathSource::Env`
    /// (i.e. inverting the two arms) — startup then fails `FeeSchedule` here
    /// and the `expect` panics.
    #[tokio::test]
    async fn start_succeeds_with_no_stream_g_path_configured_but_still_serves_no_price() {
        use crate::stream_g::models::ActionType;
        use crate::stream_g::quotes::ERR_MISSING_TARIFF;

        let dir = tempfile::tempdir().unwrap();
        let map = super::test_support::minimal_map(dir.path());
        assert!(
            !map.contains_key("STREAM_G_FEE_SCHEDULE_PATH")
                && !map.contains_key("STREAM_G_DEPLOYMENT_MANIFEST_PATH"),
            "this test is only meaningful while neither document path is configured"
        );
        let cfg = config::load_from_map(&map).expect("the minimum config must load");
        assert!(!cfg.stream_g.fee_schedule_path.exists());
        assert!(!cfg.stream_g.deployment_manifest_path.exists());

        let state = StreamGState::start(&cfg, ShutdownController::new().token())
            .await
            .expect("a fresh clone must start Stream G without operator path config");

        assert_eq!(
            state.manifest().chain_id,
            BUILTIN_DEPLOYMENT_MANIFEST_CHAIN_ID,
            "the built-in manifest is the 31337 lab deployment"
        );
        assert_eq!(
            state.fee_schedule_origin(),
            BUILTIN_FEE_SCHEDULE_LABEL,
            "the state must report the built-in as its origin, never a path no file is at"
        );

        // Startup is not quoting. Every action still refuses.
        for action in [
            ActionType::SponsoredEnrollment,
            ActionType::SponsoredSell,
            ActionType::GoatTransfer,
            ActionType::UsdtTransfer,
        ] {
            let err = match state.fee_schedule().fee_for(action) {
                Ok(amount) => panic!(
                    "{action:?} must have no tariff under the built-in schedule, but it served \
                     {amount}: zero-config STARTUP must not become zero-config QUOTING"
                ),
                Err(e) => e,
            };
            assert_eq!(err.code(), ERR_MISSING_TARIFF, "{action:?}");
        }
        assert!(!state.fee_schedule().has_any_tariff());
    }

    /// The built-in manifest is chain 31337 and does not pretend otherwise.
    ///
    /// This is the honest failure the brief demands: on any other `CHAIN_ID`
    /// the fall-through still reaches `parse_deployment_manifest`'s chain gate
    /// (`token_manifest.rs`'s `ManifestChainMismatch`) rather than skipping it,
    /// so the operator is told *which two chain ids disagree* instead of being
    /// told a file is missing.
    ///
    /// **Mutation this detects (applied, run, reverted):** disabling the
    /// `manifest.chain_id != configured_chain_id` guard in
    /// `token_manifest::parse_deployment_manifest` — the built-in then loads
    /// as an 84532 deployment and this `expect_err` panics on an `Ok`. That is
    /// the guard the built-in has to keep going through: it is the difference
    /// between "this crate ships one deployment" and "this crate invents one
    /// for whatever chain you asked for".
    #[tokio::test]
    async fn builtin_manifest_is_refused_on_a_chain_it_was_not_deployed_to() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = super::test_support::minimal_map(dir.path());
        map.insert("CHAIN_ID".into(), "84532".into());
        let cfg = config::load_from_map(&map).unwrap();

        let err = StreamGState::start(&cfg, ShutdownController::new().token())
            .await
            .expect_err("the 31337 built-in must not load as a Base Sepolia deployment");
        let rendered = err.to_string();
        assert!(
            matches!(
                err,
                StreamGStartupError::Manifest {
                    source: TokenManifestError::ManifestChainMismatch { .. },
                    ..
                }
            ),
            "a chain mismatch must not present as an IO error: {rendered}"
        );
        assert!(
            rendered.contains("31337") && rendered.contains("84532"),
            "the refusal must name both chain ids: {rendered}"
        );
    }

    /// **No silent fallback for a path the operator chose.**
    ///
    /// An operator who sets `STREAM_G_FEE_SCHEDULE_PATH` and mistypes it must
    /// get a failure naming their path, not a process quietly running the
    /// built-in placeholder they never selected. This is the security half of
    /// the fallback: `config::PathSource::Env` has no fallback arm.
    ///
    /// **Mutation this detects (applied, run, reverted):** deleting the
    /// `PathSource::Env` arm in `read_startup_document` so both provenances
    /// share the `NotFound` fall-through — startup then succeeds and the
    /// `expect_err` panics.
    #[tokio::test]
    async fn start_refuses_an_explicitly_configured_but_missing_fee_schedule() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = super::test_support::minimal_map(dir.path());
        let typo = dir.path().join("fee_schedule.jsno");
        map.insert(
            "STREAM_G_FEE_SCHEDULE_PATH".into(),
            typo.display().to_string(),
        );
        let cfg = config::load_from_map(&map).unwrap();
        assert_eq!(cfg.stream_g.fee_schedule_path_source, PathSource::Env);

        let err = StreamGState::start(&cfg, ShutdownController::new().token())
            .await
            .expect_err("a configured schedule path that does not exist must fail startup");
        let rendered = err.to_string();
        assert!(
            matches!(err, StreamGStartupError::FeeSchedule { .. }),
            "expected a FeeSchedule error, got: {rendered}"
        );
        assert!(
            rendered.contains("fee_schedule.jsno"),
            "the refusal must name the operator's own path: {rendered}"
        );
        assert!(
            !rendered.contains(BUILTIN_FEE_SCHEDULE_LABEL),
            "the built-in must not appear anywhere in a refusal about a configured path: \
             {rendered}"
        );
    }

    /// The manifest twin of
    /// [`start_refuses_an_explicitly_configured_but_missing_fee_schedule`].
    /// Both documents share `read_startup_document`, so both are pinned rather
    /// than one standing in for the other.
    #[tokio::test]
    async fn start_refuses_an_explicitly_configured_but_missing_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = super::test_support::minimal_map(dir.path());
        let typo = dir.path().join("31337.stream-g.jsno");
        map.insert(
            "STREAM_G_DEPLOYMENT_MANIFEST_PATH".into(),
            typo.display().to_string(),
        );
        let cfg = config::load_from_map(&map).unwrap();
        assert_eq!(
            cfg.stream_g.deployment_manifest_path_source,
            PathSource::Env
        );

        let err = StreamGState::start(&cfg, ShutdownController::new().token())
            .await
            .expect_err("a configured manifest path that does not exist must fail startup");
        let rendered = err.to_string();
        assert!(
            matches!(
                err,
                StreamGStartupError::Manifest {
                    source: TokenManifestError::Io { .. },
                    ..
                }
            ),
            "expected a manifest IO error, got: {rendered}"
        );
        assert!(
            rendered.contains("31337.stream-g.jsno"),
            "the refusal must name the operator's own path: {rendered}"
        );
        assert!(
            !rendered.contains(BUILTIN_MANIFEST_LABEL),
            "the built-in must not appear anywhere in a refusal about a configured path: \
             {rendered}"
        );
    }

    /// A file that exists at an **unconfigured default** still wins over the
    /// built-in — the fallback is a last resort, not a preference.
    ///
    /// Without this arm, `read_startup_document` could ignore the disk
    /// entirely under `PathSource::Default` and every other test here would
    /// still pass.
    #[tokio::test]
    async fn a_file_at_the_unconfigured_default_path_beats_the_builtin() {
        use super::test_support::{schedule_hash_hex, schedule_payload_json};

        let dir = tempfile::tempdir().unwrap();
        let map = super::test_support::minimal_map(dir.path());
        let cfg = config::load_from_map(&map).unwrap();

        // A schedule WITH a tariff, at the default path, plus the manifest that
        // publishes its digest — the only pair `start` accepts.
        let payload = schedule_payload_json(Some("500000"));
        let hash = schedule_hash_hex(&payload);
        std::fs::write(
            &cfg.stream_g.deployment_manifest_path,
            super::test_support::manifest_json_with_fee_schedule_hash(31337, &hash),
        )
        .unwrap();
        std::fs::write(
            &cfg.stream_g.fee_schedule_path,
            super::test_support::fee_schedule_json(&hash, &payload),
        )
        .unwrap();

        let state = StreamGState::start(&cfg, ShutdownController::new().token())
            .await
            .expect("start");
        assert_eq!(
            state.fee_schedule_origin(),
            cfg.stream_g.fee_schedule_path.display().to_string(),
            "a file that is actually there must be read, not shadowed by the built-in"
        );
        assert_eq!(
            state
                .fee_schedule()
                .fee_for(crate::stream_g::models::ActionType::SponsoredEnrollment)
                .unwrap(),
            500_000,
            "the tariff must come from the file on disk, which the built-in does not carry"
        );
    }

    /// The loaded tariff table reaches a handler, and it is the table from the
    /// file rather than an empty default.
    ///
    /// Note what setting a tariff now costs: the manifest has to be rewritten
    /// too, because it publishes a digest of the payload. That is the operator
    /// procedure, and a fixture that could skip it would not be testing this
    /// build.
    ///
    /// **Mutation this detects (applied, run, reverted):** storing
    /// `FeeSchedule::for_test(&[])` in `Inner` instead of the loaded
    /// `fee_schedule` — the `500_000` assertion fails with `MISSING_TARIFF`.
    #[tokio::test]
    async fn state_carries_the_loaded_fee_schedule() {
        use super::test_support::{schedule_payload_json, write_consistent_manifest_and_schedule};
        use crate::stream_g::models::ActionType;

        let dir = tempfile::tempdir().unwrap();
        let map = enabled_map(dir.path());
        write_consistent_manifest_and_schedule(
            dir.path(),
            31337,
            &schedule_payload_json(Some("500000")),
        );
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");

        assert_eq!(
            state
                .fee_schedule()
                .fee_for(ActionType::SponsoredEnrollment)
                .unwrap(),
            500_000
        );
        // Discriminating control: an action the file omits still refuses, so
        // the state is not holding a table that answers everything.
        assert!(state
            .fee_schedule()
            .fee_for(ActionType::UsdtTransfer)
            .is_err());
        assert_eq!(
            state.fee_schedule_origin(),
            dir.path().join("fee_schedule.json").display().to_string(),
            "an explicitly-configured schedule reports the path it was read from, never the \
             built-in label"
        );
    }

    /// The state's `Debug` must not leak the newly-stored hex. The existing
    /// `state_debug_never_prints_key_material` covers `DataKey`; Wave 0 added
    /// a second copy of the same secret to `Inner`, and `StreamGState`'s
    /// `Debug` is hand-written, so a future field addition could re-expose it.
    ///
    /// **Mutation this detects (applied, run, reverted):** adding
    /// `.field("data_key_hex", &self.inner.data_key_hex.as_str())` to
    /// `StreamGState`'s `Debug` impl.
    #[tokio::test]
    async fn state_debug_does_not_leak_the_stored_data_key_hex() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = enabled_map(dir.path());
        let key_hex = hex::encode([0x5Au8; 32]);
        map.insert("STREAM_G_DATA_KEY_HEX".into(), key_hex.clone());
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");

        // Control: the state really does hold that key.
        assert_eq!(state.data_key_hex().as_str(), key_hex);

        let rendered = format!("{state:?}");
        assert!(
            !rendered.contains(&key_hex),
            "state Debug leaked the stored data key hex: {rendered}"
        );
        // And the SecretHex's own Debug, in case it is nested somewhere later.
        let nested = format!("{:?}", state.data_key_hex());
        assert!(!nested.contains(&key_hex), "{nested}");
    }

    // -- Wave C W1: signing lease, claim owner, broadcast gas policy -------

    /// **W1a.** Cloning the state must not fork the signing lease registry.
    ///
    /// This is the property the whole mechanism rests on and the one a
    /// plausible refactor destroys silently: axum clones `StreamGState` per
    /// request, so if the registry were a by-value field on the outer struct
    /// (or minted per handler) every request would get a private `held` set,
    /// `try_acquire` could never collide, and two concurrent submits for one
    /// action nonce would both sign. Nothing would fail — not this suite, not
    /// the type checker.
    ///
    /// Asserted through *observable behaviour* rather than pointer equality:
    /// a lease taken on one clone must be visible to another clone, and must
    /// be released for both when the guard drops.
    ///
    /// **MUTATION DETECTED (applied, run, reverted).** `leases()` changed to
    /// `Box::leak(Box::new(SigningLeaseRegistry::new()))` — the compiling
    /// form of "a fresh registry per call", i.e. the per-request bug. Run
    /// 2026-07-27: `685 passed; 1 failed` — this test, on the cross-clone
    /// visibility assertion, was the **only** failure in the suite. That count
    /// is the measure of the problem: nothing else in 686 tests can observe
    /// the difference, so without this test the mutation ships green.
    #[tokio::test]
    async fn the_signing_lease_registry_is_shared_by_every_clone_of_the_state() {
        use crate::stream_g::models::ActionType;
        use crate::stream_g::submit::NonceLeaseKey;

        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_cfg(dir.path());
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");
        let cloned = state.clone();

        let key = || NonceLeaseKey::new(31337, [0x11u8; 20], ActionType::SponsoredEnrollment, 7);

        assert!(!state.leases().is_held(&key()));
        assert!(!cloned.leases().is_held(&key()));

        {
            let _lease = state
                .leases()
                .try_acquire(key())
                .expect("first acquire must succeed");

            // The load-bearing assertion: the OTHER clone sees it.
            assert!(
                cloned.leases().is_held(&key()),
                "a lease taken on one clone must be visible through another — two registries \
                 in one process silently void the single-signer guarantee"
            );
            assert!(
                cloned.leases().try_acquire(key()).is_err(),
                "the other clone must be refused the same action nonce"
            );
        }

        // ... and the RAII release is shared too.
        assert!(!cloned.leases().is_held(&key()));
        assert!(
            cloned.leases().try_acquire(key()).is_ok(),
            "the key must be re-acquirable once the guard drops"
        );
    }

    /// **W1b.** Two independently minted identities must differ.
    ///
    /// The `hostname` and `pid` segments are identical for both calls here (it
    /// is one process), so anything this test observes as different came from
    /// the fresh per-process-start UUID — which is exactly the segment the
    /// container hazard requires. Docker/K8s default the hostname and run the
    /// entrypoint as pid 1, so `hostname:pid` alone collides between replicas.
    ///
    /// Mutation this detects: deriving the entropy from anything stable —
    /// `store::db_uuid` (minted per DATABASE FILE, so two processes sharing a
    /// DB derive an identical owner by construction), a constant, or dropping
    /// the UUID segment entirely.
    #[test]
    fn two_independently_minted_claim_owners_differ() {
        let a = mint_submit_claim_owner();
        let b = mint_submit_claim_owner();
        assert_ne!(a, b, "each mint must draw fresh entropy: {a} vs {b}");

        // Paired positive arm, so the assertion above cannot be passing on two
        // differently-malformed strings: both must share the constant prefix,
        // the host segment and the pid segment, and differ only in the last.
        let (head_a, uuid_a) = a.rsplit_once(':').expect("five colon-separated segments");
        let (head_b, uuid_b) = b.rsplit_once(':').expect("five colon-separated segments");
        assert_eq!(head_a, head_b, "only the UUID segment may differ");
        assert_ne!(uuid_a, uuid_b);
        assert_eq!(uuid_a.len(), 32, "16 random bytes, hex-encoded");
        assert!(uuid_a.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(head_a.starts_with(SUBMIT_CLAIM_OWNER_PREFIX));
        assert!(head_a.ends_with(&format!(":{}", std::process::id())));
    }

    /// **W1b.** The identity must be STABLE across reads within one process.
    ///
    /// This is not the same claim as the test above and it is the one the
    /// outbox actually depends on: `reserve_and_persist_raw_tx` stamps
    /// `claim_owner` onto the row, and every later release/record
    /// compare-and-swap matches it by equality. A `claim_owner()` that minted
    /// on each call would leave every reserved row un-releasable by the
    /// process that reserved it, until the sweeper's lease expiry reclaimed it
    /// — a 900-second stall that no unit test of `mint_submit_claim_owner`
    /// alone would catch.
    ///
    /// Mutation this detects: `claim_owner()` returning
    /// `mint_submit_claim_owner()` instead of the stored field.
    #[tokio::test]
    async fn the_claim_owner_is_stable_across_reads_and_clones() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_cfg(dir.path());
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");

        let first = state.claim_owner().to_string();
        assert_eq!(state.claim_owner(), first, "re-reading must not re-mint");
        assert_eq!(
            state.clone().claim_owner(),
            first,
            "a clone shares the identity"
        );

        // The one property `outbox` relies on beyond stability.
        assert_ne!(
            state.claim_owner(),
            SWEEPER_CLAIM_OWNER,
            "the submit owner must never collide with the sweeper's"
        );
        assert!(state.claim_owner().starts_with(SUBMIT_CLAIM_OWNER_PREFIX));
    }

    /// **W1b.** Two states started in the same process (the container case,
    /// minus the shared filesystem) must not agree on an identity.
    #[tokio::test]
    async fn two_started_states_do_not_share_a_claim_owner() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let controller = ShutdownController::new();
        let a = StreamGState::start(&enabled_cfg(dir_a.path()), controller.token())
            .await
            .expect("start a");
        let b = StreamGState::start(&enabled_cfg(dir_b.path()), controller.token())
            .await
            .expect("start b");
        assert_ne!(a.claim_owner(), b.claim_owner());
    }

    /// **W1b.** The hostname segment cannot disturb the format.
    ///
    /// It is an env read (this crate has no hostname primitive and std exposes
    /// none), so it is attacker-influenceable in principle. It carries no
    /// weight — uniqueness is the UUID's job alone — but it must not be able
    /// to inject the field separator or an unbounded string into every
    /// `tx_attempts` row.
    #[test]
    fn the_hostname_segment_is_sanitized_and_bounded() {
        assert_eq!(
            sanitize_hostname_segment("worker-01.local"),
            "worker-01.local"
        );
        assert_eq!(
            sanitize_hostname_segment("evil:host"),
            "evil_host",
            "the field separator must not survive"
        );
        assert_eq!(sanitize_hostname_segment("   "), UNKNOWN_HOSTNAME);
        assert_eq!(sanitize_hostname_segment(""), UNKNOWN_HOSTNAME);
        assert_eq!(sanitize_hostname_segment(&"x".repeat(200)).len(), 32);
    }

    /// **W1c.** The state hands back exactly the policy config validated, and
    /// the default is the named starting-values constructor rather than any
    /// number written in `config.rs`.
    ///
    /// Mutation this detects: `config::build_broadcast_gas_policy` growing its
    /// own literals — which would be a second copy of three figures that are
    /// still awaiting founder review.
    #[tokio::test]
    async fn the_state_exposes_the_configured_broadcast_gas_policy() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_cfg(dir.path());
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");

        assert_eq!(state.broadcast_gas(), cfg.stream_g.broadcast_gas);
        assert_eq!(
            state.broadcast_gas(),
            BroadcastGasPolicy::starting_values_pending_founder_review(),
            "unset env must resolve to the starting values, not to a local literal"
        );
    }

    /// **W1c.** An override reaches the state unchanged.
    #[tokio::test]
    async fn a_configured_broadcast_gas_policy_reaches_the_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut map = enabled_map(dir.path());
        map.insert(config::ENV_BROADCAST_GAS_LIMIT.into(), "750000".into());
        map.insert(
            config::ENV_BROADCAST_MAX_FEE_PER_GAS_WEI.into(),
            "2000000000".into(),
        );
        map.insert(
            config::ENV_BROADCAST_MAX_PRIORITY_FEE_PER_GAS_WEI.into(),
            "5000000".into(),
        );
        let cfg = config::load_from_map(&map).unwrap();
        let controller = ShutdownController::new();
        let state = StreamGState::start(&cfg, controller.token())
            .await
            .expect("start");

        assert_eq!(state.broadcast_gas().gas_limit().get(), 750_000);
        assert_eq!(state.broadcast_gas().max_fee_per_gas().get(), 2_000_000_000);
        assert_eq!(
            state.broadcast_gas().max_priority_fee_per_gas().get(),
            5_000_000
        );
        assert_ne!(
            state.broadcast_gas(),
            BroadcastGasPolicy::starting_values_pending_founder_review()
        );
    }
}

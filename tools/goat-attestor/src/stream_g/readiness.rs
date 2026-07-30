//! Real readiness for `GET /v1/stream-g/ready`.
//!
//! Until Task 8 Wave C this endpoint was a hardcoded
//! `StatusCode::SERVICE_UNAVAILABLE`. A constant 503 is honest but useless: it
//! cannot distinguish a healthy process from a degraded one, so an operator
//! learns nothing and an orchestrator can never route to it. This module
//! replaces it with four checks that are actually asked of the running store,
//! per request.
//!
//! # Fail closed, and the exact shape of "closed"
//!
//! `ready` is 200 **only** when every check passed. Every failure mode —
//! including a check that could not be evaluated at all because the query
//! errored — is `ok: false`, which is 503. There is no "unknown" state and no
//! branch on which an error is treated as a pass; that is the degraded-store
//! 200 spec §9.3 forbids.
//!
//! # The four checks
//!
//! | name | what it asks the live store |
//! |---|---|
//! | `store_reachable` | pragmas re-read and still WAL / FK on / FULL / bounded busy timeout, `store_meta` readable, and its `db_uuid` still equals the one `open` cached |
//! | `instance_lock_held` | a fresh handle **cannot** take the exclusive lock — i.e. we still hold it |
//! | `schema_version` | `store_meta.schema_version` on disk equals this build's [`store::supported_schema_version`] *and* the value cached at open |
//! | `key_canaries` | the active data key opens a bounded sample of the envelopes actually persisted in every sealed column |
//!
//! The `db_uuid` comparison in `store_reachable` is the "restore mismatch"
//! clause of spec §9.3: a database file swapped underneath a running process
//! (a backup restored from a *different* database) keeps every pragma and may
//! well be at the right schema version, but its `db_uuid` differs — and every
//! envelope in it was sealed under an AAD this process cannot reproduce.
//!
//! # What `key_canaries` does and does not prove
//!
//! Spec §9.3 asks readiness to "decrypt keyed canaries for every referenced
//! keyId". Stated precisely against this build: **there is exactly one key and
//! no keyring.** `StreamGConfig` carries a single `STREAM_G_DATA_KEY_HEX`,
//! there is no previous-key list, and no `_enc` column records the `keyId` it
//! was sealed under — the keyId only appears inside the AAD, where it is
//! authenticated rather than stored. So "every referenced keyId" cannot be
//! enumerated from the database; the equivalent question this build *can*
//! answer is asked instead: **does the active key still open what is already
//! persisted?** That is the failure this check exists to catch — an operator
//! rotating `STREAM_G_DATA_KEY_HEX` without a re-encryption pass leaves a
//! store whose rows are all undecryptable, and every affected request would
//! otherwise fail one at a time, at the worst moment, instead of at readiness.
//!
//! Two honest limits:
//!
//! * It is a **bounded sample** ([`CANARY_SAMPLE_PER_COLUMN`] rows per sealed
//!   column, lowest pk first), not a full scan. A partial rotation that left
//!   only *later* rows under an old key can pass this check. Full verification
//!   belongs to the re-encryption job, not to a per-request probe.
//! * On a store with no sealed rows yet the sample is empty, and the check
//!   falls back to a synthetic seal/open round-trip under the live AAD. That
//!   fallback proves the key is usable; it does **not** prove it matches
//!   anything on disk, because there is nothing on disk. The `sampled` count in
//!   the check's `detail` is reported so this is visible rather than implied.
//!
//! # What is not checked yet
//!
//! Spec §9.8 lists a dozen further dependencies (RPC reachability and chain id,
//! finality evidence, gateway/registry code identity, signer availability and
//! reserves, worker heartbeats, …). None of them is implemented here, and
//! rather than let their absence read as a pass, [`NOT_YET_CHECKED`] is
//! serialized into the response. A 200 from this endpoint means *these four
//! checks* passed — nothing more.

use std::path::Path;

use axum::http::StatusCode;
use serde::Serialize;

use super::crypto_store::{self, DataKey};
use super::runtime::StreamGState;
use super::store::{self, InstanceLockProbe, StreamGStore};

/// Rows read per sealed column by the canary check. Small on purpose: this
/// runs on every readiness probe, and the check's job is to notice a key that
/// no longer fits the store, which one row per column already answers.
pub const CANARY_SAMPLE_PER_COLUMN: i64 = 2;

/// Spec §9.8 dependencies this build does **not** yet verify. Serialized into
/// every readiness response so a 200 cannot be read as more than it is.
pub const NOT_YET_CHECKED: &[&str] = &[
    "rpc_reachability_and_chain_id",
    "configured_finality_evidence",
    "gateway_and_registry_code_identity",
    "deployment_token_and_fee_schedule_hashes",
    "profile_issuer_and_session_configuration",
    "quote_signer_availability",
    "broadcaster_signer_minimum_eth_reserve",
    "fee_safe_and_policy_safe_configuration",
    "outbox_broadcaster_and_reconciliation_worker_heartbeats",
];

/// One readiness check's verdict.
///
/// `detail` is operator-facing prose. It may name a table, a pragma, a schema
/// version or a `key_id` (a hash prefix, non-secret by construction — see
/// [`DataKey::key_id`]). It must never carry a row's payload, a primary key, a
/// session token or key material: this document is returned to an unauthenticated
/// HTTP caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadinessCheck {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

impl ReadinessCheck {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            ok: true,
            detail: detail.into(),
        }
    }

    fn failed(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            ok: false,
            detail: detail.into(),
        }
    }
}

/// The wire shape of `GET /v1/stream-g/ready`. snake_case (founder ruling on
/// Stream G wire DTOs), which is serde's default for these names — so there is
/// deliberately no `rename_all` attribute, and
/// `stream_g_wire_dtos_are_snake_case` asserts the result instead of trusting
/// the absence of one.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessReport {
    pub ready: bool,
    pub checks: Vec<ReadinessCheck>,
    pub not_yet_checked: &'static [&'static str],
}

impl ReadinessReport {
    fn from_checks(checks: Vec<ReadinessCheck>) -> Self {
        // `all` over an empty vec is `true`, which would be a 200 with no
        // evidence — so the constructor refuses to build an empty report
        // rather than letting a future edit that drops every check silently
        // turn readiness green.
        let ready = !checks.is_empty() && checks.iter().all(|c| c.ok);
        Self {
            ready,
            checks,
            not_yet_checked: NOT_YET_CHECKED,
        }
    }

    /// 200 only when every check passed; 503 otherwise.
    pub fn status(&self) -> StatusCode {
        if self.ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }

    /// One named check, for tests and for callers that want to branch on a
    /// specific dependency.
    pub fn check(&self, name: &str) -> Option<&ReadinessCheck> {
        self.checks.iter().find(|c| c.name == name)
    }
}

/// Evaluate readiness for a live [`StreamGState`].
pub async fn evaluate(state: &StreamGState) -> ReadinessReport {
    evaluate_parts(state.store(), state.data_key(), state.lock_path()).await
}

/// The parts [`evaluate`] is made of, taken separately.
///
/// `lock_path` is a parameter rather than being read back out of the store
/// because that is the only way to exercise the "we lost the instance lock"
/// branch on every platform: Windows will not unlink a file whose handle is
/// open, so a test cannot delete the real lock file out from under a live
/// store. Pointing this at a path nothing holds reproduces exactly the
/// observable condition — a fresh handle can take the lock — which is what the
/// check keys on.
pub(crate) async fn evaluate_parts(
    store: &StreamGStore,
    data_key: &DataKey,
    lock_path: &Path,
) -> ReadinessReport {
    ReadinessReport::from_checks(vec![
        check_store_reachable(store).await,
        check_instance_lock(lock_path),
        check_schema_version(store).await,
        check_key_canaries(store, data_key).await,
    ])
}

const STORE_REACHABLE: &str = "store_reachable";
const INSTANCE_LOCK_HELD: &str = "instance_lock_held";
const SCHEMA_VERSION: &str = "schema_version";
const KEY_CANARIES: &str = "key_canaries";

/// Pragmas re-read and still correct, `store_meta` readable, and the file is
/// still the same database this process opened.
async fn check_store_reachable(store: &StreamGStore) -> ReadinessCheck {
    let pragmas = match store.verify_pragmas().await {
        Ok(p) => p,
        Err(e) => return ReadinessCheck::failed(STORE_REACHABLE, e.to_string()),
    };

    let meta = match store.read_stored_meta().await {
        Ok(Some(meta)) => meta,
        Ok(None) => {
            return ReadinessCheck::failed(
                STORE_REACHABLE,
                "store_meta singleton row is missing — the database file changed after open",
            )
        }
        Err(e) => return ReadinessCheck::failed(STORE_REACHABLE, e.to_string()),
    };

    if meta.db_uuid != store.db_uuid() {
        // The ids themselves are non-secret random per-file identifiers, but
        // they are not printed here either: an operator needs to know *that*
        // the file changed, and the pair adds nothing actionable to a public
        // endpoint.
        return ReadinessCheck::failed(
            STORE_REACHABLE,
            "store_meta.db_uuid no longer matches the id cached at open — the database file was \
             replaced (restore mismatch); every sealed envelope in it was written under an AAD \
             this process cannot reproduce",
        );
    }

    ReadinessCheck::ok(
        STORE_REACHABLE,
        format!(
            "journal_mode={} foreign_keys={} synchronous={} busy_timeout_ms={} db_uuid stable",
            pragmas.journal_mode,
            pragmas.foreign_keys,
            pragmas.synchronous,
            pragmas.busy_timeout_ms
        ),
    )
}

/// Spec §9.3's instance lock, re-asked per probe rather than assumed from
/// startup. See [`store::instance_lock_probe`] for what a same-process probe
/// does and does not prove.
fn check_instance_lock(lock_path: &Path) -> ReadinessCheck {
    match store::instance_lock_probe(lock_path) {
        Ok(InstanceLockProbe::HeldBySomeone) => ReadinessCheck::ok(
            INSTANCE_LOCK_HELD,
            "the Stream G instance lock is held (a fresh handle was refused)",
        ),
        Ok(InstanceLockProbe::Free) => ReadinessCheck::failed(
            INSTANCE_LOCK_HELD,
            "the Stream G instance lock is FREE — this process no longer owns the store \
             (lock file deleted or replaced, or the store handle is gone)",
        ),
        Err(e) => ReadinessCheck::failed(INSTANCE_LOCK_HELD, e.to_string()),
    }
}

/// Migrations still at the version this build supports, on disk and in cache.
async fn check_schema_version(store: &StreamGStore) -> ReadinessCheck {
    let expected = store::supported_schema_version();
    let cached = i64::from(store.schema_version());

    let meta = match store.read_stored_meta().await {
        Ok(Some(meta)) => meta,
        Ok(None) => {
            return ReadinessCheck::failed(SCHEMA_VERSION, "store_meta singleton row is missing")
        }
        Err(e) => return ReadinessCheck::failed(SCHEMA_VERSION, e.to_string()),
    };

    if meta.schema_version != expected {
        return ReadinessCheck::failed(
            SCHEMA_VERSION,
            format!(
                "store_meta.schema_version is {} on disk, this build supports {expected}",
                meta.schema_version
            ),
        );
    }
    if cached != expected {
        return ReadinessCheck::failed(
            SCHEMA_VERSION,
            format!("schema_version cached at open is {cached}, this build supports {expected}"),
        );
    }

    ReadinessCheck::ok(SCHEMA_VERSION, format!("schema_version={expected}"))
}

/// The active data key must open what is already persisted. See the module
/// doc for exactly what this proves and what it does not.
async fn check_key_canaries(store: &StreamGStore, data_key: &DataKey) -> ReadinessCheck {
    // Always-run arm: the key can seal and open at all, under an AAD built the
    // same way every production call site builds one.
    let synthetic_aad = store.envelope_aad("__readiness_canary__", "canary", "canary");
    let sealed = match crypto_store::seal(data_key, &synthetic_aad, b"stream-g readiness canary") {
        Ok(bytes) => bytes,
        Err(e) => return ReadinessCheck::failed(KEY_CANARIES, format!("synthetic seal: {e}")),
    };
    if let Err(e) = crypto_store::open(data_key, &synthetic_aad, &sealed) {
        return ReadinessCheck::failed(KEY_CANARIES, format!("synthetic round-trip: {e}"));
    }

    // Evidence arm: a bounded sample of the envelopes actually on disk.
    let mut sampled = 0usize;
    let mut failed_tables: Vec<&'static str> = Vec::new();

    for column in store::SEALED_COLUMNS {
        let rows = match store
            .sample_sealed_envelopes(column, CANARY_SAMPLE_PER_COLUMN)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                return ReadinessCheck::failed(
                    KEY_CANARIES,
                    format!("sampling {}.{}: {e}", column.table, column.column),
                )
            }
        };

        for (pk, envelope) in rows {
            sampled += 1;
            let aad = store.envelope_aad(column.table, &pk, column.column);
            let opened = match envelope {
                // A hex column whose text did not decode: corrupt, and counted
                // as a canary failure rather than skipped.
                None => Err(()),
                Some(bytes) => crypto_store::open(data_key, &aad, &bytes)
                    .map(|_| ())
                    .map_err(|_| ()),
            };
            if opened.is_err() && !failed_tables.contains(&column.table) {
                failed_tables.push(column.table);
            }
        }
    }

    if !failed_tables.is_empty() {
        return ReadinessCheck::failed(
            KEY_CANARIES,
            format!(
                "active key_id {} could not open persisted envelopes in: {} — the data key does \
                 not match this store (rotation without re-encryption, or a restored backup)",
                data_key.key_id(),
                failed_tables.join(", ")
            ),
        );
    }

    ReadinessCheck::ok(
        KEY_CANARIES,
        format!(
            "key_id {} opened {sampled} sampled envelope(s) across {} sealed column(s)",
            data_key.key_id(),
            store::SEALED_COLUMNS.len()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_g::runtime::{test_support::enabled_cfg, ShutdownController, StreamGState};
    use crate::stream_g::store::{SealedEncoding, StreamGStoreError};

    async fn healthy_state(dir: &Path) -> StreamGState {
        let cfg = enabled_cfg(dir);
        let controller = ShutdownController::new();
        StreamGState::start(&cfg, controller.token())
            .await
            .expect("stream G startup")
    }

    /// Insert a `profiles` row whose `profile_enc` is whatever `envelope`
    /// says. Used to plant both a good canary and a broken one.
    async fn insert_profile(store: &StreamGStore, id: &str, envelope: Vec<u8>) {
        let id = id.to_string();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO profiles (id, created_at, status, profile_enc) \
                         VALUES (?, 0, 'active', ?)",
                    )
                    .bind(&id)
                    .bind(&envelope)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("insert profile");
    }

    /// An `auth_challenges` row with whatever `nonce` text is given.
    /// `profile_id` is nullable by migration `0001`, so no parent row is
    /// needed and `foreign_keys=ON` is satisfied.
    async fn insert_challenge(store: &StreamGStore, id: &str, nonce: &str) {
        let id = id.to_string();
        let nonce = nonce.to_string();
        store
            .write_tx(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO auth_challenges \
                         (id, challenge_type, nonce, created_at, expires_at) \
                         VALUES (?, 'readiness-test', ?, 0, 0)",
                    )
                    .bind(&id)
                    .bind(&nonce)
                    .execute(&mut **tx)
                    .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("insert challenge");
    }

    /// The baseline this whole module exists to replace: a freshly started,
    /// healthy Stream G store must be **200**, not the old hardcoded 503.
    ///
    /// Mutation this detects: any check wired to report `ok: false`
    /// unconditionally (e.g. `ReadinessCheck::failed` pasted into a success
    /// path) — verified by flipping `check_instance_lock`'s `HeldBySomeone`
    /// arm to `failed`, after which this test fails on the status assertion.
    #[tokio::test]
    async fn a_healthy_store_is_ready() {
        let dir = tempfile::tempdir().unwrap();
        let state = healthy_state(dir.path()).await;

        let report = evaluate(&state).await;
        assert_eq!(report.status(), StatusCode::OK, "{report:?}");
        assert!(report.ready);
        assert_eq!(report.checks.len(), 4, "{report:?}");
        for check in &report.checks {
            assert!(check.ok, "{check:?}");
        }
        // The four names are part of the wire contract, not incidental.
        for name in [
            STORE_REACHABLE,
            INSTANCE_LOCK_HELD,
            SCHEMA_VERSION,
            KEY_CANARIES,
        ] {
            assert!(report.check(name).is_some(), "missing check {name}");
        }
    }

    /// **Degraded store, check 1.** The database file is replaced by one with
    /// a different `db_uuid` — the restore-mismatch case. Readiness must not
    /// return 200.
    ///
    /// Condition broken: `store_meta.db_uuid` no longer equals the id cached
    /// at `open`.
    #[tokio::test]
    async fn a_swapped_database_file_is_not_ready() {
        let dir = tempfile::tempdir().unwrap();
        let state = healthy_state(dir.path()).await;
        assert_eq!(evaluate(&state).await.status(), StatusCode::OK);

        state
            .store()
            .write_tx(|tx| {
                Box::pin(async move {
                    sqlx::query("UPDATE store_meta SET db_uuid = 'restored-from-another-database'")
                        .execute(&mut **tx)
                        .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("rewrite db_uuid");

        let report = evaluate(&state).await;
        assert_ne!(report.status(), StatusCode::OK);
        assert_eq!(report.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!report.check(STORE_REACHABLE).unwrap().ok);
        // Paired arm: only that check failed — a degraded store must not make
        // every check look broken, or the report tells an operator nothing.
        assert!(report.check(INSTANCE_LOCK_HELD).unwrap().ok);
    }

    /// **Degraded store, check 2.** The instance lock is no longer held.
    ///
    /// Condition broken by pointing the check at a lock path nothing holds,
    /// which is the observable form of "we lost the lock" — see
    /// [`evaluate_parts`] for why the real file cannot simply be deleted on
    /// Windows.
    #[tokio::test]
    async fn a_lost_instance_lock_is_not_ready() {
        let dir = tempfile::tempdir().unwrap();
        let state = healthy_state(dir.path()).await;

        let free_lock = dir.path().join("nobody-holds-this.lock");
        let report = evaluate_parts(state.store(), state.data_key(), &free_lock).await;
        assert_eq!(
            report.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{report:?}"
        );
        assert!(!report.check(INSTANCE_LOCK_HELD).unwrap().ok);

        // Paired arm: the very same call against the lock this state really
        // holds is 200, so the assertion above is about the lock and not about
        // `evaluate_parts` being broken for every input.
        let held = evaluate_parts(state.store(), state.data_key(), state.lock_path()).await;
        assert_eq!(held.status(), StatusCode::OK, "{held:?}");
    }

    /// **Degraded store, check 3.** Migrations are not at the expected
    /// version.
    #[tokio::test]
    async fn a_downgraded_schema_version_is_not_ready() {
        let dir = tempfile::tempdir().unwrap();
        let state = healthy_state(dir.path()).await;
        assert_eq!(evaluate(&state).await.status(), StatusCode::OK);

        state
            .store()
            .write_tx(|tx| {
                Box::pin(async move {
                    sqlx::query("UPDATE store_meta SET schema_version = 1")
                        .execute(&mut **tx)
                        .await?;
                    Ok::<(), StreamGStoreError>(())
                })
            })
            .await
            .expect("downgrade schema_version");

        let report = evaluate(&state).await;
        assert_eq!(report.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!report.check(SCHEMA_VERSION).unwrap().ok);
        assert!(
            report.check(SCHEMA_VERSION).unwrap().detail.contains('1'),
            "{:?}",
            report.check(SCHEMA_VERSION)
        );
    }

    /// **Degraded store, check 4.** A persisted envelope the active key
    /// cannot open — key rotated without re-encryption, or a restored backup.
    ///
    /// Both arms are real rows: the positive one is a genuinely sealed
    /// envelope under this store's own AAD, so the failure below is about the
    /// *ciphertext*, not about the check rejecting everything it is handed.
    #[tokio::test]
    async fn a_persisted_envelope_the_key_cannot_open_is_not_ready() {
        let dir = tempfile::tempdir().unwrap();
        let state = healthy_state(dir.path()).await;
        let store = state.store();

        // Positive arm first: a properly sealed row keeps readiness at 200.
        let good_aad = store.envelope_aad("profiles", "profile-good", "profile_enc");
        let good = crypto_store::seal(state.data_key(), &good_aad, b"{\"kind\":\"canary\"}")
            .expect("seal");
        insert_profile(store, "profile-good", good).await;

        let report = evaluate(&state).await;
        assert_eq!(report.status(), StatusCode::OK, "{report:?}");
        let detail = &report.check(KEY_CANARIES).unwrap().detail;
        assert!(
            detail.contains("opened 1 sampled"),
            "the sample must actually have read the row: {detail}"
        );

        // Now a row sealed under a *different* key — exactly what a rotated
        // `STREAM_G_DATA_KEY_HEX` leaves behind.
        let other_key = DataKey::from_hex(&hex::encode([0x11u8; 32])).unwrap();
        assert_ne!(other_key.key_id(), state.data_key().key_id());
        let bad_aad = store.envelope_aad("profiles", "profile-a-rotated", "profile_enc");
        let bad = crypto_store::seal(&other_key, &bad_aad, b"{\"kind\":\"canary\"}").expect("seal");
        insert_profile(store, "profile-a-rotated", bad).await;

        let report = evaluate(&state).await;
        assert_eq!(
            report.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{report:?}"
        );
        let canaries = report.check(KEY_CANARIES).unwrap();
        assert!(!canaries.ok);
        assert!(canaries.detail.contains("profiles"), "{canaries:?}");
    }

    /// `auth_challenges.nonce` is a `TEXT` column holding `hex(envelope)`, so
    /// it has a corruption mode the `BLOB` columns do not: text that is not
    /// hex at all. That must be a canary failure, not a silently skipped row —
    /// a row the check cannot even decode is exactly the row it exists to
    /// notice.
    ///
    /// Mutation this detects: `sample_sealed_envelopes` dropping undecodable
    /// hex rows (e.g. `filter_map`) instead of returning `(pk, None)`, or
    /// `check_key_canaries` treating `None` as a pass.
    #[tokio::test]
    async fn a_hex_column_that_is_not_hex_fails_the_canary() {
        let dir = tempfile::tempdir().unwrap();
        let state = healthy_state(dir.path()).await;
        let store = state.store();

        // Positive arm: a properly sealed, hex-encoded challenge is fine.
        let good_aad = store.envelope_aad("auth_challenges", "chal-good", "nonce");
        let good = hex::encode(
            crypto_store::seal(state.data_key(), &good_aad, b"{\"nonce\":\"x\"}").expect("seal"),
        );
        insert_challenge(store, "chal-good", &good).await;
        assert_eq!(evaluate(&state).await.status(), StatusCode::OK);

        insert_challenge(store, "chal-corrupt", "this is not hex").await;
        let report = evaluate(&state).await;
        assert_eq!(
            report.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{report:?}"
        );
        let canaries = report.check(KEY_CANARIES).unwrap();
        assert!(!canaries.ok);
        assert!(canaries.detail.contains("auth_challenges"), "{canaries:?}");
    }

    /// The readiness document is returned to an unauthenticated caller, so it
    /// must never echo a sealed payload, a plaintext, or key material — spec
    /// §9.3 classes signed intents as bearer capabilities until expiry.
    ///
    /// Mutation this detects: a `detail` string built with the row's pk or its
    /// bytes in it (e.g. `format!("{pk}: {envelope:?}")`), which is the
    /// natural thing to write when debugging a canary failure.
    #[tokio::test]
    async fn the_readiness_document_never_echoes_payload_or_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let state = healthy_state(dir.path()).await;
        let store = state.store();

        let marker_pk = "profile-PAYLOADMARKER-77";
        let plaintext = b"SIGNED-INTENT-BEARER-CAPABILITY-MARKER";
        let aad = store.envelope_aad("profiles", marker_pk, "profile_enc");
        let sealed = crypto_store::seal(state.data_key(), &aad, plaintext).expect("seal");
        let sealed_hex = hex::encode(&sealed);
        insert_profile(store, marker_pk, sealed).await;

        let report = evaluate(&state).await;
        let rendered = serde_json::to_string(&report).expect("serialize");

        assert!(!rendered.contains("PAYLOADMARKER"), "{rendered}");
        assert!(!rendered.contains("BEARER-CAPABILITY-MARKER"), "{rendered}");
        assert!(!rendered.contains(&sealed_hex), "{rendered}");
        assert!(
            !rendered.contains(&hex::encode([0x42u8; 32])),
            "the data key hex leaked into readiness: {rendered}"
        );
        // Paired non-zero arm: the document is not empty, and the row really
        // was sampled — otherwise the assertions above would pass on nothing.
        assert!(rendered.contains("key_canaries"), "{rendered}");
        assert!(
            report
                .check(KEY_CANARIES)
                .unwrap()
                .detail
                .contains("opened 1 sampled"),
            "{report:?}"
        );
        // key_id is a hash prefix and is deliberately printed; assert it is
        // the *only* key-derived value that appears.
        assert!(rendered.contains(state.data_key().key_id()), "{rendered}");
    }

    /// An empty report can never be ready — the guard that stops a future edit
    /// which drops every check from turning readiness permanently green.
    #[test]
    fn an_empty_report_is_not_ready() {
        let empty = ReadinessReport::from_checks(vec![]);
        assert!(!empty.ready);
        assert_eq!(empty.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Paired arm: one passing check is ready, so the assertion above is
        // about emptiness and not about `from_checks` always saying no.
        let one = ReadinessReport::from_checks(vec![ReadinessCheck::ok("x", "y")]);
        assert!(one.ready);
        assert_eq!(one.status(), StatusCode::OK);
    }

    /// [`store::SEALED_COLUMNS`] is parsed out of the frozen migration rather
    /// than trusted: a future migration that adds an `_enc` column without
    /// adding it here would silently shrink the canary's coverage.
    ///
    /// Mutation this detects: deleting any entry from `SEALED_COLUMNS` —
    /// verified by removing the `tx_attempts.raw_tx_enc` entry, after which
    /// this test fails naming that column.
    #[test]
    fn sealed_columns_cover_every_enc_column_in_the_schema() {
        let sql = concat!(
            include_str!("../../migrations/0001_stream_g.sql"),
            include_str!("../../migrations/0002_stream_g_outbox.sql"),
        );

        // Every declared column whose name ends in `_enc`, taken from the DDL
        // itself. Comment lines are skipped so the migration's prose (which
        // does mention `_enc` columns) cannot satisfy this.
        let mut declared: Vec<String> = Vec::new();
        for line in sql.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("--") {
                continue;
            }
            let Some(name) = trimmed.split_whitespace().next() else {
                continue;
            };
            let name = name.trim_end_matches(',');
            if name.ends_with("_enc") {
                declared.push(name.to_string());
            }
        }
        assert!(
            declared.len() >= 8,
            "the DDL scan found only {declared:?} — the parser, not the schema, is broken"
        );

        for name in &declared {
            assert!(
                store::SEALED_COLUMNS.iter().any(|c| c.column == name),
                "sealed column {name} is in the schema but not in SEALED_COLUMNS, so the \
                 readiness canary never samples it"
            );
        }

        // The hand-added non-`_enc` entry (`auth_challenges.nonce` is TEXT
        // holding a hex envelope) is the one the scan cannot find, so assert
        // it explicitly rather than losing it to the loop above.
        let nonce = store::SEALED_COLUMNS
            .iter()
            .find(|c| c.table == "auth_challenges")
            .expect("auth_challenges.nonce must be sampled");
        assert_eq!(nonce.column, "nonce");
        assert_eq!(nonce.encoding, SealedEncoding::HexText);
    }
}

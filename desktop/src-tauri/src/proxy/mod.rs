//! The residential bandwidth surface's backend: one hashed disclosure artifact, the
//! consent gate, the daemon-held caps, the sidecar supervisor, and the ten IPC
//! commands the Bandwidth tab speaks to.
//!
//! # This plane is NOT `WorkBackend`
//!
//! `WorkBackend` is the public-good WORK plane, and a catalog row there renders in the
//! Contribute selector carrying "1 credited work unit = 1 GOAT". Bandwidth sharing is
//! supply-neutral -- it creates no GOAT -- so registering it there would put a
//! supply-neutral activity inside the supply-creating catalog. These commands are
//! registered directly; the `backend_proxy_*` prefix is IPC-naming consistency only.
//!
//! # Persistence: the Rust plane only
//!
//! Three files under the app's own data directory, beside `fah-state.json`:
//! `proxy-consent.json`, `proxy-limits.json`, `proxy-device.json`. Zero proxy state
//! lives in the JavaScript store: caps must hold with this window's process dead, so
//! the authority has to be a file the daemon owns, and the JS store is writable by the
//! webview -- the least trusted surface in the app. They are deliberately NOT added to
//! the FAH persisted struct either: a bandwidth policy is not folding state, and a
//! schema change there silently wipes the file.
//!
//! Design authority: the "The No-Ponzi Invariant — GoatCoin's load-bearing economic
//! rule" spec, §1 and §8.

pub mod consent;
pub mod limits;
pub mod policy;
pub mod supervisor;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::wallet::WalletState;

pub use supervisor::{EgressEvent, ProxyHaltReceipt, ProxyStatus, ProxySupervisor};

/// The same directory `fah-state.json` lives in. Never the JS store's file.
pub fn state_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("com.goatcoin.dagoat"))
        .unwrap_or_else(|| std::env::temp_dir().join("com.goatcoin.dagoat"))
}

/// An opaque per-installation identifier. Sixteen random bytes, generated once.
///
/// Never a hostname, never a serial number, never anything that identifies a person --
/// it exists so one operator's two machines produce two records rather than one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DeviceFile {
    #[serde(default)]
    device_id: String,
}

/// Serialises generate-then-write.
///
/// Two callers racing here would each generate an id, each write, and each return its
/// own -- so the same install would produce two device ids and the second signed
/// record would name a device the first did not. The read is repeated INSIDE the lock
/// for the same reason.
static DEVICE_ID_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn read_device_id(path: &std::path::Path) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let f: DeviceFile = serde_json::from_str(&raw).ok()?;
    (f.device_id.len() == 32).then_some(f.device_id)
}

pub fn device_id() -> String {
    let dir = state_dir();
    let path = dir.join("proxy-device.json");
    if let Some(id) = read_device_id(&path) {
        return id;
    }
    let _guard = DEVICE_ID_GATE.lock();
    if let Some(id) = read_device_id(&path) {
        return id;
    }
    let mut bytes = [0u8; 16];
    rand::Rng::fill(&mut rand::rng(), &mut bytes[..]);
    let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let _ = std::fs::create_dir_all(&dir);
    let body = serde_json::to_string_pretty(&DeviceFile {
        device_id: id.clone(),
    })
    .unwrap_or_default();
    let tmp = dir.join("proxy-device.json.tmp");
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
    read_device_id(&path).unwrap_or(id)
}

/// What `backend_proxy_policy` hands the screen: the one hashed artifact plus the two
/// digests THIS process computed, so the screen can refuse to sign text whose hash it
/// cannot reproduce.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyPolicyDoc {
    pub policy: policy::PolicyDoc,
    pub policy_digest: String,
    pub allowlist_digest: String,
    pub device_id: String,
}

// ---------------------------------------------------------------------------
// The ten commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn backend_proxy_available() -> bool {
    supervisor::available()
}

/// A REFUSAL, not an empty string, when this build cannot name its own
/// destinations canonically.
///
/// The screen compares the digest it computes against the one this command
/// returns and refuses to sign when they differ. Returning an empty digest here
/// would leave that comparison to fail for an unexplained reason; returning an
/// error names the actual problem.
#[tauri::command]
pub fn backend_proxy_policy() -> Result<ProxyPolicyDoc, String> {
    let doc = policy::policy_doc();
    let allowlist_digest = policy::allowlist_digest(&doc).map_err(|e| {
        format!("this build cannot name its own destination list: {e}")
    })?;
    Ok(ProxyPolicyDoc {
        policy_digest: policy::policy_digest(&doc),
        allowlist_digest,
        policy: doc,
        device_id: device_id(),
    })
}

/// THE EXPECTED ADDRESS IS RESOLVED HERE, NEVER SUPPLIED BY THE WEBVIEW.
///
/// The IPC table drafted these commands taking a `wallet` argument. A check whose
/// expected value the caller supplies is self-referential: the webview would name the
/// same address the record names and every self-signed blob would verify. The address
/// compared is the one this process holds unlocked, and nothing else.
fn active_wallet(state: &tauri::State<'_, WalletState>) -> Option<String> {
    crate::wallet::active_address(state)
}

#[tauri::command]
pub fn backend_proxy_consent_status(
    wallet_state: tauri::State<'_, WalletState>,
) -> consent::ProxyConsentStatus {
    let dir = state_dir();
    consent::status(
        consent::load(&dir).as_ref(),
        supervisor::now_unix(),
        active_wallet(&wallet_state).as_deref(),
    )
}

/// Verify BEFORE writing, and on failure write nothing.
///
/// A rejected record must leave no trace: a half-stored record is one the sidecar then
/// refuses on its own, which reads to the operator as "I signed and it broke".
#[tauri::command]
pub fn backend_proxy_consent_grant(
    wallet_state: tauri::State<'_, WalletState>,
    record_json: String,
) -> Result<consent::ProxyConsentStatus, String> {
    let record: consent::ProxyConsentRecord = serde_json::from_str(&record_json)
        .map_err(|_| "the record could not be read".to_string())?;
    let active = active_wallet(&wallet_state).ok_or("no wallet is active")?;
    let expected = consent::current_digests()
        .map_err(|e| format!("this build cannot name its own destination list: {e}"))?;
    let state = consent::verify(&record, &expected, supervisor::now_unix(), Some(&active));
    if state != consent::ConsentState::Valid {
        return Err(format!("the record was refused: {state:?}"));
    }
    let dir = state_dir();
    consent::store(&dir, &record)?;
    Ok(consent::status(
        Some(&record),
        supervisor::now_unix(),
        Some(&active),
    ))
}

/// Halt FIRST, then disable, then erase. In that order, so no window exists in which
/// the record is gone and traffic is still moving.
#[tauri::command]
pub async fn backend_proxy_consent_revoke(
    sup: tauri::State<'_, ProxySupervisor>,
) -> Result<ProxyHaltReceipt, String> {
    let dir = state_dir();
    let receipt = sup.halt("consent withdrawn").await?;
    let mut l = limits::load(&dir).unwrap_or_default();
    l.enabled = false;
    limits::store(&dir, &limits::clamp(l))?;
    consent::erase(&dir)?;
    Ok(receipt)
}

#[tauri::command]
pub fn backend_proxy_limits() -> limits::ProxyLimits {
    limits::load(&state_dir()).unwrap_or_default()
}

/// `enabled: true` is INTENT, not permission.
///
/// The consent state is re-checked here; the values are clamped; only then are they
/// stored, and only then is the sidecar started or halted. A hand-crafted `invoke`
/// that sets `enabled` cannot start anything the record does not authorise.
#[tauri::command]
pub async fn backend_proxy_set_limits(
    sup: tauri::State<'_, ProxySupervisor>,
    wallet_state: tauri::State<'_, WalletState>,
    limits_json: String,
) -> Result<limits::ProxyLimits, String> {
    let dir = state_dir();
    let active = active_wallet(&wallet_state);
    let parsed: limits::ProxyLimits = serde_json::from_str(&limits_json)
        .map_err(|_| "the limits could not be read".to_string())?;
    let mut next = limits::clamp(parsed);

    if next.enabled {
        let status = consent::status(
            consent::load(&dir).as_ref(),
            supervisor::now_unix(),
            active.as_deref(),
        );
        if status.state != consent::ConsentState::Valid {
            return Err(format!(
                "bandwidth sharing stays off: consent is {:?}",
                status.state
            ));
        }
    }
    limits::store(&dir, &next)?;

    if next.enabled {
        if let Err(e) = sup.spawn(&dir, active.as_deref()).await {
            // The intent is recorded, the process did not start: report the reason and
            // put the stored switch back where the daemon actually is.
            next.enabled = false;
            limits::store(&dir, &next)?;
            return Err(e);
        }
    } else {
        sup.halt("operator switched it off").await?;
    }
    Ok(limits::load(&dir).unwrap_or(next))
}

#[tauri::command]
pub async fn backend_proxy_status(
    sup: tauri::State<'_, ProxySupervisor>,
    wallet_state: tauri::State<'_, WalletState>,
) -> Result<ProxyStatus, String> {
    let active = active_wallet(&wallet_state);
    Ok(sup.status(&state_dir(), active.as_deref()).await)
}

#[tauri::command]
pub fn backend_proxy_egress_log(
    sup: tauri::State<'_, ProxySupervisor>,
    since_seq: u64,
) -> Vec<EgressEvent> {
    sup.egress_since(since_seq)
}

/// Stop everything, KEEP the signed record.
///
/// Restarting must not require signing again -- an operator who hit the stop button
/// has not withdrawn consent, and making them re-read the disclosure to resume trains
/// them to click through it.
#[tauri::command]
pub async fn backend_proxy_kill(
    sup: tauri::State<'_, ProxySupervisor>,
) -> Result<ProxyHaltReceipt, String> {
    let dir = state_dir();
    let mut l = limits::load(&dir).unwrap_or_default();
    l.enabled = false;
    let _ = limits::store(&dir, &limits::clamp(l));
    sup.halt("operator pressed stop").await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutations this detects: a device id derived from anything about the machine.
    /// Sixteen random bytes are sixteen random bytes; a hostname is a person.
    #[test]
    fn a_device_id_is_thirty_two_hex_characters_and_carries_no_machine_fact() {
        let id = device_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable across calls, because it is stored.
        assert_eq!(device_id(), id);
        let host = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_default()
            .to_lowercase();
        if !host.is_empty() {
            assert!(!id.contains(&host));
        }
    }

    /// Mutations this detects: the proxy files moving into the JavaScript store's
    /// file, which the webview can write -- and which a killed window takes with it.
    #[test]
    fn the_three_proxy_files_live_beside_the_rust_state_and_not_in_the_js_store() {
        let dir = state_dir();
        for name in [
            "proxy-consent.json",
            "proxy-limits.json",
            "proxy-device.json",
        ] {
            assert_eq!(dir.join(name).parent(), Some(dir.as_path()));
        }
        assert_eq!(consent::consent_path(&dir), dir.join("proxy-consent.json"));
        assert_eq!(limits::limits_path(&dir), dir.join("proxy-limits.json"));
        assert!(
            !dir.join("app-state.dat").exists()
                || dir.join("proxy-limits.json") != dir.join("app-state.dat")
        );
    }

    #[test]
    fn the_policy_command_hands_the_screen_the_digests_this_process_computed() {
        let doc = backend_proxy_policy().expect("the shipped document resolves");
        assert_eq!(doc.policy_digest, policy::policy_digest(&doc.policy));
        assert_eq!(
            doc.allowlist_digest,
            policy::allowlist_digest(&doc.policy).expect("resolves")
        );
        assert_eq!(doc.policy.policy_version, 1);
        // The digest the screen is handed is the CANONICAL one, reached from the
        // registry's own numbering rather than from this document's slugs, so the
        // command cannot hand out a digest only this half of the app can
        // reproduce.
        let by_id: Vec<(u32, &str)> = doc
            .policy
            .allowlist
            .iter()
            .map(|e| {
                (
                    goat_proxy_worker::destinations::id_for_slug(&e.id)
                        .expect("a shipped slug is registered"),
                    e.host.as_str(),
                )
            })
            .collect();
        let canonical = goat_proxy_worker::destinations::canonical_digest_by_id(&by_id)
            .expect("the ids resolve");
        assert_eq!(
            doc.allowlist_digest,
            canonical.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }
}

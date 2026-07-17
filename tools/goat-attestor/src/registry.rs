//! Local worker registry (JSON): bound username ↔ wallet + enrollment batch flags.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerEntry {
    pub wallet: String,
    pub username: String,
    /// True once an enrollment-snapshot batch has been proposed for this worker.
    #[serde(default)]
    pub baseline_batched: bool,
    /// Optional FAH numeric id once known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fah_id: Option<u64>,
    /// Epoch id of the enrollment batch proposed for this worker (if any).
    #[serde(default)]
    pub enrollment_epoch: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerRegistry {
    pub workers: Vec<WorkerEntry>,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("IO: {0}")]
    Io(String),
    #[error("JSON: {0}")]
    Json(String),
}

impl WorkerRegistry {
    pub fn new() -> Self {
        Self {
            workers: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = fs::read_to_string(path).map_err(|e| RegistryError::Io(e.to_string()))?;
        // Accept either `{ "workers": [...] }` or bare `[...]`.
        if raw.trim_start().starts_with('[') {
            let workers: Vec<WorkerEntry> =
                serde_json::from_str(&raw).map_err(|e| RegistryError::Json(e.to_string()))?;
            Ok(Self { workers })
        } else {
            serde_json::from_str(&raw).map_err(|e| RegistryError::Json(e.to_string()))
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| RegistryError::Io(e.to_string()))?;
            }
        }
        let raw =
            serde_json::to_string_pretty(self).map_err(|e| RegistryError::Json(e.to_string()))?;
        fs::write(path, raw).map_err(|e| RegistryError::Io(e.to_string()))
    }

    pub fn upsert(&mut self, entry: WorkerEntry) {
        if let Some(existing) = self
            .workers
            .iter_mut()
            .find(|w| w.wallet.eq_ignore_ascii_case(&entry.wallet))
        {
            *existing = entry;
        } else {
            self.workers.push(entry);
        }
    }

    /// Workers that are bound but have not yet had an enrollment snapshot batched.
    pub fn needs_enrollment_batch(&self) -> Vec<&WorkerEntry> {
        self.workers
            .iter()
            .filter(|w| !w.baseline_batched)
            .collect()
    }

    pub fn mark_baseline_batched(&mut self, wallet: &str, epoch: u64) {
        if let Some(w) = self
            .workers
            .iter_mut()
            .find(|w| w.wallet.eq_ignore_ascii_case(wallet))
        {
            w.baseline_batched = true;
            w.enrollment_epoch = Some(epoch);
        }
    }

    /// Clear enrollment batch flag (legacy self-heal when `enrollment_epoch` is missing).
    pub fn clear_baseline_batched(&mut self, wallet: &str) {
        if let Some(w) = self
            .workers
            .iter_mut()
            .find(|w| w.wallet.eq_ignore_ascii_case(wallet))
        {
            w.baseline_batched = false;
            w.enrollment_epoch = None;
        }
    }

    pub fn all_bound(&self) -> &[WorkerEntry] {
        &self.workers
    }

    /// Merge on-chain `Bound` workers into the local registry.
    /// - New wallets: insert with `baseline_batched = false`.
    /// - Existing: refresh `username` if changed; keep `baseline_batched` / `fah_id`.
    ///
    /// Returns how many **new** workers were added.
    pub fn sync_from_bound_workers(
        &mut self,
        bound: impl IntoIterator<Item = (String, String)>,
    ) -> usize {
        let mut added = 0;
        for (wallet, username) in bound {
            let wallet = wallet.trim().to_string();
            let username = username.trim().to_string();
            if wallet.is_empty() || username.is_empty() {
                continue;
            }
            if let Some(existing) = self
                .workers
                .iter_mut()
                .find(|w| w.wallet.eq_ignore_ascii_case(&wallet))
            {
                if existing.username != username {
                    existing.username = username;
                }
            } else {
                self.workers.push(WorkerEntry {
                    wallet,
                    username,
                    baseline_batched: false,
                    fah_id: None,
                    enrollment_epoch: None,
                });
                added += 1;
            }
        }
        added
    }

    /// Replace registry with the on-chain Bound set (authoritative for redeploys).
    /// Preserves `baseline_batched` / `fah_id` / `enrollment_epoch` for wallets that still exist on-chain.
    /// Returns (added, removed).
    pub fn replace_from_bound_workers(
        &mut self,
        bound: impl IntoIterator<Item = (String, String)>,
    ) -> (usize, usize) {
        let prev = std::mem::take(&mut self.workers);
        let mut kept_flags: std::collections::HashMap<String, (bool, Option<u64>, Option<u64>)> =
            std::collections::HashMap::new();
        for w in &prev {
            kept_flags.insert(
                w.wallet.to_ascii_lowercase(),
                (w.baseline_batched, w.fah_id, w.enrollment_epoch),
            );
        }
        let mut seen = std::collections::HashSet::new();
        for (wallet, username) in bound {
            let wallet = wallet.trim().to_string();
            let username = username.trim().to_string();
            if wallet.is_empty() || username.is_empty() {
                continue;
            }
            let key = wallet.to_ascii_lowercase();
            if !seen.insert(key.clone()) {
                continue;
            }
            let (baseline_batched, fah_id, enrollment_epoch) =
                kept_flags.get(&key).copied().unwrap_or((false, None, None));
            self.workers.push(WorkerEntry {
                wallet,
                username,
                baseline_batched,
                fah_id,
                enrollment_epoch,
            });
        }
        let after: std::collections::HashSet<String> = self
            .workers
            .iter()
            .map(|w| w.wallet.to_ascii_lowercase())
            .collect();
        let before: std::collections::HashSet<String> =
            prev.iter().map(|w| w.wallet.to_ascii_lowercase()).collect();
        let added = after.difference(&before).count();
        let removed = before.difference(&after).count();
        (added, removed)
    }

    /// Register one bind immediately (relayer path). Idempotent.
    pub fn register_bind(&mut self, wallet: &str, username: &str) -> bool {
        let before = self.workers.len();
        self.sync_from_bound_workers([(wallet.to_string(), username.to_string())]);
        self.workers.len() > before
    }
}

impl Default for WorkerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_save_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let mut reg = WorkerRegistry::new();
        reg.upsert(WorkerEntry {
            wallet: "0x00000000000000000000000000000000000000A1".into(),
            username: "GOAT-alice".into(),
            baseline_batched: false,
            fah_id: None,
            enrollment_epoch: None,
        });
        reg.save(&path).unwrap();
        let loaded = WorkerRegistry::load(&path).unwrap();
        assert_eq!(loaded.workers.len(), 1);
        assert!(!loaded.workers[0].baseline_batched);
    }

    #[test]
    fn enrollment_flags() {
        let mut reg = WorkerRegistry::new();
        reg.upsert(WorkerEntry {
            wallet: "0xA1".into(),
            username: "GOAT-alice".into(),
            baseline_batched: false,
            fah_id: None,
            enrollment_epoch: None,
        });
        reg.upsert(WorkerEntry {
            wallet: "0xB2".into(),
            username: "GOAT-bob".into(),
            baseline_batched: true,
            fah_id: None,
            enrollment_epoch: Some(1),
        });
        let need = reg.needs_enrollment_batch();
        assert_eq!(need.len(), 1);
        assert_eq!(need[0].username, "GOAT-alice");
        reg.mark_baseline_batched("0xA1", 1);
        assert!(reg.needs_enrollment_batch().is_empty());
        let alice = reg.workers.iter().find(|w| w.wallet == "0xA1").unwrap();
        assert_eq!(alice.enrollment_epoch, Some(1));
    }

    #[test]
    fn sync_from_bound_adds_and_preserves_baseline_flag() {
        let mut reg = WorkerRegistry::new();
        reg.upsert(WorkerEntry {
            wallet: "0x00000000000000000000000000000000000000A1".into(),
            username: "GOAT-alice".into(),
            baseline_batched: true,
            fah_id: Some(1),
            enrollment_epoch: Some(9_000_000_000_001),
        });
        let added = reg.sync_from_bound_workers([
            (
                "0x00000000000000000000000000000000000000A1".into(),
                "GOAT-alice".into(),
            ),
            (
                "0x00000000000000000000000000000000000000B2".into(),
                "GOAT-rookie".into(),
            ),
        ]);
        assert_eq!(added, 1);
        assert_eq!(reg.workers.len(), 2);
        let alice = reg
            .workers
            .iter()
            .find(|w| w.wallet.ends_with("a1") || w.wallet.ends_with("A1"))
            .unwrap();
        assert!(alice.baseline_batched);
        assert_eq!(alice.fah_id, Some(1));
        assert_eq!(alice.enrollment_epoch, Some(9_000_000_000_001));
        let rook = reg
            .workers
            .iter()
            .find(|w| w.username == "GOAT-rookie")
            .unwrap();
        assert!(!rook.baseline_batched);
        assert_eq!(rook.enrollment_epoch, None);
    }
}

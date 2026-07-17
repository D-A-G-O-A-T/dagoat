//! Evidence file writer + keccak ref used as `evidenceRef` on-chain.

use std::fs;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::merkle::keccak256;

/// Write pretty JSON evidence under `dir/{name}` and return the path.
pub fn write_evidence_json<T: Serialize>(
    dir: &Path,
    name: &str,
    value: &T,
) -> Result<std::path::PathBuf, String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join(name);
    let raw = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    fs::write(&path, &raw).map_err(|e| e.to_string())?;
    Ok(path)
}

/// `evidenceRef` = keccak256 of arbitrary bytes (typically the evidence JSON).
pub fn evidence_ref_keccak(bytes: &[u8]) -> [u8; 32] {
    keccak256(bytes)
}

/// Optional SHA-256 hex of a body (for human-readable evidence digests).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_and_hash() {
        let dir = tempdir().unwrap();
        let path = write_evidence_json(dir.path(), "e1.json", &serde_json::json!({"a":1})).unwrap();
        let bytes = fs::read(&path).unwrap();
        let r = evidence_ref_keccak(&bytes);
        assert_ne!(r, [0u8; 32]);
        assert_eq!(r, evidence_ref_keccak(&bytes));
    }
}

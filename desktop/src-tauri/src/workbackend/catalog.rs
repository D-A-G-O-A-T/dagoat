//! Backend catalog — the source of truth the Miner tab's selector cards render from.
//!
//! The catalog is deliberately separate from the `Registry` (`super::Registry`): it describes
//! what's visible in the UI (id, display name, beneficiary, isolation class, honesty tags,
//! enabled/disabled) whereas the registry holds the actual `Box<dyn WorkBackend>` trait objects
//! wired up to Tauri commands. That split lets a catalog row exist with no backend behind it at
//! all — e.g. the disabled NGO placeholder, which is visibly pluggable in the UI without any
//! adapter code existing yet.

use serde::Serialize;

use super::{ConfigField, Registry, WorkBackend};

/// Published Season-0 conversion formula (design §4) — shown verbatim in Miner, Wallet, and
/// README copy. Mint basis is always the beneficiary's own credit accounting, never GPU model,
/// TFLOPS, uptime, or power level.
pub const SEASON0_FORMULA: &str = "1 credited Folding@home work unit (WU) = 1 work unit = 1 GOAT";

/// FAH's isolation/trust disclosure (design §3): the host runs the official FAHClient: Goat does
/// not claim, sandbox, or mediate the GPU itself.
pub const FAH_ISOLATION_CLASS: &str =
    "Class C — host runs the official FAHClient; Goat does not claim a GPU sandbox";

/// A catalog row as rendered by the Miner tab's backend selector.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CatalogEntry {
    pub id: &'static str,
    pub display_name: &'static str,
    pub beneficiary: &'static str,
    pub isolation_class: &'static str,
    pub honesty_tags: Vec<String>,
    pub formula: &'static str,
    pub enabled: bool,
    pub disabled_reason: Option<&'static str>,
    /// Fix-steps copy for the current `detect_install()` state; empty for rows with no adapter.
    pub install_hint: String,
    /// The config form the UI should render, declared by the adapter itself (empty for rows
    /// with no adapter, e.g. the disabled NGO placeholder).
    pub config_fields: Vec<ConfigField>,
}

/// Full catalog, driven by the live `Registry` (single source of truth — no metadata is
/// duplicated between a backend's trait methods and its catalog row): `folding_at_home` when
/// registered (always, today), plus `ngo_placeholder` (always present, disabled, no backend
/// exists), plus `rehearsal` only when it's actually registered (`GOAT_REHEARSAL=1` at
/// startup) — so the UI never shows a selector card for a backend id that isn't wired up.
pub fn catalog_entries(registry: &Registry) -> Vec<CatalogEntry> {
    let mut entries = Vec::new();

    if let Ok(fah) = registry.get("folding_at_home") {
        entries.push(enabled_entry_from(fah));
    }

    entries.push(CatalogEntry {
        id: "ngo_placeholder",
        display_name: "More public-good projects",
        beneficiary: "None yet — no NGO partner has been onboarded",
        isolation_class: "N/A — no adapter exists yet",
        honesty_tags: vec![],
        // No adapter exists yet, so no formula is published for it either — showing the FAH
        // formula here would falsely imply this row already has a conversion rate.
        formula: "—",
        enabled: false,
        disabled_reason: Some("More public-good projects when NGOs join"),
        install_hint: String::new(),
        config_fields: vec![],
    });

    if let Ok(rehearsal) = registry.get("rehearsal") {
        entries.push(enabled_entry_from(rehearsal));
    }

    entries
}

/// Builds a catalog row for any registered, enabled backend straight from its own trait methods.
fn enabled_entry_from(backend: &dyn WorkBackend) -> CatalogEntry {
    CatalogEntry {
        id: backend.id(),
        display_name: backend.display_name(),
        beneficiary: backend.beneficiary(),
        isolation_class: backend.isolation_class(),
        honesty_tags: backend.honesty_tags(),
        formula: SEASON0_FORMULA,
        enabled: true,
        disabled_reason: None,
        install_hint: backend.install_hint(),
        config_fields: backend.config_fields(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::rehearsal;
    use super::*;

    #[test]
    fn always_includes_fah_enabled_and_ngo_disabled() {
        let _guard = rehearsal::env_lock();
        std::env::remove_var("GOAT_REHEARSAL");
        let entries = catalog_entries(&super::super::build_registry());

        let fah = entries
            .iter()
            .find(|e| e.id == "folding_at_home")
            .expect("folding_at_home row must exist");
        assert!(fah.enabled);
        assert!(fah.honesty_tags.iter().any(|t| t.contains("1 GOAT")));
        assert!(fah.isolation_class.contains("Class C"));
        // Managed engine: Start contributing auto-downloads + launches the official installer.
        let hint = fah.install_hint.to_lowercase();
        assert!(
            hint.contains("managed")
                || hint.contains("portable")
                || hint.contains("start contributing"),
            "expected managed-engine install hint, got: {}",
            fah.install_hint
        );

        let ngo = entries
            .iter()
            .find(|e| e.id == "ngo_placeholder")
            .expect("ngo_placeholder row must exist");
        assert!(!ngo.enabled);
        assert_eq!(
            ngo.disabled_reason,
            Some("More public-good projects when NGOs join")
        );
    }

    #[test]
    fn fah_declares_config_fields_with_passkey_secret() {
        let _guard = rehearsal::env_lock();
        std::env::remove_var("GOAT_REHEARSAL");
        let entries = catalog_entries(&super::super::build_registry());

        let fah = entries
            .iter()
            .find(|e| e.id == "folding_at_home")
            .expect("folding_at_home row must exist");
        let keys: Vec<&str> = fah.config_fields.iter().map(|f| f.key).collect();
        assert_eq!(keys, vec!["username", "team", "passkey"]);
        assert!(
            fah.config_fields
                .iter()
                .find(|f| f.key == "passkey")
                .expect("passkey field present")
                .secret,
            "passkey must be marked secret so the UI renders it as a password input"
        );
        assert!(fah
            .config_fields
            .iter()
            .filter(|f| f.key != "passkey")
            .all(|f| !f.secret));
    }

    #[test]
    fn ngo_placeholder_has_no_config_fields_and_no_borrowed_formula() {
        let _guard = rehearsal::env_lock();
        std::env::remove_var("GOAT_REHEARSAL");
        let entries = catalog_entries(&super::super::build_registry());

        let ngo = entries
            .iter()
            .find(|e| e.id == "ngo_placeholder")
            .expect("ngo_placeholder row must exist");
        assert!(ngo.config_fields.is_empty());
        // No adapter exists yet, so it must not falsely claim the FAH conversion formula.
        assert_ne!(ngo.formula, SEASON0_FORMULA);
        assert_eq!(ngo.formula, "—");
    }

    #[test]
    fn rehearsal_has_no_config_fields() {
        let _guard = rehearsal::env_lock();
        std::env::set_var("GOAT_REHEARSAL", "1");

        let entries = catalog_entries(&super::super::build_registry());
        let rehearsal_entry = entries
            .iter()
            .find(|e| e.id == "rehearsal")
            .expect("rehearsal row must appear when GOAT_REHEARSAL=1");
        assert!(rehearsal_entry.config_fields.is_empty());

        std::env::remove_var("GOAT_REHEARSAL");
    }

    #[test]
    fn rehearsal_row_hidden_without_env() {
        let _guard = rehearsal::env_lock();
        std::env::remove_var("GOAT_REHEARSAL");

        let entries = catalog_entries(&super::super::build_registry());
        assert!(!entries.iter().any(|e| e.id == "rehearsal"));
    }

    #[test]
    fn rehearsal_row_present_with_env_and_carries_ci_tag() {
        let _guard = rehearsal::env_lock();
        std::env::set_var("GOAT_REHEARSAL", "1");

        let entries = catalog_entries(&super::super::build_registry());
        let rehearsal_entry = entries
            .iter()
            .find(|e| e.id == "rehearsal")
            .expect("rehearsal row must appear when GOAT_REHEARSAL=1");
        assert!(rehearsal_entry
            .honesty_tags
            .iter()
            .any(|t| t == "REHEARSAL — CI only, not a founder demo"));

        std::env::remove_var("GOAT_REHEARSAL");
    }
}

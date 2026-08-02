//! Lane-scoped audits. `#[cfg(test)]` and private, like `citation_audit` and
//! `license_audit`: they ship no runtime behaviour.
//!
//! Like those two, this file **is** published, and the reason is structural
//! rather than editorial: `src/proxy/mod.rs` declares the module, `mod.rs` is
//! published, and a tree that carries the declaration without the file does not
//! compile. Withholding it does not keep a test-only module off the public
//! surface; it breaks the build for everyone. This module previously asserted
//! its own ABSENCE from the baseline, on the stated grounds that
//! `citation_audit` and `license_audit` are absent too — they are not, and were
//! never absent. Acting on that claim published a `mod` declaration pointing at
//! nothing and turned three CI jobs red with `E0583`.
//!
//! Four sweeps, and each one carries a positive control. A sweep that has never
//! fired is indistinguishable from a broken one, and every sweep here asserts
//! that something is ABSENT -- which is exactly the shape that passes against a
//! scanner reading an empty corpus.
//!
//! The controls are deliberately of two kinds, because they catch different
//! failures:
//!
//! * **Corpus controls** assert the swept text contains a symbol only the real
//!   lane sources have (`BytesTransferredReceipt`, `PROXY_LEAF_DOMAIN_STR`,
//!   `allowlist`). These catch "the reader read the wrong directory", which a
//!   file-count floor alone does not: a floor is satisfied by any eight files.
//! * **Matcher controls** assert the needle fires against a string built from
//!   it. These catch "the marker assembly is broken", which a corpus control
//!   does not.

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    /// Forbidden markers are assembled at runtime, exactly as
    /// `citation_audit::internal_doc_tree_markers()` does, so no whole banned
    /// token is written as a literal here.
    ///
    /// Assembly alone is not enough, and the exclusion below is what actually
    /// carries it: two fragments of this file's own rule tables are themselves
    /// substrings a rule bans, and the module doc names its two sibling audits
    /// by their real names, one of which is a banned token in full. A sweep that
    /// reads itself is a sweep that can never be green, so `lane_files()` drops
    /// this file by name.
    fn marker(parts: &[&str]) -> String {
        parts.concat()
    }

    /// The crate root, resolved from the manifest rather than from the process
    /// working directory.
    ///
    /// `cargo test` happens to set the cwd to the package root today, so
    /// `read_dir("src/proxy")` would work; it stops working the moment anything
    /// runs this suite from elsewhere, and a sweep that silently reads zero
    /// files is the failure this whole module exists to prevent. The vacuity
    /// guards would catch it -- but as a panic in an unrelated place, which is a
    /// worse failure than not having the bug.
    fn crate_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Every file of this lane, as `(shown path, text)`.
    ///
    /// `src/proxy/` in full, plus this lane's migration and nothing else's.
    /// `lane_audit.rs` itself is excluded.
    fn lane_files() -> Vec<(String, String)> {
        let root = crate_root();
        let mut out = Vec::new();
        for dir in ["src/proxy", "migrations"] {
            let abs: PathBuf = root.join(dir.replace('/', std::path::MAIN_SEPARATOR_STR).as_str());
            let entries = std::fs::read_dir(&abs).unwrap_or_else(|e| panic!("read {dir}: {e}"));
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let name = shown(&path);
                if name.ends_with("lane_audit.rs") {
                    continue; // a sweep must not read itself
                }
                if dir == "migrations" && !name.contains("proxy") {
                    continue; // only this lane's migration
                }
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                out.push((name, text));
            }
        }
        out
    }

    /// Repo-shaped path for a failure message: forward slashes, no absolute
    /// prefix.
    fn shown(path: &Path) -> String {
        let root = crate_root();
        path.strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }

    /// Floor on the swept corpus, in files AND in bytes.
    ///
    /// Ten `src/proxy` modules plus one migration = 11 today. The floor is a
    /// `>=` here rather than the exact count the master's convention prefers,
    /// because this sweep's job is "read the whole directory" and the directory
    /// grows; the *byte* floor below is what a truncating reader trips on, and
    /// it is the one a file-count floor cannot substitute for.
    const MIN_LANE_FILES: usize = 8;

    /// Measured 456 742 bytes today across the eleven files (on-disk bytes; the
    /// in-memory total is slightly lower where a file has CRLF line endings). A
    /// fifteenth of that is far above anything a truncated or empty read
    /// produces and far below anything a real deletion would leave, which is the
    /// band a byte floor has to sit in to be worth having.
    const MIN_LANE_BYTES: usize = 30_000;

    /// Assert the corpus is real before asserting anything is absent from it,
    /// and return it.
    fn swept_corpus(symbol: &str) -> Vec<(String, String)> {
        let files = lane_files();
        assert!(
            files.len() >= MIN_LANE_FILES,
            "vacuity guard: swept only {} file(s), floor is {MIN_LANE_FILES}",
            files.len()
        );
        let bytes: usize = files.iter().map(|(_, t)| t.len()).sum();
        assert!(
            bytes >= MIN_LANE_BYTES,
            "vacuity guard: swept only {bytes} byte(s) across {} file(s); a file-count floor \
             alone is defeated by a truncating reader",
            files.len()
        );
        // POSITIVE CONTROL: a symbol only the real lane sources carry. A floor
        // is satisfied by any eight files; this is what says they are the RIGHT
        // eight.
        assert!(
            files.iter().any(|(_, t)| t.contains(symbol)),
            "the sweep is not reading the lane's source: no file contains `{symbol}`"
        );
        files
    }

    /// Founder ruling FR-1 as an executable assertion. The take routes to
    /// protocol operations and the reserve only; there is no supply-destroying
    /// code path, parameter or event. An absent mechanism cannot be enabled
    /// later, which is the entire point of making it absent rather than zero.
    ///
    /// Mutations this detects: a supply-destroying function, constant, event or
    /// parameter added to any lane module or to migration 0004; the conventional
    /// sink address appearing as a payout destination.
    #[test]
    fn the_proxy_lane_contains_no_burn_mechanism() {
        let files = swept_corpus("BytesTransferredReceipt");
        let markers = [
            marker(&["bu", "rn"]),
            marker(&["0x000000000000000000000000000000000000", "dead"]),
        ];
        // MATCHER CONTROL: each needle fires against a line built from it, so a
        // marker that assembled to the empty string (which `contains` answers
        // `true` for, and would therefore fail loudly) or to something
        // unmatchable cannot pass unnoticed.
        for m in &markers {
            let probe = format!("    let x = {m}_bps;").to_ascii_lowercase();
            assert!(
                probe.contains(m.as_str()) && !m.is_empty(),
                "the marker `{m}` did not match a line built from it"
            );
        }
        for (name, text) in &files {
            let lower = text.to_ascii_lowercase();
            for m in &markers {
                assert!(
                    !lower.contains(m.as_str()),
                    "{name} contains a forbidden marker"
                );
            }
        }
    }

    /// INV-13. The lane transfers pre-funded GOAT. It must not be able to reach
    /// a supply-increasing path even by accident.
    ///
    /// The corpus control asserts the swept text contains a symbol only the real
    /// lane sources have. An earlier draft asserted that a string literal in the
    /// test body contained its own marker -- which tests `String::concat` and
    /// `str::contains` and says nothing about whether `lane_files()` read the
    /// right files, which is the exact failure a positive control exists to
    /// catch.
    ///
    /// Mutations this detects: an import of the compute lane's minter; a call to
    /// the compute settlement's payout claim; the supply-increasing verb
    /// reappearing anywhere in the lane, including in a doc comment that merely
    /// says the lane does not do it.
    #[test]
    fn the_proxy_lane_never_reaches_a_minting_path() {
        // `PROXY_LEAF_DOMAIN_STR` is the Rust-side leaf-domain constant, checked
        // against `proxy_merkle.rs` rather than assumed: the master's task body
        // named a constant §4.1 does not, and the rule is that the test names
        // what the source named, never the other way round.
        let files = swept_corpus("PROXY_LEAF_DOMAIN_STR");
        let markers = [
            marker(&["work", "minter"]),
            marker(&["claim", "_payout"]),
            marker(&["claim", "payout"]),
            marker(&["mi", "nt"]),
        ];
        for m in &markers {
            let probe = format!("use crate::{m};").to_ascii_lowercase();
            assert!(
                probe.contains(m.as_str()) && !m.is_empty(),
                "the marker `{m}` did not match a line built from it"
            );
        }
        for (name, text) in &files {
            let lower = text.to_ascii_lowercase();
            for m in &markers {
                assert!(
                    !lower.contains(m.as_str()),
                    "{name} names a supply-increasing symbol"
                );
            }
        }
    }

    /// Vocabulary law for the lane: allowlist / deny-net only, and no retired
    /// money vocabulary anywhere -- including comments, SQL and fixtures.
    ///
    /// The American spelling of the permission-document word is on the banned
    /// list because the master puts it there. It is **suspect and it is being
    /// raised rather than deleted**: no rule elsewhere forbids that word, and it
    /// collides with the crate's own `license_audit` concern, which requires
    /// published files to carry a header naming exactly that. It is harmless
    /// today only because Rust sources here carry no such header (the crate
    /// declares the dual licence in `Cargo.toml`) -- so the day a header
    /// convention changes, this entry reds the lane for doing the right thing.
    /// A sweep entry that looks wrong and is right is exactly the kind of guard
    /// that gets removed by whoever is annoyed by it second, so it stays until
    /// the founder rules.
    ///
    /// Mutations this detects: a deny-list spelled with any of its three
    /// conventional names; retired money vocabulary in an identifier, comment,
    /// SQL column or fixture string.
    #[test]
    fn the_proxy_lane_uses_allowlist_vocabulary_and_no_retired_money_words() {
        // The corpus control is the approved vocabulary itself: a sweep that
        // matched nothing at all fails here.
        let files = swept_corpus("allowlist");
        let banned = [
            marker(&["block", "list"]),
            marker(&["black", "list"]),
            marker(&["white", "list"]),
            marker(&["lic", "ense"]),
            marker(&["wa", "ge"]),
            marker(&["pay", "check"]),
            marker(&["sal", "ary"]),
            marker(&["inc", "ome"]),
            marker(&["pro", "fit"]),
            marker(&["ea", "rn"]),
        ];
        for word in &banned {
            let probe = format!("// the {word} goes here").to_ascii_lowercase();
            assert!(
                probe.contains(word.as_str()) && !word.is_empty(),
                "the banned word `{word}` did not match a line built from it"
            );
        }
        for (name, text) in &files {
            let lower = text.to_ascii_lowercase();
            for word in &banned {
                assert!(
                    !lower.contains(word.as_str()),
                    "{name} contains banned vocabulary"
                );
            }
        }
    }

    /// Files whose presence means this is the INTERNAL tree.
    ///
    /// A deliberate duplicate of the lists in `citation_audit` and
    /// `license_audit`, for the same reason those two duplicate each other: the
    /// audits must be able to disagree about where they look, and a narrowing
    /// made for one must not silently narrow the others.
    ///
    /// The private-doc-tree entry is ASSEMBLED, never written out, for the same
    /// reason every other marker in this file is: this file is published and
    /// swept, so the literal would be its own first finding.
    fn internal_tree_markers() -> Vec<String> {
        let mut m: Vec<String> = [
            "DOC_INDEX.md",
            "Council",
            "wiki",
            "tools/curate-public-export.ps1",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        m.push(marker(&["docs/", "superpowers"]));
        m
    }

    /// The repository root: two levels above `tools/goat-attestor`.
    fn repo_root() -> PathBuf {
        crate_root().join("..").join("..")
    }

    /// Every published file this lane adds must be in the curator's baseline, or
    /// the licence and citation sweeps silently skip it.
    ///
    /// Mutations this detects: a lane file created and never published; a
    /// baseline row deleted or re-sorted out of existence; `lane_audit.rs`
    /// dropped from the baseline, which publishes `mod.rs`'s declaration of a
    /// module whose file is absent and fails the public build with `E0583`.
    ///
    /// WHICH TREE IS THIS, and therefore what "published" can be checked
    /// against. In the internal tree the exported surface is a subset named by
    /// the curator's record. In a published checkout there is no subset:
    /// everything present was exported, and `tools/export-baseline.txt` is
    /// itself unpublished, so it is legitimately absent there. Answering that
    /// case by panicking is not hypothetical — it is the failure `citation_audit`
    /// already carries a note about, and it fails permanently on the public
    /// repository. Answering it by skipping would be a check that cannot fail in
    /// the tree it is actually about. It is answered by checking the same claim
    /// against the disk, which is strictly the stronger evidence: a file that is
    /// THERE was published, whatever any record says.
    ///
    /// THE DISCRIMINATOR IS NOT "the baseline is missing", which would let a
    /// deleted baseline in the internal tree quietly downgrade to the other
    /// branch. A published checkout is identified positively: baseline absent
    /// AND every internal marker absent.
    #[test]
    fn every_new_proxy_lane_file_is_in_the_export_baseline() {
        const REQUIRED: &[&str] = &[
            "tools/goat-attestor/src/proxy/mod.rs",
            "tools/goat-attestor/src/proxy/receipt.rs",
            "tools/goat-attestor/src/proxy/verify.rs",
            "tools/goat-attestor/src/proxy/aggregate.rs",
            "tools/goat-attestor/src/proxy/proxy_merkle.rs",
            "tools/goat-attestor/src/proxy/meter.rs",
            "tools/goat-attestor/src/proxy/challenger.rs",
            "tools/goat-attestor/src/proxy/fraud.rs",
            "tools/goat-attestor/src/proxy/store.rs",
            "tools/goat-attestor/src/proxy/routes.rs",
            // Published because `mod.rs` declares it and `mod.rs` is published.
            // `lane_files()` drops this file so the sweeps do not read
            // themselves, so the coverage loop below can never reach it and this
            // row is the only thing asserting it.
            "tools/goat-attestor/src/proxy/lane_audit.rs",
            "tools/goat-attestor/migrations/0004_proxy_receipts.sql",
            "tools/goat-attestor/fixtures/proxy_receipt_v1.json",
            "contracts/test/ProxyRevenueMerkleParity.t.sol",
        ];
        // A path shaped exactly like the rows above, which must never resolve.
        // A membership test whose haystack is everything passes for every
        // needle, so both branches below probe this first.
        const ABSENT: &str = "tools/goat-attestor/src/proxy/not_a_real_module.rs";

        // Tree-independent, so it runs on both branches: every lane file that
        // EXISTS is covered, and a module added later without a row fails here
        // rather than shipping unswept.
        for (name, _) in lane_files() {
            let rel = format!("tools/goat-attestor/{name}");
            assert!(
                REQUIRED.contains(&rel.as_str()),
                "{rel} exists in the lane but is not in this test's published set"
            );
        }

        let baseline_path = crate_root().join("..").join("export-baseline.txt");
        let Ok(baseline) = std::fs::read_to_string(&baseline_path) else {
            let repo = repo_root();
            let present: Vec<String> = internal_tree_markers()
                .into_iter()
                .filter(|m| {
                    repo.join(m.replace('/', std::path::MAIN_SEPARATOR_STR))
                        .exists()
                })
                .collect();
            assert!(
                present.is_empty(),
                "tools/export-baseline.txt is missing, but this is an INTERNAL tree -- \
                 {present:?} present. The published set is therefore UNKNOWN: it is neither \
                 the baseline (gone) nor the whole tree (most of which is private). \
                 Restore the baseline."
            );
            let on_disk = |p: &str| {
                repo.join(p.replace('/', std::path::MAIN_SEPARATOR_STR))
                    .is_file()
            };
            assert!(
                !on_disk(ABSENT),
                "the disk probe matched a path that does not exist; the test is vacuous"
            );
            for expected in REQUIRED {
                assert!(
                    on_disk(expected),
                    "{expected} is missing from the published tree"
                );
            }
            return;
        };

        assert!(
            baseline.lines().count() > 1000,
            "vacuity guard: baseline looks truncated"
        );
        let listed = |p: &str| baseline.lines().any(|l| l.trim() == p);
        assert!(
            !listed(ABSENT),
            "the baseline matched a path that does not exist; the test is vacuous"
        );
        for expected in REQUIRED {
            assert!(
                listed(expected),
                "{expected} is missing from the export baseline"
            );
        }
    }
}

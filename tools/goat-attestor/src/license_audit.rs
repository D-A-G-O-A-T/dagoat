//! A mechanical audit of the licence story this repository publishes: every
//! exported Cargo manifest, the two licence files those manifests point at, and
//! the README that is supposed to route a reader to them.
//!
//! # Why this exists
//!
//! A licence is not one fact, it is three that have to agree, and nothing here
//! ever checked that they did:
//!
//! 1. `goatcoin-rs/Cargo.toml` declared `Apache-2.0` alone in its
//!    `[workspace.package]` table. Five member crates inherited that through
//!    `license.workspace = true`, so ONE line published a single-licence claim
//!    for five crates while two licence files -- MIT and Apache-2.0 -- sat in
//!    the repository root beside them. Nothing was wrong with any individual
//!    file; the defect existed only in the relationship between them, which is
//!    exactly the class a per-file review does not catch.
//! 2. `README.md` named neither licence file for the entire life of the
//!    repository, up to 2026-07-29, while both files sat in the root. A licence
//!    a reader cannot find is a licence that does not do its job.
//! 3. A manifest can decline to say anything at all. An absent `license` key is
//!    not "unlicensed by default" and it is not "inherits the obvious" -- it is
//!    a published manifest that states nothing, which is the worst of the three
//!    outcomes because it reads as an oversight rather than a claim.
//!
//! # What a green run here does NOT prove -- read this before trusting it
//!
//! **It proves the published manifests AGREE with the shipped licence files.
//! It does not prove anyone had the right to license the code that way.**
//! Provenance -- who wrote what, under what employment or contract, whether
//! every dependency's terms permit redistribution under these terms, whether
//! any contributor ever assigned rights -- is a legal question about the world,
//! and no test that reads this tree can answer it. This module checks internal
//! consistency and nothing else.
//!
//! **Its scope is the export baseline, not the working tree.** A crate that
//! exists here but is not published is not examined, deliberately: an
//! unpublished manifest licenses nothing to anybody, so its `license` key is a
//! note-to-self rather than a claim. The consequence is that adding a crate to
//! `tools/export-baseline.txt` widens this audit, and that is the intended
//! direction -- publication is what creates the obligation.
//!
//! **It does not read the licence texts as law.** It checks that both files
//! exist, are published, and name the same copyright holder. It does not verify
//! that `LICENSE-APACHE` is an unmodified Apache-2.0, nor that the MIT text has
//! not been quietly edited mid-body. Those are diff questions against an
//! upstream original, which this repository does not carry.
//!
//! **It says nothing about vendored code.** `contracts/lib/` is excluded, as
//! everywhere else in this crate. Upstream's licence is upstream's business and
//! a claim made here about OpenZeppelin's terms would be a claim this project
//! has no standing to make.

use std::path::{Path, PathBuf};

/// The one SPDX expression every published manifest in this repository must
/// carry, pinned as a literal.
///
/// The literal is the test. It is deliberately NOT derived from any manifest,
/// any licence file, or the README: a check that reads the expected value out
/// of the thing under test is `assert_eq!(X, X)`, which is the single most
/// common way an assertion in this repository has been found unable to fail.
/// Changing this constant is a decision about what the project publishes and
/// should be as visible in a diff as changing a manifest.
const REQUIRED_SPDX: &str = "MIT OR Apache-2.0";

/// The copyright holder both licence files must name, pinned as a literal for
/// the same reason as [`REQUIRED_SPDX`].
///
/// The trailing `/ GoatCoin contributors` is load-bearing and was added back on
/// founder decision 2026-07-29 after two independent reviews flagged its
/// removal. Authors hold copyright in their own contributions automatically, so
/// dropping the phrase took nobody's rights away -- what it did was leave the
/// shipped notice naming only the three project entities while outside
/// contributions accumulated unacknowledged. Re-adding it costs nothing and
/// needs no CLA.
const EXPECTED_COPYRIGHT_HOLDER: &str =
    "D.A. G.O.A.T. / DaGoat Engine / DaGoat Network / GoatCoin contributors";

/// Third-party code vendored into the export, excluded from this audit.
///
/// A deliberate duplicate of the constant in `citation_audit`; see
/// [`export_baseline_paths`] for why the duplication is not an oversight.
///
/// Today this filter removes nothing -- `contracts/lib/` is 781 files of
/// Solidity and carries no Cargo manifest -- and it stays anyway. The moment a
/// Rust dependency is vendored, the alternative is an audit that asserts THIS
/// project's licence expression over UPSTREAM's manifest, which is a claim this
/// project has no standing to make. Keep in lockstep with the curator's
/// `$VendoredPrefixes`.
const VENDORED_PREFIXES: &[&str] = &["contracts/lib/"];

/// Repository root, derived from this crate's manifest directory
/// (`<repo>/tools/goat-attestor`).
///
/// A deliberate duplicate of `citation_audit`'s helper of the same name rather
/// than a `pub(crate)` sharing of it. Two reasons, both about scope rather than
/// about lines of code: this module must be readable on its own, without a
/// reader having to hold a second audit's helpers in their head to know what it
/// is looking at; and a shared helper is a shared SCOPE, so a future narrowing
/// made for the citation sweep's benefit would silently narrow the licence
/// audit too, with no diff anywhere near this file to show for it. The two
/// audits check unrelated properties and must be able to disagree about where
/// they look.
fn repo_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or(crate_dir)
}

/// The curator's per-FILE publication record, `tools/export-baseline.txt`,
/// parsed into repo-relative paths.
///
/// A deliberate duplicate of `citation_audit`'s reader, for the reasons given
/// on [`repo_root`]. The parse is intentionally identical -- one path per line,
/// `#` comments and blank lines ignored, backslashes normalised -- because both
/// audits are reading the SAME curator artefact and a divergence in how it is
/// read would be a bug in one of them.
///
/// Returns `None` when the file is absent. The caller must turn that into a
/// loud failure rather than a quiet narrowing, because "the baseline vanished"
/// and "every published manifest is correctly licensed" must not produce the
/// same green run.
fn export_baseline_paths(repo: &Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(repo.join("tools").join("export-baseline.txt")).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let rel = t.replace('\\', "/");
        // A `..` component escapes the repository, and `Path` equality does not
        // normalise it away: `repo.join("../Cargo.toml")` has parent
        // `<repo>/..`, which compares UNEQUAL to `repo`, so
        // `resolve_workspace_root`'s `dir == repo` stop condition does not fire
        // on the first iteration and the first manifest it reads is one
        // directory ABOVE this project. One level is enough to satisfy the
        // inheritance arm from an out-of-repo file nobody here controls.
        //
        // The curator only ever emits repo-relative paths from a tree walk, so
        // this cannot happen today -- it is closed here because the cost is one
        // branch and the failure mode is an audit that passes on foreign
        // authority. Loud, not skipped: dropping the line quietly would narrow
        // the sweep, which is the failure shape this module exists to avoid.
        assert!(
            !rel.split('/').any(|c| c == ".."),
            "tools/export-baseline.txt line {t:?} contains a `..` component. Baseline paths are \
             repo-relative by construction; a `..` would let the workspace-root walk read a \
             manifest outside this repository and satisfy the inheritance arm from it."
        );
        out.push(rel);
    }
    Some(out)
}

/// Drop a trailing `#` comment, respecting quoted strings.
///
/// Not cosmetic and not paranoia: a naive "truncate at the first `#`" would
/// also silently accept a manifest whose licence line is COMMENTED OUT, and it
/// would mangle any value containing a hash. Both directions matter -- the
/// first is a false pass, which is the failure shape this repository has
/// shipped most often.
fn strip_toml_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'#' => return &line[..i],
            None => {}
        }
    }
    line
}

/// One `license`-family key found in a manifest, with the table it sat under.
#[derive(Debug, PartialEq, Eq)]
struct LicenceKey {
    /// The `[table]` header in force, brackets stripped (`package`,
    /// `workspace.package`, ...). Empty for keys before any header.
    table: String,
    /// Normalised key: `license` or `license.workspace`. The inline-table
    /// spelling `license = { workspace = true }` is normalised to the latter.
    key: String,
    /// Unquoted value: the SPDX string, or `true`/`false` for the workspace
    /// form.
    value: String,
}

/// Every `license` / `license.workspace` key in a Cargo manifest.
///
/// Hand-rolled rather than a TOML dependency, matching `citation_audit`'s
/// no-regex stance: this crate's manifest is itself one of the files under
/// audit, and adding a dependency to check the licence of the manifest that
/// declares the dependency is a loop nobody wants to reason about.
///
/// It parses line-wise BUT it does not string-match one spelling, because
/// "the scanner's alphabet was too small" is a documented false-zero in this
/// repository -- a scan matched one way of writing the thing, read zero, and
/// the defect shipped. All four spellings Cargo accepts are handled:
///
/// * `license = "MIT OR Apache-2.0"`   (double quotes)
/// * `license = 'MIT OR Apache-2.0'`   (single quotes)
/// * `license.workspace = true`        (dotted key)
/// * `license = { workspace = true }`  (inline table)
///
/// with arbitrary whitespace around `=`, optional quoting of the key itself,
/// and `#` comments removed first so a commented-out declaration is not read as
/// a declaration.
fn licence_keys(text: &str) -> Vec<LicenceKey> {
    let mut out = Vec::new();
    let mut table = String::new();
    for raw in text.lines() {
        let line = strip_toml_comment(raw);
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('[') && t.ends_with(']') {
            table = t.trim_matches(|c| c == '[' || c == ']').trim().to_string();
            continue;
        }
        let Some(eq) = t.find('=') else {
            continue;
        };
        let key = t[..eq].trim().trim_matches(|c| c == '"' || c == '\'');
        if key != "license" && key != "license.workspace" {
            continue;
        }
        let value = t[eq + 1..].trim();
        let first = value.as_bytes().first().copied();
        match first {
            // Quoted string: read to the matching close quote.
            Some(q @ (b'"' | b'\'')) => {
                let rest = &value[1..];
                let end = rest.find(q as char).unwrap_or(rest.len());
                out.push(LicenceKey {
                    table: table.clone(),
                    key: key.to_string(),
                    value: rest[..end].to_string(),
                });
            }
            // Inline table: the only member this audit understands is
            // `workspace = <bool>`, which is Cargo's other way of spelling
            // `license.workspace`.
            Some(b'{') => {
                let inner = value.trim_matches(|c| c == '{' || c == '}');
                let mut bool_value = None;
                for part in inner.split(',') {
                    let Some(peq) = part.find('=') else {
                        continue;
                    };
                    if part[..peq].trim() == "workspace" {
                        bool_value = Some(part[peq + 1..].trim().to_string());
                    }
                }
                if let Some(v) = bool_value {
                    out.push(LicenceKey {
                        table: table.clone(),
                        key: "license.workspace".to_string(),
                        value: v,
                    });
                }
            }
            // Bare token: `true`, `false`.
            Some(_) => {
                let end = value
                    .find(|c: char| c.is_whitespace() || c == ',')
                    .unwrap_or(value.len());
                out.push(LicenceKey {
                    table: table.clone(),
                    key: key.to_string(),
                    value: value[..end].to_string(),
                });
            }
            None => {}
        }
    }
    out
}

/// What one manifest says about its licence, with the two arms of the rule kept
/// as SEPARATE fields.
///
/// They are separate on purpose. The rule under test is a disjunction, and the
/// repository's standing finding is that mutating one disjunct of an `||`
/// proves nothing about the other -- a three-way guard here once stayed true
/// under a single-arm mutation. Collapsing these into a single
/// "does it look licensed" boolean would rebuild exactly that.
#[derive(Debug, PartialEq, Eq)]
struct LicenceDecl {
    /// Value of a `license = "..."` key in `[package]` or
    /// `[workspace.package]`. `None` when no such key exists.
    direct: Option<String>,
    /// True when `[package]` defers to the workspace
    /// (`license.workspace = true`, in either spelling).
    inherits: bool,
}

/// Read one manifest's own licence declaration.
///
/// `[workspace.package]` counts for `direct` ONLY in a virtual manifest -- one
/// with no `[package]` table at all, like `goatcoin-rs/Cargo.toml` -- because
/// that is the only shape in which it states the project's own licence.
///
/// **In a manifest that HAS a `[package]` table it counts for nothing**, and
/// that distinction is the whole point rather than pedantry. Cargo's field
/// inheritance is opt-in per key: `[workspace.package]` is an OFFER, and a
/// member takes it only by writing `license.workspace = true`. A root package
/// that declares no `license` of its own does not receive one from the
/// `[workspace.package]` table sitting in the same file -- it publishes with no
/// licence field at all, which cargo reports as nothing louder than a
/// publish-time warning.
///
/// Accepting the offer as if it were the declaration made exactly that state
/// pass: delete `license` from the root `Cargo.toml`'s `[package]` and add a
/// `[workspace.package]` table carrying it, and `goat-core` publishes
/// unlicensed while this audit stays green. Both the root manifest and
/// `desktop/src-tauri/Cargo.toml` are one table away from that shape -- each
/// already carries an empty `[workspace]`.
fn licence_declaration(text: &str) -> LicenceDecl {
    let keys = licence_keys(text);
    // Whether this manifest has a package of its own to license.
    let has_package_table = text
        .lines()
        .any(|l| strip_toml_comment(l).trim() == "[package]");
    // A manifest may carry BOTH tables -- the root `Cargo.toml` is a package
    // that is also a workspace root, and is one `[workspace.package]` table away
    // from that shape. Taking whichever `license` key came FIRST IN DOCUMENT
    // ORDER would make the verdict depend on line order: a correct
    // `[workspace.package] license` sitting above a wrong `[package] license`
    // would report the correct one and pass while the package published
    // something else.
    //
    // So when several are present, the DISAGREEING one is reported. `find` over
    // "not the required expression" first, falling back to the first key when
    // they all agree: with one key this is identical to the previous behaviour,
    // and with several it can only ever move the verdict toward red.
    let direct_keys: Vec<&LicenceKey> = keys
        .iter()
        .filter(|k| {
            k.key == "license"
                && (k.table == "package"
                    || (k.table == "workspace.package" && !has_package_table))
        })
        .collect();
    let direct = direct_keys
        .iter()
        .find(|k| k.value != REQUIRED_SPDX)
        .or(direct_keys.first())
        .map(|k| k.value.clone());
    let inherits = keys
        .iter()
        .any(|k| k.key == "license.workspace" && k.table == "package" && k.value == "true");
    LicenceDecl { direct, inherits }
}

/// The `license` value in a manifest's `[workspace.package]` table -- what an
/// inheriting member crate actually receives.
///
/// Narrower than [`licence_declaration`] on purpose: a `[package] license` in a
/// workspace root licenses that root's own package and is NOT what
/// `license.workspace = true` reads.
fn workspace_package_licence(text: &str) -> Option<String> {
    licence_keys(text)
        .into_iter()
        .find(|k| k.key == "license" && k.table == "workspace.package")
        .map(|k| k.value)
}

/// The workspace root an inheriting manifest resolves against: the nearest
/// `Cargo.toml` at or above it that carries a `[workspace]` table.
///
/// The walk starts at the manifest's OWN directory, matching Cargo: a crate
/// that declares its own `[workspace]` is a workspace root and inherits from
/// nobody. The walk stops at `repo`, so a stray `Cargo.toml` outside the
/// repository can never be read as this project's authority.
///
/// `None` means no root was found. The caller must treat that as a failure and
/// not as a skip -- a manifest that says `license.workspace = true` with
/// nothing above it to inherit from is a manifest that publishes no licence at
/// all, and "could not check" must never render as "checked and fine".
fn resolve_workspace_root(manifest: &Path, repo: &Path) -> Option<PathBuf> {
    let mut dir = manifest.parent()?;
    loop {
        let candidate = dir.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&candidate) {
            // The `[workspace]` table header is what makes a manifest a root.
            // Comments are stripped first so a commented-out header does not
            // create a workspace that Cargo does not see.
            if text
                .lines()
                .any(|l| strip_toml_comment(l).trim() == "[workspace]")
            {
                return Some(candidate);
            }
        }
        if dir == repo {
            return None;
        }
        dir = dir.parent()?;
    }
}

/// The copyright holder named by a licence file: everything after the year on
/// the first line beginning `Copyright`.
///
/// Case-SENSITIVE on the leading `Copyright`, which is load-bearing for
/// Apache-2.0: its body prose carries two lines beginning `copyright notice ...`
/// and `copyright license ...` in lower case, and a case-insensitive match
/// would extract a fragment of the licence's own terms instead of the holder.
///
/// The year is found as the first whitespace-delimited token starting with four
/// digits, so both `Copyright (c) 2026 <holder>` (MIT) and
/// `Copyright 2026 <holder>` (Apache appendix) resolve to the same string, and
/// a year RANGE (`2024-2026`) keeps working. Internal whitespace in the holder
/// is preserved rather than collapsed: two files that differ by a double space
/// do not agree, and this audit should say so.
fn copyright_holder(text: &str) -> Option<String> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("Copyright"))?;
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let token = &line[start..i];
        if token.len() >= 4 && token.as_bytes()[..4].iter().all(u8::is_ascii_digit) {
            return Some(line[i..].trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Manifests that MUST be inside this audit's scope, named individually so
    /// a scope regression fails loudly instead of silently shrinking the sweep.
    ///
    /// One per publication shape:
    ///
    /// * `Cargo.toml` -- the root spine, a standalone package that is ALSO a
    ///   workspace root.
    /// * `goatcoin-rs/Cargo.toml` -- a virtual manifest with no `[package]`
    ///   table, and the file whose single `license` line published the wrong
    ///   licence for five crates.
    /// * `desktop/src-tauri/Cargo.toml` -- a standalone crate outside every
    ///   workspace, the shape most likely to be forgotten.
    /// * `tools/goat-attestor/Cargo.toml` -- this crate; if the audit cannot
    ///   see its own manifest, its scope is wrong.
    const REQUIRED_MANIFEST_COVERAGE: &[&str] = &[
        "Cargo.toml",
        "goatcoin-rs/Cargo.toml",
        "desktop/src-tauri/Cargo.toml",
        "tools/goat-attestor/Cargo.toml",
    ];

    /// The five manifests that reach the dual licence only by INHERITING it.
    ///
    /// Named individually, not matched by prefix. A prefix test is satisfied by
    /// one survivor, so it cannot distinguish "arm 2 is covered" from "arm 2 is
    /// covered by a single crate while four others left the export". These are
    /// exactly `goatcoin-rs/Cargo.toml`'s `members = [...]`.
    const REQUIRED_INHERITING_MANIFESTS: &[&str] = &[
        "goatcoin-rs/crates/goat-backends/Cargo.toml",
        "goatcoin-rs/crates/goat-ledger/Cargo.toml",
        "goatcoin-rs/crates/goat-net/Cargo.toml",
        "goatcoin-rs/crates/goat-neutrality/Cargo.toml",
        "goatcoin-rs/crates/goat-protocol/Cargo.toml",
    ];

    /// Every published Cargo manifest declares the dual licence, either
    /// directly or by inheriting a workspace root that declares it.
    ///
    /// # The rule, and why it is two arms
    ///
    /// A manifest passes if EITHER:
    ///
    /// * **Arm 1 (declares).** It carries `license = "MIT OR Apache-2.0"` in
    ///   `[package]` or `[workspace.package]`. Four manifests pass only this
    ///   way -- the root spine, the desktop crate, this crate, and the
    ///   `goatcoin-rs` virtual root.
    /// * **Arm 2 (inherits).** It carries `license.workspace = true` AND the
    ///   workspace root it resolves against declares
    ///   `license = "MIT OR Apache-2.0"` in `[workspace.package]`. Five
    ///   manifests pass only this way -- the `goatcoin-rs/crates/` members.
    ///
    /// Arm 2 is not a formality. It is the arm the real defect lived in: the
    /// five members were individually correct (`license.workspace = true` is
    /// exactly right) and collectively wrong, because the root they inherited
    /// from said `Apache-2.0` while two licence files shipped beside them.
    ///
    /// # The two arms are separately mutable
    ///
    /// The repository's standing finding is that mutating one disjunct of an
    /// `||` proves nothing about the other. So the arms are computed as two
    /// independent expressions over two independent fields
    /// ([`LicenceDecl::direct`] and [`LicenceDecl::inherits`] plus
    /// [`workspace_package_licence`] of the resolved root), and the population
    /// is split: no manifest in this repository passes through both. That split
    /// is what makes the following two mutations DISTINCT, each flipping
    /// exactly one arm from true to false while the other arm's population
    /// stays green -- so neither arm can be deleted, stubbed to `true`, or
    /// broken without a red run.
    ///
    /// * **Arm 1 only:** in `tools/goat-attestor/Cargo.toml`, change
    ///   `license = "MIT OR Apache-2.0"` to `license = "Apache-2.0"`. That
    ///   manifest has no `license.workspace` key, so arm 2 was already false
    ///   and stays false; only arm 1 changes state. The five inheriting
    ///   manifests are untouched and still pass through arm 2.
    /// * **Arm 2 only:** in `goatcoin-rs/crates/goat-protocol/Cargo.toml`,
    ///   delete the `license.workspace = true` line. That manifest has no
    ///   direct `license` key, so arm 1 was already false and stays false; only
    ///   arm 2 changes state. Every arm-1 manifest, including both workspace
    ///   roots, is untouched.
    ///
    /// **Other mutations this detects:** setting `[workspace.package] license`
    /// in `goatcoin-rs/Cargo.toml` back to `"Apache-2.0"` (five members go red
    /// through arm 2's resolver -- the original defect, verbatim); adding a
    /// `[workspace]` table to a member crate so it resolves to itself and
    /// inherits nothing; commenting a `license` line out; removing any of the
    /// four `REQUIRED_MANIFEST_COVERAGE` entries or every `goatcoin-rs/crates/`
    /// member from `tools/export-baseline.txt` (the scope guards); deleting
    /// `tools/export-baseline.txt` (explicit panic); publishing a new crate
    /// whose manifest states no licence at all.
    #[test]
    fn every_published_cargo_manifest_declares_the_dual_licence() {
        // -- parser controls, before any manifest is read -------------------
        //
        // A parser that reported "declares the dual licence" for everything
        // would make the loop below pass over nine manifests and prove nothing.
        // The negative controls are the important half: they are what a scanner
        // with too small an alphabet -- the documented false-zero in this
        // repository -- fails.
        let spdx = REQUIRED_SPDX;
        for (probe, want) in [
            (
                format!("[package]\nname = \"x\"\nlicense = \"{spdx}\"\n"),
                LicenceDecl {
                    direct: Some(spdx.to_string()),
                    inherits: false,
                },
            ),
            (
                // Single quotes, and whitespace nobody would write by hand.
                format!("[workspace.package]\nlicense   =    '{spdx}'\n"),
                LicenceDecl {
                    direct: Some(spdx.to_string()),
                    inherits: false,
                },
            ),
            (
                "[package]\nlicense.workspace = true\n".to_string(),
                LicenceDecl {
                    direct: None,
                    inherits: true,
                },
            ),
            (
                // Cargo's other spelling of the same thing.
                "[package]\nlicense = { workspace = true }\n".to_string(),
                LicenceDecl {
                    direct: None,
                    inherits: true,
                },
            ),
            (
                // A commented-out declaration declares nothing.
                format!("[package]\n# license = \"{spdx}\"\n"),
                LicenceDecl {
                    direct: None,
                    inherits: false,
                },
            ),
            (
                // The single-licence claim this audit exists to catch.
                "[package]\nlicense = \"Apache-2.0\"\n".to_string(),
                LicenceDecl {
                    direct: Some("Apache-2.0".to_string()),
                    inherits: false,
                },
            ),
            (
                // Wrong table: `[package.metadata] license` licenses nothing.
                format!("[package.metadata]\nlicense = \"{spdx}\"\n"),
                LicenceDecl {
                    direct: None,
                    inherits: false,
                },
            ),
            (
                // A VIRTUAL manifest: no `[package]`, so `[workspace.package]`
                // IS the project's declaration. This is `goatcoin-rs/Cargo.toml`.
                format!("[workspace]\n[workspace.package]\nlicense = \"{spdx}\"\n"),
                LicenceDecl {
                    direct: Some(spdx.to_string()),
                    inherits: false,
                },
            ),
            (
                // THE SAME TABLE, in a manifest that has a package of its own:
                // declares NOTHING. `[workspace.package]` is an offer members
                // opt into with `license.workspace = true`; this package did
                // not, so it publishes with no licence field. Accepting the
                // offer as the declaration is a false pass, and both the root
                // manifest and desktop/src-tauri are one table away from it.
                format!("[package]\nname = \"x\"\n[workspace]\n[workspace.package]\nlicense = \"{spdx}\"\n"),
                LicenceDecl {
                    direct: None,
                    inherits: false,
                },
            ),
            (
                // Document order must not decide the verdict. A correct
                // workspace offer above a wrong package declaration reports the
                // WRONG one, because that is the one that ships.
                format!("[workspace.package]\nlicense = \"{spdx}\"\n[package]\nlicense = \"Apache-2.0\"\n"),
                LicenceDecl {
                    direct: Some("Apache-2.0".to_string()),
                    inherits: false,
                },
            ),
            (
                // A near-miss key that must not be mistaken for the real one.
                "[package]\nlicense-file = \"LICENSE-MIT\"\n".to_string(),
                LicenceDecl {
                    direct: None,
                    inherits: false,
                },
            ),
            (
                // Deferring to a workspace that is switched off is not
                // inheritance.
                "[package]\nlicense.workspace = false\n".to_string(),
                LicenceDecl {
                    direct: None,
                    inherits: false,
                },
            ),
        ] {
            assert_eq!(
                licence_declaration(&probe),
                want,
                "the manifest parser misread this probe, so a green sweep below would prove \
                 nothing:\n{probe}"
            );
        }

        // -- scope, asserted BEFORE the loop --------------------------------
        let repo = repo_root();
        let baseline = export_baseline_paths(&repo).unwrap_or_else(|| {
            panic!(
                "tools/export-baseline.txt could not be read, so the set of PUBLISHED manifests \
                 is unknown and this audit would sweep nothing while reporting success. An \
                 absent baseline is a failure, not an empty tree. Expected at: {}",
                repo.join("tools").join("export-baseline.txt").display()
            )
        });

        let manifests: Vec<String> = baseline
            .iter()
            .filter(|rel| rel.rsplit('/').next() == Some("Cargo.toml"))
            .filter(|rel| !VENDORED_PREFIXES.iter().any(|p| rel.starts_with(p)))
            .cloned()
            .collect();

        assert!(
            !manifests.is_empty(),
            "the export baseline parsed to {} path(s) but not one of them is a Cargo.toml. Either \
             the baseline format changed or the filename filter is broken; either way every \
             assertion below would pass over an empty set",
            baseline.len()
        );

        let missing: Vec<&str> = REQUIRED_MANIFEST_COVERAGE
            .iter()
            .copied()
            .filter(|want| !manifests.iter().any(|rel| rel == want))
            .collect();
        assert!(
            missing.is_empty(),
            "this audit does not reach {} required manifest(s): {:?}\n\nEach names a distinct \
             publication shape (standalone package, virtual workspace root, out-of-workspace \
             crate, this crate). If one genuinely stopped being published, that is a decision to \
             make in tools/export-baseline.txt and to reflect here -- do not delete the entry to \
             make this pass.",
            missing.len(),
            missing
        );

        // `workspace_package_licence` is arm 2's resolver, and over the current
        // population it is REDUNDANT with arm 1: the one root the five members
        // resolve to is `goatcoin-rs/Cargo.toml`, which is itself in scope, so
        // a wrong value there is caught twice. Redundancy is fine; an
        // unexercised resolver is not -- stubbing it to return the required
        // expression would leave every test green. These two probes are the only
        // thing that observes it directly, and they pin the distinction it
        // exists to make: it reads `[workspace.package]`, never `[package]`.
        assert_eq!(
            workspace_package_licence(&format!("[workspace.package]\nlicense = \"{spdx}\"\n")),
            Some(spdx.to_string()),
            "the workspace-root resolver cannot read a [workspace.package] licence, so arm 2 \
             would fail closed for the wrong reason"
        );
        assert_eq!(
            workspace_package_licence(&format!("[package]\nlicense = \"{spdx}\"\n")),
            None,
            "the workspace-root resolver accepted a [package] licence. A root's own package \
             licence is NOT what `license.workspace = true` reads, so a root could license \
             itself correctly while handing its members nothing, and arm 2 would call that fine"
        );

        // The inheriting population is the ONLY thing that exercises arm 2. If
        // it ever vanished from scope, arm 2 would become untested while
        // staying green -- the exact shape of "a check that cannot fail".
        let inheriting_members: Vec<&String> = manifests
            .iter()
            .filter(|rel| rel.starts_with("goatcoin-rs/crates/"))
            .collect();
        assert!(
            !inheriting_members.is_empty(),
            "no goatcoin-rs/crates/ manifest is in scope. That is the only set of manifests that \
             inherits its licence from a workspace root, so arm 2 of this rule would be asserted \
             over nothing and would stay green no matter what the root declared -- which is \
             precisely the defect this audit was written for. Manifests in scope: {manifests:?}"
        );

        // "at least one" is not a floor, it is a floor of ONE. The four arm-1
        // manifests are pinned individually above; pinning arm 2 only by prefix
        // let the audited set shrink from nine manifests to five with every
        // assertion still green. That is not hypothetical tidiness: the members
        // are named in `goatcoin-rs/Cargo.toml`'s `members = [...]` and their
        // sources stay in the baseline, so dropping four manifests would export
        // a workspace referencing crates whose licence claim had silently
        // vanished -- and the export would not build.
        //
        // Each is named, for the same reason the arm-1 four are.
        let members_missing: Vec<&&str> = REQUIRED_INHERITING_MANIFESTS
            .iter()
            .filter(|want| !manifests.iter().any(|rel| rel == *want))
            .collect();
        assert!(
            members_missing.is_empty(),
            "arm 2's population has shrunk: {:?} is/are no longer in scope. Arm 2 stays green on \
             a single surviving member, so a prefix check alone cannot see this. If a crate \
             genuinely stopped being published, remove it from `members` in \
             goatcoin-rs/Cargo.toml too -- an exported workspace that names a crate it did not \
             ship does not build.",
            members_missing
        );

        // -- the audit ------------------------------------------------------
        let mut failures = Vec::new();
        let mut passed_by_arm_one = 0usize;
        let mut passed_by_arm_two = 0usize;

        for rel in &manifests {
            let abs = repo.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
            // A published path that cannot be read is a failure, never a skip:
            // "could not check" must not render as "checked and fine".
            let Ok(text) = std::fs::read_to_string(&abs) else {
                failures.push(format!(
                    "{rel}  is listed in the export baseline but could not be read at {}",
                    abs.display()
                ));
                continue;
            };
            let decl = licence_declaration(&text);

            // ARM 1 -- the manifest states the licence itself.
            let arm_one = decl.direct.as_deref() == Some(REQUIRED_SPDX);

            // ARM 2 -- the manifest defers, and what it defers to is right.
            // Computed independently of arm 1, from a different field and a
            // different file, so neither arm can mask a break in the other.
            let mut arm_two = false;
            let mut arm_two_note = String::new();
            if decl.inherits {
                match resolve_workspace_root(&abs, &repo) {
                    None => {
                        arm_two_note =
                            " it declares `license.workspace = true` but no Cargo.toml at or above \
                             it carries a [workspace] table, so it inherits from nothing"
                                .to_string();
                    }
                    Some(root) => {
                        let root_shown = root
                            .strip_prefix(&repo)
                            .unwrap_or(&root)
                            .to_string_lossy()
                            .replace('\\', "/");
                        match std::fs::read_to_string(&root)
                            .ok()
                            .and_then(|t| workspace_package_licence(&t))
                        {
                            Some(v) if v == REQUIRED_SPDX => arm_two = true,
                            Some(v) => {
                                arm_two_note = format!(
                                    " it inherits from {root_shown}, whose [workspace.package] \
                                     declares {v:?}"
                                );
                            }
                            None => {
                                arm_two_note = format!(
                                    " it inherits from {root_shown}, which declares no `license` \
                                     in [workspace.package] at all"
                                );
                            }
                        }
                    }
                }
            }

            if arm_one {
                passed_by_arm_one += 1;
            } else if arm_two {
                passed_by_arm_two += 1;
            } else {
                let stated = match &decl.direct {
                    Some(v) => format!("declares {v:?}"),
                    None if decl.inherits => "defers to its workspace".to_string(),
                    None => "declares no `license` key at all".to_string(),
                };
                failures.push(format!("{rel}  {stated};{arm_two_note}"));
            }
        }

        assert!(
            failures.is_empty(),
            "{} published manifest(s) do not publish {REQUIRED_SPDX}:\n  {}\n\n\
             Every manifest in the export baseline is a public licence claim. Repair by declaring \
             `license = \"{REQUIRED_SPDX}\"` in [package], or by declaring \
             `license.workspace = true` and fixing the workspace root's [workspace.package] to \
             say the same. An absent key is not a default -- it is a published manifest that \
             states nothing.",
            failures.len(),
            failures.join("\n  ")
        );

        // Both arms actually carried manifests this run. Without this, a future
        // refactor that made every manifest declare directly would leave arm 2
        // asserted over nothing while the test stayed green.
        assert!(
            passed_by_arm_one > 0 && passed_by_arm_two > 0,
            "the two arms of this rule are meant to be exercised by disjoint populations, but \
             {passed_by_arm_one} manifest(s) passed by declaring and {passed_by_arm_two} by \
             inheriting. An arm with no members is an arm no mutation can turn red."
        );
    }

    /// Both licence files exist, are actually published, and name the same
    /// copyright holder -- which is the holder pinned in this test.
    ///
    /// A licence file that is not in the export baseline licenses nothing: the
    /// curator stages exactly the baseline, so an unpublished `LICENSE-MIT`
    /// means every published manifest's `MIT OR Apache-2.0` points at a
    /// document the recipient never receives. Presence on disk and presence in
    /// the baseline are therefore both required, and they are separate
    /// assertions because they fail for entirely different reasons.
    ///
    /// The expected holder is a LITERAL here and is not derived from either
    /// file. Deriving it would make this `assert_eq!(X, X)` -- the check would
    /// go on passing while both files were rewritten to name someone else,
    /// which is the single most common way an assertion in this repository has
    /// been found unable to fail.
    ///
    /// **Vacuity guards:** each extracted holder must be non-empty (an
    /// extractor returning `""` from both files would compare equal and pass);
    /// the two file bodies must differ and each must contain its own licence's
    /// name (an extractor that silently read the same file twice, or a build
    /// step that copied one licence over the other, would otherwise agree
    /// perfectly with itself).
    ///
    /// **Mutations this detects:** changing the holder in either file;
    /// re-copyrighting one file and not the other; deleting either file;
    /// removing either from `tools/export-baseline.txt`; overwriting
    /// `LICENSE-APACHE` with the MIT text; an extractor regression that returns
    /// the empty string, or that case-insensitively matches Apache-2.0's own
    /// `copyright notice ...` body line instead of the holder line.
    #[test]
    fn both_licence_files_are_published_and_agree_on_the_copyright_holder() {
        let repo = repo_root();
        let baseline = export_baseline_paths(&repo).unwrap_or_else(|| {
            panic!(
                "tools/export-baseline.txt could not be read, so whether the licence files are \
                 PUBLISHED is unknown. Expected at: {}",
                repo.join("tools").join("export-baseline.txt").display()
            )
        });

        // `LICENSE-MIT` and `LICENSE-APACHE` also appear under
        // `contracts/lib/forge-std/`, so the baseline is matched by EXACT
        // repo-relative path. A suffix match would be satisfied by vendored
        // upstream licence files and would pass with this project's own root
        // licences deleted.
        let mut published = Vec::new();
        let mut on_disk = Vec::new();
        let mut extracted: Vec<(&str, String, String)> = Vec::new();
        for name in ["LICENSE-MIT", "LICENSE-APACHE"] {
            if baseline.iter().any(|rel| rel == name) {
                published.push(name);
            }
            let path = repo.join(name);
            if let Ok(text) = std::fs::read_to_string(&path) {
                on_disk.push(name);
                if let Some(holder) = copyright_holder(&text) {
                    extracted.push((name, holder, text));
                }
            }
        }

        assert_eq!(
            on_disk,
            vec!["LICENSE-MIT", "LICENSE-APACHE"],
            "a licence file named by every published manifest is missing from the repository root"
        );
        assert_eq!(
            published,
            vec!["LICENSE-MIT", "LICENSE-APACHE"],
            "a licence file is present on disk but absent from tools/export-baseline.txt, so the \
             curator will not stage it. Every published manifest declares `{REQUIRED_SPDX}`, and \
             an unpublished licence file makes half of that expression point at a document the \
             recipient never receives"
        );
        assert_eq!(
            extracted.len(),
            2,
            "no `Copyright` line could be extracted from {} of the two licence files; the \
             extractor cannot report agreement it never measured",
            2 - extracted.len()
        );

        let (mit_name, mit_holder, mit_text) = &extracted[0];
        let (apache_name, apache_holder, apache_text) = &extracted[1];

        // Two different files were genuinely read. An extractor that opened one
        // file twice, or a copy step that overwrote one licence with the other,
        // would agree with itself perfectly and say nothing.
        assert_ne!(
            mit_text, apache_text,
            "{mit_name} and {apache_name} hold byte-identical text, so one of them is a copy of \
             the other and the agreement asserted below is an artefact of reading one document \
             twice"
        );
        assert!(
            mit_text.contains("MIT License") && !mit_text.contains("Apache License"),
            "{mit_name} does not read as the MIT licence"
        );
        assert!(
            apache_text.contains("Apache License") && !apache_text.contains("MIT License"),
            "{apache_name} does not read as the Apache licence"
        );

        // Non-empty, checked before the comparison: `"" == ""` is agreement
        // that means nothing.
        for (name, holder, _) in &extracted {
            assert!(
                !holder.is_empty(),
                "the copyright holder extracted from {name} is empty, so comparing it against \
                 anything is comparing nothing"
            );
        }

        assert_eq!(
            mit_holder, apache_holder,
            "the two licence files name different copyright holders. A dual licence is one grant \
             made twice; two holders is two grants, and a recipient cannot tell which one they \
             have"
        );
        assert_eq!(
            mit_holder, EXPECTED_COPYRIGHT_HOLDER,
            "both licence files agree with each other but not with the holder this project \
             publishes. The expected value is pinned in this test on purpose -- if the holder \
             genuinely changed, change it here in the same commit so the change is visible"
        );
    }

    /// `README.md` routes a reader to both licence files and states the SPDX
    /// expression.
    ///
    /// # Why this is a test and not a style note
    ///
    /// The README named NEITHER licence file for the entire life of this
    /// repository, up to 2026-07-29, while both files sat in the root beside
    /// it. That is not a cosmetic gap. The README is the first and often the
    /// only document a reader opens, the manifests state an SPDX expression
    /// that only means something once you can find the two texts it refers to,
    /// and a licence a reader cannot find does not do the one job a licence
    /// has. Nothing checked it, so nothing noticed for the repository's whole
    /// history.
    ///
    /// All three needles are asserted SEPARATELY rather than as one
    /// "mentions the licence" boolean, so each has a mutation that turns it and
    /// only it red.
    ///
    /// **Mutations this detects:** deleting the `LICENSE-MIT` link from the
    /// README; deleting the `LICENSE-APACHE` link; dropping the
    /// `MIT OR Apache-2.0` SPDX expression, or rewriting it to name one licence
    /// (which is exactly the drift `goatcoin-rs/Cargo.toml` shipped); deleting
    /// `README.md` (explicit panic naming the path).
    #[test]
    fn the_readme_points_a_reader_at_both_licence_files() {
        let repo = repo_root();

        // Presence in the baseline is a SEPARATE question from the file's
        // contents, and it is asked first for the same reason the licence-file
        // test asks it: this module's scope is what gets published, not what
        // sits in the working tree. Without this, deleting the `README.md` line
        // from tools/export-baseline.txt would export nine manifests declaring
        // `MIT OR Apache-2.0` and no README naming either licence file -- the
        // exact state the rest of this test exists to forbid -- with all three
        // tests still green.
        let baseline = export_baseline_paths(&repo).unwrap_or_else(|| {
            panic!(
                "tools/export-baseline.txt could not be read, so whether the README is PUBLISHED \
                 is unknown. Expected at: {}",
                repo.join("tools").join("export-baseline.txt").display()
            )
        });
        assert!(
            baseline.iter().any(|rel| rel == "README.md"),
            "README.md is absent from tools/export-baseline.txt, so the curator will not stage \
             it. A README that routes a reader to both licences routes nobody if it is not \
             published"
        );

        let path = repo.join("README.md");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "README.md could not be read, so whether it routes a reader to the licences is \
                 unknown. A missing README is a failure of this check, not an exemption from it. \
                 Expected at: {}",
                path.display()
            )
        });

        assert!(
            text.contains("LICENSE-MIT"),
            "README.md never names LICENSE-MIT. Both licence files sit in the repository root and \
             the README named neither of them for this repository's entire history; a reader who \
             cannot find the text cannot rely on the grant"
        );
        assert!(
            text.contains("LICENSE-APACHE"),
            "README.md never names LICENSE-APACHE. Naming one half of a dual licence is worse \
             than naming neither -- it reads as a single-licence project"
        );
        assert!(
            text.contains(REQUIRED_SPDX),
            "README.md does not carry the SPDX expression `{REQUIRED_SPDX}`, which is what every \
             published manifest declares. The README and the manifests must tell one story"
        );
    }
}

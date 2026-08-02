//! Crate-source sweeps, in one place, self-excluded.
//!
//! `#[cfg(test)]` only, and deliberately the ONE module that holds them, so
//! that every forbidden marker is written down exactly once and the file that
//! names them excludes itself from its own sweep. Markers are assembled at
//! runtime — the same technique `citation_audit::internal_doc_tree_markers()`
//! already uses — so this file cannot trip the very rules it enforces.
//!
//! Three properties live here, all of them source-level and all of them
//! enforced rather than documented:
//!
//! * **INV-5** — no listener API and no relay primitive in production code.
//! * **INV-19** — no persistence, no service registration, and no path to key
//!   material.
//! * **Vocabulary law** — the design term is allowlist and the refusal set is
//!   the deny-net; the retired money vocabulary appears nowhere.
//!
//! # Design authority
//!
//! The "Residential Proxy Network — Worker & Tunnel Spec (Tasks 18-36, 44, 45,
//! 47)", Task 34 and its Global Constraints section (vocabulary law) and
//! Security invariants section (INV-5, INV-19).

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    /// Assemble a forbidden marker at runtime, so this file does not contain
    /// the token it forbids.
    fn marker(parts: &[&str]) -> String {
        parts.concat()
    }

    /// `production_sources()` minus this file. AT THIS TASK: 17 source files,
    /// of which 16 are swept.
    ///
    /// Raised 14 -> 15 by Task 35, which adds `meter.rs`; 15 -> 16 by the
    /// canonical slug <-> id table, which adds `destinations.rs`.
    const PRODUCTION_SOURCES_AT_THIS_TASK: usize = 16;
    /// A floor on BYTES, not just on files: a file-count floor alone is
    /// defeated by a truncating pre-filter that blanks most of a file while
    /// leaving the count right.
    const MIN_SWEPT_BYTES: usize = 140_000;

    fn production_sources() -> Vec<(PathBuf, String)> {
        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).expect("src/ must be readable") {
            let p = e.expect("dir entry").path();
            if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                continue;
            }
            if p.ends_with("vocabulary_audit.rs") {
                continue; // a sweep must not read itself
            }
            let body = std::fs::read_to_string(&p).expect("read source");
            // The TRAILING test block only. Truncating at the first
            // `#[cfg(test)]` blanks everything after an early test helper —
            // `fetch.rs`'s `tests_support` module is exactly that shape — and
            // leaves it unswept while the file count stays right.
            let prod = match body.rfind("\n#[cfg(test)]\nmod tests {") {
                Some(i) => body[..i].to_string(),
                None => body,
            };
            out.push((p, prod));
        }
        out
    }

    /// Both floors, in one place, applied by every sweep below.
    fn swept_corpus() -> Vec<(PathBuf, String)> {
        let files = production_sources();
        assert_eq!(
            files.len(),
            PRODUCTION_SOURCES_AT_THIS_TASK,
            "the swept file count moved; raise PRODUCTION_SOURCES_AT_THIS_TASK in the same commit"
        );
        let bytes: usize = files.iter().map(|(_, b)| b.len()).sum();
        assert!(
            bytes >= MIN_SWEPT_BYTES,
            "swept only {bytes} bytes; the pre-filter is eating the corpus"
        );

        // NEGATIVE CONTROL ON THE PRE-FILTER, because the byte floor alone does
        // NOT catch a first-match truncation. `fetch.rs` declares a
        // `#[cfg(test)]` helper module at column zero about a hundred lines
        // above its trailing test block; cutting at the first occurrence blanks
        // everything from there on, which is a few thousand bytes out of two
        // hundred thousand — the floor stays met and the sweep quietly stops
        // reading most of that file.
        let marker = marker(&["mod tests", "_support"]);
        let (path, body) = files
            .iter()
            .find(|(p, _)| p.ends_with("fetch.rs"))
            .expect("fetch.rs must be in the swept set");
        assert!(
            body.contains(marker.as_str()),
            "the pre-filter truncated {} at the FIRST #[cfg(test)] instead of the trailing test \
             block",
            path.display()
        );
        files
    }

    /// INV-5. No listener API and no relay primitive in production code.
    ///
    /// **No carve-out.** An earlier revision of this class of check swept whole
    /// files including their test modules, tripped on its own fixture origins,
    /// and was repaired with a per-file exemption — which disabled the listener
    /// check for the entire file, production code included, and that file is
    /// exactly where a listener would be added. Stripping the trailing test
    /// block removes the need for the carve-out, so the carve-out is gone.
    ///
    /// Mutations this detects: an accept half added to `net.rs`; a
    /// bidirectional copy added to `fetch.rs` to "support tunnelling"; a local
    /// control port bound by `main.rs` instead of reading the parent's stdin.
    #[test]
    fn no_listener_or_relay_apis_in_production_source() {
        let files = swept_corpus();
        let banned = [
            marker(&["Tcp", "Listener"]),
            marker(&["Udp", "Socket"]),
            marker(&["copy_bi", "directional"]),
            marker(&["bind", "("]),
        ];
        // POSITIVE CONTROL: the scanner sees its own tokens. A scanner with too
        // small an alphabet reports a clean sweep over everything.
        let control = banned.join(" ");
        for b in &banned {
            assert!(control.contains(b.as_str()), "the scanner cannot see {b}");
        }

        for (p, prod) in &files {
            for b in &banned {
                assert!(
                    !prod.contains(b.as_str()),
                    "{b} appears in production code in {}",
                    p.display()
                );
            }
        }
        // POSITIVE CONTROL: the sweep is reading real networking source, not
        // empty strings.
        assert!(
            files.iter().any(|(_, t)| t.contains("TcpStream")),
            "the sweep is not reading the crate's networking source"
        );
    }

    /// INV-19. No autostart, no service registration, no scheduled task.
    ///
    /// Persistence beyond the app is one of the heaviest behavioural triggers
    /// for an anti-malware proxyware classification, and the sidecar has none:
    /// it lives and dies with the supervisor that spawned it.
    ///
    /// Mutations this detects: a "start with Windows" convenience added to the
    /// sidecar; a launch agent or a unit file written at first run; a service
    /// control handler registered so the daemon survives a logout.
    #[test]
    fn no_autostart_or_service_registration_in_crate_source() {
        let files = swept_corpus();
        let banned = [
            marker(&["CurrentVersion", "\\\\Run"]),
            marker(&["Launch", "Agents"]),
            marker(&["launch", "ctl"]),
            marker(&["sch", "tasks"]),
            marker(&["system", "ctl"]),
            marker(&["SetService", "Status"]),
            marker(&["RegisterService", "CtrlHandler"]),
        ];
        // POSITIVE CONTROL before the absence assertion.
        let control = banned.join(" ");
        for b in &banned {
            assert!(control.contains(b.as_str()), "the scanner cannot see {b}");
        }

        for (p, prod) in &files {
            for b in &banned {
                assert!(
                    !prod.contains(b.as_str()),
                    "a persistence API appears in {}",
                    p.display()
                );
            }
        }
    }

    /// INV-19. The sidecar has no path to key material.
    ///
    /// **The banned markers are key-material PATHS, not the bare token for a
    /// key holder.** An earlier revision banned that substring across every
    /// production source, which is unsatisfiable: the consent record must carry
    /// the address of the key that signed it — INV-8's whole point is that
    /// consent names a key — and the configuration must carry the address the
    /// supervisor named. A rule that cannot hold gets resolved by whoever
    /// writes second, and the likely resolution — renaming the field in this
    /// crate only — silently breaks the shared signature preimage with no test
    /// to catch it.
    ///
    /// `consent.rs` is additionally exempt by name, on the precedent this
    /// module already uses to exclude itself.
    ///
    /// Mutations this detects: a key file read added for "convenience"; a seed
    /// path threaded through the configuration; the exemption widened from one
    /// named file to a prefix.
    #[test]
    fn crate_source_names_no_wallet_or_keystore_path() {
        let files = swept_corpus();
        let banned = [
            marker(&["key", "store"]),
            marker(&["mne", "monic"]),
            marker(&["private", "key"]),
            marker(&["private", "_key"]),
            marker(&["seed", "phrase"]),
            marker(&["wall", "et_path"]),
            marker(&["wall", "et_dir"]),
            marker(&["wall", "et_file"]),
            marker(&["signing", "key"]),
        ];
        let mut checked = 0usize;
        for (p, prod) in &files {
            if p.ends_with("consent.rs") {
                continue; // the record definition; see the doc comment
            }
            checked += 1;
            let lower = prod.to_ascii_lowercase();
            for b in &banned {
                assert!(
                    !lower.contains(b.to_ascii_lowercase().as_str()),
                    "a key-material symbol appears in {}",
                    p.display()
                );
            }
        }
        assert_eq!(
            checked,
            PRODUCTION_SOURCES_AT_THIS_TASK - 1,
            "exactly one file is exempt"
        );

        // POSITIVE CONTROL: the markers can match. Without this, a typo in a
        // marker would make the sweep permanently green.
        for b in &banned {
            let probe = format!("let p = {b};");
            assert!(
                probe
                    .to_ascii_lowercase()
                    .contains(b.to_ascii_lowercase().as_str()),
                "the scanner cannot see its own marker {b}"
            );
        }
    }

    /// Vocabulary law. The design term is allowlist; the refusal set is the
    /// deny-net; the retired money vocabulary appears nowhere.
    ///
    /// Mutations this detects: a comment describing the destination list by the
    /// token a deny-list is normally called; any present-tense
    /// contribution-reward wording reaching a source comment or an identifier.
    #[test]
    fn forbidden_policy_vocabulary_absent_from_proxy_crate() {
        let files = swept_corpus();
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
        // POSITIVE CONTROL: the scanner sees its own tokens.
        let control = banned.join(" ").to_ascii_lowercase();
        for b in &banned {
            assert!(
                control.contains(b.to_ascii_lowercase().as_str()),
                "the scanner cannot see {b}"
            );
        }

        for (p, prod) in &files {
            let lower = prod.to_ascii_lowercase();
            for b in &banned {
                assert!(
                    !lower.contains(b.as_str()),
                    "banned vocabulary {b} in {}",
                    p.display()
                );
            }
        }
        // POSITIVE CONTROL: the approved vocabulary really is used.
        assert!(
            files
                .iter()
                .any(|(_, t)| t.to_ascii_lowercase().contains("allowlist")),
            "the crate must actually use the approved vocabulary"
        );
        assert!(
            files
                .iter()
                .any(|(_, t)| t.to_ascii_lowercase().contains("deny-net")),
            "the crate must actually use the approved refusal-set term"
        );
    }

    /// Citation discipline in a published tree.
    ///
    /// Every file this crate ships is published, so every design-authority
    /// pointer in it must be a quoted title and a section — never an internal
    /// document-tree path and never a bare date. The attestor's citation audit
    /// sweeps the same surface from the export baseline; this is the same rule
    /// enforced one crate earlier, so a regression fails in the crate's own job
    /// rather than three jobs downstream.
    ///
    /// Mutations this detects: a path citation added to a doc comment; a spec
    /// referenced by the date in its filename stem.
    #[test]
    fn no_internal_document_tree_path_is_cited_in_crate_source() {
        let files = swept_corpus();
        let banned = [
            marker(&["docs/", "superpowers"]),
            marker(&["Coun", "cil/"]),
            marker(&["wiki/", "hot.md"]),
            marker(&["wiki/", "log.md"]),
            marker(&["wiki/", "index.md"]),
            marker(&["DOC_", "INDEX.md"]),
            marker(&[".superpowers", "/sdd"]),
        ];
        // POSITIVE CONTROL: the scanner sees its own tokens.
        let control = banned.join(" ");
        for b in &banned {
            assert!(control.contains(b.as_str()), "the scanner cannot see {b}");
        }

        for (p, prod) in &files {
            for b in &banned {
                assert!(
                    !prod.contains(b.as_str()),
                    "{} cites design authority by path ({b}); cite the quoted title and section",
                    p.display()
                );
            }
        }
        // POSITIVE CONTROL: the crate really does cite its authority, so this
        // is not a sweep over sources that cite nothing at all.
        assert!(
            files
                .iter()
                .any(|(_, t)| t.contains("Residential Proxy Network")),
            "no source cites the spec by title; this sweep is watching an empty set"
        );
    }

    /// The module names `lib.rs` declares with `mod NAME;` — declarations only,
    /// never an inline `mod NAME { … }`, which needs no file.
    ///
    /// Comment lines are dropped before matching. This file's own declaration in
    /// `lib.rs` carries a paragraph of prose above it, and a doc comment that
    /// happened to contain the phrase would otherwise be read as a declaration.
    fn declared_modules(src: &str) -> Vec<String> {
        let mut out = Vec::new();
        for line in src.lines() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with('#') {
                continue;
            }
            let t = t.strip_prefix("pub ").unwrap_or(t);
            let Some(rest) = t.strip_prefix("mod ") else {
                continue;
            };
            let Some(name) = rest.strip_suffix(';') else {
                continue; // `mod NAME {` — inline, no file to publish
            };
            let name = name.trim();
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                out.push(name.to_string());
            }
        }
        out
    }

    /// Every `mod NAME;` in `lib.rs` must resolve to a file that is PUBLISHED,
    /// not merely present on this machine.
    ///
    /// THE FAILURE THIS CATCHES, MEASURED. `lib.rs` declared
    /// `mod vocabulary_audit;` and was itself published, while
    /// `vocabulary_audit.rs` was withheld from the export on the reasoning that
    /// a `#[cfg(test)]` module ships no runtime code and therefore need not be
    /// published. The public tree then carried a declaration pointing at
    /// nothing: `cargo fmt` refused to resolve the module before a single test
    /// ran, and the same class of break took out two more jobs in the attestor
    /// crate. `#[cfg(test)]` is no protection — `cargo fmt`, `cargo clippy
    /// --all-targets` and `cargo test` all resolve `mod NAME;`.
    ///
    /// It is a CLASS check rather than a list: `lib.rs` is re-read each run, so
    /// a module added later is covered without anyone remembering a row.
    #[test]
    fn every_module_lib_declares_is_published() {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let lib = std::fs::read_to_string(crate_root.join("src").join("lib.rs"))
            .expect("src/lib.rs must be readable");
        let mods = declared_modules(&lib);

        // VACUITY GUARD plus a positive and a negative control on the parser: a
        // parser that returns nothing passes every membership test below.
        assert!(
            mods.len() >= 10,
            "parsed only {} module declaration(s) from lib.rs; the parser is broken and every \
             assertion below would pass against an empty list",
            mods.len()
        );
        assert!(
            mods.iter().any(|m| m == "policy"),
            "the parser did not find `mod policy;`, which lib.rs certainly declares"
        );
        assert!(
            !mods.iter().any(|m| m == "tests"),
            "the parser treated an inline `mod tests {{` as a declaration; it needs no file"
        );

        // Every declared module resolves to a real file. In a published checkout
        // this is also guaranteed by the fact that this test compiled at all —
        // it is kept because it proves the names the parser returned are real
        // rather than plausible.
        for m in &mods {
            let f = crate_root.join("src").join(format!("{m}.rs"));
            assert!(
                f.is_file(),
                "lib.rs declares `mod {m};` but {} does not exist",
                f.display()
            );
        }

        // WHICH TREE IS THIS. The baseline is itself unpublished, so its absence
        // is normal in a published checkout and must not be read as permission
        // to skip: a published checkout is identified positively, by the absence
        // of every internal marker as well.
        let repo = crate_root.join("..").join("..");
        let baseline_path = crate_root.join("..").join("export-baseline.txt");
        let Ok(baseline) = std::fs::read_to_string(&baseline_path) else {
            let markers = [
                "DOC_INDEX.md",
                "Council",
                "wiki",
                "tools/curate-public-export.ps1",
                &marker(&["docs/", "superpowers"]),
            ];
            let present: Vec<&&str> = markers
                .iter()
                .filter(|m| {
                    repo.join(m.replace('/', std::path::MAIN_SEPARATOR_STR))
                        .exists()
                })
                .collect();
            assert!(
                present.is_empty(),
                "the export baseline is missing, but this is an INTERNAL tree -- {present:?} \
                 present. What is published is therefore unknown. Restore the baseline."
            );
            return; // published checkout: the compiler already proved the point
        };

        assert!(
            baseline.lines().count() > 1000,
            "vacuity guard: the baseline looks truncated"
        );
        let listed = |p: &str| baseline.lines().any(|l| l.trim() == p);
        assert!(
            !listed("tools/goat-proxy-worker/src/not_a_real_module.rs"),
            "the baseline matched a path that does not exist; the membership test is vacuous"
        );
        for m in &mods {
            let row = format!("tools/goat-proxy-worker/src/{m}.rs");
            assert!(
                listed(&row),
                "lib.rs declares `mod {m};` and lib.rs is published, but {row} is NOT in the \
                 export baseline. The exported tree would carry a declaration whose file is \
                 absent and fail to build with E0583. Publish the file or drop the declaration."
            );
        }
    }
}

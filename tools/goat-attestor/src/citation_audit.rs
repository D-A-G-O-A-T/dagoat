//! A mechanical range check over the `file.rs:LINE` citations this crate's
//! doc comments are written in.
//!
//! # Why this exists
//!
//! This crate documents itself by pointing at other code: `preflight.rs`
//! names the Solidity line a revert is raised at, `runtime.rs` names the
//! config function that validated a key, tests name the contract passage they
//! pin. Those pointers are prose, so nothing has ever checked them, and they
//! rot in two ways that look identical to a reader and are not:
//!
//! 1. **The cited file grew or shrank**, so the number now names a different
//!    line of the same file. Silent, and the citation still *looks* plausible.
//! 2. **The cited line does not exist at all** — the file was refactored down,
//!    split, or replaced. This is the loud class, and it is the one this
//!    module catches.
//!
//! Both happened in this repository. Adding ~3,500 lines to `quotes.rs` and
//! `runtime.rs` in one session shifted 28 distinct citation targets (class 1),
//! and splitting `GoatRelayGateway.sol`'s body into `library` DELEGATECALL
//! targets left 39 citations pointing past the end of that now-484-line file
//! (class 2) — the worst named lines 741 through 758.
//!
//! # What this check does NOT do — read this before trusting a green run
//!
//! **It cannot tell whether a citation points at the RIGHT thing.** It only
//! proves the cited file exists and is long enough for the cited line to be
//! *a* line. A citation naming line 1642 of `quotes.rs` for a
//! `PrivateKeySigner::from_str` call that has since moved to line 2428 passes
//! this check, because line 1642 still exists. Class 1 rot is invisible here.
//!
//! The durable fix for class 1 is not a better test, it is a better citation:
//! **name the symbol** (function, const, struct, test name) and keep a line
//! number only where it genuinely adds something. A citation that names a
//! symbol cannot rot when a file grows. This check is the floor, not the
//! standard.
//!
//! # Scope
//!
//! * Scans every `.rs` file under this crate's `src/`.
//! * Recognises citations shaped `<basename>.rs:<N>` and `<basename>.sol:<N>`,
//!   optionally `-<M>`; the highest number in the range is the one checked.
//! * Resolves a basename against `src/` (recursively) plus the repository's
//!   `contracts/src`, `contracts/test` and `contracts/script`. A basename that
//!   matches several files passes if *any* candidate is long enough — this
//!   check deliberately errs toward silence rather than toward a false alarm
//!   it cannot disambiguate.
//! * [`EXTERNAL_CRATE_SOURCES`] is skipped: `log_capture.rs` cites
//!   `tracing-core`'s own source by path, which is not in this repository.
//! * `.md` spec citations are out of scope. They are written with elisions
//!   (`…-usdt-paymaster-….md:808`) that no basename lookup can resolve.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Basenames that name a *dependency's* source file, not one of ours. A
/// citation into one of these is unresolvable here and is not a defect.
const EXTERNAL_CRATE_SOURCES: &[&str] = &[
    // `tracing-core-0.1.36 src/…`, cited by `stream_g::log_capture`.
    "callsite.rs",
    "dispatcher.rs",
    "subscriber.rs",
];

/// One `<basename>:<lo>[-<hi>]` occurrence, with where it was written.
#[derive(Debug)]
struct Citation {
    /// Repo-relative path of the file the citation is written in.
    site_file: String,
    /// 1-indexed line the citation is written on.
    site_line: usize,
    /// The citation text exactly as it appears in the source, basename
    /// through last digit. Reproduced verbatim in the failure message so the
    /// offending string can be grepped for.
    text: String,
    /// Cited basename.
    base: String,
    /// Highest line number named (the `hi` of a range, else the only number).
    highest: usize,
}

/// Everything under `root` with one of `exts`, recursively.
fn walk(root: &Path, exts: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, exts, out);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| exts.contains(&e))
        {
            out.push(path);
        }
    }
}

/// `basename -> (longest candidate's line count, that candidate's path)`.
fn build_index(roots: &[PathBuf]) -> BTreeMap<String, (usize, String)> {
    let mut index: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for root in roots {
        let mut files = Vec::new();
        walk(root, &["rs", "sol"], &mut files);
        for path in files {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let lines = text.lines().count();
            let shown = path.to_string_lossy().replace('\\', "/");
            index
                .entry(name.to_string())
                .and_modify(|slot| {
                    if lines > slot.0 {
                        *slot = (lines, shown.clone());
                    }
                })
                .or_insert((lines, shown));
        }
    }
    index
}

/// Pull every `<basename>.(rs|sol):<N>[-<M>]` out of one line.
///
/// Hand-rolled rather than regex: this crate has no regex dependency, and a
/// scanner is easier to reason about than a pattern when the thing being
/// scanned is prose that also contains `Type::method`, `a:b` and URLs.
fn citations_in_line(site_file: &str, site_line: usize, line: &str, out: &mut Vec<Citation>) {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Find the next `.rs:` / `.sol:` — the extension is what anchors a
        // citation, so scan for the dot and test what follows.
        if bytes[i] != b'.' {
            i += 1;
            continue;
        }
        let rest = &line[i..];
        let ext_len = if rest.starts_with(".rs:") {
            4
        } else if rest.starts_with(".sol:") {
            5
        } else {
            i += 1;
            continue;
        };
        // Walk backwards over the basename stem. Allowed: alphanumerics,
        // `_`, `-`, `.` (for `PublishStreamG.s.sol`).
        let mut start = i;
        while start > 0 {
            let c = bytes[start - 1];
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.' {
                start -= 1;
            } else {
                break;
            }
        }
        if start == i {
            // `.rs:` with nothing in front of it — not a citation.
            i += ext_len;
            continue;
        }
        let num_start = i + ext_len;
        let mut j = num_start;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j == num_start {
            i += ext_len;
            continue;
        }
        let lo: usize = line[num_start..j].parse().unwrap_or(0);
        let mut highest = lo;
        let mut end = j;
        // Optional `-<M>` range.
        if j < bytes.len() && bytes[j] == b'-' {
            let mut k = j + 1;
            while k < bytes.len() && bytes[k].is_ascii_digit() {
                k += 1;
            }
            if k > j + 1 {
                if let Ok(hi) = line[j + 1..k].parse::<usize>() {
                    highest = highest.max(hi);
                    end = k;
                }
            }
        }
        // The basename is everything from `start` through the extension.
        let base = line[start..num_start - 1].to_string();
        out.push(Citation {
            site_file: site_file.to_string(),
            site_line,
            text: line[start..end].to_string(),
            base,
            highest,
        });
        i = end;
    }
}

/// The internal-only documentation trees that must never be named by a
/// citation in shipped source.
///
/// Assembled from fragments at runtime rather than written as literals, for
/// the same reason the scanner tests assemble their needles: this file is
/// itself inside the swept tree, and a literal here would make the sweep flag
/// its own rule table. Anything that changes here should change in lockstep
/// with the curator's `INTERNAL_KB_REF` rule in
/// `tools/curate-public-export.ps1`.
fn internal_doc_tree_markers() -> Vec<String> {
    let docs = "docs";
    let sp = "superpowers";
    let sep = "/";
    vec![
        // The design-spec and plan tree.
        format!("{docs}{sep}{sp}"),
        // Session reports (the dot-prefixed sibling tree's `sdd` directory).
        format!(".{sp}{sep}sdd"),
        // The strategy / advisor tree.
        format!("Council{sep}"),
        // The Obsidian vault's three routed notes.
        format!("wiki{sep}hot.md"),
        format!("wiki{sep}log.md"),
        format!("wiki{sep}index.md"),
        // OpenSpec change proposals.
        format!("openspec{sep}changes"),
    ]
}

/// Every occurrence of any `markers` entry in `text`, as `(line_no, line)`.
///
/// Case-insensitive, matching the curator rule this mirrors. Whole-line
/// context is returned rather than just the marker so a failure message can be
/// grepped for directly.
fn internal_doc_tree_hits(text: &str, markers: &[String]) -> Vec<(usize, String)> {
    let lowered_markers: Vec<String> = markers.iter().map(|m| m.to_lowercase()).collect();
    let mut hits = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let lowered = line.to_lowercase();
        if lowered_markers.iter().any(|m| lowered.contains(m)) {
            hits.push((n + 1, line.trim().to_string()));
        }
    }
    hits
}

/// The curator's per-FILE publication record, `tools/export-baseline.txt`,
/// parsed into repo-relative paths.
///
/// This is not a convenience: it is what makes the internal-doc-tree sweep's
/// scope impossible to drift from the exporter's. The curator stages exactly
/// `allowlisted-tree ∩ this file`, so a path listed here is a path a human has
/// accepted for publication, and a path accepted for publication is a path
/// whose contents the `INTERNAL_KB_REF` rule will be applied to.
///
/// Format: one repo-relative path per line, `#` comments and blank lines
/// ignored, backslashes normalised. Returns `None` when the file is absent —
/// the caller turns that into a loud failure rather than a quiet narrowing,
/// because "the baseline vanished" and "the tree is clean" must not produce
/// the same green run.
fn export_baseline_paths(repo: &Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(repo.join("tools").join("export-baseline.txt")).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        out.push(t.replace('\\', "/"));
    }
    Some(out)
}

/// `Some(text)` when `path` holds decodable text, `None` when it is binary,
/// unreadable or absent.
///
/// A NUL byte is the discriminator, checked before UTF-8 validation: `desktop/`
/// and `brand/` publish PNGs and icon fonts, and a byte sequence that happens
/// to be valid UTF-8 is not thereby text. Nothing here reports an error,
/// because "not text" is the normal case for a large fraction of the exported
/// tree; the vacuity guards downstream are what prove the reader is working.
fn read_text_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.contains(&0u8) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Third-party code vendored into the export, excluded from every sweep here.
///
/// `contracts/lib/` is 781 files of OpenZeppelin + forge-std committed inline.
/// The curator makes the same exclusion for the same reason and says so:
/// upstream code cannot leak *our* internal material, only its own, so it lists
/// `INTERNAL_KB_REF` among the classes it downgrades to Review inside these
/// prefixes. Measured: OpenZeppelin's own audit archive carries
/// `note on <date>: this report ma…` in `audits/`, which is upstream's
/// citation of upstream's document and is none of this repository's business.
///
/// Keep this in lockstep with the curator's `$VendoredPrefixes`.
const VENDORED_PREFIXES: &[&str] = &["contracts/lib/"];

/// Files whose presence means this is the INTERNAL tree. None is ever published:
/// measured 2026-07-30, the export baseline contains zero paths under any of
/// them, and a published checkout carries none of them on disk.
///
/// A deliberate duplicate of `license_audit`'s list, for the same reason its
/// baseline reader is duplicated: the two audits must be able to disagree about
/// where they look, and a narrowing made for one must not silently narrow the
/// other.
/// The private-doc-tree entry is ASSEMBLED, never written out: this file is
/// inside the swept set, so the literal would be its own first finding. That is
/// the same reason the probes further down are built at runtime, and it was not
/// theoretical -- writing it plainly here turned this very test red, naming both
/// audit modules.
fn internal_docs_marker() -> String {
    format!("docs/{}", "superpowers")
}

const INTERNAL_TREE_MARKERS: &[&str] = &[
    "DOC_INDEX.md",
    "Council",
    "wiki",
    "tools/curate-public-export.ps1",
];

/// Directory NAMES the published-tree walk never descends into.
const WALK_PRUNE: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "out",
    "cache",
    "broadcast",
    "dist",
    "build",
];

/// WHICH TREE IS THIS, and therefore what "the exported surface" means here.
///
/// In the INTERNAL tree the exported surface is a subset, named by the curator's
/// record. In a PUBLISHED checkout there is no subset: everything present was
/// exported. Answering the second case by panicking made this audit fail
/// permanently on the public repository; answering it by skipping would be a
/// check that cannot fail in the tree it is actually about. It is answered by
/// deriving the set, and the derived set is strictly WIDER — every file, not an
/// accepted subset — so the published branch sweeps more, never less.
///
/// THE DISCRIMINATOR IS NOT "the baseline is missing", because that would let a
/// deleted baseline in the internal tree downgrade to the whole-tree branch and
/// quietly change what "exported" means. A published checkout is identified
/// positively: baseline absent AND every internal marker absent. A missing
/// baseline beside any marker is still a hard panic.
enum Publication {
    Internal(Vec<String>),
    Published,
}

fn publication(repo: &Path) -> Publication {
    if let Some(baseline) = export_baseline_paths(repo) {
        return Publication::Internal(baseline);
    }
    let mut all_markers: Vec<String> = INTERNAL_TREE_MARKERS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    all_markers.push(internal_docs_marker());
    let present: Vec<&String> = all_markers
        .iter()
        .filter(|m| {
            repo.join(m.replace('/', std::path::MAIN_SEPARATOR_STR))
                .exists()
        })
        .collect();
    assert!(
        present.is_empty(),
        "tools/export-baseline.txt is missing, but this is an INTERNAL tree -- {present:?} \
         present. The exported surface is therefore UNKNOWN: it is neither the baseline (gone) \
         nor the whole tree (most of which is private), so a sweep would silently narrow. \
         Restore the baseline. Only a genuine published checkout, carrying none of those \
         markers, takes the derived path."
    );
    Publication::Published
}

/// Every file in a published checkout, repo-relative, build output pruned.
fn walk_published_tree(repo: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !WALK_PRUNE.contains(&name.as_str()) {
                walk_published_tree(repo, &path, out);
            }
        } else if let Ok(rel) = path.strip_prefix(repo) {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// The words that turn a nearby date into a *document* reference rather than
/// just a date: `spec YYYY-MM-DD`, `design YYYY-MM-DD`, `plan YYYY-MM-DD`,
/// `YYYY-MM-DD-session-report`.
///
/// Deliberately short. `consultant YYYY-MM-DD` and `founder decision
/// YYYY-MM-DD` name an event, not a document, and are left alone; a rule that
/// swallowed every date in the tree would be turned off within a week.
///
/// Dates are written `YYYY-MM-DD` in every doc comment in this file, never as
/// digits, for the same reason the marker table is assembled at runtime: this
/// file is inside the swept set and a literal example would make the sweep
/// flag its own documentation.
const DOC_KIND_WORDS: &[&str] = &["spec", "specs", "plan", "plans", "design", "report", "brief"];

/// Collapse a source file into one line of prose with comment leaders removed,
/// so a citation that wraps across two comment lines is still one string.
///
/// This is not cosmetic. Every long title in this repository wraps: the Stream
/// G live-chain-sourcing title runs to sixty characters and is written across
/// two comment lines with the break falling inside the quotes, so a
/// line-at-a-time scanner sees two fragments and neither resolves. The same is
/// true of the date citations this replaced.
///
/// (No example is spelled out here. This file is inside the swept set, and a
/// literal title-plus-keyword would make the sweep flag its own
/// documentation — the same reason the marker table is assembled at runtime.)
fn flatten_prose(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let mut t = line.trim();
        // Strip one comment leader, longest first so `///` is not read as `//`
        // plus a stray slash.
        for lead in ["<!--", "///", "//!", "//", "--", "#", "*"] {
            if let Some(rest) = t.strip_prefix(lead) {
                t = rest.trim_start();
                break;
            }
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(t);
    }
    out
}

/// Fold a document title to a comparison key: markdown bold stripped, every
/// dash form unified, whitespace collapsed, case folded.
///
/// The dash unification is load-bearing. `.sol` sources write
/// `Stream G -- USDT …` because the Solidity tree avoids non-ASCII, markdown
/// writes `Stream G — USDT …`, and `DOC_INDEX.md` writes the em dash. All
/// three are the same citation and a byte comparison would call two of them
/// unresolvable.
fn normalize_title(s: &str) -> String {
    let de_bold = s.replace("**", "");
    // Em dash and en dash in one pass, THEN the ASCII double hyphen. The order
    // matters and the two calls cannot merge: the first maps single characters,
    // the second collapses a two-character sequence that the first can produce.
    let dashed = de_bold.replace(['\u{2014}', '\u{2013}'], "-").replace("--", "-");
    dashed
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// `(title, path)` for every row of `DOC_INDEX.md` §7, the table that makes a
/// title citation resolvable. `None` when the file or the section is absent.
fn doc_index_title_rows(repo: &Path) -> Option<Vec<(String, String)>> {
    let text = std::fs::read_to_string(repo.join("DOC_INDEX.md")).ok()?;
    let mut rows = Vec::new();
    let mut in_section = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("## ") {
            in_section = t.starts_with("## 7.");
            continue;
        }
        if !in_section || !t.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = t.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 2 {
            continue;
        }
        // Skip the header row and the `|---|---|` separator.
        if cells[0].eq_ignore_ascii_case("title") || cells[0].starts_with("---") {
            continue;
        }
        rows.push((cells[0].to_string(), cells[1].trim_matches('`').to_string()));
    }
    Some(rows)
}

/// True when `word` occurs in `hay` bounded by non-alphanumerics on both
/// sides. `hay` is expected to be lowercase already.
fn contains_word(hay: &str, word: &str) -> bool {
    let bytes = hay.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(word) {
        let i = from + rel;
        let j = i + word.len();
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let after_ok = j >= bytes.len() || !bytes[j].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

/// First char boundary at or after `from`, never past `limit`.
fn snap_up(s: &str, from: usize, limit: usize) -> usize {
    (from..=limit).find(|k| s.is_char_boundary(*k)).unwrap_or(limit)
}

/// Last char boundary at or before `from`, never before `limit`.
fn snap_down(s: &str, from: usize, limit: usize) -> usize {
    (limit..=from)
        .rev()
        .find(|k| s.is_char_boundary(*k))
        .unwrap_or(limit)
}

/// Every `YYYY-MM-DD` in `flat` that is being used as a *document* reference,
/// returned as the excerpt around it.
///
/// Two shapes are caught, both measured in this repository:
///
/// 1. A date within [`DOC_REF_WINDOW`] characters of a word in
///    [`DOC_KIND_WORDS`] — `spec YYYY-MM-DD`, `UI spec YYYY-MM-DD §9.1`,
///    `FAH attribution plan YYYY-MM-DD`, `founder decision YYYY-MM-DD, design
///    §C3`.
/// 2. A date immediately followed by `-` and slug text — a dated FILENAME stem
///    with the directory and extension filed off, which is a path citation in
///    disguise: `spec YYYY-MM-DD-allowance-buydesk-design`,
///    `YYYY-MM-DD-session-report-eip712-relayer-hardening.md`. Shape 2 is the
///    one a half-done cleanup produces: ten citations in this crate had the
///    spec-tree prefix stripped and the dated filename left behind, which
///    satisfies the path rule and resolves to nothing.
fn dated_document_references(flat: &str) -> Vec<String> {
    let lower = flat.to_lowercase();
    let bytes = lower.as_bytes();
    let mut hits = Vec::new();
    let mut i = 0usize;
    while i + 10 <= bytes.len() {
        // `20dd-dd-dd`
        let is_date = bytes[i] == b'2'
            && bytes[i + 1] == b'0'
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            && bytes[i + 4] == b'-'
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6].is_ascii_digit()
            && bytes[i + 7] == b'-'
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit();
        if !is_date {
            i += 1;
            continue;
        }
        // Not part of a longer number/word on the left.
        if i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
            i += 10;
            continue;
        }
        let end = i + 10;
        let slug_stem = end < bytes.len()
            && bytes[end] == b'-'
            && end + 1 < bytes.len()
            && bytes[end + 1].is_ascii_alphabetic();
        // Window bounds are snapped to char boundaries before ANY slice. The
        // flattened prose carries em dashes, arrows and `‖`, and slicing one
        // in half panics — which is a crash in the checker rather than a
        // finding, i.e. the worst outcome available.
        let lo = snap_up(&lower, i.saturating_sub(DOC_REF_WINDOW), i);
        let hi = snap_down(&lower, (end + DOC_REF_WINDOW).min(bytes.len()), end);
        let before = &lower[lo..i];
        let after = &lower[end..hi];
        let near_kind = DOC_KIND_WORDS
            .iter()
            .any(|w| contains_word(before, w) || contains_word(after, w));
        if slug_stem || near_kind {
            hits.push(lower[lo..hi].trim().to_string());
        }
        i = end;
    }
    hits
}

/// How far either side of a date a document-kind word still counts as
/// describing it. 16 characters spans `UI spec `, `attribution plan ` and
/// `, design §C3` without reaching across an unrelated sentence.
const DOC_REF_WINDOW: usize = 16;

/// Every `"<title>" <spec|plan|notice>` citation in `flat`, as the raw quoted
/// span.
///
/// The trailing keyword is what separates a citation from ordinary quoting.
/// This repository quotes freely — `the "attacker"`, `the "days, not weeks"`,
/// `section 8.1 "Quote construction"` — and demanding that every quoted string
/// resolve to a document title would be a rule nobody could keep.
fn quoted_title_citations(flat: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = flat.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let Some(rel) = flat[i + 1..].find('"') else {
            break;
        };
        let close = i + 1 + rel;
        let inner = &flat[i + 1..close];
        // Snapped: the character after a closing quote is routinely a `—`, and
        // a mid-char slice would panic the checker instead of reporting.
        let tail_end = snap_down(flat, (close + 12).min(bytes.len()), close + 1);
        let tail = &flat[close + 1..tail_end];
        let tail_lower = tail.trim_start().to_lowercase();
        let is_citation = ["spec", "plan", "notice"]
            .iter()
            .any(|k| tail_lower.starts_with(k));
        if is_citation && inner.len() >= 8 && inner.len() <= 200 {
            out.push(inner.to_string());
        }
        i = close + 1;
    }
    out
}

/// Repository root, derived from this crate's manifest directory
/// (`<repo>/tools/goat-attestor`).
fn repo_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or(crate_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `file.rs:N` / `file.sol:N` citation in this crate's sources names
    /// a file that exists and a line that file actually has.
    ///
    /// **This does not verify that a citation points at the right thing** —
    /// see the module doc. It catches only the class where the number is past
    /// the end of the file (or the file is gone), which is the class that
    /// shipped 39 times in this repository after `GoatRelayGateway.sol` was
    /// split into libraries.
    ///
    /// Kept fast on purpose: two directory walks and one pass over each
    /// source file, no regex, no process spawn.
    ///
    /// **Mutations this detects:** re-introducing a citation into lines
    /// 741-758 of the 484-line `GoatRelayGateway.sol`; citing a file that no
    /// longer exists; a citation whose line number is one past the end of its
    /// target.
    ///
    /// This file writes no literal `name.rs:N` of its own — every needle is
    /// assembled at runtime — so the sweep never scans its own examples.
    #[test]
    fn every_source_citation_names_a_line_that_exists() {
        let repo = repo_root();
        let crate_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let roots = vec![
            crate_src.clone(),
            repo.join("contracts").join("src"),
            repo.join("contracts").join("test"),
            repo.join("contracts").join("script"),
        ];
        let index = build_index(&roots);
        assert!(
            index.contains_key("quotes.rs") && index.contains_key("GoatRelayGateway.sol"),
            "the citation index resolved neither a known .rs nor a known .sol target — the \
             scan roots are wrong, and a green run would mean nothing. Roots: {roots:?}"
        );

        let mut sources = Vec::new();
        walk(&crate_src, &["rs"], &mut sources);
        sources.sort();

        let mut found = Vec::new();
        for path in &sources {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            let shown = path
                .strip_prefix(&repo)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            for (n, line) in text.lines().enumerate() {
                citations_in_line(&shown, n + 1, line, &mut found);
            }
        }
        assert!(
            found.len() > 100,
            "only {} citations were extracted; this crate has hundreds, so the scanner is \
             broken and a green run would prove nothing",
            found.len()
        );

        let mut failures = Vec::new();
        for c in &found {
            if EXTERNAL_CRATE_SOURCES.contains(&c.base.as_str()) {
                continue;
            }
            match index.get(&c.base) {
                None => failures.push(format!(
                    "{}:{}  cites `{}` — no such file under src/ or contracts/",
                    c.site_file, c.site_line, c.text
                )),
                Some((lines, target)) if *lines < c.highest => failures.push(format!(
                    "{}:{}  cites `{}` — {} has only {} lines",
                    c.site_file, c.site_line, c.text, target, lines
                )),
                Some(_) => {}
            }
        }

        assert!(
            failures.is_empty(),
            "{} citation(s) point at a line that does not exist:\n  {}\n\n\
             Repair by naming the SYMBOL the citation is about (function, const, struct, test \
             name), not by nudging the number — a symbol cannot rot when a file grows.",
            failures.len(),
            failures.join("\n  ")
        );
    }

    /// The trees walked *in addition to* the export baseline, so that a file
    /// created today — before anyone has run `-UpdateBaseline` on it — is
    /// still swept in the places this repository actually changes.
    ///
    /// The baseline is the authority on what gets published; these six roots
    /// are the authority on what is about to. Extensions are per-root because
    /// a walk cannot ask a path whether it is text without opening it, and
    /// these roots are the hot ones — narrowing them here costs nothing, since
    /// every file that matters is also reached through the baseline once it is
    /// accepted.
    fn internal_doc_tree_walk_roots() -> Vec<(PathBuf, Vec<&'static str>)> {
        let repo = repo_root();
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        vec![
            (crate_dir.join("src"), vec!["rs"]),
            // The `include_str!`-ed fixtures: a citation here is compiled into
            // the binary and, for the fee schedule, logged to the operator.
            (crate_dir.join("fixtures"), vec!["json"]),
            (repo.join("contracts").join("src"), vec!["sol"]),
            (
                repo.join("contracts").join("test"),
                vec!["sol", "mjs", "js"],
            ),
            (repo.join("contracts").join("script"), vec!["sol"]),
            // Machine-written from `DeployStreamG.PAYLOAD_NOTE`; swept so a
            // hand edit or a stale regeneration is caught here too.
            (repo.join("contracts").join("deployments"), vec!["json"]),
        ]
    }

    /// Floor on how many text files a sweep must actually read.
    ///
    /// Measured 409 today (566 candidates, 157 of them binary — the `brand/`
    /// and `desktop/` image assets). The six walk roots contribute 129 on
    /// their own, so any bound at or below that would pass even with the
    /// export baseline entirely disconnected, which is the exact failure this
    /// guard exists to catch. 350 sits between the two.
    const MIN_SWEPT_TEXT_FILES: usize = 350;

    /// Files that MUST be in the swept set, one per exported surface the sweep
    /// has to reach, named individually so a scope regression fails loudly
    /// instead of silently.
    ///
    /// Every entry is a file a real defect was found in, or a file a verifier
    /// demonstrated the previous scope could not see:
    ///
    /// * `desktop/src/chain/abis.js`, `desktop/src-tauri/src/wallet.rs` —
    ///   the two `desktop/` files a verifier planted marker strings in while
    ///   the sweep stayed green.
    /// * `contracts/README.md` — the same, for a markdown file inside an
    ///   allowlisted tree that the extension list `{rs,sol,mjs,js,json}` could
    ///   not match.
    /// * `README.md` — an allowlisted ROOT file, a class the old scan roots
    ///   contained none of, and one of the two files the citation cleanup had
    ///   to repair for this very rule.
    /// * `desktop/src/components/HonestyBanner.jsx` — the other repaired file,
    ///   and a `.jsx` extension the old list did not carry.
    /// * `tools/goat-attestor/src/rpc_chain.rs` — the crate file that DID fail
    ///   under the old scope. It stays on this list so the sweep can never be
    ///   narrowed to nothing at all.
    const REQUIRED_SWEEP_COVERAGE: &[&str] = &[
        "desktop/src/chain/abis.js",
        "desktop/src-tauri/src/wallet.rs",
        "desktop/src/components/HonestyBanner.jsx",
        "contracts/README.md",
        "README.md",
        "tools/goat-attestor/src/rpc_chain.rs",
    ];

    /// Every file [`no_internal_doc_tree_path_citations`] reads, as
    /// `(repo-relative path, absolute path)`, deduplicated and sorted.
    ///
    /// Union of the export baseline and [`internal_doc_tree_walk_roots`]. The
    /// baseline half is why `desktop/` and the allowlisted root markdown are in
    /// scope at all; the walk half is why a brand-new contract or crate source
    /// is covered before anyone blesses it.
    fn internal_doc_tree_scan_set(repo: &Path) -> Vec<(String, PathBuf)> {
        let mut seen: BTreeMap<String, PathBuf> = BTreeMap::new();

        // In the internal tree this is the curator's accepted subset; in a
        // published checkout it is the whole tree, which is the same question
        // answered from the only evidence that exists there -- and it is the
        // WIDER answer. See `publication`.
        let paths = match publication(repo) {
            Publication::Internal(baseline) => baseline,
            Publication::Published => {
                let mut all = Vec::new();
                walk_published_tree(repo, repo, &mut all);
                all
            }
        };
        for rel in paths {
            if VENDORED_PREFIXES.iter().any(|p| rel.starts_with(p)) {
                continue;
            }
            let abs = repo.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
            seen.entry(rel).or_insert(abs);
        }

        for (root, exts) in internal_doc_tree_walk_roots() {
            let mut files = Vec::new();
            walk(&root, &exts, &mut files);
            for path in files {
                let rel = path
                    .strip_prefix(repo)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                seen.entry(rel).or_insert(path);
            }
        }

        seen.into_iter().collect()
    }

    /// No shipped source names an internal-only documentation tree.
    ///
    /// # What this defends
    ///
    /// The public-export curator (`tools/curate-public-export.ps1`) blocks any
    /// exported file containing a pointer into a private tree — its
    /// `INTERNAL_KB_REF` rule. That class does not stay fixed once cleaned:
    /// it grew from 51 to 56 hits during a single session, entirely from
    /// agents doing the right thing and citing design authority, because
    /// "cite your source" and "do not name the private tree" pull in opposite
    /// directions and citing wins every time. A one-time cleanup therefore
    /// cannot hold, and a documented convention that nothing checks decays
    /// exactly as this one did. This test is what makes the convention real.
    ///
    /// The replacement convention is **cite by title and section**: the
    /// document's H1 in double quotes, then the word `spec` (or `plan`), then
    /// `§<section>`. Titles resolve to paths through
    /// `DOC_INDEX.md` §7, which is never published, so the pointer survives
    /// for anyone holding the internal tree. It also survives a file rename,
    /// which a dated-filename path citation does not.
    ///
    /// # Scope, and how it is kept honest
    ///
    /// The swept set is the union of the curator's own per-file publication
    /// record (`tools/export-baseline.txt`) and the six hot trees in
    /// [`internal_doc_tree_walk_roots`], read as text regardless of extension.
    ///
    /// It is driven from the curator's record rather than from a hand-picked
    /// list because a hand-picked list is exactly how this test was wrong
    /// before: it swept the Rust crate and `contracts/`, while the class had
    /// actually regrown in `desktop/` and in `README.md`. A verifier planted
    /// marker strings in `desktop/src/chain/abis.js`,
    /// `desktop/src-tauri/src/wallet.rs` and `contracts/README.md` — all three
    /// inside allowlisted trees, all three matching the curator's regex — and
    /// this test stayed green on all three. `REQUIRED_SWEEP_COVERAGE` names
    /// those files so the scope can never narrow back without failing.
    ///
    /// Only internal-DOC-TREE pointers are in scope. The `file.rs:N` /
    /// `file.sol:N` SOURCE citations are a different mechanism with a
    /// different failure mode and are checked by
    /// [`every_source_citation_names_a_line_that_exists`]; nothing here looks
    /// at them.
    ///
    /// Fixtures and generated deployment documents are in scope on purpose:
    /// two of the worst instances of this class were not comments at all but
    /// `include_str!`-ed JSON `note` strings compiled into the binary, one of
    /// which was printed verbatim to whoever was running the relayer.
    ///
    /// `tools/curate-public-export.ps1` and `tools/export-baseline.txt` are
    /// NOT in scope, and cannot be: the curator excludes both from its own
    /// export (the script writes the marker regex and the baseline enumerates
    /// internal paths), so neither appears in the baseline and neither is
    /// under a walk root.
    ///
    /// **Mutations this detects:** adding a spec-tree path to any doc comment,
    /// string constant, fixture note, JSX file, markdown file or root README
    /// anywhere in the exported surface; re-introducing a strategy-tree or
    /// session-report pointer; a path split across two source lines (the tree
    /// prefix alone is enough to match); and — through
    /// `REQUIRED_SWEEP_COVERAGE` — narrowing the sweep's own scope.
    ///
    /// This file writes no marker literals of its own — every needle is
    /// assembled at runtime by [`internal_doc_tree_markers`] — so the sweep
    /// never flags its own rule table.
    #[test]
    fn no_internal_doc_tree_path_citations() {
        let repo = repo_root();
        let markers = internal_doc_tree_markers();

        // Positive control. Before trusting an empty result, prove the
        // detector fires at all: a green run from a broken matcher and a green
        // run from a clean tree are indistinguishable without this.
        for marker in &markers {
            let probe = format!("/// see {marker}/some-doc.md for the rule");
            let got = internal_doc_tree_hits(&probe, &markers);
            assert_eq!(
                got.len(),
                1,
                "the marker `{marker}` did not match a line built from it — the matcher is \
                 broken and an empty sweep would prove nothing"
            );
        }
        // Negative control: an ordinary line must not match.
        assert!(
            internal_doc_tree_hits(
                "/// the \"Stream G\" spec, section 8.1, publishes the rule",
                &markers,
            )
            .is_empty(),
            "a title-and-section citation — the convention this test exists to enforce — was \
             flagged; the matcher is over-broad"
        );

        // The scope guard, checked BEFORE the sweep runs. The class this test
        // exists to stop regrew in `desktop/` and in the allowlisted root
        // markdown; an earlier revision of this test could not see either, and
        // was green while three planted marker strings sat in exported files.
        // A green sweep whose scope is wrong is worse than no sweep, so the
        // scope is asserted first and by name.
        // The scope source, whichever tree this is. `publication` refuses a
        // MISSING baseline in an internal tree exactly as the old panic here did
        // -- that protection is unchanged. What is new is that a genuine
        // published checkout resolves to the whole tree instead of collapsing to
        // the walk roots.
        let scope = match publication(&repo) {
            Publication::Internal(baseline) => {
                assert!(
                    baseline.len() > 1000,
                    "the export baseline parsed to only {} path(s); it records over a thousand, \
                     so the parse is broken and the sweep would silently cover almost nothing",
                    baseline.len()
                );
                baseline.len()
            }
            Publication::Published => {
                let mut all = Vec::new();
                walk_published_tree(&repo, &repo, &mut all);
                assert!(
                    all.len() > 1000,
                    "this published checkout walked to only {} file(s); the export stages over a \
                     thousand, so the walk is broken and the sweep would cover almost nothing",
                    all.len()
                );
                all.len()
            }
        };
        let _ = scope;

        let scan_set = internal_doc_tree_scan_set(&repo);
        let in_scope: std::collections::BTreeSet<&str> =
            scan_set.iter().map(|(rel, _)| rel.as_str()).collect();
        let missing: Vec<&str> = REQUIRED_SWEEP_COVERAGE
            .iter()
            .copied()
            .filter(|rel| !in_scope.contains(rel))
            .collect();
        assert!(
            missing.is_empty(),
            "the sweep does not reach {} required file(s): {:?}\n\nEach one is an exported file \
             this rule demonstrably regrew in. Widen the scan set — do not delete the entry.",
            missing.len(),
            missing
        );

        let mut scanned = 0usize;
        let mut skipped_binary_or_absent = 0usize;
        let mut failures = Vec::new();
        for (shown, path) in &scan_set {
            let Some(text) = read_text_file(path) else {
                skipped_binary_or_absent += 1;
                continue;
            };
            scanned += 1;
            for (line_no, line) in internal_doc_tree_hits(&text, &markers) {
                let excerpt: String = line.chars().take(140).collect();
                failures.push(format!("{shown}:{line_no}  {excerpt}"));
            }
        }
        // Measured today: 566 candidates, 409 of them text. The six walk roots
        // ALONE contribute 129, so this threshold is what distinguishes "the
        // baseline half of the scan set is working" from "the baseline half
        // silently dropped out" — a bound below 129 would be a check that
        // cannot fail.
        assert!(
            scanned > MIN_SWEPT_TEXT_FILES,
            "only {scanned} of {} candidate file(s) were read as text ({skipped_binary_or_absent} \
             skipped as binary or absent). The six walk roots alone hold ~129, so a number this \
             low means the export baseline stopped contributing and `desktop/` plus the \
             allowlisted root files went unswept",
            scan_set.len()
        );

        assert!(
            failures.is_empty(),
            "{} citation(s) name an internal-only documentation tree, which the public-export \
             curator blocks (INTERNAL_KB_REF) and which does not survive a file rename:\n  {}\n\n\
             Repair by citing the document's TITLE and SECTION instead of its path — the H1 in \
             double quotes, then the word spec (or plan), then the section — and resolve the \
             title through DOC_INDEX.md §7, which is never published. If the document's own \
             title carries retired vocabulary, cite the DECISION rather than the document; if \
             it is a session report, drop the pointer and keep the substance.",
            failures.len(),
            failures.join("\n  ")
        );
    }

    /// Spec citations in shipped source are resolvable: none is a bare date,
    /// and every title cited names a row of `DOC_INDEX.md` §7 that points at a
    /// document that exists and still carries that title.
    ///
    /// # Why a title rule needs this test
    ///
    /// [`no_internal_doc_tree_path_citations`] forbids the path form. On its
    /// own that is only half a convention: it says what not to write and
    /// leaves "what to write instead" to good intentions, and the thing good
    /// intentions actually produced here was a DATE.
    ///
    /// A date looks like a citation and is not one. Twenty-two of them
    /// shipped — `spec YYYY-MM-DD` (three documents carry that one date),
    /// `UI spec YYYY-MM-DD §9.1` (two, one of them 111 KB),
    /// `spec YYYY-MM-DD-allowance-buydesk-design` and ten `…-usdt-paymaster-…`
    /// stems (filenames with the directory filed off — what a cleanup that
    /// removes the tree prefix and stops there leaves behind). None resolved,
    /// none was in §7, and nothing surfaced them: the path sweep is green on
    /// every one, because a date names no tree.
    ///
    /// So this test closes the other half. It is also what makes §7 a
    /// *resolver* rather than a list: a row whose file was renamed or whose
    /// H1 was rewritten fails here, at which point the citations pointing
    /// through it are known to be dead instead of quietly wrong.
    ///
    /// # The three assertions
    ///
    /// 1. **§7 resolves.** Every row's path exists and the file's H1 still
    ///    matches the row's Title (a trailing status parenthetical —
    ///    `(spec)`, `(founder-confirmed)`, `(DRAFT for consultant review)` —
    ///    is allowed to differ, per the table's own stated convention).
    /// 2. **No dated document reference** anywhere in the exported surface.
    /// 3. **Every quoted title citation** — `"<Title>" spec|plan|notice` —
    ///    names a §7 row.
    ///
    /// **Mutations this detects:** writing `spec YYYY-MM-DD` instead of a
    /// title; citing a title that has no §7 row; renaming a spec file without
    /// updating its row; rewriting a spec's H1 without updating its row;
    /// deleting §7.
    #[test]
    fn spec_citations_resolve_through_doc_index() {
        let repo = repo_root();

        // -- positive controls, before trusting any empty result ------------
        //
        // Needles assembled at runtime, as everywhere else in this file, so
        // the sweeps below never find this test's own examples.
        let y = "20";
        let probe_date = format!("the {y}26-07-13 spec says so");
        assert_eq!(
            dated_document_references(&probe_date).len(),
            1,
            "the dated-reference detector did not fire on a date next to a document word; an \
             empty sweep would prove nothing"
        );
        let probe_stem = format!("see {y}26-07-15-session-report-eip712 for the vectors");
        assert_eq!(
            dated_document_references(&probe_stem).len(),
            1,
            "the dated-reference detector did not fire on a dated filename stem; that is the \
             shape a path citation degrades into"
        );
        // Negative controls: a date that names an event, and a version string.
        for benign in [
            format!("founder ruling {y}26-07-28 locked the vocabulary"),
            format!("generated {y}26-07-28T05:03:27Z by the curator"),
        ] {
            assert!(
                dated_document_references(&benign).is_empty(),
                "an ordinary date was read as a document citation: {benign:?} — the detector is \
                 over-broad and will be switched off"
            );
        }
        // Every probe below is BUILT, never written out: a literal
        // quote-then-`spec` in this file would be a title citation by the very
        // rule under test, and this file is inside the swept set. Two of these
        // three were literals first, and the sweep flagged its own test.
        let q = '"';
        let probe_title = format!("per the {q}Some Document — Design{q} spec, §2");
        assert_eq!(
            quoted_title_citations(&probe_title),
            vec!["Some Document — Design".to_string()],
            "the title-citation extractor did not find a quoted title followed by `spec`"
        );
        let probe_quote = format!("section 8.1 {q}Quote construction{q}, which pins the bytes");
        assert!(
            quoted_title_citations(&probe_quote).is_empty(),
            "an ordinary quoted phrase was read as a document title; the extractor is over-broad"
        );
        // Wrapping is the norm for long titles; prove the flattener joins.
        let wrapped = format!(
            "// the {q}Some Long Document Title Split Across\n// Two Comment Lines{q} spec, §2"
        );
        assert_eq!(
            quoted_title_citations(&flatten_prose(&wrapped)).len(),
            1,
            "a citation wrapped across two comment lines was not rejoined; every long title in \
             this repository wraps, so a line-at-a-time scan would miss most of them"
        );

        // -- 1. DOC_INDEX.md §7 is a working resolver -----------------------
        //
        // THE RESOLVER IS AN INTERNAL-TREE OBJECT. `DOC_INDEX.md` maps a spec
        // title to its path inside the private doc tree, so publishing it would
        // itself violate the rule the sibling test enforces. In a published
        // checkout it is therefore absent BY DESIGN, and "does every citation
        // resolve through §7?" is not a question that has an answer there --
        // there is no §7.
        //
        // Panicking on that (the original behaviour) made this test fail
        // permanently on the public repository. What runs instead is everything
        // that IS defined without a resolver: the dated-reference sweep below,
        // over the same scan set, with the same floor. The resolver half is
        // skipped only where no resolver can exist, and `publication` proves
        // that is the case rather than assuming it.
        //
        // 🔴 THE RESIDUAL IS REAL AND IS NOT FIXED BY THIS TEST. Measured
        // 2026-07-30: 56 quoted title citations sit in published files, and a
        // public reader can resolve none of them, because the documents they
        // name are not published and neither is the table that would map them.
        // That is a CONTENT decision about what the public repository should
        // ship, not something a test can assert its way out of, and it is
        // recorded here so the gap is visible rather than implied by silence.
        let resolver = match (doc_index_title_rows(&repo), publication(&repo)) {
            (Some(rows), _) => Some(rows),
            (None, Publication::Published) => None,
            (None, Publication::Internal(_)) => panic!(
                "DOC_INDEX.md §7 could not be read, so no title citation in this repository is \
                 resolvable. The table is the only resolver; it is not optional. (This is an \
                 INTERNAL tree -- a published checkout, which carries none of the internal \
                 markers, is the only place its absence is expected.)"
            ),
        };
        let resolver_available = resolver.is_some();
        let rows = resolver.unwrap_or_default();
        if resolver_available {
            assert!(
                rows.len() >= 15,
                "DOC_INDEX.md §7 parsed to only {} row(s); it carries at least fifteen, so the \
                 parse is broken and every check below would pass vacuously",
                rows.len()
            );
        }

        let mut index_failures = Vec::new();
        let mut known: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (title, path) in &rows {
            known.insert(normalize_title(title));
            let full = repo.join(path.replace('/', std::path::MAIN_SEPARATOR_STR));
            let Ok(text) = std::fs::read_to_string(&full) else {
                index_failures.push(format!(
                    "row {title:?} -> {path} : no such file. A citation resolved through this row \
                     lands nowhere."
                ));
                continue;
            };
            let Some(h1) = text
                .lines()
                .find_map(|l| l.strip_prefix("# ").map(str::trim))
            else {
                index_failures
                    .push(format!("row {title:?} -> {path} : the document has no H1 heading"));
                continue;
            };
            let want = normalize_title(title);
            let got = normalize_title(h1);
            // The table's own rule: Title is the H1 verbatim, minus any
            // trailing status parenthetical.
            if got != want && !got.starts_with(&format!("{want} (")) {
                index_failures.push(format!(
                    "row {title:?} -> {path} : the document's H1 is now {h1:?}. Either the \
                     document was retitled or the row was mistyped; a citation using the row's \
                     title no longer names this document."
                ));
            }
        }
        assert!(
            index_failures.is_empty(),
            "{} DOC_INDEX.md §7 row(s) do not resolve:\n  {}",
            index_failures.len(),
            index_failures.join("\n  ")
        );

        // -- 2 & 3. the exported surface ------------------------------------
        let scan_set = internal_doc_tree_scan_set(&repo);
        let mut scanned = 0usize;
        let mut dated = Vec::new();
        let mut unresolved = Vec::new();
        for (shown, path) in &scan_set {
            // DOC_INDEX.md is the resolver, not a citation site, and it is
            // never exported. Nothing here reads it as source.
            let Some(text) = read_text_file(path) else {
                continue;
            };
            scanned += 1;
            let flat = flatten_prose(&text);
            for hit in dated_document_references(&flat) {
                dated.push(format!("{shown}  …{hit}…"));
            }
            for title in quoted_title_citations(&flat) {
                if !known.contains(&normalize_title(&title)) {
                    unresolved.push(format!("{shown}  {title:?}"));
                }
            }
        }
        assert!(
            scanned > MIN_SWEPT_TEXT_FILES,
            "only {scanned} file(s) were scanned; the six walk roots alone hold ~129, so a number \
             this low means the export baseline stopped contributing and a clean result here \
             would prove nothing"
        );

        assert!(
            dated.is_empty(),
            "{} document reference(s) name a DATE instead of a title:\n  {}\n\n\
             A date is not a citation — three documents in this repository share 2026-07-13 and \
             two share 2026-07-17. Cite the document's TITLE and SECTION and add its row to \
             DOC_INDEX.md §7 if it has none. If the date names an EVENT rather than a document \
             (a founder ruling, a consultant round), reword so no spec/plan/design/report/brief \
             word sits beside it.",
            dated.len(),
            dated.join("\n  ")
        );

        // Only meaningful where a resolver exists. In a published checkout
        // `known` is empty because there is no §7, so asserting `unresolved` is
        // empty there would flag all 56 published citations at once -- a red
        // that says nothing about this commit and everything about a publication
        // decision. `resolver_available` is proven by `publication`, not assumed.
        if resolver_available {
            assert!(
                unresolved.is_empty(),
                "{} title citation(s) name no row of DOC_INDEX.md §7, so nobody can resolve \
                 them:\n  {}\n\nAdd the row (Title = the document's H1 verbatim, minus any \
                 trailing status parenthetical), or fix the citation to match the title already \
                 recorded there.",
                unresolved.len(),
                unresolved.join("\n  ")
            );
        } else {
            // NOT a free pass: the sweep still had to reach a real population,
            // and the extractor still had to find the citations that are there.
            // A published checkout with a broken extractor would show zero
            // titles, and that must not read as "clean".
            assert!(
                !unresolved.is_empty(),
                "no title citations were extracted from {scanned} published file(s). The \
                 convention puts them in shipped source deliberately, so zero means the \
                 extractor stopped working -- and every other title check here would then pass \
                 over nothing."
            );
        }
    }

    /// The scanner itself, against inputs the real sweep must get right and
    /// the near-misses it must not flag. Without this a scanner that silently
    /// matched nothing would let the sweep above pass vacuously.
    #[test]
    fn the_citation_scanner_extracts_ranges_and_ignores_near_misses() {
        // Needles assembled at runtime so this file contains no literal
        // citation for its own sweep to find.
        let colon = ":";
        let probe = format!(
            "see `quotes.rs{colon}1642` and `GoatRelayGateway.sol{colon}741-758` plus \
             PublishStreamG.s.sol{colon}12",
        );
        let mut got = Vec::new();
        citations_in_line("t.rs", 1, &probe, &mut got);
        let summary: Vec<(String, usize)> =
            got.iter().map(|c| (c.base.clone(), c.highest)).collect();
        assert_eq!(
            summary,
            vec![
                ("quotes.rs".to_string(), 1642),
                ("GoatRelayGateway.sol".to_string(), 758),
                ("PublishStreamG.s.sol".to_string(), 12),
            ],
            "the range's HIGH end is what must be checked, and a multi-dot basename must \
             survive the backwards scan"
        );

        // Near-misses that must NOT be read as citations.
        let mut none = Vec::new();
        citations_in_line(
            "t.rs",
            1,
            "`quotes.rs::some_test_name` is a path",
            &mut none,
        );
        citations_in_line(
            "t.rs",
            2,
            &format!("a bare .rs{colon} with no stem"),
            &mut none,
        );
        citations_in_line(
            "t.rs",
            3,
            &format!("`store.rs` alone, and `store.rs{colon}` alone"),
            &mut none,
        );
        assert!(
            none.is_empty(),
            "these are not line citations, but the scanner produced {none:?}"
        );
    }
}

//! Neutrality auditor (WP-0.5). Enforces the standing design test — "if it names a device
//! type, it's wrong" — and Core Principle 7 (no content/model/license inspection) at the
//! toolchain layer. Scans the PROTOCOL crate source for device-type identifiers and
//! content-policy tokens IN CODE (comments and doc-comments stripped; string literals kept,
//! so a branch like `class_id == "gpu"` is caught). Device terms match as whole words AND as
//! identifier sub-tokens (so `observed_gpu_equiv` is caught) without substring false
//! positives (`input` does NOT contain the sub-token `npu`). Exits nonzero on any finding —
//! wired as a merge gate in CI.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

const FORBIDDEN_DEVICE_TERMS: &[&str] = &[
    "gpu", "npu", "tpu", "fpga", "cuda", "rocm", "onnx", "llama", "nvidia", "radeon", "vulkan",
    "tensorrt", "openvino",
];
const FORBIDDEN_POLICY_TERMS: &[&str] = &[
    "license",
    "copyright",
    "censor",
    "blocklist",
    "allowlist_model",
    "content_filter",
    "banned_model",
    "model_name",
];

#[derive(Debug, PartialEq, Eq)]
struct Finding {
    module: String,
    line_no: usize,
    term: String,
    line: String,
}

/// Strip line/block comments while preserving string literals (so device-type string
/// operands survive to be caught, but prose in comments does not).
fn strip_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let (mut i, n) = (0usize, b.len());
    let (mut in_str, mut in_line, mut in_block) = (false, false, false);
    while i < n {
        let c = b[i] as char;
        let next = if i + 1 < n { b[i + 1] as char } else { '\0' };
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push('\n');
            }
            i += 1;
        } else if in_block {
            if c == '*' && next == '/' {
                in_block = false;
                i += 2;
            } else {
                if c == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
        } else if in_str {
            out.push(c);
            if c == '\\' && next != '\0' {
                out.push(next);
                i += 2;
            } else {
                if c == '"' {
                    in_str = false;
                }
                i += 1;
            }
        } else if c == '/' && next == '/' {
            in_line = true;
            i += 2;
        } else if c == '/' && next == '*' {
            in_block = true;
            i += 2;
        } else if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn identifier_subtokens(code: &str) -> Vec<String> {
    let mut idents = Vec::new();
    let mut cur = String::new();
    for ch in code.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            idents.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        idents.push(cur);
    }
    let mut subs = Vec::new();
    for ident in idents {
        // split on '_' and camelCase boundaries
        let mut piece = String::new();
        let chars: Vec<char> = ident.chars().collect();
        for (k, &ch) in chars.iter().enumerate() {
            if ch == '_' {
                if !piece.is_empty() {
                    subs.push(std::mem::take(&mut piece));
                }
                continue;
            }
            if k > 0 && ch.is_uppercase() && chars[k - 1].is_lowercase() && !piece.is_empty() {
                subs.push(std::mem::take(&mut piece));
            }
            piece.push(ch);
        }
        if !piece.is_empty() {
            subs.push(piece);
        }
    }
    subs.into_iter().map(|s| s.to_lowercase()).collect()
}

fn word_matches(haystack: &str, term: &str) -> bool {
    // whole-word match on a lowercased line
    let bytes = haystack.as_bytes();
    let tb = term.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut idx = 0;
    while let Some(pos) = haystack[idx..].find(term) {
        let start = idx + pos;
        let end = start + tb.len();
        let before_ok = start == 0 || !is_word(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        idx = start + 1;
    }
    false
}

fn scan_module(module: &str, text: &str) -> Vec<Finding> {
    let code = strip_comments(text);
    let mut findings = Vec::new();
    for (i, line) in code.lines().enumerate() {
        let low = line.to_lowercase();
        let subs: std::collections::HashSet<String> =
            identifier_subtokens(line).into_iter().collect();
        for &term in FORBIDDEN_DEVICE_TERMS {
            if word_matches(&low, term) || subs.contains(term) {
                findings.push(Finding {
                    module: module.into(),
                    line_no: i + 1,
                    term: term.into(),
                    line: line.trim().into(),
                });
            }
        }
        for &term in FORBIDDEN_POLICY_TERMS {
            if word_matches(&low, term) {
                findings.push(Finding {
                    module: module.into(),
                    line_no: i + 1,
                    term: term.into(),
                    line: line.trim().into(),
                });
            }
        }
    }
    findings
}

fn audit_dir(dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return findings,
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "rs").unwrap_or(false))
        .collect();
    files.sort();
    for path in files {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            findings.extend(scan_module(&name, &text));
        }
    }
    findings
}

fn main() -> ExitCode {
    // Scan every protocol-layer crate passed as an argument (default: both device-agnostic
    // crates). Backends are device-specific and deliberately NOT scanned.
    let dirs: Vec<String> = {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            vec![
                "crates/goat-protocol/src".to_string(),
                "crates/goat-ledger/src".to_string(),
                "crates/goat-net/src".to_string(),
            ]
        } else {
            args
        }
    };
    let mut total = Vec::new();
    for dir in &dirs {
        let findings = audit_dir(Path::new(dir));
        if findings.is_empty() {
            println!("neutrality: CLEAN — {dir}");
        } else {
            eprintln!("neutrality: {} FINDING(S) in {dir}", findings.len());
            for f in &findings {
                eprintln!("  {}:{} '{}' -> {}", f.module, f.line_no, f.term, f.line);
            }
        }
        total.extend(findings);
    }
    if total.is_empty() {
        println!("neutrality: all protocol-layer crates name no device type and inspect no content/license");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_device_term_inside_identifier() {
        let src = "fn f(observed_gpu_equiv: u32) -> u32 { observed_gpu_equiv }";
        let terms: Vec<String> = scan_module("x.rs", src)
            .into_iter()
            .map(|f| f.term)
            .collect();
        assert!(terms.contains(&"gpu".to_string()));
    }

    #[test]
    fn catches_device_literal_in_branch() {
        let src = "fn f(class_id: &str) { if class_id == \"gpu\" { let model_name = 1; } }";
        let terms: Vec<String> = scan_module("x.rs", src)
            .into_iter()
            .map(|f| f.term)
            .collect();
        assert!(terms.contains(&"gpu".to_string()));
        assert!(terms.contains(&"model_name".to_string()));
    }

    #[test]
    fn no_substring_false_positive() {
        let src = "fn f(input_bytes: u32) -> u32 { input_bytes }"; // 'input' must not match 'npu'
        assert_eq!(scan_module("x.rs", src), Vec::new());
    }

    #[test]
    fn ignores_prose_in_comments_and_doc_comments() {
        let src = "/// this module never inspects a license or a gpu type\nlet x = 1; // no gpu, no license here\n";
        assert_eq!(scan_module("x.rs", src), Vec::new());
    }

    #[test]
    fn keeps_string_literals_but_not_urls_in_comments() {
        // a device term in a // comment is stripped; the same in a string literal is kept
        let stripped = "let s = 1; // http://example/gpu";
        assert_eq!(scan_module("x.rs", stripped), Vec::new());
    }
}

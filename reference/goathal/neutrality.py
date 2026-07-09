"""
Neutrality auditor (PROTOCOL layer) — the source-scan half of Spec D8.

Enforces the standing invariant "if it names a device type, it's wrong" and Core
Principle 7 (no content/model/license inspection) at the toolchain layer, mechanically:
PROTOCOL modules must contain no device-type identifier and no content-policy token
IN CODE. It scans code only — comments and docstrings are stripped first, because
documentation that *explains* neutrality is legitimate; the ban is on logic that
branches on device type or inspects content. DEVICE modules (backends/*) are exempt —
they are the thing being abstracted, below the trait. This module itself is exempt: it
is the enforcement definition and must necessarily name the forbidden terms.
"""
import io
import os
import re
import tokenize
from dataclasses import dataclass
from typing import List

FORBIDDEN_DEVICE_TERMS = [
    "gpu", "npu", "tpu", "fpga", "cuda", "rocm", "onnx", "llama", "nvidia",
    "radeon", "vulkan", "metal", "tensorrt", "openvino",
]
FORBIDDEN_POLICY_TERMS = [
    "license", "copyright", "censor", "blocklist", "allowlist_model",
    "content_filter", "banned_model", "model_name",
]

# The auditor definition file (this module) is intentionally excluded — it must name
# the forbidden terms to detect them. Everything else in the protocol layer is scanned.
PROTOCOL_MODULES = ["types.py", "commit.py", "backend.py", "conformance.py",
                    "pqsign.py", "capability.py", "attestation_chain.py", "maturity.py",
                    "verification.py"]


def _identifier_subtokens(code: str):
    """Split identifiers on '_' and camelCase so a device term embedded in a name
    (e.g. 'observed_gpu_equiv' -> gpu) is caught, without substring false positives
    (e.g. 'input' does NOT contain the sub-token 'npu')."""
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", code):
        for sub in re.split(r"_|(?<=[a-z0-9])(?=[A-Z])", ident):
            if sub:
                yield sub.lower()


@dataclass
class NeutralityFinding:
    module: str
    line_no: int
    term: str
    line: str


def _code_only(text: str):
    """Yield (line_no, code_text) with comments and docstrings removed, so only
    executable code (identifiers + inline string literals used in logic) is scanned."""
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except tokenize.TokenError:
        # fall back to raw text on unparseable source (still better to over-report)
        for i, line in enumerate(text.splitlines(), 1):
            yield i, line
        return
    kept = {}
    for tok in toks:
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING:
            s = tok.string.lstrip("rbfRBF")
            if s.startswith(('"""', "'''")):   # docstring / prose block -> not logic
                continue
            # keep short inline literals: a device-type operand like == 'gpu' survives
        line_no = tok.start[0]
        kept.setdefault(line_no, []).append(tok.string)
    for line_no in sorted(kept):
        yield line_no, " ".join(kept[line_no])


def _scan(module: str, text: str, terms: List[str], split_identifiers: bool) -> List[NeutralityFinding]:
    findings = []
    for line_no, code in _code_only(text):
        low = code.lower()
        subs = set(_identifier_subtokens(code)) if split_identifiers else set()
        for term in terms:
            hit = re.search(r"\b" + re.escape(term) + r"\b", low) or (term in subs)
            if hit:
                findings.append(NeutralityFinding(module, line_no, term, code.strip()))
    return findings


def audit_protocol_layer(pkg_dir: str) -> List[NeutralityFinding]:
    """Scan protocol modules for forbidden device-type / content-policy tokens in code.
    Device terms are matched both as whole words and as identifier sub-tokens (so
    'observed_gpu_equiv' is caught); policy terms (which are multi-part, e.g.
    'model_name') are matched as whole tokens. Returns [] when the layer is neutral."""
    findings: List[NeutralityFinding] = []
    for mod in PROTOCOL_MODULES:
        path = os.path.join(pkg_dir, mod)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        findings += _scan(mod, text, FORBIDDEN_DEVICE_TERMS, split_identifiers=True)
        findings += _scan(mod, text, FORBIDDEN_POLICY_TERMS, split_identifiers=False)
    return findings

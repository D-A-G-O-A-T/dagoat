"""
Deterministic reference "compute" shared by the two reference backends.

This stands in for a real inference engine (llama.cpp / ONNX Runtime). The point of
the reference implementation is to exercise the PROTOCOL machinery (canonical
commitment, determinism profiles, cross-class comparison, conformance), not to
re-derive an inference stack. A real backend swaps these two functions for engine
calls behind the identical GoatBackend trait.

Key property for cross-class verification (Spec C):
  * tokens are IDENTICAL across backends (pinned greedy decode) -> token_agreement = 1.0
  * the numeric vector is computed from an identical base; a backend may add a small
    BOUNDED perturbation to model cross-vendor FP roundoff. l_inf(A,B) stays within the
    widened tolerance band.
Payload is treated as OPAQUE bytes: only hashed, never parsed for content.
"""
import hashlib

FP_SCALE = 1_000_000            # fixed-point vector range


def reference_tokens(payload: bytes, seed: int, n: int = 16):
    h = hashlib.sha3_256(b"tok" + payload + seed.to_bytes(8, "big")).digest()
    toks, ctr = [], 0
    while len(toks) < n:
        h = hashlib.sha3_256(h + ctr.to_bytes(4, "big")).digest()
        for i in range(0, len(h), 2):
            toks.append(int.from_bytes(h[i:i + 2], "big") % 32000)
            if len(toks) >= n:
                break
        ctr += 1
    return tuple(toks)


def reference_vector_base(payload: bytes, seed: int, n: int = 8):
    h = hashlib.sha3_256(b"vec" + payload + seed.to_bytes(8, "big")).digest()
    return tuple(int.from_bytes(h[i * 4:(i + 1) * 4], "big") % FP_SCALE for i in range(n))


def bounded_perturbation(base, magnitude: int):
    """Deterministic per-index delta in [-magnitude, +magnitude]; models FP roundoff."""
    if magnitude == 0:
        return tuple(base)
    out = []
    for i, v in enumerate(base):
        d = ((i * 7 + 3) % (2 * magnitude + 1)) - magnitude
        out.append(v + d)
    return tuple(out)

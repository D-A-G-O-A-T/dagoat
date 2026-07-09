"""
Canonical commitment (PROTOCOL layer — device-agnostic).

Spec A/D4: commit() MUST produce byte-identical output for byte-identical
(result, build) across all nodes, independent of which backend produced it.
The commitment is over TASK semantics (task_class_id, tokens, vector, build) and
carries NO device identity — this is the neutrality property cross-class
verification relies on.
"""
import hashlib
from .types import TaskResult, OutputCommitment


def _u32(n: int) -> bytes:
    return int(n).to_bytes(4, "big", signed=False)


def _i64(n: int) -> bytes:
    return int(n).to_bytes(8, "big", signed=True)


def canonical_serialize(result: TaskResult) -> bytes:
    """Deterministic, field-ordered, length-prefixed TLV. No dict iteration,
    no floats, no locale — same object always yields the same bytes."""
    out = bytearray()
    out += b"GRES\x01"                                  # magic + version
    out += _u32(result.task_class_id)
    bid = result.engine_build_id.encode("utf-8")
    out += _u32(len(bid)) + bid
    out += _u32(len(result.tokens))
    for t in result.tokens:
        out += _u32(t)
    out += _u32(len(result.vector))
    for v in result.vector:
        out += _i64(v)
    return bytes(out)


def commit(result: TaskResult) -> OutputCommitment:
    return OutputCommitment(digest=hashlib.sha3_256(canonical_serialize(result)).digest())

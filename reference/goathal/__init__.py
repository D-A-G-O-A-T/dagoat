"""
GoatHAL reference implementation (GoatCoin / GOAT, Phase 3 item 1).

Layer discipline (enforced by goathal.neutrality):
  * PROTOCOL layer  (types, commit, backend trait, conformance, neutrality):
    device-agnostic. May NOT name a device type or inspect model/content/license.
  * DEVICE layer    (backends/*): device-specific by nature; lives *below* the trait.

Python stands in for the target Rust crate; module/type names map 1:1.
"""
__all__ = ["types", "commit", "backend", "conformance", "neutrality"]

# D.A. G.O.A.T. (GoatCoin / GPUCoin)

**D.A. G.O.A.T.** — *Decentralized Architecture, Global Orchestration & Aligned Technology*

Aligning the world’s idle compute toward **real, useful public-good work**.  
**Token (design):** GoatCoin (GOAT) · **Alias:** GPUCoin

> **Runtime reality (read first).** What runs today is an *experimental post-quantum verification mesh*
> with **real but pre-1.0, not-yet-audited** PQ crypto and **Phase-0**-only execution isolation —
> and **no** live token, rewards, or marketplace.  
> Exact matrix: [`RUNTIME_VS_SPEC.md`](RUNTIME_VS_SPEC.md) · Spine: [`ARCHITECTURE_CONVERGENCE.md`](ARCHITECTURE_CONVERGENCE.md).  
> Do not present vision language as shipped product.

---

## Quick start

1. **`RUNTIME_VS_SPEC.md`** — honesty matrix  
2. **`DEPLOY.md`** / **`ALPHA_PILOT.md`** — run the mesh

```bash
cargo test
cargo build --release --bin goatd
# docker compose up --build   # local multi-node lab
```

---

## Design pack (v2.1-aligned)

| Doc | Topic |
|-----|--------|
| `01_Vision_Golden_Goal.md` | Commons vision / Golden Goal |
| `02_Core_Principles.md` | Invariants (No-Ponzi, PoVW, honesty, PQ) |
| `03_Architecture_Guidelines.md` | Target layers vs deploy spine |
| `04_Anti_Monopolization_Strategy.md` | Anti-farm design intent |
| `06_Project_Structure.md` | Actual repo map |
| `07_Tokenomics_Framework.md` | Funded Public Good / No-Ponzi |
| `08_Roadmap.md` | Mesh → pilot → economy → research |

---

## Repository layout (short)

| Path | Role |
|------|------|
| `src/` + `goatd` | Deploy spine |
| `goatcoin-rs/` | Mechanism / verification workspace |
| `reference/` | Python reference |
| `RUNTIME_VS_SPEC.md` | Shipped vs designed |

---

## Invariants (soul)

1. **No-Ponzi** — monetary reward ≤ real external inflow  
2. **Proof-of-Valued-Work** — correct *and* wanted (m-of-n usefulness)  
3. **Device-agnostic / anti-monopolization**  
4. **Post-quantum only**  
5. **Radical honesty** — claims ≤ code  
6. **Humane engagement** — no exploitation / no player→player cash gambling  

Detail: `02_Core_Principles.md`.

---

## Licence

Dual-licensed, at your option, under either:

- **MIT** - [`LICENSE-MIT`](LICENSE-MIT)
- **Apache License 2.0** - [`LICENSE-APACHE`](LICENSE-APACHE)

SPDX identifier: `MIT OR Apache-2.0`, which is what every crate manifest in this
repository declares.

Copyright (c) 2026 D.A. G.O.A.T. / DaGoat Engine / DaGoat Network / GoatCoin contributors.

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this work is dual-licensed as above, with no additional terms.

Third-party code vendored under `contracts/lib/` keeps its own licence; those
files are not covered by the two licences above.

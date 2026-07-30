# GoatCoin (GOAT) — F5 Empirical Endpoint Density Study Design

### *Field Measurement & Statistical Calibration Blueprint — Track A2 (Phase 1, cross-cutting)*

> **Version 1.0 (draft, 2026-07-06), aligned to `GoatCoin_Yellowpaper.md` v1.0 (sealed) and
> `GoatCoin_Threat_Model.md` v1.3.** This document is the formal design of the **F5 empirical
> study**: the externally-measured quantity on which the quantitative anti-capture guarantee rests
> (Yellowpaper §37) — *the real-world statistical shape of genuine residential endpoints, and the
> real-world cost of imitating that shape at scale.* It specifies (1) the telemetry payloads the
> field probes emit, (2) the sampling and deployment methodology, and (3) the statistical pipeline
> that reduces raw telemetry to the pure-integer `[calibration]` constants the Yellowpaper defers
> to F5. It is a *study design*, not a specification amendment: its outputs enter the Yellowpaper
> later, as numbered amendments under the §4 discipline.
>
> **Defensive purpose statement.** This study is defensive calibration of a decentralized compute
> network's anti-Sybil and anti-capture mechanisms (Yellowpaper Part III/VI), conducted to protect
> honest household contributors before public exposure. Per the project language convention
> (`goatcoin-rs/CONTENT_FILTER_GUIDELINES.md`), this document describes **nodes and observable
> conditions, never actors and intents**; the study's adversarial-condition arm is a controlled
> testbed operated by the study team, and every adversarial condition studied is paired with the
> mechanism whose threshold it calibrates.
>
> **Numeric convention.** All normative outputs are pure-integer per Yellowpaper Appendix A:
> `Ppm` (`u64`, `PPM = 1_000_000` = unity), `Bp` (`u32`, `BP_FULL = 10_000` = 100%), fixed-width
> little-endian integers, floor division, `u128` intermediates. Exploratory analysis (§18) is
> unconstrained; the **normative derivation pipeline** (§19–§26) is integer-exact and reproducible.
>
> Cross-references (`§`) are to `GoatCoin_Yellowpaper.md` v1.0 unless prefixed `TM` (Threat Model
> v1.3) or `RM` (Post-MVP Roadmap). Status tags carry over: **[shipped]**, **[design]**,
> **[calibration]**.

---

## 0. Scope — the question F5 answers, and the constants it owns

### 0.1 The single question

Every physical anti-Sybil defense in Part III reduces to one empirical claim: **a genuine
residential last mile has a measurable statistical signature — in sustained throughput, in
availability dynamics, and in compute co-residency — that a co-located cohort can imitate only at
a cost exceeding the reward imitation would capture.** The mechanisms (F4 degradation, F6
cohort-merge, the R-C13 conjunction, the R-C17 contention probe) are **[shipped]** or **[design]**
and provably correct at *any* in-band parameter value (§37 discipline); what is missing is the
*measured location of "normal."* F5 supplies it:

1. the empirical distribution of **residential endpoint density** — probe-observed sustained
   throughput per endpoint, in reference-device-equivalents (§14);
2. the empirical **null distributions** of the co-location evidence dimensions across genuinely
   independent households — aggregate-throughput dependence, uptime co-transition, cross-identity
   contention correlation — so merge thresholds sit above honest noise;
3. the empirical **transient-noise process** of real last miles (ISP outages, BGP events,
   congestion) that sizes the temporal smoothing window;
4. the measured **cost curve of imitation**: what a co-located cohort must spend (hardware count,
   bandwidth shaping, uptime staggering) to hold its fingerprint under each candidate threshold —
   the quantity the R-VER1 per-site cost assumption and the Iteration-3 economics import.

### 0.2 Calibration rows owned by this study

From the consolidated **[calibration]** index (§37), this study owns exactly the **"F5 proper"**
rows plus the endpoint-density-coupled rows:

| §37 row | Strawman | Owning section | F5 deliverable that sets it |
|---|---|---|---|
| F4 density curve / F6 merge thresholds | `max(0.10, 0.85·(5/d)^1.5)`; ~1–5 plausible devices | §14 | §22, §23 |
| Topological-fingerprint smoothing window | 72 h | §14 | §24 |
| CGNAT per-last-mile throughput ceiling / availability-correlation threshold (R-C13) | — / — | §14 | §21, §22 |
| `contention_timing` probe: working-set sizes / schedule / cross-identity correlation threshold (R-C17, D-6) | — | §14, §8 | §10, §25 |
| R-VER1 per-site cost-curve input (Iteration-3 economics) | ≥ 11 disjoint sites, ~$770/mo | §26 | §26 (cost curve) |

**Out of scope (F5-adjacent, separate workstreams):** the macro/economic rows (`κ_thin`, emission
schedules, regional amortization bands, R-C3 emergency-band data, `VOL_WINDOW_MIN_RETURNS`
backtests) and the testnet-operations rows (`DA_TIMEOUT_EPOCHS`, isolation-mode tuning). They are
listed in §37 as *F5-adjacent* precisely because they need macro/operations data, not endpoint
field measurement. This document does not design them.

### 0.3 Design constraints inherited from the specification

Four constraints are constitutional, not stylistic; every design choice below is checked against
them:

- **C-A (Device-agnosticism, §3.5).** The telemetry payload emits **opaque measured scalars,
  never device types**. No field, identifier, or enumerant names a device class, vendor, or
  product; the study instrument's schema must pass the `goat-neutrality` token discipline
  (whole-word *and* sub-token). Ground-truth cohort labels exist only in a physically separate
  enrollment frame (§11) and never appear in a measurement payload.
- **C-B (No PII).** No raw IP addresses, no precise geolocation, no names/addresses/emails in the
  measurement plane, no inspection of participant traffic — every network quantity is measured on
  **probe-generated traffic only**. Privacy engineering is per-field (§8–§11).
- **C-C (Pure-integer, recomputable outputs, Appendix A / §3.8).** Every normative constant this
  study emits is a `Ppm`/`Bp`/fixed-width-integer value derived by a published, deterministic,
  integer-exact pipeline from a content-addressed dataset — so the *calibration itself* is
  recomputable by any third party, extending the fraud-provable discipline from the mechanisms to
  their parameters (§26.3).
- **C-D (Accessibility, S1).** The field probe is the same bounded, not-always-on instrument the
  protocol will ship (D-6): short scheduled runs, negligible floor cost on low-end hardware, no
  heavyweight continuous profiling. The study explicitly measures the probe's own resource cost on
  the weakest enrolled hardware and reports it against the S1 budget.

### 0.4 Instrument–protocol parity

The field probe client is built **from the `goatcoin-rs` probe code paths themselves** — the
density/throughput probe validated in MVP-3 and the D-6 `contention_timing` conformance observable
(§8) — compiled into a study client with a study-scoped telemetry uploader. This is deliberate:
the distributions we measure must be distributions of *the instrument that ships*, or the
calibration does not transfer. Any divergence between study client and protocol probe is a
protocol change and goes through the §4 amendment discipline first.

---

# Part A — Deliverable 1: The Telemetry Payload Specification

## 1. Payload architecture overview

The probe emits four frame types, all canonically serialized per TM §11 (fixed field order,
length-prefixed variable fields, fixed-width little-endian integers, byte-aligned) and ML-DSA-65
signed under a dedicated study context:

| Frame | Cadence | Measures | Calibrates |
|---|---|---|---|
| **NDF** — Network Density Frame (§8) | per tick (5 min), batched per epoch | probe-generated throughput ceiling, RTT vector, origin-stability counters | F4 curve, F6 merge trigger, R-C13 ceiling |
| **PAF** — Presence/Availability Frame (§9) | per epoch | heartbeat presence bitmap, transition edges | uptime co-transition null, smoothing window |
| **CCF** — Compute Contention Frame (§10) | per scheduled probe run (≈ 2×/day) | R-C17 contention-timing digests + cross-identity pairing data | R-C17 correlation threshold, probe schedule |
| **GTF** — Ground-Truth Frame (§11) | once at enrollment (+ amendments) | cohort stratum, site attributes, verification evidence refs | stratified reweighting only — **never joined in the measurement plane** |

**Signing context.** All frames sign under a new study-scoped domain context following the TM
Part V registry scheme:

```
CTX_GOAT_F5_TELEMETRY = len_u8 ‖ "GOAT/v1/f5tel" ‖ 0x01
```

Keys are **enrollment-issued study keys**, not protocol identity keys — participants need no
protocol identity, and no study signature is valid in any protocol context (pairwise separation
per A-CI1b). The context enters the TM §10 registry via a §4 amendment before deployment.
Transport is the shipped PQ channel (§17: ML-KEM-768 + AES-256-GCM), so the study exercises — and
incidentally field-tests — the same wire path the protocol uses.

**Common header (all frames):**

| Field | Type | Notes |
|---|---|---|
| `schema_version` | `u16` | frame-schema version; bump = new schema, no in-place reinterpretation |
| `frame_type` | `u8` | NDF=1, PAF=2, CCF=3, GTF=4 |
| `endpoint_pseudonym` | `[u8; 32]` | HMAC-SHA3-256 of the enrollment record under the per-study pseudonymization key (§12); the only cross-frame join key |
| `identity_index` | `u16` | ordinal of this enrolled device *within* the endpoint (multi-device households enroll each device; §14.3) |
| `epoch` | `u64` | study epoch (1 h), from the coordinator clock |
| `run_nonce` | `[u8; 32]` | SHA3-256(`study_beacon_epoch_value` ‖ `endpoint_pseudonym` ‖ `epoch`) — binds the frame to the coordinator's published daily commit-reveal nonce chain, preventing precomputation and replay (mirrors §19 discipline at study scale) |

## 2. Amendment log — the F5 design record

> Amendments follow the Yellowpaper §4 discipline: numbered entries against owning sections,
> inline patch markers at every touched site, and this log as the index. **The deployment schema
> is v2** — F5-A1/F5-A2 landed before milestone M1, so schema v1 was never fielded and no v1
> frame exists to migrate.

### F5-A1 — Micro-burst evaporation in the tick-averaged ceiling *(Core Protocol Security Review, hazard 1)*

- **Hazard.** §8/§20.1 (v1) measured throughput as per-tick (5-min) rates folded through a
  12-tick sustained min. A co-located cohort under condition M1 (§14.3) can shape its probe
  traffic through a token bucket that admits **5–10 s full-rate pulses** and chokes to near-zero
  between pulses: the tick-mean flattens the pulse into a low-rate bin, the sustained estimator
  reads residential, and the cohort's fat physical pipe **evaporates below the tick floor**.
- **Consequence if unpatched.** The M1 arm falsely passes the density guard; the honest
  residential ceiling distribution absorbs shaped-industrial samples; the F4 curve and F6 merge
  trigger are calibrated **loose**, weakening the quantitative anti-capture guarantee at its
  foundation.
- **Resolution — measure at burst-commensurate resolution; the pulse reveals the pipe.**
  1. **On-device 1-s byte counters** during every probe transfer (the traffic is already
     probe-generated; the counter is local and never leaves the device raw). Per tick, the
     device computes the **micro-burst peak**: the maximum over sliding `S_MICRO = 5`-second
     windows of transferred bytes, emitted as `peak_micro_bin` (same eighth-octave quantization —
     no new precision leaves the device).
  2. **Burst-shape digests:** `crest_eighth_oct = peak_micro_bin − dl_bin` (saturating; a
     scale-free integer crest factor — each unit ≈ ×1.0905) and `duty_ppm` (fraction of active
     transfer seconds at ≥ half the per-second peak, `s_half·PPM / max(1, s_active)`). A steady
     residential line shows low crest / high duty; a pulse-shaped cohort shows the token-bucket
     signature: high crest, low duty. Population-statistical use only — never a per-node gate
     (§15 posture).
  3. **Estimator split (§20.1):** the ceiling family now separates `CEIL_sust` (12-tick
     sustained, unchanged semantics) from **`CEIL_peak`** (order statistic over per-epoch maxima
     of `peak_micro_bin`) — the burst-revealed physical capacity. Density (§20.2) and the R-C13
     dependence statistic (§21.2) key on the **peak frame**: a 5-s pulse through a warehouse pipe
     is measured at its pulse rate, not its average. Evading the peak estimator requires shaping
     that holds at **1-s granularity, continuously** — i.e., genuinely capping each identity's
     bandwidth at residential rates at all timescales, which is exactly the M1 cost the study
     exists to price (the evasion *is* the mitigation).
  4. **Integrity:** reflectors log per-second serve rates for every transfer (§13.3 extended),
     so a fabricated low `peak_micro_bin` is a divergent submission caught by independent
     recomputation.
  5. **Transport realism guard:** micro-burst windows are evaluated only *inside* established,
     congestion-warmed transfers (never the first `S_MICRO` seconds of a connection), so slow
     transport ramp-up on high-BDP paths cannot under-read the peak.
  6. **Instrument–protocol parity flag (§0.4):** the shipped density probe (§14 Yellowpaper)
     must adopt the same peak-window semantics, or production F4/F6 would re-open the tick-floor
     blind spot this amendment closes in the study. Filed as a Yellowpaper §14 amendment
     candidate accompanying the F5 constants.
- **Sections amended:** §8.1, §8.2, §8.3, §13.3, §14.3 (M1 condition), §20.1, §20.2, §21.2,
  §26.2. New emitted parameter: `S_MICRO_SECONDS` (validated, not assumed — the sweep in §22.4's
  sensitivity family includes `S_MICRO ∈ {3, 5, 10}` s).

### F5-A2 — Morphology-dependent traffic shaping: the DPI throttle bias *(Core Protocol Security Review, hazard 2)*

- **Hazard.** §8.1 (v1) measured ceilings with bulk transfers of raw random bytes. In exactly
  the strata where precision matters most (S1/S2 emerging-market and dense-urban CGNAT), many
  ISPs deploy DPI-based traffic management that aggressively throttles **unidentifiable
  high-volume high-entropy flows** (classifying them with P2P/bulk traffic). The probe would
  measure the ISP's *policy ceiling for one traffic morphology*, not the household's physical
  link.
- **Consequence if unpatched.** Systematic, stratum-asymmetric underestimation of honest S1/S2
  ceilings; the stratified reweighting (§20.3) then propagates the bias into the pooled p99; and
  — worse — the bias is *invisible*, because a single-morphology instrument cannot distinguish
  "slow link" from "shaped flow."
- **Resolution — a morphology suite: measure the shaping, don't guess at it.**
  1. **Three wire morphologies, identical inner payload** (probe-generated random bytes), rotated
     per tick on the `run_nonce`-derived schedule (re-derivable, unpredictable to the path):
     - `MORPH_R` — the v1 raw high-entropy stream (retained as the shaping-sensitive control);
     - `MORPH_T` — genuine TLS 1.3 on 443 to study reflectors (standard ALPN and record sizes —
       the commonly-whitelisted envelope; **no third-party impersonation**: SNI names study
       domains only);
     - `MORPH_P` — the **protocol morphology**: goat-net PQ transport framing (ML-KEM-768
       handshake + AES-256-GCM length-prefixed frames, §17 Yellowpaper) on the protocol port —
       the traffic production F4/F6 will actually ride (§0.4 parity).
  2. **Frame discipline (which morphology calibrates what).** Production density probes observe
     *protocol traffic*, so the **normative F6/F4 derivation frame is the operative frame**:
     `CEIL_oper(e)` = the `MORPH_P` peak ceiling (post-F5-A1 semantics). The physical-truth frame
     `CEIL_phys(e) = max over morphologies` lower-bounds true link capacity; the per-endpoint
     **shaping bias** is `shape_delta_ppm = (bps(CEIL_phys) − bps(CEIL_oper))·PPM /
     max(1, bps(CEIL_phys))`. Thresholds are derived where production will measure; the bias is
     *quantified and published*, never silently absorbed.
  3. **Throttle-onset detection (shared instrumentation with F5-A1).** From the same 1-s
     counters, an integer changepoint statistic (prefix-sum split maximizing the between-segment
     rate contrast) emits `throttle_onset_s` + `pre_bin`/`post_bin` per transfer — the
     token-bucket / mid-flow-classification signature that distinguishes *shaped* from *slow*.
     When onset fires, sustained estimators use the post-onset steady segment; peak estimators
     keep the pre-onset burst (that burst is physics).
  4. **Stratum shaping table as a first-class output (§26.2):** `SHAPE_TRANSFER_TABLE` —
     per-stratum quantiles of `shape_delta_ppm` by morphology. If S1/S2 medians are material,
     that is an **accessibility finding about the protocol itself** (its traffic is throttled for
     the populations §1 most wants): escalated per `ACCESSIBILITY.md` and routed to the
     transport-layer roadmap decisions (RM H4/I3) — explicitly *not* resolved by a study-side
     workaround, and explicitly *not* a recommendation to disguise protocol traffic (a
     transport-morphology decision is a protocol design fork with its own review).
  5. **Reflector-identity control.** Reflector addresses rotate within each regional anchor pool
     so destination-based classification of the reflectors themselves (allow-listing or
     de-prioritizing known measurement endpoints) is detectable as a rotation-correlated rate
     shift rather than silently biasing one anchor.
  6. **Budget:** the §12.6 data cap is split across the suite (each morphology ≥ ⅓ of ticks);
     per-morphology CIs widen ~√3, absorbed by the §17.4 sample-size margins.
- **Privacy/neutrality check (constraints C-A/C-B unchanged):** all morphologies carry
  probe-generated bytes to study reflectors; no user traffic is touched; new fields are bins,
  counts, and `Ppm` scalars of the probe's own transfers; no field names a device, vendor, ISP
  product, or DPI vendor — `morphology_id` enumerates *study wire envelopes*, a property of the
  instrument, not the device.
- **Sections amended:** §8.1, §8.2, §8.3, §13.3, §20.1, §20.2, §22 (derivation frame note),
  §26.2.

## 3–7. *(reserved for future amendments)*

## 8. NDF — the Network Density Frame

Calibrates: F4 density curve, F6 merge trigger, the R-C13 per-last-mile throughput ceiling, and
the aggregate-throughput-dependence dimension of the merge conjunction (§14).

### 8.1 Measurement principle — active, probe-generated, coarse, morphology-rotated *(amended F5-A2)*, burst-resolved *(amended F5-A1)*

The endpoint's throughput ceiling is measured by **timed bulk transfers of probe-generated
bytes** against study-operated reflectors, on a randomized schedule inside participant-consented
windows. Nothing about the participant's own traffic is observed, sampled, or counted — the study
never passively meters the line (constraint C-B). Multi-device endpoints run **coordinated
concurrent transfers** on schedule so the *aggregate* ceiling (the R-C13 quantity: does combined
throughput saturate at one last-mile bound, or scale with device count?) is directly observed, not
inferred.

<!-- F5-A2: single-morphology random streams measure DPI policy, not link capacity, in shaped
     strata (S1/S2). Rotate three wire envelopes carrying the same probe payload. -->
Each transfer is dressed in one of **three wire morphologies** rotated per tick on the
`run_nonce`-derived schedule (§2, F5-A2): `MORPH_R` (raw high-entropy stream — the
shaping-sensitive control), `MORPH_T` (genuine TLS 1.3 on 443 to study domains — the
commonly-whitelisted envelope), and `MORPH_P` (goat-net PQ transport framing — the **operative**
morphology production F4/F6 will observe). The spread between morphologies is the endpoint's
measured shaping bias (`shape_delta_ppm`); the normative calibration frame is `MORPH_P` (§20.1).

<!-- F5-A1: tick-mean averaging evaporates sub-tick pulses; the pulse reveals the pipe. -->
Within every transfer, **1-s on-device byte counters** resolve sub-tick structure (§2, F5-A1):
the per-tick micro-burst peak (`peak_micro_bin`, max over sliding `S_MICRO = 5`-s windows,
evaluated only inside congestion-warmed segments), the crest/duty burst-shape digests, and the
integer changepoint `throttle_onset_s` that separates *shaped* flows from *slow* links. Raw 1-s
counters never leave the device; only eighth-octave bins and `Ppm` digests are uploaded.

### 8.2 Schema

| Field | Type | Semantics | Privacy treatment |
|---|---|---|---|
| `tick_index` | `u16` | 5-min tick within the epoch batch | — |
| `dl_bin` | `u8` | downlink sustained-rate bin: **eighth-octave quantization** — bin `k` covers `[2^(k/8), 2^((k+1)/8))` bps; 256 bins span 1 bps–4.3 Gbps | rate is quantized at source (≈ 9.05% multiplicative resolution); the exact rate never leaves the device |
| `ul_bin` | `u8` | uplink, same quantization | same |
| `concurrent_flag` | `u8` | 1 if this tick's transfer ran in the coordinated-concurrent schedule (aggregate measurement), else 0 | — |
| `agg_dl_bin` / `agg_ul_bin` | `u8` × 2 | endpoint-aggregate bins for coordinated ticks (0 = not applicable) | computed on-device from local coordination; per-device rates of *other* devices are not uploaded |
| `rtt_q` | `[u16; 8]` | RTT in ms (capped 65 535) to the 8 fixed regional anchor reflectors | multilateration is bounded to **region-level** resolution by anchor placement (≥ ~200 km anchor spacing); no finer geography is computable from the vector, matching the §13 grid-territory granularity the protocol itself uses |
| `origin_change_count` | `u8` | count of observed routing-origin changes (exit-identifier churn as seen by the reflector, salted-hashed on-device) this epoch | raw ASN/IP never uploaded; only the *count* of changes — the transient-noise signal for §24 |
| `shared_origin_degree_bin` | `u8` | log2 bin of the number of *distinct study endpoints* observed behind the same salted origin hash this epoch (reflector-computed, fed back) | CGNAT-density signal; the origin hash is salted per-study and destroyed at study end (§12) |
| `xfer_bytes_bin` | `u8` | eighth-octave bin of bytes moved this tick | caps participant data-budget accounting; also a data-budget fairness control |
| `morphology_id` *(F5-A2)* | `u8` | wire envelope of this tick's transfer: 1 = `MORPH_R`, 2 = `MORPH_T`, 3 = `MORPH_P` | a property of the study instrument, not the device or the participant |
| `peak_micro_bin` *(F5-A1)* | `u8` | micro-burst peak: max over sliding `S_MICRO = 5`-s windows of 1-s probe byte counters, eighth-octave binned | computed on-device; raw 1-s counters never uploaded |
| `crest_eighth_oct` *(F5-A1)* | `u8` | `peak_micro_bin − dl_bin`, saturating — scale-free integer crest factor | bin-difference only; carries no new precision |
| `duty_ppm` *(F5-A1)* | `u32` | `s_half·PPM / max(1, s_active)` — fraction of active transfer seconds at ≥ half the per-second peak | probe's own transfer seconds only |
| `throttle_onset_s` *(F5-A2)* | `u8` | integer-changepoint onset second of a mid-flow rate discontinuity (255 = none detected) | derived from the probe's own counters |
| `pre_bin` / `post_bin` *(F5-A2)* | `u8` × 2 | eighth-octave rates before/after a detected onset (0 = n/a) | same quantization as all rates |

### 8.3 Derived on-device, uploaded in preference to raw series *(amended F5-A1/A2)*

To minimize both payload volume and inference surface, the device also uploads per-epoch integer
reductions (the same reductions the normative pipeline uses, §20), now computed **per
morphology**: the epoch's **sustained ceiling** `sust_dl_bin` / `sust_ul_bin` (max over the epoch
of the minimum bin across `S_SUSTAIN = 12` consecutive ticks — one continuous hour; ticks with a
detected `throttle_onset_s` contribute their `post_bin` steady segment), the epoch's **peak
ceiling** `peak_epoch_bin` (max of `peak_micro_bin` over the epoch — pre-onset bursts included:
the burst is physics), and the epoch bin histogram (`[u16; 256]`, sparse-encoded). Raw tick and
1-s series are retained on-device for 14 days for audit sampling (§13.4) then deleted.

## 9. PAF — the Presence/Availability Frame

Calibrates: the uptime co-transition null distribution (R-C13 conjunction dimension 2) and the
smoothing window (§24).

| Field | Type | Semantics | Privacy treatment |
|---|---|---|---|
| `presence_bitmap` | `u64` | 1 bit per 5-min tick (12 bits/h; one epoch uses 12 bits, batched 5 epochs/frame) — heartbeat received / not | presence only; no usage, no activity semantics, no process or screen state — a bit that says "the probe daemon was reachable" |
| `rise_edges` / `fall_edges` | `u8` × 2 | count of off→on / on→off transitions in the batch | — |
| `edge_ticks` | `len_u32 ‖ [u16]` | tick indices of edges (for the coincidence-window matching in §21) | tick resolution (5 min) is the floor; no finer timing is collected |
| `local_hour` | `u8` | local hour-of-day 0–23 at batch start | hour-of-day only — needed for diurnal modeling; timezone is *not* uploaded (recoverable only to ±coarse-region already known from `rtt_q`) |

Presence is measured by the probe daemon's own heartbeat — a household that turns a laptop off,
sleeps it, or loses power produces exactly the availability signal the protocol will see (A-5:
availability churn is normal, never adversarial). No wake-locks: the probe must never alter the
sleep behavior it is measuring (bias control, §16.2).

## 10. CCF — the Compute Contention Frame (the R-C17 probe)

Calibrates: the `contention_timing` probe parameters and cross-identity correlation threshold
(R-C17 / amendment D-6, §14) — the compute-side co-location dimension that a network throttle
cannot reach.

### 10.1 Measurement principle — self-timing under self-generated load, relational use only

The probe is the standardized bounded micro-benchmark of amendment D-6: it walks pointer-chased
buffers across a **fixed geometric working-set ladder**, inducing controlled contention in the
memory hierarchy, and records the distribution of its **own** access latencies. Three disciplines
are constitutional:

- **Self-timing only.** The probe times only its own memory accesses under its own load. It reads
  no other process's data, probes no addresses outside its own allocations, and extracts no
  co-tenant information beyond *timing interference with itself*. (The co-residency signal is that
  two identities' *self*-measurements are mutually coupled when run concurrently — §14, R-C17.)
- **Device-agnostic ladder.** The working-set ladder is a fixed geometric schedule — 18 steps,
  4 KiB × 2^k for k = 0…17 (4 KiB → 512 MiB) — chosen to *span* commodity memory hierarchies
  without naming or fitting any. The ladder is identified by `ws_ladder_id` referencing a published
  table; no field names a hierarchy level, and the schema passes the neutrality token discipline
  (identifiers: `working_set`, `contention`, `latency_hist` — no device or hierarchy-level tokens).
- **Relational use only (§14).** Absolute latency figures never gate anything; the calibrated
  quantity is **cross-identity correlation**. A slow low-end machine and a fast one are measured
  identically; only *coupling between identities* is evidence.

### 10.2 Run scheduling — the concurrency lattice

Co-residency is visible only under **concurrent** runs, so the coordinator schedules probe runs in
a **paired lattice**: for each scheduled slot, a pseudo-random subset of identities (drawn from the
`run_nonce` chain, hence re-derivable) runs the ladder simultaneously; each identity also runs
solo-baseline slots. Within an endpoint, all enrolled identities are paired against each other
(intra-endpoint pairs — the honest multi-device baseline); across endpoints, identities are paired
only in aggregate statistics (inter-endpoint pairs — the independence null). In the co-location
reference arm (§15.3) the lattice pairs identities known to share physical hardware — the positive
class. Runs are **bounded**: ≤ 90 s per ladder pass, ≤ 2 passes/day, always inside consented
windows and never on battery power below a charge floor (S1 discipline, C-D).

### 10.3 Schema

| Field | Type | Semantics |
|---|---|---|
| `ws_ladder_id` | `u16` | published ladder table reference |
| `slot_id` | `u64` | concurrency-lattice slot (from the coordinator schedule; re-derivable from `run_nonce`) |
| `pairing_class` | `u8` | 0 = solo baseline, 1 = intra-endpoint concurrent, 2 = lattice concurrent, 3 = reference-arm concurrent |
| `latency_hist` | `[u32; 32]` per ladder step (`18 × 32` counts, length-prefixed) | fixed-edge geometric histogram of access latencies in ns: bin `j` covers `[2^(j/2), 2^((j+1)/2))` ns (half-octave, 1 ns–64 µs) |
| `dispersion_ppm` | `u64` per ladder step | the opaque contention scalar: the **integer Simpson dispersion** of the step's histogram — `dispersion_ppm = PPM − Σ(c_j² · PPM) / n²` with `u128` intermediates, where `c_j` are bin counts and `n = Σc_j`. A collision-based (Rényi-2) dispersion digest: exact-integer, log-free (the R-C2 no-logarithm discipline applied to entropy), total and panic-free on all inputs (`max(1, n²)` guard per Appendix A contract 3) |
| `self_lag1_ppm` | `u64` | within-run lag-1 autocorrelation of the latency series (via the §35.1 `correlation_ppm` idiom, offset to `[0, 2·PPM]`) — a run-stability/quality control |
| `thermal_throttle_flag` | `u8` | 1 if the run detected monotonic latency drift beyond a published bound (run excluded from nulls; kept for robustness analysis) |
| `probe_cost_ms` / `probe_cost_bytes` | `u32` × 2 | the probe's own wall-clock and memory cost — the S1 budget evidence (C-D) |

**What is deliberately absent:** clock frequencies, core counts, cache sizes, topology strings,
model identifiers, OS identifiers, instruction-set flags. The frame contains timing histograms and
`Ppm` scalars — nothing a classifier could name a device with beyond what timing itself implies,
and nothing the *protocol* ever sees as a type (§3.5).

### 10.4 What the study must decide (and how)

The R-C17 **[calibration]** parameters this frame feeds (§25): which ladder steps carry
co-residency signal vs. noise (step selection), the concurrent-run schedule density needed for a
stable correlation estimate, and the **cross-identity correlation threshold** in `Ppm` with its
operating characteristic measured against ground truth (reference arm = positive class,
inter-endpoint pairs = null).

## 11. GTF — the Ground-Truth Frame (enrollment plane, never joined in the measurement plane)

Stratified reweighting (§20.3) and label-supervised threshold validation need cohort ground truth.
It is collected **once, at enrollment, into a physically separate store** (separate keys, separate
operator role, clean-room join only — §12), because C-A forbids labels in the measurement plane:

| Field | Type | Notes |
|---|---|---|
| `stratum_code` | `u8` | one of the §14.1 strata |
| `access_evidence_class` | `u8` | how residential status was verified (§15.2): 0 = self-report only, 1 = subscription-document verified, 2 = site-visited subsample |
| `dwelling_class` | `u8` | coarse: standalone / multi-unit / shared-housing (the R-C13 false-positive frontier) |
| `subscription_tier_bin` | `u8` | advertised access rate, eighth-octave bin (from the participant's plan, self-reported) |
| `enrolled_identity_count` | `u8` | devices enrolled at this endpoint |
| `region_code` | `u16` | balancing-authority-scale region (§13 granularity) |
| `consent_manifest_hash` | `[u8; 32]` | content-address of the signed consent record |

No names, no street addresses, no account numbers, no device makes/models — even in the enrollment
plane. Verification evidence (e.g., a subscription bill) is sighted by the enrollment operator,
attested by `access_evidence_class`, and **not retained**.

## 12. Privacy engineering — cross-cutting mechanics

1. **Pseudonymization at source.** `endpoint_pseudonym` is an HMAC under a per-study key held in
   an HSM by the data custodian; the key is **destroyed at study close**, permanently severing
   frames from enrollment identities. Re-identification after close is cryptographically dead, not
   policy-dead.
2. **Quantization at source.** Rates, byte counts, and latencies are binned on-device
   (eighth-octave / half-octave). The exact values never exist off-device.
3. **Plane separation.** Measurement frames and the GTF live in separate stores under separate
   operator roles; joins happen only inside the analysis clean room (audited access, no export of
   row-level joined data). Published statistics are stratum-level with a **k-anonymity floor of
   k ≥ 50 endpoints per published cell**; sub-threshold cells are merged upward.
4. **No passive metering, ever.** Every byte measured is a byte the probe generated (§8.1); every
   latency is the probe timing itself (§10.1). Participant traffic, DNS, applications, and content
   are structurally invisible to the instrument — the study client contains no capture path, which
   is auditable in its (published) source.
5. **Publication noise, derivation exactness.** Publicly released aggregate tables carry
   calibrated integer dithering for disclosure control; the **normative constants** are derived in
   the clean room from undithered pseudonymous data and are safe to publish exactly because each is
   a single coarse population constant (a `Ppm` threshold reveals nothing about any endpoint).
6. **Data budget and retention.** Probe transfer volume is capped and disclosed at consent
   (default ≤ 15 GB/month, configurable down; metered lines get a low-volume schedule with wider
   CIs, honestly flagged in the stratum metadata). Raw frames retain for the study term + 24
   months for recomputation (§26.3), then reduce to the published digests.

## 13. Integrity of the telemetry itself

The study inherits the project's zero-trust posture toward its own instrument:

1. **Signed frames, replay-bound.** Every frame is ML-DSA-65-signed under
   `CTX_GOAT_F5_TELEMETRY` and bound to the coordinator nonce chain (`run_nonce`) — a frame cannot
   be forged, replayed across epochs, or attributed to another endpoint (TM A-CI2 discipline).
2. **A divergent-submission model for participants.** Field participants are honest-majority but
   not trusted: a node in an adversarial condition (altered client, fabricated frames) is bounded
   by (a) signature binding to one enrolled pseudonym, (b) reflector-side cross-checks — the
   reflector independently measures every transfer it serves, so an NDF that disagrees with the
   reflector's own log is a **divergent submission**, flagged and excluded, and (c) lattice
   cross-checks on CCF (a fabricated concurrent run shows no coupling with its scheduled partner's
   genuine run). Divergence rates are themselves a study output (instrument-noise floor).
3. **Reflector-side ground truth.** Study reflectors log (salted-origin, quantized-rate, tick,
   morphology, per-second serve-rate series) for every probe transfer they serve *(extended
   F5-A1/A2)* — an independent recomputation surface for the NDF plane including `peak_micro_bin`
   and `throttle_onset_s`, in the spirit of §3.8: two independent records of the same measurement
   must agree, or the frame is excluded. A fabricated low peak is a divergent submission.
4. **On-device audit window.** 14-day on-device raw retention (§8.3) supports a random 1%
   audit-resample: the coordinator requests re-upload of raw tick series for randomly selected
   epoch/endpoint pairs and recomputes the on-device reductions (§20) bit-identically.

---

# Part B — Deliverable 2: The Field Deployment Methodology

## 14. Population frame and cohort structure

### 14.1 Residential strata (the measurement population)

The population of interest is *global residential last miles plausibly hosting idle compute*.
Six strata, chosen to span the axes that move the §14 signals (access technology, address-sharing
regime, and the R-C13 false-positive frontier):

| Stratum | Code | Definition | Why it is load-bearing |
|---|---|---|---|
| S1 — Emerging-market cellular | `0x01` | 4G/5G-only households behind carrier CGNAT, mobile-first regions | the R-C13 catastrophe class: durable shared origin, must never false-merge; also the §1 accessibility priority population |
| S2 — Dense-urban CGNAT fixed line | `0x02` | fixed-line ISPs with CGNAT/shared-gateway deployment (high-rises, dense metros) | second R-C13 class; high genuine endpoint density behind one origin |
| S3 — Urban non-CGNAT fiber | `0x03` | publicly-routable fiber-to-the-premises | upper tail of honest residential throughput — dominates the p99 ceiling (§22) |
| S4 — Suburban cable/DSL | `0x04` | mainstream cable/DSL, publicly routable | the modal residential endpoint; anchors the distribution body |
| S5 — Rural / satellite (incl. LEO) | `0x05` | long-loop DSL, WISP, LEO satellite | high-latency, high-churn tail; stresses the smoothing window and availability nulls |
| S6 — Shared-housing residential | `0x06` | dormitories, co-living, multi-family behind one *residential* subscription | the hardest honest case: many genuinely independent people behind one true last mile — the boundary the merge predicate must respect (they *are* one endpoint physically, yet must not be misread as one *operator*) |

Target geographic spread: ≥ 12 countries across ≥ 5 regions (weighting per §20.3 toward global
broadband-population shares from ITU/regulator statistics), with S1/S2 deliberately
**oversampled** relative to naive population shares — the accessibility-critical strata get the
tightest estimates, per §1.

### 14.2 Control cohorts (the co-location reference population)

| Cohort | Code | Definition | Ground truth provided |
|---|---|---|---|
| C1 — Cloud VMs, scattered | `0x11` | VMs across ≥ 3 providers, ≥ 6 regions, default placement | industrial *network* fingerprints (throughput, uptime, origin) |
| C2 — Cloud VMs, co-resident by construction | `0x12` | multiple VMs pinned to **dedicated hosts** (single-tenant placement we control) | **guaranteed physical co-residency** — the R-C17 positive class with zero label noise |
| C3 — Bare-metal colocation | `0x13` | rented bare-metal in colo facilities | single-tenant silicon in industrial network conditions (separates the network axis from the compute axis) |
| C4 — On-premises server room | `0x14` | study-operated small server room on business-class fiber | the "company-town" shape (§24 P_r adjacency): distributed-looking but single-infrastructure |

### 14.3 The co-location reference arm (controlled adversarial-condition testbed)

A study-team-operated testbed measures the **cost of imitation** directly — the F5 headline
quantity. On C2/C3/C4 infrastructure, the team operates cohorts of `N ∈ {4, 8, 16, 40}` identities
per physical site under progressively stronger residential-mimicry conditions, each condition a
named, scripted configuration (never an uninstrumented free-play exercise):

| Condition | What is configured | Which threshold it stresses |
|---|---|---|
| M0 — unshaped | co-located identities, no mitigation | baseline separability (should replicate MVP-3's 40/40 merge) |
| M1 — bandwidth shaping | per-identity egress shaped under candidate residential ceilings; *(F5-A1)* shaping must hold at **1-s granularity** against the micro-burst instrumentation — a token bucket admitting 5–10 s full-rate pulses is measured at its pulse rate, not its average | F6 throughput-dependence dimension: does shaping to pass cost proportional throughput? (it must — that is the design claim) |
| M2 — uptime staggering | scripted de-correlated power/sleep schedules per identity | uptime co-transition dimension: measure the residual correlation floor and the operational cost of maintaining stagger |
| M3 — M1+M2 combined | full network-fingerprint suppression | the R-C17 motivating condition (V9, TM §3.2): network axis fully suppressed — the contention probe must carry the detection alone |
| M4 — M3 + one-identity-per-machine | identities thinned until each has sole tenancy | the cost endpoint: by construction undetectable (it *is* genuine distribution) — establishes the cost ceiling `C_site` where imitation becomes real distribution (§14's breakeven-at-best claim, priced) |

Every condition logs its **fully-loaded cost** (hardware, hosting, power, bandwidth,
operator-time) so §26 can express detection thresholds as *adversary cost curves*, not just
error rates. Multi-device honest households (§14.1) are the honest mirror of M-conditions: the
study deliberately recruits households enrolling 2–6 genuine devices, giving the honest
multi-identity-per-endpoint baseline that the "~1–5 plausible devices" strawman guesses at.

## 15. Recruitment and ground-truth verification

### 15.1 Recruitment channels

Stratified quota recruitment through channels with different selection biases, deliberately mixed
so no single channel's bias dominates (§16.1): established consumer measurement panels
(probe-hosting communities in the RIPE-Atlas mold), regional ISP partnerships (opt-in invitations
to subscriber samples in CGNAT-heavy markets — the only reliable S1/S2 source), distributed-
computing volunteer communities (high multi-device density, flagged as a biased-toward-enthusiast
channel and down-weighted accordingly), and general-population panel vendors for the S4 body.

### 15.2 Verifying "residential"

Cohort labels are study ground truth, so label noise directly widens every threshold CI. Layered
verification, recorded as `access_evidence_class` (§11):

1. **Structural checks (all participants):** enrollment origin consistency with residential
   allocation blocks (RIR data), RTT-vector plausibility against the claimed region, subscription-
   tier bin vs. measured ceiling sanity.
2. **Document verification (target ≥ 70%):** sighted (not retained) evidence of a consumer-class
   subscription at enrollment.
3. **Site-verified subsample (target ≥ 5%, ≥ 150 endpoints):** in-person or video enrollment
   verification, concentrated in S1/S2/S6 where labels are hardest — this subsample anchors a
   **label-noise model** used to de-attenuate the stratum estimates (§20.4).

Labels are calibration-frame data only (C-A): the protocol never consumes them, so label
verification is a *study* quality problem, not a protocol gatekeeping mechanism — no tension with
permissionless entry (§3.6).

### 15.3 Reference-arm governance

The §14.3 testbed runs on infrastructure the study team owns or rents with provider consent;
conditions M0–M4 are configuration scripts version-controlled with the study; no probe run
touches hardware or identities outside the enrolled testbed. (Lead-with-defense: the arm exists to
*price the imitation out*, and its outputs are cost curves and thresholds, not techniques — the
publishable artifact is §26's cost function, under the same publication discipline as Q1
iteration reports.)

## 16. Bias and validity threats — named, with mitigations

### 16.1 Selection bias

Volunteer probe-hosts skew technical, better-connected, multi-device — inflating the honest
density and throughput tails exactly where the merge threshold sits. Mitigations: multi-channel
recruitment with per-channel bias flags (§15.1); post-stratification to external broadband
statistics (§20.3); sensitivity analysis re-deriving every threshold with each channel excluded
(a threshold that moves materially under channel exclusion is flagged **unstable** and takes the
conservative bound, §22.4).

### 16.2 Behavioral distortion (Hawthorne / incentive effects)

Participation that changes uptime behavior corrupts the co-transition null. Mitigations:
**flat-rate compensation** — never uptime- or volume-proportional (an uptime-paid panel would
manufacture always-on households and poison the availability baseline); no wake-locks and no
"keep your device on" language anywhere in participant materials; a 14-day burn-in excluded from
all estimates (novelty decay); passive-cohort cross-check — presence patterns of long-standing
probe-hosting-community devices (enrolled years before this study) compared against fresh
recruits for a novelty signature.

### 16.3 Attrition and survivorship

90-day panels lose participants non-randomly (churn correlates with exactly the intermittency we
must measure). Mitigations: enrollment overshoot (+30%); attrition analysis comparing early
frames of completers vs. non-completers; availability estimates computed with
inverse-probability-of-retention weights in the exploratory tier, and reported both weighted and
unweighted.

### 16.4 Seasonality and event coverage

A single 90-day window under-samples seasonal behavior (heating/cooling cycles, school terms,
holidays) and rare transients. Mitigation: the longitudinal panel (§17.2) plus an external
transient-event catalog (§17.3).

## 17. Temporal design — how long, and why

### 17.1 The core window: 90 days + 14-day burn-in

The temporal-smoothing strawman is 72 h (§14). Calibrating a smoothing window demands observing
many independent instances of both the *transients it must absorb* and the *persistent signals it
must not delay*, so the core window must be a large multiple of the candidate windows:

- **90 days = 30× the 72-h strawman** and ≥ 10× the longest candidate window under evaluation
  (up to 7 days), giving ≥ 10 non-overlapping evaluation blocks per endpoint at the longest
  candidate — the minimum for stable per-endpoint false-trigger estimates.
- **≥ 12 full weekly cycles**, sufficient to estimate the weekly periodic component of presence
  and throughput per stratum (day-of-week × hour-of-day cells at ≥ 12 observations each).
- **Transition volume:** households transition presence ~1–6 times/day; 90 days yields ~100–500
  edges per endpoint — enough for pairwise co-transition coefficients (§21) with per-pair
  binomial CIs narrow relative to the honest/co-located separation observed in MVP-3.
- **Tail estimation:** per-endpoint sustained ceilings are estimated per epoch (24/day); 90 days
  gives ~2,160 epoch-ceilings per endpoint, so the *per-endpoint* ceiling estimate (a max-min
  statistic, §20.1) is stable, and population percentiles (§22) are limited by endpoint count,
  not by per-endpoint sampling noise.

### 17.2 The longitudinal panel: 12 months, 10% subsample

A randomly-selected 10% of completing endpoints (stratum-balanced) continues for 12 months.
Purpose: seasonal stability check on every emitted constant (§26.4 requires re-running the
normative pipeline on the panel's four quarters; a constant whose quarterly re-derivations drift
beyond its published CI triggers a scheduled recalibration flag, not an emergency change — the
±5%/quarter posture of §34 applied to calibration governance).

### 17.3 The transient-event catalog

Smoothing-window calibration (§24) needs *labeled* transients. The study ingests public routing
and outage feeds (RouteViews/RIS-class BGP archives, regional outage trackers) for the enrollment
regions across the core window, building a catalog of (region, interval, event-class) rows.
Windows overlapping catalog events are the labeled transient set; the smoothing window is then
chosen so that catalog-event-induced fingerprint distortions produce **zero** merge triggers
(§24.2) — the design intent of §14's temporal smoothing, now empirically sized.

### 17.4 Sample-size targets (with the order-statistic arithmetic that sets them)

| Cohort | Target n (endpoints) | Justification |
|---|---|---|
| Residential pooled | **5,000** (completing) | distribution-free p99: exceedance count ~ Binomial(5000, 0.01), E = 50, σ ≈ 7.04 → the 95% CI on the p99 order statistic spans ranks 4950 ± 14 — a tight bracket (§22.2); demonstrating a composite false-merge rate ≤ 0.1% needs ≥ 3,000 clean endpoint-quarters with zero false merges (rule of three: 3/n upper bound), which 5,000 completers supply with attrition margin |
| Per stratum | **≥ 600**, S1/S2 ≥ 900 | per-stratum p95 with exceedance E = 30 (σ ≈ 5.3) is tight; per-stratum p99 (E = 6–9) is reported with honest wide brackets — pooled-with-reweighting is the normative path (§22), per-stratum tails are diagnostics |
| Multi-device households (across strata) | ≥ 800 with 2–6 enrolled devices | the honest multi-identity baseline: intra-endpoint pair count ≥ 2,400 pairs for the co-transition and contention *intra-endpoint honest* nulls |
| C1–C4 controls | 500 VMs / 60 dedicated-host pairs / 40 bare-metal / 1 server room | C2's 60 guaranteed-co-resident pairs give the R-C17 positive class ≥ 60 × (concurrent runs over 90 d ≈ 180) ≈ 10,800 positive-pair run observations |
| Reference arm | 4 sites × 5 conditions × {4,8,16,40} identities | full factorial on the §14.3 grid; each cell ≥ 30 days dwell |

Enrollment target with +30% attrition overshoot: **≈ 6,500 residential endpoints**.

---

# Part C — Deliverable 3: The Statistical Calibration Framework

## 18. Two-tier discipline: exploratory freedom, normative exactness

The pipeline is split, honoring Appendix A without hobbling the science:

- **Tier E (exploratory).** Model selection, bias analysis, robustness checks, visualization —
  unconstrained tooling, floats permitted, pre-registered hypotheses (§27) but free methods. Tier
  E chooses *functional forms and candidate thresholds*; it never emits a constant.
- **Tier N (normative).** A published, deterministic, **pure-integer** reduction pipeline
  (Appendix A contracts: fixed-width integers, `u128` intermediates, floor division, saturating
  arithmetic, canonical ordering) that maps the content-addressed frame dataset to the final
  constants. Tier N is the *only* source of emitted values, and anyone holding the dataset digest
  recomputes every constant **bit-identically** (§26.3). Where Tier E selects a form (say, a
  penalty-curve shape), Tier N re-derives its parameters by integer grid search with a published
  integer loss — Tier E guides, Tier N decides.

## 19. Notation and units

All Tier-N quantities: rates as eighth-octave bin indices `u8` (converted to bps lower-bounds
`u64` only via the published bin table); densities, correlations, coefficients as `Ppm` (`u64`);
weights as `Bp` (`u32`); time as ticks (`u16`)/epochs (`u64`). Reference-device throughput
`R_ref` (bps, `u64`) is the protocol's published reference-workload figure (§14) — an input to
this study, not an output.

## 20. Stage 1 — per-endpoint integer reductions

### 20.1 The ceiling family *(amended F5-A1/A2)*

Per endpoint `e`, per epoch `t`, per morphology `m`, from coordinated-concurrent NDF ticks:

```
sust_bin(e, t, m) = max over epoch t of ( min over S_SUSTAIN = 12 consecutive ticks of agg_dl_bin )
                    // shaped ticks contribute their post-onset steady segment (§8.3)
peak_bin(e, t, m) = max over epoch t of peak_micro_bin        // burst-revealed capacity (F5-A1)

CEIL_sust(e, m)   = 95th-per-endpoint-percentile of { sust_bin(e, t, m) } over the core window
CEIL_peak(e, m)   = 95th-per-endpoint-percentile of { peak_bin(e, t, m) }
                    (order statistics, floor rank k = (95·T + 99) / 100, T = epoch count)

CEIL_oper(e)      = CEIL_peak(e, MORPH_P)           // the frame production F4/F6 observes — NORMATIVE
CEIL_phys(e)      = max over m of CEIL_peak(e, m)   // physical-truth lower bound
shape_delta_ppm(e)= ( (bps_lower(CEIL_phys) − bps_lower(CEIL_oper)) · PPM )
                    / max(1, bps_lower(CEIL_phys))  // the measured shaping bias (F5-A2)
```

The *per-endpoint* 95th (not max) discards singleton flukes while tracking the true ceiling; the
population tail (§22) is then taken across endpoints. Uplink symmetric. The peak frame is
normative because a sub-tick pulse through a wide pipe must be measured at its pulse rate
(F5-A1); the `MORPH_P` frame is normative because thresholds must live where production will
measure (F5-A2) — `CEIL_phys` and `shape_delta_ppm` de-bias the stratum comparisons and feed the
`SHAPE_TRANSFER_TABLE` accessibility output (§26.2).

### 20.2 Endpoint density *(amended)*

```
d_ppm(e) = ( bps_lower(CEIL_oper(e)) · PPM ) / R_ref        // u128 intermediate, floor division
```

— the §14 quantity: probe-observed throughput capacity per endpoint in reference-device-
equivalents, `Ppm`-scaled, in the operative peak frame. Sensitivity requirement: re-deriving §22
in the `CEIL_phys` frame must not change any honest-panel merge outcome beyond the pre-registered
tolerance, or the affected stratum's thresholds take the conservative bound (§22.4 discipline).

### 20.3 Population weighting

Stratum weights `w_s` (`Bp`, `Σ w_s = BP_FULL` by largest-remainder, Appendix A contract 4) are
fixed **before unblinding** from external broadband-population statistics (ITU/regulator
subscriber counts per access class per region), mapping the enrolled sample to the global
residential population. Weighted histograms accumulate `count(bin) · w_s` in `u128`.

### 20.4 Label de-attenuation

The §15.2 site-verified subsample yields a stratum-level label-confusion estimate (fraction of
claimed-residential endpoints that are mislabeled, with binomial CI). Tier E corrects the stratum
distributions for label noise; Tier N takes the **conservative direction**: thresholds are
derived from the *uncorrected* distribution or the *corrected* one, whichever yields the tighter
(lower) residential ceiling — mislabeling must never loosen a threshold.

## 21. Stage 2 — pairwise co-location statistics (integer forms)

### 21.1 Uptime co-transition coefficient

For identities `a, b` with edge-tick sets `T_a, T_b` (PAF `edge_ticks`) over a window: match edges
greedily one-to-one within a coincidence window `Δ` ticks (candidate parameter, strawman Δ = 2
ticks = 10 min); `m` = matched count. The coefficient uses the project's symmetric idiom (§30.1):

```
cotrans_ppm(a, b) = min( 2·m·PPM / max(1, |T_a| + |T_b|),  PPM )
```

Total, panic-free, symmetric; `PPM` = perfectly co-transitioning, `0` = no coincident edges.
Computed for: intra-endpoint honest pairs (multi-device households — the *honest co-located*
distribution), inter-endpoint pairs within stratum/region (the *independence null*, including
same-CGNAT-origin pairs — the R-C13 case), and reference-arm pairs under M0–M3 (the co-located
cohort distribution and its suppression residuals).

### 21.2 Aggregate-throughput dependence

For a candidate cohort `G` behind one origin: the dependence statistic is the ratio of the
cohort's *joint* sustained ceiling to the sum of its members' *solo* ceilings:

```
dep_ppm(G) = ( bps_lower(CEIL_joint(G)) · PPM ) / max(1, Σ_{e∈G} bps_lower(CEIL_solo(e)) )
             // joint and solo ceilings both in the CEIL_oper peak frame (F5-A1/A2, §20.1):
             // pulse-shaped members contribute their burst-revealed capacity, so a cohort
             // cannot buy independence evidence by staggering micro-bursts through one pipe
```

`dep_ppm ≈ PPM` ⇒ combined throughput scales with the count (independent last miles);
`dep_ppm ≪ PPM` ⇒ the cohort saturates one shared ceiling (one physical pipe). Genuine S1/S2
CGNAT neighborhoods are the critical null: they share *origin* but their `dep_ppm` stays high —
the empirical foundation under R-C13's "insufficient alone" rule, now measured rather than argued.

### 21.3 Cross-identity contention correlation (R-C17)

For a concurrent lattice pair `(a, b)` at ladder step `k`: the coupling statistic is the integer
Pearson correlation (§35.1 `correlation_ppm` idiom — reduce-before-multiply, integer square roots
before the variance product, `u128` throughout) between the paired sequence of per-run
`dispersion_ppm` deltas from each identity's own solo baseline:

```
couple_ppm(a, b, k) = correlation_ppm( Δdisp_a[runs], Δdisp_b[runs] )     // offset-scaled to [0, 2·PPM], PPM = zero correlation
```

Positive-class distribution from C2 (guaranteed co-resident) and reference-arm pairs; null from
inter-endpoint lattice pairs and — critically — intra-endpoint honest pairs (two genuine separate
machines in one household must land in the null, or the probe would merge honest families).

## 22. Stage 3 — the F6 merge trigger (the residential p99 and its guards)

### 22.1 The task

Set the F6/R-C13 **per-last-mile throughput ceiling** and the merge conjunction thresholds so
that (a) honest endpoints essentially never merge, (b) a co-located cohort holding many
identities cannot stay under all thresholds without paying the M-condition cost curve.

### 22.2 The integer percentile

With the weighted density histogram `H` (weights `u128`, total `W`), the residential p99 density:

```
k99   = (99·W + 99) / 100                          // ⌈0.99·W⌉ in floor arithmetic
D_p99 = smallest bin b such that cumweight(b) ≥ k99
```

Distribution-free CI: the bracketing order-statistic ranks from Binomial(`W_eff`, 99/100) at 95%
coverage, where `W_eff` is the *endpoint* count (not weighted mass — weighting shifts location,
endpoints carry the information; both counts are reported). Per §17.4, n = 5,000 brackets the p99
within ±14 ranks. The same machinery yields p95 / p99.9 for the sensitivity family.

### 22.3 From percentile to trigger — the conjunction budget

The merge predicate is a **conjunction** (R-C13): throughput-dependence ∧ uptime co-transition
(∧, as an additional dimension, contention coupling — R-C17). Per-dimension thresholds therefore
sit at their *individual* p99 nulls while the composite honest false-merge rate multiplies down —
the study's acceptance target is the *composite* rate:

- **Per-dimension:** threshold at the honest-null p99 with the CI's conservative edge
  (upper edge for ceilings, i.e. the threshold moves *up* so honest tails clear it).
- **Composite acceptance gate:** zero false merges over ≥ 3,000 clean residential
  endpoint-quarters ⇒ demonstrated composite rate ≤ 0.1% (rule of three), echoing and tightening
  MVP-3's 0/200. S6 (shared housing) and S1/S2 (CGNAT) are scored separately and must
  individually show zero — the accessibility catastrophe class gets its own gate, not an average.
- **De-merge verification:** for every false merge observed at *any* candidate threshold during
  sensitivity sweeps, verify the §14 recomputable de-merge fires from the published probe series
  alone (the escape valve is part of the calibrated system, and its latency — epochs from
  false-merge to de-merge — is a reported operating characteristic).

### 22.4 Adversarial-margin selection

Among threshold candidates satisfying the false-merge gate, Tier N selects the one **maximizing
measured imitation cost** from the reference-arm cost curves (§26): choose the candidate vector
`θ` maximizing `C_site(θ)` (the fully-loaded per-site cost of holding N identities under all
thresholds at condition M3) subject to the composite honest gate. Ties break toward the tighter
threshold. Any threshold flagged **unstable** under §16.1 channel-exclusion takes its
conservative bound instead.

## 23. Stage 4 — the F4 density curve as a monotone integer table

The strawman `q_network = max(0.10, 0.85·(5/d)^1.5)` contains a fractional power no consensus
path may compute (Appendix A contract 1). The shipped form is a **monotone step table**:

```
F4_TABLE: [(d_upper_ppm: u64, q_network_ppm: u64); K]     // K ≤ 32, d ascending, q non-increasing
```

Derivation: Tier E fits the parametric family `(q_max, d_0, γ)` to the policy targets — full
score across the measured honest multi-device body (the ~800-household multi-device baseline
replaces the "~1–5 plausible devices" guess with a measured distribution), degradation beginning
above the honest p95, floor `q_ppm = 100_000` — then Tier N quantizes the fitted curve to K
steps by integer grid search minimizing the worst-case step deviation (integer loss, `u128`
accumulators), with step edges snapped to eighth-octave density bins. The table is exact to
evaluate, trivially fraud-provable, and monotone by construction. Published with it: the honest
attainment check — every enrolled honest household's measured density maps to `q ≥ 850_000 Ppm`
(the full-score claim of §14 verified against the field distribution, not assumed).

## 24. Stage 5 — sizing the temporal smoothing window

### 24.1 The trade

The window must absorb transient distortions (catalog events, §17.3) and still merge a genuine
co-located cohort "within a few days of coming online" (§14). Both sides are now measurable.

### 24.2 The procedure

For candidate windows `w ∈ {24 h, 48 h, 72 h, 96 h, 7 d}` (evaluated on the frame series with
trailing moving-average smoothing per §14):

1. **False-trigger side:** replay every residential endpoint's smoothed fingerprint through the
   §22-calibrated merge predicate across the core window; count merge triggers within catalog
   transient intervals + burn-out margins. Requirement: **zero** transient-induced triggers at
   the composite level (the §22.3 gate re-scored per window).
2. **Detection-latency side:** replay reference-arm cohort onsets (each M-condition site has a
   known switch-on epoch); measure epochs-to-merge. Requirement: median ≤ 2× window length,
   maximum ≤ 4× (the "days, not weeks" intent of §14 made numeric).
3. **Selection:** the smallest `w` meeting both. The strawman 72 h is the prior; the emitted
   constant is `SMOOTHING_WINDOW_EPOCHS: u64` with its full operating-characteristic table.

## 25. Stage 6 — the R-C17 correlation threshold and probe schedule

From the §21.3 distributions: choose ladder-step subset `K*` and threshold
`CONTENTION_COUPLE_THRESHOLD_PPM` maximizing the margin between the positive class (C2 dedicated-
host pairs, reference-arm M3 pairs) and the null's p99.9 (inter-endpoint pairs ∪ intra-endpoint
honest pairs — the family-of-real-machines null is binding, per §10.4). Acceptance gates:

- **Separation:** positive-class detection ≥ 99% at null false-positive ≤ 0.1% on held-out pairs
  (train/holdout split by *site*, never by run, to prevent leakage);
- **Schedule cost:** the concurrent-run density needed for a stable `couple_ppm` estimate (target
  CI half-width ≤ 50_000 Ppm) fixes `PROBE_RUNS_PER_DAY` — reported against the S1 budget with
  the measured `probe_cost_ms`/`probe_cost_bytes` (§10.3); if the schedule that achieves
  separation exceeds the S1 budget on the weakest enrolled hardware, that is an explicit
  accessibility deviation escalated per `ACCESSIBILITY.md`, not silently shipped;
- **Robustness:** thermal-throttle-flagged runs and battery-power runs excluded from nulls but
  replayed as sensitivity — the threshold must hold under their inclusion (low-end devices in
  poor thermal conditions must not drift toward the positive class).

Emitted: `WS_LADDER_TABLE` (final step subset), `PROBE_SCHEDULE`, and the threshold — the three
R-C17 `[calibration]` rows of §37.

## 26. Stage 7 — the imitation cost curve and output manifest

### 26.1 The cost curve

From the reference arm: `C_site(θ*, N)` — fully-loaded monthly cost of sustaining `N` identities
under the selected thresholds `θ*` at the strongest suppression condition still evading merge —
and the **cost endpoint** at M4 (one-identity-per-machine, where evasion becomes genuine
distribution). Deliverables: the cost table per `N ∈ {4, 8, 16, 40}`, the marginal cost per
imitated household, and the resulting update to the R-VER1 economics (§26 Yellowpaper: the
"≥ 11 disjoint sites, ~$770/mo" figure re-derived from measured, not assumed, per-site cost).
This is F5's headline number: the measured price of pretending to be many households.

### 26.2 Emitted constants (the complete list)

| Constant | Type | §37 row closed |
|---|---|---|
| `F4_TABLE[(d_upper_ppm, q_network_ppm)]` | `[(u64, u64)]` | F4 density curve |
| `F6_DENSITY_MERGE_PPM` | `u64` (Ppm) | F6 merge trigger (density dimension) |
| `LASTMILE_CEIL_BIN` | `u8` (eighth-octave) | R-C13 per-last-mile throughput ceiling |
| `AGG_DEP_THRESHOLD_PPM` | `u64` | R-C13 aggregate-throughput-dependence threshold |
| `COTRANS_THRESHOLD_PPM`, `COTRANS_DELTA_TICKS` | `u64`, `u16` | R-C13 availability-correlation threshold |
| `SMOOTHING_WINDOW_EPOCHS` | `u64` | topological-fingerprint smoothing window |
| `WS_LADDER_TABLE`, `PROBE_SCHEDULE`, `CONTENTION_COUPLE_THRESHOLD_PPM` | table, table, `u64` | R-C17 probe parameters |
| `C_SITE(θ*, N)` cost table | `MicroUsd` table | R-VER1 cost-curve input (informative, feeds A1) |
| `S_MICRO_SECONDS` *(F5-A1)* | `u8` | micro-burst window (validated over {3, 5, 10} s in the §22.4 sensitivity family) |
| `SHAPE_TRANSFER_TABLE[(stratum, morphology, shape_delta quantiles)]` *(F5-A2)* | `Ppm` table | informative: the measured DPI-shaping bias per stratum — the accessibility-escalation trigger (§2, F5-A2) and the operative↔physical de-biasing map |

### 26.3 Calibration provenance — recomputable constants

The output artifact is a **calibration manifest**: SHA3-256 content-address of the frozen frame
dataset (pseudonymous, post-close), the Tier-N pipeline source at a pinned revision, the stratum
weight vector (`Bp`), and every emitted constant with its derivation trace. Anyone holding the
dataset recomputes every constant bit-identically — Appendix A's corollary applied to
calibration: disagreement with a published constant is an error proof, not a methods dispute.
Constants enter `GoatCoin_Yellowpaper.md` as a numbered amendment per §4, flipping the owned
**[calibration]** tags; the Q1 simulation and WP-3.5 replay harness are re-run at the final
values as the acceptance regression (small-node target attainment ≥ 1.05 must survive
recalibration — §26 Yellowpaper's surviving-configuration criterion re-checked at measured
parameters).

### 26.4 Recalibration governance

The 12-month panel (§17.2) re-derives all constants quarterly. Drift beyond a constant's
published CI raises a scheduled recalibration flag — handled as an amendment with the same
manifest discipline, never an operational hot-patch. (Parameter recalibration is deliberately
slower and more public than the §35.1 bounded component-mutation machinery — these constants
gate anti-Sybil physics, not basket weights.)

---

## 27. Pre-registration, ethics, and governance

- **Pre-registration.** Hypotheses, strata, sample targets, acceptance gates (§22.3, §24.2,
  §25), and the Tier-E/Tier-N split are pre-registered before unblinding; deviations are logged
  amendments. Threshold selection criteria are fixed *before* the reference-arm cost data is
  seen (the adversarial-margin rule §22.4 is a function, not a judgment call).
- **Consent & lawful basis.** Informed consent covering: probe traffic volumes, presence
  heartbeats, contention self-timing, data retention (§12.6), and the key-destruction guarantee
  (§12.1). GDPR-class lawful basis is consent; data minimization is structural (quantization at
  source, plane separation). Participants can withdraw; withdrawal deletes enrollment linkage
  immediately and frames at the next reduction cycle.
- **Compensation.** Flat-rate per completed month (§16.2), disclosed at enrollment, identical
  within region — never proportional to uptime, volume, or measured capability.
- **Publication.** Stratum-level results at k ≥ 50 (§12.3); the calibration manifest and Tier-N
  pipeline are public; the reference-arm deliverable is the cost curve and thresholds (§15.3).
- **Independent review.** Protocol reviewed by an external ethics board before recruitment; the
  privacy design (§12) is in scope for the A3 external audit's C2 delta-assessment window as an
  adjacent artifact (RM D2 vendor, if scoping permits).

## 28. Risks and open questions

| Risk | Impact | Posture |
|---|---|---|
| S1/S2 recruitment shortfall (ISP partnerships slow) | widest CIs land on the accessibility-critical strata | front-load partnership negotiation (this is the study's long lead-time item, mirroring RM's "external and slow"); fallback: extend S1/S2 enrollment window rather than accept thin strata |
| `R_ref` revision mid-study | density unit changes under the analysis | densities stored as rate bins; `d_ppm` derived at reduction time — an `R_ref` change is a manifest re-run, not a re-collection |
| Reference arm under-approximates a better-resourced co-located cohort | thresholds calibrated against too-weak suppression | M-conditions are scripted ceilings, not claims of optimality; the conjunction design means evasion must clear *every* dimension at once, and §26.1's cost endpoint (M4) is condition-independent — one-identity-per-machine is the structural floor; residual honestly carried to A1's smarter-adversary track |
| Probe cost exceeds S1 budget on weakest hardware | accessibility deviation | measured explicitly (§10.3, §25); escalation path defined — the study *reports* the conflict rather than tuning it away |
| LEO satellite (S5) fingerprint instability (shared uplink cells resemble CGNAT + mobility) | S5 false-positive exposure | S5 scored separately in §22.3; if S5 cannot meet the zero-false-merge gate at thresholds that hold elsewhere, that is a finding for §14 (a possible seventh fingerprint dimension), not a threshold compromise |
| Content-filter interference with adversarial-condition analysis (R-C6/S3) | reference-arm analysis depth | this document and all study artifacts follow `CONTENT_FILTER_GUIDELINES.md`: nodes and observable conditions, defensive purpose stated, measure-don't-instruct |

## 29. Timeline and milestones

| Milestone | Window | Exit criterion |
|---|---|---|
| M0 — Commission | now (Phase-1 start, per RM §3 cross-cutting) | study charter + ethics review submitted; ISP partnership outreach begun |
| M1 — Instrument | M0 + 2 mo | study client built from `goatcoin-rs` probe paths (§0.4); `CTX_GOAT_F5_TELEMETRY` amendment landed; reflector network live; schema frozen at **v2** (F5-A1/F5-A2 applied pre-deployment, §2) |
| M2 — Pilot | 14 d burn-in, ~200 endpoints | end-to-end frame integrity (§13) verified; probe cost measured on weakest pilot hardware |
| M3 — Core window | 90 d, full enrollment | ≥ 5,000 completing residential endpoints; reference-arm factorial complete |
| M4 — Analysis | M3 + 2 mo | Tier-E complete; Tier-N pipeline frozen and run; acceptance gates evaluated |
| M5 — Integration | M4 + 1 mo | calibration manifest published; Yellowpaper amendment drafted; Q1/WP-3.5 regression green at measured constants |
| M6 — Longitudinal close | M3 + 12 mo | four quarterly re-derivations; recalibration governance report |

---

*Maintained alongside `GoatCoin_Yellowpaper.md` v1.0 under the §4 amendment discipline. This
document designs the study; its outputs — the §26.2 constants and the §26.3 manifest — enter the
specification as numbered amendments against §14, §8, and §37. Until then, every value in the
Yellowpaper tagged **[calibration]** on an F5-proper row remains a reasoned strawman, and the
quantitative anti-capture guarantee remains simulation-validated (§26 Yellowpaper), not
field-measured. Closing that gap is this study's entire purpose.*

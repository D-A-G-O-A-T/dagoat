//! Off-chain half of the allowlisted fetch network's settlement lane.
//!
//! This module owns leaf canonicalisation and the Merkle tree that the
//! settlement contract verifies proofs against. It is a SEPARATE tree from the
//! compute lane's: a different leaf shape, a different arity, and its own domain
//! word in the preimage, so a leaf built here can never be replayed against the
//! supply-issuing compute settlement and a compute leaf can never be replayed
//! here.
//!
//! Nothing in this module issues supply and nothing in it destroys supply. It
//! computes hashes and splits an already-funded pool.
//!
//! # What lives here, and what lives in `config.rs`
//!
//! This file holds the lane's **policy bands** — the numbers a configured value
//! is checked against — and nothing that reads the environment. The
//! `ProxyConfig` struct, its `PROXY_*` env keys and its `validate` method
//! live beside `StreamGConfig` in `crate::config`, because they are the same
//! kind of object (a nested struct on `Config`, built during `load_from_map`)
//! and a reader comparing the two lanes' startup policy should find them in one
//! place. The bands live here so that the module that enforces a bound and the
//! module that declares it are the same module.
//!
//! # Reject versus clamp, stated per band
//!
//! Both postures already exist in `config.rs` on purpose, and the difference is
//! not stylistic:
//!
//! * **Reject** — [`MIN_TAKE_BPS`]/[`MAX_TAKE_BPS`],
//!   [`MIN_EPOCH_BYTE_CEILING`]/[`MAX_EPOCH_BYTE_CEILING`],
//!   [`MIN_PRICE_GOAT_WEI_PER_MEBIBYTE`]/[`MAX_PRICE_GOAT_WEI_PER_MEBIBYTE`],
//!   [`MIN_PAIR_CONCENTRATION_BPS`]/[`MAX_PAIR_CONCENTRATION_BPS`] and
//!   [`PROXY_CHAIN_ALLOWLIST`]. Every one of these decides how much value moves
//!   to whom, or which deployment a signature is bound to. Silently rewriting an
//!   operator's number to the nearest legal one there would move value with
//!   every test green, which is exactly the failure the take band exists to
//!   prevent.
//! * **Clamp** — [`MIN_METER_MIN_REQUEST_INTERVAL_MS`] ..=
//!   [`MAX_METER_MIN_REQUEST_INTERVAL_MS`] and [`MIN_RECEIPT_PAGE_SIZE`] ..=
//!   [`MAX_RECEIPT_PAGE_SIZE`]. An absurd request cadence or page size costs
//!   throughput and nothing else; refusing to start over a typo in one would be
//!   worse than running at the nearest sane value with a warning. This mirrors
//!   the Stream G sweep knobs exactly.
//!
//! A **syntactically** unparseable value is a refusal in both groups, same as
//! every other numeric in `config.rs`.

pub mod aggregate;
pub mod challenger;
pub mod fraud;
/// Lane-scoped audits — supply, vocabulary and export-baseline coverage.
///
/// `#[cfg(test)]` and private, like the two crate-root audit modules
/// (`citation_audit` and its publication-consistency sibling): it ships no
/// runtime behaviour, only the four sweeps and their controls, so compiling it
/// into the binary would be dead symbols. It is
/// deliberately absent from `tools/export-baseline.txt` for the same reason,
/// and `every_new_proxy_lane_file_is_in_the_export_baseline` asserts that
/// absence rather than leaving it to habit.
#[cfg(test)]
mod lane_audit;
pub mod meter;
pub mod proxy_merkle;
pub mod receipt;
pub mod routes;
pub mod store;
pub mod verify;

/// Chain ids this lane may be configured for.
///
/// Deploys and integration runs are permitted on Anvil (`31337`) and Base
/// Sepolia (`84532`) only; anything else is a startup refusal. Every EIP-712
/// digest in this lane binds `chainId` and the verifying contract, so a chain id
/// that names no deployment produces signatures no deployment can check.
pub const PROXY_CHAIN_ALLOWLIST: &[u64] = &[31_337, 84_532];

/// Lowest accepted `protocol_take_bps` — 8%.
///
/// The band is the **launch band** from the "The No-Ponzi Invariant — GoatCoin's
/// load-bearing economic rule" spec, §8, and deliberately **not** that section's
/// hard ceiling. An earlier draft of this lane used the hard ceiling as
/// [`MAX_TAKE_BPS`], which turned the outer bound of the entire policy into a
/// routine config value: paired with a contract that derives nothing from this
/// number, one env edit would have moved five percent of gross away from
/// operators with every test still green.
pub const MIN_TAKE_BPS: u32 = 800;

/// Highest accepted `protocol_take_bps` — 10%. See [`MIN_TAKE_BPS`] for why this
/// is the launch band and not the hard ceiling.
///
/// It must also equal the immutable `TAKE_BPS()` compiled into the deployed
/// settlement contract; `the_configured_take_equals_the_deployed_take` reads
/// that value back out of the deployment record and compares.
pub const MAX_TAKE_BPS: u32 = 1_000;

/// Basis-point denominator, matching the contract's `BPS_DENOM`.
pub const BPS_DENOM: u32 = 10_000;

/// One mebibyte. The receipt's price denominator, exact and a power of two.
pub const MIB_BYTES: u64 = 1_048_576;

/// Smallest accepted per-epoch byte ceiling — 1 GiB.
///
/// The bound is the operator-adjustable daily byte range (1–200 GB) restated as
/// a protocol-level per-epoch cap. A ceiling below one gibibyte would refuse
/// every honest operator on the first session.
pub const MIN_EPOCH_BYTE_CEILING: u64 = 1_073_741_824;

/// Largest accepted per-epoch byte ceiling — 200 GiB, the top of the same band.
pub const MAX_EPOCH_BYTE_CEILING: u64 = 214_748_364_800;

/// Smallest accepted price. Zero is refused rather than clamped: a lane that
/// values real bytes moved at nothing is a settlement that pays nothing, and no
/// test of the Merkle tree would ever notice.
pub const MIN_PRICE_GOAT_WEI_PER_MEBIBYTE: u128 = 1;

/// Largest accepted price — 1e18 wei, i.e. one whole GOAT per mebibyte.
///
/// A backstop against a typo adding digits, not a policy figure: combined with
/// [`MAX_EPOCH_BYTE_CEILING`] it already allows 204 800 GOAT to one operator in
/// one epoch, far outside any pool this lane can fund.
pub const MAX_PRICE_GOAT_WEI_PER_MEBIBYTE: u128 = 1_000_000_000_000_000_000;

/// Smallest accepted per-`(consumer, operator)` concentration cap.
///
/// Rejected rather than clamped, with the money knobs: `0` would refuse every
/// pair and silently stop the lane, and a cap is an anti-fraud bound, so
/// rewriting one to a legal-looking neighbour is the same class of error as
/// rewriting the take.
pub const MIN_PAIR_CONCENTRATION_BPS: u32 = 1;

/// Largest accepted concentration cap — [`BPS_DENOM`], i.e. "no cap at all".
/// Accepted so the control can be deliberately opened, refused above so a value
/// that cannot mean anything never reaches the fraud checks.
pub const MAX_PAIR_CONCENTRATION_BPS: u32 = BPS_DENOM;

/// Default minimum spacing between gateway meter requests, in milliseconds.
pub const DEFAULT_METER_MIN_REQUEST_INTERVAL_MS: u64 = 1_000;
/// Tightest accepted meter request spacing. Clamped, not refused.
pub const MIN_METER_MIN_REQUEST_INTERVAL_MS: u64 = 50;
/// Loosest accepted meter request spacing. Clamped, not refused.
pub const MAX_METER_MIN_REQUEST_INTERVAL_MS: u64 = 60_000;

/// Default receipt rows read per page.
pub const DEFAULT_RECEIPT_PAGE_SIZE: u32 = 500;
/// Smallest accepted page size. Clamped, not refused — a `0` page size is an
/// infinite loop of empty pages, which is a throughput failure, not a value one.
pub const MIN_RECEIPT_PAGE_SIZE: u32 = 1;
/// Largest accepted page size. Clamped, not refused.
pub const MAX_RECEIPT_PAGE_SIZE: u32 = 5_000;

#[cfg(test)]
mod tests {
    use super::*;

    /// The bands have to be non-degenerate before any test that exercises them
    /// proves anything: a `min == max` band accepts one value and a `min > max`
    /// band accepts none, and either would make `config.rs`'s boundary arms pass
    /// for the wrong reason.
    ///
    /// Mutations this detects: collapsing [`MIN_TAKE_BPS`] onto
    /// [`MAX_TAKE_BPS`]; setting [`MAX_TAKE_BPS`] to the hard ceiling (1_500),
    /// which is the specific regression the band exists to prevent; inverting
    /// any of the four bands; moving [`MIB_BYTES`] off a power of two.
    #[test]
    fn every_policy_band_is_non_degenerate_and_ordered() {
        // Carried through a runtime table rather than asserted constant by
        // constant, so a failure names the band and the loop is a real
        // comparison instead of something the compiler folds away.
        let bands: [(&str, u128, u128); 6] = [
            (
                "take_bps",
                u128::from(MIN_TAKE_BPS),
                u128::from(MAX_TAKE_BPS),
            ),
            (
                "epoch_byte_ceiling",
                u128::from(MIN_EPOCH_BYTE_CEILING),
                u128::from(MAX_EPOCH_BYTE_CEILING),
            ),
            (
                "price_goat_wei_per_mebibyte",
                MIN_PRICE_GOAT_WEI_PER_MEBIBYTE,
                MAX_PRICE_GOAT_WEI_PER_MEBIBYTE,
            ),
            (
                "pair_concentration_bps",
                u128::from(MIN_PAIR_CONCENTRATION_BPS),
                u128::from(MAX_PAIR_CONCENTRATION_BPS),
            ),
            (
                "meter_min_request_interval_ms",
                u128::from(MIN_METER_MIN_REQUEST_INTERVAL_MS),
                u128::from(MAX_METER_MIN_REQUEST_INTERVAL_MS),
            ),
            (
                "receipt_page_size",
                u128::from(MIN_RECEIPT_PAGE_SIZE),
                u128::from(MAX_RECEIPT_PAGE_SIZE),
            ),
        ];
        for (name, min, max) in bands {
            assert!(
                min < max,
                "the {name} band is degenerate or inverted: {min}..={max}"
            );
        }

        // The launch band, spelled out, so a silent widening to the hard
        // ceiling fails here as well as in `config.rs`.
        assert_eq!((MIN_TAKE_BPS, MAX_TAKE_BPS), (800, 1_000));
        assert_eq!(
            MAX_TAKE_BPS * 100 / BPS_DENOM,
            10,
            "the launch band tops at 10%"
        );
        assert_eq!(MAX_PAIR_CONCENTRATION_BPS, BPS_DENOM);

        // Exact powers of two, not "about a megabyte".
        assert_eq!(MIB_BYTES, 1 << 20);
        assert_eq!(MIN_EPOCH_BYTE_CEILING, 1 << 30);
        assert_eq!(MAX_EPOCH_BYTE_CEILING, 200 * (1u64 << 30));

        // Defaults must sit INSIDE the clamp bands, or the clamp silently
        // rewrites an unset knob.
        let clamped: [(&str, u64, u64, u64); 2] = [
            (
                "meter_min_request_interval_ms",
                MIN_METER_MIN_REQUEST_INTERVAL_MS,
                DEFAULT_METER_MIN_REQUEST_INTERVAL_MS,
                MAX_METER_MIN_REQUEST_INTERVAL_MS,
            ),
            (
                "receipt_page_size",
                u64::from(MIN_RECEIPT_PAGE_SIZE),
                u64::from(DEFAULT_RECEIPT_PAGE_SIZE),
                u64::from(MAX_RECEIPT_PAGE_SIZE),
            ),
        ];
        for (name, min, default, max) in clamped {
            assert!(
                (min..=max).contains(&default),
                "the {name} default {default} sits outside its own clamp band {min}..={max}, so \
                 an unset knob would be silently rewritten"
            );
        }
    }

    /// The chain allowlist is exactly the two permitted deployments, with a
    /// negative control so an allowlist that accepted everything could not pass.
    ///
    /// Mutations this detects: adding a third chain id; replacing the list with
    /// an empty slice (which would make every membership test below fail rather
    /// than pass vacuously); swapping Base Sepolia's id for Base mainnet's.
    #[test]
    fn the_chain_allowlist_is_exactly_anvil_and_base_sepolia() {
        assert_eq!(PROXY_CHAIN_ALLOWLIST, &[31_337, 84_532]);
        assert!(PROXY_CHAIN_ALLOWLIST.contains(&31_337));
        assert!(PROXY_CHAIN_ALLOWLIST.contains(&84_532));
        // Negative controls: mainnet Ethereum, Base mainnet, and the
        // "unset chain id" value the crate's own signer already refuses.
        for refused in [1u64, 8_453, 0, 84_531] {
            assert!(
                !PROXY_CHAIN_ALLOWLIST.contains(&refused),
                "{refused} must not be in the allowlist"
            );
        }
    }
}

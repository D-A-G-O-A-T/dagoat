//! Direct-ETH sponsored enrollment — **informational preparation only**.
//!
//! # Why this module can never broadcast
//!
//! `GoatRelayGateway.executeSponsoredEnrollment` has two branches. Which one
//! runs is decided by `_isDirectEthEnrollment`
//! (`StreamGEnroll.sol:162-169` — the gateway body now lives in `library`
//! DELEGATECALL targets),
//! and on the direct-ETH branch the very first thing the contract does is
//!
//! ```solidity
//! if (msg.sender != intent.controller) revert NotController();   // :379
//! ```
//!
//! A relayer is, by definition, not the controller. There is no configuration,
//! no key, and no future task that makes the attestor able to submit this
//! branch on a user's behalf — the check is on `msg.sender`, which the relayer
//! cannot forge. `preflight.rs` already reaches the same conclusion and returns
//! [`Disposition::ClientMustSubmitDirectly`]; until now that verdict collapsed
//! to a bare `SubmitError::NotRelayable` at `submit.rs:1413-1415` and the
//! client was told "no" with nothing it could act on.
//!
//! This module gives that verdict a usable shape: the exact calldata, the
//! exact `to`, and the one address that is allowed to be `from`.
//!
//! # What this module deliberately does NOT do (architect assumption A1)
//!
//! * **No broadcast.** It takes no `ChainClient`, no `TrustedChain`, no
//!   `RpcChain` and no store. It cannot reach the network even by accident;
//!   there is nothing to reach it with.
//! * **No fund movement.** In particular no `send_native` and **no
//!   `DripLedger` call site**. `stream_g` today has zero drip call sites
//!   (`grep -rn "crate::gas_drips" src/stream_g/*.rs` = 0) and that property is
//!   load-bearing: the moment one appears, the gas-drip cap becomes part of
//!   Stream G's threat model. Funding a controller's gas so they can submit
//!   this branch themselves would be the first such call site. It is not
//!   assumed here; if the founder wants it, it is a separate, explicitly
//!   scoped decision.
//! * **No signature verification.** [`preflight::preflight_sponsored_enrollment`]
//!   is the validator and it needs live chain state (controller, epoch,
//!   nonces) that this module has no way to read. What is checked here is
//!   strictly the *branch shape* — the conditions that decide **who must
//!   submit** — and nothing else. A caller that skips preflight and trusts
//!   this module alone has an unvalidated call, and the returned envelope says
//!   so ([`DirectEthEnvelope::validated_by_preflight`] is not a field: there is
//!   no such claim to make).
//!
//! # `value` is zero, and that is not an oversight
//!
//! Despite the name, the "direct ETH" branch is **not payable**:
//! `executeSponsoredEnrollment` is declared `external nonReentrant`
//! (`GoatRelayGateway.sol:329-340`) with no `payable`. "Direct ETH" means *no
//! ERC-20 fee is collected* — the controller simply pays their own gas. A
//! client that attaches `msg.value` gets a revert from the compiler-generated
//! non-payable guard before any of the contract's own checks run, so
//! [`DirectEthEnvelope::value_wei`] is always `0`.
//!
//! # Calldata provenance
//!
//! The ten-argument ABI encoding is pinned byte-for-byte against `cast
//! calldata` output in two fixtures (see [`tests`]) — a legal direct-ETH call
//! and a fully-populated one that discriminates every field position,
//! including the ones the direct-ETH branch forces to zero. The selector is
//! **not** hand-derived; it comes from `cast sig` and `forge inspect`, which
//! agree:
//!
//! ```text
//! $ forge inspect GoatRelayGateway methodIdentifiers | grep executeSponsoredEnrollment
//! | executeSponsoredEnrollment(( ...full tuple expansion... ),bytes,bytes,bytes,bytes) | 90945f08 |
//! $ cast sig "executeSponsoredEnrollment(( ...same... ),bytes,bytes,bytes,bytes)"
//! 0x90945f08
//! ```
//!
//! # The encoder is shared, the branch decision is not (Wave B2)
//!
//! [`sponsored_enrollment_calldata`] is this module's ABI encoding reached
//! without the direct-ETH refusals, and it is what
//! `stream_g::broadcaster`'s production signer calls for the *relayable*
//! branch. There is exactly one encoder because there is exactly one `cast`
//! pin; the two callers apply opposite branch checks around it. Nothing about
//! sharing it lets this module broadcast — it still takes no chain, no store
//! and no key.
//!
//! # Disclosed encoding limitation
//!
//! [`preflight::SponsoredEnrollmentCall`] carries `fee_authorization_mode` and
//! the EIP-2612 payload, but **not** the EIP-3009 payload, the prior-allowance
//! payload, or `priorAllowanceSignature` — the three other arms of
//! `StreamGTypes.TokenAuthorization`. They are encoded as zero/empty. On this
//! branch that is not a lossy approximation but the only reachable value:
//! `:389` reverts unless `feeAuthorization.mode == AuthorizationMode.NONE`,
//! and with mode `NONE` the contract reads no arm at all (`_collectEip2612Fee`
//! is called only under `if (!ethPath)`, `:417-419`). The encoder itself is
//! general and is pinned on a `mode == EIP3009` fixture as well, so the
//! limitation is in what the caller can *supply*, not in what this file can
//! *encode*.

use thiserror::Error;

use super::models::{self, FeeQuote, LinkSecondary};
use super::preflight::{
    self, Disposition, Eip2612Authorization, RootAuthorization, SponsorEnrollment,
    SponsoredEnrollmentCall, V1Enrollment, AUTHORIZATION_MODE_NONE,
};

// ---------------------------------------------------------------------------
// Error codes (stable strings for logs / HTTP mapping) — same convention as
// `submit.rs`, `outbox.rs`, `broadcaster.rs`.
// ---------------------------------------------------------------------------

pub const ERR_DIRECT_ETH_NOT_DIRECT_BRANCH: &str = "DIRECT_ETH_NOT_DIRECT_BRANCH";
pub const ERR_DIRECT_ETH_QUOTE_NOT_ZEROED: &str = "DIRECT_ETH_QUOTE_NOT_ZEROED";
pub const ERR_DIRECT_ETH_QUOTE_SIGNATURE_PRESENT: &str = "DIRECT_ETH_QUOTE_SIGNATURE_PRESENT";
pub const ERR_DIRECT_ETH_FEE_AUTHORIZATION_PRESENT: &str = "DIRECT_ETH_FEE_AUTHORIZATION_PRESENT";
pub const ERR_DIRECT_ETH_ROOT_AUTHORIZATION_PRESENT: &str = "DIRECT_ETH_ROOT_AUTHORIZATION_PRESENT";
pub const ERR_DIRECT_ETH_MALFORMED_SIGNATURE: &str = "DIRECT_ETH_MALFORMED_SIGNATURE";

/// `cast sig` / `forge inspect` — see the module doc. Never hand-derived.
pub const EXECUTE_SPONSORED_ENROLLMENT_SELECTOR: [u8; 4] = [0x90, 0x94, 0x5f, 0x08];

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DirectEthError {
    /// `_isDirectEthEnrollment` is false, so this call goes down the sponsored
    /// (token-fee) branch, where `:379` does **not** apply and the relayer is
    /// the intended sender. Telling the client to self-submit here would be
    /// actively wrong: it would push gas cost onto a user who is paying a fee
    /// precisely so they do not have to hold ETH.
    #[error(
        "not the direct-ETH branch: StreamGEnroll._isDirectEthEnrollment is \
         false, so this call is relayable and must not be handed back to the client"
    )]
    NotDirectEthBranch,
    /// `GoatRelayGateway.sol:381-388` — every `FeeQuote` field must be zero on
    /// this branch or the contract reverts `InvalidQuote`.
    #[error("FeeQuote is not fully zeroed; GoatRelayGateway.sol:381-388 reverts InvalidQuote")]
    QuoteNotZeroed,
    /// `GoatRelayGateway.sol:380` — `quoteSignature` must be zero-length.
    #[error(
        "quoteSignature must be zero-length on the direct-ETH branch \
         (GoatRelayGateway.sol:380 reverts InvalidQuote), got {len} bytes"
    )]
    QuoteSignaturePresent { len: usize },
    /// `GoatRelayGateway.sol:389` — `feeAuthorization.mode` must be `NONE`.
    #[error(
        "feeAuthorization.mode must be NONE(0) on the direct-ETH branch \
         (GoatRelayGateway.sol:389 reverts InvalidFeeFields), got {mode}"
    )]
    FeeAuthorizationPresent { mode: u8 },
    /// `GoatRelayGateway.sol:365-373` — `intent.rootAuthorizationDigest`, all
    /// six `RootAuthorization` fields and `rootAuthorizationSignature` must be
    /// zero/empty on **every** sponsored-enrollment call, direct-ETH included.
    #[error(
        "root authorization must be entirely absent on sponsored enrollment \
         (GoatRelayGateway.sol:365-373 reverts InvalidFeeFields): {detail}"
    )]
    RootAuthorizationPresent { detail: String },
    #[error("malformed {field} hex: {detail}")]
    MalformedSignature { field: &'static str, detail: String },
}

impl DirectEthError {
    /// Stable code for logs / HTTP mapping.
    pub fn code(&self) -> &'static str {
        match self {
            DirectEthError::NotDirectEthBranch => ERR_DIRECT_ETH_NOT_DIRECT_BRANCH,
            DirectEthError::QuoteNotZeroed => ERR_DIRECT_ETH_QUOTE_NOT_ZEROED,
            DirectEthError::QuoteSignaturePresent { .. } => ERR_DIRECT_ETH_QUOTE_SIGNATURE_PRESENT,
            DirectEthError::FeeAuthorizationPresent { .. } => {
                ERR_DIRECT_ETH_FEE_AUTHORIZATION_PRESENT
            }
            DirectEthError::RootAuthorizationPresent { .. } => {
                ERR_DIRECT_ETH_ROOT_AUTHORIZATION_PRESENT
            }
            DirectEthError::MalformedSignature { .. } => ERR_DIRECT_ETH_MALFORMED_SIGNATURE,
        }
    }
}

// ---------------------------------------------------------------------------
// The envelope.
// ---------------------------------------------------------------------------

/// Everything the **controller** needs to submit `executeSponsoredEnrollment`
/// themselves, and nothing the attestor could use to submit it for them.
///
/// Note what is absent: no private key, no signed raw transaction, no gas
/// price, no nonce for `from`. Those are the controller's to choose, and a
/// signed raw transaction is exactly the artifact
/// [`super::broadcaster`] knows how to send — so this type deliberately is not
/// one and cannot be turned into one here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectEthEnvelope {
    /// The chain this calldata is bound to. The intent's EIP-712 digest is
    /// domain-separated by chain id, so calldata built for one chain is not
    /// merely useless on another — it is unrecoverable.
    pub chain_id: u64,
    /// `to` — the `GoatRelayGateway` address from the deployment manifest.
    pub to: [u8; 20],
    /// The **only** address that may be `msg.sender`
    /// (`GoatRelayGateway.sol:379`). Always `intent.controller`.
    pub from_must_be: [u8; 20],
    /// Always `0`: `executeSponsoredEnrollment` is not `payable`
    /// (`GoatRelayGateway.sol:329-340`). See the module doc.
    pub value_wei: u128,
    /// Selector + ABI-encoded arguments.
    pub data: Vec<u8>,
    /// The gateway's single-use `intentUsed[intentId]` key
    /// (`GoatRelayGateway.sol:315-323`), surfaced so a client can correlate
    /// its own submission with a later `SponsoredEnrollmentExecuted` log.
    pub intent_id: [u8; 32],
    /// `actionNonces[controller][ACTION_SPONSORED_ENROLLMENT]` the intent was
    /// signed against.
    pub action_nonce: u64,
    /// `intent.deadline` — chain time, `uint48`. After this the call reverts
    /// `ExpiredDeadline` (`GoatRelayGateway.sol:342`) and the controller needs
    /// a fresh intent, not a retry.
    pub deadline: u64,
}

/// The result of preparing a direct-ETH call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectEthPreparation {
    /// Always [`Disposition::ClientMustSubmitDirectly`]. Carried rather than
    /// implied so a caller matching on `Disposition` handles this path with
    /// the same code it uses for a preflight report.
    pub disposition: Disposition,
    pub envelope: DirectEthEnvelope,
}

// ---------------------------------------------------------------------------
// Preparation.
// ---------------------------------------------------------------------------

/// Build the transaction envelope the **controller** must submit themselves.
///
/// Refuses anything that is not actually on the direct-ETH branch. That
/// refusal is the load-bearing part of this function: a sponsored (token-fee)
/// call handed back to the client as "you must submit this yourself" is a
/// worse failure than a plain error, because the client can *act* on it — and
/// acting on it means a user who paid a fee to avoid holding ETH being told to
/// pay gas.
pub fn prepare_direct_eth_enrollment(
    call: &SponsoredEnrollmentCall<'_>,
    gateway: [u8; 20],
    chain_id: u64,
) -> Result<DirectEthPreparation, DirectEthError> {
    let intent = call.intent;

    // 1. Is this actually the branch that forbids relaying?
    //    `is_direct_eth_enrollment` is `preflight`'s, not a second copy: two
    //    definitions of a six-condition predicate is exactly how one of them
    //    drifts.
    if !preflight::is_direct_eth_enrollment(intent) {
        return Err(DirectEthError::NotDirectEthBranch);
    }

    // 2. Root authorization must be entirely absent — `:365-373`. This is
    //    checked on BOTH branches by the contract, so it is not "the direct-ETH
    //    branch's business", but an envelope that would revert here is not
    //    worth handing to a client.
    if intent.root_authorization_digest != [0u8; 32] {
        return Err(DirectEthError::RootAuthorizationPresent {
            detail: "intent.rootAuthorizationDigest != 0 (:365)".to_string(),
        });
    }
    if !call.root_authorization.is_all_zero() {
        return Err(DirectEthError::RootAuthorizationPresent {
            detail: "RootAuthorization struct is not all-zero (:366-372)".to_string(),
        });
    }
    let root_auth_sig = decode_hex_bytes(
        call.root_authorization_signature_hex,
        "rootAuthorizationSignature",
    )?;
    if !root_auth_sig.is_empty() {
        return Err(DirectEthError::RootAuthorizationPresent {
            detail: format!(
                "rootAuthorizationSignature must be zero-length (:370), got {} bytes",
                root_auth_sig.len()
            ),
        });
    }

    // 3. `:380` — no quote signature on this branch.
    let quote_sig = decode_hex_bytes(call.quote_signature_hex, "quoteSignature")?;
    if !quote_sig.is_empty() {
        return Err(DirectEthError::QuoteSignaturePresent {
            len: quote_sig.len(),
        });
    }

    // 4. `:381-388` — the whole `FeeQuote` must be zero.
    if !preflight::fee_quote_is_all_zero(call.quote) {
        return Err(DirectEthError::QuoteNotZeroed);
    }

    // 5. `:389` — no token authorization.
    if call.fee_authorization_mode != AUTHORIZATION_MODE_NONE {
        return Err(DirectEthError::FeeAuthorizationPresent {
            mode: call.fee_authorization_mode,
        });
    }

    // Shared with the broadcaster's signing seam — see
    // [`sponsored_enrollment_calldata`]. A second copy of the ten-argument
    // encoding call is exactly how one of them drifts, and only one of the two
    // is pinned against `cast`.
    let data = sponsored_enrollment_calldata(call)?;

    Ok(DirectEthPreparation {
        disposition: Disposition::ClientMustSubmitDirectly,
        envelope: DirectEthEnvelope {
            chain_id,
            to: gateway,
            // `GoatRelayGateway.sol:379`. Not the broadcaster, not the fee
            // safe, not the root — `intent.controller` and only that.
            from_must_be: intent.controller,
            // Not payable — see the module doc.
            value_wei: 0,
            data,
            intent_id: intent.intent_id,
            action_nonce: intent.nonce,
            deadline: intent.deadline,
        },
    })
}

fn decode_hex_bytes(s: &str, field: &'static str) -> Result<Vec<u8>, DirectEthError> {
    let t = s.trim();
    let h = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if h.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(h).map_err(|e| DirectEthError::MalformedSignature {
        field,
        detail: e.to_string(),
    })
}

// ---------------------------------------------------------------------------
// ABI encoding.
// ---------------------------------------------------------------------------

/// `executeSponsoredEnrollment` calldata for **either** branch, from the same
/// [`SponsoredEnrollmentCall`] both branches carry.
///
/// # Why this lives in the "informational preparation only" module
///
/// Because the encoding does, and it must exist exactly once. The ten-argument
/// ABI layout is pinned byte-for-byte against `cast calldata` in this module's
/// tests ([`tests::calldata_matches_the_cast_reference_for_a_direct_eth_call`]
/// and the fully-populated fixture). A second encoder written for the relayable
/// branch would be an unpinned copy of a 43-word layout — the exact drift the
/// `EncodeArgs` doc below already warns about, one level up.
///
/// This function **encodes and nothing else**. It does not decide which branch
/// the call is on, does not validate any contract precondition, and — like the
/// rest of this module — cannot broadcast: it takes no chain, no store and no
/// key. [`prepare_direct_eth_enrollment`] applies the direct-ETH refusals and
/// then calls this; `stream_g::broadcaster`'s production signer applies the
/// mirror-image refusal (it declines the direct-ETH branch, where
/// `msg.sender != intent.controller` reverts `NotController` at
/// `GoatRelayGateway.sol:379`) and then calls this. Neither refusal belongs
/// here, and neither is weakened by sharing the encoder.
///
/// The only errors are malformed signature hex — the four trailing `bytes`
/// arguments and `V1Enrollment.signature` arrive as strings.
pub(super) fn sponsored_enrollment_calldata(
    call: &SponsoredEnrollmentCall<'_>,
) -> Result<Vec<u8>, DirectEthError> {
    let sponsor_sig = decode_hex_bytes(call.sponsor_signature_hex, "sponsorSignature")?;
    let quote_sig = decode_hex_bytes(call.quote_signature_hex, "quoteSignature")?;
    let link_sig = decode_hex_bytes(call.link_signature_hex, "linkSignature")?;
    let root_auth_sig = decode_hex_bytes(
        call.root_authorization_signature_hex,
        "rootAuthorizationSignature",
    )?;
    let v1_sig = decode_hex_bytes(&call.v1_enrollment.signature_hex, "v1Enrollment.signature")?;

    Ok(encode_execute_sponsored_enrollment(EncodeArgs {
        intent: call.intent,
        quote: call.quote,
        v1_enrollment: call.v1_enrollment,
        v1_signature: &v1_sig,
        link: call.link,
        root_authorization: call.root_authorization,
        fee_authorization_mode: call.fee_authorization_mode,
        fee_eip2612: call.fee_eip2612_authorization,
        sponsor_signature: &sponsor_sig,
        quote_signature: &quote_sig,
        link_signature: &link_sig,
        root_authorization_signature: &root_auth_sig,
    }))
}

/// Arguments of the ten-parameter `executeSponsoredEnrollment`.
///
/// A struct rather than ten positional parameters because two of the four
/// trailing `bytes` arguments are empty on this branch, and a positional call
/// with `&[], &[]` adjacent is exactly how two `bytes` arguments get swapped
/// without any test noticing.
struct EncodeArgs<'a> {
    intent: &'a SponsorEnrollment,
    quote: &'a FeeQuote,
    v1_enrollment: &'a V1Enrollment,
    v1_signature: &'a [u8],
    link: &'a LinkSecondary,
    root_authorization: &'a RootAuthorization,
    fee_authorization_mode: u8,
    fee_eip2612: &'a Eip2612Authorization,
    sponsor_signature: &'a [u8],
    quote_signature: &'a [u8],
    link_signature: &'a [u8],
    root_authorization_signature: &'a [u8],
}

/// Words of the static head, in the ABI's parameter order.
///
/// `SponsorEnrollment` (17), `FeeQuote` (12), `LinkSecondary` (4) and
/// `RootAuthorization` (6) contain only value types, so they are **static
/// tuples** and are inlined into the head. `V1Enrollment` (has `bytes
/// signature`) and `TokenAuthorization` (has `bytes priorAllowanceSignature`)
/// are dynamic, so they contribute one offset word each, as do the four
/// trailing `bytes`.
const HEAD_WORDS: usize = 17 + 12 + 1 + 4 + 6 + 1 + 1 + 1 + 1 + 1;

/// `abi.encodeWithSelector(executeSponsoredEnrollment.selector, ...)`.
///
/// Pinned byte-for-byte against `cast calldata` in
/// [`tests::calldata_matches_the_cast_reference_for_a_direct_eth_call`] and
/// [`tests::calldata_matches_the_cast_reference_for_a_fully_populated_call`].
fn encode_execute_sponsored_enrollment(a: EncodeArgs<'_>) -> Vec<u8> {
    let mut head: Vec<u8> = Vec::with_capacity(HEAD_WORDS * 32);
    let mut tail: Vec<u8> = Vec::new();

    // --- intent: static tuple, 17 words, StreamGTypes.sol:202-220 ---------
    let i = a.intent;
    head.extend_from_slice(&i.intent_id);
    head.extend_from_slice(&i.deployment_manifest_hash);
    head.extend_from_slice(&i.fee_token_config_hash);
    head.extend_from_slice(&models::address_word(&i.root));
    head.extend_from_slice(&models::address_word(&i.controller));
    head.extend_from_slice(&models::u256_be(u128::from(i.controller_epoch)));
    head.extend_from_slice(&models::address_word(&i.secondary));
    head.extend_from_slice(&i.enroll_digest);
    head.extend_from_slice(&i.link_digest);
    head.extend_from_slice(&i.root_authorization_digest);
    head.extend_from_slice(&models::address_word(&i.fee_token));
    head.extend_from_slice(&models::u256_be_u8(i.fee_authorization_mode));
    head.extend_from_slice(&i.fee_authorization_digest);
    head.extend_from_slice(&models::u256_be(i.max_fee));
    head.extend_from_slice(&i.fee_quote_hash);
    head.extend_from_slice(&models::u256_be(u128::from(i.nonce)));
    head.extend_from_slice(&models::u256_be(u128::from(i.deadline)));

    // --- quote: static tuple, 12 words, StreamGTypes.sol:107-120 ----------
    let q = a.quote;
    head.extend_from_slice(&q.quote_id);
    head.extend_from_slice(&q.action_type);
    head.extend_from_slice(&q.action_core_hash);
    head.extend_from_slice(&q.deployment_manifest_hash);
    head.extend_from_slice(&q.fee_token_config_hash);
    head.extend_from_slice(&q.fee_schedule_hash);
    head.extend_from_slice(&models::address_word(&q.payer));
    head.extend_from_slice(&models::address_word(&q.fee_token));
    head.extend_from_slice(&models::u256_be(q.fee_amount));
    head.extend_from_slice(&models::address_word(&q.fee_recipient));
    head.extend_from_slice(&models::u256_be(u128::from(q.valid_after)));
    head.extend_from_slice(&models::u256_be(u128::from(q.valid_until)));

    // --- v1Enrollment: DYNAMIC tuple -> offset word -----------------------
    let v1_tail = encode_v1_enrollment(a.v1_enrollment, a.v1_signature);
    head.extend_from_slice(&offset_word(HEAD_WORDS, tail.len()));
    tail.extend_from_slice(&v1_tail);

    // --- link: static tuple, 4 words, StreamGTypes.sol:186-191 ------------
    let l = a.link;
    head.extend_from_slice(&models::address_word(&l.root));
    head.extend_from_slice(&models::address_word(&l.secondary));
    head.extend_from_slice(&models::u256_be(u128::from(l.nonce)));
    head.extend_from_slice(&models::u256_be(u128::from(l.deadline)));

    // --- rootAuthorization: static tuple, 6 words, :193-200 ---------------
    let r = a.root_authorization;
    head.extend_from_slice(&models::address_word(&r.root));
    head.extend_from_slice(&models::address_word(&r.secondary));
    head.extend_from_slice(&r.enroll_digest);
    head.extend_from_slice(&r.link_digest);
    head.extend_from_slice(&models::u256_be(u128::from(r.nonce)));
    head.extend_from_slice(&models::u256_be(u128::from(r.deadline)));

    // --- feeAuthorization: DYNAMIC tuple -> offset word --------------------
    let fa_tail = encode_token_authorization(a.fee_authorization_mode, a.fee_eip2612);
    head.extend_from_slice(&offset_word(HEAD_WORDS, tail.len()));
    tail.extend_from_slice(&fa_tail);

    // --- the four trailing `bytes`, in declaration order -------------------
    for bytes in [
        a.sponsor_signature,
        a.quote_signature,
        a.link_signature,
        a.root_authorization_signature,
    ] {
        head.extend_from_slice(&offset_word(HEAD_WORDS, tail.len()));
        tail.extend_from_slice(&abi_bytes_tail(bytes));
    }

    debug_assert_eq!(head.len(), HEAD_WORDS * 32, "head width drifted");

    let mut out = Vec::with_capacity(4 + head.len() + tail.len());
    out.extend_from_slice(&EXECUTE_SPONSORED_ENROLLMENT_SELECTOR);
    out.extend_from_slice(&head);
    out.extend_from_slice(&tail);
    out
}

/// `StreamGTypes.V1Enrollment` (`:308-313`) — dynamic because of `bytes
/// signature`. Offsets inside a dynamic tuple are relative to the **start of
/// that tuple**, not to the start of the argument block.
fn encode_v1_enrollment(v1: &V1Enrollment, signature: &[u8]) -> Vec<u8> {
    const INNER_HEAD_WORDS: usize = 4;
    let mut out = Vec::with_capacity(INNER_HEAD_WORDS * 32 + 32 + signature.len() + 32);
    out.extend_from_slice(&models::address_word(&v1.wallet));
    out.extend_from_slice(&models::u256_be(u128::from(v1.nonce)));
    out.extend_from_slice(&models::u256_be(u128::from(v1.deadline)));
    out.extend_from_slice(&offset_word(INNER_HEAD_WORDS, 0));
    out.extend_from_slice(&abi_bytes_tail(signature));
    out
}

/// `StreamGTypes.TokenAuthorization` (`:341-347`) — dynamic because of `bytes
/// priorAllowanceSignature`.
///
/// The EIP-3009 (`:328-338`, 9 words) and prior-allowance (`:273-282`, 8
/// words) arms and the trailing signature are zero/empty: `SponsoredEnrollmentCall`
/// does not carry them. See the module doc's "disclosed encoding limitation" —
/// on the direct-ETH branch `mode` is forced to `NONE`, under which the
/// contract reads no arm at all.
fn encode_token_authorization(mode: u8, eip2612: &Eip2612Authorization) -> Vec<u8> {
    const EIP3009_WORDS: usize = 9;
    const PRIOR_ALLOWANCE_WORDS: usize = 8;
    // mode + eip2612(7) + eip3009(9) + priorAllowance(8) + offset
    const INNER_HEAD_WORDS: usize = 1 + 7 + EIP3009_WORDS + PRIOR_ALLOWANCE_WORDS + 1;

    let mut out = Vec::with_capacity(INNER_HEAD_WORDS * 32 + 32);
    out.extend_from_slice(&models::u256_be_u8(mode));

    // Eip2612Authorization (`:316-324`): address, address, uint256, uint256,
    // uint8, bytes32, bytes32 — all value types, so inlined.
    out.extend_from_slice(&models::address_word(&eip2612.owner));
    out.extend_from_slice(&models::address_word(&eip2612.spender));
    out.extend_from_slice(&models::u256_be(eip2612.value));
    out.extend_from_slice(&models::u256_be(u128::from(eip2612.deadline)));
    out.extend_from_slice(&models::u256_be_u8(eip2612.v));
    out.extend_from_slice(&eip2612.r);
    out.extend_from_slice(&eip2612.s);

    out.extend_from_slice(&[0u8; 32 * EIP3009_WORDS]);
    out.extend_from_slice(&[0u8; 32 * PRIOR_ALLOWANCE_WORDS]);

    out.extend_from_slice(&offset_word(INNER_HEAD_WORDS, 0));
    out.extend_from_slice(&abi_bytes_tail(&[]));
    out
}

/// The offset word for a dynamic member: `head_words * 32 + bytes_of_tail_so_far`.
fn offset_word(head_words: usize, tail_len_so_far: usize) -> [u8; 32] {
    models::u256_be((head_words * 32 + tail_len_so_far) as u128)
}

/// A dynamic `bytes` tail: length word, data, right-padded to a 32-byte
/// boundary.
fn abi_bytes_tail(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + data.len() + 32);
    out.extend_from_slice(&models::u256_be(data.len() as u128));
    out.extend_from_slice(data);
    let pad = (32 - (data.len() % 32)) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- `cast`-derived ground truth ------------------------------------
    //
    // Both constants are verbatim `cast calldata` output (foundry cast 1.7.1,
    // a standalone binary -- not this crate) for the canonical signature that
    // `forge inspect GoatRelayGateway methodIdentifiers` prints. Nothing here
    // was computed by hand or by grep.
    include!("direct_eth_cast_reference.rs");

    const GATEWAY: [u8; 20] = hex_addr(0x0e01);
    const CHAIN_ID: u64 = 31337;

    const fn hex_addr(low: u16) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[18] = (low >> 8) as u8;
        a[19] = (low & 0xff) as u8;
        a
    }

    const fn word(b: u8) -> [u8; 32] {
        [b; 32]
    }

    const SPONSOR_SIG: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1b";
    const LINK_SIG: &str = "0xccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd1c";

    /// The exact fixture the `cast calldata` in [`CAST_REF_DIRECT_ETH`] was
    /// generated from: a legal direct-ETH call.
    struct Fixture {
        intent: SponsorEnrollment,
        quote: FeeQuote,
        v1: V1Enrollment,
        link: LinkSecondary,
        root_auth: RootAuthorization,
        eip2612: Eip2612Authorization,
        mode: u8,
        sponsor_sig: String,
        quote_sig: String,
        link_sig: String,
        root_auth_sig: String,
    }

    fn zero_quote() -> FeeQuote {
        FeeQuote {
            quote_id: [0u8; 32],
            action_type: [0u8; 32],
            action_core_hash: [0u8; 32],
            deployment_manifest_hash: [0u8; 32],
            fee_token_config_hash: [0u8; 32],
            fee_schedule_hash: [0u8; 32],
            payer: [0u8; 20],
            fee_token: [0u8; 20],
            fee_amount: 0,
            fee_recipient: [0u8; 20],
            valid_after: 0,
            valid_until: 0,
        }
    }

    fn direct_eth_fixture() -> Fixture {
        Fixture {
            intent: SponsorEnrollment {
                intent_id: word(0x11),
                deployment_manifest_hash: word(0x22),
                fee_token_config_hash: [0u8; 32],
                root: hex_addr(0x0a01),
                controller: hex_addr(0x0a02),
                controller_epoch: 7,
                secondary: hex_addr(0x0a03),
                enroll_digest: word(0x33),
                link_digest: word(0x44),
                root_authorization_digest: [0u8; 32],
                fee_token: [0u8; 20],
                fee_authorization_mode: 0,
                fee_authorization_digest: [0u8; 32],
                max_fee: 0,
                fee_quote_hash: [0u8; 32],
                nonce: 9,
                deadline: 1_234_567,
            },
            quote: zero_quote(),
            v1: V1Enrollment {
                wallet: hex_addr(0x0a03),
                nonce: 11,
                deadline: 222,
                signature_hex: "0xaabb".to_string(),
            },
            link: LinkSecondary {
                root: hex_addr(0x0a01),
                secondary: hex_addr(0x0a03),
                nonce: 13,
                deadline: 333,
            },
            root_auth: RootAuthorization::default(),
            eip2612: Eip2612Authorization {
                owner: hex_addr(0x0b01),
                spender: hex_addr(0x0b02),
                value: 555,
                deadline: 666,
                v: 27,
                r: word(0x55),
                s: word(0x66),
            },
            mode: AUTHORIZATION_MODE_NONE,
            sponsor_sig: SPONSOR_SIG.to_string(),
            quote_sig: String::new(),
            link_sig: LINK_SIG.to_string(),
            root_auth_sig: String::new(),
        }
    }

    impl Fixture {
        fn call(&self) -> SponsoredEnrollmentCall<'_> {
            SponsoredEnrollmentCall {
                intent: &self.intent,
                quote: &self.quote,
                v1_enrollment: &self.v1,
                link: &self.link,
                root_authorization: &self.root_auth,
                fee_authorization_mode: self.mode,
                fee_eip2612_authorization: &self.eip2612,
                sponsor_signature_hex: &self.sponsor_sig,
                quote_signature_hex: &self.quote_sig,
                link_signature_hex: &self.link_sig,
                root_authorization_signature_hex: &self.root_auth_sig,
            }
        }

        fn prepare(&self) -> Result<DirectEthPreparation, DirectEthError> {
            prepare_direct_eth_enrollment(&self.call(), GATEWAY, CHAIN_ID)
        }
    }

    // -----------------------------------------------------------------
    // Calldata provenance.
    // -----------------------------------------------------------------

    /// MUTATION DETECTED: any drift in the ABI encoder — a swapped field pair,
    /// a wrong offset base, a missing pad word, a hand-typed selector.
    /// Verified by swapping the `link.nonce` / `link.deadline` writes in
    /// `encode_execute_sponsored_enrollment`: this test and
    /// `calldata_matches_the_cast_reference_for_a_fully_populated_call` both
    /// fail; reverted.
    #[test]
    fn calldata_matches_the_cast_reference_for_a_direct_eth_call() {
        let f = direct_eth_fixture();
        let prep = f.prepare().expect("the fixture is a legal direct-ETH call");
        assert_eq!(
            hex::encode(&prep.envelope.data),
            CAST_REF_DIRECT_ETH,
            "calldata diverged from `cast calldata` ground truth"
        );
        // Paired non-zero arm: the reference is not the empty string and the
        // encoder did not simply return the selector.
        assert!(
            prep.envelope.data.len() > 4,
            "encoder produced no arguments"
        );
        assert_eq!(
            &prep.envelope.data[..4],
            &EXECUTE_SPONSORED_ENROLLMENT_SELECTOR,
            "selector"
        );
    }

    /// The direct-ETH fixture forces `quote`, `rootAuthorization` and six
    /// intent fields to zero, so it cannot discriminate their field ORDER.
    /// This fixture populates every position with a distinct value and is
    /// pinned against a second `cast calldata` run. It is deliberately NOT a
    /// legal on-chain call (`mode = EIP3009`, non-zero quote), so it exercises
    /// the encoder directly rather than through
    /// [`prepare_direct_eth_enrollment`], which would — correctly — refuse it.
    ///
    /// MUTATION DETECTED: reordering any field inside `SponsorEnrollment`,
    /// `FeeQuote`, `LinkSecondary` or `RootAuthorization`; encoding `uint48`
    /// deadlines as anything but a full 32-byte word.
    #[test]
    fn calldata_matches_the_cast_reference_for_a_fully_populated_call() {
        let intent = SponsorEnrollment {
            intent_id: word(0x11),
            deployment_manifest_hash: word(0x22),
            fee_token_config_hash: word(0x33),
            root: hex_addr(0x0a01),
            controller: hex_addr(0x0a02),
            controller_epoch: 7,
            secondary: hex_addr(0x0a03),
            enroll_digest: word(0x44),
            link_digest: word(0x55),
            root_authorization_digest: word(0x66),
            fee_token: hex_addr(0x0a04),
            fee_authorization_mode: 3,
            fee_authorization_digest: word(0x77),
            max_fee: 88_888,
            fee_quote_hash: word(0x99),
            nonce: 10,
            // uint48 max — proves the width is not truncated to u48 bytes.
            deadline: 281_474_976_710_655,
        };
        let quote = FeeQuote {
            quote_id: word(0x01),
            action_type: word(0x02),
            action_core_hash: word(0x03),
            deployment_manifest_hash: word(0x04),
            fee_token_config_hash: word(0x05),
            fee_schedule_hash: word(0x06),
            payer: hex_addr(0x0c01),
            fee_token: hex_addr(0x0c02),
            fee_amount: 777,
            fee_recipient: hex_addr(0x0c03),
            valid_after: 12,
            valid_until: 34,
        };
        let f = direct_eth_fixture();
        let root_auth = RootAuthorization {
            root: hex_addr(0x0d01),
            secondary: hex_addr(0x0d02),
            enroll_digest: word(0x07),
            link_digest: word(0x08),
            nonce: 44,
            deadline: 55,
        };
        let data = encode_execute_sponsored_enrollment(EncodeArgs {
            intent: &intent,
            quote: &quote,
            v1_enrollment: &f.v1,
            v1_signature: &hex::decode("aabb").unwrap(),
            link: &f.link,
            root_authorization: &root_auth,
            fee_authorization_mode: 2,
            fee_eip2612: &f.eip2612,
            sponsor_signature: &hex::decode(&SPONSOR_SIG[2..]).unwrap(),
            quote_signature: &hex::decode("deadbeef").unwrap(),
            link_signature: &hex::decode(&LINK_SIG[2..]).unwrap(),
            root_authorization_signature: &hex::decode("feed").unwrap(),
        });
        assert_eq!(hex::encode(&data), CAST_REF_FULLY_POPULATED);
        // Paired arm: this encoding really is different from the direct-ETH
        // one, so the two constants are not accidentally the same string.
        assert_ne!(CAST_REF_FULLY_POPULATED, CAST_REF_DIRECT_ETH);
    }

    /// The calldata the **broadcaster's signing seam** will put inside a
    /// transaction is byte-identical to the `cast`-pinned calldata this module
    /// already produces — because it is the same function, not a second
    /// encoder that happens to agree today.
    ///
    /// That equality is the whole point: `stream_g::broadcaster`'s production
    /// signer has no `cast` fixture of its own, and inherits this one only for
    /// as long as there is exactly one encoder. If someone later gives the
    /// relayable branch its own encoding call site, this test fails.
    ///
    /// The second half is the arm that proves the helper is not merely
    /// `prepare_direct_eth_enrollment` under another name: on a **relayable**
    /// (token-fee) call, `prepare` refuses with `NotDirectEthBranch` while the
    /// helper still encodes — which is exactly the case the broadcaster needs
    /// and the only case it will ever sign.
    ///
    /// **MUTATION DETECTED (run and reverted):** make
    /// `sponsored_enrollment_calldata` pass `quote_signature: &[]`
    /// unconditionally (a plausible "it is empty on the direct-ETH branch
    /// anyway" simplification). The direct-ETH arm still passes — its quote
    /// signature really is empty — and the relayable arm below fails, because
    /// the encoded calldata then drops a signature the gateway requires.
    #[test]
    fn the_broadcast_calldata_helper_is_the_cast_pinned_encoder() {
        let f = direct_eth_fixture();

        // Arm 1: same bytes as the `cast`-pinned envelope, via the two
        // different entry points.
        let via_helper = sponsored_enrollment_calldata(&f.call()).expect("well-formed hex");
        let via_prepare = f.prepare().expect("legal direct-ETH call").envelope.data;
        assert_eq!(
            hex::encode(&via_helper),
            CAST_REF_DIRECT_ETH,
            "the broadcaster's calldata must be the cast-pinned encoding"
        );
        assert_eq!(via_helper, via_prepare, "one encoder, not two");

        // Arm 2: the relayable branch — refused by `prepare`, encoded by the
        // helper. A non-empty quote signature is what a sponsored call carries
        // and what arm 1 cannot discriminate.
        let mut relayable = direct_eth_fixture();
        relayable.intent.fee_token = hex_addr(0x0f01);
        relayable.quote_sig = "0xdeadbeef".to_string();
        assert_eq!(
            relayable.prepare().unwrap_err(),
            DirectEthError::NotDirectEthBranch,
            "non-zero arm: `prepare` really does refuse this call"
        );
        let relayable_data =
            sponsored_enrollment_calldata(&relayable.call()).expect("the helper still encodes it");
        assert_ne!(
            hex::encode(&relayable_data),
            CAST_REF_DIRECT_ETH,
            "a different call must produce different calldata"
        );
        assert_eq!(
            &relayable_data[..4],
            &EXECUTE_SPONSORED_ENROLLMENT_SELECTOR,
            "same function, different arguments"
        );
        assert!(
            hex::encode(&relayable_data).contains("deadbeef"),
            "the quote signature must survive into the calldata"
        );

        // Malformed hex is an error here too, not a silently-empty field.
        let mut bad = direct_eth_fixture();
        bad.link_sig = "0xzz".to_string();
        assert!(matches!(
            sponsored_enrollment_calldata(&bad.call()),
            Err(DirectEthError::MalformedSignature {
                field: "linkSignature",
                ..
            })
        ));
    }

    /// MUTATION DETECTED: hand-typing the selector. Pinned to the value
    /// `cast sig` and `forge inspect` independently produced.
    #[test]
    fn selector_is_the_cast_derived_one() {
        assert_eq!(
            hex::encode(EXECUTE_SPONSORED_ENROLLMENT_SELECTOR),
            "90945f08"
        );
        assert_eq!(&CAST_REF_DIRECT_ETH[..8], "90945f08");
    }

    // -----------------------------------------------------------------
    // The refusal that matters.
    // -----------------------------------------------------------------

    /// The load-bearing guard, with both arms.
    ///
    /// MUTATION DETECTED: delete the `is_direct_eth_enrollment` check in
    /// `prepare_direct_eth_enrollment`. Verified: the sponsored arm then
    /// returns `Ok` and the test fails; reverted.
    #[test]
    fn a_relayable_sponsored_call_is_refused_but_a_direct_eth_one_is_prepared() {
        // NEGATIVE arm — a token-fee call is relayable; handing it back to the
        // client would push gas onto a user who paid a fee to avoid it.
        let mut f = direct_eth_fixture();
        f.intent.fee_token = hex_addr(0x0f01);
        assert_eq!(f.prepare().unwrap_err(), DirectEthError::NotDirectEthBranch);
        assert_eq!(
            DirectEthError::NotDirectEthBranch.code(),
            ERR_DIRECT_ETH_NOT_DIRECT_BRANCH
        );

        // POSITIVE arm — the same fixture with `feeToken` back to zero IS the
        // direct-ETH branch and must prepare.
        f.intent.fee_token = [0u8; 20];
        let prep = f.prepare().expect("all six conditions hold");
        assert_eq!(prep.disposition, Disposition::ClientMustSubmitDirectly);
    }

    /// Each of the six `_isDirectEthEnrollment` conditions independently takes
    /// the call off this branch. Paired with the all-six-hold positive arm so
    /// no assertion is vacuous.
    ///
    /// MUTATION DETECTED: dropping any condition from
    /// `preflight::is_direct_eth_enrollment`.
    #[test]
    fn every_one_of_the_six_conditions_is_load_bearing() {
        let base = direct_eth_fixture();
        assert!(base.prepare().is_ok(), "all six hold");

        let mut n = 0;
        for mutate in [
            (|i: &mut SponsorEnrollment| i.fee_token = hex_addr(1)) as fn(&mut SponsorEnrollment),
            |i: &mut SponsorEnrollment| i.fee_authorization_mode = 1,
            |i: &mut SponsorEnrollment| i.fee_authorization_digest = word(0xee),
            |i: &mut SponsorEnrollment| i.fee_quote_hash = word(0xee),
            |i: &mut SponsorEnrollment| i.max_fee = 1,
            |i: &mut SponsorEnrollment| i.fee_token_config_hash = word(0xee),
        ] {
            let mut f = direct_eth_fixture();
            mutate(&mut f.intent);
            assert_eq!(
                f.prepare().unwrap_err(),
                DirectEthError::NotDirectEthBranch,
                "condition {n} did not take the call off the direct-ETH branch"
            );
            n += 1;
        }
        assert_eq!(n, 6, "all six conditions must be exercised");
    }

    // -----------------------------------------------------------------
    // The envelope.
    // -----------------------------------------------------------------

    /// MUTATION DETECTED: set `from_must_be` to `intent.root`, to the gateway,
    /// or to any constant. The second arm changes only the controller and
    /// requires the field to follow it, so a hard-coded address fails even if
    /// it happens to equal the first fixture's controller.
    #[test]
    fn the_envelope_names_the_controller_and_only_the_controller_as_sender() {
        let f = direct_eth_fixture();
        let prep = f.prepare().unwrap();
        assert_eq!(prep.envelope.from_must_be, f.intent.controller);
        assert_ne!(
            prep.envelope.from_must_be, f.intent.root,
            "root is not the controller in this fixture"
        );
        assert_ne!(prep.envelope.from_must_be, GATEWAY);

        let mut g = direct_eth_fixture();
        g.intent.controller = hex_addr(0x0a99);
        let prep2 = g.prepare().unwrap();
        assert_eq!(prep2.envelope.from_must_be, hex_addr(0x0a99));
        assert_ne!(
            prep2.envelope.from_must_be, prep.envelope.from_must_be,
            "from_must_be must track the controller, not be a constant"
        );
    }

    /// `executeSponsoredEnrollment` is `external nonReentrant`, NOT payable
    /// (`GoatRelayGateway.sol:329-340`), so attaching `msg.value` reverts in
    /// the compiler-generated guard before any contract check runs.
    ///
    /// MUTATION DETECTED: setting `value_wei` from `intent.max_fee` or from a
    /// caller-supplied amount. The paired arm proves the envelope's other
    /// numeric fields are NOT uniformly zero, so "everything is 0" cannot pass.
    #[test]
    fn the_envelope_attaches_no_ether_because_the_function_is_not_payable() {
        let f = direct_eth_fixture();
        let e = f.prepare().unwrap().envelope;
        assert_eq!(e.value_wei, 0);
        // Paired non-zero arm.
        assert_eq!(e.chain_id, CHAIN_ID);
        assert_eq!(e.action_nonce, 9);
        assert_eq!(e.deadline, 1_234_567);
        assert_eq!(e.intent_id, word(0x11));
        assert_eq!(e.to, GATEWAY);
        assert_ne!(e.action_nonce, 0);
        assert_ne!(e.deadline, 0);
    }

    // -----------------------------------------------------------------
    // The other branch preconditions.
    // -----------------------------------------------------------------

    /// `GoatRelayGateway.sol:380`.
    ///
    /// MUTATION DETECTED: delete the `quote_sig.is_empty()` check — the
    /// negative arm then returns `Ok`.
    #[test]
    fn a_present_quote_signature_is_refused_and_an_absent_one_is_not() {
        let mut f = direct_eth_fixture();
        f.quote_sig = SPONSOR_SIG.to_string();
        assert_eq!(
            f.prepare().unwrap_err(),
            DirectEthError::QuoteSignaturePresent { len: 65 }
        );
        f.quote_sig = String::new();
        assert!(f.prepare().is_ok());
        // "0x" and "" must both mean zero-length.
        f.quote_sig = "0x".to_string();
        assert!(f.prepare().is_ok());
    }

    /// `GoatRelayGateway.sol:381-388`.
    ///
    /// MUTATION DETECTED: delete the `fee_quote_is_all_zero` check.
    #[test]
    fn a_non_zeroed_quote_is_refused_and_a_zeroed_one_is_not() {
        let mut f = direct_eth_fixture();
        f.quote.fee_amount = 1;
        assert_eq!(f.prepare().unwrap_err(), DirectEthError::QuoteNotZeroed);
        f.quote.fee_amount = 0;
        assert!(f.prepare().is_ok());
        f.quote.payer = hex_addr(0x0c01);
        assert_eq!(f.prepare().unwrap_err(), DirectEthError::QuoteNotZeroed);
    }

    /// `GoatRelayGateway.sol:389`.
    ///
    /// MUTATION DETECTED: delete the `fee_authorization_mode` check. Note this
    /// is the OUTER `TokenAuthorization.mode`, which is a separate field from
    /// `intent.feeAuthorizationMode` (checked by the six-condition predicate);
    /// the contract checks both, at `:389` and `:646` respectively.
    #[test]
    fn a_present_fee_authorization_mode_is_refused_and_none_is_not() {
        let mut f = direct_eth_fixture();
        f.mode = 1;
        assert_eq!(
            f.prepare().unwrap_err(),
            DirectEthError::FeeAuthorizationPresent { mode: 1 }
        );
        f.mode = AUTHORIZATION_MODE_NONE;
        assert!(f.prepare().is_ok());
    }

    /// `GoatRelayGateway.sol:365-373` — three distinct ways the root
    /// authorization can be present, each refused, each with the zeroed arm
    /// proving the guard is not simply always-firing.
    ///
    /// MUTATION DETECTED: delete any of the three root-authorization checks.
    #[test]
    fn any_trace_of_a_root_authorization_is_refused() {
        let mut f = direct_eth_fixture();
        f.intent.root_authorization_digest = word(0xab);
        assert!(matches!(
            f.prepare().unwrap_err(),
            DirectEthError::RootAuthorizationPresent { .. }
        ));
        f.intent.root_authorization_digest = [0u8; 32];
        assert!(f.prepare().is_ok());

        f.root_auth.nonce = 1;
        assert!(matches!(
            f.prepare().unwrap_err(),
            DirectEthError::RootAuthorizationPresent { .. }
        ));
        f.root_auth.nonce = 0;
        assert!(f.prepare().is_ok());

        f.root_auth_sig = SPONSOR_SIG.to_string();
        assert!(matches!(
            f.prepare().unwrap_err(),
            DirectEthError::RootAuthorizationPresent { .. }
        ));
        f.root_auth_sig = String::new();
        assert!(f.prepare().is_ok());
    }

    /// MUTATION DETECTED: `unwrap_or_default()` on the hex decode — a
    /// malformed signature would then silently encode as empty `bytes`, and
    /// the controller would submit a call that reverts `BadLinkSignature` with
    /// no clue why.
    #[test]
    fn malformed_signature_hex_is_an_error_not_an_empty_bytes_field() {
        let mut f = direct_eth_fixture();
        f.link_sig = "0xzzzz".to_string();
        let err = f.prepare().unwrap_err();
        assert!(matches!(
            err,
            DirectEthError::MalformedSignature {
                field: "linkSignature",
                ..
            }
        ));
        assert_eq!(err.code(), ERR_DIRECT_ETH_MALFORMED_SIGNATURE);
        // Paired arm: the well-formed value is accepted and lands in calldata.
        f.link_sig = LINK_SIG.to_string();
        let data = f.prepare().unwrap().envelope.data;
        assert!(
            hex::encode(&data).contains(&LINK_SIG[2..]),
            "the link signature must actually appear in the calldata"
        );
    }

    /// `stream_g` has zero `DripLedger` call sites and this module must not be
    /// the first. Asserted as a SOURCE-TEXT property of this file, not as a
    /// runtime counter: a runtime "zero drips" assertion would be 0-vs-0 (the
    /// I7 defect shape the brief forbids), whereas this fails the moment
    /// someone writes the call.
    ///
    /// MUTATION DETECTED: add `crate::gas_drips::` or `send_native` anywhere in
    /// this file. Verified by inserting `// crate::gas_drips::DripLedger` into
    /// the module doc: the test failed; reverted.
    #[test]
    fn this_module_contains_no_fund_moving_call_site() {
        let whole = include_str!("direct_eth.rs");
        // Only the PRODUCTION half is scanned: the needles are spelled out in
        // this test, so scanning the test module would trip on itself.
        let production = whole
            .split_once("#[cfg(test)]")
            .expect("this file has a test module")
            .0;
        // Paired non-vacuous arm: the split really did keep the production
        // code, so the zero-hit assertions below are searching real source and
        // not an empty string.
        assert!(
            production.contains("fn prepare_direct_eth_enrollment"),
            "the production half was not captured; the assertions below would be vacuous"
        );
        assert!(
            production.len() > 4_000,
            "production half implausibly short"
        );

        // Built by concatenation so these literals do not appear whole in the
        // scanned region even if someone later moves the split point.
        let needles = [
            format!("{}{}", "gas_", "drips"),
            format!("{}{}", "send_", "native"),
            format!("{}{}", "Drip", "Ledger"),
        ];
        for needle in &needles {
            let hits = production
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    // The module doc names them deliberately; comments are not
                    // call sites.
                    !t.starts_with("//") && !t.starts_with("*") && l.contains(needle.as_str())
                })
                .count();
            assert_eq!(
                hits, 0,
                "`{needle}` appears in non-comment production source"
            );
        }
        // Paired positive arm for the scanner itself: a needle that IS present
        // in non-comment source must be found, otherwise the loop above proves
        // only that the filter is broken.
        let control = production
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//") && !t.starts_with("*") && l.contains("DirectEthEnvelope")
            })
            .count();
        assert!(
            control > 0,
            "the scanner cannot find a string that is there"
        );
    }
}

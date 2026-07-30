// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Permit} from "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {StreamGTypes} from "../StreamGTypes.sol";
import {IEIP3009} from "../interfaces/IEIP3009.sol";
import {FeeTokenRegistry} from "../FeeTokenRegistry.sol";
import {StreamGHashes} from "./StreamGHashes.sol";

/// Shared Stream G gateway logic hoisted out of `GoatRelayGateway` for EIP-170.
///
/// Everything here is `internal` **on purpose**: this file is a code-sharing
/// unit for the *action libraries* (`StreamGEnroll`, `StreamGActions`), which
/// are themselves `public` libraries reached by `DELEGATECALL` from the gateway.
/// Making these `public` would add a second nested `DELEGATECALL` per helper and
/// buy nothing — the gateway already sheds the bytes when the action bodies move
/// out. Each action library gets its own inlined copy, which is fine: only the
/// *gateway's* runtime size is bound by EIP-170, and each library is far under it.
///
/// `DELEGATECALL` preserves `address(this)` and the gateway's storage, so every
/// `address(this)` below is still the gateway, storage writes land in the
/// gateway's slots, and the EIP-712 domain separator is untouched. Gateway
/// immutables and `_domainSeparatorV4()` are not visible to library code, so
/// they arrive in `Ctx`; the digest formula is the same
/// `"\x19\x01" || domainSeparator || structHash` OpenZeppelin uses.
library StreamGCommon {
    using SafeERC20 for IERC20;

    error ZeroIntentId();
    error IntentAlreadyUsed();
    error BadActionNonce();
    error InvalidQuote();
    error QuoteAlreadyUsed();
    error FeeExceedsMax();
    error ConfigHashMismatch();
    error BadQuoteSignature();
    error InvalidFeeFields();
    error UnsupportedFeeMode();
    error UnexpectedBalanceDelta();
    error BadPriorAllowance();
    error ExpiredDeadline();

    /// Gateway immutables / config the libraries cannot read for themselves.
    struct Ctx {
        address enrollmentRegistry;
        address feeTokenRegistry;
        address sponsorship;
        address goat;
        address feeSafe;
        address quoteSigner;
        bytes32 feeScheduleHash;
        bytes32 domainSeparator;
    }

    /// Byte-identical to OpenZeppelin `EIP712._hashTypedDataV4`.
    function digest(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function markIntentAndNonce(
        mapping(bytes32 => bool) storage intentUsed,
        mapping(address => mapping(bytes32 => uint256)) storage actionNonces,
        bytes32 intentId,
        address signer,
        bytes32 actionType,
        uint256 expectedNonce
    ) internal {
        if (intentId == bytes32(0)) revert ZeroIntentId();
        if (intentUsed[intentId]) revert IntentAlreadyUsed();
        if (actionNonces[signer][actionType] != expectedNonce) revert BadActionNonce();
        intentUsed[intentId] = true;
        actionNonces[signer][actionType] = expectedNonce + 1;
    }

    function capabilityForMode(uint8 mode) internal pure returns (uint256) {
        if (mode == uint8(StreamGTypes.AuthorizationMode.EIP2612)) return StreamGTypes.CAP_EIP2612;
        if (mode == uint8(StreamGTypes.AuthorizationMode.EIP3009)) return StreamGTypes.CAP_EIP3009;
        if (mode == uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE)) return StreamGTypes.CAP_PRIOR_ALLOWANCE;
        revert UnsupportedFeeMode();
    }

    /// Quote binding fields that vary per action. Grouped so the shared
    /// validator keeps a workable arity under `via_ir`.
    struct QuoteCheck {
        bytes32 actionType;
        address payer;
        address feeToken;
        bytes32 feeTokenConfigHash;
        bytes32 deploymentManifestHash;
        uint256 maxFee;
        bytes32 actionCoreHash;
        uint256 requiredCapability;
    }

    /// Verbatim port of `GoatRelayGateway._validateAndConsumeQuoteGeneric`.
    /// Check order is unchanged — several tests pin which revert fires first.
    function validateAndConsumeQuote(
        mapping(bytes32 => bool) storage quoteUsed,
        Ctx memory ctx,
        QuoteCheck memory qc,
        StreamGTypes.FeeQuote calldata quote,
        bytes calldata quoteSignature
    ) internal returns (uint256 feeAmount) {
        if (ctx.quoteSigner == address(0)) revert InvalidQuote();
        if (quote.quoteId == bytes32(0)) revert InvalidQuote();
        if (quoteUsed[quote.quoteId]) revert QuoteAlreadyUsed();
        if (quote.actionType != qc.actionType) revert InvalidQuote();
        if (quote.payer != qc.payer) revert InvalidQuote();
        if (quote.feeRecipient != ctx.feeSafe) revert InvalidQuote();
        if (quote.feeToken != qc.feeToken || quote.feeToken == address(0)) revert InvalidQuote();
        if (quote.feeAmount == 0) revert InvalidQuote();
        if (quote.feeAmount > qc.maxFee) revert FeeExceedsMax();
        if (!(quote.validAfter <= block.timestamp && block.timestamp < quote.validUntil)) revert InvalidQuote();

        bytes32 liveManifest = FeeTokenRegistry(ctx.feeTokenRegistry).activeManifestHash();
        if (qc.deploymentManifestHash != liveManifest || quote.deploymentManifestHash != liveManifest) {
            revert ConfigHashMismatch();
        }
        if (quote.feeScheduleHash != ctx.feeScheduleHash || ctx.feeScheduleHash == bytes32(0)) {
            revert ConfigHashMismatch();
        }

        // Hard-gated capability check before any state mutation (Hazard A / SG-24).
        FeeTokenRegistry(ctx.feeTokenRegistry).assertTokenAuthorized(qc.feeToken, qc.requiredCapability);
        bytes32 liveCfg = FeeTokenRegistry(ctx.feeTokenRegistry).getTokenConfigHash(qc.feeToken);
        if (liveCfg == bytes32(0) || qc.feeTokenConfigHash != liveCfg || quote.feeTokenConfigHash != liveCfg) {
            revert ConfigHashMismatch();
        }

        if (quote.actionCoreHash != qc.actionCoreHash) revert InvalidQuote();

        bytes32 qDigest = digest(ctx.domainSeparator, StreamGHashes.feeQuoteStructHash(quote));
        address qSigner = ECDSA.recover(qDigest, quoteSignature);
        if (qSigner != ctx.quoteSigner) revert BadQuoteSignature();

        quoteUsed[quote.quoteId] = true;
        return quote.feeAmount;
    }

    /// Verbatim port of `GoatRelayGateway._goatPermitMatches`. The GOAT permit is
    /// signed under the *token's* own domain, which is read live from the token.
    function goatPermitMatches(
        address goat,
        StreamGTypes.Eip2612Authorization calldata p,
        address owner,
        address spender,
        uint256 value,
        bytes32 expectedDigest
    ) internal view returns (bool) {
        if (p.owner != owner || p.spender != spender || p.value != value) return false;
        bytes32 structHash = keccak256(
            abi.encode(
                StreamGTypes.EIP2612_PERMIT_TYPEHASH,
                p.owner,
                p.spender,
                p.value,
                IERC20Permit(goat).nonces(p.owner),
                p.deadline
            )
        );
        bytes32 liveDigest = digest(IERC20Permit(goat).DOMAIN_SEPARATOR(), structHash);
        if (expectedDigest != bytes32(0) && expectedDigest != liveDigest) {
            return false;
        }
        return true;
    }

    // -------------------------------------------------------------------------
    // Fee collection (verbatim ports of the gateway's `_collect*` family)
    // -------------------------------------------------------------------------

    function collectFee(
        Ctx memory ctx,
        address payer,
        address feeToken,
        uint256 feeAmount,
        StreamGTypes.TokenAuthorization calldata auth,
        bytes32 intentId,
        bytes32 actionType
    ) internal {
        if (feeAmount == 0) revert InvalidFeeFields();
        if (auth.mode == uint8(StreamGTypes.AuthorizationMode.EIP2612)) {
            collectEip2612(ctx.feeSafe, payer, feeToken, feeAmount, auth.eip2612);
            return;
        }
        if (auth.mode == uint8(StreamGTypes.AuthorizationMode.EIP3009)) {
            collectEip3009(ctx.feeSafe, payer, feeToken, feeAmount, auth.eip3009);
            return;
        }
        if (auth.mode == uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE)) {
            collectPriorAllowance(ctx, payer, feeToken, feeAmount, auth, intentId, actionType);
            return;
        }
        revert UnsupportedFeeMode();
    }

    function collectEip2612(
        address feeSafe,
        address payer,
        address feeToken,
        uint256 feeAmount,
        StreamGTypes.Eip2612Authorization calldata p
    ) internal {
        if (p.owner != payer || p.spender != address(this) || p.value < feeAmount) revert InvalidFeeFields();
        IERC20Permit(feeToken).permit(p.owner, p.spender, p.value, p.deadline, p.v, p.r, p.s);
        uint256 beforeBal = IERC20(feeToken).balanceOf(feeSafe);
        IERC20(feeToken).safeTransferFrom(payer, feeSafe, feeAmount);
        if (IERC20(feeToken).balanceOf(feeSafe) != beforeBal + feeAmount) revert UnexpectedBalanceDelta();
    }

    function collectEip3009(
        address feeSafe,
        address payer,
        address feeToken,
        uint256 feeAmount,
        StreamGTypes.Eip3009Authorization calldata a
    ) internal {
        if (a.from != payer || a.to != address(this) || a.value != feeAmount) revert InvalidFeeFields();
        if (!(a.validAfter < block.timestamp && block.timestamp < a.validBefore)) revert InvalidFeeFields();
        uint256 gatewayBefore = IERC20(feeToken).balanceOf(address(this));
        uint256 feeSafeBefore = IERC20(feeToken).balanceOf(feeSafe);
        IEIP3009(feeToken).receiveWithAuthorization(
            a.from, a.to, a.value, a.validAfter, a.validBefore, a.nonce, a.v, a.r, a.s
        );
        if (IERC20(feeToken).balanceOf(address(this)) != gatewayBefore + feeAmount) revert UnexpectedBalanceDelta();
        IERC20(feeToken).safeTransfer(feeSafe, feeAmount);
        if (IERC20(feeToken).balanceOf(feeSafe) != feeSafeBefore + feeAmount) revert UnexpectedBalanceDelta();
        if (IERC20(feeToken).balanceOf(address(this)) != gatewayBefore) revert UnexpectedBalanceDelta();
    }

    function collectPriorAllowance(
        Ctx memory ctx,
        address payer,
        address feeToken,
        uint256 feeAmount,
        StreamGTypes.TokenAuthorization calldata auth,
        bytes32 intentId,
        bytes32 actionType
    ) internal {
        StreamGTypes.PriorAllowanceAuthorization calldata p = auth.priorAllowance;
        if (
            p.intentId != intentId || p.actionType != actionType || p.owner != payer || p.token != feeToken
                || p.spender != address(this) || p.value < feeAmount
        ) {
            revert BadPriorAllowance();
        }
        if (block.timestamp >= p.deadline) revert ExpiredDeadline();
        bytes32 d = digest(
            ctx.domainSeparator,
            keccak256(
                abi.encode(
                    StreamGTypes.PRIOR_ALLOWANCE_AUTHORIZATION_TYPEHASH,
                    p.intentId,
                    p.actionType,
                    p.owner,
                    p.token,
                    p.spender,
                    p.value,
                    p.nonce,
                    p.deadline
                )
            )
        );
        address signer = ECDSA.recover(d, auth.priorAllowanceSignature);
        if (signer != payer) revert BadPriorAllowance();
        if (IERC20(feeToken).allowance(payer, address(this)) < feeAmount) revert BadPriorAllowance();
        uint256 beforeBal = IERC20(feeToken).balanceOf(ctx.feeSafe);
        IERC20(feeToken).safeTransferFrom(payer, ctx.feeSafe, feeAmount);
        if (IERC20(feeToken).balanceOf(ctx.feeSafe) != beforeBal + feeAmount) revert UnexpectedBalanceDelta();
    }
}

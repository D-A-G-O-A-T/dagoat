// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {StreamGTypes} from "../StreamGTypes.sol";

/// Pure EIP-712 struct-hash / core-hash encoders lifted out of `GoatRelayGateway`
/// to keep the gateway's runtime bytecode under EIP-170 (24,576 bytes).
///
/// EVERY function here is `internal` on purpose, i.e. INLINED into its callers
/// (the `public` action libraries and the gateway's two harness-facing stubs).
///
/// Measured, not assumed: these nine encoders were `public` for one wave, which
/// bought the gateway **184 bytes** — the ~2.7 kB of bodies that left were almost
/// exactly cancelled by the `DELEGATECALL` marshalling stubs that appeared at the
/// 13 call sites. The bytes now come from moving whole action bodies out
/// (`StreamGEnroll` / `StreamGSell` / `StreamGXfer`), so paying a `DELEGATECALL`
/// per struct hash — twice per sponsored action, on the fee path — buys nothing.
/// Inlined keccak is both smaller here and cheaper in gas.
///
/// Either way the digests are identical: these are pure keccak over an unchanged
/// field order, and inlining cannot change `address(this)` or the gateway's
/// `EIP712("GoatRelayGateway","1")` domain separator.
library StreamGHashes {
    function feeQuoteStructHash(StreamGTypes.FeeQuote calldata quote) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                StreamGTypes.FEE_QUOTE_TYPEHASH,
                quote.quoteId,
                quote.actionType,
                quote.actionCoreHash,
                quote.deploymentManifestHash,
                quote.feeTokenConfigHash,
                quote.feeScheduleHash,
                quote.payer,
                quote.feeToken,
                quote.feeAmount,
                quote.feeRecipient,
                quote.validAfter,
                quote.validUntil
            )
        );
    }

    function sponsorEnrollmentStructHash(StreamGTypes.SponsorEnrollment calldata intent)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                StreamGTypes.SPONSOR_ENROLLMENT_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.root,
                intent.controller,
                intent.controllerEpoch,
                intent.secondary,
                intent.enrollDigest,
                intent.linkDigest,
                intent.rootAuthorizationDigest,
                intent.feeToken,
                intent.feeAuthorizationMode,
                intent.feeAuthorizationDigest,
                intent.maxFee,
                intent.feeQuoteHash,
                intent.nonce,
                intent.deadline
            )
        );
    }

    function sponsorEnrollmentCoreHash(StreamGTypes.SponsorEnrollment calldata intent)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                StreamGTypes.SPONSOR_ENROLLMENT_CORE_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.root,
                intent.controller,
                intent.controllerEpoch,
                intent.secondary,
                intent.enrollDigest,
                intent.linkDigest,
                intent.rootAuthorizationDigest,
                intent.feeToken,
                intent.feeAuthorizationMode,
                intent.maxFee,
                intent.nonce,
                intent.deadline
            )
        );
    }

    function sellCoreHash(StreamGTypes.SellIntent calldata intent) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                StreamGTypes.SELL_CORE_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.seller,
                intent.expectedRoot,
                intent.desk,
                intent.goatAmount,
                intent.minNetUsdtOut,
                intent.goatPermitDigest,
                intent.maxFee,
                intent.nonce,
                intent.deadline
            )
        );
    }

    function sellIntentStructHash(StreamGTypes.SellIntent calldata intent) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                StreamGTypes.SELL_INTENT_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.seller,
                intent.expectedRoot,
                intent.desk,
                intent.goatAmount,
                intent.minNetUsdtOut,
                intent.goatPermitDigest,
                intent.maxFee,
                intent.feeQuoteHash,
                intent.nonce,
                intent.deadline
            )
        );
    }

    function goatTransferCoreHash(StreamGTypes.GoatTransferIntent calldata intent) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                StreamGTypes.GOAT_TRANSFER_CORE_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.owner,
                intent.expectedRoot,
                intent.recipient,
                intent.amount,
                intent.goatPermitDigest,
                intent.feeToken,
                intent.feeAuthorizationMode,
                intent.maxFee,
                intent.nonce,
                intent.deadline
            )
        );
    }

    function goatTransferIntentStructHash(StreamGTypes.GoatTransferIntent calldata intent)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                StreamGTypes.GOAT_TRANSFER_INTENT_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.owner,
                intent.expectedRoot,
                intent.recipient,
                intent.amount,
                intent.goatPermitDigest,
                intent.feeToken,
                intent.feeAuthorizationMode,
                intent.feeAuthorizationDigest,
                intent.maxFee,
                intent.feeQuoteHash,
                intent.nonce,
                intent.deadline
            )
        );
    }

    function usdtTransferCoreHash(StreamGTypes.UsdtTransferIntent calldata intent) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                StreamGTypes.USDT_TRANSFER_CORE_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.owner,
                intent.expectedRoot,
                intent.token,
                intent.recipient,
                intent.amount,
                intent.authorizationMode,
                intent.maxFee,
                intent.nonce,
                intent.deadline
            )
        );
    }

    function usdtTransferIntentStructHash(StreamGTypes.UsdtTransferIntent calldata intent)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                StreamGTypes.USDT_TRANSFER_INTENT_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.owner,
                intent.expectedRoot,
                intent.token,
                intent.recipient,
                intent.amount,
                intent.authorizationMode,
                intent.transferAuthorizationDigest,
                intent.maxFee,
                intent.feeQuoteHash,
                intent.nonce,
                intent.deadline
            )
        );
    }
}

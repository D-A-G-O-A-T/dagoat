// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {StreamGTypes} from "../StreamGTypes.sol";
import {WalletSponsorshipRegistry} from "../WalletSponsorshipRegistry.sol";
import {GoatCoin} from "../GoatCoin.sol";
import {StreamGHashes} from "./StreamGHashes.sol";
import {StreamGCommon} from "./StreamGCommon.sol";
import {StreamGTransfers} from "./StreamGTransfers.sol";

/// `GoatRelayGateway.executeGoatTransfer` / `.executeUsdtTransfer` bodies,
/// lifted verbatim. `public` on purpose (DELEGATECALL preserves `address(this)`,
/// storage and the EIP-712 domain) — see the note in `StreamGCommon.sol`.
library StreamGXfer {
    error ZeroAddress();
    error ExpiredDeadline();
    error RootNotRegistered();
    error ClusterSuspended();
    error InvalidFeeFields();
    error InvalidTransferAuth();
    error InvalidQuote();
    error BadGoatPermit();
    error BadIntentSignature();
    error UnexpectedBalanceDelta();

    function executeGoat(
        StreamGCommon.Ctx memory ctx,
        StreamGTypes.GoatTransferIntent calldata intent,
        StreamGTypes.FeeQuote calldata quote,
        StreamGTypes.Eip2612Authorization calldata goatPermit,
        StreamGTypes.TokenAuthorization calldata feeAuthorization,
        bytes calldata intentSignature,
        bytes calldata quoteSignature,
        mapping(bytes32 => bool) storage intentUsed,
        mapping(address => mapping(bytes32 => uint256)) storage actionNonces,
        mapping(bytes32 => bool) storage quoteUsed
    ) public returns (uint256 feeAmount) {
        WalletSponsorshipRegistry sponsorship = WalletSponsorshipRegistry(ctx.sponsorship);

        if (block.timestamp >= intent.deadline) revert ExpiredDeadline();
        if (intent.owner == address(0) || intent.expectedRoot == address(0) || intent.recipient == address(0)) {
            revert ZeroAddress();
        }

        address liveRoot = sponsorship.primaryOf(intent.owner);
        if (liveRoot == address(0) || liveRoot != intent.expectedRoot) revert RootNotRegistered();
        if (sponsorship.primaryOf(intent.expectedRoot) != intent.expectedRoot) revert RootNotRegistered();
        if (sponsorship.suspendedClusters(intent.expectedRoot)) revert ClusterSuspended();

        if (intent.feeAuthorizationMode != feeAuthorization.mode) revert InvalidFeeFields();
        // Hoisted so the mode check still reverts before the (pure) core hash, as before.
        uint256 requiredCap = StreamGCommon.capabilityForMode(feeAuthorization.mode);

        feeAmount = StreamGCommon.validateAndConsumeQuote(
            quoteUsed,
            ctx,
            StreamGCommon.QuoteCheck({
                actionType: StreamGTypes.ACTION_GOAT_TRANSFER,
                payer: intent.owner,
                feeToken: intent.feeToken,
                feeTokenConfigHash: intent.feeTokenConfigHash,
                deploymentManifestHash: intent.deploymentManifestHash,
                maxFee: intent.maxFee,
                actionCoreHash: StreamGHashes.goatTransferCoreHash(intent),
                requiredCapability: requiredCap
            }),
            quote,
            quoteSignature
        );
        bytes32 feeQuoteHash = StreamGCommon.digest(ctx.domainSeparator, StreamGHashes.feeQuoteStructHash(quote));
        if (intent.feeQuoteHash != feeQuoteHash) revert InvalidQuote();
        if (quote.feeToken != intent.feeToken) revert InvalidQuote();

        if (
            !StreamGCommon.goatPermitMatches(
                ctx.goat, goatPermit, intent.owner, address(this), intent.amount, intent.goatPermitDigest
            )
        ) {
            revert BadGoatPermit();
        }

        bytes32 intentDigest =
            StreamGCommon.digest(ctx.domainSeparator, StreamGHashes.goatTransferIntentStructHash(intent));
        address signer = ECDSA.recover(intentDigest, intentSignature);
        if (signer != intent.owner) revert BadIntentSignature();

        StreamGCommon.markIntentAndNonce(
            intentUsed, actionNonces, intent.intentId, intent.owner, StreamGTypes.ACTION_GOAT_TRANSFER, intent.nonce
        );

        GoatCoin goat = GoatCoin(ctx.goat);
        goat.permit(
            goatPermit.owner,
            goatPermit.spender,
            goatPermit.value,
            goatPermit.deadline,
            goatPermit.v,
            goatPermit.r,
            goatPermit.s
        );
        uint256 ownerBefore = goat.balanceOf(intent.owner);
        uint256 recipientBefore = goat.balanceOf(intent.recipient);
        goat.transferFrom(intent.owner, intent.recipient, intent.amount);
        if (goat.balanceOf(intent.owner) != ownerBefore - intent.amount) revert UnexpectedBalanceDelta();
        if (goat.balanceOf(intent.recipient) != recipientBefore + intent.amount) revert UnexpectedBalanceDelta();

        StreamGCommon.collectFee(
            ctx,
            intent.owner,
            intent.feeToken,
            feeAmount,
            feeAuthorization,
            intent.intentId,
            StreamGTypes.ACTION_GOAT_TRANSFER
        );
    }

    function executeUsdt(
        StreamGCommon.Ctx memory ctx,
        StreamGTypes.UsdtTransferIntent calldata intent,
        StreamGTypes.FeeQuote calldata quote,
        StreamGTypes.TokenAuthorization calldata transferAuthorization,
        bytes calldata intentSignature,
        bytes calldata quoteSignature,
        mapping(bytes32 => bool) storage intentUsed,
        mapping(address => mapping(bytes32 => uint256)) storage actionNonces,
        mapping(bytes32 => bool) storage quoteUsed
    ) public returns (uint256 feeAmount) {
        WalletSponsorshipRegistry sponsorship = WalletSponsorshipRegistry(ctx.sponsorship);

        if (block.timestamp >= intent.deadline) revert ExpiredDeadline();
        if (
            intent.owner == address(0) || intent.expectedRoot == address(0) || intent.recipient == address(0)
                || intent.token == address(0)
        ) {
            revert ZeroAddress();
        }

        address liveRoot = sponsorship.primaryOf(intent.owner);
        if (liveRoot == address(0) || liveRoot != intent.expectedRoot) revert RootNotRegistered();
        if (sponsorship.primaryOf(intent.expectedRoot) != intent.expectedRoot) revert RootNotRegistered();
        if (sponsorship.suspendedClusters(intent.expectedRoot)) revert ClusterSuspended();

        if (intent.authorizationMode != transferAuthorization.mode) revert InvalidTransferAuth();
        // Hoisted so the mode check still reverts before the (pure) core hash, as before.
        uint256 requiredCap = StreamGCommon.capabilityForMode(transferAuthorization.mode);

        feeAmount = StreamGCommon.validateAndConsumeQuote(
            quoteUsed,
            ctx,
            StreamGCommon.QuoteCheck({
                actionType: StreamGTypes.ACTION_USDT_TRANSFER,
                payer: intent.owner,
                feeToken: intent.token,
                feeTokenConfigHash: intent.feeTokenConfigHash,
                deploymentManifestHash: intent.deploymentManifestHash,
                maxFee: intent.maxFee,
                actionCoreHash: StreamGHashes.usdtTransferCoreHash(intent),
                requiredCapability: requiredCap
            }),
            quote,
            quoteSignature
        );
        bytes32 feeQuoteHash = StreamGCommon.digest(ctx.domainSeparator, StreamGHashes.feeQuoteStructHash(quote));
        if (intent.feeQuoteHash != feeQuoteHash) revert InvalidQuote();
        if (quote.feeToken != intent.token) revert InvalidQuote();

        bytes32 intentDigest =
            StreamGCommon.digest(ctx.domainSeparator, StreamGHashes.usdtTransferIntentStructHash(intent));
        address signer = ECDSA.recover(intentDigest, intentSignature);
        if (signer != intent.owner) revert BadIntentSignature();

        StreamGCommon.markIntentAndNonce(
            intentUsed, actionNonces, intent.intentId, intent.owner, StreamGTypes.ACTION_USDT_TRANSFER, intent.nonce
        );

        StreamGTransfers.executeUsdtTransferWithAuth(
            intent, transferAuthorization, feeAmount, ctx.feeSafe, ctx.domainSeparator
        );
    }
}

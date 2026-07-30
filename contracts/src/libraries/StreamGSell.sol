// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {StreamGTypes} from "../StreamGTypes.sol";
import {WalletSponsorshipRegistry} from "../WalletSponsorshipRegistry.sol";
import {SponsoredBuyDesk} from "../SponsoredBuyDesk.sol";
import {StreamGHashes} from "./StreamGHashes.sol";
import {StreamGCommon} from "./StreamGCommon.sol";

/// `GoatRelayGateway.executeSponsoredSell` body, lifted verbatim.
/// `public` on purpose (DELEGATECALL preserves `address(this)`, storage and the
/// EIP-712 domain) — see the note in `StreamGCommon.sol`.
library StreamGSell {
    error ZeroAddress();
    error ExpiredDeadline();
    error DeskNotConfigured();
    error DeskMismatch();
    error DeskCodeHashMismatch();
    error RootNotRegistered();
    error ClusterSuspended();
    error InvalidQuote();
    error BadGoatPermit();
    error BadIntentSignature();

    function execute(
        StreamGCommon.Ctx memory ctx,
        address desk,
        bytes32 deskCodeHash,
        StreamGTypes.SellIntent calldata intent,
        StreamGTypes.FeeQuote calldata quote,
        StreamGTypes.Eip2612Authorization calldata goatPermit,
        bytes calldata intentSignature,
        bytes calldata quoteSignature,
        mapping(bytes32 => bool) storage intentUsed,
        mapping(address => mapping(bytes32 => uint256)) storage actionNonces,
        mapping(bytes32 => bool) storage quoteUsed
    ) public returns (uint256 feeAmount, uint256 netUsdtOut) {
        WalletSponsorshipRegistry sponsorship = WalletSponsorshipRegistry(ctx.sponsorship);

        if (block.timestamp >= intent.deadline) revert ExpiredDeadline();
        if (intent.seller == address(0) || intent.expectedRoot == address(0) || intent.desk == address(0)) {
            revert ZeroAddress();
        }
        if (desk == address(0)) revert DeskNotConfigured();
        if (intent.desk != desk) revert DeskMismatch();
        if (intent.desk.codehash != deskCodeHash) revert DeskCodeHashMismatch();

        address liveRoot = sponsorship.primaryOf(intent.seller);
        if (liveRoot == address(0) || liveRoot != intent.expectedRoot) revert RootNotRegistered();
        if (sponsorship.primaryOf(intent.expectedRoot) != intent.expectedRoot) revert RootNotRegistered();
        if (sponsorship.suspendedClusters(intent.expectedRoot)) revert ClusterSuspended();

        // Fee token for sell quotes is the desk payout token with CAP_SELL_SPLIT.
        // Quote.feeToken is validated by the generic helper; intent does not carry feeToken.
        feeAmount = StreamGCommon.validateAndConsumeQuote(
            quoteUsed,
            ctx,
            StreamGCommon.QuoteCheck({
                actionType: StreamGTypes.ACTION_SPONSORED_SELL,
                payer: intent.seller,
                feeToken: quote.feeToken,
                feeTokenConfigHash: intent.feeTokenConfigHash,
                deploymentManifestHash: intent.deploymentManifestHash,
                maxFee: intent.maxFee,
                actionCoreHash: StreamGHashes.sellCoreHash(intent),
                requiredCapability: StreamGTypes.CAP_SELL_SPLIT
            }),
            quote,
            quoteSignature
        );
        bytes32 feeQuoteHash = StreamGCommon.digest(ctx.domainSeparator, StreamGHashes.feeQuoteStructHash(quote));
        if (intent.feeQuoteHash != feeQuoteHash) revert InvalidQuote();

        if (
            !StreamGCommon.goatPermitMatches(
                ctx.goat, goatPermit, intent.seller, intent.desk, intent.goatAmount, intent.goatPermitDigest
            )
        ) {
            revert BadGoatPermit();
        }

        bytes32 intentDigest = StreamGCommon.digest(ctx.domainSeparator, StreamGHashes.sellIntentStructHash(intent));
        address signer = ECDSA.recover(intentDigest, intentSignature);
        if (signer != intent.seller) revert BadIntentSignature();

        StreamGCommon.markIntentAndNonce(
            intentUsed,
            actionNonces,
            intent.intentId,
            intent.seller,
            StreamGTypes.ACTION_SPONSORED_SELL,
            intent.nonce
        );

        address root;
        (root,, netUsdtOut) = SponsoredBuyDesk(intent.desk).sellFor(
            intent.seller, intent.expectedRoot, intent.goatAmount, intent.minNetUsdtOut, feeAmount, goatPermit
        );
        if (root != intent.expectedRoot) revert RootNotRegistered();
    }
}

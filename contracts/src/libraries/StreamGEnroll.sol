// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {StreamGTypes} from "../StreamGTypes.sol";
import {IEnrollmentRegistryV1} from "../interfaces/IEnrollmentRegistryV1.sol";
import {WalletSponsorshipRegistry} from "../WalletSponsorshipRegistry.sol";
import {StreamGHashes} from "./StreamGHashes.sol";
import {StreamGCommon} from "./StreamGCommon.sol";

/// `GoatRelayGateway.executeSponsoredEnrollment` body, lifted verbatim.
///
/// `public` on purpose — an `internal` library function is inlined into the
/// caller and would save zero bytes. Reached by `DELEGATECALL`, so
/// `address(this)` is still the gateway: every storage write lands in the
/// gateway's slots, every external call is made *as* the gateway, and the
/// EIP-712 domain separator (derived by OpenZeppelin from `address(this)`) is
/// unchanged, so all pinned digests survive.
///
/// The effects ordering the reconciler keys on is preserved exactly:
/// `markIntentAndNonce` -> `enrollV1OrAcceptFrontRun` -> `linkSecondary` ->
/// fee collected LAST on the token path. The gateway emits
/// `SponsoredEnrollmentExecuted` on return, i.e. still after all of them.
library StreamGEnroll {
    error ZeroAddress();
    error ExpiredDeadline();
    error InvalidFeeFields();
    error InvalidV1Enrollment();
    error RootNotRegistered();
    error ClusterSuspended();
    error ControllerMismatch();
    error EpochMismatch();
    error BadV1Signature();
    error BadLinkSignature();
    error BadSponsorSignature();
    error NotController();
    error InvalidQuote();
    error UnsupportedFeeMode();

    function execute(
        StreamGCommon.Ctx memory ctx,
        StreamGTypes.SponsorEnrollment calldata intent,
        StreamGTypes.FeeQuote calldata quote,
        StreamGTypes.V1Enrollment calldata v1Enrollment,
        StreamGTypes.LinkSecondary calldata link,
        StreamGTypes.RootAuthorization calldata rootAuthorization,
        StreamGTypes.TokenAuthorization calldata feeAuthorization,
        bytes calldata sponsorSignature,
        bytes calldata quoteSignature,
        bytes calldata linkSignature,
        bytes calldata rootAuthorizationSignature,
        mapping(bytes32 => bool) storage intentUsed,
        mapping(address => mapping(bytes32 => uint256)) storage actionNonces,
        mapping(bytes32 => bool) storage quoteUsed
    ) public returns (uint256 feeAmount) {
        WalletSponsorshipRegistry sponsorship = WalletSponsorshipRegistry(ctx.sponsorship);

        if (block.timestamp >= intent.deadline) revert ExpiredDeadline();
        if (intent.secondary == address(0) || intent.root == address(0)) revert ZeroAddress();
        if (intent.secondary != link.secondary || intent.root != link.root) revert InvalidFeeFields();
        if (v1Enrollment.wallet != intent.secondary) revert InvalidV1Enrollment();

        address liveController = sponsorship.controllerOf(intent.root);
        bool rootRegistered = sponsorship.primaryOf(intent.root) == intent.root;
        if (!rootRegistered) revert RootNotRegistered();
        if (sponsorship.suspendedClusters(intent.root)) revert ClusterSuspended();
        if (liveController == address(0)) revert ControllerMismatch();
        if (intent.controller != liveController) revert ControllerMismatch();
        if (intent.controllerEpoch != sponsorship.controllerEpoch(intent.root)) revert EpochMismatch();

        bytes32 enrollDigest =
            _v1EnrollDigest(ctx.enrollmentRegistry, v1Enrollment.wallet, v1Enrollment.nonce, v1Enrollment.deadline);
        if (enrollDigest != intent.enrollDigest) revert InvalidV1Enrollment();
        address enrollSigner = ECDSA.recover(enrollDigest, v1Enrollment.signature);
        if (enrollSigner != intent.secondary) revert BadV1Signature();

        bytes32 linkDigest = _linkDigest(sponsorship, link);
        if (linkDigest != intent.linkDigest) revert BadLinkSignature();
        address linkSigner = ECDSA.recover(linkDigest, linkSignature);
        if (linkSigner != intent.secondary) revert BadLinkSignature();

        if (intent.rootAuthorizationDigest != bytes32(0)) revert InvalidFeeFields();
        if (
            rootAuthorization.root != address(0) || rootAuthorization.secondary != address(0)
                || rootAuthorization.enrollDigest != bytes32(0) || rootAuthorization.linkDigest != bytes32(0)
                || rootAuthorization.nonce != 0 || rootAuthorization.deadline != 0
                || rootAuthorizationSignature.length != 0
        ) {
            revert InvalidFeeFields();
        }

        bool ethPath = _isDirectEthEnrollment(intent);

        if (ethPath) {
            if (msg.sender != intent.controller) revert NotController();
            if (quoteSignature.length != 0) revert InvalidQuote();
            if (
                quote.quoteId != bytes32(0) || quote.actionType != bytes32(0) || quote.actionCoreHash != bytes32(0)
                    || quote.deploymentManifestHash != bytes32(0) || quote.feeTokenConfigHash != bytes32(0)
                    || quote.feeScheduleHash != bytes32(0) || quote.payer != address(0)
                    || quote.feeToken != address(0) || quote.feeAmount != 0 || quote.feeRecipient != address(0)
                    || quote.validAfter != 0 || quote.validUntil != 0
            ) {
                revert InvalidQuote();
            }
            if (feeAuthorization.mode != uint8(StreamGTypes.AuthorizationMode.NONE)) revert InvalidFeeFields();
        } else {
            feeAmount = StreamGCommon.validateAndConsumeQuote(
                quoteUsed,
                ctx,
                StreamGCommon.QuoteCheck({
                    actionType: StreamGTypes.ACTION_SPONSORED_ENROLLMENT,
                    payer: intent.controller,
                    feeToken: intent.feeToken,
                    feeTokenConfigHash: intent.feeTokenConfigHash,
                    deploymentManifestHash: intent.deploymentManifestHash,
                    maxFee: intent.maxFee,
                    actionCoreHash: StreamGHashes.sponsorEnrollmentCoreHash(intent),
                    requiredCapability: StreamGTypes.CAP_EIP2612
                }),
                quote,
                quoteSignature
            );
            bytes32 feeQuoteHash = StreamGCommon.digest(ctx.domainSeparator, StreamGHashes.feeQuoteStructHash(quote));
            if (intent.feeQuoteHash != feeQuoteHash) revert InvalidQuote();
            if (intent.feeAuthorizationMode != uint8(StreamGTypes.AuthorizationMode.EIP2612)) {
                revert UnsupportedFeeMode();
            }
        }

        bytes32 sponsorDigest =
            StreamGCommon.digest(ctx.domainSeparator, StreamGHashes.sponsorEnrollmentStructHash(intent));
        address sponsor = ECDSA.recover(sponsorDigest, sponsorSignature);
        if (sponsor != intent.controller) revert BadSponsorSignature();

        // Effects: consume gateway intent/nonce before external calls (rollback on failure).
        StreamGCommon.markIntentAndNonce(
            intentUsed,
            actionNonces,
            intent.intentId,
            intent.controller,
            StreamGTypes.ACTION_SPONSORED_ENROLLMENT,
            intent.nonce
        );

        // V1 enrollment first: WalletSponsorshipRegistry.linkSecondary requires live V1 eligibility.
        _enrollV1OrAcceptFrontRun(ctx.enrollmentRegistry, v1Enrollment);

        // Link secondary (gateway-only) after V1 eligibility is satisfied.
        StreamGTypes.RootAuthorization memory zeroAuth;
        sponsorship.linkSecondary(link, linkSignature, zeroAuth, "");

        // Collect USDT fee last on token path.
        if (!ethPath) {
            if (feeAuthorization.mode != uint8(StreamGTypes.AuthorizationMode.EIP2612)) revert UnsupportedFeeMode();
            StreamGCommon.collectEip2612(
                ctx.feeSafe, intent.controller, intent.feeToken, feeAmount, feeAuthorization.eip2612
            );
        }
    }

    function _isDirectEthEnrollment(StreamGTypes.SponsorEnrollment calldata intent) private pure returns (bool) {
        return intent.feeToken == address(0)
            && intent.feeAuthorizationMode == uint8(StreamGTypes.AuthorizationMode.NONE)
            && intent.feeAuthorizationDigest == bytes32(0)
            && intent.feeQuoteHash == bytes32(0)
            && intent.maxFee == 0
            && intent.feeTokenConfigHash == bytes32(0);
    }

    function _v1EnrollDigest(address registry, address wallet, uint256 nonce, uint256 deadline)
        private
        view
        returns (bytes32)
    {
        IEnrollmentRegistryV1 r = IEnrollmentRegistryV1(registry);
        bytes32 domain = r.DOMAIN_SEPARATOR();
        bytes32 structHash = keccak256(abi.encode(r.ENROLL_TYPEHASH(), wallet, nonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function _linkDigest(WalletSponsorshipRegistry sponsorship, StreamGTypes.LinkSecondary calldata link)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                sponsorship.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        StreamGTypes.LINK_SECONDARY_TYPEHASH, link.root, link.secondary, link.nonce, link.deadline
                    )
                )
            )
        );
    }

    function _enrollV1OrAcceptFrontRun(address registry, StreamGTypes.V1Enrollment calldata v1Enrollment) private {
        IEnrollmentRegistryV1 r = IEnrollmentRegistryV1(registry);
        address wallet = v1Enrollment.wallet;
        uint256 liveNonce = r.nonces(wallet);
        bool enrolled = r.enrolled(wallet);
        if (r.blacklisted(wallet)) revert InvalidV1Enrollment();

        if (!enrolled && liveNonce == v1Enrollment.nonce) {
            r.enrollSelfWithSignature(wallet, v1Enrollment.deadline, v1Enrollment.signature);
            return;
        }
        if (enrolled && liveNonce == v1Enrollment.nonce + 1) {
            bytes32 d = _v1EnrollDigest(registry, wallet, v1Enrollment.nonce, v1Enrollment.deadline);
            address signer = ECDSA.recover(d, v1Enrollment.signature);
            if (signer != wallet) revert BadV1Signature();
            return;
        }
        revert InvalidV1Enrollment();
    }
}

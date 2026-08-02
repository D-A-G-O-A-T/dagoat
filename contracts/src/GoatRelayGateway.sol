// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {IERC20Permit} from "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {StreamGTypes} from "./StreamGTypes.sol";
import {IEnrollmentRegistryV1} from "./interfaces/IEnrollmentRegistryV1.sol";
import {FeeTokenRegistry} from "./FeeTokenRegistry.sol";
import {WalletSponsorshipRegistry} from "./WalletSponsorshipRegistry.sol";
import {GoatCoin} from "./GoatCoin.sol";
import {StreamGHashes} from "./libraries/StreamGHashes.sol";
import {StreamGCommon} from "./libraries/StreamGCommon.sol";
import {StreamGEnroll} from "./libraries/StreamGEnroll.sol";
import {StreamGSell} from "./libraries/StreamGSell.sol";
import {StreamGXfer} from "./libraries/StreamGXfer.sol";

/// Stream G action-specific EIP-712 gateway.
/// Task 6: shared preamble storage + secondaryEnrollmentNonceSnapshot (Hazard 2).
/// Task 7: executeSponsoredEnrollment (ETH + USDT).
/// Task 8: executeSponsoredSell + GOAT/USDT transfers.
contract GoatRelayGateway is EIP712, ReentrancyGuard {
    error NotPolicySafe();
    error ZeroAddress();
    error AlreadyActivated();
    error NotActivated();
    error Paused();
    error UnknownActionType();
    error IntentAlreadyUsed();
    error ZeroIntentId();
    error BadActionNonce();
    error ExpiredDeadline();
    error RootNotRegistered();
    error ClusterSuspended();
    error ConfigHashMismatch();
    error TokenNotAuthorized();
    error BadSponsorSignature();
    error BadQuoteSignature();
    error BadLinkSignature();
    error BadV1Signature();
    error InvalidFeeFields();
    error InvalidQuote();
    error QuoteAlreadyUsed();
    error ControllerMismatch();
    error EpochMismatch();
    error NotController();
    error InvalidV1Enrollment();
    error FeeExceedsMax();
    error UnsupportedFeeMode();
    error DeskNotConfigured();
    error DeskMismatch();
    error DeskCodeHashMismatch();
    error DeskAlreadySet();
    error ProxyAlreadySet();
    error BadIntentSignature();
    error BadGoatPermit();
    error BadPriorAllowance();
    error InvalidTransferAuth();
    error UnexpectedBalanceDelta();

    IEnrollmentRegistryV1 public immutable enrollmentRegistry;
    FeeTokenRegistry public immutable feeTokenRegistry;
    WalletSponsorshipRegistry public immutable sponsorship;
    GoatCoin public immutable goat;
    address public immutable policySafe;
    address public immutable feeSafe;

    bool public activated;
    bool public paused = true;
    bytes32 public feeScheduleHash;
    address public quoteSigner;
    address public sponsoredBuyDesk;
    bytes32 public sponsoredBuyDeskCodeHash;

    /// Residential-proxy settlement bindings. Plain `address`, deliberately not
    /// the contract types: the gateway calls neither today, and importing the
    /// proxy sources here would pull their type machinery into the largest
    /// contract in the tree for no behaviour. They are read by operators and by
    /// deploy scripts wiring the two trees together, not by any hot path, so
    /// they are also NOT members of `_ctx()`.
    address public proxyRevenueSettlement;
    address public proxyConsumerRegistry;

    /// actionNonces[signer][actionType] — sequential gateway action nonces.
    mapping(address => mapping(bytes32 => uint256)) public actionNonces;
    /// intentUsed[intentId] — single-use intent ids.
    mapping(bytes32 => bool) public intentUsed;
    /// quoteUsed[quoteId] — single-use fee quotes.
    mapping(bytes32 => bool) public quoteUsed;

    event Activated(bytes32 deploymentManifestHash, bytes32 feeScheduleHash);
    event FeeScheduleHashSet(bytes32 feeScheduleHash);
    event PausedSet(bool paused);
    event QuoteSignerSet(address indexed quoteSigner);
    event SponsoredEnrollmentExecuted(
        bytes32 indexed intentId,
        address indexed root,
        address indexed secondary,
        address controller,
        address feeToken,
        uint256 feeAmount
    );
    event SponsoredBuyDeskSet(address indexed desk, bytes32 codeHash);
    event ProxyRevenueSettlementSet(address indexed settlement);
    event ProxyConsumerRegistrySet(address indexed registry);
    event SponsoredSellExecuted(
        bytes32 indexed intentId,
        address indexed seller,
        address indexed root,
        address desk,
        uint256 goatAmount,
        uint256 feeAmount,
        uint256 netUsdtOut
    );
    event GoatTransferExecuted(
        bytes32 indexed intentId,
        address indexed owner,
        address indexed recipient,
        address root,
        uint256 amount,
        address feeToken,
        uint256 feeAmount
    );
    event UsdtTransferExecuted(
        bytes32 indexed intentId,
        address indexed owner,
        address indexed recipient,
        address root,
        address token,
        uint256 amount,
        uint256 feeAmount,
        uint8 authorizationMode
    );

    modifier onlyPolicy() {
        if (msg.sender != policySafe) revert NotPolicySafe();
        _;
    }

    constructor(
        address enrollmentRegistry_,
        address feeTokenRegistry_,
        address sponsorship_,
        address goat_,
        address policySafe_,
        address feeSafe_
    ) EIP712("GoatRelayGateway", "1") {
        if (
            enrollmentRegistry_ == address(0) || feeTokenRegistry_ == address(0) || sponsorship_ == address(0)
                || goat_ == address(0) || policySafe_ == address(0) || feeSafe_ == address(0)
        ) {
            revert ZeroAddress();
        }
        enrollmentRegistry = IEnrollmentRegistryV1(enrollmentRegistry_);
        feeTokenRegistry = FeeTokenRegistry(feeTokenRegistry_);
        sponsorship = WalletSponsorshipRegistry(sponsorship_);
        goat = GoatCoin(goat_);
        policySafe = policySafe_;
        feeSafe = feeSafe_;
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function setFeeScheduleHash(bytes32 feeScheduleHash_) external onlyPolicy {
        feeScheduleHash = feeScheduleHash_;
        emit FeeScheduleHashSet(feeScheduleHash_);
    }

    function setPaused(bool paused_) external onlyPolicy {
        paused = paused_;
        emit PausedSet(paused_);
    }

    function setQuoteSigner(address quoteSigner_) external onlyPolicy {
        if (quoteSigner_ == address(0)) revert ZeroAddress();
        quoteSigner = quoteSigner_;
        emit QuoteSignerSet(quoteSigner_);
    }

    /// One-shot approved SponsoredBuyDesk binding. Desk is not a user-selectable target.
    function setSponsoredBuyDesk(address desk_) external onlyPolicy {
        if (desk_ == address(0)) revert ZeroAddress();
        if (sponsoredBuyDesk != address(0)) revert DeskAlreadySet();
        bytes32 codeHash = desk_.codehash;
        if (codeHash == bytes32(0)) revert DeskMismatch();
        sponsoredBuyDesk = desk_;
        sponsoredBuyDeskCodeHash = codeHash;
        emit SponsoredBuyDeskSet(desk_, codeHash);
    }

    /// One-shot ProxyRevenueSettlement binding. Recorded for operators and for
    /// the deploy scripts that wire the proxy tree to this gateway; no code
    /// path in this contract calls it.
    function setProxyRevenueSettlement(address settlement_) external onlyPolicy {
        if (settlement_ == address(0)) revert ZeroAddress();
        if (proxyRevenueSettlement != address(0)) revert ProxyAlreadySet();
        proxyRevenueSettlement = settlement_;
        emit ProxyRevenueSettlementSet(settlement_);
    }

    /// One-shot ProxyConsumerRegistry binding. Same terms as above.
    function setProxyConsumerRegistry(address registry_) external onlyPolicy {
        if (registry_ == address(0)) revert ZeroAddress();
        if (proxyConsumerRegistry != address(0)) revert ProxyAlreadySet();
        proxyConsumerRegistry = registry_;
        emit ProxyConsumerRegistrySet(registry_);
    }

    /// One-shot activation after children bind and Policy Safe precommits hashes.
    function activate() external onlyPolicy {
        if (activated) revert AlreadyActivated();
        if (feeScheduleHash == bytes32(0)) revert ConfigHashMismatch();
        if (feeTokenRegistry.activeManifestHash() == bytes32(0)) revert ConfigHashMismatch();
        // Children must already be bound to this gateway.
        if (sponsorship.gateway() != address(this)) revert ConfigHashMismatch();
        activated = true;
        // Activation may leave paused=true; policy unpauses separately via setPaused(false).
        emit Activated(feeTokenRegistry.activeManifestHash(), feeScheduleHash);
    }

    // -------------------------------------------------------------------------
    // Hazard 2: advisory same-state nonce snapshot (not execution authority)
    // -------------------------------------------------------------------------

    /// Secondary enrollment convenience wrapper (design §10.3).
    function secondaryEnrollmentNonceSnapshot(address root, address secondary, address feeToken)
        external
        view
        returns (StreamGTypes.NonceSnapshot memory)
    {
        return _snapshot(
            StreamGTypes.ACTION_SPONSORED_ENROLLMENT,
            /*signer*/
            sponsorship.controllerOf(root) == address(0) ? root : sponsorship.controllerOf(root),
            root,
            secondary,
            feeToken
        );
    }

    /// General advisory snapshot. Rejects unknown action types.
    function nonceSnapshot(bytes32 actionType, address signer, address root, address secondary, address feeToken)
        external
        view
        returns (StreamGTypes.NonceSnapshot memory)
    {
        if (!_isKnownAction(actionType)) revert UnknownActionType();
        return _snapshot(actionType, signer, root, secondary, feeToken);
    }

    /// The recognised action types — the set with a reserved nonce namespace
    /// and a fee-schedule row. Recognition is NOT sponsorability: the three
    /// `ACTION_PROXY_*` rows have no `execute*` entrypoint on this gateway, so
    /// recognising them widens `nonceSnapshot` and nothing else.
    function _isKnownAction(bytes32 actionType) internal pure returns (bool) {
        return actionType == StreamGTypes.ACTION_SPONSORED_ENROLLMENT
            || actionType == StreamGTypes.ACTION_SPONSORED_SELL || actionType == StreamGTypes.ACTION_GOAT_TRANSFER
            || actionType == StreamGTypes.ACTION_USDT_TRANSFER || actionType == StreamGTypes.ACTION_PROXY_CLAIM
            || actionType == StreamGTypes.ACTION_PROXY_PROPOSE_BATCH
            || actionType == StreamGTypes.ACTION_PROXY_CHALLENGE_BATCH;
    }

    function _snapshot(bytes32 actionType, address signer, address root, address secondary, address feeToken)
        internal
        view
        returns (StreamGTypes.NonceSnapshot memory snap)
    {
        // Snapshot is advisory only — never consumes nonces/intents.
        address controller = sponsorship.controllerOf(root);
        if (controller == address(0)) {
            // Unregistered root: controller fields may still be present as zeros.
            controller = address(0);
        }

        uint32 mask;
        snap.blockNumber = uint64(block.number);

        // Action nonce for signer+actionType
        snap.actionNonce = actionNonces[signer][actionType];
        mask |= StreamGTypes.SNAP_ACTION_NONCE;

        // V1 enroll nonce for secondary (or signer if secondary is zero)
        address v1Subject = secondary == address(0) ? signer : secondary;
        snap.v1EnrollNonce = enrollmentRegistry.nonces(v1Subject);
        mask |= StreamGTypes.SNAP_V1_ENROLL_NONCE;

        // Link nonce is per secondary
        if (secondary != address(0)) {
            snap.linkNonce = sponsorship.linkNonces(secondary);
            mask |= StreamGTypes.SNAP_LINK_NONCE;
        }

        // Root registration / rotation / controller
        if (root != address(0)) {
            snap.rootRegistrationNonce = sponsorship.rootRegistrationNonces(root);
            mask |= StreamGTypes.SNAP_ROOT_REG_NONCE;
            snap.rotationNonce = sponsorship.rotationNonces(root);
            mask |= StreamGTypes.SNAP_ROTATION_NONCE;
            snap.controllerEpoch = sponsorship.controllerEpoch(root);
            snap.controller = sponsorship.controllerOf(root);
            mask |= StreamGTypes.SNAP_CONTROLLER;
        }

        // GOAT permit nonce for controller/signer (enrollment fee payer is controller/root)
        address goatOwner = controller != address(0) ? controller : (root != address(0) ? root : signer);
        snap.goatPermitNonce = goat.nonces(goatOwner);
        mask |= StreamGTypes.SNAP_GOAT_PERMIT_NONCE;

        // Fee-token EIP-2612 permit nonce only when active CAP_EIP2612
        snap.deploymentManifestHash = feeTokenRegistry.activeManifestHash();
        snap.feeScheduleHash = feeScheduleHash;
        mask |= StreamGTypes.SNAP_CONFIG_HASHES;

        if (feeToken != address(0) && feeTokenRegistry.isTokenAuthorized(feeToken, StreamGTypes.CAP_EIP2612)) {
            // Safe: authorized EIP-2612 tokens implement nonces(address)
            snap.feeTokenPermitNonce = IERC20Permit(feeToken).nonces(goatOwner);
            snap.feeTokenConfigHash = feeTokenRegistry.getTokenConfigHash(feeToken);
            mask |= StreamGTypes.SNAP_FEE_TOKEN_PERMIT_NONCE;
        } else {
            snap.feeTokenPermitNonce = 0;
            snap.feeTokenConfigHash = bytes32(0);
            // no SNAP_FEE_TOKEN_PERMIT_NONCE bit
        }

        snap.presentMask = mask;
    }

    // -------------------------------------------------------------------------
    // Shared preamble helpers for later action tasks (storage already present)
    // -------------------------------------------------------------------------

    function _requireLive() internal view {
        if (!activated) revert NotActivated();
        if (paused) revert Paused();
    }

    function _requireKnownAction(bytes32 actionType) internal pure {
        if (!_isKnownAction(actionType)) revert UnknownActionType();
    }

    // -------------------------------------------------------------------------
    // Task 7: sponsored enrollment (ETH + USDT)
    // -------------------------------------------------------------------------

    function executeSponsoredEnrollment(
        StreamGTypes.SponsorEnrollment calldata intent,
        StreamGTypes.FeeQuote calldata quote,
        StreamGTypes.V1Enrollment calldata v1Enrollment,
        StreamGTypes.LinkSecondary calldata link,
        StreamGTypes.RootAuthorization calldata rootAuthorization,
        StreamGTypes.TokenAuthorization calldata feeAuthorization,
        bytes calldata sponsorSignature,
        bytes calldata quoteSignature,
        bytes calldata linkSignature,
        bytes calldata rootAuthorizationSignature
    ) external nonReentrant {
        _requireLive();
        // Body lives in StreamGEnroll (public library, DELEGATECALL — `address(this)`,
        // storage, msg.sender and the EIP-712 domain are all preserved). The effects
        // order is unchanged inside the library; the event is still emitted last.
        uint256 feeAmount = StreamGEnroll.execute(
            _ctx(),
            intent,
            quote,
            v1Enrollment,
            link,
            rootAuthorization,
            feeAuthorization,
            sponsorSignature,
            quoteSignature,
            linkSignature,
            rootAuthorizationSignature,
            intentUsed,
            actionNonces,
            quoteUsed
        );

        emit SponsoredEnrollmentExecuted(
            intent.intentId, intent.root, intent.secondary, intent.controller, intent.feeToken, feeAmount
        );
    }

    /// Gateway immutables + config the libraries cannot read for themselves.
    function _ctx() internal view returns (StreamGCommon.Ctx memory c) {
        c.enrollmentRegistry = address(enrollmentRegistry);
        c.feeTokenRegistry = address(feeTokenRegistry);
        c.sponsorship = address(sponsorship);
        c.goat = address(goat);
        c.feeSafe = feeSafe;
        c.quoteSigner = quoteSigner;
        c.feeScheduleHash = feeScheduleHash;
        c.domainSeparator = _domainSeparatorV4();
    }

    // -------------------------------------------------------------------------
    // Task 8: sponsored sell + GOAT/USDT transfers
    // -------------------------------------------------------------------------

    function executeSponsoredSell(
        StreamGTypes.SellIntent calldata intent,
        StreamGTypes.FeeQuote calldata quote,
        StreamGTypes.Eip2612Authorization calldata goatPermit,
        bytes calldata intentSignature,
        bytes calldata quoteSignature
    ) external nonReentrant {
        _requireLive();
        // Body lives in StreamGSell (public library, DELEGATECALL).
        (uint256 feeAmount, uint256 netUsdtOut) = StreamGSell.execute(
            _ctx(),
            sponsoredBuyDesk,
            sponsoredBuyDeskCodeHash,
            intent,
            quote,
            goatPermit,
            intentSignature,
            quoteSignature,
            intentUsed,
            actionNonces,
            quoteUsed
        );

        emit SponsoredSellExecuted(
            intent.intentId, intent.seller, intent.expectedRoot, intent.desk, intent.goatAmount, feeAmount, netUsdtOut
        );
    }

    function executeGoatTransfer(
        StreamGTypes.GoatTransferIntent calldata intent,
        StreamGTypes.FeeQuote calldata quote,
        StreamGTypes.Eip2612Authorization calldata goatPermit,
        StreamGTypes.TokenAuthorization calldata feeAuthorization,
        bytes calldata intentSignature,
        bytes calldata quoteSignature
    ) external nonReentrant {
        _requireLive();
        // Body lives in StreamGXfer (public library, DELEGATECALL). Fee is still
        // collected last, inside the library, before this event is emitted.
        uint256 feeAmount = StreamGXfer.executeGoat(
            _ctx(),
            intent,
            quote,
            goatPermit,
            feeAuthorization,
            intentSignature,
            quoteSignature,
            intentUsed,
            actionNonces,
            quoteUsed
        );

        emit GoatTransferExecuted(
            intent.intentId,
            intent.owner,
            intent.recipient,
            intent.expectedRoot,
            intent.amount,
            intent.feeToken,
            feeAmount
        );
    }

    function executeUsdtTransfer(
        StreamGTypes.UsdtTransferIntent calldata intent,
        StreamGTypes.FeeQuote calldata quote,
        StreamGTypes.TokenAuthorization calldata transferAuthorization,
        bytes calldata intentSignature,
        bytes calldata quoteSignature
    ) external nonReentrant {
        _requireLive();
        // Body lives in StreamGXfer (public library, DELEGATECALL).
        uint256 feeAmount = StreamGXfer.executeUsdt(
            _ctx(),
            intent,
            quote,
            transferAuthorization,
            intentSignature,
            quoteSignature,
            intentUsed,
            actionNonces,
            quoteUsed
        );

        emit UsdtTransferExecuted(
            intent.intentId,
            intent.owner,
            intent.recipient,
            intent.expectedRoot,
            intent.token,
            intent.amount,
            feeAmount,
            intent.authorizationMode
        );
    }

    function _sponsorEnrollmentStructHash(StreamGTypes.SponsorEnrollment calldata intent)
        internal
        pure
        returns (bytes32)
    {
        return StreamGHashes.sponsorEnrollmentStructHash(intent);
    }

    function _feeQuoteStructHash(StreamGTypes.FeeQuote calldata quote) internal pure returns (bytes32) {
        return StreamGHashes.feeQuoteStructHash(quote);
    }
}

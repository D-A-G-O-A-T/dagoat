// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stream G shared types, typehashes, action constants, and capability bits.
/// Design authority: the "Stream G -- USDT Gas Abstraction and Multi-Wallet
/// Sponsoring" spec, §6 and §5.1.
/// Frozen for G1 cross-language parity. Do not rename fields without a design revision.
library StreamGTypes {
    // -------------------------------------------------------------------------
    // Authorization modes (ordinals) vs capability bits (bitmask)
    // -------------------------------------------------------------------------

    enum AuthorizationMode {
        NONE, // 0
        EIP2612, // 1
        EIP3009, // 2
        PRIOR_ALLOWANCE // 3
    }

    uint256 internal constant CAP_EIP2612 = 1 << 0;
    uint256 internal constant CAP_EIP3009 = 1 << 1;
    uint256 internal constant CAP_PRIOR_ALLOWANCE = 1 << 2;
    uint256 internal constant CAP_SELL_SPLIT = 1 << 3;

    // -------------------------------------------------------------------------
    // Action type constants (design §6.2)
    // -------------------------------------------------------------------------

    bytes32 internal constant ACTION_SPONSORED_ENROLLMENT = keccak256("GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1");
    bytes32 internal constant ACTION_SPONSORED_SELL = keccak256("GOAT_STREAM_G_SPONSORED_SELL_V1");
    bytes32 internal constant ACTION_GOAT_TRANSFER = keccak256("GOAT_STREAM_G_GOAT_TRANSFER_V1");
    bytes32 internal constant ACTION_USDT_TRANSFER = keccak256("GOAT_STREAM_G_USDT_TRANSFER_V1");

    // Residential-proxy settlement action types. These reserve the tariff keys
    // and the gateway nonce namespace for the three ProxyRevenueSettlement
    // entrypoints a relayer could route. NOTE, precisely: the gateway has no
    // execute* entrypoint for any of them today, so recognising them widens
    // nothing except `nonceSnapshot`. Two of the three are also not sponsorable
    // as ProxyRevenueSettlement is written -- `proposeBatch` is publisher-only
    // and both it and `challengeBatch` take a native-ETH bond from msg.sender,
    // which is the thing a USDT gas-abstraction relayer exists to avoid. Only
    // `claim` credits an operator parameter rather than msg.sender.
    bytes32 internal constant ACTION_PROXY_CLAIM = keccak256("GOAT_STREAM_G_PROXY_CLAIM_V1");
    bytes32 internal constant ACTION_PROXY_PROPOSE_BATCH = keccak256("GOAT_STREAM_G_PROXY_PROPOSE_BATCH_V1");
    bytes32 internal constant ACTION_PROXY_CHALLENGE_BATCH = keccak256("GOAT_STREAM_G_PROXY_CHALLENGE_BATCH_V1");

    // -------------------------------------------------------------------------
    // Canonical TYPEHASH constants (design §6.9 + action cores + FeeTokenConfig)
    // -------------------------------------------------------------------------

    bytes32 internal constant FEE_QUOTE_TYPEHASH = keccak256(
        "FeeQuote(bytes32 quoteId,bytes32 actionType,bytes32 actionCoreHash,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,bytes32 feeScheduleHash,address payer,address feeToken,uint256 feeAmount,address feeRecipient,uint48 validAfter,uint48 validUntil)"
    );

    bytes32 internal constant SPONSOR_ENROLLMENT_CORE_TYPEHASH = keccak256(
        "SponsorEnrollmentCore(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address root,address controller,uint256 controllerEpoch,address secondary,bytes32 enrollDigest,bytes32 linkDigest,bytes32 rootAuthorizationDigest,address feeToken,uint8 feeAuthorizationMode,uint256 maxFee,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant SELL_CORE_TYPEHASH = keccak256(
        "SellCore(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address seller,address expectedRoot,address desk,uint256 goatAmount,uint256 minNetUsdtOut,bytes32 goatPermitDigest,uint256 maxFee,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant GOAT_TRANSFER_CORE_TYPEHASH = keccak256(
        "GoatTransferCore(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address owner,address expectedRoot,address recipient,uint256 amount,bytes32 goatPermitDigest,address feeToken,uint8 feeAuthorizationMode,uint256 maxFee,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant USDT_TRANSFER_CORE_TYPEHASH = keccak256(
        "UsdtTransferCore(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address owner,address expectedRoot,address token,address recipient,uint256 amount,uint8 authorizationMode,uint256 maxFee,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant LINK_SECONDARY_TYPEHASH =
        keccak256("LinkSecondary(address root,address secondary,uint256 nonce,uint48 deadline)");

    bytes32 internal constant ROOT_AUTHORIZATION_TYPEHASH = keccak256(
        "RootAuthorization(address root,address secondary,bytes32 enrollDigest,bytes32 linkDigest,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant SPONSOR_ENROLLMENT_TYPEHASH = keccak256(
        "SponsorEnrollment(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address root,address controller,uint256 controllerEpoch,address secondary,bytes32 enrollDigest,bytes32 linkDigest,bytes32 rootAuthorizationDigest,address feeToken,uint8 feeAuthorizationMode,bytes32 feeAuthorizationDigest,uint256 maxFee,bytes32 feeQuoteHash,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant SELL_INTENT_TYPEHASH = keccak256(
        "SellIntent(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address seller,address expectedRoot,address desk,uint256 goatAmount,uint256 minNetUsdtOut,bytes32 goatPermitDigest,uint256 maxFee,bytes32 feeQuoteHash,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant GOAT_TRANSFER_INTENT_TYPEHASH = keccak256(
        "GoatTransferIntent(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address owner,address expectedRoot,address recipient,uint256 amount,bytes32 goatPermitDigest,address feeToken,uint8 feeAuthorizationMode,bytes32 feeAuthorizationDigest,uint256 maxFee,bytes32 feeQuoteHash,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant USDT_TRANSFER_INTENT_TYPEHASH = keccak256(
        "UsdtTransferIntent(bytes32 intentId,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,address owner,address expectedRoot,address token,address recipient,uint256 amount,uint8 authorizationMode,bytes32 transferAuthorizationDigest,uint256 maxFee,bytes32 feeQuoteHash,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant PRIOR_ALLOWANCE_AUTHORIZATION_TYPEHASH = keccak256(
        "PriorAllowanceAuthorization(bytes32 intentId,bytes32 actionType,address owner,address token,address spender,uint256 value,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant CONTROLLER_ROTATION_TYPEHASH = keccak256(
        "ControllerRotation(address root,address oldController,address newController,uint256 nonce,uint48 deadline)"
    );

    bytes32 internal constant FEE_TOKEN_CONFIG_TYPEHASH = keccak256(
        "FeeTokenConfig(uint256 chainId,address token,bytes32 runtimeCodeHash,bytes32 proxyIdentityHash,uint256 capabilityMask,uint8 decimals,bytes32 domainNameHash,bytes32 domainVersionHash,bytes32 builtInModeId,uint64 configVersion,bool active)"
    );

    // Canonical EIP-2612 Permit (token-native; domain is the token's).
    bytes32 internal constant EIP2612_PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // Canonical EIP-3009 ReceiveWithAuthorization (token-native).
    bytes32 internal constant EIP3009_RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    // -------------------------------------------------------------------------
    // Structs
    // -------------------------------------------------------------------------

    struct FeeQuote {
        bytes32 quoteId;
        bytes32 actionType;
        bytes32 actionCoreHash;
        bytes32 deploymentManifestHash;
        bytes32 feeTokenConfigHash;
        bytes32 feeScheduleHash;
        address payer;
        address feeToken;
        uint256 feeAmount;
        address feeRecipient;
        uint48 validAfter;
        uint48 validUntil;
    }

    struct SponsorEnrollmentCore {
        bytes32 intentId;
        bytes32 deploymentManifestHash;
        bytes32 feeTokenConfigHash;
        address root;
        address controller;
        uint256 controllerEpoch;
        address secondary;
        bytes32 enrollDigest;
        bytes32 linkDigest;
        bytes32 rootAuthorizationDigest;
        address feeToken;
        uint8 feeAuthorizationMode;
        uint256 maxFee;
        uint256 nonce;
        uint48 deadline;
    }

    struct SellCore {
        bytes32 intentId;
        bytes32 deploymentManifestHash;
        bytes32 feeTokenConfigHash;
        address seller;
        address expectedRoot;
        address desk;
        uint256 goatAmount;
        uint256 minNetUsdtOut;
        bytes32 goatPermitDigest;
        uint256 maxFee;
        uint256 nonce;
        uint48 deadline;
    }

    struct GoatTransferCore {
        bytes32 intentId;
        bytes32 deploymentManifestHash;
        bytes32 feeTokenConfigHash;
        address owner;
        address expectedRoot;
        address recipient;
        uint256 amount;
        bytes32 goatPermitDigest;
        address feeToken;
        uint8 feeAuthorizationMode;
        uint256 maxFee;
        uint256 nonce;
        uint48 deadline;
    }

    struct UsdtTransferCore {
        bytes32 intentId;
        bytes32 deploymentManifestHash;
        bytes32 feeTokenConfigHash;
        address owner;
        address expectedRoot;
        address token;
        address recipient;
        uint256 amount;
        uint8 authorizationMode;
        uint256 maxFee;
        uint256 nonce;
        uint48 deadline;
    }

    struct LinkSecondary {
        address root;
        address secondary;
        uint256 nonce;
        uint48 deadline;
    }

    struct RootAuthorization {
        address root;
        address secondary;
        bytes32 enrollDigest;
        bytes32 linkDigest;
        uint256 nonce;
        uint48 deadline;
    }

    struct SponsorEnrollment {
        bytes32 intentId;
        bytes32 deploymentManifestHash;
        bytes32 feeTokenConfigHash;
        address root;
        address controller;
        uint256 controllerEpoch;
        address secondary;
        bytes32 enrollDigest;
        bytes32 linkDigest;
        bytes32 rootAuthorizationDigest;
        address feeToken;
        uint8 feeAuthorizationMode;
        bytes32 feeAuthorizationDigest;
        uint256 maxFee;
        bytes32 feeQuoteHash;
        uint256 nonce;
        uint48 deadline;
    }

    struct SellIntent {
        bytes32 intentId;
        bytes32 deploymentManifestHash;
        bytes32 feeTokenConfigHash;
        address seller;
        address expectedRoot;
        address desk;
        uint256 goatAmount;
        uint256 minNetUsdtOut;
        bytes32 goatPermitDigest;
        uint256 maxFee;
        bytes32 feeQuoteHash;
        uint256 nonce;
        uint48 deadline;
    }

    struct GoatTransferIntent {
        bytes32 intentId;
        bytes32 deploymentManifestHash;
        bytes32 feeTokenConfigHash;
        address owner;
        address expectedRoot;
        address recipient;
        uint256 amount;
        bytes32 goatPermitDigest;
        address feeToken;
        uint8 feeAuthorizationMode;
        bytes32 feeAuthorizationDigest;
        uint256 maxFee;
        bytes32 feeQuoteHash;
        uint256 nonce;
        uint48 deadline;
    }

    struct UsdtTransferIntent {
        bytes32 intentId;
        bytes32 deploymentManifestHash;
        bytes32 feeTokenConfigHash;
        address owner;
        address expectedRoot;
        address token;
        address recipient;
        uint256 amount;
        uint8 authorizationMode;
        bytes32 transferAuthorizationDigest;
        uint256 maxFee;
        bytes32 feeQuoteHash;
        uint256 nonce;
        uint48 deadline;
    }

    struct PriorAllowanceAuthorization {
        bytes32 intentId;
        bytes32 actionType;
        address owner;
        address token;
        address spender;
        uint256 value;
        uint256 nonce;
        uint48 deadline;
    }

    struct ControllerRotation {
        address root;
        address oldController;
        address newController;
        uint256 nonce;
        uint48 deadline;
    }

    struct FeeTokenConfig {
        uint256 chainId;
        address token;
        bytes32 runtimeCodeHash;
        bytes32 proxyIdentityHash;
        uint256 capabilityMask;
        uint8 decimals;
        bytes32 domainNameHash;
        bytes32 domainVersionHash;
        bytes32 builtInModeId;
        uint64 configVersion;
        bool active;
    }

    /// Frozen V1 enroll payload decoded for gateway front-run branch / snapshot binding.
    /// V1 callable API omits nonce; gateway still needs the signed nonce.
    struct V1Enrollment {
        address wallet;
        uint256 nonce;
        uint256 deadline;
        bytes signature;
    }

    /// Exact EIP-2612 authorization fields (token-native permit).
    struct Eip2612Authorization {
        address owner;
        address spender;
        uint256 value;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// Exact EIP-3009 receiveWithAuthorization fields (token-native).
    struct Eip3009Authorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// Union-ish token authorization envelope used by gateway calldata.
    /// mode selects which nested payload is meaningful.
    struct TokenAuthorization {
        uint8 mode; // AuthorizationMode ordinal
        Eip2612Authorization eip2612;
        Eip3009Authorization eip3009;
        PriorAllowanceAuthorization priorAllowance;
        bytes priorAllowanceSignature;
    }

    /// Advisory same-state nonce snapshot for multi-signature enrollment UX.
    /// Not an execution authorization; every execution method rechecks live values.
    struct NonceSnapshot {
        uint64 blockNumber;
        uint256 actionNonce;
        uint256 v1EnrollNonce;
        uint256 linkNonce;
        uint256 rootRegistrationNonce;
        uint256 rotationNonce;
        uint256 controllerEpoch;
        address controller;
        uint256 goatPermitNonce;
        uint256 feeTokenPermitNonce;
        uint32 presentMask;
        bytes32 deploymentManifestHash;
        bytes32 feeTokenConfigHash;
        bytes32 feeScheduleHash;
    }

    // presentMask bits for NonceSnapshot
    uint32 internal constant SNAP_ACTION_NONCE = 1 << 0;
    uint32 internal constant SNAP_V1_ENROLL_NONCE = 1 << 1;
    uint32 internal constant SNAP_LINK_NONCE = 1 << 2;
    uint32 internal constant SNAP_ROOT_REG_NONCE = 1 << 3;
    uint32 internal constant SNAP_ROTATION_NONCE = 1 << 4;
    uint32 internal constant SNAP_CONTROLLER = 1 << 5;
    uint32 internal constant SNAP_GOAT_PERMIT_NONCE = 1 << 6;
    uint32 internal constant SNAP_FEE_TOKEN_PERMIT_NONCE = 1 << 7;
    uint32 internal constant SNAP_CONFIG_HASHES = 1 << 8;

    // -------------------------------------------------------------------------
    // Frozen GoatRelayGateway external ABI (comments only; implementation later)
    // -------------------------------------------------------------------------
    // function executeSponsoredEnrollment(
    //   SponsorEnrollment intent, FeeQuote quote, V1Enrollment v1Enrollment,
    //   LinkSecondary link, RootAuthorization rootAuthorization,
    //   TokenAuthorization feeAuthorization,
    //   bytes sponsorSignature, bytes quoteSignature, bytes linkSignature,
    //   bytes rootAuthorizationSignature
    // ) external;
    // function executeSponsoredSell(
    //   SellIntent intent, FeeQuote quote, Eip2612Authorization goatPermit,
    //   bytes intentSignature, bytes quoteSignature
    // ) external;
    // function executeGoatTransfer(
    //   GoatTransferIntent intent, FeeQuote quote, Eip2612Authorization goatPermit,
    //   TokenAuthorization feeAuthorization, bytes intentSignature, bytes quoteSignature
    // ) external;
    // function executeUsdtTransfer(
    //   UsdtTransferIntent intent, FeeQuote quote, TokenAuthorization transferAuthorization,
    //   bytes intentSignature, bytes quoteSignature
    // ) external;
    // function secondaryEnrollmentNonceSnapshot(address root, address secondary, address feeToken)
    //   external view returns (NonceSnapshot memory);
}

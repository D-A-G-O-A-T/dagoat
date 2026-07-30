// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {StreamGTypes} from "./StreamGTypes.sol";

/// Stream G fee-token hard gate: Policy Safe-approved token identity + capability mask.
/// G1: non-proxy tokens only (`proxyIdentityHash` must be zero).
contract FeeTokenRegistry {
    // -------------------------------------------------------------------------
    // Fixed role IDs (precommit/bind)
    // -------------------------------------------------------------------------

    bytes32 public constant ROLE_FEE_TOKEN_REGISTRY = keccak256("FEE_TOKEN_REGISTRY");
    bytes32 public constant ROLE_WALLET_SPONSORSHIP_REGISTRY = keccak256("WALLET_SPONSORSHIP_REGISTRY");
    bytes32 public constant ROLE_SPONSORED_BUY_DESK = keccak256("SPONSORED_BUY_DESK");
    bytes32 public constant ROLE_GATEWAY = keccak256("GATEWAY");

    // -------------------------------------------------------------------------
    // Errors / events
    // -------------------------------------------------------------------------

    error NotPolicySafe();
    error ZeroAddress();
    error ZeroToken();
    error ProxyIdentityUnsupported();
    error TokenNotAuthorized();
    error UnknownRole();
    error TokenNotConfigured();

    event ActiveManifestHashSet(bytes32 indexed manifestHash);
    event RoleCommitmentSet(bytes32 indexed roleId, address addr, bytes32 runtimeCodeHash);
    event TokenConfigUpserted(
        address indexed token, bytes32 configHash, uint64 configVersion, bool active
    );
    event TokenDeactivated(address indexed token, bytes32 configHash, uint64 configVersion);

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    address public immutable policySafe;

    bytes32 private _activeManifestHash;

    struct RoleCommitment {
        address addr;
        bytes32 runtimeCodeHash;
    }

    mapping(bytes32 => RoleCommitment) private _roleCommitments;
    mapping(address => StreamGTypes.FeeTokenConfig) private _tokenConfigs;
    mapping(address => bytes32) private _tokenConfigHashes;

    // -------------------------------------------------------------------------
    // Construction / access
    // -------------------------------------------------------------------------

    constructor(address policySafe_) {
        if (policySafe_ == address(0)) revert ZeroAddress();
        policySafe = policySafe_;
    }

    modifier onlySafe() {
        if (msg.sender != policySafe) revert NotPolicySafe();
        _;
    }

    // -------------------------------------------------------------------------
    // Policy mutations
    // -------------------------------------------------------------------------

    function setActiveManifestHash(bytes32 manifestHash) external onlySafe {
        _activeManifestHash = manifestHash;
        emit ActiveManifestHashSet(manifestHash);
    }

    function setRoleCommitment(bytes32 roleId, address addr, bytes32 runtimeCodeHash)
        external
        onlySafe
    {
        if (!_isKnownRole(roleId)) revert UnknownRole();
        _roleCommitments[roleId] = RoleCommitment({addr: addr, runtimeCodeHash: runtimeCodeHash});
        emit RoleCommitmentSet(roleId, addr, runtimeCodeHash);
    }

    /// Upsert a token capability config. Registry assigns/increments `configVersion`.
    /// G1 rejects any non-zero `proxyIdentityHash`.
    function upsertTokenConfig(StreamGTypes.FeeTokenConfig calldata cfg)
        external
        onlySafe
        returns (bytes32 configHash)
    {
        if (cfg.token == address(0)) revert ZeroToken();
        if (cfg.proxyIdentityHash != bytes32(0)) revert ProxyIdentityUnsupported();

        StreamGTypes.FeeTokenConfig storage stored = _tokenConfigs[cfg.token];
        uint64 nextVersion = stored.configVersion == 0 ? 1 : stored.configVersion + 1;

        StreamGTypes.FeeTokenConfig memory next = StreamGTypes.FeeTokenConfig({
            chainId: cfg.chainId,
            token: cfg.token,
            runtimeCodeHash: cfg.runtimeCodeHash,
            proxyIdentityHash: bytes32(0),
            capabilityMask: cfg.capabilityMask,
            decimals: cfg.decimals,
            domainNameHash: cfg.domainNameHash,
            domainVersionHash: cfg.domainVersionHash,
            builtInModeId: cfg.builtInModeId,
            configVersion: nextVersion,
            active: cfg.active
        });

        configHash = _hashConfig(next);
        _tokenConfigs[cfg.token] = next;
        _tokenConfigHashes[cfg.token] = configHash;

        emit TokenConfigUpserted(cfg.token, configHash, nextVersion, next.active);
    }

    function deactivateToken(address token) external onlySafe {
        if (token == address(0)) revert ZeroToken();
        StreamGTypes.FeeTokenConfig storage stored = _tokenConfigs[token];
        if (stored.configVersion == 0) revert TokenNotConfigured();

        stored.active = false;
        stored.configVersion += 1;
        bytes32 configHash = _hashConfig(stored);
        _tokenConfigHashes[token] = configHash;

        emit TokenDeactivated(token, configHash, stored.configVersion);
    }

    // -------------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------------

    function activeManifestHash() external view returns (bytes32) {
        return _activeManifestHash;
    }

    function getRoleCommitment(bytes32 roleId)
        external
        view
        returns (address addr, bytes32 runtimeCodeHash)
    {
        RoleCommitment memory c = _roleCommitments[roleId];
        return (c.addr, c.runtimeCodeHash);
    }

    function getTokenConfig(address token)
        external
        view
        returns (StreamGTypes.FeeTokenConfig memory)
    {
        return _tokenConfigs[token];
    }

    function getTokenConfigHash(address token) external view returns (bytes32) {
        return _tokenConfigHashes[token];
    }

    function isTokenAuthorized(address token, uint256 requiredCapability)
        external
        view
        returns (bool)
    {
        return _isAuthorized(token, requiredCapability);
    }

    function assertTokenAuthorized(address token, uint256 requiredCapability) external view {
        if (!_isAuthorized(token, requiredCapability)) revert TokenNotAuthorized();
    }

    // -------------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------------

    function _isKnownRole(bytes32 roleId) private pure returns (bool) {
        return roleId == ROLE_FEE_TOKEN_REGISTRY || roleId == ROLE_WALLET_SPONSORSHIP_REGISTRY
            || roleId == ROLE_SPONSORED_BUY_DESK || roleId == ROLE_GATEWAY;
    }

    function _hashConfig(StreamGTypes.FeeTokenConfig memory cfg) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                StreamGTypes.FEE_TOKEN_CONFIG_TYPEHASH,
                cfg.chainId,
                cfg.token,
                cfg.runtimeCodeHash,
                cfg.proxyIdentityHash,
                cfg.capabilityMask,
                cfg.decimals,
                cfg.domainNameHash,
                cfg.domainVersionHash,
                cfg.builtInModeId,
                cfg.configVersion,
                cfg.active
            )
        );
    }

    function _isAuthorized(address token, uint256 requiredCapability)
        private
        view
        returns (bool)
    {
        StreamGTypes.FeeTokenConfig storage cfg = _tokenConfigs[token];
        if (!cfg.active) return false;
        if (cfg.token != token) return false;
        if (cfg.chainId != block.chainid) return false;
        if (token.codehash != cfg.runtimeCodeHash) return false;
        if ((cfg.capabilityMask & requiredCapability) != requiredCapability) return false;
        return true;
    }
}
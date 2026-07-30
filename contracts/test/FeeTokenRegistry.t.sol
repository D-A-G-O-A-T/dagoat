// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FeeTokenRegistry} from "../src/FeeTokenRegistry.sol";
import {StreamGTypes} from "../src/StreamGTypes.sol";
import {PermitMockUSDT} from "./mocks/PermitMockUSDT.sol";

contract FeeTokenRegistryTest is Test {
    address internal policy = address(0xA11CE);
    address internal stranger = address(0xB0B);
    FeeTokenRegistry internal registry;
    PermitMockUSDT internal token;

    function setUp() public {
        registry = new FeeTokenRegistry(policy);
        token = new PermitMockUSDT();
    }

    function _activeCfg(address tokenAddr, uint256 capabilityMask, bytes32 proxyIdentityHash)
        internal
        view
        returns (StreamGTypes.FeeTokenConfig memory cfg)
    {
        cfg = StreamGTypes.FeeTokenConfig({
            chainId: block.chainid,
            token: tokenAddr,
            runtimeCodeHash: tokenAddr.codehash,
            proxyIdentityHash: proxyIdentityHash,
            capabilityMask: capabilityMask,
            decimals: 6,
            domainNameHash: keccak256(bytes("Permit Mock USDT")),
            domainVersionHash: keccak256(bytes("1")),
            builtInModeId: keccak256("EIP2612_STANDARD"),
            configVersion: 0, // registry assigns/increments
            active: true
        });
    }

    function test_activate_token_requires_exact_codehash_and_config_hash() public {
        StreamGTypes.FeeTokenConfig memory cfg =
            _activeCfg(address(token), StreamGTypes.CAP_EIP2612 | StreamGTypes.CAP_SELL_SPLIT, bytes32(0));

        vm.prank(policy);
        bytes32 configHash = registry.upsertTokenConfig(cfg);

        StreamGTypes.FeeTokenConfig memory stored = registry.getTokenConfig(address(token));
        assertTrue(stored.active);
        assertEq(stored.runtimeCodeHash, address(token).codehash);
        assertEq(stored.configVersion, 1);
        assertEq(registry.getTokenConfigHash(address(token)), configHash);

        // Recompute expected hash with assigned version.
        stored.configVersion = 1;
        bytes32 expected = keccak256(
            abi.encode(
                StreamGTypes.FEE_TOKEN_CONFIG_TYPEHASH,
                stored.chainId,
                stored.token,
                stored.runtimeCodeHash,
                stored.proxyIdentityHash,
                stored.capabilityMask,
                stored.decimals,
                stored.domainNameHash,
                stored.domainVersionHash,
                stored.builtInModeId,
                stored.configVersion,
                stored.active
            )
        );
        assertEq(configHash, expected);
        assertTrue(registry.isTokenAuthorized(address(token), StreamGTypes.CAP_EIP2612));
        assertTrue(registry.isTokenAuthorized(address(token), StreamGTypes.CAP_SELL_SPLIT));
    }

    function test_inactive_or_mismatched_codehash_reverts() public {
        StreamGTypes.FeeTokenConfig memory cfg =
            _activeCfg(address(token), StreamGTypes.CAP_EIP2612, bytes32(0));
        vm.prank(policy);
        registry.upsertTokenConfig(cfg);
        assertTrue(registry.isTokenAuthorized(address(token), StreamGTypes.CAP_EIP2612));

        // Deactivate
        vm.prank(policy);
        registry.deactivateToken(address(token));
        assertFalse(registry.isTokenAuthorized(address(token), StreamGTypes.CAP_EIP2612));
        vm.expectRevert(FeeTokenRegistry.TokenNotAuthorized.selector);
        registry.assertTokenAuthorized(address(token), StreamGTypes.CAP_EIP2612);

        // Reactivate with wrong codehash
        cfg.runtimeCodeHash = bytes32(uint256(0xdead));
        cfg.active = true;
        vm.prank(policy);
        registry.upsertTokenConfig(cfg);
        assertFalse(registry.isTokenAuthorized(address(token), StreamGTypes.CAP_EIP2612));
        vm.expectRevert(FeeTokenRegistry.TokenNotAuthorized.selector);
        registry.assertTokenAuthorized(address(token), StreamGTypes.CAP_EIP2612);
    }

    function test_proxy_identity_nonzero_rejected_in_g1() public {
        StreamGTypes.FeeTokenConfig memory cfg =
            _activeCfg(address(token), StreamGTypes.CAP_EIP2612, bytes32(uint256(1)));
        vm.prank(policy);
        vm.expectRevert(FeeTokenRegistry.ProxyIdentityUnsupported.selector);
        registry.upsertTokenConfig(cfg);
    }

    function test_capability_mask_sell_split_independent_of_mode_ordinal() public {
        // PRIOR_ALLOWANCE mode ordinal is 3; CAP_SELL_SPLIT is 1<<3 == 8.
        assertEq(uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE), 3);
        assertEq(StreamGTypes.CAP_SELL_SPLIT, 8);

        StreamGTypes.FeeTokenConfig memory cfg =
            _activeCfg(address(token), StreamGTypes.CAP_SELL_SPLIT, bytes32(0));
        vm.prank(policy);
        registry.upsertTokenConfig(cfg);

        assertTrue(registry.isTokenAuthorized(address(token), StreamGTypes.CAP_SELL_SPLIT));
        assertFalse(registry.isTokenAuthorized(address(token), StreamGTypes.CAP_EIP2612));
        assertFalse(registry.isTokenAuthorized(address(token), StreamGTypes.CAP_PRIOR_ALLOWANCE));
    }

    function test_only_policy_safe_mutates_config() public {
        StreamGTypes.FeeTokenConfig memory cfg =
            _activeCfg(address(token), StreamGTypes.CAP_EIP2612, bytes32(0));
        bytes32 gatewayRole = registry.ROLE_GATEWAY();

        vm.prank(stranger);
        vm.expectRevert(FeeTokenRegistry.NotPolicySafe.selector);
        registry.upsertTokenConfig(cfg);

        vm.prank(stranger);
        vm.expectRevert(FeeTokenRegistry.NotPolicySafe.selector);
        registry.setActiveManifestHash(bytes32(uint256(1)));

        vm.prank(stranger);
        vm.expectRevert(FeeTokenRegistry.NotPolicySafe.selector);
        registry.setRoleCommitment(gatewayRole, address(0x1111), bytes32(uint256(2)));
    }

    function test_role_commitment_gateway_codehash_bound_by_policy() public {
        address gateway = address(0x1111);
        bytes32 codeHash = bytes32(uint256(0x2222));
        bytes32 gatewayRole = registry.ROLE_GATEWAY();

        vm.prank(policy);
        registry.setRoleCommitment(gatewayRole, gateway, codeHash);

        (address addr, bytes32 storedHash) = registry.getRoleCommitment(gatewayRole);
        assertEq(addr, gateway);
        assertEq(storedHash, codeHash);

        // Policy may update pre-activation commitments.
        vm.prank(policy);
        registry.setRoleCommitment(gatewayRole, address(0x3333), bytes32(uint256(0x4444)));
        (addr, storedHash) = registry.getRoleCommitment(gatewayRole);
        assertEq(addr, address(0x3333));
        assertEq(storedHash, bytes32(uint256(0x4444)));

        // Unknown role rejected.
        vm.prank(policy);
        vm.expectRevert(FeeTokenRegistry.UnknownRole.selector);
        registry.setRoleCommitment(keccak256("NOT_A_ROLE"), gateway, codeHash);
    }

    function test_set_active_manifest_hash_only_policy() public {
        bytes32 manifest = keccak256("manifest-v1");
        vm.prank(policy);
        registry.setActiveManifestHash(manifest);
        assertEq(registry.activeManifestHash(), manifest);
    }
}

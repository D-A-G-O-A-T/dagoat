// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {FeeTokenRegistry} from "../src/FeeTokenRegistry.sol";
import {WalletSponsorshipRegistry} from "../src/WalletSponsorshipRegistry.sol";
import {StreamGTypes} from "../src/StreamGTypes.sol";

contract WalletSponsorshipRegistryTest is Test {
    using ECDSA for bytes32;

    uint256 constant ISSUER_PK = 0xA11CE;
    uint256 constant ROOT_PK = 0xB0B;
    uint256 constant SECONDARY_PK = 0xC0FFEE;
    uint256 constant CONTROLLER2_PK = 0xD00D;
    uint256 constant RECOVERY_PK = 0xE11E;

    address internal policy;
    address internal issuer;
    address internal root;
    address internal secondary;
    address internal controller2;
    address internal recoverySafe;
    address internal gateway;

    EnrollmentRegistry internal v1;
    FeeTokenRegistry internal feeRegistry;
    WalletSponsorshipRegistry internal sidecar;

    bytes32 constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    function setUp() public {
        policy = address(this);
        issuer = vm.addr(ISSUER_PK);
        root = vm.addr(ROOT_PK);
        secondary = vm.addr(SECONDARY_PK);
        controller2 = vm.addr(CONTROLLER2_PK);
        recoverySafe = vm.addr(RECOVERY_PK);
        gateway = address(0x1111);

        v1 = new EnrollmentRegistry(policy);
        feeRegistry = new FeeTokenRegistry(policy);
        sidecar = new WalletSponsorshipRegistry(address(v1), address(feeRegistry), policy, recoverySafe, 7 days);

        // Enroll root + secondary in frozen V1.
        vm.prank(root);
        v1.enrollSelf();
        vm.prank(secondary);
        v1.enrollSelf();

        // Precommit gateway role, then bind once.
        feeRegistry.setRoleCommitment(feeRegistry.ROLE_GATEWAY(), gateway, bytes32(uint256(0x91)));
        // etch empty runtime at gateway address for codehash match if needed later
        vm.etch(gateway, hex"60006000");
        // update commitment to actual etched codehash
        feeRegistry.setRoleCommitment(feeRegistry.ROLE_GATEWAY(), gateway, gateway.codehash);
        vm.prank(policy);
        sidecar.bindGatewayOnce(gateway);

        // Set issuer role on sidecar
        vm.prank(policy);
        sidecar.setProfileIssuer(issuer, true);
    }

    function _domainSeparator(address verifying) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("GoatWalletSponsorship")),
                keccak256(bytes("1")),
                block.chainid,
                verifying
            )
        );
    }

    function _signRootAuth(StreamGTypes.RootAuthorization memory auth, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                StreamGTypes.ROOT_AUTHORIZATION_TYPEHASH,
                auth.root,
                auth.secondary,
                auth.enrollDigest,
                auth.linkDigest,
                auth.nonce,
                auth.deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(address(sidecar)), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signLink(StreamGTypes.LinkSecondary memory link, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(StreamGTypes.LINK_SECONDARY_TYPEHASH, link.root, link.secondary, link.nonce, link.deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(address(sidecar)), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signRotation(StreamGTypes.ControllerRotation memory rot, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                StreamGTypes.CONTROLLER_ROTATION_TYPEHASH,
                rot.root,
                rot.oldController,
                rot.newController,
                rot.nonce,
                rot.deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(address(sidecar)), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_register_primary_requires_live_v1_enrollment_and_issuer_sig() public {
        StreamGTypes.RootAuthorization memory auth = StreamGTypes.RootAuthorization({
            root: root,
            secondary: address(0),
            enrollDigest: bytes32(uint256(1)),
            linkDigest: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        bytes memory issuerSig = _signRootAuth(auth, ISSUER_PK);

        // Wrong issuer fails
        bytes memory badSig = _signRootAuth(auth, ROOT_PK);
        vm.expectRevert(WalletSponsorshipRegistry.BadIssuerSignature.selector);
        sidecar.registerPrimary(auth, badSig);

        // Success
        sidecar.registerPrimary(auth, issuerSig);
        assertEq(sidecar.primaryOf(root), root);
        assertEq(sidecar.controllerOf(root), root);
        assertEq(sidecar.controlledRootOf(root), root);
        assertEq(sidecar.controllerEpoch(root), 0);
        assertEq(sidecar.rootRegistrationNonces(root), 1);

        // Cannot register twice
        auth.nonce = 1;
        auth.deadline = uint48(block.timestamp + 2 hours);
        bytes memory issuerSig2 = _signRootAuth(auth, ISSUER_PK);
        vm.expectRevert(WalletSponsorshipRegistry.RootAlreadyRegistered.selector);
        sidecar.registerPrimary(auth, issuerSig2);
    }

    function test_link_secondary_is_gateway_only_and_sets_immutable_primaryOf() public {
        // Register root first
        StreamGTypes.RootAuthorization memory rootAuth = StreamGTypes.RootAuthorization({
            root: root,
            secondary: address(0),
            enrollDigest: bytes32(uint256(1)),
            linkDigest: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        sidecar.registerPrimary(rootAuth, _signRootAuth(rootAuth, ISSUER_PK));

        StreamGTypes.LinkSecondary memory link = StreamGTypes.LinkSecondary({
            root: root,
            secondary: secondary,
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        // Zeroed RootAuthorization because root already registered
        StreamGTypes.RootAuthorization memory zeroAuth;
        bytes memory linkSig = _signLink(link, SECONDARY_PK);

        // Non-gateway rejected
        vm.expectRevert(WalletSponsorshipRegistry.NotGateway.selector);
        sidecar.linkSecondary(link, linkSig, zeroAuth, "");

        // Gateway succeeds
        vm.prank(gateway);
        sidecar.linkSecondary(link, linkSig, zeroAuth, "");
        assertEq(sidecar.primaryOf(secondary), root);

        // Immutable: second link attempt for same secondary fails
        link.nonce = 1;
        link.deadline = uint48(block.timestamp + 2 hours);
        bytes memory linkSig2 = _signLink(link, SECONDARY_PK);
        vm.prank(gateway);
        vm.expectRevert(WalletSponsorshipRegistry.SecondaryAlreadyLinked.selector);
        sidecar.linkSecondary(link, linkSig2, zeroAuth, "");
    }

    function test_secondary_cannot_sponsor_another_wallet_flat_star() public {
        StreamGTypes.RootAuthorization memory rootAuth = StreamGTypes.RootAuthorization({
            root: root,
            secondary: address(0),
            enrollDigest: bytes32(uint256(1)),
            linkDigest: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        sidecar.registerPrimary(rootAuth, _signRootAuth(rootAuth, ISSUER_PK));

        StreamGTypes.LinkSecondary memory link = StreamGTypes.LinkSecondary({
            root: root,
            secondary: secondary,
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        StreamGTypes.RootAuthorization memory zeroAuth;
        vm.prank(gateway);
        sidecar.linkSecondary(link, _signLink(link, SECONDARY_PK), zeroAuth, "");

        // Attempt to register secondary as a new primary root fails because primaryOf[secondary] already set
        // and controlledRoot topology: secondary already linked.
        uint256 tertiaryPk = 0x7777;
        address tertiary = vm.addr(tertiaryPk);
        vm.prank(tertiary);
        v1.enrollSelf();

        // Try linking tertiary under secondary as if secondary were a root — must fail (secondary is not a root)
        StreamGTypes.LinkSecondary memory bad = StreamGTypes.LinkSecondary({
            root: secondary,
            secondary: tertiary,
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        vm.prank(gateway);
        vm.expectRevert(WalletSponsorshipRegistry.RootNotRegistered.selector);
        sidecar.linkSecondary(bad, _signLink(bad, tertiaryPk), zeroAuth, "");
    }

    function test_controller_rotation_increments_epoch() public {
        StreamGTypes.RootAuthorization memory rootAuth = StreamGTypes.RootAuthorization({
            root: root,
            secondary: address(0),
            enrollDigest: bytes32(uint256(1)),
            linkDigest: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        sidecar.registerPrimary(rootAuth, _signRootAuth(rootAuth, ISSUER_PK));

        StreamGTypes.ControllerRotation memory rot = StreamGTypes.ControllerRotation({
            root: root,
            oldController: root,
            newController: controller2,
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        bytes memory oldSig = _signRotation(rot, ROOT_PK);
        bytes memory newSig = _signRotation(rot, CONTROLLER2_PK);
        sidecar.rotateController(rot, oldSig, newSig);

        assertEq(sidecar.controllerOf(root), controller2);
        assertEq(sidecar.controlledRootOf(controller2), root);
        assertEq(sidecar.controlledRootOf(root), address(0));
        assertEq(sidecar.controllerEpoch(root), 1);
        assertEq(sidecar.primaryOf(root), root); // immutable
        assertEq(sidecar.rotationNonces(root), 1);

        // Rotate back to root
        StreamGTypes.ControllerRotation memory rot2 = StreamGTypes.ControllerRotation({
            root: root,
            oldController: controller2,
            newController: root,
            nonce: 1,
            deadline: uint48(block.timestamp + 2 hours)
        });
        sidecar.rotateController(rot2, _signRotation(rot2, CONTROLLER2_PK), _signRotation(rot2, ROOT_PK));
        assertEq(sidecar.controllerOf(root), root);
        assertEq(sidecar.controllerEpoch(root), 2);
    }

    function test_suspension_blocks_new_links_not_balances() public {
        StreamGTypes.RootAuthorization memory rootAuth = StreamGTypes.RootAuthorization({
            root: root,
            secondary: address(0),
            enrollDigest: bytes32(uint256(1)),
            linkDigest: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        sidecar.registerPrimary(rootAuth, _signRootAuth(rootAuth, ISSUER_PK));

        vm.prank(policy);
        sidecar.setClusterSuspended(root, true, bytes32(uint256(9)));
        assertTrue(sidecar.suspendedClusters(root));

        StreamGTypes.LinkSecondary memory link = StreamGTypes.LinkSecondary({
            root: root,
            secondary: secondary,
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        StreamGTypes.RootAuthorization memory zeroAuth;
        vm.prank(gateway);
        vm.expectRevert(WalletSponsorshipRegistry.ClusterSuspended.selector);
        sidecar.linkSecondary(link, _signLink(link, SECONDARY_PK), zeroAuth, "");

        // V1 enrollment/state untouched
        assertTrue(v1.enrolled(root));
        assertTrue(v1.enrolled(secondary));
        assertEq(sidecar.primaryOf(root), root);
    }

    function test_recovery_timelock_updates_controller_keeps_primaryOf() public {
        StreamGTypes.RootAuthorization memory rootAuth = StreamGTypes.RootAuthorization({
            root: root,
            secondary: address(0),
            enrollDigest: bytes32(uint256(1)),
            linkDigest: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        sidecar.registerPrimary(rootAuth, _signRootAuth(rootAuth, ISSUER_PK));

        uint256 rotNonce = sidecar.rotationNonces(root);
        uint256 epoch = sidecar.controllerEpoch(root);
        vm.prank(recoverySafe);
        bytes32 scheduleId = sidecar.scheduleRecovery(root, controller2, rotNonce, epoch, bytes32(uint256(7)));

        // Too early
        vm.prank(recoverySafe);
        vm.expectRevert(WalletSponsorshipRegistry.RecoveryNotReady.selector);
        sidecar.executeRecovery(scheduleId);

        vm.warp(block.timestamp + 7 days);
        vm.prank(recoverySafe);
        sidecar.executeRecovery(scheduleId);

        assertEq(sidecar.controllerOf(root), controller2);
        assertEq(sidecar.primaryOf(root), root);
        assertEq(sidecar.controllerEpoch(root), epoch + 1);
        assertEq(sidecar.rotationNonces(root), rotNonce + 1);
    }
}

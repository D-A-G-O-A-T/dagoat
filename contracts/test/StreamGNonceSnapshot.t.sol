// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {FeeTokenRegistry} from "../src/FeeTokenRegistry.sol";
import {WalletSponsorshipRegistry} from "../src/WalletSponsorshipRegistry.sol";
import {GoatRelayGateway} from "../src/GoatRelayGateway.sol";
import {StreamGTypes} from "../src/StreamGTypes.sol";
import {PermitMockUSDT} from "./mocks/PermitMockUSDT.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";

/// Minimal EIP-2612 surface, so the permit-nonce fixture can drive `goat` and
/// `permitToken` through one code path without importing OZ's full extension.
interface IERC20PermitLike {
    function nonces(address owner) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external;
}

/// Hazard 2: same-state secondary enrollment nonce snapshot (design §10.3).
contract StreamGNonceSnapshotTest is Test {
    uint256 constant ISSUER_PK = 0xA11CE;
    uint256 constant ROOT_PK = 0xB0B;
    uint256 constant SECONDARY_PK = 0xC0FFEE;

    address internal policy;
    address internal issuer;
    address internal root;
    address internal secondary;
    address internal feeSafe;
    address internal recovery;

    EnrollmentRegistry internal v1;
    GoatCoin internal goat;
    FeeTokenRegistry internal feeRegistry;
    WalletSponsorshipRegistry internal sidecar;
    GoatRelayGateway internal gateway;
    PermitMockUSDT internal permitToken;
    MockUSDT internal plainToken;

    bytes32 constant ROOT_AUTH_TYPEHASH = keccak256(
        "RootAuthorization(address root,address secondary,bytes32 enrollDigest,bytes32 linkDigest,uint256 nonce,uint48 deadline)"
    );
    bytes32 constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    function setUp() public {
        policy = address(this);
        issuer = vm.addr(ISSUER_PK);
        root = vm.addr(ROOT_PK);
        secondary = vm.addr(SECONDARY_PK);
        feeSafe = makeAddr("feeSafe");
        recovery = makeAddr("recovery");

        v1 = new EnrollmentRegistry(policy);
        goat = new GoatCoin("GoatCoin", "GOAT", policy, v1);
        feeRegistry = new FeeTokenRegistry(policy);
        sidecar = new WalletSponsorshipRegistry(address(v1), address(feeRegistry), policy, recovery, 7 days);
        permitToken = new PermitMockUSDT();
        plainToken = new MockUSDT();

        // Enroll root in V1 and register as primary root.
        vm.prank(root);
        v1.enrollSelf();

        // Deploy gateway first so we can commit its real codehash, then bind children.
        gateway = new GoatRelayGateway(
            address(v1),
            address(feeRegistry),
            address(sidecar),
            address(goat),
            policy,
            feeSafe
        );

        // Precommit + bind gateway on sidecar (needs etched/runtime codehash of gateway).
        feeRegistry.setRoleCommitment(feeRegistry.ROLE_GATEWAY(), address(gateway), address(gateway).codehash);
        sidecar.bindGatewayOnce(address(gateway));
        sidecar.setProfileIssuer(issuer, true);

        // Register primary root via issuer signature.
        StreamGTypes.RootAuthorization memory auth = StreamGTypes.RootAuthorization({
            root: root,
            secondary: address(0),
            enrollDigest: bytes32(uint256(1)),
            linkDigest: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 days)
        });
        sidecar.registerPrimary(auth, _signRootAuth(auth, ISSUER_PK));

        // Activate gateway config hashes for snapshot.
        bytes32 manifest = keccak256("manifest-g1");
        bytes32 schedule = keccak256("schedule-g1");
        feeRegistry.setActiveManifestHash(manifest);
        gateway.setFeeScheduleHash(schedule);
        gateway.setPaused(false);
        gateway.activate();

        // Authorize permit token with EIP-2612 capability.
        StreamGTypes.FeeTokenConfig memory cfg = StreamGTypes.FeeTokenConfig({
            chainId: block.chainid,
            token: address(permitToken),
            runtimeCodeHash: address(permitToken).codehash,
            proxyIdentityHash: bytes32(0),
            capabilityMask: StreamGTypes.CAP_EIP2612,
            decimals: 6,
            domainNameHash: keccak256(bytes("Permit Mock USDT")),
            domainVersionHash: keccak256(bytes("1")),
            builtInModeId: keccak256("EIP2612_STANDARD"),
            configVersion: 0,
            active: true
        });
        feeRegistry.upsertTokenConfig(cfg);
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
                ROOT_AUTH_TYPEHASH,
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

    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    /// Advances `owner`'s EIP-2612 nonce on `token` by one, using a real signed
    /// `permit` rather than a storage poke, so the nonce moves the way it moves
    /// in production.
    function _bumpPermitNonce(address token, address owner, uint256 pk) internal {
        uint256 nonce = IERC20PermitLike(token).nonces(owner);
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, address(this), uint256(1), nonce, type(uint256).max));
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", IERC20PermitLike(token).DOMAIN_SEPARATOR(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        IERC20PermitLike(token).permit(owner, address(this), 1, type(uint256).max, v, r, s);
    }

    /// The discriminating half of the snapshot check.
    ///
    /// WHY THIS EXISTS: the same-state test below asserts every snapshot field
    /// against a live re-read of the same mapping, but at that point almost
    /// every one of those mappings is still ZERO -- `secondary` has never
    /// enrolled or linked, no action has executed, no rotation has occurred,
    /// and neither token has seen a permit. Seven of its thirteen assertions
    /// were literally `0 == 0`, and the two payer-selection fields compared
    /// against an address that happened to be identical. A `_snapshot` refactor
    /// that swapped two read SUBJECTS -- for instance
    /// `IERC20Permit(feeToken).nonces(goatOwner)` becoming `...nonces(secondary)`,
    /// an easy slip because `secondary` is a parameter in scope -- left the
    /// whole suite green while every relayed enrollment on a root whose
    /// controller had ever touched the fee token began failing.
    ///
    /// This test drives the two permit nonces to DISTINCT NON-ZERO values
    /// before reading the snapshot, so subject and field swaps both change an
    /// asserted number. Mutations it kills:
    ///   * `goatPermitNonce  <- goat.nonces(secondary)`      (subject swap)
    ///   * `feeTokenPermitNonce <- permitToken.nonces(secondary)` (subject swap)
    ///   * the two permit-nonce fields transposed              (field swap)
    function test_snapshot_permit_nonce_fields_are_distinct_and_subject_bound() public {
        // goat: root -> 1 permit. feeToken: root -> 2 permits. secondary: none.
        // Three different values, so no two asserted fields can alias.
        _bumpPermitNonce(address(goat), root, ROOT_PK);
        _bumpPermitNonce(address(permitToken), root, ROOT_PK);
        _bumpPermitNonce(address(permitToken), root, ROOT_PK);

        assertEq(goat.nonces(root), 1, "fixture: goat nonce must be 1");
        assertEq(permitToken.nonces(root), 2, "fixture: fee token nonce must be 2");
        assertEq(goat.nonces(secondary), 0, "fixture: secondary must be untouched");
        assertEq(permitToken.nonces(secondary), 0, "fixture: secondary must be untouched");

        StreamGTypes.NonceSnapshot memory snap =
            gateway.secondaryEnrollmentNonceSnapshot(root, secondary, address(permitToken));

        // Each of these now pins a different number, so a swap of either the
        // subject or the field is observable.
        assertEq(snap.goatPermitNonce, 1, "goatPermitNonce must read the ROOT's goat nonce");
        assertEq(snap.feeTokenPermitNonce, 2, "feeTokenPermitNonce must read the ROOT's fee-token nonce");
        assertTrue(
            snap.goatPermitNonce != snap.feeTokenPermitNonce,
            "the two permit nonces must not be equal, or a transposition is invisible"
        );
    }

    /// Same-state consistency check.
    ///
    /// HONEST SCOPE, so this is not read as more than it is: this asserts that
    /// the snapshot agrees with a live re-read, and the config-hash, controller
    /// and mask assertions below are genuinely load-bearing. But most of the
    /// NONCE fields here are still zero on both sides at this point in the
    /// fixture, so those particular comparisons cannot detect a subject swap.
    /// `test_snapshot_permit_nonce_fields_are_distinct_and_subject_bound` above
    /// is what covers that, and it is the test to extend when a future field
    /// needs the same treatment.
    function test_secondary_enrollment_nonce_snapshot_returns_same_state_fields() public view {
        StreamGTypes.NonceSnapshot memory snap =
            gateway.secondaryEnrollmentNonceSnapshot(root, secondary, address(permitToken));

        assertEq(snap.blockNumber, uint64(block.number));
        assertEq(snap.v1EnrollNonce, v1.nonces(secondary));
        assertEq(snap.linkNonce, sidecar.linkNonces(secondary));
        assertEq(snap.actionNonce, gateway.actionNonces(root, StreamGTypes.ACTION_SPONSORED_ENROLLMENT));
        assertEq(snap.rootRegistrationNonce, sidecar.rootRegistrationNonces(root));
        assertEq(snap.rotationNonce, sidecar.rotationNonces(root));
        assertEq(snap.controllerEpoch, sidecar.controllerEpoch(root));
        assertEq(snap.controller, sidecar.controllerOf(root));
        assertEq(snap.goatPermitNonce, goat.nonces(root));
        assertEq(snap.feeTokenPermitNonce, permitToken.nonces(root));
        assertEq(snap.deploymentManifestHash, feeRegistry.activeManifestHash());
        assertEq(snap.feeTokenConfigHash, feeRegistry.getTokenConfigHash(address(permitToken)));
        assertEq(snap.feeScheduleHash, gateway.feeScheduleHash());

        uint32 expectedMask = StreamGTypes.SNAP_ACTION_NONCE | StreamGTypes.SNAP_V1_ENROLL_NONCE
            | StreamGTypes.SNAP_LINK_NONCE | StreamGTypes.SNAP_ROOT_REG_NONCE | StreamGTypes.SNAP_ROTATION_NONCE
            | StreamGTypes.SNAP_CONTROLLER | StreamGTypes.SNAP_GOAT_PERMIT_NONCE
            | StreamGTypes.SNAP_FEE_TOKEN_PERMIT_NONCE | StreamGTypes.SNAP_CONFIG_HASHES;
        assertEq(snap.presentMask, expectedMask);
    }

    function test_snapshot_fee_token_permit_nonce_only_when_eip2612_active() public {
        // Unauthorized/plain token: no fee-token permit bit, permit nonce zeroed.
        StreamGTypes.NonceSnapshot memory snapPlain =
            gateway.secondaryEnrollmentNonceSnapshot(root, secondary, address(plainToken));
        assertEq(snapPlain.feeTokenPermitNonce, 0);
        assertTrue((snapPlain.presentMask & StreamGTypes.SNAP_FEE_TOKEN_PERMIT_NONCE) == 0);

        // EIP-2612 authorized token includes the bit.
        StreamGTypes.NonceSnapshot memory snapPermit =
            gateway.secondaryEnrollmentNonceSnapshot(root, secondary, address(permitToken));
        assertTrue((snapPermit.presentMask & StreamGTypes.SNAP_FEE_TOKEN_PERMIT_NONCE) != 0);
        assertEq(snapPermit.feeTokenPermitNonce, permitToken.nonces(root));
    }

    function test_snapshot_rejects_unknown_action_or_inactive_token() public {
        // General nonceSnapshot rejects unknown action type.
        vm.expectRevert(GoatRelayGateway.UnknownActionType.selector);
        gateway.nonceSnapshot(bytes32(uint256(0xdead)), root, root, secondary, address(permitToken));

        // Deactivate fee token -> secondaryEnrollmentNonceSnapshot still returns but without fee permit bit.
        feeRegistry.deactivateToken(address(permitToken));
        StreamGTypes.NonceSnapshot memory snap =
            gateway.secondaryEnrollmentNonceSnapshot(root, secondary, address(permitToken));
        assertTrue((snap.presentMask & StreamGTypes.SNAP_FEE_TOKEN_PERMIT_NONCE) == 0);
        assertEq(snap.feeTokenConfigHash, bytes32(0));
    }

    function test_snapshot_is_not_execution_authority() public {
        // Snapshot does not consume action nonces or mark intents used.
        uint256 beforeNonce = gateway.actionNonces(root, StreamGTypes.ACTION_SPONSORED_ENROLLMENT);
        gateway.secondaryEnrollmentNonceSnapshot(root, secondary, address(permitToken));
        assertEq(gateway.actionNonces(root, StreamGTypes.ACTION_SPONSORED_ENROLLMENT), beforeNonce);
        assertFalse(gateway.intentUsed(bytes32(uint256(1))));
    }
}

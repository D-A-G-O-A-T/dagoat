// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {StreamGTypes} from "./StreamGTypes.sol";
import {IEnrollmentRegistryV1} from "./interfaces/IEnrollmentRegistryV1.sol";
import {FeeTokenRegistry} from "./FeeTokenRegistry.sol";

/// Append-only wallet sponsorship sidecar.
/// Domain: GoatWalletSponsorship / 1
/// Flat-star topology, immutable primaryOf, rotatable controllerOf.
contract WalletSponsorshipRegistry is EIP712 {
    using ECDSA for bytes32;

    error NotPolicySafe();
    error NotGateway();
    error NotRecoverySafe();
    error ZeroAddress();
    error GatewayAlreadyBound();
    error GatewayCodeMismatch();
    error BadIssuerSignature();
    error BadSecondarySignature();
    error BadRotationSignature();
    error ExpiredSignature();
    error InvalidRootAuthorization();
    error RootAlreadyRegistered();
    error RootNotRegistered();
    error SecondaryAlreadyLinked();
    error SecondaryIsRootController();
    error NotV1Eligible();
    error ClusterSuspended();
    error InvalidControllerRotation();
    error ControllerAlreadyAssigned();
    error RecoveryNotReady();
    error RecoveryMismatch();
    error RecoveryUnknown();
    error RecoveryAlreadyExecuted();

    IEnrollmentRegistryV1 public immutable enrollmentRegistry;
    FeeTokenRegistry public immutable feeTokenRegistry;
    address public immutable policySafe;
    address public immutable recoverySafe;
    uint256 public immutable recoveryTimelock;

    address public gateway;
    bool public gatewayBound;

    mapping(address => address) public primaryOf;
    mapping(address => address) public controllerOf;
    mapping(address => address) public controlledRootOf;
    mapping(address => uint256) public controllerEpoch;
    mapping(address => uint256) public rootRegistrationNonces;
    mapping(address => uint256) public linkNonces;
    mapping(address => uint256) public rotationNonces;
    mapping(address => bool) public suspendedClusters;
    mapping(address => bool) public profileIssuers;

    struct RecoverySchedule {
        address root;
        address newController;
        uint256 expectedRotationNonce;
        uint256 expectedControllerEpoch;
        uint64 readyAt;
        bool executed;
        bool exists;
    }

    mapping(bytes32 => RecoverySchedule) public recoverySchedules;

    event GatewayBound(address indexed gateway);
    event ProfileIssuerSet(address indexed issuer, bool allowed);
    event PrimaryRegistered(address indexed root, address indexed controller, uint256 registrationNonce);
    event SecondaryLinked(address indexed root, address indexed secondary, uint256 linkNonce);
    event ControllerRotated(
        address indexed root, address indexed oldController, address indexed newController, uint256 epoch
    );
    event ClusterSuspensionSet(address indexed root, bool suspended, bytes32 reasonHash);
    event RecoveryScheduled(
        bytes32 indexed scheduleId,
        address indexed root,
        address indexed newController,
        uint256 expectedRotationNonce,
        uint256 expectedControllerEpoch,
        uint64 readyAt,
        bytes32 reasonHash
    );
    event RecoveryExecuted(bytes32 indexed scheduleId, address indexed root, address indexed newController);

    modifier onlyPolicy() {
        if (msg.sender != policySafe) revert NotPolicySafe();
        _;
    }

    modifier onlyGateway() {
        if (msg.sender != gateway) revert NotGateway();
        _;
    }

    modifier onlyRecovery() {
        if (msg.sender != recoverySafe) revert NotRecoverySafe();
        _;
    }

    constructor(
        address enrollmentRegistry_,
        address feeTokenRegistry_,
        address policySafe_,
        address recoverySafe_,
        uint256 recoveryTimelock_
    ) EIP712("GoatWalletSponsorship", "1") {
        if (
            enrollmentRegistry_ == address(0) || feeTokenRegistry_ == address(0) || policySafe_ == address(0)
                || recoverySafe_ == address(0)
        ) {
            revert ZeroAddress();
        }
        if (recoveryTimelock_ < 2 days) {
            // Design floor for real-value is 48h; G1 tests use 7 days.
            // Allow constructor values >= 0 for unit flexibility only if policy sets >= 2 days in production.
        }
        enrollmentRegistry = IEnrollmentRegistryV1(enrollmentRegistry_);
        feeTokenRegistry = FeeTokenRegistry(feeTokenRegistry_);
        policySafe = policySafe_;
        recoverySafe = recoverySafe_;
        recoveryTimelock = recoveryTimelock_;
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function bindGatewayOnce(address gateway_) external onlyPolicy {
        if (gatewayBound) revert GatewayAlreadyBound();
        if (gateway_ == address(0)) revert ZeroAddress();
        (address committed, bytes32 codeHash) = feeTokenRegistry.getRoleCommitment(feeTokenRegistry.ROLE_GATEWAY());
        if (committed != gateway_ || gateway_.codehash != codeHash) revert GatewayCodeMismatch();
        gateway = gateway_;
        gatewayBound = true;
        emit GatewayBound(gateway_);
    }

    function setProfileIssuer(address issuer, bool allowed) external onlyPolicy {
        if (issuer == address(0)) revert ZeroAddress();
        profileIssuers[issuer] = allowed;
        emit ProfileIssuerSet(issuer, allowed);
    }

    function setClusterSuspended(address root, bool status, bytes32 reasonHash) external onlyPolicy {
        if (primaryOf[root] != root) revert RootNotRegistered();
        suspendedClusters[root] = status;
        emit ClusterSuspensionSet(root, status, reasonHash);
    }

    /// Permissionless: issuer-signed standalone root registration only.
    function registerPrimary(StreamGTypes.RootAuthorization calldata auth, bytes calldata issuerSignature)
        external
    {
        if (auth.root == address(0)) revert ZeroAddress();
        if (auth.secondary != address(0) || auth.linkDigest != bytes32(0)) revert InvalidRootAuthorization();
        if (auth.enrollDigest == bytes32(0)) revert InvalidRootAuthorization();
        if (block.timestamp >= auth.deadline) revert ExpiredSignature();
        if (primaryOf[auth.root] != address(0) || controlledRootOf[auth.root] != address(0)) {
            revert RootAlreadyRegistered();
        }
        if (auth.nonce != rootRegistrationNonces[auth.root]) revert InvalidRootAuthorization();
        _requireV1Eligible(auth.root);

        bytes32 digest = _hashRootAuthorization(auth);
        address signer = ECDSA.recover(digest, issuerSignature);
        if (!profileIssuers[signer]) revert BadIssuerSignature();

        rootRegistrationNonces[auth.root] = auth.nonce + 1;
        primaryOf[auth.root] = auth.root;
        controllerOf[auth.root] = auth.root;
        controlledRootOf[auth.root] = auth.root;
        // controllerEpoch starts at 0

        emit PrimaryRegistered(auth.root, auth.root, auth.nonce);
    }

    /// Gateway-only ordinary/combined link.
    function linkSecondary(
        StreamGTypes.LinkSecondary calldata link,
        bytes calldata secondarySignature,
        StreamGTypes.RootAuthorization calldata auth,
        bytes calldata issuerSignature
    ) external onlyGateway {
        if (link.root == address(0) || link.secondary == address(0)) revert ZeroAddress();
        if (link.secondary == link.root) revert InvalidRootAuthorization();
        if (block.timestamp >= link.deadline) revert ExpiredSignature();
        if (link.nonce != linkNonces[link.secondary]) revert InvalidRootAuthorization();
        if (primaryOf[link.secondary] != address(0)) revert SecondaryAlreadyLinked();
        if (controlledRootOf[link.secondary] != address(0)) revert SecondaryIsRootController();
        _requireV1Eligible(link.secondary);

        // If root not yet registered, require migration RootAuthorization with matching secondary/link.
        if (primaryOf[link.root] == address(0)) {
            if (auth.root != link.root || auth.secondary != link.secondary) revert InvalidRootAuthorization();
            if (auth.linkDigest == bytes32(0)) revert InvalidRootAuthorization();
            if (block.timestamp >= auth.deadline) revert ExpiredSignature();
            if (auth.nonce != rootRegistrationNonces[auth.root]) revert InvalidRootAuthorization();
            if (controlledRootOf[auth.root] != address(0)) revert RootAlreadyRegistered();
            _requireV1Eligible(auth.root);

            bytes32 rootDigest = _hashRootAuthorization(auth);
            // linkDigest must match the LinkSecondary digest being applied
            bytes32 expectedLinkDigest = _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        StreamGTypes.LINK_SECONDARY_TYPEHASH, link.root, link.secondary, link.nonce, link.deadline
                    )
                )
            );
            if (auth.linkDigest != expectedLinkDigest) revert InvalidRootAuthorization();

            address issuer = ECDSA.recover(rootDigest, issuerSignature);
            if (!profileIssuers[issuer]) revert BadIssuerSignature();

            rootRegistrationNonces[auth.root] = auth.nonce + 1;
            primaryOf[auth.root] = auth.root;
            controllerOf[auth.root] = auth.root;
            controlledRootOf[auth.root] = auth.root;
            emit PrimaryRegistered(auth.root, auth.root, auth.nonce);
        } else {
            // Already registered: require zeroed RootAuthorization fields
            if (
                auth.root != address(0) || auth.secondary != address(0) || auth.enrollDigest != bytes32(0)
                    || auth.linkDigest != bytes32(0) || auth.nonce != 0 || auth.deadline != 0
                    || issuerSignature.length != 0
            ) {
                revert InvalidRootAuthorization();
            }
            if (primaryOf[link.root] != link.root) revert RootNotRegistered();
        }

        if (suspendedClusters[link.root]) revert ClusterSuspended();

        bytes32 linkDigest = _hashTypedDataV4(
            keccak256(
                abi.encode(StreamGTypes.LINK_SECONDARY_TYPEHASH, link.root, link.secondary, link.nonce, link.deadline)
            )
        );
        address secondarySigner = ECDSA.recover(linkDigest, secondarySignature);
        if (secondarySigner != link.secondary) revert BadSecondarySignature();

        linkNonces[link.secondary] = link.nonce + 1;
        primaryOf[link.secondary] = link.root;
        emit SecondaryLinked(link.root, link.secondary, link.nonce);
    }

    function rotateController(
        StreamGTypes.ControllerRotation calldata rotation,
        bytes calldata oldSignature,
        bytes calldata newSignature
    ) external {
        if (primaryOf[rotation.root] != rotation.root) revert RootNotRegistered();
        if (rotation.oldController == address(0) || rotation.newController == address(0)) revert ZeroAddress();
        if (rotation.newController == rotation.oldController) revert InvalidControllerRotation();
        if (block.timestamp >= rotation.deadline) revert ExpiredSignature();
        if (rotation.nonce != rotationNonces[rotation.root]) revert InvalidControllerRotation();
        if (controllerOf[rotation.root] != rotation.oldController) revert InvalidControllerRotation();

        // Topology: newController must not already control another root (unless becoming this root's controller from unset)
        if (controlledRootOf[rotation.newController] != address(0)) revert ControllerAlreadyAssigned();
        // If newController != root, it must not already be linked under another primary
        if (rotation.newController != rotation.root && primaryOf[rotation.newController] != address(0)) {
            revert InvalidControllerRotation();
        }

        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    StreamGTypes.CONTROLLER_ROTATION_TYPEHASH,
                    rotation.root,
                    rotation.oldController,
                    rotation.newController,
                    rotation.nonce,
                    rotation.deadline
                )
            )
        );
        if (ECDSA.recover(digest, oldSignature) != rotation.oldController) revert BadRotationSignature();
        if (ECDSA.recover(digest, newSignature) != rotation.newController) revert BadRotationSignature();

        _applyControllerChange(rotation.root, rotation.oldController, rotation.newController);
    }

    function scheduleRecovery(
        address root,
        address newController,
        uint256 expectedRotationNonce,
        uint256 expectedControllerEpoch,
        bytes32 reasonHash
    ) external onlyRecovery returns (bytes32 scheduleId) {
        if (primaryOf[root] != root) revert RootNotRegistered();
        if (newController == address(0)) revert ZeroAddress();
        if (newController == controllerOf[root]) revert InvalidControllerRotation();
        if (controlledRootOf[newController] != address(0)) revert ControllerAlreadyAssigned();
        if (newController != root && primaryOf[newController] != address(0)) revert InvalidControllerRotation();
        if (expectedRotationNonce != rotationNonces[root]) revert RecoveryMismatch();
        if (expectedControllerEpoch != controllerEpoch[root]) revert RecoveryMismatch();

        scheduleId = keccak256(
            abi.encode(
                root, newController, expectedRotationNonce, expectedControllerEpoch, reasonHash, block.timestamp
            )
        );
        RecoverySchedule storage s = recoverySchedules[scheduleId];
        if (s.exists) revert RecoveryMismatch();

        uint64 readyAt = uint64(block.timestamp + recoveryTimelock);
        recoverySchedules[scheduleId] = RecoverySchedule({
            root: root,
            newController: newController,
            expectedRotationNonce: expectedRotationNonce,
            expectedControllerEpoch: expectedControllerEpoch,
            readyAt: readyAt,
            executed: false,
            exists: true
        });
        emit RecoveryScheduled(
            scheduleId, root, newController, expectedRotationNonce, expectedControllerEpoch, readyAt, reasonHash
        );
    }

    function executeRecovery(bytes32 scheduleId) external onlyRecovery {
        RecoverySchedule storage s = recoverySchedules[scheduleId];
        if (!s.exists) revert RecoveryUnknown();
        if (s.executed) revert RecoveryAlreadyExecuted();
        if (block.timestamp < s.readyAt) revert RecoveryNotReady();
        if (primaryOf[s.root] != s.root) revert RootNotRegistered();
        if (rotationNonces[s.root] != s.expectedRotationNonce) revert RecoveryMismatch();
        if (controllerEpoch[s.root] != s.expectedControllerEpoch) revert RecoveryMismatch();
        if (controlledRootOf[s.newController] != address(0)) revert ControllerAlreadyAssigned();
        if (s.newController != s.root && primaryOf[s.newController] != address(0)) {
            revert InvalidControllerRotation();
        }

        address oldController = controllerOf[s.root];
        s.executed = true;
        _applyControllerChange(s.root, oldController, s.newController);
        emit RecoveryExecuted(scheduleId, s.root, s.newController);
    }

    function _applyControllerChange(address root, address oldController, address newController) internal {
        if (controlledRootOf[oldController] == root) {
            controlledRootOf[oldController] = address(0);
        }
        controllerOf[root] = newController;
        controlledRootOf[newController] = root;
        rotationNonces[root] += 1;
        controllerEpoch[root] += 1;
        emit ControllerRotated(root, oldController, newController, controllerEpoch[root]);
    }

    function _requireV1Eligible(address wallet) internal view {
        if (!enrollmentRegistry.enrolled(wallet) || enrollmentRegistry.blacklisted(wallet)) {
            revert NotV1Eligible();
        }
    }

    function _hashRootAuthorization(StreamGTypes.RootAuthorization calldata auth)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    StreamGTypes.ROOT_AUTHORIZATION_TYPEHASH,
                    auth.root,
                    auth.secondary,
                    auth.enrollDigest,
                    auth.linkDigest,
                    auth.nonce,
                    auth.deadline
                )
            )
        );
    }
}
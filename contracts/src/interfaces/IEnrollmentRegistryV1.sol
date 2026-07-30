// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Frozen ABI surface of the deployed EnrollmentRegistry (V1).
/// Do not rename or edit contracts/src/EnrollmentRegistry.sol.
interface IEnrollmentRegistryV1 {
    function enrollSelf() external;

    function enrollSelfWithSignature(address wallet, uint256 deadline, bytes calldata signature) external;

    function nonces(address wallet) external view returns (uint256);

    function enrolled(address wallet) external view returns (bool);

    function blacklisted(address wallet) external view returns (bool);

    function DOMAIN_SEPARATOR() external view returns (bytes32);

    function ENROLL_TYPEHASH() external view returns (bytes32);
}
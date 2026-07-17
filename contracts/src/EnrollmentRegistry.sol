// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

/// Enrollment allowlist (spec §2.1). Transfers of GOAT are restricted to
/// enrolled↔enrolled during the pilot; system addresses (vault, desk,
/// escrow, safe, beneficiary) bypass. kycRef is a hash of the off-chain
/// enrollment record — no PII on-chain.
///
/// Gas models (same as WorkerBinding):
/// - `enrollSelf` — worker pays gas (Option B).
/// - `enrollSelfWithSignature` — relayer pays gas; worker recovered from EIP-712 (Option A).
contract EnrollmentRegistry is EIP712 {
    using ECDSA for bytes32;

    error NotSafe();
    error Blacklisted();
    error ExpiredSignature();
    error BadSignature();

    address public immutable safe;
    mapping(address => bool) public enrolled;
    mapping(address => bytes32) public kycRef;
    mapping(address => bool) public systemAddress;
    /// Founder security override — self-enroll reverts while true.
    mapping(address => bool) public blacklisted;
    /// per-wallet EIP-712 nonce for meta-tx enroll
    mapping(address => uint256) public nonces;

    /// keccak256("Enroll(address wallet,uint256 nonce,uint256 deadline)")
    bytes32 public constant ENROLL_TYPEHASH =
        keccak256("Enroll(address wallet,uint256 nonce,uint256 deadline)");

    event Enrolled(address indexed who, bool status, bytes32 kycRef);
    event SystemAddressSet(address indexed who, bool status);
    event BlacklistedSet(address indexed who, bool status);

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafe();
        _;
    }

    constructor(address safe_) EIP712("GoatEnrollmentRegistry", "1") {
        safe = safe_;
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// Permissionless self-enroll. Worker pays gas.
    function enrollSelf() external {
        _enroll(msg.sender);
    }

    /// Relayer path: any `msg.sender` submits; `wallet` must sign EIP-712 Enroll.
    function enrollSelfWithSignature(address wallet, uint256 deadline, bytes calldata signature)
        external
    {
        if (block.timestamp > deadline) revert ExpiredSignature();
        if (wallet == address(0)) revert BadSignature();

        uint256 nonce = nonces[wallet]++;
        bytes32 structHash = keccak256(abi.encode(ENROLL_TYPEHASH, wallet, nonce, deadline));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        if (signer != wallet) revert BadSignature();

        _enroll(wallet);
    }

    function _enroll(address wallet) internal {
        if (blacklisted[wallet]) revert Blacklisted();
        enrolled[wallet] = true;
        emit Enrolled(wallet, true, bytes32(0));
    }

    function setEnrolled(address who, bool status, bytes32 kycRef_) external onlySafe {
        enrolled[who] = status;
        kycRef[who] = kycRef_;
        emit Enrolled(who, status, kycRef_);
    }

    function setBlacklisted(address who, bool status) external onlySafe {
        blacklisted[who] = status;
        if (status) enrolled[who] = false;
        emit BlacklistedSet(who, status);
    }

    function setSystemAddress(address who, bool status) external onlySafe {
        systemAddress[who] = status;
        emit SystemAddressSet(who, status);
    }

    function isTransferAllowed(address from, address to) external view returns (bool) {
        if (systemAddress[from] || systemAddress[to]) return true;
        return enrolled[from] && enrolled[to];
    }
}

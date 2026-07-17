// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

/// Minimal wallet ↔ GOAT-username registry (FAH attribution plan 2026-07-14 §2b / T1–T2).
/// Uniqueness + set-once only — NO bonds, NO challenge lane. Baseline lives in EpochSettlement
/// as the first claimPayout watermark (mint 0). Rebind forbidden (INV-6).
///
/// Gas models:
/// - `bind` — worker pays gas (`msg.sender` = wallet). Option B / faucet-funded wallets.
/// - `bindWithSignature` — anyone (relayer/daemon) pays gas; worker is recovered from EIP-712
///   signature. Option A relayer. Without this, a relayer would bind the daemon's address
///   permanently under set-once (consultant hazard 2026-07-15).
contract WorkerBinding is EIP712 {
    using ECDSA for bytes32;

    error AlreadyBound();
    error NameTaken();
    error BadUsername();
    error ExpiredSignature();
    error BadSignature();

    /// wallet → "GOAT-<custom>" (public so challengers know which FAH /user/{name} to check)
    mapping(address => string) public usernameOf;
    /// keccak256(bytes(username)) → wallet (uniqueness)
    mapping(bytes32 => address) public walletOfNameHash;
    /// set-once guard
    mapping(address => bool) public bound;
    /// per-wallet EIP-712 nonce (replay protection for meta-tx)
    mapping(address => uint256) public nonces;

    /// keccak256("Bind(address wallet,string username,uint256 nonce,uint256 deadline)")
    bytes32 public constant BIND_TYPEHASH =
        keccak256("Bind(address wallet,string username,uint256 nonce,uint256 deadline)");

    event Bound(address indexed wallet, string username);

    constructor() EIP712("GoatWorkerBinding", "1") {}

    function nameHash(string calldata u) public pure returns (bytes32) {
        return keccak256(bytes(u));
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// Worker self-binds (msg.sender = wallet). For wallets that hold their own gas.
    function bind(string calldata username) external {
        _bind(msg.sender, username);
    }

    /// Relayer path: any `msg.sender` may submit; `wallet` must have signed the EIP-712 payload.
    /// `signature` is 65-byte r||s||v over the typed data digest.
    function bindWithSignature(
        address wallet,
        string calldata username,
        uint256 deadline,
        bytes calldata signature
    ) external {
        if (block.timestamp > deadline) revert ExpiredSignature();
        if (wallet == address(0)) revert BadSignature();

        uint256 nonce = nonces[wallet]++;
        bytes32 structHash = keccak256(
            abi.encode(BIND_TYPEHASH, wallet, keccak256(bytes(username)), nonce, deadline)
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        if (signer != wallet) revert BadSignature();

        _bind(wallet, username);
    }

    function _bind(address wallet, string calldata username) internal {
        if (bound[wallet]) revert AlreadyBound();
        if (!_validGoatUsername(username)) revert BadUsername();
        bytes32 h = nameHash(username);
        if (walletOfNameHash[h] != address(0)) revert NameTaken();

        usernameOf[wallet] = username;
        walletOfNameHash[h] = wallet;
        bound[wallet] = true;
        emit Bound(wallet, username);
    }

    function _validGoatUsername(string calldata username) internal pure returns (bool) {
        bytes memory b = bytes(username);
        // "GOAT-" + at least 1 char custom
        if (b.length < 6) return false;
        return b[0] == "G" && b[1] == "O" && b[2] == "A" && b[3] == "T" && b[4] == "-";
    }
}

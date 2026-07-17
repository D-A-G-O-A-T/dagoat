// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Swappable dispute resolver. EpochSettlement calls onDispute (informational) when a
/// batch is challenged; the resolver later calls back settleDispute with a ruling. A
/// FounderResolver today; a decentralized court later — same interface, no settlement change.
interface IDisputeResolver {
    function onDispute(uint256 epoch, address proposer, address challenger) external;
}

/// The settlement surface a resolver calls back into (avoids importing the full contract).
interface ISettlementDisputeSink {
    function settleDispute(uint256 epoch, bool proposerWon, bytes32 reasonRef) external;
}

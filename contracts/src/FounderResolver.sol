// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDisputeResolver, ISettlementDisputeSink} from "./IDisputeResolver.sol";

/// Pilot dispute resolver: the founder reviews the FAH public data off-chain and rules
/// on-chain, publicly and auditably. This is the labeled centralization residue on the
/// (rare) dispute path — swappable for a decentralized court via settlement.setResolver.
contract FounderResolver is IDisputeResolver {
    error NotFounder();
    error NotSettlement();

    address public immutable founder;
    address public immutable settlement;

    event DisputeSeen(uint256 indexed epoch, address proposer, address challenger);
    event Decided(uint256 indexed epoch, bool proposerWon, bytes32 reasonRef);

    constructor(address founder_, address settlement_) {
        founder = founder_;
        settlement = settlement_;
    }

    function onDispute(uint256 epoch, address proposer, address challenger) external {
        if (msg.sender != settlement) revert NotSettlement();
        emit DisputeSeen(epoch, proposer, challenger);
    }

    function decide(uint256 epoch, bool proposerWon, bytes32 reasonRef) external {
        if (msg.sender != founder) revert NotFounder();
        emit Decided(epoch, proposerWon, reasonRef);
        ISettlementDisputeSink(settlement).settleDispute(epoch, proposerWon, reasonRef);
    }
}

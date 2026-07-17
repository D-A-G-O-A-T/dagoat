// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {FounderResolver} from "../src/FounderResolver.sol";
import {ISettlementDisputeSink} from "../src/IDisputeResolver.sol";

// Minimal sink that records the last settleDispute call.
contract SinkMock is ISettlementDisputeSink {
    uint256 public lastEpoch;
    bool public lastProposerWon;
    bytes32 public lastReason;
    uint256 public calls;

    function settleDispute(uint256 epoch, bool proposerWon, bytes32 reasonRef) external {
        lastEpoch = epoch;
        lastProposerWon = proposerWon;
        lastReason = reasonRef;
        calls++;
    }
}

contract FounderResolverTest is Test {
    FounderResolver resolver;
    SinkMock sink;
    address founder = makeAddr("founder");
    address settlement; // = address(sink)

    function setUp() public {
        sink = new SinkMock();
        settlement = address(sink);
        resolver = new FounderResolver(founder, settlement);
    }

    function test_onDispute_onlySettlement() public {
        vm.expectRevert(FounderResolver.NotSettlement.selector);
        resolver.onDispute(1, address(1), address(2));
    }

    function test_decide_onlyFounder() public {
        vm.expectRevert(FounderResolver.NotFounder.selector);
        resolver.decide(1, true, bytes32(0));
    }

    function test_decide_callsSettlement() public {
        vm.prank(founder);
        resolver.decide(7, false, keccak256("bad-numbers"));
        assertEq(sink.calls(), 1);
        assertEq(sink.lastEpoch(), 7);
        assertEq(sink.lastProposerWon(), false);
        assertEq(sink.lastReason(), keccak256("bad-numbers"));
    }
}

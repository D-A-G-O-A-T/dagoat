// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {ProxyConsumerRegistry} from "../src/proxy/ProxyConsumerRegistry.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";

/// The consumer registry's six load-bearing facts.
///
/// The first of them -- that no address can put itself into the consumer set -- is the
/// R9 gate, and it is asserted against the deployed runtime rather than against the
/// source, because the property that matters is what the bytecode can be made to do.
contract ProxyConsumerRegistryTest is Test {
    ProxyConsumerRegistry reg;
    EnrollmentRegistry allowlist;
    MockUSDT stake;

    address safe = makeAddr("safe");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address stranger = makeAddr("stranger");
    address reserveSink = makeAddr("reserveSink");
    address courtRoom = makeAddr("courtRoom");

    uint256 constant MIN_STAKE = 1_000e6;
    uint64 constant DELAY = 3 days;
    bytes32 constant ALICE_REF = keccak256("consumer-record-alice");
    bytes32 constant BOB_REF = keccak256("consumer-record-bob");

    function setUp() public {
        allowlist = new EnrollmentRegistry(safe);
        stake = new MockUSDT();

        vm.startPrank(safe);
        allowlist.setEnrolled(alice, true, keccak256("kyc-alice"));
        allowlist.setEnrolled(bob, true, keccak256("kyc-bob"));
        vm.stopPrank();

        reg = new ProxyConsumerRegistry(safe, address(stake), address(allowlist), reserveSink, MIN_STAKE, DELAY);

        vm.prank(safe);
        reg.enrolConsumer(alice, ALICE_REF);

        stake.mint(alice, 10 * MIN_STAKE);
        vm.prank(alice);
        stake.approve(address(reg), type(uint256).max);
    }

    // ------------------------------------------------------------------ helpers

    /// Solidity's dispatcher emits each external function's selector as a literal
    /// PUSH4 in the runtime, so a contiguous four-byte scan is a faithful question to
    /// ask of the deployed code. Every test that uses it asserts a selector that IS
    /// present in the same test, so an empty result can never come from a broken
    /// scanner.
    function _hasSelector(bytes memory code, bytes4 sel) internal pure returns (bool) {
        for (uint256 i = 0; i + 4 <= code.length; i++) {
            if (code[i] == sel[0] && code[i + 1] == sel[1] && code[i + 2] == sel[2] && code[i + 3] == sel[3]) {
                return true;
            }
        }
        return false;
    }

    /// A call to a signature the contract does not implement reverts with EMPTY
    /// returndata, because there is no fallback. A call to a signature it does
    /// implement and refuses reverts with a four-byte custom error. That difference is
    /// what separates "absent" from "present but gated", and asserting only "the call
    /// failed" would conflate the two.
    function _absentEntrypoint(string memory signature) internal returns (bool) {
        (bool ok, bytes memory ret) = address(reg).call(abi.encodeWithSignature(signature));
        return !ok && ret.length == 0;
    }

    // -------------------------------------------------------------------- tests

    /// Mutations this detects:
    ///  - adding `function register() external { isConsumer[msg.sender] = true; }` or any
    ///    of the other three public-door spellings to ProxyConsumerRegistry;
    ///  - adding a fallback that routes unknown calldata into an enrolment path (the
    ///    empty-returndata half catches this even if the selector never appears);
    ///  - deleting `enrolConsumer`, which would make the absence assertions vacuous.
    function test_there_is_no_public_registration_path() public {
        bytes memory code = address(reg).code;
        assertGt(code.length, 1_000, "vacuity guard: the runtime scan read almost nothing");

        // Positive control FIRST: the scanner can find a selector that is really there.
        assertTrue(
            _hasSelector(code, bytes4(keccak256("enrolConsumer(address,bytes32)"))),
            "the selector scan cannot see the one enrolment entrypoint; an absence result would prove nothing"
        );

        string[4] memory publicDoors;
        publicDoors[0] = "register()";
        publicDoors[1] = "registerSelf()";
        publicDoors[2] = "joinAsConsumer()";
        publicDoors[3] = "enrol()";
        for (uint256 i = 0; i < publicDoors.length; i++) {
            assertFalse(
                _hasSelector(code, bytes4(keccak256(bytes(publicDoors[i])))),
                string.concat("a public registration path exists in the runtime: ", publicDoors[i])
            );
            assertTrue(
                _absentEntrypoint(publicDoors[i]),
                string.concat("calling it did not fail as an unimplemented function: ", publicDoors[i])
            );
        }

        // The discriminator itself, proven: a signature that DOES exist and is merely
        // gated fails with four bytes of returndata, not zero.
        (bool ok, bytes memory ret) =
            address(reg).call(abi.encodeWithSignature("enrolConsumer(address,bytes32)", stranger, BOB_REF));
        assertFalse(ok);
        assertEq(ret.length, 4, "a gated call must return a custom error, not empty returndata");
        assertEq(bytes4(ret), ProxyConsumerRegistry.NotSafe.selector);
    }

    /// Mutations this detects:
    ///  - dropping `onlySafe` from `enrolConsumer`;
    ///  - widening the modifier to the resolver, or to any address the Safe can point at;
    ///  - dropping the `registry.enrolled` check, which would make this contract a second
    ///    identity system instead of a composition with the existing allowlist.
    function test_only_safe_can_enrol_a_consumer() public {
        vm.expectRevert(ProxyConsumerRegistry.NotSafe.selector);
        vm.prank(stranger);
        reg.enrolConsumer(stranger, BOB_REF);

        // The resolver is not a second door either, even after the Safe repoints it.
        vm.prank(safe);
        reg.setResolver(courtRoom);
        vm.expectRevert(ProxyConsumerRegistry.NotSafe.selector);
        vm.prank(courtRoom);
        reg.enrolConsumer(courtRoom, BOB_REF);

        // Nor can the Safe enrol an address the shared allowlist does not hold.
        vm.expectRevert(ProxyConsumerRegistry.NotOnAllowlist.selector);
        vm.prank(safe);
        reg.enrolConsumer(stranger, BOB_REF);

        // Positive control: the one path that works, works.
        vm.prank(safe);
        reg.enrolConsumer(bob, BOB_REF);
        assertTrue(reg.isConsumer(bob));
        assertEq(reg.consumerOf(BOB_REF), bob);
        assertEq(reg.refOf(bob), BOB_REF);
    }

    /// Mutations this detects:
    ///  - changing `stakeOf[c] >= minStake` to `> 0`, or dropping the stake term entirely;
    ///  - dropping the live `registry.enrolled` read, so removal from the shared allowlist
    ///    would silently leave a consumer active here;
    ///  - leaving `stakeOf` untouched by `requestUnstake`, so an exiting consumer would
    ///    keep transacting while its collateral was already on the way out.
    function test_a_consumer_below_min_stake_is_not_active() public {
        assertFalse(reg.isActiveConsumer(alice), "enrolment alone must not make a consumer active");

        vm.prank(alice);
        reg.topUp(MIN_STAKE - 1);
        assertFalse(reg.isActiveConsumer(alice), "one unit short of the floor is still short");

        vm.prank(alice);
        reg.topUp(1);
        assertTrue(reg.isActiveConsumer(alice), "at the floor the consumer is active");
        assertEq(reg.stakeOf(alice), MIN_STAKE);

        // Composition: the shared allowlist still decides membership.
        vm.prank(safe);
        allowlist.setEnrolled(alice, false, bytes32(0));
        assertFalse(reg.isActiveConsumer(alice), "removal from the shared allowlist must deactivate");
        vm.prank(safe);
        allowlist.setEnrolled(alice, true, keccak256("kyc-alice"));
        assertTrue(reg.isActiveConsumer(alice));

        // And an exit request deactivates immediately, before the collateral moves.
        vm.prank(alice);
        reg.requestUnstake();
        assertFalse(reg.isActiveConsumer(alice));
        assertEq(reg.stakeOf(alice), 0);

        // A stranger was never a consumer and never becomes one by holding tokens.
        assertFalse(reg.isActiveConsumer(stranger));
    }

    /// Mutations this detects:
    ///  - deleting the `block.timestamp < unstakeReadyAt` check in `withdraw`;
    ///  - an off-by-one that lets the withdrawal land one second early;
    ///  - setting `unstakeReadyAt` from anything other than `unstakeDelay`;
    ///  - allowing a second `requestUnstake` to restart or bypass a pending exit.
    function test_unstake_honours_the_delay() public {
        vm.prank(alice);
        reg.topUp(MIN_STAKE);
        uint256 balanceBefore = stake.balanceOf(alice);

        vm.prank(alice);
        reg.requestUnstake();
        uint64 readyAt = reg.unstakeReadyAt(alice);
        assertEq(readyAt, uint64(block.timestamp) + DELAY, "the delay is not the configured one");
        assertEq(reg.pendingUnstakeOf(alice), MIN_STAKE);

        vm.prank(alice);
        vm.expectRevert(ProxyConsumerRegistry.UnstakeNotReady.selector);
        reg.withdraw();

        vm.warp(readyAt - 1);
        vm.prank(alice);
        vm.expectRevert(ProxyConsumerRegistry.UnstakeNotReady.selector);
        reg.withdraw();

        // A second request cannot restart or duplicate the pending exit.
        vm.prank(alice);
        vm.expectRevert(ProxyConsumerRegistry.UnstakeAlreadyRequested.selector);
        reg.requestUnstake();

        // Positive control: at the boundary exactly, it pays.
        vm.warp(readyAt);
        vm.prank(alice);
        reg.withdraw();
        assertEq(stake.balanceOf(alice), balanceBefore + MIN_STAKE);
        assertEq(reg.pendingUnstakeOf(alice), 0);
        assertEq(stake.balanceOf(address(reg)), 0);

        // Nothing pending, nothing to collect.
        vm.prank(alice);
        vm.expectRevert(ProxyConsumerRegistry.NoUnstakeRequested.selector);
        reg.withdraw();
    }

    /// Mutations this detects:
    ///  - adding a destination parameter to `slash`, or sending anywhere but `reserveSink`;
    ///  - dropping `onlyResolver`;
    ///  - taking from the pending exit before the active stake, or failing to reach the
    ///    pending exit at all -- which would make `requestUnstake` an escape hatch from a
    ///    ruling that has not landed yet;
    ///  - dropping the `amount > active + pending` bound.
    function test_slash_routes_to_the_reserve_sink_only() public {
        vm.prank(alice);
        reg.topUp(2 * MIN_STAKE);

        vm.expectRevert(ProxyConsumerRegistry.NotResolver.selector);
        vm.prank(stranger);
        reg.slash(alice, 1, "unauthorised");

        // Point the resolver at a third party, so "goes to the reserve sink" is
        // distinguishable from "goes to whoever called".
        vm.prank(safe);
        reg.setResolver(courtRoom);

        uint256 aliceBefore = stake.balanceOf(alice);
        uint256 held = stake.balanceOf(address(reg));

        vm.expectEmit(true, true, false, true);
        emit ProxyConsumerRegistry.StakeSlashed(alice, MIN_STAKE, reserveSink, "ruling-7");
        vm.prank(courtRoom);
        reg.slash(alice, MIN_STAKE, "ruling-7");

        assertEq(stake.balanceOf(reserveSink), MIN_STAKE, "the sink did not receive the slash");
        assertEq(stake.balanceOf(address(reg)), held - MIN_STAKE);
        assertEq(reg.stakeOf(alice), MIN_STAKE, "the active stake was not the source");
        // To nowhere else, named one by one.
        assertEq(stake.balanceOf(courtRoom), 0, "the resolver took a cut");
        assertEq(stake.balanceOf(safe), 0);
        assertEq(stake.balanceOf(stranger), 0);
        assertEq(stake.balanceOf(alice), aliceBefore, "the slashed party was refunded");

        // A pending exit is still reachable: the delay is what makes that true.
        vm.prank(alice);
        reg.requestUnstake();
        assertEq(reg.slashableStakeOf(alice), MIN_STAKE);
        vm.prank(courtRoom);
        reg.slash(alice, MIN_STAKE, "ruling-8");
        assertEq(stake.balanceOf(reserveSink), 2 * MIN_STAKE);
        assertEq(reg.pendingUnstakeOf(alice), 0, "the pending exit was not the second source");
        assertEq(stake.balanceOf(address(reg)), 0);

        // And nothing beyond what is held can be taken.
        vm.prank(courtRoom);
        vm.expectRevert(ProxyConsumerRegistry.AmountExceedsStake.selector);
        reg.slash(alice, 1, "ruling-9");
    }

    /// Mutations this detects:
    ///  - adding any supply-reducing entrypoint to this contract, under any of the three
    ///    conventional spellings, including one added later "behind a flag";
    ///  - a fallback that forwards unknown calldata to such a path on the stake token.
    function test_registry_has_no_burn_selector() public {
        bytes memory code = address(reg).code;
        assertGt(code.length, 1_000, "vacuity guard: the runtime scan read almost nothing");

        // Positive control FIRST, on a value-moving selector that really is there.
        assertTrue(
            _hasSelector(code, bytes4(keccak256("slash(address,uint256,string)"))),
            "the selector scan cannot see `slash`; an absence result would prove nothing"
        );

        string[3] memory forbidden;
        forbidden[0] = "burn(uint256)";
        forbidden[1] = "burn(address,uint256)";
        forbidden[2] = "burnFrom(address,uint256)";
        for (uint256 i = 0; i < forbidden.length; i++) {
            assertFalse(
                _hasSelector(code, bytes4(keccak256(bytes(forbidden[i])))),
                string.concat("the runtime carries a supply-reducing selector: ", forbidden[i])
            );
        }
        assertTrue(_absentEntrypoint("burn(uint256)"), "burn(uint256) is callable");
        assertTrue(_absentEntrypoint("burnFrom(address,uint256)"), "burnFrom(address,uint256) is callable");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {ProxyRevenueSettlement} from "../src/proxy/ProxyRevenueSettlement.sol";

/// Founder ruling FR-1 as executable code: the proxy revenue lane has no supply
/// destruction path and no issuance path. Not deferred, not a parameter set to
/// zero -- absent.
///
/// Three independent observers, because each of them fails differently:
///   1. the compiled RUNTIME, scanned for the three standard selectors and for a
///      hardcoded dead-address sink -- catches a function that reaches the
///      dispatcher under any name;
///   2. the compiled ABI, scanned by name -- catches an event or a custom error,
///      neither of which has a selector in the runtime dispatcher;
///   3. the SOURCE, swept in `ProxyNoBurnSource.test.mjs` -- catches a path
///      reachable only through an unlinked library or an inherited abstract.
/// Plus the issuance side: this contract holds no minter role, and a full
/// fund -> propose -> finalize -> claim cycle moves `totalSupply` by zero.
///
/// Historical note that makes the ruling cheap to honour: `SponsoredBuyDesk.sol`
/// has no buy entrypoint and no destruction path, and `GoatCoin` exposes no
/// supply-destruction function at all -- so the mechanism the brief named could
/// not have been built as written.
///
/// EVERY SCAN HERE CARRIES A POSITIVE CONTROL in the same test. A scanner that
/// always answers "not found" satisfies an absence assertion forever, so each
/// observer is first shown finding something that really is there.
contract ProxyRevenueNoBurnTest is Test {
    GoatCoin goat;
    EnrollmentRegistry reg;
    ProxyRevenueSettlement pool;

    address safe = makeAddr("safe");
    address funder = makeAddr("funder");
    address publisher = makeAddr("publisher");
    address treasury = makeAddr("treasury");
    address attestorSafe = makeAddr("attestorSafe");
    address reserveSink = makeAddr("reserveSink");
    address gateway = makeAddr("gateway");
    address resolver = makeAddr("resolver");
    address operator = makeAddr("operator");

    address constant DEAD = 0x000000000000000000000000000000000000dEaD;

    uint256 constant EPOCH = 8_000_000_020_664;
    uint256 constant BOND = 0.05 ether;

    string constant ARTIFACT = "out/ProxyRevenueSettlement.sol/ProxyRevenueSettlement.json";

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        pool = new ProxyRevenueSettlement(_config());

        vm.startPrank(safe);
        reg.setSystemAddress(address(pool), true);
        for (uint256 i = 0; i < 5; i++) {
            reg.setEnrolled([funder, treasury, attestorSafe, reserveSink, operator][i], true, bytes32("kyc"));
        }
        goat.setMinter(safe, true);
        goat.mint(funder, 1_000_000e18);
        vm.stopPrank();
        vm.deal(publisher, 10 ether);
    }

    // ------------------------------------------------------------- scanners

    function _contains(bytes memory hay, bytes4 needle) internal pure returns (bool) {
        if (hay.length < 4) return false;
        for (uint256 i = 0; i + 4 <= hay.length; i++) {
            if (hay[i] == needle[0] && hay[i + 1] == needle[1] && hay[i + 2] == needle[2] && hay[i + 3] == needle[3]) {
                return true;
            }
        }
        return false;
    }

    function _containsAddress(bytes memory hay, address needle) internal pure returns (bool) {
        bytes20 n = bytes20(needle);
        if (hay.length < 20) return false;
        for (uint256 i = 0; i + 20 <= hay.length; i++) {
            bool ok = true;
            for (uint256 j = 0; j < 20; j++) {
                if (hay[i + j] != n[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return true;
        }
        return false;
    }

    /// Byte-offset search. Returns `type(uint256).max` for "absent" so the caller
    /// must handle the miss rather than silently slicing from zero.
    function _indexOf(bytes memory hay, bytes memory needle) internal pure returns (uint256) {
        if (needle.length == 0 || hay.length < needle.length) return type(uint256).max;
        for (uint256 i = 0; i + needle.length <= hay.length; i++) {
            bool ok = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return i;
        }
        return type(uint256).max;
    }

    function _slice(bytes memory b, uint256 start, uint256 end) internal pure returns (string memory) {
        bytes memory out = new bytes(end - start);
        for (uint256 i = start; i < end; i++) {
            out[i - start] = b[i];
        }
        return string(out);
    }

    // ------------------------------------------------- controls on the tools

    /// POSITIVE CONTROL for the address scanner. `_contains` gets one inside the
    /// runtime test; without the same treatment here, a `_containsAddress` that
    /// always returned false would satisfy the dead-address assertion forever.
    ///
    /// Mutations this detects: `_containsAddress` returning a constant.
    function test_addressScannerFindsAnAddressThatIsReallyThere() public pure {
        bytes memory hay = abi.encodePacked(bytes12(0), bytes20(uint160(0xBEEF)));
        assertTrue(_containsAddress(hay, address(uint160(0xBEEF))), "address scanner control failed");
        assertFalse(_containsAddress(hay, address(uint160(0xF00D))), "address scanner matches anything");
    }

    /// POSITIVE CONTROL for the substring scanner that carves the ABI region out
    /// of the artifact. A `_indexOf` that always missed would make the ABI region
    /// empty (or the whole file), and either way the scan below stops meaning
    /// anything.
    ///
    /// Mutations this detects: `_indexOf` returning a constant; `_slice`
    /// returning an empty string.
    function test_substringScannerFindsAndSlicesWhatIsReallyThere() public pure {
        bytes memory hay = bytes("alpha-BRAVO-charlie");
        assertEq(_indexOf(hay, bytes("BRAVO")), 6, "substring scanner missed a present needle");
        assertEq(_indexOf(hay, bytes("DELTA")), type(uint256).max, "substring scanner matches anything");
        assertEq(_slice(hay, 6, 11), "BRAVO", "slice returned the wrong window");
    }

    /// The three literal selectors this suite scans for are asserted against their
    /// own preimages, so a typo in a hex literal cannot quietly turn a scan into a
    /// search for nothing.
    ///
    /// Mutations this detects: any edit to the three selector literals below.
    function test_theScannedSelectorsAreTheOnesTheyClaimToBe() public pure {
        assertEq(bytes4(0x42966c68), bytes4(keccak256("burn(uint256)")), "burn(uint256) literal is wrong");
        assertEq(bytes4(0x79cc6790), bytes4(keccak256("burnFrom(address,uint256)")), "burnFrom literal is wrong");
        assertEq(bytes4(0x44df8e70), bytes4(keccak256("burn()")), "burn() literal is wrong");
    }

    // ------------------------------------------------------- layer 1: runtime

    /// Mutations this detects: a burn function added in any visibility that
    /// reaches the dispatcher; a dead-address sink hardcoded.
    ///
    /// POSITIVE CONTROL FIRST: the scanner is shown to FIND a selector that really
    /// is in the runtime, so an always-false `_contains` cannot pass this test.
    function test_noBurnSelectorInProxyRevenueRuntime() public view {
        bytes memory rt = address(pool).code;
        assertGt(rt.length, 0, "runtime code must be non-empty");
        assertTrue(
            _contains(rt, ProxyRevenueSettlement.claim.selector),
            "scanner control failed: claim() selector must be findable in the runtime"
        );
        assertFalse(_contains(rt, bytes4(0x42966c68)), "burn(uint256) selector present");
        assertFalse(_contains(rt, bytes4(0x79cc6790)), "burnFrom(address,uint256) selector present");
        assertFalse(_contains(rt, bytes4(0x44df8e70)), "burn() selector present");
        assertFalse(_containsAddress(rt, DEAD), "dead-address sink hardcoded in the runtime");
    }

    // ----------------------------------------------------------- layer 2: ABI

    /// Mutations this detects: a Burn / Burned / BuyAndBurn event or custom error
    /// declared on the contract, which the runtime-selector scan alone would miss
    /// -- an event has no dispatcher entry, and a custom error only has one at the
    /// revert site.
    ///
    /// THE SCAN IS SCOPED TO THE `abi` ARRAY, NOT THE WHOLE FILE, and that is
    /// load-bearing. The artifact also carries `rawMetadata`, which embeds the
    /// contract's NatSpec -- and this contract's NatSpec documents the absence in
    /// so many words. A whole-file scan therefore reports a hit today, on prose
    /// that asserts the opposite of a defect, and the only way to make it green is
    /// to weaken it. The `abi` array is where a real declaration would land.
    ///
    /// The needle has NO SPACE after the colon: forge writes compact JSON. With
    /// `"name": "burn` the assertion passes against an artifact that really does
    /// declare one -- verified by the negative control, which was run with both
    /// spellings.
    function test_noBurnEventInProxyRevenueAbi() public view {
        bytes memory json = bytes(vm.readFile(ARTIFACT));
        assertGt(json.length, 10_000, "artifact read control failed: file is implausibly small");

        uint256 abiEnd = _indexOf(json, bytes("\"bytecode\""));
        assertTrue(abiEnd != type(uint256).max, "artifact layout changed: no \"bytecode\" key found");
        string memory abiRegion = vm.toLowercase(_slice(json, 0, abiEnd));

        // Controls: the region really is the ABI, and it really is being read.
        assertTrue(bytes(abiRegion).length > 5_000, "abi region control failed: slice is implausibly small");
        assertTrue(vm.contains(abiRegion, "proxyrevenuesettlement"), "artifact read control failed");
        assertTrue(vm.contains(abiRegion, "\"name\":\"claim\""), "abi scan control failed: claim() must be listed");

        assertFalse(vm.contains(abiRegion, "\"name\":\"burn"), "a burn-named ABI entry exists");
        assertFalse(vm.contains(abiRegion, "buyandburn"), "a buy-and-burn ABI entry exists");
        // Broadest form: no ABI entry of any kind -- function, event, error, or
        // parameter -- names the mechanism.
        assertFalse(vm.contains(abiRegion, "burn"), "the ABI names the forbidden mechanism");
    }

    // --------------------------------------------------------- the mint side

    /// Mutations this detects: the deploy script or a setter granting the pool
    /// minter rights; a mint path reintroduced on this lane.
    function test_proxySettlementIsNotAGoatMinter() public {
        assertFalse(goat.isMinter(address(pool)), "the revenue pool must never be a minter");
        vm.prank(address(pool));
        vm.expectRevert();
        goat.mint(makeAddr("op"), 1e18);
    }

    /// The property the minter-role assertion exists to protect: settlement moves
    /// GOAT that already exists, so a complete cycle is supply-neutral in BOTH
    /// directions. A role check alone would miss a mint reached through some other
    /// authority, and it would miss a destruction path entirely -- `totalSupply`
    /// falling is just as much a defect here as `totalSupply` rising.
    ///
    /// The cycle is real, not a stub: inflow recorded, epoch funded, batch
    /// proposed, challenge window elapsed, batch finalized (which routes the take
    /// to two live destinations), operator claim settled against a Merkle proof.
    /// Balances are asserted to have actually moved, so a cycle that silently did
    /// nothing cannot pass by leaving supply untouched.
    ///
    /// Mutations this detects: any mint or supply-destruction call added to
    /// `fundEpoch`, `finalizeBatch` or `claim`; a take routed to a sink that
    /// removes supply rather than to a holder.
    function test_totalSupplyIsUnchangedByAFullFundAndClaimCycle() public {
        uint256 supplyBefore = goat.totalSupply();
        assertGt(supplyBefore, 0, "supply control failed: nothing was issued in setUp");

        uint256 gross = 1_000e18;
        uint256 payout = 900e18;

        vm.prank(gateway);
        pool.recordUsdtInflow(EPOCH, 1_000e6);
        vm.startPrank(funder);
        goat.approve(address(pool), gross);
        pool.fundEpoch(EPOCH, gross, 1_000e6);
        vm.stopPrank();

        bytes32 root = keccak256(
            bytes.concat(keccak256(abi.encode(pool.PROXY_LEAF_DOMAIN(), operator, EPOCH, uint256(1), payout)))
        );

        vm.prank(publisher);
        pool.proposeBatch{value: BOND}(EPOCH, root, bytes32("evidence"), gross);
        vm.warp(block.timestamp + 6 hours + 1);
        vm.prank(publisher);
        pool.finalizeBatch(EPOCH);

        pool.claim(EPOCH, operator, 1, payout, new bytes32[](0));

        // The cycle actually moved value -- otherwise "supply unchanged" is
        // satisfied by a cycle that did nothing at all.
        assertEq(goat.balanceOf(operator), payout, "the operator payout did not settle");
        assertEq(goat.balanceOf(treasury), (gross * 600) / 10_000, "the treasury share did not settle");
        assertEq(goat.balanceOf(attestorSafe), (gross * 200) / 10_000, "the attestor share did not settle");

        assertEq(goat.totalSupply(), supplyBefore, "settlement moved total supply");
    }

    // -------------------------------------------------------------- helpers

    function _config() internal returns (ProxyRevenueSettlement.Config memory) {
        return ProxyRevenueSettlement.Config({
            safe: safe,
            goat: address(goat),
            registry: address(reg),
            treasury: treasury,
            attestorSafe: attestorSafe,
            reserveSink: reserveSink,
            funder: funder,
            publisher: publisher,
            gateway: gateway,
            usdtTreasury: makeAddr("usdtTreasury"),
            resolver: resolver,
            watcher: makeAddr("watcher"),
            challengeWindow: 6 hours,
            claimWindow: 30 days,
            resolveWindow: 7 days,
            proposerBond: BOND,
            challengerBond: BOND,
            referenceRateUsdtPerGoat: 1e6
        });
    }
}

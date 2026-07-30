// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {FeeTokenRegistry} from "../src/FeeTokenRegistry.sol";
import {WalletSponsorshipRegistry} from "../src/WalletSponsorshipRegistry.sol";
import {SponsoredBuyDesk} from "../src/SponsoredBuyDesk.sol";
import {StreamGTypes} from "../src/StreamGTypes.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";

contract SponsoredBuyDeskTest is Test {
    using ECDSA for bytes32;

    uint256 constant ISSUER_PK = 0xA11CE;
    uint256 constant ROOT_PK = 0xB0B;
    uint256 constant SECONDARY_PK = 0xC0FFEE;
    uint256 constant SELLER_PK = 0xB0B; // root sells in basic tests

    address internal policy;
    address internal issuer;
    address internal owner; // desk owner / founder
    address internal feeSafe;
    address internal gateway;
    address internal minter;
    address internal root;
    address internal secondary;

    EnrollmentRegistry internal v1;
    GoatCoin internal goat;
    MockUSDT internal usdt;
    FeeTokenRegistry internal feeRegistry;
    WalletSponsorshipRegistry internal sidecar;
    SponsoredBuyDesk internal desk;

    uint256 constant BID = 10_000; // 0.01 USDT per GOAT
    uint256 constant DAILY_ROOT_CAP = 10_000e18;
    uint256 constant OWNER_USDT = 1_000_000e6;

    bytes32 constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 constant ROOT_AUTH_TYPEHASH = keccak256(
        "RootAuthorization(address root,address secondary,bytes32 enrollDigest,bytes32 linkDigest,uint256 nonce,uint48 deadline)"
    );
    bytes32 constant LINK_TYPEHASH =
        keccak256("LinkSecondary(address root,address secondary,uint256 nonce,uint48 deadline)");

    function setUp() public {
        policy = address(this);
        issuer = vm.addr(ISSUER_PK);
        owner = makeAddr("owner");
        feeSafe = makeAddr("feeSafe");
        gateway = makeAddr("gateway");
        minter = makeAddr("minter");
        root = vm.addr(ROOT_PK);
        secondary = vm.addr(SECONDARY_PK);

        v1 = new EnrollmentRegistry(policy);
        goat = new GoatCoin("GoatCoin", "GOAT", policy, v1);
        usdt = new MockUSDT();
        feeRegistry = new FeeTokenRegistry(policy);
        sidecar = new WalletSponsorshipRegistry(address(v1), address(feeRegistry), policy, makeAddr("recovery"), 7 days);

        // System addresses so restricted transfers work for desk/owner/feeSafe
        v1.setSystemAddress(owner, true);
        v1.setSystemAddress(feeSafe, true);

        goat.setMinter(minter, true);

        // Enroll root/secondary
        vm.prank(root);
        v1.enrollSelf();
        vm.prank(secondary);
        v1.enrollSelf();

        // Register root + link secondary in sidecar
        feeRegistry.setRoleCommitment(feeRegistry.ROLE_GATEWAY(), gateway, bytes32(uint256(1)));
        vm.etch(gateway, hex"60006000");
        feeRegistry.setRoleCommitment(feeRegistry.ROLE_GATEWAY(), gateway, gateway.codehash);
        sidecar.bindGatewayOnce(gateway);
        sidecar.setProfileIssuer(issuer, true);

        StreamGTypes.RootAuthorization memory rootAuth = StreamGTypes.RootAuthorization({
            root: root,
            secondary: address(0),
            enrollDigest: bytes32(uint256(1)),
            linkDigest: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 days)
        });
        sidecar.registerPrimary(rootAuth, _signRootAuth(rootAuth, ISSUER_PK));

        StreamGTypes.LinkSecondary memory link = StreamGTypes.LinkSecondary({
            root: root,
            secondary: secondary,
            nonce: 0,
            deadline: uint48(block.timestamp + 1 days)
        });
        StreamGTypes.RootAuthorization memory zeroAuth;
        vm.prank(gateway);
        sidecar.linkSecondary(link, _signLink(link, SECONDARY_PK), zeroAuth, "");

        desk = new SponsoredBuyDesk(
            owner,
            IERC20(address(usdt)),
            goat,
            v1,
            sidecar,
            feeSafe,
            DAILY_ROOT_CAP
        );

        // Bind gateway on desk (owner-gated admin op for G1).
        feeRegistry.setRoleCommitment(feeRegistry.ROLE_SPONSORED_BUY_DESK(), address(desk), address(desk).codehash);
        vm.prank(owner);
        desk.bindGatewayOnce(gateway);

        // Fund owner USDT allowance and mint GOAT to sellers
        usdt.mint(owner, OWNER_USDT);
        vm.prank(owner);
        usdt.approve(address(desk), type(uint256).max);

        vm.prank(minter);
        goat.mint(root, 10_000e18);
        vm.prank(minter);
        goat.mint(secondary, 10_000e18);

        // Open a session
        vm.prank(owner);
        desk.setBid(BID);
        vm.prank(owner);
        desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 5_000e18);

        // Mark desk as system for GOAT transfers to owner
        v1.setSystemAddress(address(desk), true);
    }

    function _domainSeparator(string memory name, address verifying) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
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
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator("GoatWalletSponsorship", address(sidecar)), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signLink(StreamGTypes.LinkSecondary memory link, uint256 pk) internal view returns (bytes memory) {
        bytes32 structHash =
            keccak256(abi.encode(LINK_TYPEHASH, link.root, link.secondary, link.nonce, link.deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator("GoatWalletSponsorship", address(sidecar)), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _goatPermit(address seller, uint256 sellerPk, uint256 amount)
        internal
        view
        returns (StreamGTypes.Eip2612Authorization memory p)
    {
        uint256 nonce = goat.nonces(seller);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, seller, address(desk), amount, nonce, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", goat.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sellerPk, digest);
        p = StreamGTypes.Eip2612Authorization({
            owner: seller,
            spender: address(desk),
            value: amount,
            deadline: deadline,
            v: v,
            r: r,
            s: s
        });
    }

    function test_sellFor_only_gateway() public {
        uint256 amount = 100e18;
        StreamGTypes.Eip2612Authorization memory permit = _goatPermit(root, ROOT_PK, amount);
        vm.expectRevert(SponsoredBuyDesk.NotGateway.selector);
        desk.sellFor(root, root, amount, 0, 0, permit);
    }

    function test_sellFor_splits_gross_fee_net_and_respects_minNet() public {
        uint256 amount = 100e18; // gross = 100e18 * 10000 / 1e18 = 1e6 = 1 USDT
        uint256 fee = 0.1e6;
        uint256 minNet = 0.9e6;
        StreamGTypes.Eip2612Authorization memory permit = _goatPermit(root, ROOT_PK, amount);

        uint256 ownerUsdtBefore = usdt.balanceOf(owner);
        uint256 sellerUsdtBefore = usdt.balanceOf(root);
        uint256 feeSafeBefore = usdt.balanceOf(feeSafe);
        uint256 ownerGoatBefore = goat.balanceOf(owner);
        uint256 sellerGoatBefore = goat.balanceOf(root);

        vm.prank(gateway);
        (address gotRoot, uint256 gross, uint256 net) =
            desk.sellFor(root, root, amount, minNet, fee, permit);

        assertEq(gotRoot, root);
        assertEq(gross, 1e6);
        assertEq(net, 0.9e6);
        assertEq(usdt.balanceOf(root), sellerUsdtBefore + net);
        assertEq(usdt.balanceOf(feeSafe), feeSafeBefore + fee);
        assertEq(usdt.balanceOf(owner), ownerUsdtBefore - gross);
        assertEq(goat.balanceOf(owner), ownerGoatBefore + amount);
        assertEq(goat.balanceOf(root), sellerGoatBefore - amount);
    }

    function test_exact_goat_permit_spender_is_desk() public {
        uint256 amount = 50e18;
        // Wrong spender in permit
        StreamGTypes.Eip2612Authorization memory bad = _goatPermit(root, ROOT_PK, amount);
        bad.spender = gateway;
        // resign with wrong spender fields but keep signature for desk spender -> invalid
        // Build signature for gateway spender
        uint256 nonce = goat.nonces(root);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, root, gateway, amount, nonce, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", goat.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ROOT_PK, digest);
        bad = StreamGTypes.Eip2612Authorization({
            owner: root,
            spender: gateway,
            value: amount,
            deadline: deadline,
            v: v,
            r: r,
            s: s
        });

        vm.prank(gateway);
        vm.expectRevert(SponsoredBuyDesk.InvalidGoatPermit.selector);
        desk.sellFor(root, root, amount, 0, 0, bad);
    }

    function test_root_session_and_utc_day_caps_aggregate_secondaries() public {
        // Session cap 150 GOAT; sell 100 as root then 100 as secondary should fail on second
        vm.prank(owner);
        desk.closeSession();
        vm.prank(owner);
        desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 150e18);

        StreamGTypes.Eip2612Authorization memory p1 = _goatPermit(root, ROOT_PK, 100e18);
        vm.prank(gateway);
        desk.sellFor(root, root, 100e18, 0, 0, p1);

        StreamGTypes.Eip2612Authorization memory p2 = _goatPermit(secondary, SECONDARY_PK, 100e18);
        vm.prank(gateway);
        vm.expectRevert(SponsoredBuyDesk.SessionCapExceeded.selector);
        desk.sellFor(secondary, root, 100e18, 0, 0, p2);

        // UTC day cap: reopen huge session but tiny daily cap via new desk would be needed;
        // here assert soldInSession aggregates under root for secondary success path under larger cap
        vm.prank(owner);
        desk.closeSession();
        vm.prank(owner);
        desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 10_000e18);

        StreamGTypes.Eip2612Authorization memory p3 = _goatPermit(secondary, SECONDARY_PK, 50e18);
        vm.prank(gateway);
        desk.sellFor(secondary, root, 50e18, 0, 0, p3);
        (uint256 sessionId,,,) = desk.currentSession();
        // New session only contains the post-reopen secondary sale, still keyed by immutable root.
        assertEq(desk.soldInSession(sessionId, root), 50e18);
        // UTC-day aggregation still includes the earlier root sale from the previous session.
        uint256 dayIndex = block.timestamp / 1 days;
        assertEq(desk.soldPerUtcDay(dayIndex, root), 150e18);
    }

    function test_minNet_and_fee_constraints() public {
        uint256 amount = 100e18; // gross 1e6
        StreamGTypes.Eip2612Authorization memory permit = _goatPermit(root, ROOT_PK, amount);
        vm.prank(gateway);
        vm.expectRevert(SponsoredBuyDesk.MinNetNotMet.selector);
        desk.sellFor(root, root, amount, 1e6, 0.1e6, permit); // minNet 1 USDT but fee 0.1 => net 0.9

        StreamGTypes.Eip2612Authorization memory permit2 = _goatPermit(root, ROOT_PK, amount);
        vm.prank(gateway);
        vm.expectRevert(SponsoredBuyDesk.FeeExceedsGross.selector);
        desk.sellFor(root, root, amount, 0, 2e6, permit2);
    }

    function test_expected_root_must_match_cluster() public {
        uint256 amount = 10e18;
        StreamGTypes.Eip2612Authorization memory permit = _goatPermit(secondary, SECONDARY_PK, amount);
        vm.prank(gateway);
        vm.expectRevert(SponsoredBuyDesk.RootMismatch.selector);
        desk.sellFor(secondary, secondary, amount, 0, 0, permit); // secondary is not a root
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {FeeTokenRegistry} from "../src/FeeTokenRegistry.sol";
import {WalletSponsorshipRegistry} from "../src/WalletSponsorshipRegistry.sol";
import {SponsoredBuyDesk} from "../src/SponsoredBuyDesk.sol";
import {GoatRelayGateway} from "../src/GoatRelayGateway.sol";
import {StreamGTypes} from "../src/StreamGTypes.sol";
import {PermitMockUSDT} from "./mocks/PermitMockUSDT.sol";
import {FeeOnTransferMockUSDT} from "./mocks/FeeOnTransferMockUSDT.sol";
import {FalseReturnMockUSDT} from "./mocks/FalseReturnMockUSDT.sol";

/// Task 9: Stream G invariants + adversarial fail-closed cases.
contract StreamGHandler is Test {
    EnrollmentRegistry public v1;
    WalletSponsorshipRegistry public sidecar;
    SponsoredBuyDesk public desk;
    GoatRelayGateway public gateway;
    GoatCoin public goat;
    PermitMockUSDT public usdt;
    address public feeSafe;
    address public deskOwner;
    address public minter;
    address public root;
    uint256 public rootPk;
    address public secondary;
    uint256 public secondaryPk;
    address public tertiary;
    uint256 public tertiaryPk;
    uint256 public quotePk;

    uint256 public ghostSellSuccess;
    uint256 public ghostLinked;

    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    constructor(
        EnrollmentRegistry v1_,
        WalletSponsorshipRegistry sidecar_,
        SponsoredBuyDesk desk_,
        GoatRelayGateway gateway_,
        GoatCoin goat_,
        PermitMockUSDT usdt_,
        address feeSafe_,
        address deskOwner_,
        address minter_,
        address root_,
        uint256 rootPk_,
        address secondary_,
        uint256 secondaryPk_,
        address tertiary_,
        uint256 tertiaryPk_,
        uint256 quotePk_
    ) {
        v1 = v1_;
        sidecar = sidecar_;
        desk = desk_;
        gateway = gateway_;
        goat = goat_;
        usdt = usdt_;
        feeSafe = feeSafe_;
        deskOwner = deskOwner_;
        minter = minter_;
        root = root_;
        rootPk = rootPk_;
        secondary = secondary_;
        secondaryPk = secondaryPk_;
        tertiary = tertiary_;
        tertiaryPk = tertiaryPk_;
        quotePk = quotePk_;
    }

    function _sign(bytes32 digest, uint256 pk) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function tryLinkSecondary(uint8 who) external {
        address sec = who % 2 == 0 ? secondary : tertiary;
        uint256 secPk = who % 2 == 0 ? secondaryPk : tertiaryPk;
        if (sidecar.primaryOf(sec) != address(0)) return;
        if (!v1.enrolled(sec)) {
            vm.prank(sec);
            v1.enrollSelf();
        }
        StreamGTypes.LinkSecondary memory link = StreamGTypes.LinkSecondary({
            root: root,
            secondary: sec,
            nonce: sidecar.linkNonces(sec),
            deadline: uint48(block.timestamp + 1 hours)
        });
        bytes32 structHash = keccak256(
            abi.encode(StreamGTypes.LINK_SECONDARY_TYPEHASH, link.root, link.secondary, link.nonce, link.deadline)
        );
        bytes memory sig =
            _sign(keccak256(abi.encodePacked("\x19\x01", sidecar.DOMAIN_SEPARATOR(), structHash)), secPk);
        StreamGTypes.RootAuthorization memory zeroAuth;
        vm.prank(address(gateway));
        try sidecar.linkSecondary(link, sig, zeroAuth, "") {
            ghostLinked += 1;
        } catch {}
    }

    function trySecondaryAsRoot() external {
        if (sidecar.primaryOf(secondary) == address(0)) return;
        if (!v1.enrolled(tertiary)) {
            vm.prank(tertiary);
            v1.enrollSelf();
        }
        StreamGTypes.LinkSecondary memory link = StreamGTypes.LinkSecondary({
            root: secondary,
            secondary: tertiary,
            nonce: sidecar.linkNonces(tertiary),
            deadline: uint48(block.timestamp + 1 hours)
        });
        bytes32 structHash = keccak256(
            abi.encode(StreamGTypes.LINK_SECONDARY_TYPEHASH, link.root, link.secondary, link.nonce, link.deadline)
        );
        bytes memory sig =
            _sign(keccak256(abi.encodePacked("\x19\x01", sidecar.DOMAIN_SEPARATOR(), structHash)), tertiaryPk);
        StreamGTypes.RootAuthorization memory zeroAuth;
        vm.prank(address(gateway));
        try sidecar.linkSecondary(link, sig, zeroAuth, "") {} catch {}
    }

    function trySponsoredSell(uint96 amountSeed, uint96 feeSeed) external {
        uint256 goatAmount = bound(uint256(amountSeed), 1e18, 20e18);
        uint256 gross = goatAmount * desk.bid() / 1e18;
        if (gross < 2) return;
        uint256 feeAmount = bound(uint256(feeSeed), 1, gross / 10);
        if (goat.balanceOf(root) < goatAmount) {
            vm.prank(minter);
            goat.mint(root, goatAmount);
        }
        if (usdt.balanceOf(deskOwner) < gross) {
            usdt.mint(deskOwner, gross * 2);
            vm.prank(deskOwner);
            usdt.approve(address(desk), type(uint256).max);
        }

        uint256 nonce = gateway.actionNonces(root, StreamGTypes.ACTION_SPONSORED_SELL);
        bytes32 intentId = keccak256(abi.encode("sell", nonce, goatAmount, feeAmount, block.number));
        bytes32 feeCfg = gateway.feeTokenRegistry().getTokenConfigHash(address(usdt));
        bytes32 manifest = gateway.feeTokenRegistry().activeManifestHash();

        uint256 pn = goat.nonces(root);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 permitStruct =
            keccak256(abi.encode(PERMIT_TYPEHASH, root, address(desk), goatAmount, pn, deadline));
        bytes32 goatPermitDigest = keccak256(abi.encodePacked("\x19\x01", goat.DOMAIN_SEPARATOR(), permitStruct));
        (uint8 pv, bytes32 pr, bytes32 ps) = vm.sign(rootPk, goatPermitDigest);
        StreamGTypes.Eip2612Authorization memory goatPermit = StreamGTypes.Eip2612Authorization({
            owner: root,
            spender: address(desk),
            value: goatAmount,
            deadline: deadline,
            v: pv,
            r: pr,
            s: ps
        });

        StreamGTypes.SellIntent memory intent = StreamGTypes.SellIntent({
            intentId: intentId,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            seller: root,
            expectedRoot: root,
            desk: address(desk),
            goatAmount: goatAmount,
            minNetUsdtOut: gross - feeAmount,
            goatPermitDigest: goatPermitDigest,
            maxFee: feeAmount,
            feeQuoteHash: bytes32(0),
            nonce: nonce,
            deadline: uint48(block.timestamp + 1 hours)
        });

        bytes32 core = keccak256(
            abi.encode(
                StreamGTypes.SELL_CORE_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.seller,
                intent.expectedRoot,
                intent.desk,
                intent.goatAmount,
                intent.minNetUsdtOut,
                intent.goatPermitDigest,
                intent.maxFee,
                intent.nonce,
                intent.deadline
            )
        );
        StreamGTypes.FeeQuote memory quote = StreamGTypes.FeeQuote({
            quoteId: keccak256(abi.encode(intentId, "q")),
            actionType: StreamGTypes.ACTION_SPONSORED_SELL,
            actionCoreHash: core,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            feeScheduleHash: gateway.feeScheduleHash(),
            payer: root,
            feeToken: address(usdt),
            feeAmount: feeAmount,
            feeRecipient: feeSafe,
            validAfter: uint48(block.timestamp - 1),
            validUntil: uint48(block.timestamp + 1 hours)
        });
        bytes32 qStruct = keccak256(
            abi.encode(
                StreamGTypes.FEE_QUOTE_TYPEHASH,
                quote.quoteId,
                quote.actionType,
                quote.actionCoreHash,
                quote.deploymentManifestHash,
                quote.feeTokenConfigHash,
                quote.feeScheduleHash,
                quote.payer,
                quote.feeToken,
                quote.feeAmount,
                quote.feeRecipient,
                quote.validAfter,
                quote.validUntil
            )
        );
        bytes32 feeQuoteHash = keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), qStruct));
        intent.feeQuoteHash = feeQuoteHash;
        bytes memory quoteSig = _sign(feeQuoteHash, quotePk);

        bytes32 iStruct = keccak256(
            abi.encode(
                StreamGTypes.SELL_INTENT_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.seller,
                intent.expectedRoot,
                intent.desk,
                intent.goatAmount,
                intent.minNetUsdtOut,
                intent.goatPermitDigest,
                intent.maxFee,
                intent.feeQuoteHash,
                intent.nonce,
                intent.deadline
            )
        );
        bytes memory intentSig =
            _sign(keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), iStruct)), rootPk);

        uint256 feeBefore = usdt.balanceOf(feeSafe);
        uint256 goatBefore = goat.balanceOf(root);
        try gateway.executeSponsoredSell(intent, quote, goatPermit, intentSig, quoteSig) {
            ghostSellSuccess += 1;
            require(usdt.balanceOf(feeSafe) == feeBefore + feeAmount, "fee only on success");
            require(goat.balanceOf(root) == goatBefore - goatAmount, "goat moved");
        } catch {
            require(usdt.balanceOf(feeSafe) == feeBefore, "no fee on fail");
            require(goat.balanceOf(root) == goatBefore, "no goat on fail");
        }
    }
}

contract StreamGInvariants is StdInvariant, Test {
    uint256 constant ISSUER_PK = 0xA11CE;
    uint256 constant ROOT_PK = 0xB0B;
    uint256 constant SECONDARY_PK = 0xC0FFEE;
    uint256 constant TERTIARY_PK = 0xD00D;
    uint256 constant QUOTE_PK = 0xE11E;

    StreamGHandler internal handler;
    EnrollmentRegistry internal v1;
    WalletSponsorshipRegistry internal sidecar;
    SponsoredBuyDesk internal desk;
    GoatRelayGateway internal gateway;
    GoatCoin internal goat;
    PermitMockUSDT internal usdt;
    FeeTokenRegistry internal feeRegistry;
    address internal issuer;
    address internal root;
    address internal secondary;
    address internal tertiary;
    address internal feeSafe;
    address internal deskOwner;
    address internal minter;
    address internal quoteSigner;
    address internal recovery;

    function setUp() public {
        issuer = vm.addr(ISSUER_PK);
        root = vm.addr(ROOT_PK);
        secondary = vm.addr(SECONDARY_PK);
        tertiary = vm.addr(TERTIARY_PK);
        quoteSigner = vm.addr(QUOTE_PK);
        feeSafe = makeAddr("feeSafe");
        deskOwner = makeAddr("deskOwner");
        minter = makeAddr("minter");
        recovery = makeAddr("recovery");

        v1 = new EnrollmentRegistry(address(this));
        goat = new GoatCoin("GoatCoin", "GOAT", address(this), v1);
        feeRegistry = new FeeTokenRegistry(address(this));
        sidecar = new WalletSponsorshipRegistry(address(v1), address(feeRegistry), address(this), recovery, 7 days);
        usdt = new PermitMockUSDT();

        vm.prank(root);
        v1.enrollSelf();

        gateway = new GoatRelayGateway(
            address(v1), address(feeRegistry), address(sidecar), address(goat), address(this), feeSafe
        );
        feeRegistry.setRoleCommitment(feeRegistry.ROLE_GATEWAY(), address(gateway), address(gateway).codehash);
        sidecar.bindGatewayOnce(address(gateway));
        sidecar.setProfileIssuer(issuer, true);

        StreamGTypes.RootAuthorization memory auth = StreamGTypes.RootAuthorization({
            root: root,
            secondary: address(0),
            enrollDigest: bytes32(uint256(1)),
            linkDigest: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 days)
        });
        bytes32 rootStruct = keccak256(
            abi.encode(
                StreamGTypes.ROOT_AUTHORIZATION_TYPEHASH,
                auth.root,
                auth.secondary,
                auth.enrollDigest,
                auth.linkDigest,
                auth.nonce,
                auth.deadline
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(ISSUER_PK, keccak256(abi.encodePacked("\x19\x01", sidecar.DOMAIN_SEPARATOR(), rootStruct)));
        sidecar.registerPrimary(auth, abi.encodePacked(r, s, v));

        feeRegistry.setActiveManifestHash(keccak256("manifest-g1-inv"));
        gateway.setFeeScheduleHash(keccak256("schedule-g1-inv"));
        gateway.setQuoteSigner(quoteSigner);
        gateway.setPaused(false);
        gateway.activate();

        v1.setSystemAddress(deskOwner, true);
        v1.setSystemAddress(feeSafe, true);
        v1.setSystemAddress(address(gateway), true);
        goat.setMinter(minter, true);

        desk = new SponsoredBuyDesk(deskOwner, IERC20(address(usdt)), goat, v1, sidecar, feeSafe, 10_000e18);
        v1.setSystemAddress(address(desk), true);
        feeRegistry.setRoleCommitment(feeRegistry.ROLE_SPONSORED_BUY_DESK(), address(desk), address(desk).codehash);
        vm.prank(deskOwner);
        desk.bindGatewayOnce(address(gateway));
        gateway.setSponsoredBuyDesk(address(desk));

        StreamGTypes.FeeTokenConfig memory cfg = StreamGTypes.FeeTokenConfig({
            chainId: block.chainid,
            token: address(usdt),
            runtimeCodeHash: address(usdt).codehash,
            proxyIdentityHash: bytes32(0),
            capabilityMask: StreamGTypes.CAP_EIP2612 | StreamGTypes.CAP_SELL_SPLIT | StreamGTypes.CAP_PRIOR_ALLOWANCE,
            decimals: 6,
            domainNameHash: keccak256(bytes("Permit Mock USDT")),
            domainVersionHash: keccak256(bytes("1")),
            builtInModeId: keccak256("EIP2612_STANDARD"),
            configVersion: 0,
            active: true
        });
        feeRegistry.upsertTokenConfig(cfg);

        usdt.mint(deskOwner, 10_000_000e6);
        vm.prank(deskOwner);
        usdt.approve(address(desk), type(uint256).max);
        usdt.mint(root, 1_000_000e6);
        vm.prank(minter);
        goat.mint(root, 100_000e18);
        vm.prank(deskOwner);
        desk.setBid(10_000);
        vm.prank(deskOwner);
        desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 30 days), 50_000e18);

        handler = new StreamGHandler(
            v1,
            sidecar,
            desk,
            gateway,
            goat,
            usdt,
            feeSafe,
            deskOwner,
            minter,
            root,
            ROOT_PK,
            secondary,
            SECONDARY_PK,
            tertiary,
            TERTIARY_PK,
            QUOTE_PK
        );
        targetContract(address(handler));
    }

    function invariant_primaryOf_immutable_once_set() public view {
        assertEq(sidecar.primaryOf(root), root);
        address secPrimary = sidecar.primaryOf(secondary);
        if (secPrimary != address(0)) assertEq(secPrimary, root);
        address terPrimary = sidecar.primaryOf(tertiary);
        if (terPrimary != address(0)) assertEq(terPrimary, root);
    }

    function invariant_secondary_never_sponsors_another_wallet() public view {
        if (sidecar.primaryOf(secondary) == root) {
            assertTrue(sidecar.primaryOf(tertiary) != secondary);
            assertEq(sidecar.controllerOf(secondary), address(0));
        }
        if (sidecar.primaryOf(tertiary) != address(0)) {
            assertEq(sidecar.primaryOf(tertiary), root);
        }
    }

    /// Highest `actionNonces` value this invariant has observed for `root`,
    /// keyed by action type. Reset per run along with the rest of the test
    /// contract's storage, so it measures monotonicity WITHIN a call sequence,
    /// which is where a regression would show up.
    mapping(bytes32 => uint256) private _highWaterActionNonce;
    bool private _highWaterSeeded;
    bytes32[4] private _trackedActions;

    /// `actionNonces[signer][actionType]` must never decrease.
    /// `StreamGCommon.markIntentAndNonce` advances it by exactly one and is the
    /// only writer; a nonce that fails to advance, or moves backwards, re-opens
    /// replay of an intent that has already executed.
    ///
    /// The previous revision of this function was four
    /// `assertGe(<uint256>, 0)` calls. That is recorded here rather than
    /// quietly replaced, because the shape is worth recognising: an unsigned
    /// integer is unconditionally >= 0, so it held in every reachable program
    /// state and in every unreachable one too. It also recorded no prior value
    /// whatsoever, while its name claimed monotonicity — the assertion and the
    /// name were about different things. It ran 512 x 25 = 12,800 calls per
    /// campaign and contributed a passing test to the suite total.
    ///
    /// Mutation this now detects: make `markIntentAndNonce` write
    /// `actionNonces[signer][actionType] = intent.nonce` instead of
    /// `intent.nonce + 1`.
    function invariant_gateway_nonces_monotonic() public {
        if (!_highWaterSeeded) {
            _trackedActions[0] = StreamGTypes.ACTION_SPONSORED_SELL;
            _trackedActions[1] = StreamGTypes.ACTION_GOAT_TRANSFER;
            _trackedActions[2] = StreamGTypes.ACTION_USDT_TRANSFER;
            _trackedActions[3] = StreamGTypes.ACTION_SPONSORED_ENROLLMENT;
            _highWaterSeeded = true;
        }
        for (uint256 i = 0; i < 4; i++) {
            bytes32 action = _trackedActions[i];
            uint256 current = gateway.actionNonces(root, action);
            uint256 highWater = _highWaterActionNonce[action];
            assertGe(current, highWater, "action nonce decreased -- replay window reopened");
            if (current > highWater) _highWaterActionNonce[action] = current;
        }
        // The sell handler is the one path in this campaign that consumes an
        // action nonce, so tie the two together: every successful sell must
        // have advanced the sell nonce by exactly one. This is what makes the
        // invariant bite on a stuck nonce (>= alone cannot see "did not move").
        assertEq(
            gateway.actionNonces(root, StreamGTypes.ACTION_SPONSORED_SELL),
            handler.ghostSellSuccess(),
            "sell nonce must equal the number of successful sells"
        );
    }

    function invariant_root_caps_never_exceed_ceilings() public view {
        (uint256 id,,, uint256 sessionCap) = desk.currentSession();
        if (id != 0) {
            assertLe(desk.soldInSession(id, root), sessionCap);
        }
        uint256 dayIndex = block.timestamp / 1 days;
        assertLe(desk.soldPerUtcDay(dayIndex, root), desk.dailyRootCapGoat());
    }

    function test_fee_on_transfer_token_fails_closed() public {
        FeeOnTransferMockUSDT bad = new FeeOnTransferMockUSDT();
        _authorizePrior(address(bad), "FeeOnTransfer Mock USDT");
        bad.mint(root, 1_000_000);
        vm.prank(root);
        bad.approve(address(gateway), 600_000);
        _expectUsdtTransferFailClosed(address(bad), bytes32(uint256(9001)));
    }

    function test_false_return_token_fails_closed() public {
        FalseReturnMockUSDT bad = new FalseReturnMockUSDT();
        _authorizePrior(address(bad), "FalseReturn Mock USDT");
        bad.mint(root, 1_000_000);
        vm.prank(root);
        bad.approve(address(gateway), 600_000);
        _expectUsdtTransferFailClosed(address(bad), bytes32(uint256(9002)));
    }

    function _authorizePrior(address token, string memory domainName) internal {
        StreamGTypes.FeeTokenConfig memory cfg = StreamGTypes.FeeTokenConfig({
            chainId: block.chainid,
            token: token,
            runtimeCodeHash: token.codehash,
            proxyIdentityHash: bytes32(0),
            capabilityMask: StreamGTypes.CAP_PRIOR_ALLOWANCE,
            decimals: 6,
            domainNameHash: keccak256(bytes(domainName)),
            domainVersionHash: keccak256(bytes("1")),
            builtInModeId: keccak256("PRIOR_ALLOWANCE"),
            configVersion: 0,
            active: true
        });
        feeRegistry.upsertTokenConfig(cfg);
    }

    function _expectUsdtTransferFailClosed(address token, bytes32 intentId) internal {
        uint256 amount = 100_000;
        uint256 feeAmount = 10_000;
        bytes32 feeCfg = feeRegistry.getTokenConfigHash(token);
        bytes32 manifest = feeRegistry.activeManifestHash();
        uint256 nonce = gateway.actionNonces(root, StreamGTypes.ACTION_USDT_TRANSFER);

        StreamGTypes.PriorAllowanceAuthorization memory prior = StreamGTypes.PriorAllowanceAuthorization({
            intentId: intentId,
            actionType: StreamGTypes.ACTION_USDT_TRANSFER,
            owner: root,
            token: token,
            spender: address(gateway),
            value: amount + feeAmount,
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        bytes32 priorStruct = keccak256(
            abi.encode(
                StreamGTypes.PRIOR_ALLOWANCE_AUTHORIZATION_TYPEHASH,
                prior.intentId,
                prior.actionType,
                prior.owner,
                prior.token,
                prior.spender,
                prior.value,
                prior.nonce,
                prior.deadline
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(ROOT_PK, keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), priorStruct)));
        StreamGTypes.TokenAuthorization memory transferAuth;
        transferAuth.mode = uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE);
        transferAuth.priorAllowance = prior;
        transferAuth.priorAllowanceSignature = abi.encodePacked(r, s, v);

        StreamGTypes.UsdtTransferIntent memory intent = StreamGTypes.UsdtTransferIntent({
            intentId: intentId,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            owner: root,
            expectedRoot: root,
            token: token,
            recipient: tertiary,
            amount: amount,
            authorizationMode: uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE),
            transferAuthorizationDigest: bytes32(0),
            maxFee: feeAmount,
            feeQuoteHash: bytes32(0),
            nonce: nonce,
            deadline: uint48(block.timestamp + 1 hours)
        });
        bytes32 core = keccak256(
            abi.encode(
                StreamGTypes.USDT_TRANSFER_CORE_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.owner,
                intent.expectedRoot,
                intent.token,
                intent.recipient,
                intent.amount,
                intent.authorizationMode,
                intent.maxFee,
                intent.nonce,
                intent.deadline
            )
        );
        StreamGTypes.FeeQuote memory quote = StreamGTypes.FeeQuote({
            quoteId: keccak256(abi.encode(intentId, "q")),
            actionType: StreamGTypes.ACTION_USDT_TRANSFER,
            actionCoreHash: core,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            feeScheduleHash: gateway.feeScheduleHash(),
            payer: root,
            feeToken: token,
            feeAmount: feeAmount,
            feeRecipient: feeSafe,
            validAfter: uint48(block.timestamp - 1),
            validUntil: uint48(block.timestamp + 1 hours)
        });
        bytes32 qStruct = keccak256(
            abi.encode(
                StreamGTypes.FEE_QUOTE_TYPEHASH,
                quote.quoteId,
                quote.actionType,
                quote.actionCoreHash,
                quote.deploymentManifestHash,
                quote.feeTokenConfigHash,
                quote.feeScheduleHash,
                quote.payer,
                quote.feeToken,
                quote.feeAmount,
                quote.feeRecipient,
                quote.validAfter,
                quote.validUntil
            )
        );
        bytes32 feeQuoteHash = keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), qStruct));
        intent.feeQuoteHash = feeQuoteHash;
        (uint8 qv, bytes32 qr, bytes32 qs) = vm.sign(QUOTE_PK, feeQuoteHash);
        bytes memory quoteSig = abi.encodePacked(qr, qs, qv);

        bytes32 iStruct = keccak256(
            abi.encode(
                StreamGTypes.USDT_TRANSFER_INTENT_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.owner,
                intent.expectedRoot,
                intent.token,
                intent.recipient,
                intent.amount,
                intent.authorizationMode,
                intent.transferAuthorizationDigest,
                intent.maxFee,
                intent.feeQuoteHash,
                intent.nonce,
                intent.deadline
            )
        );
        (uint8 iv, bytes32 ir, bytes32 isig) =
            vm.sign(ROOT_PK, keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), iStruct)));
        bytes memory intentSig = abi.encodePacked(ir, isig, iv);

        uint256 rootBefore = IERC20(token).balanceOf(root);
        vm.expectRevert();
        gateway.executeUsdtTransfer(intent, quote, transferAuth, intentSig, quoteSig);
        assertEq(IERC20(token).balanceOf(root), rootBefore);
        assertFalse(gateway.intentUsed(intentId));
    }
}

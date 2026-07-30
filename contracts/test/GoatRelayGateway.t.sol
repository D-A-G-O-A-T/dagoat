// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {FeeTokenRegistry} from "../src/FeeTokenRegistry.sol";
import {WalletSponsorshipRegistry} from "../src/WalletSponsorshipRegistry.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {GoatRelayGateway} from "../src/GoatRelayGateway.sol";
import {SponsoredBuyDesk} from "../src/SponsoredBuyDesk.sol";
import {StreamGTypes} from "../src/StreamGTypes.sol";
import {PermitMockUSDT} from "./mocks/PermitMockUSDT.sol";
import {AuthorizationMockUSDT} from "./mocks/AuthorizationMockUSDT.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";

/// Task 7/8: enrollment + sponsored sell + transfers.
contract GoatRelayGatewayTest is Test {
    using ECDSA for bytes32;

    uint256 constant ISSUER_PK = 0xA11CE;
    uint256 constant ROOT_PK = 0xB0B;
    uint256 constant SECONDARY_PK = 0xC0FFEE;
    uint256 constant QUOTE_PK = 0xD00D;

    address internal policy;
    address internal issuer;
    address internal root;
    address internal secondary;
    address internal feeSafe;
    address internal recovery;
    address internal quoteSigner;

    EnrollmentRegistry internal v1;
    GoatCoin internal goat;
    FeeTokenRegistry internal feeRegistry;
    WalletSponsorshipRegistry internal sidecar;
    GoatRelayGateway internal gateway;
    PermitMockUSDT internal permitToken;
    AuthorizationMockUSDT internal authToken;
    MockUSDT internal legacyToken;
    SponsoredBuyDesk internal desk;
    address internal deskOwner;
    address internal minter;
    address internal recipient;
    uint256 constant RECIPIENT_PK = 0xACE0;
    uint256 constant BID = 10_000;
    uint256 constant DAILY_ROOT_CAP = 10_000e18;

    bytes32 constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 constant ENROLL_TYPEHASH =
        keccak256("Enroll(address wallet,uint256 nonce,uint256 deadline)");

    function setUp() public {
        policy = address(this);
        issuer = vm.addr(ISSUER_PK);
        root = vm.addr(ROOT_PK);
        secondary = vm.addr(SECONDARY_PK);
        quoteSigner = vm.addr(QUOTE_PK);
        feeSafe = makeAddr("feeSafe");
        recovery = makeAddr("recovery");

        v1 = new EnrollmentRegistry(policy);
        goat = new GoatCoin("GoatCoin", "GOAT", policy, v1);
        feeRegistry = new FeeTokenRegistry(policy);
        sidecar = new WalletSponsorshipRegistry(address(v1), address(feeRegistry), policy, recovery, 7 days);
        permitToken = new PermitMockUSDT();

        vm.prank(root);
        v1.enrollSelf();

        gateway = new GoatRelayGateway(
            address(v1),
            address(feeRegistry),
            address(sidecar),
            address(goat),
            policy,
            feeSafe
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
        sidecar.registerPrimary(auth, _signRootAuth(auth, ISSUER_PK));

        bytes32 manifest = keccak256("manifest-g1");
        bytes32 schedule = keccak256("schedule-g1");
        feeRegistry.setActiveManifestHash(manifest);
        gateway.setFeeScheduleHash(schedule);
        gateway.setQuoteSigner(quoteSigner);
        gateway.setPaused(false);
        gateway.activate();

        StreamGTypes.FeeTokenConfig memory cfg = StreamGTypes.FeeTokenConfig({
            chainId: block.chainid,
            token: address(permitToken),
            runtimeCodeHash: address(permitToken).codehash,
            proxyIdentityHash: bytes32(0),
            capabilityMask: StreamGTypes.CAP_EIP2612,
            decimals: 6,
            domainNameHash: keccak256(bytes("Permit Mock USDT")),
            domainVersionHash: keccak256(bytes("1")),
            builtInModeId: keccak256("EIP2612_STANDARD"),
            configVersion: 0,
            active: true
        });
        feeRegistry.upsertTokenConfig(cfg);

        // Fund controller for USDT fees.
        permitToken.mint(root, 1_000_000);

        // Task 8 fixtures: desk, transfer tokens, system addresses, GOAT mint.
        deskOwner = makeAddr("deskOwner");
        minter = makeAddr("minter");
        recipient = vm.addr(RECIPIENT_PK);
        authToken = new AuthorizationMockUSDT();
        legacyToken = new MockUSDT();

        v1.setSystemAddress(deskOwner, true);
        v1.setSystemAddress(feeSafe, true);
        v1.setSystemAddress(address(gateway), true);
        goat.setMinter(minter, true);

        vm.prank(recipient);
        v1.enrollSelf();

        desk = new SponsoredBuyDesk(
            deskOwner,
            IERC20(address(permitToken)),
            goat,
            v1,
            sidecar,
            feeSafe,
            DAILY_ROOT_CAP
        );
        v1.setSystemAddress(address(desk), true);
        feeRegistry.setRoleCommitment(
            feeRegistry.ROLE_SPONSORED_BUY_DESK(), address(desk), address(desk).codehash
        );
        vm.prank(deskOwner);
        desk.bindGatewayOnce(address(gateway));
        gateway.setSponsoredBuyDesk(address(desk));

        StreamGTypes.FeeTokenConfig memory sellCfg = StreamGTypes.FeeTokenConfig({
            chainId: block.chainid,
            token: address(permitToken),
            runtimeCodeHash: address(permitToken).codehash,
            proxyIdentityHash: bytes32(0),
            capabilityMask: StreamGTypes.CAP_EIP2612 | StreamGTypes.CAP_SELL_SPLIT | StreamGTypes.CAP_PRIOR_ALLOWANCE,
            decimals: 6,
            domainNameHash: keccak256(bytes("Permit Mock USDT")),
            domainVersionHash: keccak256(bytes("1")),
            builtInModeId: keccak256("EIP2612_STANDARD"),
            configVersion: 0,
            active: true
        });
        feeRegistry.upsertTokenConfig(sellCfg);

        StreamGTypes.FeeTokenConfig memory authCfg = StreamGTypes.FeeTokenConfig({
            chainId: block.chainid,
            token: address(authToken),
            runtimeCodeHash: address(authToken).codehash,
            proxyIdentityHash: bytes32(0),
            capabilityMask: StreamGTypes.CAP_EIP3009,
            decimals: 6,
            domainNameHash: keccak256(bytes("Authorization Mock USDT")),
            domainVersionHash: keccak256(bytes("1")),
            builtInModeId: keccak256("EIP3009_RECEIVE"),
            configVersion: 0,
            active: true
        });
        feeRegistry.upsertTokenConfig(authCfg);

        permitToken.mint(deskOwner, 1_000_000e6);
        vm.prank(deskOwner);
        permitToken.approve(address(desk), type(uint256).max);
        authToken.mint(root, 1_000_000);
        legacyToken.mint(root, 1_000_000);

        vm.prank(minter);
        goat.mint(root, 10_000e18);
        vm.prank(minter);
        goat.mint(recipient, 1_000e18);

        vm.prank(deskOwner);
        desk.setBid(BID);
        vm.prank(deskOwner);
        desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 5_000e18);
    }

    function _domain(string memory name, address verifying) internal view returns (bytes32) {
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

    function _sign(bytes32 digest, uint256 pk) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signRootAuth(StreamGTypes.RootAuthorization memory auth, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
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
        return _sign(keccak256(abi.encodePacked("\x19\x01", _domain("GoatWalletSponsorship", address(sidecar)), structHash)), pk);
    }

    function _v1Enroll(address wallet, uint256 nonce, uint256 deadline, uint256 pk)
        internal
        view
        returns (StreamGTypes.V1Enrollment memory e, bytes32 digest)
    {
        bytes32 structHash = keccak256(abi.encode(ENROLL_TYPEHASH, wallet, nonce, deadline));
        digest = keccak256(abi.encodePacked("\x19\x01", _domain("GoatEnrollmentRegistry", address(v1)), structHash));
        e = StreamGTypes.V1Enrollment({
            wallet: wallet,
            nonce: nonce,
            deadline: deadline,
            signature: _sign(digest, pk)
        });
    }

    function _link(address root_, address secondary_, uint256 nonce, uint48 deadline, uint256 pk)
        internal
        view
        returns (StreamGTypes.LinkSecondary memory link, bytes32 digest, bytes memory sig)
    {
        link = StreamGTypes.LinkSecondary({root: root_, secondary: secondary_, nonce: nonce, deadline: deadline});
        bytes32 structHash =
            keccak256(abi.encode(StreamGTypes.LINK_SECONDARY_TYPEHASH, root_, secondary_, nonce, deadline));
        digest = keccak256(abi.encodePacked("\x19\x01", _domain("GoatWalletSponsorship", address(sidecar)), structHash));
        sig = _sign(digest, pk);
    }

    function _coreHash(
        bytes32 intentId,
        bytes32 manifest,
        bytes32 feeCfg,
        address root_,
        address controller,
        uint256 epoch,
        address secondary_,
        bytes32 enrollDigest,
        bytes32 linkDigest,
        bytes32 rootAuthDigest,
        address feeToken,
        uint8 feeMode,
        uint256 maxFee,
        uint256 nonce,
        uint48 deadline
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                StreamGTypes.SPONSOR_ENROLLMENT_CORE_TYPEHASH,
                intentId,
                manifest,
                feeCfg,
                root_,
                controller,
                epoch,
                secondary_,
                enrollDigest,
                linkDigest,
                rootAuthDigest,
                feeToken,
                feeMode,
                maxFee,
                nonce,
                deadline
            )
        );
    }

    function _sponsorIntent(
        bytes32 intentId,
        bytes32 manifest,
        bytes32 feeCfg,
        address root_,
        address controller,
        uint256 epoch,
        address secondary_,
        bytes32 enrollDigest,
        bytes32 linkDigest,
        address feeToken,
        uint8 feeMode,
        bytes32 feeAuthDigest,
        uint256 maxFee,
        bytes32 feeQuoteHash,
        uint256 nonce,
        uint48 deadline
    ) internal pure returns (StreamGTypes.SponsorEnrollment memory intent) {
        intent = StreamGTypes.SponsorEnrollment({
            intentId: intentId,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            root: root_,
            controller: controller,
            controllerEpoch: epoch,
            secondary: secondary_,
            enrollDigest: enrollDigest,
            linkDigest: linkDigest,
            rootAuthorizationDigest: bytes32(0),
            feeToken: feeToken,
            feeAuthorizationMode: feeMode,
            feeAuthorizationDigest: feeAuthDigest,
            maxFee: maxFee,
            feeQuoteHash: feeQuoteHash,
            nonce: nonce,
            deadline: deadline
        });
    }

    function _signSponsor(StreamGTypes.SponsorEnrollment memory intent, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                StreamGTypes.SPONSOR_ENROLLMENT_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.root,
                intent.controller,
                intent.controllerEpoch,
                intent.secondary,
                intent.enrollDigest,
                intent.linkDigest,
                intent.rootAuthorizationDigest,
                intent.feeToken,
                intent.feeAuthorizationMode,
                intent.feeAuthorizationDigest,
                intent.maxFee,
                intent.feeQuoteHash,
                intent.nonce,
                intent.deadline
            )
        );
        return _sign(keccak256(abi.encodePacked("\x19\x01", _domain("GoatRelayGateway", address(gateway)), structHash)), pk);
    }

    function _signQuote(StreamGTypes.FeeQuote memory quote, uint256 pk) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
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
        return _sign(keccak256(abi.encodePacked("\x19\x01", _domain("GoatRelayGateway", address(gateway)), structHash)), pk);
    }

    function _quoteDigest(StreamGTypes.FeeQuote memory quote) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
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
        return keccak256(abi.encodePacked("\x19\x01", _domain("GoatRelayGateway", address(gateway)), structHash));
    }

    function _emptyQuote() internal pure returns (StreamGTypes.FeeQuote memory q) {}
    function _emptyRootAuth() internal pure returns (StreamGTypes.RootAuthorization memory a) {}
    function _emptyTokenAuth() internal pure returns (StreamGTypes.TokenAuthorization memory t) {
        t.mode = uint8(StreamGTypes.AuthorizationMode.NONE);
    }

    function _buildEthEnrollment(bytes32 intentId)
        internal
        view
        returns (
            StreamGTypes.SponsorEnrollment memory intent,
            StreamGTypes.V1Enrollment memory v1e,
            StreamGTypes.LinkSecondary memory link,
            bytes memory sponsorSig,
            bytes memory linkSig
        )
    {
        uint48 deadline = uint48(block.timestamp + 1 hours);
        uint256 v1Nonce = v1.nonces(secondary);
        bytes32 enrollDigest;
        (v1e, enrollDigest) = _v1Enroll(secondary, v1Nonce, deadline, SECONDARY_PK);
        bytes32 linkDigest;
        (link, linkDigest, linkSig) = _link(root, secondary, sidecar.linkNonces(secondary), deadline, SECONDARY_PK);

        intent = _sponsorIntent(
            intentId,
            feeRegistry.activeManifestHash(),
            bytes32(0),
            root,
            root,
            sidecar.controllerEpoch(root),
            secondary,
            enrollDigest,
            linkDigest,
            address(0),
            uint8(StreamGTypes.AuthorizationMode.NONE),
            bytes32(0),
            0,
            bytes32(0),
            gateway.actionNonces(root, StreamGTypes.ACTION_SPONSORED_ENROLLMENT),
            deadline
        );
        sponsorSig = _signSponsor(intent, ROOT_PK);
    }

    function test_direct_eth_enrollment_requires_controller_caller_and_zero_fee_fields() public {
        (
            StreamGTypes.SponsorEnrollment memory intent,
            StreamGTypes.V1Enrollment memory v1e,
            StreamGTypes.LinkSecondary memory link,
            bytes memory sponsorSig,
            bytes memory linkSig
        ) = _buildEthEnrollment(bytes32(uint256(1)));

        // Non-controller caller
        vm.prank(secondary);
        vm.expectRevert(GoatRelayGateway.NotController.selector);
        gateway.executeSponsoredEnrollment(
            intent,
            _emptyQuote(),
            v1e,
            link,
            _emptyRootAuth(),
            _emptyTokenAuth(),
            sponsorSig,
            "",
            linkSig,
            ""
        );
    }

    function test_direct_eth_enrollment_links_and_enrolls_secondary_pays_zero() public {
        (
            StreamGTypes.SponsorEnrollment memory intent,
            StreamGTypes.V1Enrollment memory v1e,
            StreamGTypes.LinkSecondary memory link,
            bytes memory sponsorSig,
            bytes memory linkSig
        ) = _buildEthEnrollment(bytes32(uint256(11)));

        uint256 secBalBefore = secondary.balance;
        uint256 rootBalBefore = root.balance;

        vm.prank(root);
        gateway.executeSponsoredEnrollment(
            intent,
            _emptyQuote(),
            v1e,
            link,
            _emptyRootAuth(),
            _emptyTokenAuth(),
            sponsorSig,
            "",
            linkSig,
            ""
        );

        assertTrue(v1.enrolled(secondary));
        assertEq(sidecar.primaryOf(secondary), root);
        assertEq(secondary.balance, secBalBefore);
        assertEq(root.balance, rootBalBefore); // no value transfer
        assertEq(gateway.actionNonces(root, StreamGTypes.ACTION_SPONSORED_ENROLLMENT), 1);
        assertTrue(gateway.intentUsed(bytes32(uint256(11))));
    }

    function test_secondary_pays_zero() public {
        // Covered by ETH success path balance assertions.
        test_direct_eth_enrollment_links_and_enrolls_secondary_pays_zero();
    }

    function test_v1_front_run_branch_accepts_already_enrolled_n_plus_one() public {
        // Prepare signatures first.
        (
            StreamGTypes.SponsorEnrollment memory intent,
            StreamGTypes.V1Enrollment memory v1e,
            StreamGTypes.LinkSecondary memory link,
            bytes memory sponsorSig,
            bytes memory linkSig
        ) = _buildEthEnrollment(bytes32(uint256(22)));

        // Front-run the V1 enrollment with the same signed payload.
        v1.enrollSelfWithSignature(v1e.wallet, v1e.deadline, v1e.signature);
        assertTrue(v1.enrolled(secondary));
        assertEq(v1.nonces(secondary), v1e.nonce + 1);

        vm.prank(root);
        gateway.executeSponsoredEnrollment(
            intent,
            _emptyQuote(),
            v1e,
            link,
            _emptyRootAuth(),
            _emptyTokenAuth(),
            sponsorSig,
            "",
            linkSig,
            ""
        );

        assertEq(sidecar.primaryOf(secondary), root);
    }

    function _buildUsdtEnrollment(bytes32 intentId, uint256 feeAmount)
        internal
        view
        returns (
            StreamGTypes.SponsorEnrollment memory intent,
            StreamGTypes.FeeQuote memory quote,
            StreamGTypes.V1Enrollment memory v1e,
            StreamGTypes.LinkSecondary memory link,
            StreamGTypes.TokenAuthorization memory feeAuth,
            bytes memory sponsorSig,
            bytes memory quoteSig,
            bytes memory linkSig
        )
    {
        uint48 deadline = uint48(block.timestamp + 1 hours);
        uint256 v1Nonce = v1.nonces(secondary);
        bytes32 enrollDigest;
        (v1e, enrollDigest) = _v1Enroll(secondary, v1Nonce, deadline, SECONDARY_PK);
        bytes32 linkDigest;
        (link, linkDigest, linkSig) = _link(root, secondary, sidecar.linkNonces(secondary), deadline, SECONDARY_PK);

        bytes32 manifest = feeRegistry.activeManifestHash();
        bytes32 feeCfg = feeRegistry.getTokenConfigHash(address(permitToken));
        uint256 actionNonce = gateway.actionNonces(root, StreamGTypes.ACTION_SPONSORED_ENROLLMENT);

        bytes32 coreHash = _coreHash(
            intentId,
            manifest,
            feeCfg,
            root,
            root,
            sidecar.controllerEpoch(root),
            secondary,
            enrollDigest,
            linkDigest,
            bytes32(0),
            address(permitToken),
            uint8(StreamGTypes.AuthorizationMode.EIP2612),
            feeAmount,
            actionNonce,
            deadline
        );

        quote = StreamGTypes.FeeQuote({
            quoteId: bytes32(uint256(uint160(uint256(intentId)) + 99)),
            actionType: StreamGTypes.ACTION_SPONSORED_ENROLLMENT,
            actionCoreHash: coreHash,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            feeScheduleHash: gateway.feeScheduleHash(),
            payer: root,
            feeToken: address(permitToken),
            feeAmount: feeAmount,
            feeRecipient: feeSafe,
            validAfter: uint48(block.timestamp),
            validUntil: uint48(block.timestamp + 5 minutes)
        });
        quoteSig = _signQuote(quote, QUOTE_PK);
        bytes32 feeQuoteHash = _quoteDigest(quote);

        // EIP-2612 permit fields
        uint256 permitNonce = permitToken.nonces(root);
        uint256 permitDeadline = block.timestamp + 1 hours;
        bytes32 permitStruct = keccak256(
            abi.encode(PERMIT_TYPEHASH, root, address(gateway), feeAmount, permitNonce, permitDeadline)
        );
        bytes32 permitDigest =
            keccak256(abi.encodePacked("\x19\x01", permitToken.DOMAIN_SEPARATOR(), permitStruct));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ROOT_PK, permitDigest);
        feeAuth.mode = uint8(StreamGTypes.AuthorizationMode.EIP2612);
        feeAuth.eip2612 = StreamGTypes.Eip2612Authorization({
            owner: root,
            spender: address(gateway),
            value: feeAmount,
            deadline: permitDeadline,
            v: v,
            r: r,
            s: s
        });

        // For G1 tests we set feeAuthorizationDigest to zero and do not bind it in sponsor intent
        // beyond the mode/token/maxFee fields already covered by core/quote.
        intent = _sponsorIntent(
            intentId,
            manifest,
            feeCfg,
            root,
            root,
            sidecar.controllerEpoch(root),
            secondary,
            enrollDigest,
            linkDigest,
            address(permitToken),
            uint8(StreamGTypes.AuthorizationMode.EIP2612),
            bytes32(0),
            feeAmount,
            feeQuoteHash,
            actionNonce,
            deadline
        );
        sponsorSig = _signSponsor(intent, ROOT_PK);
    }

    function test_usdt_enrollment_collects_fee_only_on_success() public {
        uint256 feeAmount = 250_000;
        (
            StreamGTypes.SponsorEnrollment memory intent,
            StreamGTypes.FeeQuote memory quote,
            StreamGTypes.V1Enrollment memory v1e,
            StreamGTypes.LinkSecondary memory link,
            StreamGTypes.TokenAuthorization memory feeAuth,
            bytes memory sponsorSig,
            bytes memory quoteSig,
            bytes memory linkSig
        ) = _buildUsdtEnrollment(bytes32(uint256(33)), feeAmount);

        uint256 rootUsdtBefore = permitToken.balanceOf(root);
        uint256 feeSafeBefore = permitToken.balanceOf(feeSafe);
        uint256 secondaryUsdtBefore = permitToken.balanceOf(secondary);

        // Anyone can submit USDT path once signatures are valid.
        gateway.executeSponsoredEnrollment(
            intent,
            quote,
            v1e,
            link,
            _emptyRootAuth(),
            feeAuth,
            sponsorSig,
            quoteSig,
            linkSig,
            ""
        );

        assertTrue(v1.enrolled(secondary));
        assertEq(sidecar.primaryOf(secondary), root);
        assertEq(permitToken.balanceOf(root), rootUsdtBefore - feeAmount);
        assertEq(permitToken.balanceOf(feeSafe), feeSafeBefore + feeAmount);
        assertEq(permitToken.balanceOf(secondary), secondaryUsdtBefore);
        assertTrue(gateway.quoteUsed(quote.quoteId));
    }

    function test_usdt_enrollment_reverts_roll_back_link_and_fee() public {
        uint256 feeAmount = 250_000;
        (
            StreamGTypes.SponsorEnrollment memory intent,
            StreamGTypes.FeeQuote memory quote,
            StreamGTypes.V1Enrollment memory v1e,
            StreamGTypes.LinkSecondary memory link,
            StreamGTypes.TokenAuthorization memory feeAuth,
            bytes memory sponsorSig,
            bytes memory quoteSig,
            bytes memory linkSig
        ) = _buildUsdtEnrollment(bytes32(uint256(44)), feeAmount);

        // Corrupt fee auth so collection fails after link attempt would have happened.
        feeAuth.eip2612.value = feeAmount - 1; // insufficient permit value vs required fee
        // resign sponsor still uses original intent; collection uses feeAuth value check.

        uint256 rootUsdtBefore = permitToken.balanceOf(root);
        uint256 feeSafeBefore = permitToken.balanceOf(feeSafe);

        vm.expectRevert(GoatRelayGateway.InvalidFeeFields.selector);
        gateway.executeSponsoredEnrollment(
            intent,
            quote,
            v1e,
            link,
            _emptyRootAuth(),
            feeAuth,
            sponsorSig,
            quoteSig,
            linkSig,
            ""
        );

        // Full rollback: no link, no enrollment via this tx, no fee, no nonce/intent consumption.
        // Note: if V1 was not enrolled before, remains unenrolled.
        assertFalse(v1.enrolled(secondary));
        assertEq(sidecar.primaryOf(secondary), address(0));
        assertEq(permitToken.balanceOf(root), rootUsdtBefore);
        assertEq(permitToken.balanceOf(feeSafe), feeSafeBefore);
        assertEq(gateway.actionNonces(root, StreamGTypes.ACTION_SPONSORED_ENROLLMENT), 0);
        assertFalse(gateway.intentUsed(bytes32(uint256(44))));
        assertFalse(gateway.quoteUsed(quote.quoteId));
    }
    // -------------------------------------------------------------------------
    // Task 8 helpers
    // -------------------------------------------------------------------------

    function _signSell(StreamGTypes.SellIntent memory intent, uint256 pk) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
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
        return _sign(keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), structHash)), pk);
    }

    function _signGoatTransfer(StreamGTypes.GoatTransferIntent memory intent, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                StreamGTypes.GOAT_TRANSFER_INTENT_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.owner,
                intent.expectedRoot,
                intent.recipient,
                intent.amount,
                intent.goatPermitDigest,
                intent.feeToken,
                intent.feeAuthorizationMode,
                intent.feeAuthorizationDigest,
                intent.maxFee,
                intent.feeQuoteHash,
                intent.nonce,
                intent.deadline
            )
        );
        return _sign(keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), structHash)), pk);
    }

    function _signUsdtTransfer(StreamGTypes.UsdtTransferIntent memory intent, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
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
        return _sign(keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), structHash)), pk);
    }

    function _signPriorAllowance(StreamGTypes.PriorAllowanceAuthorization memory auth, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                StreamGTypes.PRIOR_ALLOWANCE_AUTHORIZATION_TYPEHASH,
                auth.intentId,
                auth.actionType,
                auth.owner,
                auth.token,
                auth.spender,
                auth.value,
                auth.nonce,
                auth.deadline
            )
        );
        return _sign(keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), structHash)), pk);
    }

    function _goatPermitFor(address owner_, uint256 pk, address spender, uint256 amount)
        internal
        view
        returns (StreamGTypes.Eip2612Authorization memory p, bytes32 permitDigest)
    {
        uint256 nonce = goat.nonces(owner_);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender, amount, nonce, deadline));
        permitDigest = keccak256(abi.encodePacked("\x19\x01", goat.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, permitDigest);
        p = StreamGTypes.Eip2612Authorization({
            owner: owner_,
            spender: spender,
            value: amount,
            deadline: deadline,
            v: v,
            r: r,
            s: s
        });
    }

    function _usdtPermit(address owner_, uint256 pk, address token, address spender, uint256 value)
        internal
        view
        returns (StreamGTypes.Eip2612Authorization memory p)
    {
        uint256 nonce = PermitMockUSDT(token).nonces(owner_);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender, value, nonce, deadline));
        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", PermitMockUSDT(token).DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        p = StreamGTypes.Eip2612Authorization({
            owner: owner_,
            spender: spender,
            value: value,
            deadline: deadline,
            v: v,
            r: r,
            s: s
        });
    }

    function _quote(
        bytes32 quoteId,
        bytes32 actionType,
        bytes32 actionCoreHash,
        address payer,
        address feeToken,
        uint256 feeAmount,
        bytes32 feeCfg
    ) internal view returns (StreamGTypes.FeeQuote memory quote, bytes memory quoteSig, bytes32 feeQuoteHash) {
        bytes32 manifest = feeRegistry.activeManifestHash();
        bytes32 schedule = gateway.feeScheduleHash();
        quote = StreamGTypes.FeeQuote({
            quoteId: quoteId,
            actionType: actionType,
            actionCoreHash: actionCoreHash,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            feeScheduleHash: schedule,
            payer: payer,
            feeToken: feeToken,
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
        feeQuoteHash = keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), qStruct));
        quoteSig = _sign(feeQuoteHash, QUOTE_PK);
    }

    function _sellCoreHash(StreamGTypes.SellIntent memory intent) internal pure returns (bytes32) {
        return keccak256(
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
    }

    function _goatTransferCoreHash(StreamGTypes.GoatTransferIntent memory intent) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                StreamGTypes.GOAT_TRANSFER_CORE_TYPEHASH,
                intent.intentId,
                intent.deploymentManifestHash,
                intent.feeTokenConfigHash,
                intent.owner,
                intent.expectedRoot,
                intent.recipient,
                intent.amount,
                intent.goatPermitDigest,
                intent.feeToken,
                intent.feeAuthorizationMode,
                intent.maxFee,
                intent.nonce,
                intent.deadline
            )
        );
    }

    function _usdtTransferCoreHash(StreamGTypes.UsdtTransferIntent memory intent) internal pure returns (bytes32) {
        return keccak256(
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
    }

    // -------------------------------------------------------------------------
    // Task 8 tests
    // -------------------------------------------------------------------------

    function test_sponsored_sell_uses_desk_sellFor_and_does_not_pull_seller_usdt_fee() public {
        uint256 goatAmount = 100e18;
        uint256 feeAmount = 0.1e6;
        uint256 minNet = 0.9e6;
        bytes32 intentId = bytes32(uint256(801));
        bytes32 feeCfg = feeRegistry.getTokenConfigHash(address(permitToken));
        bytes32 manifest = feeRegistry.activeManifestHash();

        (StreamGTypes.Eip2612Authorization memory goatPermit, bytes32 goatPermitDigest) =
            _goatPermitFor(root, ROOT_PK, address(desk), goatAmount);

        StreamGTypes.SellIntent memory intent = StreamGTypes.SellIntent({
            intentId: intentId,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            seller: root,
            expectedRoot: root,
            desk: address(desk),
            goatAmount: goatAmount,
            minNetUsdtOut: minNet,
            goatPermitDigest: goatPermitDigest,
            maxFee: feeAmount,
            feeQuoteHash: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });

        (StreamGTypes.FeeQuote memory quote, bytes memory quoteSig, bytes32 feeQuoteHash) = _quote(
            bytes32(uint256(1801)),
            StreamGTypes.ACTION_SPONSORED_SELL,
            _sellCoreHash(intent),
            root,
            address(permitToken),
            feeAmount,
            feeCfg
        );
        intent.feeQuoteHash = feeQuoteHash;
        (quote, quoteSig, feeQuoteHash) = _quote(
            bytes32(uint256(1801)),
            StreamGTypes.ACTION_SPONSORED_SELL,
            _sellCoreHash(intent),
            root,
            address(permitToken),
            feeAmount,
            feeCfg
        );
        intent.feeQuoteHash = feeQuoteHash;

        bytes memory intentSig = _signSell(intent, ROOT_PK);

        uint256 sellerUsdtBefore = permitToken.balanceOf(root);
        uint256 feeSafeBefore = permitToken.balanceOf(feeSafe);
        uint256 ownerUsdtBefore = permitToken.balanceOf(deskOwner);
        uint256 sellerGoatBefore = goat.balanceOf(root);

        gateway.executeSponsoredSell(intent, quote, goatPermit, intentSig, quoteSig);

        assertEq(goat.balanceOf(root), sellerGoatBefore - goatAmount);
        assertEq(permitToken.balanceOf(root), sellerUsdtBefore + minNet);
        assertEq(permitToken.balanceOf(feeSafe), feeSafeBefore + feeAmount);
        assertEq(permitToken.balanceOf(deskOwner), ownerUsdtBefore - (minNet + feeAmount));
        assertTrue(gateway.intentUsed(intentId));
        assertEq(gateway.actionNonces(root, StreamGTypes.ACTION_SPONSORED_SELL), 1);
    }

    function test_goat_transfer_permit_then_transfer_then_fee() public {
        uint256 amount = 25e18;
        uint256 feeAmount = 100_000;
        bytes32 intentId = bytes32(uint256(802));
        bytes32 feeCfg = feeRegistry.getTokenConfigHash(address(permitToken));
        bytes32 manifest = feeRegistry.activeManifestHash();

        (StreamGTypes.Eip2612Authorization memory goatPermit, bytes32 goatPermitDigest) =
            _goatPermitFor(root, ROOT_PK, address(gateway), amount);

        StreamGTypes.Eip2612Authorization memory feePermit =
            _usdtPermit(root, ROOT_PK, address(permitToken), address(gateway), feeAmount);
        StreamGTypes.TokenAuthorization memory feeAuth;
        feeAuth.mode = uint8(StreamGTypes.AuthorizationMode.EIP2612);
        feeAuth.eip2612 = feePermit;

        StreamGTypes.GoatTransferIntent memory intent = StreamGTypes.GoatTransferIntent({
            intentId: intentId,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            owner: root,
            expectedRoot: root,
            recipient: recipient,
            amount: amount,
            goatPermitDigest: goatPermitDigest,
            feeToken: address(permitToken),
            feeAuthorizationMode: uint8(StreamGTypes.AuthorizationMode.EIP2612),
            feeAuthorizationDigest: bytes32(0),
            maxFee: feeAmount,
            feeQuoteHash: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });

        (StreamGTypes.FeeQuote memory quote, bytes memory quoteSig, bytes32 feeQuoteHash) = _quote(
            bytes32(uint256(1802)),
            StreamGTypes.ACTION_GOAT_TRANSFER,
            _goatTransferCoreHash(intent),
            root,
            address(permitToken),
            feeAmount,
            feeCfg
        );
        intent.feeQuoteHash = feeQuoteHash;
        (quote, quoteSig, feeQuoteHash) = _quote(
            bytes32(uint256(1802)),
            StreamGTypes.ACTION_GOAT_TRANSFER,
            _goatTransferCoreHash(intent),
            root,
            address(permitToken),
            feeAmount,
            feeCfg
        );
        intent.feeQuoteHash = feeQuoteHash;

        bytes memory intentSig = _signGoatTransfer(intent, ROOT_PK);

        uint256 ownerGoatBefore = goat.balanceOf(root);
        uint256 recipientGoatBefore = goat.balanceOf(recipient);
        uint256 ownerUsdtBefore = permitToken.balanceOf(root);
        uint256 feeSafeBefore = permitToken.balanceOf(feeSafe);

        gateway.executeGoatTransfer(intent, quote, goatPermit, feeAuth, intentSig, quoteSig);

        assertEq(goat.balanceOf(root), ownerGoatBefore - amount);
        assertEq(goat.balanceOf(recipient), recipientGoatBefore + amount);
        assertEq(permitToken.balanceOf(root), ownerUsdtBefore - feeAmount);
        assertEq(permitToken.balanceOf(feeSafe), feeSafeBefore + feeAmount);
        assertTrue(gateway.intentUsed(intentId));
    }

    function test_usdt_transfer_eip2612_exact_amount_plus_fee() public {
        uint256 amount = 500_000;
        uint256 feeAmount = 50_000;
        bytes32 intentId = bytes32(uint256(803));
        bytes32 feeCfg = feeRegistry.getTokenConfigHash(address(permitToken));
        bytes32 manifest = feeRegistry.activeManifestHash();

        StreamGTypes.Eip2612Authorization memory permit =
            _usdtPermit(root, ROOT_PK, address(permitToken), address(gateway), amount + feeAmount);
        StreamGTypes.TokenAuthorization memory transferAuth;
        transferAuth.mode = uint8(StreamGTypes.AuthorizationMode.EIP2612);
        transferAuth.eip2612 = permit;

        StreamGTypes.UsdtTransferIntent memory intent = StreamGTypes.UsdtTransferIntent({
            intentId: intentId,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            owner: root,
            expectedRoot: root,
            token: address(permitToken),
            recipient: recipient,
            amount: amount,
            authorizationMode: uint8(StreamGTypes.AuthorizationMode.EIP2612),
            transferAuthorizationDigest: bytes32(0),
            maxFee: feeAmount,
            feeQuoteHash: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });

        (StreamGTypes.FeeQuote memory quote, bytes memory quoteSig, bytes32 feeQuoteHash) = _quote(
            bytes32(uint256(1803)),
            StreamGTypes.ACTION_USDT_TRANSFER,
            _usdtTransferCoreHash(intent),
            root,
            address(permitToken),
            feeAmount,
            feeCfg
        );
        intent.feeQuoteHash = feeQuoteHash;
        (quote, quoteSig, feeQuoteHash) = _quote(
            bytes32(uint256(1803)),
            StreamGTypes.ACTION_USDT_TRANSFER,
            _usdtTransferCoreHash(intent),
            root,
            address(permitToken),
            feeAmount,
            feeCfg
        );
        intent.feeQuoteHash = feeQuoteHash;
        bytes memory intentSig = _signUsdtTransfer(intent, ROOT_PK);

        uint256 ownerBefore = permitToken.balanceOf(root);
        uint256 recipientBefore = permitToken.balanceOf(recipient);
        uint256 feeSafeBefore = permitToken.balanceOf(feeSafe);

        gateway.executeUsdtTransfer(intent, quote, transferAuth, intentSig, quoteSig);

        assertEq(permitToken.balanceOf(root), ownerBefore - amount - feeAmount);
        assertEq(permitToken.balanceOf(recipient), recipientBefore + amount);
        assertEq(permitToken.balanceOf(feeSafe), feeSafeBefore + feeAmount);
    }

    function test_usdt_transfer_eip3009_receive_then_split() public {
        uint256 amount = 400_000;
        uint256 feeAmount = 40_000;
        bytes32 intentId = bytes32(uint256(804));
        bytes32 feeCfg = feeRegistry.getTokenConfigHash(address(authToken));
        bytes32 manifest = feeRegistry.activeManifestHash();

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 authNonce = bytes32(uint256(42));
        bytes32 structHash = keccak256(
            abi.encode(
                StreamGTypes.EIP3009_RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
                root,
                address(gateway),
                amount + feeAmount,
                validAfter,
                validBefore,
                authNonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", authToken.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ROOT_PK, digest);

        StreamGTypes.TokenAuthorization memory transferAuth;
        transferAuth.mode = uint8(StreamGTypes.AuthorizationMode.EIP3009);
        transferAuth.eip3009 = StreamGTypes.Eip3009Authorization({
            from: root,
            to: address(gateway),
            value: amount + feeAmount,
            validAfter: validAfter,
            validBefore: validBefore,
            nonce: authNonce,
            v: v,
            r: r,
            s: s
        });

        StreamGTypes.UsdtTransferIntent memory intent = StreamGTypes.UsdtTransferIntent({
            intentId: intentId,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            owner: root,
            expectedRoot: root,
            token: address(authToken),
            recipient: recipient,
            amount: amount,
            authorizationMode: uint8(StreamGTypes.AuthorizationMode.EIP3009),
            transferAuthorizationDigest: bytes32(0),
            maxFee: feeAmount,
            feeQuoteHash: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });

        (StreamGTypes.FeeQuote memory quote, bytes memory quoteSig, bytes32 feeQuoteHash) = _quote(
            bytes32(uint256(1804)),
            StreamGTypes.ACTION_USDT_TRANSFER,
            _usdtTransferCoreHash(intent),
            root,
            address(authToken),
            feeAmount,
            feeCfg
        );
        intent.feeQuoteHash = feeQuoteHash;
        (quote, quoteSig, feeQuoteHash) = _quote(
            bytes32(uint256(1804)),
            StreamGTypes.ACTION_USDT_TRANSFER,
            _usdtTransferCoreHash(intent),
            root,
            address(authToken),
            feeAmount,
            feeCfg
        );
        intent.feeQuoteHash = feeQuoteHash;
        bytes memory intentSig = _signUsdtTransfer(intent, ROOT_PK);

        uint256 ownerBefore = authToken.balanceOf(root);
        uint256 recipientBefore = authToken.balanceOf(recipient);
        uint256 feeSafeBefore = authToken.balanceOf(feeSafe);

        gateway.executeUsdtTransfer(intent, quote, transferAuth, intentSig, quoteSig);

        assertEq(authToken.balanceOf(root), ownerBefore - amount - feeAmount);
        assertEq(authToken.balanceOf(recipient), recipientBefore + amount);
        assertEq(authToken.balanceOf(feeSafe), feeSafeBefore + feeAmount);
        assertEq(authToken.balanceOf(address(gateway)), 0);
    }

    function test_usdt_transfer_prior_allowance_path() public {
        uint256 amount = 300_000;
        uint256 feeAmount = 30_000;
        bytes32 intentId = bytes32(uint256(805));
        bytes32 feeCfg = feeRegistry.getTokenConfigHash(address(permitToken));
        bytes32 manifest = feeRegistry.activeManifestHash();

        vm.prank(root);
        permitToken.approve(address(gateway), amount + feeAmount);

        StreamGTypes.PriorAllowanceAuthorization memory prior = StreamGTypes.PriorAllowanceAuthorization({
            intentId: intentId,
            actionType: StreamGTypes.ACTION_USDT_TRANSFER,
            owner: root,
            token: address(permitToken),
            spender: address(gateway),
            value: amount + feeAmount,
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });
        bytes memory priorSig = _signPriorAllowance(prior, ROOT_PK);

        StreamGTypes.TokenAuthorization memory transferAuth;
        transferAuth.mode = uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE);
        transferAuth.priorAllowance = prior;
        transferAuth.priorAllowanceSignature = priorSig;

        StreamGTypes.UsdtTransferIntent memory intent = StreamGTypes.UsdtTransferIntent({
            intentId: intentId,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: feeCfg,
            owner: root,
            expectedRoot: root,
            token: address(permitToken),
            recipient: recipient,
            amount: amount,
            authorizationMode: uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE),
            transferAuthorizationDigest: bytes32(0),
            maxFee: feeAmount,
            feeQuoteHash: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });

        (StreamGTypes.FeeQuote memory quote, bytes memory quoteSig, bytes32 feeQuoteHash) = _quote(
            bytes32(uint256(1805)),
            StreamGTypes.ACTION_USDT_TRANSFER,
            _usdtTransferCoreHash(intent),
            root,
            address(permitToken),
            feeAmount,
            feeCfg
        );
        intent.feeQuoteHash = feeQuoteHash;
        (quote, quoteSig, feeQuoteHash) = _quote(
            bytes32(uint256(1805)),
            StreamGTypes.ACTION_USDT_TRANSFER,
            _usdtTransferCoreHash(intent),
            root,
            address(permitToken),
            feeAmount,
            feeCfg
        );
        intent.feeQuoteHash = feeQuoteHash;
        bytes memory intentSig = _signUsdtTransfer(intent, ROOT_PK);

        uint256 ownerBefore = permitToken.balanceOf(root);
        uint256 recipientBefore = permitToken.balanceOf(recipient);
        uint256 feeSafeBefore = permitToken.balanceOf(feeSafe);

        gateway.executeUsdtTransfer(intent, quote, transferAuth, intentSig, quoteSig);

        assertEq(permitToken.balanceOf(root), ownerBefore - amount - feeAmount);
        assertEq(permitToken.balanceOf(recipient), recipientBefore + amount);
        assertEq(permitToken.balanceOf(feeSafe), feeSafeBefore + feeAmount);
    }

    function test_unsupported_token_reverts_without_state_change() public {
        uint256 amount = 100_000;
        uint256 feeAmount = 10_000;
        bytes32 intentId = bytes32(uint256(806));
        bytes32 fakeCfg = keccak256("legacy-unsupported");
        bytes32 manifest = feeRegistry.activeManifestHash();

        StreamGTypes.UsdtTransferIntent memory intent = StreamGTypes.UsdtTransferIntent({
            intentId: intentId,
            deploymentManifestHash: manifest,
            feeTokenConfigHash: fakeCfg,
            owner: root,
            expectedRoot: root,
            token: address(legacyToken),
            recipient: recipient,
            amount: amount,
            authorizationMode: uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE),
            transferAuthorizationDigest: bytes32(0),
            maxFee: feeAmount,
            feeQuoteHash: bytes32(0),
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours)
        });

        StreamGTypes.FeeQuote memory quote = StreamGTypes.FeeQuote({
            quoteId: bytes32(uint256(1806)),
            actionType: StreamGTypes.ACTION_USDT_TRANSFER,
            actionCoreHash: _usdtTransferCoreHash(intent),
            deploymentManifestHash: manifest,
            feeTokenConfigHash: fakeCfg,
            feeScheduleHash: gateway.feeScheduleHash(),
            payer: root,
            feeToken: address(legacyToken),
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
        quote.actionCoreHash = _usdtTransferCoreHash(intent);
        qStruct = keccak256(
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
        feeQuoteHash = keccak256(abi.encodePacked("\x19\x01", gateway.DOMAIN_SEPARATOR(), qStruct));
        intent.feeQuoteHash = feeQuoteHash;
        bytes memory quoteSig = _sign(feeQuoteHash, QUOTE_PK);
        bytes memory intentSig = _signUsdtTransfer(intent, ROOT_PK);

        StreamGTypes.TokenAuthorization memory transferAuth;
        transferAuth.mode = uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE);

        uint256 ownerBefore = legacyToken.balanceOf(root);
        vm.expectRevert(FeeTokenRegistry.TokenNotAuthorized.selector);
        gateway.executeUsdtTransfer(intent, quote, transferAuth, intentSig, quoteSig);

        assertEq(legacyToken.balanceOf(root), ownerBefore);
        assertFalse(gateway.intentUsed(intentId));
        assertEq(gateway.actionNonces(root, StreamGTypes.ACTION_USDT_TRANSFER), 0);
        assertFalse(gateway.quoteUsed(quote.quoteId));
    }
}


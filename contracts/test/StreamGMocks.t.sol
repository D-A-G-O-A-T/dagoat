// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {PermitMockUSDT} from "./mocks/PermitMockUSDT.sol";
import {AuthorizationMockUSDT} from "./mocks/AuthorizationMockUSDT.sol";
import {MockGasPriceOracle} from "./mocks/MockGasPriceOracle.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {IEIP3009} from "../src/interfaces/IEIP3009.sol";

contract StreamGMocksTest is Test {
    using ECDSA for bytes32;

    address constant BASE_GAS_ORACLE = 0x420000000000000000000000000000000000000F;

    // Anvil #0 — test key only.
    uint256 constant OWNER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address constant OWNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address constant SPENDER = address(0xBEEF);
    address constant RECIPIENT = address(0xCAFE);

    bytes32 constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 constant RECEIVE_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    function test_legacy_mock_usdt_remains_plain_erc20_without_permit() public {
        MockUSDT token = new MockUSDT();
        token.mint(OWNER, 1_000_000);
        assertEq(token.decimals(), 6);
        assertEq(token.balanceOf(OWNER), 1_000_000);
        // No nonces()/permit() on plain MockUSDT — unsupported-token path later.
    }

    function test_permit_mock_usdt_supports_eip2612() public {
        PermitMockUSDT token = new PermitMockUSDT();
        token.mint(OWNER, 1_000_000);
        assertEq(token.decimals(), 6);
        assertEq(token.nonces(OWNER), 0);

        uint256 value = 250_000;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, OWNER, SPENDER, value, token.nonces(OWNER), deadline)
        );
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                token.DOMAIN_SEPARATOR(),
                structHash
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);
        token.permit(OWNER, SPENDER, value, deadline, v, r, s);
        assertEq(token.allowance(OWNER, SPENDER), value);
        assertEq(token.nonces(OWNER), 1);
    }

    function test_authorization_mock_receive_with_authorization_and_replay_guard() public {
        AuthorizationMockUSDT token = new AuthorizationMockUSDT();
        token.mint(OWNER, 1_000_000);

        uint256 value = 100_000;
        uint256 validAfter = 0;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = bytes32(uint256(42));

        bytes32 structHash = keccak256(
            abi.encode(RECEIVE_TYPEHASH, OWNER, RECIPIENT, value, validAfter, validBefore, nonce)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);

        assertFalse(token.authorizationState(OWNER, nonce));
        token.receiveWithAuthorization(OWNER, RECIPIENT, value, validAfter, validBefore, nonce, v, r, s);
        assertTrue(token.authorizationState(OWNER, nonce));
        assertEq(token.balanceOf(RECIPIENT), value);
        assertEq(token.balanceOf(OWNER), 1_000_000 - value);

        vm.expectRevert(AuthorizationMockUSDT.AuthorizationUsed.selector);
        token.receiveWithAuthorization(OWNER, RECIPIENT, value, validAfter, validBefore, nonce, v, r, s);
    }

    function test_mock_gas_price_oracle_etch_at_base_predeploy() public {
        MockGasPriceOracle impl = new MockGasPriceOracle();
        impl.setFees(11 gwei, 22 gwei, 3 gwei);
        vm.etch(BASE_GAS_ORACLE, address(impl).code);

        // Storage is not copied by etch; set fees on the etched account via a fresh
        // wrapper pattern: deploy helper that writes through the predeploy interface.
        // For G1 we call the implementation first, then re-etch after setting by
        // using a simple store via MockGasPriceOracle at the predeploy by deploying
        // with etch of runtime code and manually setting slots if needed.
        // Prefer: create2-less approach — call setFees through a temporary proxy
        // is unnecessary; re-set via low-level after etch by deploying a setter contract
        // that selfdestructs, OR just use the impl address for unit tests and also
        // prove eth_call against etched code by setting storage slots.

        // Slot layout for public uint256s: l1Fee@0, l1FeeUpperBound@1, operatorFee@2
        vm.store(BASE_GAS_ORACLE, bytes32(uint256(0)), bytes32(uint256(11 gwei)));
        vm.store(BASE_GAS_ORACLE, bytes32(uint256(1)), bytes32(uint256(22 gwei)));
        vm.store(BASE_GAS_ORACLE, bytes32(uint256(2)), bytes32(uint256(3 gwei)));

        MockGasPriceOracle oracle = MockGasPriceOracle(BASE_GAS_ORACLE);
        bytes memory dummy = hex"deadbeef";
        assertEq(oracle.getL1Fee(dummy), 11 gwei);
        // Fjord takes the unsigned tx SIZE, not calldata — see selector pin below.
        assertEq(oracle.getL1FeeUpperBound(dummy.length), 22 gwei);
        assertEq(oracle.getOperatorFee(500_000), 3 gwei);
    }

    /// The attestor (`stream_g/base_fee.rs`) hand-encodes calldata against the
    /// real OP-Stack predeploy selectors, so a signature change in the mock
    /// would silently break Anvil integration decoding instead of failing to
    /// compile. Pin all three literally.
    function test_gas_price_oracle_selectors_match_op_stack_predeploy() public pure {
        assertEq(MockGasPriceOracle.getL1Fee.selector, bytes4(0x49948e0e), "getL1Fee(bytes)");
        assertEq(
            MockGasPriceOracle.getL1FeeUpperBound.selector,
            bytes4(0xf1c7a58b),
            "getL1FeeUpperBound(uint256) - Fjord takes tx size, not calldata"
        );
        assertEq(MockGasPriceOracle.getOperatorFee.selector, bytes4(0x275aedd2), "getOperatorFee(uint256)");
    }

    function test_ieip3009_interface_matches_authorization_mock() public {
        AuthorizationMockUSDT token = new AuthorizationMockUSDT();
        IEIP3009 i = IEIP3009(address(token));
        assertEq(
            i.authorizationState.selector,
            bytes4(keccak256("authorizationState(address,bytes32)"))
        );
    }
}

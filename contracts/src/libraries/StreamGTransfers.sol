// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Permit} from "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {StreamGTypes} from "../StreamGTypes.sol";
import {IEIP3009} from "../interfaces/IEIP3009.sol";

/// USDT-transfer settlement lifted out of `GoatRelayGateway` for EIP-170 headroom.
///
/// `internal` — inlined into `StreamGXfer`, which is itself the `public` library
/// the gateway reaches by `DELEGATECALL`. Only the gateway's runtime size is
/// bound by EIP-170, so a second nested `DELEGATECALL` here would cost gas on the
/// settlement path and save the gateway nothing.
///
/// Because the whole chain runs under the gateway's `DELEGATECALL` context,
/// `address(this)` is still the gateway and every balance check, allowance check
/// and `receiveWithAuthorization` recipient is unchanged. Gateway immutables
/// (`feeSafe`) and the EIP-712 domain separator cannot be read from library code,
/// so they are passed in explicitly; the digest formula is the same
/// `"\x19\x01" || domainSeparator || structHash` OpenZeppelin uses.
library StreamGTransfers {
    using SafeERC20 for IERC20;

    error InvalidFeeFields();
    error InvalidTransferAuth();
    error UnexpectedBalanceDelta();
    error BadPriorAllowance();
    error ExpiredDeadline();
    error UnsupportedFeeMode();

    function executeUsdtTransferWithAuth(
        StreamGTypes.UsdtTransferIntent calldata intent,
        StreamGTypes.TokenAuthorization calldata auth,
        uint256 feeAmount,
        address feeSafe,
        bytes32 domainSeparator
    ) internal {
        uint256 total = intent.amount + feeAmount;
        if (total < intent.amount) revert InvalidFeeFields();

        if (auth.mode == uint8(StreamGTypes.AuthorizationMode.EIP2612)) {
            StreamGTypes.Eip2612Authorization calldata p = auth.eip2612;
            if (p.owner != intent.owner || p.spender != address(this) || p.value != total) revert InvalidTransferAuth();
            IERC20Permit(intent.token).permit(p.owner, p.spender, p.value, p.deadline, p.v, p.r, p.s);
            _splitFromOwner(intent.owner, intent.token, intent.recipient, intent.amount, feeAmount, feeSafe);
            return;
        }

        if (auth.mode == uint8(StreamGTypes.AuthorizationMode.EIP3009)) {
            StreamGTypes.Eip3009Authorization calldata a = auth.eip3009;
            if (a.from != intent.owner || a.to != address(this) || a.value != total) revert InvalidTransferAuth();
            if (!(a.validAfter < block.timestamp && block.timestamp < a.validBefore)) revert InvalidTransferAuth();
            uint256 gatewayBefore = IERC20(intent.token).balanceOf(address(this));
            IEIP3009(intent.token).receiveWithAuthorization(
                a.from, a.to, a.value, a.validAfter, a.validBefore, a.nonce, a.v, a.r, a.s
            );
            if (IERC20(intent.token).balanceOf(address(this)) != gatewayBefore + total) revert UnexpectedBalanceDelta();
            uint256 recipientBefore = IERC20(intent.token).balanceOf(intent.recipient);
            uint256 feeSafeBefore = IERC20(intent.token).balanceOf(feeSafe);
            IERC20(intent.token).safeTransfer(intent.recipient, intent.amount);
            IERC20(intent.token).safeTransfer(feeSafe, feeAmount);
            if (IERC20(intent.token).balanceOf(intent.recipient) != recipientBefore + intent.amount) {
                revert UnexpectedBalanceDelta();
            }
            if (IERC20(intent.token).balanceOf(feeSafe) != feeSafeBefore + feeAmount) revert UnexpectedBalanceDelta();
            if (IERC20(intent.token).balanceOf(address(this)) != gatewayBefore) revert UnexpectedBalanceDelta();
            return;
        }

        if (auth.mode == uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE)) {
            StreamGTypes.PriorAllowanceAuthorization calldata p = auth.priorAllowance;
            if (
                p.intentId != intent.intentId || p.actionType != StreamGTypes.ACTION_USDT_TRANSFER
                    || p.owner != intent.owner || p.token != intent.token || p.spender != address(this)
                    || p.value != total
            ) {
                revert BadPriorAllowance();
            }
            if (block.timestamp >= p.deadline) revert ExpiredDeadline();
            bytes32 digest = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    domainSeparator,
                    keccak256(
                        abi.encode(
                            StreamGTypes.PRIOR_ALLOWANCE_AUTHORIZATION_TYPEHASH,
                            p.intentId,
                            p.actionType,
                            p.owner,
                            p.token,
                            p.spender,
                            p.value,
                            p.nonce,
                            p.deadline
                        )
                    )
                )
            );
            address signer = ECDSA.recover(digest, auth.priorAllowanceSignature);
            if (signer != intent.owner) revert BadPriorAllowance();
            if (IERC20(intent.token).allowance(intent.owner, address(this)) < total) revert BadPriorAllowance();
            _splitFromOwner(intent.owner, intent.token, intent.recipient, intent.amount, feeAmount, feeSafe);
            return;
        }

        revert UnsupportedFeeMode();
    }

    function _splitFromOwner(
        address owner,
        address token,
        address recipient,
        uint256 amount,
        uint256 feeAmount,
        address feeSafe
    ) internal {
        uint256 ownerBefore = IERC20(token).balanceOf(owner);
        uint256 recipientBefore = IERC20(token).balanceOf(recipient);
        uint256 feeSafeBefore = IERC20(token).balanceOf(feeSafe);
        IERC20(token).safeTransferFrom(owner, recipient, amount);
        IERC20(token).safeTransferFrom(owner, feeSafe, feeAmount);
        if (IERC20(token).balanceOf(owner) != ownerBefore - amount - feeAmount) revert UnexpectedBalanceDelta();
        if (IERC20(token).balanceOf(recipient) != recipientBefore + amount) revert UnexpectedBalanceDelta();
        if (IERC20(token).balanceOf(feeSafe) != feeSafeBefore + feeAmount) revert UnexpectedBalanceDelta();
    }
}

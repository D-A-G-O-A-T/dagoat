// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {GoatCoin} from "./GoatCoin.sol";
import {EnrollmentRegistry} from "./EnrollmentRegistry.sol";

/// The "trade to USDT" rail (spec §2.5): atomic GOAT→USDT at the
/// published rate during Safe-opened weekly windows. Season 0
/// beneficiary = founder (he acquires redeemed GOAT and HOLDS it —
/// founder amendment 1); Season 1+ deploys a fresh desk whose
/// beneficiary is the donor Treasury Safe (no co-mingling by
/// construction). Instant settlement is safe because clearing happened
/// before mint (spec §2.5). The published rate is a mint-backing
/// redemption, NOT a market peg (No-Ponzi §8).
/// DEPLOY PRECONDITION: the beneficiary must be registered as a system
/// address in EnrollmentRegistry (or enrolled) before the first window,
/// or every redeem reverts with GoatCoin.TransferRestricted.
/// SOLVENCY ASSUMPTION: desk solvency additionally assumes the beneficiary
/// and reserve do not recirculate acquired GOAT back to workers (Season-0
/// policy: founder holds). Beneficiary self-redeem is blocked in code.
contract RedemptionDesk {
    using SafeERC20 for IERC20;

    error NotSafe();
    error NoActiveWindow();
    error CapExceeded();
    error NotEnrolled();
    error ZeroPayout();
    error BeneficiaryCannotRedeem();

    uint256 public constant RATE = 10_000; // USDT 6dp per 1e18 GOAT

    address public immutable safe;
    IERC20 public immutable usdt;
    GoatCoin public immutable goat;
    EnrollmentRegistry public immutable registry;
    address public immutable beneficiary;

    struct Window {
        uint64 start;
        uint64 end;
        uint256 perAccountCapGoat;
    }

    uint256 public windowCount;
    mapping(uint256 => Window) public windows;
    mapping(uint256 => mapping(address => uint256)) public redeemedInWindow;

    event WindowOpened(uint256 indexed id, uint64 start, uint64 end, uint256 perAccountCapGoat);
    event Redeemed(uint256 indexed windowId, address indexed worker, uint256 goatAmount, uint256 usdtOut);

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafe();
        _;
    }

    constructor(address safe_, IERC20 usdt_, GoatCoin goat_, EnrollmentRegistry registry_, address beneficiary_) {
        safe = safe_;
        usdt = usdt_;
        goat = goat_;
        registry = registry_;
        beneficiary = beneficiary_;
    }

    function openWindow(uint64 start, uint64 end, uint256 perAccountCapGoat) external onlySafe {
        windowCount += 1;
        windows[windowCount] = Window(start, end, perAccountCapGoat);
        emit WindowOpened(windowCount, start, end, perAccountCapGoat);
    }

    function currentWindow() public view returns (uint256 id, uint64 start, uint64 end, uint256 cap) {
        Window storage w = windows[windowCount];
        if (windowCount == 0 || block.timestamp < w.start || block.timestamp > w.end) {
            return (0, 0, 0, 0);
        }
        return (windowCount, w.start, w.end, w.perAccountCapGoat);
    }

    function redeem(uint256 goatAmount) external {
        if (msg.sender == beneficiary) revert BeneficiaryCannotRedeem();
        if (!registry.enrolled(msg.sender)) revert NotEnrolled();
        (uint256 id,,, uint256 cap) = currentWindow();
        if (id == 0) revert NoActiveWindow();
        uint256 already = redeemedInWindow[id][msg.sender];
        if (already + goatAmount > cap) revert CapExceeded();
        redeemedInWindow[id][msg.sender] = already + goatAmount;

        uint256 usdtOut = goatAmount * RATE / 1e18;
        if (usdtOut == 0) revert ZeroPayout();
        goat.transferFrom(msg.sender, beneficiary, goatAmount);
        usdt.safeTransfer(msg.sender, usdtOut);
        emit Redeemed(id, msg.sender, goatAmount, usdtOut);
    }
}

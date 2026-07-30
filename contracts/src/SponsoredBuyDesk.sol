// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {GoatCoin} from "./GoatCoin.sol";
import {EnrollmentRegistry} from "./EnrollmentRegistry.sol";
import {WalletSponsorshipRegistry} from "./WalletSponsorshipRegistry.sol";
import {StreamGTypes} from "./StreamGTypes.sol";

/// Stream G sponsored market desk. Gateway-only sellFor; never wraps BuyDeskV1.
contract SponsoredBuyDesk is ReentrancyGuard {
    using SafeERC20 for IERC20;

    error NotOwner();
    error NotGateway();
    error ZeroAddress();
    error GatewayAlreadyBound();
    error NoActiveSession();
    error SessionCapExceeded();
    error DailyCapExceeded();
    error NotEnrolled();
    error Blacklisted();
    error OwnerCannotSell();
    error ZeroPayout();
    error InvalidGoatPermit();
    error FeeExceedsGross();
    error MinNetNotMet();
    error RootMismatch();
    error ClusterSuspended();
    error InvalidSession();

    address public immutable owner;
    IERC20 public immutable usdt;
    GoatCoin public immutable goat;
    EnrollmentRegistry public immutable registry;
    WalletSponsorshipRegistry public immutable sponsorship;
    address public immutable feeSafe;
    uint256 public immutable dailyRootCapGoat;

    address public gateway;
    bool public gatewayBound;

    /// USDT 6dp per 1e18 GOAT wei. Mutable via setBid; zero allowed.
    uint256 public bid = 10_000;

    struct Session {
        uint64 start;
        uint64 end;
        uint256 rootSessionCapGoat;
        bool closed;
    }

    uint256 public sessionCount;
    mapping(uint256 => Session) public sessions;
    /// Aggregated GOAT sold by root cluster in a session (root + secondaries).
    mapping(uint256 => mapping(address => uint256)) public soldInSession;
    /// Aggregated GOAT sold by root cluster in a UTC day (timestamp / 1 days).
    mapping(uint256 => mapping(address => uint256)) public soldPerUtcDay;

    event BidSet(uint256 oldBid, uint256 newBid);
    event SessionOpened(uint256 indexed id, uint64 start, uint64 end, uint256 rootSessionCapGoat);
    event SessionClosed(uint256 indexed id);
    event GatewayBound(address indexed gateway);
    event SoldFor(
        uint256 indexed sessionId,
        address indexed seller,
        address indexed root,
        uint256 goatAmount,
        uint256 grossUsdtOut,
        uint256 feeAmount,
        uint256 netUsdtOut
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyGateway() {
        if (msg.sender != gateway) revert NotGateway();
        _;
    }

    constructor(
        address owner_,
        IERC20 usdt_,
        GoatCoin goat_,
        EnrollmentRegistry registry_,
        WalletSponsorshipRegistry sponsorship_,
        address feeSafe_,
        uint256 dailyRootCapGoat_
    ) {
        if (
            owner_ == address(0) || address(usdt_) == address(0) || address(goat_) == address(0)
                || address(registry_) == address(0) || address(sponsorship_) == address(0)
                || feeSafe_ == address(0)
        ) {
            revert ZeroAddress();
        }
        owner = owner_;
        usdt = usdt_;
        goat = goat_;
        registry = registry_;
        sponsorship = sponsorship_;
        feeSafe = feeSafe_;
        dailyRootCapGoat = dailyRootCapGoat_;
    }

    function bindGatewayOnce(address gateway_) external onlyOwner {
        if (gatewayBound) revert GatewayAlreadyBound();
        if (gateway_ == address(0)) revert ZeroAddress();
        gateway = gateway_;
        gatewayBound = true;
        emit GatewayBound(gateway_);
    }

    function setBid(uint256 newBid) external onlyOwner {
        emit BidSet(bid, newBid);
        bid = newBid;
    }

    function openSession(uint64 start, uint64 end, uint256 rootSessionCapGoat) external onlyOwner {
        if (end <= start) revert InvalidSession();
        if (sessionCount > 0) {
            Session storage prev = sessions[sessionCount];
            // Non-overlapping: previous must be closed or ended.
            if (!prev.closed && block.timestamp <= prev.end) revert InvalidSession();
        }
        sessionCount += 1;
        sessions[sessionCount] = Session(start, end, rootSessionCapGoat, false);
        emit SessionOpened(sessionCount, start, end, rootSessionCapGoat);
    }

    function closeSession() external onlyOwner {
        if (sessionCount == 0) return;
        sessions[sessionCount].closed = true;
        emit SessionClosed(sessionCount);
    }

    function currentSession()
        public
        view
        returns (uint256 id, uint64 start, uint64 end, uint256 cap)
    {
        Session storage s = sessions[sessionCount];
        if (sessionCount == 0 || s.closed || block.timestamp < s.start || block.timestamp > s.end) {
            return (0, 0, 0, 0);
        }
        return (sessionCount, s.start, s.end, s.rootSessionCapGoat);
    }

    /// Gateway-only sponsored sell. Fee is split from gross USDT proceeds.
    function sellFor(
        address seller,
        address expectedRoot,
        uint256 goatAmount,
        uint256 minNetUsdtOut,
        uint256 feeAmount,
        StreamGTypes.Eip2612Authorization calldata goatPermit
    ) external onlyGateway nonReentrant returns (address root, uint256 grossUsdtOut, uint256 netUsdtOut) {
        if (seller == owner) revert OwnerCannotSell();
        if (!registry.enrolled(seller)) revert NotEnrolled();
        if (registry.blacklisted(seller)) revert Blacklisted();

        root = sponsorship.primaryOf(seller);
        if (root == address(0) || root != expectedRoot) revert RootMismatch();
        if (sponsorship.suspendedClusters(root)) revert ClusterSuspended();

        (uint256 id,,, uint256 sessionCap) = currentSession();
        if (id == 0) revert NoActiveSession();

        uint256 sessionSold = soldInSession[id][root];
        if (sessionSold + goatAmount > sessionCap) revert SessionCapExceeded();

        uint256 dayIndex = block.timestamp / 1 days;
        uint256 daySold = soldPerUtcDay[dayIndex][root];
        if (daySold + goatAmount > dailyRootCapGoat) revert DailyCapExceeded();

        // Exact GOAT permit: owner=seller, spender=this desk, value=goatAmount.
        if (
            goatPermit.owner != seller || goatPermit.spender != address(this)
                || goatPermit.value != goatAmount
        ) {
            revert InvalidGoatPermit();
        }
        // Permit call; any failure reverts whole sell.
        goat.permit(
            goatPermit.owner,
            goatPermit.spender,
            goatPermit.value,
            goatPermit.deadline,
            goatPermit.v,
            goatPermit.r,
            goatPermit.s
        );

        grossUsdtOut = goatAmount * bid / 1e18;
        if (grossUsdtOut == 0) revert ZeroPayout();
        if (feeAmount > grossUsdtOut) revert FeeExceedsGross();
        netUsdtOut = grossUsdtOut - feeAmount;
        if (netUsdtOut < minNetUsdtOut) revert MinNetNotMet();

        // Effects before interactions for caps; full tx rolls back on transfer failure.
        soldInSession[id][root] = sessionSold + goatAmount;
        soldPerUtcDay[dayIndex][root] = daySold + goatAmount;

        uint256 goatOwnerBefore = goat.balanceOf(owner);
        uint256 goatSellerBefore = goat.balanceOf(seller);
        uint256 usdtOwnerBefore = usdt.balanceOf(owner);
        uint256 usdtSellerBefore = usdt.balanceOf(seller);
        uint256 usdtFeeBefore = usdt.balanceOf(feeSafe);

        goat.transferFrom(seller, owner, goatAmount);
        if (netUsdtOut > 0) {
            usdt.safeTransferFrom(owner, seller, netUsdtOut);
        }
        if (feeAmount > 0) {
            usdt.safeTransferFrom(owner, feeSafe, feeAmount);
        }

        // Exact balance deltas.
        if (goat.balanceOf(owner) != goatOwnerBefore + goatAmount) revert InvalidGoatPermit();
        if (goat.balanceOf(seller) != goatSellerBefore - goatAmount) revert InvalidGoatPermit();
        if (usdt.balanceOf(owner) != usdtOwnerBefore - grossUsdtOut) revert ZeroPayout();
        if (usdt.balanceOf(seller) != usdtSellerBefore + netUsdtOut) revert ZeroPayout();
        if (usdt.balanceOf(feeSafe) != usdtFeeBefore + feeAmount) revert ZeroPayout();

        emit SoldFor(id, seller, root, goatAmount, grossUsdtOut, feeAmount, netUsdtOut);
    }

    function depth() external view returns (uint256) {
        uint256 allowed = usdt.allowance(owner, address(this));
        uint256 held = usdt.balanceOf(owner);
        return allowed < held ? allowed : held;
    }
}
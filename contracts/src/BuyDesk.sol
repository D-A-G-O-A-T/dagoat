// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {GoatCoin} from "./GoatCoin.sol";
import {EnrollmentRegistry} from "./EnrollmentRegistry.sol";

/// The free-market "sell to the founder" trade venue (Season-0
/// full-system design §2, task S2) — the free-market successor to the
/// retired RedemptionDesk (backed Season-0 pilot, left untouched
/// in-repo). This is a VOLUNTARY TRADE VENUE, never a redemption of a
/// claim: `bid` is simply the founder's own posted buy order, a standing
/// bid he may raise, lower, or zero out via `setBid` at will. There is no
/// promise of buyers or liquidity — the desk may have zero committed cap,
/// may have no open session, and the founder may set `bid` to zero ("desk
/// closed for value"). The bid is PRICE DISCOVERY, not a peg: unlike the
/// backed RedemptionDesk's published redemption rate, nothing backs this
/// number 1:1. A seller NEVER has to sell — holding GOAT and never touching
/// this contract is always a valid choice (No-Ponzi §8).
/// Bid changes are never retroactive: `sell` always reads the CURRENT
/// `bid` at call time; the UI must show sellers the live bid before they
/// submit, since it can move between when they look and when they call
/// `sell`.
/// GOAT bought here flows to `owner` on every sale — these on-chain
/// transfers ARE the founder's public acquisition log (Founder Decision
/// Record Q8 mitigation: the founder may buy, but every purchase is a
/// visible on-chain event, never hidden).
/// ALLOWANCE (wallet-direct) MODEL — the desk NEVER custodies USDT. It
/// spends the owner's own WALLET USDT via `usdt.safeTransferFrom(owner,
/// seller, ...)` on each sell, up to the allowance the owner grants with
/// `usdt.approve(desk, cap)`. That allowance is the desk's spending cap;
/// `depth()` reports min(allowance, owner wallet balance) — the truthful
/// buying power right now — so it decrements as GOAT is bought even under an
/// unlimited `type(uint256).max` approval (which OZ ERC20 never decrements),
/// never exposes more than the owner committed, and never advertises USDT the
/// owner cannot actually pay. Closing the desk is simply `usdt.approve(desk,
/// 0)` — depth returns to 0 instantly because the funds never left the
/// wallet. There is no pooled contract balance and no `fund`/`withdraw`:
/// stronger isolation than a funded desk (No-Ponzi — a desk pays out only the
/// owner's own real USDT, only up to the owner's own allowance). Honest
/// residue: the cap is committed intent, not a locked reserve; if the owner
/// spends their wallet USDT elsewhere, depth() falls with the balance and a
/// sell for more than the balance reverts ERC20InsufficientBalance.
/// DEPLOY PRECONDITION: `owner` must be a system address (or enrolled) in
/// EnrollmentRegistry before the first session, or every sell reverts
/// with GoatCoin.TransferRestricted.
contract BuyDesk {
    using SafeERC20 for IERC20;

    error NotOwner();
    error NoActiveSession();
    error CapExceeded();
    error NotEnrolled();
    error ZeroPayout();
    error OwnerCannotSell();

    address public immutable owner;
    IERC20 public immutable usdt;
    GoatCoin public immutable goat;
    EnrollmentRegistry public immutable registry;

    /// USDT 6dp per 1e18 GOAT wei. Mutable via setBid; zero allowed
    /// (desk closed for value). Never retroactive — sell() always reads
    /// this at call time.
    uint256 public bid = 10_000;

    struct Session {
        uint64 start;
        uint64 end;
        uint256 perAccountCapGoat;
        bool closed;
    }

    uint256 public sessionCount;
    mapping(uint256 => Session) public sessions;
    mapping(uint256 => mapping(address => uint256)) public soldInSession;

    event BidSet(uint256 oldBid, uint256 newBid);
    event SessionOpened(uint256 indexed id, uint64 start, uint64 end, uint256 perAccountCapGoat);
    event Sold(uint256 indexed sessionId, address indexed seller, uint256 goatAmount, uint256 usdtOut);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_, IERC20 usdt_, GoatCoin goat_, EnrollmentRegistry registry_) {
        owner = owner_;
        usdt = usdt_;
        goat = goat_;
        registry = registry_;
    }

    function setBid(uint256 newBid) external onlyOwner {
        emit BidSet(bid, newBid);
        bid = newBid;
    }

    function openSession(uint64 start, uint64 end, uint256 perAccountCapGoat) external onlyOwner {
        sessionCount += 1;
        sessions[sessionCount] = Session(start, end, perAccountCapGoat, false);
        emit SessionOpened(sessionCount, start, end, perAccountCapGoat);
    }

    /// Ends the current session early, regardless of its natural end
    /// time. No-op if no session was ever opened.
    function closeSession() external onlyOwner {
        if (sessionCount == 0) return;
        sessions[sessionCount].closed = true;
    }

    function currentSession() public view returns (uint256 id, uint64 start, uint64 end, uint256 cap) {
        Session storage s = sessions[sessionCount];
        if (sessionCount == 0 || s.closed || block.timestamp < s.start || block.timestamp > s.end) {
            return (0, 0, 0, 0);
        }
        return (sessionCount, s.start, s.end, s.perAccountCapGoat);
    }

    /// Voluntary trade: seller offers GOAT, desk pays the CURRENT bid.
    /// Atomic swap — GOAT to owner, USDT from the owner's wallet to the
    /// seller in the same call. USDT is pulled directly from `owner` via
    /// allowance (the desk holds none). Any failure (allowance exhausted or
    /// the owner's wallet balance short included) reverts the whole
    /// transaction and leaves all state, including soldInSession,
    /// unchanged.
    function sell(uint256 goatAmount) external {
        if (msg.sender == owner) revert OwnerCannotSell();
        if (!registry.enrolled(msg.sender)) revert NotEnrolled();
        (uint256 id,,, uint256 cap) = currentSession();
        if (id == 0) revert NoActiveSession();
        uint256 already = soldInSession[id][msg.sender];
        if (already + goatAmount > cap) revert CapExceeded();
        soldInSession[id][msg.sender] = already + goatAmount;

        uint256 usdtOut = goatAmount * bid / 1e18;
        if (usdtOut == 0) revert ZeroPayout();
        goat.transferFrom(msg.sender, owner, goatAmount);
        usdt.safeTransferFrom(owner, msg.sender, usdtOut);
        emit Sold(id, msg.sender, goatAmount, usdtOut);
    }

    /// Desk cap (buying power) = the lesser of the owner's committed USDT
    /// allowance to this desk and the owner's actual wallet balance — i.e.
    /// what can truthfully be paid out right now. It decrements as GOAT is
    /// bought (the wallet balance always drops on each sell, even when the
    /// owner granted an unlimited `type(uint256).max` approval that OZ ERC20
    /// never decrements) and is 0 once the owner sets `approve(desk, 0)`.
    /// Capped at the allowance so it never exposes more than the owner
    /// committed; capped at the balance so it never advertises USDT the
    /// owner cannot actually pay. May be zero.
    function depth() external view returns (uint256) {
        uint256 allowed = usdt.allowance(owner, address(this));
        uint256 held = usdt.balanceOf(owner);
        return allowed < held ? allowed : held;
    }
}

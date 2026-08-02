// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {ProxyRevenueSettlement} from "./ProxyRevenueSettlement.sol";

/// Custodian of consumer USDT and the owner of a dedicated BuyDesk instance.
///
/// This is Option B of the funding path and it is GATED: `armed` is false at
/// deploy and only the Policy Safe can flip it, after the criteria named in this
/// lane's decision D-4 plus the money gate. Until then the contract can hold USDT
/// and post a bid, but it cannot fund settlement.
///
/// It never mints and it has no burn path. The only assets that leave are USDT, up
/// to an approval the Policy Safe sets, and GOAT, only into ProxyRevenueSettlement.
///
/// The desk it owns is an UNMODIFIED BuyDesk: that contract already pulls USDT from
/// its owner by allowance and delivers GOAT to its owner, which is exactly the
/// shape a revenue-funded market bid needs. The allowance IS the spending cap;
/// depth() reports min(allowance, balance), so the truthful buying power is on
/// chain and closing the bid is setDeskAllowance(0).
///
/// It cannot conjure a counterparty. If nobody sells at the posted bid, no GOAT is
/// acquired and no epoch is funded. That is correct behaviour under the monetary
/// rule and a real product failure mode; do not paper over it with a mint.
///
/// ---------------------------------------------------------------------------
/// MANDATORY OPERATOR-FACING COPY (Task 7 Step 1 of this lane's contracts spec).
/// These four sentences are recorded here, in the only contract this task
/// creates, and must appear VERBATIM in any operator-facing surface that
/// describes how an operator is compensated. Their absence from such a surface
/// is a defect, not an omission:
///
///   1. Payouts are GOAT that already exists.
///   2. No GOAT is created by using the network.
///   3. The protocol does not promise a buyer for it.
///   4. No consumer payment is distributed to operators: the 90/10 split
///      divides a grant the funder deposited, not a share of what a consumer
///      paid.
///
/// The fourth exists because the first three are all true and still leave an
/// operator with the wrong picture. An operator reading "90/10 revenue split"
/// concludes they receive 90% of the consumer's money. They receive 90% of
/// whatever the funder chose to deposit. This holds under the SHIPPED funding
/// option, which is the one where no new contract is deployed at all; this
/// contract is the gated alternative and changes nothing about those sentences
/// until it is armed.
/// ---------------------------------------------------------------------------
///
/// DEPLOY PRECONDITION, inherited from the desk it owns
/// (`contracts/src/BuyDesk.sol:45-47`): this contract's address must be enrolled
/// or a system address in EnrollmentRegistry before the first sale, or every
/// `BuyDesk.sell` reverts `GoatCoin.TransferRestricted`. The same holds for the
/// settlement contract on the `fundSettlement` leg -- GOAT has to be able to
/// reach it. The monetary rule this path serves is the "The No-Ponzi Invariant —
/// GoatCoin's load-bearing economic rule" spec, §1.
contract ProxyRevenueTreasury is ReentrancyGuard {
    using SafeERC20 for IERC20;

    error NotSafe();
    error NotArmed();
    error AlreadyArmed();
    error DeskAlreadyBound();
    error DeskNotBound();
    error ZeroAddress();
    error ZeroAmount();
    error SettlementMismatch();

    address public immutable safe;
    IERC20 public immutable usdt;
    IERC20 public immutable goat;

    address public desk;
    bool public armed;

    event DeskBound(address indexed desk);
    event DeskAllowanceSet(uint256 amount);
    event Armed(uint64 at);
    event SettlementFunded(address indexed settlement, uint256 indexed epochId, uint256 goatAmount);
    event UsdtWithdrawn(address indexed to, uint256 amount);

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafe();
        _;
    }

    constructor(address safe_, address usdt_, address goat_) {
        if (safe_ == address(0) || usdt_ == address(0) || goat_ == address(0)) revert ZeroAddress();
        safe = safe_;
        usdt = IERC20(usdt_);
        goat = IERC20(goat_);
    }

    function bindDeskOnce(address desk_) external onlySafe {
        if (desk_ == address(0)) revert ZeroAddress();
        if (desk != address(0)) revert DeskAlreadyBound();
        desk = desk_;
        emit DeskBound(desk_);
    }

    /// The desk's spending cap. Set to 0 to close the bid instantly; the USDT never
    /// leaves this contract until a seller actually sells.
    function setDeskAllowance(uint256 amount) external onlySafe {
        if (desk == address(0)) revert DeskNotBound();
        usdt.forceApprove(desk, amount);
        emit DeskAllowanceSet(amount);
    }

    /// ------------------------------------------------------------------------
    /// DESK OPERATION, forwarded.
    ///
    /// These three exist because the desk's own governance calls are `onlyOwner`
    /// and THIS CONTRACT is the owner. Without them the custodian owns a desk it
    /// cannot operate: no session can ever be opened, so `BuyDesk.sell` reverts
    /// `NoActiveSession` forever, no GOAT is ever acquired, and Option B is not
    /// gated but dead. Every one is `onlySafe`, so operating the desk stays a
    /// Policy Safe transaction and this contract adds no discretion of its own.
    /// ------------------------------------------------------------------------

    /// Opens the desk's next session. The per-account cap and the window are the
    /// desk's parameters, unchanged; this only supplies the owner's authority.
    function openDeskSession(uint64 start, uint64 end, uint256 perAccountCapGoat) external onlySafe {
        if (desk == address(0)) revert DeskNotBound();
        IProxyBuyDesk(desk).openSession(start, end, perAccountCapGoat);
    }

    /// Ends the current session early. Note that this is the WEAKER of the two
    /// ways to stop buying: `setDeskAllowance(0)` also works and is immediate at
    /// the token, not at the desk's session bookkeeping.
    function closeDeskSession() external onlySafe {
        if (desk == address(0)) revert DeskNotBound();
        IProxyBuyDesk(desk).closeSession();
    }

    /// The posted bid, in USDT 6dp per 1e18 GOAT. It is PRICE DISCOVERY, not a
    /// peg: nothing backs the number, the Safe may raise it, lower it or zero it,
    /// and no holder is ever obliged to sell into it.
    function setDeskBid(uint256 newBid) external onlySafe {
        if (desk == address(0)) revert DeskNotBound();
        IProxyBuyDesk(desk).setBid(newBid);
    }

    /// One-way. Deliberately irreversible: an arming that can be un-armed invites
    /// arming "temporarily". There is no disarm function, no owner override and no
    /// self-destruct -- the only way back is a redeploy of this contract.
    function arm() external onlySafe {
        if (armed) revert AlreadyArmed();
        armed = true;
        emit Armed(uint64(block.timestamp));
    }

    /// Moves acquired GOAT into an epoch's payable pool. The settlement contract
    /// re-checks the backing bound against its own recorded USDT inflow, so this
    /// function cannot over-fund even if the treasury is mistaken.
    function fundSettlement(address settlement, uint256 epochId, uint256 goatAmount, uint256 backedUsdt)
        external
        onlySafe
        nonReentrant
    {
        if (!armed) revert NotArmed();
        if (settlement == address(0)) revert ZeroAddress();
        if (goatAmount == 0) revert ZeroAmount();
        // `isFunder`, not `funder()`: the settlement's funder set is a one-way
        // mapping precisely so this treasury can be added to an already-deployed
        // settlement that shipped with the founder as funder, instead of requiring
        // a redeploy.
        if (!ProxyRevenueSettlement(payable(settlement)).isFunder(address(this))) revert SettlementMismatch();
        goat.forceApprove(settlement, goatAmount);
        ProxyRevenueSettlement(payable(settlement)).fundEpoch(epochId, goatAmount, backedUsdt);
        goat.forceApprove(settlement, 0);
        emit SettlementFunded(settlement, epochId, goatAmount);
    }

    /// Returns unspent consumer USDT. No dead-address sink, no destruction path.
    function withdrawUsdt(address to, uint256 amount) external onlySafe nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        usdt.safeTransfer(to, amount);
        emit UsdtWithdrawn(to, amount);
    }
}

/// The three owner-only calls this contract forwards to the desk it owns.
///
/// Declared as a minimal interface rather than importing `BuyDesk`, for the same
/// reason `ProxyRevenueSettlement` declares `IProxyEnrollment` instead of
/// importing the registry: the forwarders cost three `call`s and no extra
/// bytecode, and the desk stays on the zero-edit list untouched by this file.
interface IProxyBuyDesk {
    function setBid(uint256 newBid) external;
    function openSession(uint64 start, uint64 end, uint256 perAccountCapGoat) external;
    function closeSession() external;
}

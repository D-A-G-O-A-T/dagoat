import { formatBid, formatUsdt, testnetAmount } from "../chain/format.js";
import { isOwnDesk, POSTED_BID_COPY } from "../market.js";

/// Multi-desk list (design §2.3) — `rows` must already be sorted best-bid
/// first (market.js sortDesksByBestBid). `bestOpenAddress` marks the
/// highest active bid across ALL desks (not just ones open to `myAddress`)
/// with a BEST BID tag; `myAddress` marks the caller's own desk so it's
/// never mistaken for a sell target.
///
/// `showDepth` gates the Depth column: a desk's buying power is NEVER public
/// on this shared list (founder direction 2026-07-13). A desk's own owner
/// sees its depth in the Market "My desk" panel; the founder sees it here as
/// a debug column. Everyone else sees Desk / Bid / Status only.
export default function DeskTable({ rows, myAddress, bestOpenAddress, showDepth = false }) {
  if (rows.length === 0) {
    return <p className="placeholder-note">No buy desks yet — be the first donor to open one below.</p>;
  }

  return (
    <table className="pending-table desk-table">
      <caption className="muted desk-table__caption">
        Every bid below is {POSTED_BID_COPY}.{showDepth ? " Depth column is founder-only (debug)." : ""}
      </caption>
      <thead>
        <tr>
          <th>Desk</th>
          <th>Bid</th>
          {showDepth && <th>Depth (debug)</th>}
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => {
          const mine = isOwnDesk(row, myAddress);
          const best = row.address === bestOpenAddress;
          return (
            <tr key={row.address} className={best ? "desk-table__row--best" : ""}>
              <td>
                {row.displayName}
                {best && <span className="desk-table__tag desk-table__tag--best">Best bid</span>}
                {mine && <span className="desk-table__tag desk-table__tag--mine">Your desk</span>}
              </td>
              <td>1 GOAT = {testnetAmount(formatBid(row.bid), "USDT")}</td>
              {showDepth && <td>{testnetAmount(formatUsdt(row.depth), "USDT")}</td>}
              <td>
                <span className={`desk-table__badge ${row.isOpen ? "desk-table__badge--open" : "desk-table__badge--closed"}`}>
                  {row.isOpen ? "Open" : "Closed"}
                </span>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

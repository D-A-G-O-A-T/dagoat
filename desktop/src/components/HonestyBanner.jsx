// Persistent, non-dismissible honesty banner. Copy is locked — see
// the "Season-0 Full System Implementation Plan (Miner + Wallet + Free-Market Mint)"
// (Global Constraints: copy rules) and the locked founder economic decisions.
// Do not soften, shorten, or hide this.
import { APP_VERSION_LABEL } from "../version.js";

export default function HonestyBanner() {
  return (
    <div className="honesty-banner" role="note">
      <span>
        Testnet GOAT — not money. Real public-good work, pilot token. Price is a posted bid and
        may find zero buyers. Sponsor #1 is the founder; this proves the mechanism, not external
        demand.
      </span>
      <span className="honesty-banner-version">{APP_VERSION_LABEL}</span>
    </div>
  );
}

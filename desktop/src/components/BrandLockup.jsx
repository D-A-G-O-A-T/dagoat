import mark from "../assets/brand/goat-mark-cream.svg";
import { openExternal } from "../lib/openExternal.js";
import { TEAM_STATS_URL } from "../identity.js";

/** Composed lockup (spec §4): mark SVG + wordmark text, floats on glass.
 *  Click opens the GOAT team page on Folding@home stats (system browser). */
export default function BrandLockup() {
  return (
    <button
      type="button"
      className="brand-lockup"
      title="GOAT team on Folding@home stats"
      onClick={() => openExternal(TEAM_STATS_URL)}
    >
      <img src={mark} alt="" aria-hidden className="brand-lockup__mark" />
      <span className="brand-lockup__words">
        <span className="brand-lockup__name">GOATPROJECT</span>
        <span className="brand-lockup__sub">THE PEOPLE&apos;S COMPUTE COMMONS</span>
      </span>
    </button>
  );
}

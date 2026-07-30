import { CREATE_CARD, IMPORT_CARD, OPT_OUT_LINK, WALLET_GATE_TITLE } from "../copy.js";
import { saveOnboardingFlags } from "../onboardingState.js";

export default function WalletGate({ goTo, finish }) {
  async function optOut() {
    const flags = { disclaimerAccepted: true, completed: true, choice: "public_good_only" };
    await saveOnboardingFlags(flags);
    finish(flags);
  }
  return (
    <div className="wizard-step">
      <h2>{WALLET_GATE_TITLE}</h2>
      <div className="wizard-cards">
        <button type="button" className="wizard-card glass" onClick={() => goTo("create")}>
          <h3>{CREATE_CARD.title}</h3>
          <p className="muted">{CREATE_CARD.body}</p>
        </button>
        <button type="button" className="wizard-card glass" onClick={() => goTo("import")}>
          <h3>{IMPORT_CARD.title}</h3>
          <p className="muted">{IMPORT_CARD.body}</p>
        </button>
      </div>
      <button type="button" className="link-button wizard-optout" onClick={optOut}>
        {OPT_OUT_LINK}
      </button>
    </div>
  );
}

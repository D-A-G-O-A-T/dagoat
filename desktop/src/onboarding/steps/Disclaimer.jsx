import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  DISCLAIMER_ACCEPT, DISCLAIMER_DECLINE, DISCLAIMER_PARAGRAPHS, DISCLAIMER_TITLE,
} from "../copy.js";
import { DEFAULT_FLAGS, saveOnboardingFlags } from "../onboardingState.js";

export default function Disclaimer({ goTo }) {
  async function accept() {
    await saveOnboardingFlags({ ...DEFAULT_FLAGS, disclaimerAccepted: true });
    goTo("wallet_gate");
  }
  async function decline() {
    try {
      await getCurrentWindow().close();
    } catch {
      window.close(); // plain-browser dev fallback
    }
  }
  return (
    <div className="wizard-step">
      <h2>{DISCLAIMER_TITLE}</h2>
      <div className="wizard-scrollbox" tabIndex={0}>
        {DISCLAIMER_PARAGRAPHS.map((p, i) => (
          <p key={i}>
            {p.heading && <strong>{p.heading}: </strong>}
            {p.body}
          </p>
        ))}
      </div>
      <div className="wizard-actions">
        <button type="button" className="primary-cta" onClick={accept}>{DISCLAIMER_ACCEPT}</button>
        <button type="button" className="link-button" onClick={decline}>{DISCLAIMER_DECLINE}</button>
      </div>
    </div>
  );
}

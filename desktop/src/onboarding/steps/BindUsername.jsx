import { useState } from "react";
import { useNetwork } from "../../components/NetworkSwitch.jsx";
import { tryAutoEnroll } from "../../chain/enroll.js";
import {
  cleanCustomName, fullUsername, generatePasskey, isValidPasskeyInput,
  GOAT_USERNAME_PREFIX,
} from "../../identity.js";
import { bindWalletFahProfile } from "../../walletProfiles.js";
import { PASSKEY_HELP, PASSKEY_LABEL, USERNAME_CAUTION } from "../copy.js";
import { saveOnboardingFlags } from "../onboardingState.js";

export default function BindUsername({ finish, wizardCtx }) {
  const { networkId } = useNetwork();
  const [user, setUser] = useState("");
  const [passkey, setPasskey] = useState(wizardCtx.passkey ?? "");
  const [busy, setBusy] = useState(false);
  const canSubmit = cleanCustomName(user) && isValidPasskeyInput(passkey) && !busy;

  async function submit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    try {
      const username = fullUsername(user);
      const pk = passkey.trim() || generatePasskey();
      if (wizardCtx.wallet?.address) {
        await bindWalletFahProfile(wizardCtx.wallet.address, { username, passkey: pk });
      }
      await tryAutoEnroll(networkId, wizardCtx.wallet?.address);
    } catch { /* surfaces in Attribution with retry */ }
    const flags = { disclaimerAccepted: true, completed: true, choice: "wallet" };
    await saveOnboardingFlags(flags);
    finish(flags);
  }

  return (
    <form className="wizard-step" onSubmit={submit}>
      <h2>Choose your username</h2>
      <div className="firstrun-input-row">
        <span className="firstrun-prefix">{GOAT_USERNAME_PREFIX}</span>
        <input type="text" placeholder="your name (letters, digits, _)" value={user}
          onChange={(e) => setUser(e.target.value)} autoComplete="off" spellCheck={false} />
      </div>
      <p className="warning-text">{USERNAME_CAUTION}</p>
      <label className="muted">{PASSKEY_LABEL}</label>
      <input type="password" placeholder="32-hex passkey (leave empty to auto-generate)"
        value={passkey} onChange={(e) => setPasskey(e.target.value)} />
      <p className="muted">{PASSKEY_HELP}</p>
      <div className="wizard-actions">
        <button type="submit" className="primary-cta" disabled={!canSubmit}>
          {busy ? "Binding…" : "Bind and finish"}
        </button>
      </div>
    </form>
  );
}

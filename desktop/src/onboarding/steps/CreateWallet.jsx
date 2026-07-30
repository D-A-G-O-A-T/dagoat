import { useState } from "react";
import { useNetwork } from "../../components/NetworkSwitch.jsx";
import { createWallet, unlock } from "../../chain/wallet.js";
import { tryAutoEnroll } from "../../chain/enroll.js";
import {
  cleanCustomName, fullUsername, generatePasskey, isValidPasskeyInput,
  GOAT_USERNAME_PREFIX,
} from "../../identity.js";
import { bindWalletFahProfile } from "../../walletProfiles.js";
import { PASSKEY_HELP, PASSKEY_LABEL, USERNAME_CAUTION } from "../copy.js";

const MIN_PW = 8;

export default function CreateWallet({ goTo, setWizardCtx }) {
  const { networkId } = useNetwork();
  const [name, setName] = useState("");
  const [user, setUser] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [passkey, setPasskey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const canSubmit =
    name.trim() && cleanCustomName(user) && pw.length >= MIN_PW && pw === pw2 &&
    isValidPasskeyInput(passkey) && !busy;

  async function submit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError("");
    try {
      const username = fullUsername(user);
      const pk = passkey.trim() || generatePasskey();
      const meta = await createWallet(name.trim(), pw);
      await unlock(name.trim(), pw);
      // FAH identity + enroll are non-blocking (spec §11): failures surface in
      // Attribution with retry; the wizard always reaches the key-reveal step.
      // bindWalletFahProfile also stores a per-wallet profile so later unlocks swap FAH.
      try {
        await bindWalletFahProfile(meta.address, { username, passkey: pk });
        await tryAutoEnroll(networkId, meta.address);
      } catch { /* surfaces in Attribution */ }
      setWizardCtx((ctx) => ({ ...ctx, wallet: meta, username }));
      goTo("key_reveal");
    } catch (err) {
      setError(err?.message ?? String(err));
      setBusy(false);
    }
  }

  return (
    <form className="wizard-step" onSubmit={submit}>
      <h2>Create your wallet</h2>
      <input type="text" placeholder="Wallet name (local label)" value={name}
        onChange={(e) => setName(e.target.value)} autoComplete="off" />
      <label className="muted">Username</label>
      <div className="firstrun-input-row">
        <span className="firstrun-prefix">{GOAT_USERNAME_PREFIX}</span>
        <input type="text" placeholder="your name (letters, digits, _)" value={user}
          onChange={(e) => setUser(e.target.value)} autoComplete="off" spellCheck={false} />
      </div>
      <p className="warning-text">{USERNAME_CAUTION}</p>
      <input type="password" placeholder={`Password (min ${MIN_PW} chars)`} value={pw}
        onChange={(e) => setPw(e.target.value)} />
      <input type="password" placeholder="Confirm password" value={pw2}
        onChange={(e) => setPw2(e.target.value)} />
      <label className="muted">{PASSKEY_LABEL}</label>
      <input type="password" placeholder="32-hex passkey (leave empty to auto-generate)"
        value={passkey} onChange={(e) => setPasskey(e.target.value)} />
      <p className="muted">{PASSKEY_HELP}</p>
      {!isValidPasskeyInput(passkey) && <p className="error-text">Passkey must be empty or exactly 32 hex characters.</p>}
      {error && <p className="error-text">{error}</p>}
      <div className="wizard-actions">
        <button type="submit" className="primary-cta" disabled={!canSubmit}>
          {busy ? "Creating…" : "Create wallet"}
        </button>
      </div>
    </form>
  );
}

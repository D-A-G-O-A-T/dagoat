import { useState } from "react";
import { useNetwork } from "../../components/NetworkSwitch.jsx";
import { importWallet, unlock } from "../../chain/wallet.js";
import { KEY_IMPORT_WARNING } from "../../chain/client.js";
import { readBoundUsername } from "../../chain/attribution.js";
import { tryAutoEnroll } from "../../chain/enroll.js";
import { generatePasskey, isValidPasskeyInput } from "../../identity.js";
import { bindWalletFahProfile } from "../../walletProfiles.js";
import { saveOnboardingFlags } from "../onboardingState.js";
import { PASSKEY_HELP, PASSKEY_LABEL } from "../copy.js";

const MIN_PW = 8;

export default function ImportWallet({ goTo, finish, setWizardCtx }) {
  const { networkId } = useNetwork();
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [key, setKey] = useState("");
  const [passkey, setPasskey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e) {
    e.preventDefault();
    if (!name.trim() || pw.length < MIN_PW || !key.trim() || !isValidPasskeyInput(passkey) || busy) return;
    setBusy(true);
    setError("");
    try {
      const meta = await importWallet(name.trim(), pw, key.trim());
      await unlock(name.trim(), pw);
      setKey(""); // drop the pasted key from state immediately
      const bound = await readBoundUsername(networkId, meta.address);
      setWizardCtx((ctx) => ({ ...ctx, wallet: meta, username: bound, passkey: passkey.trim() }));
      if (bound) {
        // Adopt the existing bind: configure FAH + store per-wallet profile + finish.
        try {
          await bindWalletFahProfile(meta.address, {
            username: bound,
            passkey: passkey.trim() || generatePasskey(),
          });
          await tryAutoEnroll(networkId, meta.address);
        } catch { /* surfaces in Attribution */ }
        const flags = { disclaimerAccepted: true, completed: true, choice: "wallet" };
        await saveOnboardingFlags(flags);
        finish(flags);
      } else {
        goTo("bind_username");
      }
    } catch (err) {
      setError(err?.message ?? String(err));
      setBusy(false);
    }
  }

  return (
    <form className="wizard-step" onSubmit={submit}>
      <h2>Import a wallet</h2>
      <p className="warning-text">{KEY_IMPORT_WARNING}</p>
      <input type="text" placeholder="Wallet name" value={name} onChange={(e) => setName(e.target.value)} />
      <input type="password" placeholder={`Password (min ${MIN_PW} chars)`} value={pw} onChange={(e) => setPw(e.target.value)} />
      <input type="password" placeholder="0x… private key" value={key} onChange={(e) => setKey(e.target.value)} />
      <label className="muted">{PASSKEY_LABEL}</label>
      <input type="password" placeholder="32-hex passkey (leave empty to auto-generate)"
        value={passkey} onChange={(e) => setPasskey(e.target.value)} />
      <p className="muted">{PASSKEY_HELP}</p>
      {!isValidPasskeyInput(passkey) && <p className="error-text">Passkey must be empty or exactly 32 hex characters.</p>}
      {error && <p className="error-text">{error}</p>}
      <div className="wizard-actions">
        <button type="submit" className="primary-cta" disabled={busy || !isValidPasskeyInput(passkey)}>{busy ? "Importing…" : "Import"}</button>
      </div>
    </form>
  );
}

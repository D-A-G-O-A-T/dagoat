import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  KEY_REVEAL_CONFIRM, KEY_REVEAL_FALLBACK, KEY_REVEAL_TITLE, KEY_REVEAL_WARNING,
} from "../copy.js";
import { saveOnboardingFlags } from "../onboardingState.js";

export default function KeyReveal({ finish, wizardCtx }) {
  const [key, setKey] = useState(null);      // string | null; null = reveal failed
  const [failed, setFailed] = useState(false);
  const [written, setWritten] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    invoke("wallet_reveal_key", { expectedAddress: wizardCtx.wallet?.address ?? "" })
      .then((k) => { if (!cancelled) setKey(k); })
      .catch(() => { if (!cancelled) setFailed(true); });
    return () => { cancelled = true; setKey(null); }; // key never outlives this step
  }, [wizardCtx.wallet?.address]);

  async function done() {
    const flags = { disclaimerAccepted: true, completed: true, choice: "wallet" };
    await saveOnboardingFlags(flags);
    finish(flags);
  }

  return (
    <div className="wizard-step">
      <h2>{KEY_REVEAL_TITLE}</h2>
      <p className="warning-text">{KEY_REVEAL_WARNING}</p>
      {key ? (
        <div className="key-chip">
          <code>{key}</code>
          <button type="button" onClick={async () => {
            await navigator.clipboard.writeText(key);
            setCopied(true);
          }}>{copied ? "Copied" : "Copy"}</button>
        </div>
      ) : failed ? (
        <p className="muted">{KEY_REVEAL_FALLBACK}</p>
      ) : (
        <p className="muted">Revealing…</p>
      )}
      <label className="wizard-confirm">
        <input type="checkbox" checked={written} onChange={(e) => setWritten(e.target.checked)} />
        {KEY_REVEAL_CONFIRM}
      </label>
      <div className="wizard-actions">
        <button type="button" className="primary-cta" disabled={failed ? false : key ? !written : true} onClick={done}>
          Finish
        </button>
      </div>
    </div>
  );
}

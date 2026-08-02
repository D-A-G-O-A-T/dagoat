import { useRef, useState } from "react";
import {
  PROXY_ALLOWLIST_NOTE,
  PROXY_ALLOWLIST_TITLE,
  PROXY_CONSENT_SCROLL_HINT,
  PROXY_CONSENT_SIGN_HELP,
  PROXY_CONSENT_TITLE,
  PROXY_POLICY_MISMATCH_NOTE,
  PROXY_WALLET_LOCKED_NOTE,
} from "../copy.js";
import { allowlistDigest, policyDigest } from "../policyDigest.js";
import { normalizeHex } from "../consentRecord.js";

// The disclosure text is NEVER inlined here. It is rendered out of the one hashed
// artifact the daemon also reads, so the text on screen and the text in the signature
// cannot differ.
export default function ProxyDisclosure({ policyDoc, walletPresent, busy, onSign, onDecline }) {
  const [readToEnd, setReadToEnd] = useState(false);
  const scrollRef = useRef(null);

  // A THROW IS A REFUSAL, NOT A CRASH. `allowlistDigest` refuses outright when a
  // destination is not in the canonical slug <-> id registry -- it never returns a
  // digest over a zero id. Caught here so the screen renders the mismatch warning and
  // leaves the sign button disabled, rather than unmounting and leaving the operator
  // with a blank panel and no explanation.
  const digestsAgree = (() => {
    try {
      return (
        normalizeHex(policyDigest(policyDoc.policy)) === normalizeHex(policyDoc.policy_digest) &&
        normalizeHex(allowlistDigest(policyDoc.policy)) === normalizeHex(policyDoc.allowlist_digest)
      );
    } catch {
      return false;
    }
  })();

  function handleScroll() {
    const el = scrollRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 8) setReadToEnd(true);
  }

  return (
    <section className="wizard__step glass glass--static">
      <h2>{PROXY_CONSENT_TITLE}</h2>

      <div className="proxy-disclosure__scroll" ref={scrollRef} onScroll={handleScroll}>
        {policyDoc.policy.paragraphs.map((p, i) => (
          <div key={`p${i}`} className="proxy-disclosure__para">
            {p.heading ? <h3>{p.heading}</h3> : null}
            <p>{p.body}</p>
          </div>
        ))}

        <h3>{PROXY_ALLOWLIST_TITLE}</h3>
        <p>{PROXY_ALLOWLIST_NOTE}</p>
        <ul className="proxy-allowlist">
          {policyDoc.policy.allowlist.map((e) => (
            <li key={e.id}>
              <code>{e.host}</code> {e.note}
            </li>
          ))}
        </ul>
      </div>

      {!digestsAgree ? <p className="proxy-warn" role="alert">{PROXY_POLICY_MISMATCH_NOTE}</p> : null}
      {!readToEnd ? <p className="proxy-hint">{PROXY_CONSENT_SCROLL_HINT}</p> : null}
      {!walletPresent ? <p className="proxy-hint">{PROXY_WALLET_LOCKED_NOTE}</p> : null}
      <p className="proxy-hint">{PROXY_CONSENT_SIGN_HELP}</p>

      <div className="wizard__actions">
        <button
          type="button"
          className="btn btn--primary"
          disabled={!readToEnd || !walletPresent || !digestsAgree || busy}
          onClick={onSign}
        >
          {policyDoc.policy.accept_label}
        </button>
        <button type="button" className="btn" onClick={onDecline}>
          {policyDoc.policy.decline_label}
        </button>
      </div>
    </section>
  );
}
